import { describe, it, expect } from 'vitest';
import type { Finding, NodeProperties, NodeType } from '../../types.js';
import { prepareFindingForIngest, normalizeFindingNode, validateFindingNode } from '../finding-validation.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'test-finding',
    agent_id: 'test-agent',
    timestamp: new Date().toISOString(),
    nodes: [],
    edges: [],
    ...overrides,
  };
}

function makeCredNode(id: string, overrides: Record<string, unknown> = {}): Partial<NodeProperties> & { id: string; type: NodeType } {
  return {
    id,
    type: 'credential' as NodeType,
    label: id,
    ...overrides,
  } as Partial<NodeProperties> & { id: string; type: NodeType };
}

describe('finding-validation', () => {
  // =============================================
  // normalizeFindingNode
  // =============================================
  describe('normalizeFindingNode', () => {
    it('maps username → cred_user on credential nodes', () => {
      const node = normalizeFindingNode(makeCredNode('cred-1', { username: 'jdoe' }));
      expect(node.cred_user).toBe('jdoe');
    });

    it('maps domain → cred_domain on credential nodes', () => {
      const node = normalizeFindingNode(makeCredNode('cred-1', { domain: 'test.local' }));
      expect(node.cred_domain).toBe('test.local');
    });

    it('maps credential_type → cred_type on credential nodes', () => {
      const node = normalizeFindingNode(makeCredNode('cred-1', { credential_type: 'ntlm' }));
      expect(node.cred_type).toBe('ntlm');
    });

    it('maps nthash → cred_hash and infers cred_type=ntlm', () => {
      const node = normalizeFindingNode(makeCredNode('cred-1', { nthash: 'aabbccdd' }));
      expect(node.cred_hash).toBe('aabbccdd');
      expect(node.cred_type).toBe('ntlm');
    });

    it('maps password → cred_value', () => {
      const node = normalizeFindingNode(makeCredNode('cred-1', { password: 'secret123' }));
      expect(node.cred_value).toBe('secret123');
    });

    it('does not overwrite existing cred_user with username', () => {
      const node = normalizeFindingNode(makeCredNode('cred-1', { cred_user: 'existing', username: 'new' }));
      expect(node.cred_user).toBe('existing');
    });

    it('infers cred_material_kind from cred_type when not set', () => {
      const node = normalizeFindingNode(makeCredNode('cred-1', {
        cred_type: 'ntlm',
        cred_hash: 'aabbccdd',
        cred_user: 'admin',
      }));
      expect(node.cred_material_kind).toBeDefined();
    });

    it('infers cred_usable_for_auth when material kind is available', () => {
      const node = normalizeFindingNode(makeCredNode('cred-1', {
        cred_type: 'ntlm',
        cred_hash: 'aabbccdd',
        cred_user: 'admin',
        cred_domain: 'test.local',
      }));
      expect(typeof node.cred_usable_for_auth).toBe('boolean');
    });

    it('passes non-credential nodes through unchanged', () => {
      const node = { id: 'host-1', type: 'host' as NodeType, label: 'host', ip: '10.0.0.1' };
      const result = normalizeFindingNode(node);
      expect(result).toEqual(node);
    });
  });

  // =============================================
  // validateFindingNode
  // =============================================
  describe('validateFindingNode', () => {
    it('returns empty errors for non-credential nodes', () => {
      const errors = validateFindingNode({ id: 'host-1', type: 'host' as NodeType, label: 'host' });
      expect(errors.length).toBe(0);
    });

    it('returns error for privileged credential without material kind', () => {
      const errors = validateFindingNode(makeCredNode('cred-1', { privileged: true }));
      expect(errors.length).toBe(1);
      expect(errors[0].code).toBe('credential_material_missing');
    });

    it('returns error for cred_usable_for_auth=true without material kind', () => {
      const errors = validateFindingNode(makeCredNode('cred-1', { cred_usable_for_auth: true }));
      expect(errors.length).toBe(1);
      expect(errors[0].code).toBe('credential_material_missing');
    });

    it('returns no error for privileged credential with proper material', () => {
      const errors = validateFindingNode(makeCredNode('cred-1', {
        privileged: true,
        cred_type: 'ntlm',
        cred_hash: 'aabbccdd',
        cred_user: 'admin',
        cred_domain: 'test.local',
        cred_material_kind: 'ntlm_hash',
      }));
      expect(errors.length).toBe(0);
    });

    it('returns no error for non-privileged credential without material', () => {
      const errors = validateFindingNode(makeCredNode('cred-1', { cred_user: 'jdoe' }));
      expect(errors.length).toBe(0);
    });
  });

  // =============================================
  // prepareFindingForIngest
  // =============================================
  describe('prepareFindingForIngest', () => {
    const noExistingNode = () => null;

    it('passes a valid finding through with no errors', () => {
      const finding = makeFinding({
        nodes: [
          { id: 'host-1', type: 'host' as NodeType, label: '10.0.0.1', ip: '10.0.0.1' },
          { id: 'svc-1', type: 'service' as NodeType, label: 'SMB', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-1', target: 'svc-1', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      });
      const result = prepareFindingForIngest(finding, noExistingNode);
      expect(result.errors.length).toBe(0);
      expect(result.finding.nodes.length).toBe(2);
    });

    it('reports error for edge referencing missing nodes', () => {
      const finding = makeFinding({
        edges: [
          { source: 'nonexistent-a', target: 'nonexistent-b', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      });
      const result = prepareFindingForIngest(finding, noExistingNode);
      const missingNodeErrors = result.errors.filter(e => e.code === 'missing_node_reference');
      expect(missingNodeErrors.length).toBe(1);
      expect(missingNodeErrors[0].source_id).toBe('nonexistent-a');
    });

    it('allows edge referencing existing graph nodes', () => {
      const finding = makeFinding({
        edges: [
          { source: 'host-1', target: 'svc-1', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      });
      const existingNode = (id: string) => {
        if (id === 'host-1') return { id: 'host-1', type: 'host', label: '10.0.0.1' } as NodeProperties;
        if (id === 'svc-1') return { id: 'svc-1', type: 'service', label: 'SMB' } as NodeProperties;
        return null;
      };
      const result = prepareFindingForIngest(finding, existingNode);
      const missingErrors = result.errors.filter(e => e.code === 'missing_node_reference');
      expect(missingErrors.length).toBe(0);
    });

    it('reports edge type constraint violation', () => {
      // RUNS requires source=host, target=service. Flip them.
      const finding = makeFinding({
        nodes: [
          { id: 'host-1', type: 'host' as NodeType, label: '10.0.0.1' },
          { id: 'svc-1', type: 'service' as NodeType, label: 'SMB' },
        ],
        edges: [
          { source: 'svc-1', target: 'host-1', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      });
      const result = prepareFindingForIngest(finding, noExistingNode);
      const constraintErrors = result.errors.filter(e => e.code === 'edge_type_constraint');
      expect(constraintErrors.length).toBe(1);
      expect(constraintErrors[0].edge_type).toBe('RUNS');
    });

    it('normalizes credential nodes during preparation', () => {
      const finding = makeFinding({
        nodes: [
          makeCredNode('cred-1', { username: 'admin', nthash: 'aabbccdd' }) as Partial<NodeProperties> & { id: string; type: NodeType },
        ],
      });
      const result = prepareFindingForIngest(finding, noExistingNode);
      const cred = result.finding.nodes[0] as any;
      expect(cred.cred_user).toBe('admin');
      expect(cred.cred_hash).toBe('aabbccdd');
      expect(cred.cred_type).toBe('ntlm');
    });

    it('handles empty finding (no nodes, no edges) cleanly', () => {
      const finding = makeFinding();
      const result = prepareFindingForIngest(finding, noExistingNode);
      expect(result.errors.length).toBe(0);
      expect(result.finding.nodes.length).toBe(0);
      expect(result.finding.edges.length).toBe(0);
    });
  });
});
