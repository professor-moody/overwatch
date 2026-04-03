import { describe, it, expect, afterEach } from 'vitest';
import { unlinkSync, existsSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { isCredentialUsableForAuth, isCredentialStaleOrExpired } from '../credential-utils.js';
import { buildCredentialChains } from '../retrospective.js';
import { validateEdgeEndpoints } from '../graph-schema.js';
import type { NodeProperties, EngagementConfig, ExportedGraph } from '../../types.js';

const TEST_STATE_FILE = './state-test-cred-lifecycle.json';

function cleanup() {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}
}

function makeConfig(): EngagementConfig {
  return {
    id: 'test-cred-lifecycle',
    name: 'Credential Lifecycle Test',
    created_at: '2026-01-01T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/30'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.8 },
  };
}

function makeCredNode(overrides: Partial<NodeProperties> = {}): NodeProperties {
  return {
    id: 'cred-test',
    type: 'credential',
    label: 'test-cred',
    confidence: 1.0,
    discovered_at: '2026-01-01T00:00:00Z',
    cred_type: 'ntlm',
    cred_material_kind: 'ntlm_hash',
    cred_user: 'admin',
    cred_domain: 'test.local',
    ...overrides,
  } as NodeProperties;
}

describe('Sprint 3 — Credential Lifecycle & Provenance', () => {
  afterEach(cleanup);

  // =============================================
  // 3.1 Credential lifecycle properties
  // =============================================
  describe('3.1 isCredentialUsableForAuth with lifecycle', () => {
    it('returns false when valid_until is in the past', () => {
      const node = makeCredNode({ valid_until: '2020-01-01T00:00:00Z' });
      expect(isCredentialUsableForAuth(node)).toBe(false);
    });

    it('returns false when credential_status is expired', () => {
      const node = makeCredNode({ credential_status: 'expired' });
      expect(isCredentialUsableForAuth(node)).toBe(false);
    });

    it('returns false when credential_status is rotated', () => {
      const node = makeCredNode({ credential_status: 'rotated' });
      expect(isCredentialUsableForAuth(node)).toBe(false);
    });

    it('returns true when credential_status is active and valid_until is in the future', () => {
      const node = makeCredNode({
        credential_status: 'active',
        valid_until: '2099-01-01T00:00:00Z',
      });
      expect(isCredentialUsableForAuth(node)).toBe(true);
    });

    it('returns true when credential_status is stale (stale != expired for auth)', () => {
      // stale credentials may still work — only expired/rotated are hard gates
      const node = makeCredNode({ credential_status: 'stale' });
      expect(isCredentialUsableForAuth(node)).toBe(true);
    });

    it('returns true with no lifecycle fields set (backwards compat)', () => {
      const node = makeCredNode();
      expect(isCredentialUsableForAuth(node)).toBe(true);
    });
  });

  describe('3.1 isCredentialStaleOrExpired', () => {
    it('returns true for expired status', () => {
      expect(isCredentialStaleOrExpired(makeCredNode({ credential_status: 'expired' }))).toBe(true);
    });

    it('returns true for stale status', () => {
      expect(isCredentialStaleOrExpired(makeCredNode({ credential_status: 'stale' }))).toBe(true);
    });

    it('returns true for rotated status', () => {
      expect(isCredentialStaleOrExpired(makeCredNode({ credential_status: 'rotated' }))).toBe(true);
    });

    it('returns true when valid_until is in the past', () => {
      expect(isCredentialStaleOrExpired(makeCredNode({ valid_until: '2020-01-01T00:00:00Z' }))).toBe(true);
    });

    it('returns false for active credential', () => {
      expect(isCredentialStaleOrExpired(makeCredNode({ credential_status: 'active' }))).toBe(false);
    });

    it('returns false with no lifecycle fields', () => {
      expect(isCredentialStaleOrExpired(makeCredNode())).toBe(false);
    });
  });

  // =============================================
  // 3.2 DERIVED_FROM edge type
  // =============================================
  describe('3.2 DERIVED_FROM edge schema', () => {
    it('allows DERIVED_FROM between two credentials', () => {
      const result = validateEdgeEndpoints('DERIVED_FROM', 'credential', 'credential', {
        source_id: 'cred-a',
        target_id: 'cred-b',
      });
      expect(result.valid).toBe(true);
    });

    it('rejects DERIVED_FROM from user to credential', () => {
      const result = validateEdgeEndpoints('DERIVED_FROM', 'user', 'credential', {
        source_id: 'user-a',
        target_id: 'cred-b',
      });
      expect(result.valid).toBe(false);
    });

    it('rejects DERIVED_FROM from credential to host', () => {
      const result = validateEdgeEndpoints('DERIVED_FROM', 'credential', 'host', {
        source_id: 'cred-a',
        target_id: 'host-b',
      });
      expect(result.valid).toBe(false);
    });
  });

  // =============================================
  // 3.3 Frontier scoring with stale credentials
  // =============================================
  describe('3.3 frontier scoring with stale credentials', () => {
    it('flags frontier item for edge sourced from expired credential', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({
        id: 'cred-expired', type: 'credential', label: 'expired-cred',
        confidence: 0.9, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
        credential_status: 'expired',
      });
      engine.addNode({
        id: 'svc-smb', type: 'service', label: 'SMB',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        service_name: 'smb', port: 445,
      });
      engine.addEdge('cred-expired', 'svc-smb', {
        type: 'POTENTIAL_AUTH', confidence: 0.7,
        discovered_at: '2026-01-01T00:00:00Z',
        discovered_by: 'inference:test',
        tested: false,
      });

      const frontier = engine.computeFrontier();
      const edgeItem = frontier.find(f => f.edge_source === 'cred-expired');
      expect(edgeItem).toBeDefined();
      expect(edgeItem!.stale_credential).toBe(true);
      expect(edgeItem!.graph_metrics.confidence).toBeLessThan(0.1);
    });

    it('does NOT flag frontier item for active credential', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({
        id: 'cred-active', type: 'credential', label: 'active-cred',
        confidence: 0.9, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
        credential_status: 'active',
      });
      engine.addNode({
        id: 'svc-smb2', type: 'service', label: 'SMB',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        service_name: 'smb', port: 445,
      });
      engine.addEdge('cred-active', 'svc-smb2', {
        type: 'POTENTIAL_AUTH', confidence: 0.7,
        discovered_at: '2026-01-01T00:00:00Z',
        discovered_by: 'inference:test',
        tested: false,
      });

      const frontier = engine.computeFrontier();
      const edgeItem = frontier.find(f => f.edge_source === 'cred-active');
      expect(edgeItem).toBeDefined();
      expect(edgeItem!.stale_credential).toBeUndefined();
      expect(edgeItem!.graph_metrics.confidence).toBe(0.7);
    });
  });

  // =============================================
  // 3.4 degradeExpiredCredentialEdges
  // =============================================
  describe('3.4 degradeExpiredCredentialEdges', () => {
    it('reduces POTENTIAL_AUTH confidence from expired credential', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({
        id: 'cred-exp', type: 'credential', label: 'exp-cred',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
        credential_status: 'expired',
      });
      engine.addNode({
        id: 'svc-target', type: 'service', label: 'target',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        service_name: 'smb', port: 445,
      });
      engine.addEdge('cred-exp', 'svc-target', {
        type: 'POTENTIAL_AUTH', confidence: 0.8,
        discovered_at: '2026-01-01T00:00:00Z',
      });

      const degraded = engine.degradeExpiredCredentialEdges('cred-exp');
      expect(degraded.length).toBe(1);

      // Verify the edge confidence was reduced
      const graph = engine.exportGraph();
      const potAuthEdge = graph.edges.find(e => e.properties.type === 'POTENTIAL_AUTH' && e.source === 'cred-exp');
      expect(potAuthEdge).toBeDefined();
      expect(potAuthEdge!.properties.confidence).toBe(0.4); // 0.8 * 0.5
    });

    it('does not affect non-POTENTIAL_AUTH edges', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({
        id: 'cred-exp2', type: 'credential', label: 'exp-cred2',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
        credential_status: 'expired',
      });
      engine.addNode({
        id: 'cred-derived', type: 'credential', label: 'derived',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
      });
      engine.addEdge('cred-exp2', 'cred-derived', {
        type: 'DERIVED_FROM', confidence: 1.0,
        discovered_at: '2026-01-01T00:00:00Z',
      });

      const degraded = engine.degradeExpiredCredentialEdges('cred-exp2');
      expect(degraded.length).toBe(0);

      const graph = engine.exportGraph();
      const derivedEdge = graph.edges.find(e => e.properties.type === 'DERIVED_FROM');
      expect(derivedEdge!.properties.confidence).toBe(1.0);
    });

    it('returns empty array for active credentials', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({
        id: 'cred-ok', type: 'credential', label: 'ok-cred',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
        credential_status: 'active',
      });

      const degraded = engine.degradeExpiredCredentialEdges('cred-ok');
      expect(degraded.length).toBe(0);
    });

    it('clamps confidence at 0.1 minimum', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({
        id: 'cred-low', type: 'credential', label: 'low-cred',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
        credential_status: 'expired',
      });
      engine.addNode({
        id: 'svc-low', type: 'service', label: 'target',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        service_name: 'smb', port: 445,
      });
      engine.addEdge('cred-low', 'svc-low', {
        type: 'POTENTIAL_AUTH', confidence: 0.15,
        discovered_at: '2026-01-01T00:00:00Z',
      });

      engine.degradeExpiredCredentialEdges('cred-low');
      const graph = engine.exportGraph();
      const edge = graph.edges.find(e => e.properties.type === 'POTENTIAL_AUTH' && e.source === 'cred-low');
      expect(edge!.properties.confidence).toBe(0.1);
    });
  });

  // =============================================
  // 3.5 Health checks
  // =============================================
  describe('3.5 health checks for credential lifecycle', () => {
    it('detects expired credential with active POTENTIAL_AUTH edges', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({
        id: 'cred-stale', type: 'credential', label: 'stale-cred',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
        credential_status: 'expired',
      });
      engine.addNode({
        id: 'svc-health', type: 'service', label: 'svc',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        service_name: 'smb', port: 445,
      });
      engine.addEdge('cred-stale', 'svc-health', {
        type: 'POTENTIAL_AUTH', confidence: 0.7,
        discovered_at: '2026-01-01T00:00:00Z',
      });

      const report = engine.getHealthReport();
      const issue = report.issues.find(i => i.check === 'expired_credential_auth_edges');
      expect(issue).toBeDefined();
      expect(issue!.severity).toBe('warning');
      expect(issue!.node_ids).toContain('cred-stale');
    });

    it('detects DERIVED_FROM edge to superseded node', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({
        id: 'cred-src', type: 'credential', label: 'src',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
      });
      engine.addNode({
        id: 'cred-tgt', type: 'credential', label: 'tgt',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
        identity_status: 'superseded',
      });
      engine.addEdge('cred-src', 'cred-tgt', {
        type: 'DERIVED_FROM', confidence: 1.0,
        discovered_at: '2026-01-01T00:00:00Z',
      });

      const report = engine.getHealthReport();
      const issue = report.issues.find(i => i.check === 'broken_credential_lineage');
      expect(issue).toBeDefined();
      expect(issue!.severity).toBe('critical');
    });

    it('detects unmarked stale credential (valid_until past, status active)', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({
        id: 'cred-unmarked', type: 'credential', label: 'unmarked',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'kerberos_tgt', cred_material_kind: 'kerberos_tgt',
        valid_until: '2020-01-01T00:00:00Z',
        credential_status: 'active',
      });

      const report = engine.getHealthReport();
      const issue = report.issues.find(i => i.check === 'unmarked_stale_credential');
      expect(issue).toBeDefined();
      expect(issue!.severity).toBe('warning');
      expect(issue!.node_ids).toContain('cred-unmarked');
    });

    it('does NOT flag unmarked stale when credential_status is already expired', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({
        id: 'cred-ok-exp', type: 'credential', label: 'ok-exp',
        confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
        cred_type: 'kerberos_tgt', cred_material_kind: 'kerberos_tgt',
        valid_until: '2020-01-01T00:00:00Z',
        credential_status: 'expired',
      });

      const report = engine.getHealthReport();
      const issue = report.issues.find(i => i.check === 'unmarked_stale_credential');
      expect(issue).toBeUndefined();
    });
  });

  // =============================================
  // 3.6 Credential chains in retrospective
  // =============================================
  describe('3.6 buildCredentialChains', () => {
    it('builds correct chain from A → B → C graph', () => {
      const graph: ExportedGraph = {
        nodes: [
          { id: 'cred-a', properties: makeCredNode({ id: 'cred-a', label: 'cred-a', cred_user: 'alice', cred_type: 'plaintext', cred_material_kind: 'plaintext_password' }) },
          { id: 'cred-b', properties: makeCredNode({ id: 'cred-b', label: 'cred-b', cred_user: 'bob', cred_type: 'ntlm', cred_material_kind: 'ntlm_hash' }) },
          { id: 'cred-c', properties: makeCredNode({ id: 'cred-c', label: 'cred-c', cred_user: 'charlie', cred_type: 'ntlm', cred_material_kind: 'ntlm_hash' }) },
        ],
        edges: [
          { source: 'cred-a', target: 'cred-b', properties: { type: 'DERIVED_FROM', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z', derivation_method: 'crack' } },
          { source: 'cred-b', target: 'cred-c', properties: { type: 'DERIVED_FROM', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z', derivation_method: 'dcsync' } },
        ],
      };

      const chains = buildCredentialChains(graph);
      expect(chains.length).toBe(1);
      // Chains are now in attack-flow order: origin → derived
      expect(chains[0].chain).toEqual(['cred-c', 'cred-b', 'cred-a']);
      expect(chains[0].methods).toEqual(['dcsync', 'crack']);
      expect(chains[0].labels.length).toBe(3);
    });

    it('skips single-node chains', () => {
      const graph: ExportedGraph = {
        nodes: [
          { id: 'cred-solo', properties: makeCredNode({ id: 'cred-solo', label: 'solo' }) },
        ],
        edges: [],
      };

      const chains = buildCredentialChains(graph);
      expect(chains.length).toBe(0);
    });

    it('returns empty when no DERIVED_FROM edges exist', () => {
      const graph: ExportedGraph = {
        nodes: [
          { id: 'cred-x', properties: makeCredNode({ id: 'cred-x', label: 'x' }) },
          { id: 'cred-y', properties: makeCredNode({ id: 'cred-y', label: 'y' }) },
        ],
        edges: [
          { source: 'cred-x', target: 'cred-y', properties: { type: 'RELATED', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } },
        ],
      };

      const chains = buildCredentialChains(graph);
      expect(chains.length).toBe(0);
    });

    it('handles branching derivation (A → B, A → C)', () => {
      const graph: ExportedGraph = {
        nodes: [
          { id: 'cred-root', properties: makeCredNode({ id: 'cred-root', label: 'root', cred_user: 'root' }) },
          { id: 'cred-b1', properties: makeCredNode({ id: 'cred-b1', label: 'b1', cred_user: 'b1' }) },
          { id: 'cred-b2', properties: makeCredNode({ id: 'cred-b2', label: 'b2', cred_user: 'b2' }) },
        ],
        edges: [
          { source: 'cred-root', target: 'cred-b1', properties: { type: 'DERIVED_FROM', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z', derivation_method: 'dump' } },
          { source: 'cred-root', target: 'cred-b2', properties: { type: 'DERIVED_FROM', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z', derivation_method: 'crack' } },
        ],
      };

      const chains = buildCredentialChains(graph);
      expect(chains.length).toBe(2);
    });
  });

  // =============================================
  // 3.6 Report markdown includes credential chains
  // =============================================
  describe('3.6 retrospective report includes credential chains', () => {
    it('includes Credential Chains section when chains exist', async () => {
      const { generateReport } = await import('../retrospective.js');
      const graph: ExportedGraph = {
        nodes: [
          { id: 'cred-a', properties: makeCredNode({ id: 'cred-a', label: 'cred-a', cred_user: 'alice', cred_type: 'plaintext', cred_material_kind: 'plaintext_password' }) },
          { id: 'cred-b', properties: makeCredNode({ id: 'cred-b', label: 'cred-b', cred_user: 'bob', cred_type: 'ntlm', cred_material_kind: 'ntlm_hash' }) },
        ],
        edges: [
          { source: 'cred-a', target: 'cred-b', properties: { type: 'DERIVED_FROM', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z', derivation_method: 'crack' } },
        ],
      };

      const input = {
        config: makeConfig(),
        graph,
        history: [],
        inferenceRules: [],
        agents: [],
        skillNames: [],
      };

      const report = generateReport(input, {});
      expect(report).toContain('### Credential Chains');
      expect(report).toContain('[crack]');
    });
  });
});
