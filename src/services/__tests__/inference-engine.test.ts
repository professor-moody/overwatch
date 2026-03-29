import { describe, it, expect, beforeEach } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties, EdgeProperties, InferenceRule } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { InferenceEngine } from '../inference-engine.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

function makeConfig() {
  return {
    id: 'test-eng',
    name: 'Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local'], exclusions: [] },
    objectives: [{ id: 'obj-da', description: 'Get DA', target_node_type: 'credential', target_criteria: { privileged: true }, achieved: false }],
    opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
  } as any;
}

const now = new Date().toISOString();

function addNode(graph: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  graph.addNode(id, { id, label: id, discovered_at: now, confidence: 1.0, ...props } as NodeProperties);
}

function addEdge(graph: OverwatchGraph, src: string, tgt: string, type: string, extra: Record<string, unknown> = {}) {
  return graph.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: now, ...extra } as EdgeProperties);
}

// Build a full InferenceEngine with real EngineContext and real builtin rules from GraphEngine
function buildEngine(graph: OverwatchGraph, rules: InferenceRule[]) {
  const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
  ctx.inferenceRules.push(...rules);

  const getNode = (id: string): NodeProperties | null =>
    graph.hasNode(id) ? graph.getNodeAttributes(id) as NodeProperties : null;
  const getNodesByType = (type: string): NodeProperties[] => {
    const nodes: NodeProperties[] = [];
    graph.forEachNode((id: string, attrs) => {
      if (attrs.type === type) nodes.push(attrs as NodeProperties);
    });
    return nodes;
  };
  const addEdgeFn = (source: string, target: string, props: EdgeProperties) => {
    // Dedup by source+target+type
    for (const e of graph.edges(source, target)) {
      if (graph.getEdgeAttributes(e).type === props.type) {
        return { id: e, isNew: false };
      }
    }
    const id = graph.addEdge(source, target, props);
    return { id, isNew: true };
  };

  return new InferenceEngine(ctx, addEdgeFn, getNode, getNodesByType as any);
}

// Individual rule definitions for isolated testing
const RULE_KERBEROS_DOMAIN: InferenceRule = {
  id: 'rule-kerberos-domain',
  name: 'Kerberos implies domain membership',
  description: '',
  trigger: { node_type: 'service', property_match: { service_name: 'kerberos' } },
  produces: [{ edge_type: 'MEMBER_OF_DOMAIN', source_selector: 'parent_host', target_selector: 'matching_domain', confidence: 0.7 }],
};

const RULE_SMB_RELAY: InferenceRule = {
  id: 'rule-smb-signing-relay',
  name: 'SMB signing disabled implies relay target',
  description: '',
  trigger: { node_type: 'service', property_match: { service_name: 'smb', smb_signing: false } },
  produces: [{ edge_type: 'RELAY_TARGET', source_selector: 'all_compromised', target_selector: 'parent_host', confidence: 0.8 }],
};

const RULE_CRED_FANOUT: InferenceRule = {
  id: 'rule-cred-fanout',
  name: 'New credential tests against compatible services',
  description: '',
  trigger: { node_type: 'credential' },
  produces: [{ edge_type: 'POTENTIAL_AUTH', source_selector: 'trigger_node', target_selector: 'compatible_services_same_domain', confidence: 0.4 }],
};

const RULE_SUID_PRIVESC: InferenceRule = {
  id: 'rule-suid-privesc',
  name: 'SUID root binary enables privilege escalation',
  description: '',
  trigger: { node_type: 'host', property_match: { has_suid_root: true } },
  produces: [{ edge_type: 'ADMIN_TO', source_selector: 'session_holders_on_host', target_selector: 'trigger_node', confidence: 0.6 }],
};

const RULE_DOCKER_ESCAPE: InferenceRule = {
  id: 'rule-docker-escape',
  name: 'Docker socket enables container escape',
  description: '',
  trigger: { node_type: 'host', property_match: { docker_socket_accessible: true } },
  produces: [{ edge_type: 'ADMIN_TO', source_selector: 'session_holders_on_host', target_selector: 'trigger_node', confidence: 0.8 }],
};

const RULE_NFS_ROOT_SQUASH: InferenceRule = {
  id: 'rule-nfs-root-squash',
  name: 'NFS no_root_squash enables privilege escalation',
  description: '',
  trigger: { node_type: 'host', property_match: { no_root_squash: true } },
  produces: [{ edge_type: 'ADMIN_TO', source_selector: 'session_holders_on_host', target_selector: 'trigger_node', confidence: 0.7 }],
};

const RULE_SSH_KEY_REUSE: InferenceRule = {
  id: 'rule-ssh-key-reuse',
  name: 'SSH key reuse across services',
  description: '',
  trigger: { node_type: 'credential', property_match: { cred_type: 'ssh_key' } },
  produces: [{ edge_type: 'POTENTIAL_AUTH', source_selector: 'trigger_node', target_selector: 'ssh_services', confidence: 0.5 }],
};

const RULE_MSSQL_LINKED: InferenceRule = {
  id: 'rule-mssql-linked-server',
  name: 'MSSQL linked server implies host reachability',
  description: '',
  trigger: { node_type: 'service', property_match: { service_name: 'mssql' } },
  produces: [{ edge_type: 'REACHABLE', source_selector: 'parent_host', target_selector: 'linked_server_hosts', confidence: 0.8 }],
};

describe('InferenceEngine', () => {
  // =============================================
  // rule-kerberos-domain
  // =============================================
  describe('rule-kerberos-domain', () => {
    it('infers MEMBER_OF_DOMAIN from Kerberos service via hostname suffix', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-test-local', { type: 'domain', domain_name: 'test.local' });
      addNode(graph, 'host-10-10-10-1', { type: 'host', ip: '10.10.10.1', hostname: 'dc01.test.local' });
      addNode(graph, 'svc-kerb', { type: 'service', service_name: 'kerberos', port: 88 });
      addEdge(graph, 'host-10-10-10-1', 'svc-kerb', 'RUNS');

      const engine = buildEngine(graph, [RULE_KERBEROS_DOMAIN]);
      const inferred = engine.runRules('svc-kerb');

      expect(inferred.length).toBeGreaterThan(0);
      // Verify the edge exists
      const edges = graph.edges('host-10-10-10-1', 'domain-test-local');
      expect(edges.some(e => graph.getEdgeAttributes(e).type === 'MEMBER_OF_DOMAIN')).toBe(true);
    });

    it('does NOT infer MEMBER_OF_DOMAIN without matching hostname', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-test-local', { type: 'domain', domain_name: 'test.local' });
      addNode(graph, 'host-10-10-10-1', { type: 'host', ip: '10.10.10.1' }); // no hostname
      addNode(graph, 'svc-kerb', { type: 'service', service_name: 'kerberos', port: 88 });
      addEdge(graph, 'host-10-10-10-1', 'svc-kerb', 'RUNS');

      const engine = buildEngine(graph, [RULE_KERBEROS_DOMAIN]);
      const inferred = engine.runRules('svc-kerb');

      expect(inferred.length).toBe(0);
    });

    it('matches domain via dot-boundary only (no suffix substring)', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-test-local', { type: 'domain', domain_name: 'test.local' });
      addNode(graph, 'domain-eviltest-local', { type: 'domain', domain_name: 'eviltest.local' });
      addNode(graph, 'host-10-10-10-3', { type: 'host', ip: '10.10.10.3', hostname: 'dc01.eviltest.local' });
      addNode(graph, 'svc-kerb', { type: 'service', service_name: 'kerberos', port: 88 });
      addEdge(graph, 'host-10-10-10-3', 'svc-kerb', 'RUNS');

      const engine = buildEngine(graph, [RULE_KERBEROS_DOMAIN]);
      const inferred = engine.runRules('svc-kerb');

      // Should match eviltest.local, NOT test.local
      const edges = graph.edges('host-10-10-10-3', 'domain-eviltest-local');
      expect(edges.some(e => graph.getEdgeAttributes(e).type === 'MEMBER_OF_DOMAIN')).toBe(true);
      const wrongEdges = graph.edges('host-10-10-10-3', 'domain-test-local');
      expect(wrongEdges.some(e => graph.getEdgeAttributes(e).type === 'MEMBER_OF_DOMAIN')).toBe(false);
    });
  });

  // =============================================
  // rule-smb-signing-relay
  // =============================================
  describe('rule-smb-signing-relay', () => {
    it('infers RELAY_TARGET from SMB signing disabled + compromised host', () => {
      const graph = makeGraph();
      addNode(graph, 'host-10-10-10-1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'user-attacker', { type: 'user' });
      addEdge(graph, 'user-attacker', 'host-10-10-10-1', 'HAS_SESSION');

      addNode(graph, 'host-10-10-10-2', { type: 'host', ip: '10.10.10.2' });
      addNode(graph, 'svc-smb', { type: 'service', service_name: 'smb', smb_signing: false, port: 445 });
      addEdge(graph, 'host-10-10-10-2', 'svc-smb', 'RUNS');

      const engine = buildEngine(graph, [RULE_SMB_RELAY]);
      const inferred = engine.runRules('svc-smb');

      expect(inferred.length).toBeGreaterThan(0);
    });

    it('does NOT infer RELAY_TARGET when smb_signing is not false', () => {
      const graph = makeGraph();
      addNode(graph, 'host-10-10-10-1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'user-attacker', { type: 'user' });
      addEdge(graph, 'user-attacker', 'host-10-10-10-1', 'HAS_SESSION');

      addNode(graph, 'host-10-10-10-2', { type: 'host', ip: '10.10.10.2' });
      addNode(graph, 'svc-smb', { type: 'service', service_name: 'smb', port: 445 }); // no smb_signing
      addEdge(graph, 'host-10-10-10-2', 'svc-smb', 'RUNS');

      const engine = buildEngine(graph, [RULE_SMB_RELAY]);
      const inferred = engine.runRules('svc-smb');

      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // rule-cred-fanout (POTENTIAL_AUTH)
  // =============================================
  describe('rule-cred-fanout', () => {
    it('infers POTENTIAL_AUTH for new NTLM credential to same-domain services', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-test-local', { type: 'domain', domain_name: 'test.local' });
      addNode(graph, 'host-10-10-10-1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'svc-smb', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-10-10-10-1', 'svc-smb', 'RUNS');
      addEdge(graph, 'host-10-10-10-1', 'domain-test-local', 'MEMBER_OF_DOMAIN');

      addNode(graph, 'user-jdoe', { type: 'user', username: 'jdoe', domain_name: 'test.local' });
      addNode(graph, 'cred-jdoe', {
        type: 'credential',
        cred_type: 'ntlm',
        cred_material_kind: 'ntlm_hash',
        cred_usable_for_auth: true,
        cred_value: 'aabbccdd',
        cred_user: 'jdoe',
        cred_domain: 'test.local',
      });
      addEdge(graph, 'user-jdoe', 'cred-jdoe', 'OWNS_CRED');
      addEdge(graph, 'user-jdoe', 'domain-test-local', 'MEMBER_OF_DOMAIN');

      const engine = buildEngine(graph, [RULE_CRED_FANOUT]);
      const inferred = engine.runRules('cred-jdoe');

      expect(inferred.length).toBeGreaterThan(0);
      const edges = graph.edges('cred-jdoe', 'svc-smb');
      expect(edges.some(e => graph.getEdgeAttributes(e).type === 'POTENTIAL_AUTH')).toBe(true);
    });

    it('does NOT fan out credential across domains', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-test-local', { type: 'domain', domain_name: 'test.local' });
      addNode(graph, 'domain-other-local', { type: 'domain', domain_name: 'other.local' });
      // Service in other.local
      addNode(graph, 'host-10-10-10-2', { type: 'host', ip: '10.10.10.2' });
      addNode(graph, 'svc-other-smb', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-10-10-10-2', 'svc-other-smb', 'RUNS');
      addEdge(graph, 'host-10-10-10-2', 'domain-other-local', 'MEMBER_OF_DOMAIN');

      // Credential in test.local
      addNode(graph, 'user-jdoe', { type: 'user', username: 'jdoe', domain_name: 'test.local' });
      addNode(graph, 'cred-jdoe', {
        type: 'credential',
        cred_type: 'ntlm',
        cred_material_kind: 'ntlm_hash',
        cred_usable_for_auth: true,
        cred_value: 'aabbccdd',
        cred_user: 'jdoe',
        cred_domain: 'test.local',
      });
      addEdge(graph, 'user-jdoe', 'cred-jdoe', 'OWNS_CRED');
      addEdge(graph, 'user-jdoe', 'domain-test-local', 'MEMBER_OF_DOMAIN');

      const engine = buildEngine(graph, [RULE_CRED_FANOUT]);
      const inferred = engine.runRules('cred-jdoe');

      // Should NOT create edge to other.local service
      const edges = graph.edges('cred-jdoe', 'svc-other-smb');
      expect(edges.some(e => graph.getEdgeAttributes(e).type === 'POTENTIAL_AUTH')).toBe(false);
    });
  });

  // =============================================
  // rule-suid-privesc
  // =============================================
  describe('rule-suid-privesc', () => {
    it('infers ADMIN_TO from SUID root + HAS_SESSION', () => {
      const graph = makeGraph();
      addNode(graph, 'host-linux', { type: 'host', has_suid_root: true, os: 'Linux' });
      addNode(graph, 'user-attacker', { type: 'user' });
      addEdge(graph, 'user-attacker', 'host-linux', 'HAS_SESSION');

      const engine = buildEngine(graph, [RULE_SUID_PRIVESC]);
      const inferred = engine.runRules('host-linux');

      expect(inferred.length).toBeGreaterThan(0);
      const edges = graph.edges('user-attacker', 'host-linux');
      expect(edges.some(e => graph.getEdgeAttributes(e).type === 'ADMIN_TO')).toBe(true);
    });

    it('does NOT infer ADMIN_TO without has_suid_root', () => {
      const graph = makeGraph();
      addNode(graph, 'host-linux', { type: 'host', os: 'Linux' }); // no has_suid_root
      addNode(graph, 'user-attacker', { type: 'user' });
      addEdge(graph, 'user-attacker', 'host-linux', 'HAS_SESSION');

      const engine = buildEngine(graph, [RULE_SUID_PRIVESC]);
      const inferred = engine.runRules('host-linux');

      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // rule-docker-escape
  // =============================================
  describe('rule-docker-escape', () => {
    it('infers ADMIN_TO from docker_socket_accessible + HAS_SESSION', () => {
      const graph = makeGraph();
      addNode(graph, 'host-docker', { type: 'host', docker_socket_accessible: true });
      addNode(graph, 'user-attacker', { type: 'user' });
      addEdge(graph, 'user-attacker', 'host-docker', 'HAS_SESSION');

      const engine = buildEngine(graph, [RULE_DOCKER_ESCAPE]);
      const inferred = engine.runRules('host-docker');

      expect(inferred.length).toBeGreaterThan(0);
    });
  });

  // =============================================
  // rule-nfs-root-squash
  // =============================================
  describe('rule-nfs-root-squash', () => {
    it('infers ADMIN_TO from no_root_squash + HAS_SESSION', () => {
      const graph = makeGraph();
      addNode(graph, 'host-nfs', { type: 'host', no_root_squash: true });
      addNode(graph, 'user-attacker', { type: 'user' });
      addEdge(graph, 'user-attacker', 'host-nfs', 'HAS_SESSION');

      const engine = buildEngine(graph, [RULE_NFS_ROOT_SQUASH]);
      const inferred = engine.runRules('host-nfs');

      expect(inferred.length).toBeGreaterThan(0);
    });
  });

  // =============================================
  // rule-ssh-key-reuse
  // =============================================
  describe('rule-ssh-key-reuse', () => {
    it('infers POTENTIAL_AUTH from SSH key to all SSH services', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'svc-ssh-1', { type: 'service', service_name: 'ssh', port: 22 });
      addEdge(graph, 'host-1', 'svc-ssh-1', 'RUNS');
      addNode(graph, 'host-2', { type: 'host', ip: '10.10.10.2' });
      addNode(graph, 'svc-ssh-2', { type: 'service', service_name: 'ssh', port: 22 });
      addEdge(graph, 'host-2', 'svc-ssh-2', 'RUNS');

      addNode(graph, 'cred-ssh', {
        type: 'credential',
        cred_type: 'ssh_key',
        cred_material_kind: 'ssh_key',
        cred_usable_for_auth: true,
        cred_value: 'ssh-rsa AAAA...',
        cred_user: 'root',
      });

      const engine = buildEngine(graph, [RULE_SSH_KEY_REUSE]);
      const inferred = engine.runRules('cred-ssh');

      expect(inferred.length).toBe(2); // One per SSH service
    });

    it('does NOT target non-SSH services', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'svc-smb', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-smb', 'RUNS');

      addNode(graph, 'cred-ssh', {
        type: 'credential',
        cred_type: 'ssh_key',
        cred_material_kind: 'ssh_key',
        cred_usable_for_auth: true,
        cred_value: 'ssh-rsa AAAA...',
        cred_user: 'root',
      });

      const engine = buildEngine(graph, [RULE_SSH_KEY_REUSE]);
      const inferred = engine.runRules('cred-ssh');

      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // rule-mssql-linked-server
  // =============================================
  describe('rule-mssql-linked-server', () => {
    it('infers REACHABLE from MSSQL linked_servers to matching hosts', () => {
      const graph = makeGraph();
      addNode(graph, 'host-10-10-10-1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'svc-mssql', { type: 'service', service_name: 'mssql', port: 1433, linked_servers: ['db02.test.local'] });
      addEdge(graph, 'host-10-10-10-1', 'svc-mssql', 'RUNS');

      addNode(graph, 'host-10-10-10-5', { type: 'host', ip: '10.10.10.5', hostname: 'db02.test.local' });

      const engine = buildEngine(graph, [RULE_MSSQL_LINKED]);
      const inferred = engine.runRules('svc-mssql');

      expect(inferred.length).toBeGreaterThan(0);
      const edges = graph.edges('host-10-10-10-1', 'host-10-10-10-5');
      expect(edges.some(e => graph.getEdgeAttributes(e).type === 'REACHABLE')).toBe(true);
    });

    it('does NOT produce REACHABLE when no linked_servers match hosts', () => {
      const graph = makeGraph();
      addNode(graph, 'host-10-10-10-1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'svc-mssql', { type: 'service', service_name: 'mssql', port: 1433 }); // no linked_servers
      addEdge(graph, 'host-10-10-10-1', 'svc-mssql', 'RUNS');

      const engine = buildEngine(graph, [RULE_MSSQL_LINKED]);
      const inferred = engine.runRules('svc-mssql');

      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // addRule deduplication
  // =============================================
  describe('addRule', () => {
    it('deduplicates rules by name', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const engine = new InferenceEngine(ctx, (() => ({ id: '', isNew: true })) as any, () => null, (() => []) as any);

      const rule1: InferenceRule = {
        id: 'custom-rule-1',
        name: 'My Custom Rule',
        description: 'v1',
        trigger: { node_type: 'host' },
        produces: [{ edge_type: 'RELATED', source_selector: 'trigger_node', target_selector: 'trigger_node', confidence: 0.5 }],
      };
      const rule2: InferenceRule = {
        id: 'custom-rule-2',
        name: 'My Custom Rule', // same name
        description: 'v2',
        trigger: { node_type: 'host' },
        produces: [{ edge_type: 'RELATED', source_selector: 'trigger_node', target_selector: 'trigger_node', confidence: 0.9 }],
      };

      engine.addRule(rule1);
      engine.addRule(rule2);

      // Should have exactly one rule
      expect(ctx.inferenceRules.length).toBe(1);
      // Should be the updated version
      expect(ctx.inferenceRules[0].description).toBe('v2');
    });

    it('deduplicates rules by ID', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const engine = new InferenceEngine(ctx, (() => ({ id: '', isNew: true })) as any, () => null, (() => []) as any);

      const rule: InferenceRule = {
        id: 'custom-rule-1',
        name: 'Rule A',
        description: '',
        trigger: { node_type: 'host' },
        produces: [{ edge_type: 'RELATED', source_selector: 'trigger_node', target_selector: 'trigger_node', confidence: 0.5 }],
      };

      engine.addRule(rule);
      engine.addRule(rule); // same ID again

      expect(ctx.inferenceRules.length).toBe(1);
    });
  });

  // =============================================
  // backfillRule
  // =============================================
  describe('backfillRule', () => {
    it('applies rule to all matching existing nodes', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-test-local', { type: 'domain', domain_name: 'test.local' });
      // Two hosts with Kerberos services already present
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1', hostname: 'dc01.test.local' });
      addNode(graph, 'svc-kerb-1', { type: 'service', service_name: 'kerberos', port: 88 });
      addEdge(graph, 'host-1', 'svc-kerb-1', 'RUNS');

      addNode(graph, 'host-2', { type: 'host', ip: '10.10.10.2', hostname: 'dc02.test.local' });
      addNode(graph, 'svc-kerb-2', { type: 'service', service_name: 'kerberos', port: 88 });
      addEdge(graph, 'host-2', 'svc-kerb-2', 'RUNS');

      const engine = buildEngine(graph, [RULE_KERBEROS_DOMAIN]);
      const inferred = engine.backfillRule(RULE_KERBEROS_DOMAIN);

      expect(inferred.length).toBe(2); // one per host
    });
  });

  // =============================================
  // compatible_services_same_domain selector: non-authoritative domain suppresses global fanout
  // =============================================
  describe('compatible_services_same_domain with parser_context', () => {
    it('suppresses global fanout when cred_domain_source is parser_context', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-test-local', { type: 'domain', domain_name: 'test.local' });
      addNode(graph, 'host-10-10-10-1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'svc-smb', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-10-10-10-1', 'svc-smb', 'RUNS');
      addEdge(graph, 'host-10-10-10-1', 'domain-test-local', 'MEMBER_OF_DOMAIN');

      // Credential with parser_context domain (non-authoritative)
      addNode(graph, 'user-admin', { type: 'user', username: 'Administrator' });
      addNode(graph, 'cred-admin', {
        type: 'credential',
        cred_type: 'ntlm',
        cred_material_kind: 'ntlm_hash',
        cred_usable_for_auth: true,
        cred_value: 'aad3b435b51404ee',
        cred_user: 'Administrator',
        cred_domain: 'test.local',
        cred_domain_source: 'parser_context',
      });
      addEdge(graph, 'user-admin', 'cred-admin', 'OWNS_CRED');

      const engine = buildEngine(graph, [RULE_CRED_FANOUT]);
      const inferred = engine.runRules('cred-admin');

      // parser_context suppresses both domain-scoped AND global fallback
      expect(inferred.length).toBe(0);
    });
  });
});
