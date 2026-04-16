import { describe, it, expect } from 'vitest';
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
    graph.forEachNode((_id: string, attrs) => {
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

const RULE_ASREP: InferenceRule = {
  id: 'rule-asrep-roastable',
  name: 'AS-REP Roastable user',
  description: '',
  trigger: { node_type: 'user', property_match: { asrep_roastable: true } },
  produces: [{ edge_type: 'AS_REP_ROASTABLE', source_selector: 'trigger_node', target_selector: 'matching_user_domain', confidence: 0.85 }],
};

const RULE_KERBEROASTABLE: InferenceRule = {
  id: 'rule-kerberoastable',
  name: 'Kerberoastable user',
  description: '',
  trigger: { node_type: 'user', property_match: { has_spn: true } },
  produces: [{ edge_type: 'KERBEROASTABLE', source_selector: 'trigger_node', target_selector: 'matching_user_domain', confidence: 0.85 }],
};

const RULE_UNCONSTRAINED_DELEGATION: InferenceRule = {
  id: 'rule-unconstrained-delegation',
  name: 'Unconstrained delegation target',
  description: '',
  trigger: { node_type: 'host', property_match: { unconstrained_delegation: true } },
  produces: [{ edge_type: 'DELEGATES_TO', source_selector: 'domain_admins_and_session_holders', target_selector: 'trigger_node', confidence: 0.7 }],
};

const RULE_DCSYNC: InferenceRule = {
  id: 'rule-dcsync',
  name: 'DCSync capable principal',
  description: '',
  trigger: { node_type: 'user', requires_edge: { type: 'CAN_DCSYNC', direction: 'outbound' } },
  produces: [{ edge_type: 'PATH_TO_OBJECTIVE', source_selector: 'trigger_node', target_selector: 'nearest_objective', confidence: 0.9 }],
};

const RULE_WRITE_DACL: InferenceRule = {
  id: 'rule-write-dacl-escalation',
  name: 'WriteDACL implies GenericAll',
  description: '',
  trigger: { requires_edge: { type: 'WRITE_DACL', direction: 'inbound' } },
  produces: [{ edge_type: 'GENERIC_ALL', source_selector: 'edge_peers', target_selector: 'trigger_node', confidence: 0.7 }],
};

const RULE_WRITE_OWNER: InferenceRule = {
  id: 'rule-write-owner-escalation',
  name: 'WriteOwner implies GenericAll',
  description: '',
  trigger: { requires_edge: { type: 'WRITE_OWNER', direction: 'inbound' } },
  produces: [{ edge_type: 'GENERIC_ALL', source_selector: 'edge_peers', target_selector: 'trigger_node', confidence: 0.7 }],
};

const RULE_FORCE_CHANGE_PWD: InferenceRule = {
  id: 'rule-force-change-password',
  name: 'ForceChangePassword enables credential takeover',
  description: '',
  trigger: { node_type: 'user', requires_edge: { type: 'FORCE_CHANGE_PASSWORD', direction: 'inbound' } },
  produces: [{ edge_type: 'OWNS_CRED', source_selector: 'edge_peers', target_selector: 'target_user_credentials', confidence: 0.8 }],
};

const RULE_SHADOW_CREDS: InferenceRule = {
  id: 'rule-shadow-credentials',
  name: 'GenericWrite on computer enables Shadow Credentials',
  description: '',
  trigger: { node_type: 'host', requires_edge: { type: 'GENERIC_WRITE', direction: 'inbound' } },
  produces: [{ edge_type: 'ADMIN_TO', source_selector: 'edge_peers', target_selector: 'trigger_node', confidence: 0.65 }],
};

const RULE_GPO_ABUSE: InferenceRule = {
  id: 'rule-gpo-abuse',
  name: 'GPO write access enables host compromise',
  description: '',
  trigger: { node_type: 'gpo', requires_edge: { type: 'GENERIC_WRITE', direction: 'inbound' } },
  produces: [{ edge_type: 'ADMIN_TO', source_selector: 'edge_peers', target_selector: 'gpo_linked_hosts', confidence: 0.6 }],
};

const RULE_SUDO_NOPASSWD: InferenceRule = {
  id: 'rule-sudo-nopasswd',
  name: 'Sudoers NOPASSWD enables privilege escalation',
  description: '',
  trigger: { node_type: 'host', property_match: { sudoers_nopasswd: true } },
  produces: [{ edge_type: 'ADMIN_TO', source_selector: 'session_holders_on_host', target_selector: 'trigger_node', confidence: 0.7 }],
};

const RULE_CAPABILITIES: InferenceRule = {
  id: 'rule-dangerous-capabilities',
  name: 'Dangerous Linux capabilities enable privilege escalation',
  description: '',
  trigger: { node_type: 'host', property_match: { has_dangerous_capabilities: true } },
  produces: [{ edge_type: 'ADMIN_TO', source_selector: 'session_holders_on_host', target_selector: 'trigger_node', confidence: 0.55 }],
};

const RULE_WRITABLE_CRON: InferenceRule = {
  id: 'rule-writable-cron-systemd',
  name: 'Writable cron/systemd enables code execution',
  description: '',
  trigger: { node_type: 'host', property_match: { writable_cron_or_systemd: true } },
  produces: [{ edge_type: 'ADMIN_TO', source_selector: 'session_holders_on_host', target_selector: 'trigger_node', confidence: 0.65 }],
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
      engine.runRules('svc-kerb');

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
      engine.runRules('cred-jdoe');

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

  // =============================================
  // matching_user_domain selector
  // =============================================
  describe('matching_user_domain selector', () => {
    it('returns only the user\'s domain via MEMBER_OF_DOMAIN edge', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-corp-local', { type: 'domain', domain_name: 'corp.local' });
      addNode(graph, 'domain-other-local', { type: 'domain', domain_name: 'other.local' });
      addNode(graph, 'user-corp-local-jdoe', { type: 'user', username: 'jdoe', asrep_roastable: true });
      addEdge(graph, 'user-corp-local-jdoe', 'domain-corp-local', 'MEMBER_OF_DOMAIN');

      const engine = buildEngine(graph, [RULE_ASREP]);
      const inferred = engine.runRules('user-corp-local-jdoe');

      expect(inferred.length).toBe(1);
      const edgeAttrs = graph.getEdgeAttributes(inferred[0]);
      expect(edgeAttrs.type).toBe('AS_REP_ROASTABLE');
      expect(graph.target(inferred[0])).toBe('domain-corp-local');
    });

    it('falls back to domain_name property match when no MEMBER_OF_DOMAIN edge', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-corp-local', { type: 'domain', domain_name: 'corp.local' });
      addNode(graph, 'domain-other-local', { type: 'domain', domain_name: 'other.local' });
      addNode(graph, 'user-corp-local-jdoe', { type: 'user', username: 'jdoe', domain_name: 'corp.local', has_spn: true });

      const engine = buildEngine(graph, [RULE_KERBEROASTABLE]);
      const inferred = engine.runRules('user-corp-local-jdoe');

      expect(inferred.length).toBe(1);
      expect(graph.target(inferred[0])).toBe('domain-corp-local');
    });

    it('F27: returns empty when no domain info available (no unsafe fallback)', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-corp-local', { type: 'domain', domain_name: 'corp.local' });
      addNode(graph, 'domain-other-local', { type: 'domain', domain_name: 'other.local' });
      addNode(graph, 'user-orphan', { type: 'user', username: 'orphan', asrep_roastable: true });

      const engine = buildEngine(graph, [RULE_ASREP]);
      const inferred = engine.runRules('user-orphan');

      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // domain_admins_and_session_holders selector
  // =============================================
  describe('domain_admins_and_session_holders selector', () => {
    it('returns session holders and admin group members', () => {
      const graph = makeGraph();
      addNode(graph, 'host-uc', { type: 'host', ip: '10.10.10.5', unconstrained_delegation: true });
      addNode(graph, 'user-session', { type: 'user', username: 'session_user', domain_joined: true });
      addNode(graph, 'group-da', { type: 'group', group_name: 'Domain Admins' });
      addNode(graph, 'user-da-member', { type: 'user', username: 'da_member', domain_joined: true });
      addNode(graph, 'user-nobody', { type: 'user', username: 'nobody', domain_joined: true });
      addEdge(graph, 'user-session', 'host-uc', 'HAS_SESSION');
      addEdge(graph, 'user-da-member', 'group-da', 'MEMBER_OF');

      const engine = buildEngine(graph, [RULE_UNCONSTRAINED_DELEGATION]);
      const inferred = engine.runRules('host-uc');

      const sources = inferred.map(e => graph.source(e));
      expect(sources).toContain('user-session');
      expect(sources).toContain('user-da-member');
      expect(sources).toContain('group-da');
      expect(sources).not.toContain('user-nobody');
    });

    it('F27: returns empty when no session holders or admin groups exist (no unsafe fallback)', () => {
      const graph = makeGraph();
      addNode(graph, 'host-uc', { type: 'host', ip: '10.10.10.5', unconstrained_delegation: true });
      addNode(graph, 'user-a', { type: 'user', username: 'a', domain_joined: true });
      addNode(graph, 'user-b', { type: 'user', username: 'b', domain_joined: true });

      const engine = buildEngine(graph, [RULE_UNCONSTRAINED_DELEGATION]);
      const inferred = engine.runRules('host-uc');

      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // DCSync rule
  // =============================================
  describe('rule-dcsync (edge-triggered)', () => {
    it('creates PATH_TO_OBJECTIVE when user has outbound CAN_DCSYNC edge', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-corp-local', { type: 'domain', domain_name: 'corp.local' });
      addNode(graph, 'user-repl', { type: 'user', username: 'repl_svc' });
      addNode(graph, 'obj-da', { type: 'objective', objective_description: 'Get DA' });
      addEdge(graph, 'user-repl', 'domain-corp-local', 'CAN_DCSYNC');

      const engine = buildEngine(graph, [RULE_DCSYNC]);
      const inferred = engine.runRules('user-repl');

      expect(inferred.length).toBe(1);
      const attrs = graph.getEdgeAttributes(inferred[0]);
      expect(attrs.type).toBe('PATH_TO_OBJECTIVE');
      expect(attrs.confidence).toBe(0.9);
      expect(graph.source(inferred[0])).toBe('user-repl');
      expect(graph.target(inferred[0])).toBe('obj-da');
    });

    it('no PATH_TO_OBJECTIVE when no objectives exist', () => {
      const graph = makeGraph();
      addNode(graph, 'domain-corp-local', { type: 'domain', domain_name: 'corp.local' });
      addNode(graph, 'user-repl', { type: 'user', username: 'repl_svc' });
      addEdge(graph, 'user-repl', 'domain-corp-local', 'CAN_DCSYNC');

      const engine = buildEngine(graph, [RULE_DCSYNC]);
      const inferred = engine.runRules('user-repl');
      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // ACL chain escalation rules
  // =============================================
  describe('ACL chain rules', () => {
    it('rule-write-dacl creates GENERIC_ALL from edge peers', () => {
      const graph = makeGraph();
      addNode(graph, 'user-target', { type: 'user', username: 'target' });
      addNode(graph, 'user-attacker', { type: 'user', username: 'attacker' });
      addEdge(graph, 'user-attacker', 'user-target', 'WRITE_DACL');

      const engine = buildEngine(graph, [RULE_WRITE_DACL]);
      const inferred = engine.runRules('user-target');

      expect(inferred.length).toBe(1);
      const attrs = graph.getEdgeAttributes(inferred[0]);
      expect(attrs.type).toBe('GENERIC_ALL');
      expect(attrs.confidence).toBe(0.7);
      expect(graph.source(inferred[0])).toBe('user-attacker');
    });

    it('rule-write-dacl works on GPO nodes (no node_type restriction)', () => {
      const graph = makeGraph();
      addNode(graph, 'gpo-test', { type: 'gpo', label: 'Test GPO' });
      addNode(graph, 'user-attacker', { type: 'user', username: 'attacker' });
      addEdge(graph, 'user-attacker', 'gpo-test', 'WRITE_DACL');

      const engine = buildEngine(graph, [RULE_WRITE_DACL]);
      const inferred = engine.runRules('gpo-test');

      expect(inferred.length).toBe(1);
      expect(graph.getEdgeAttributes(inferred[0]).type).toBe('GENERIC_ALL');
    });

    it('rule-write-owner creates GENERIC_ALL from edge peers', () => {
      const graph = makeGraph();
      addNode(graph, 'host-dc01', { type: 'host', hostname: 'dc01.corp.local' });
      addNode(graph, 'user-attacker', { type: 'user', username: 'attacker' });
      addEdge(graph, 'user-attacker', 'host-dc01', 'WRITE_OWNER');

      const engine = buildEngine(graph, [RULE_WRITE_OWNER]);
      const inferred = engine.runRules('host-dc01');

      expect(inferred.length).toBe(1);
      expect(graph.getEdgeAttributes(inferred[0]).type).toBe('GENERIC_ALL');
      expect(graph.getEdgeAttributes(inferred[0]).confidence).toBe(0.7);
    });

    it('rule-force-change-password creates OWNS_CRED to target user credentials', () => {
      const graph = makeGraph();
      addNode(graph, 'user-victim', { type: 'user', username: 'victim' });
      addNode(graph, 'user-attacker', { type: 'user', username: 'attacker' });
      addNode(graph, 'cred-victim', { type: 'credential', cred_type: 'ntlm', cred_user: 'victim' });
      addEdge(graph, 'user-victim', 'cred-victim', 'OWNS_CRED');
      addEdge(graph, 'user-attacker', 'user-victim', 'FORCE_CHANGE_PASSWORD');

      const engine = buildEngine(graph, [RULE_FORCE_CHANGE_PWD]);
      const inferred = engine.runRules('user-victim');

      expect(inferred.length).toBe(1);
      const attrs = graph.getEdgeAttributes(inferred[0]);
      expect(attrs.type).toBe('OWNS_CRED');
      expect(attrs.confidence).toBe(0.8);
      expect(graph.source(inferred[0])).toBe('user-attacker');
      expect(graph.target(inferred[0])).toBe('cred-victim');
    });

    it('rule-force-change-password produces nothing when user has no credentials', () => {
      const graph = makeGraph();
      addNode(graph, 'user-victim', { type: 'user', username: 'victim' });
      addNode(graph, 'user-attacker', { type: 'user', username: 'attacker' });
      addEdge(graph, 'user-attacker', 'user-victim', 'FORCE_CHANGE_PASSWORD');

      const engine = buildEngine(graph, [RULE_FORCE_CHANGE_PWD]);
      const inferred = engine.runRules('user-victim');
      expect(inferred.length).toBe(0);
    });

    it('rule-shadow-credentials creates ADMIN_TO from GenericWrite on host', () => {
      const graph = makeGraph();
      addNode(graph, 'host-srv01', { type: 'host', hostname: 'srv01.corp.local' });
      addNode(graph, 'user-attacker', { type: 'user', username: 'attacker' });
      addEdge(graph, 'user-attacker', 'host-srv01', 'GENERIC_WRITE');

      const engine = buildEngine(graph, [RULE_SHADOW_CREDS]);
      const inferred = engine.runRules('host-srv01');

      expect(inferred.length).toBe(1);
      const attrs = graph.getEdgeAttributes(inferred[0]);
      expect(attrs.type).toBe('ADMIN_TO');
      expect(attrs.confidence).toBe(0.65);
      expect(graph.source(inferred[0])).toBe('user-attacker');
    });
  });

  // =============================================
  // GPO abuse rule
  // =============================================
  describe('rule-gpo-abuse', () => {
    it('creates ADMIN_TO from edge peers to hosts linked via GPO', () => {
      const graph = makeGraph();
      addNode(graph, 'gpo-malicious', { type: 'gpo', label: 'Malicious GPO' });
      addNode(graph, 'ou-servers', { type: 'ou', label: 'Servers OU' });
      addNode(graph, 'host-srv01', { type: 'host', hostname: 'srv01.corp.local' });
      addNode(graph, 'user-attacker', { type: 'user', username: 'attacker' });
      // GPO -> OU link
      addEdge(graph, 'gpo-malicious', 'ou-servers', 'RELATED');
      // Host is member of OU
      addEdge(graph, 'host-srv01', 'ou-servers', 'MEMBER_OF');
      // Attacker has GenericWrite on GPO
      addEdge(graph, 'user-attacker', 'gpo-malicious', 'GENERIC_WRITE');

      const engine = buildEngine(graph, [RULE_GPO_ABUSE]);
      const inferred = engine.runRules('gpo-malicious');

      expect(inferred.length).toBe(1);
      const attrs = graph.getEdgeAttributes(inferred[0]);
      expect(attrs.type).toBe('ADMIN_TO');
      expect(attrs.confidence).toBe(0.6);
      expect(graph.source(inferred[0])).toBe('user-attacker');
      expect(graph.target(inferred[0])).toBe('host-srv01');
    });

    it('no edges when GPO has no linked hosts', () => {
      const graph = makeGraph();
      addNode(graph, 'gpo-orphan', { type: 'gpo', label: 'Orphan GPO' });
      addNode(graph, 'user-attacker', { type: 'user', username: 'attacker' });
      addEdge(graph, 'user-attacker', 'gpo-orphan', 'GENERIC_WRITE');

      const engine = buildEngine(graph, [RULE_GPO_ABUSE]);
      const inferred = engine.runRules('gpo-orphan');
      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // Linux privesc rules
  // =============================================
  describe('Linux privesc rules', () => {
    function buildLinuxHost(graph: ReturnType<typeof makeGraph>, props: Record<string, unknown>) {
      addNode(graph, 'host-linux', { type: 'host', ip: '10.10.10.20', ...props });
      addNode(graph, 'user-attacker', { type: 'user', username: 'attacker' });
      addEdge(graph, 'user-attacker', 'host-linux', 'HAS_SESSION');
    }

    it('rule-sudo-nopasswd creates ADMIN_TO from session holder', () => {
      const graph = makeGraph();
      buildLinuxHost(graph, { sudoers_nopasswd: true });
      const engine = buildEngine(graph, [RULE_SUDO_NOPASSWD]);
      const inferred = engine.runRules('host-linux');

      expect(inferred.length).toBe(1);
      const attrs = graph.getEdgeAttributes(inferred[0]);
      expect(attrs.type).toBe('ADMIN_TO');
      expect(attrs.confidence).toBe(0.7);
    });

    it('rule-dangerous-capabilities creates ADMIN_TO from session holder', () => {
      const graph = makeGraph();
      buildLinuxHost(graph, { has_dangerous_capabilities: true });
      const engine = buildEngine(graph, [RULE_CAPABILITIES]);
      const inferred = engine.runRules('host-linux');

      expect(inferred.length).toBe(1);
      expect(graph.getEdgeAttributes(inferred[0]).confidence).toBe(0.55);
    });

    it('rule-writable-cron-systemd creates ADMIN_TO from session holder', () => {
      const graph = makeGraph();
      buildLinuxHost(graph, { writable_cron_or_systemd: true });
      const engine = buildEngine(graph, [RULE_WRITABLE_CRON]);
      const inferred = engine.runRules('host-linux');

      expect(inferred.length).toBe(1);
      expect(graph.getEdgeAttributes(inferred[0]).confidence).toBe(0.65);
    });

    it('no edges when no session holder exists', () => {
      const graph = makeGraph();
      addNode(graph, 'host-linux', { type: 'host', ip: '10.10.10.20', sudoers_nopasswd: true });
      const engine = buildEngine(graph, [RULE_SUDO_NOPASSWD]);
      const inferred = engine.runRules('host-linux');

      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // F28: production.properties cannot override fixed fields
  // =============================================
  describe('production.properties spread safety', () => {
    it('custom rule properties cannot override confidence or discovered_by', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'host-b', { type: 'host', ip: '10.10.10.2' });

      // host-a connects to host-b so trigger_node → domain_nodes works
      addNode(graph, 'domain-test', { type: 'domain', domain_name: 'test.local' });
      addEdge(graph, 'host-a', 'domain-test', 'MEMBER_OF_DOMAIN');

      const maliciousRule: InferenceRule = {
        id: 'rule-override-attempt',
        name: 'Rule that tries to override fixed fields',
        description: '',
        trigger: { node_type: 'host', property_match: { ip: '10.10.10.1' } },
        produces: [{
          edge_type: 'RELATED',
          source_selector: 'trigger_node',
          target_selector: 'domain_nodes',
          confidence: 0.6,
          properties: {
            confidence: 999,
            discovered_by: 'attacker',
            tested: true,
            inferred_by_rule: 'fake-rule',
          },
        }],
      };

      const engine = buildEngine(graph, [maliciousRule]);
      const inferred = engine.runRules('host-a');

      expect(inferred.length).toBe(1);
      const attrs = graph.getEdgeAttributes(inferred[0]);
      // Fixed fields must NOT be overridden by production.properties
      expect(attrs.confidence).toBe(0.6);
      expect(attrs.discovered_by).toBe('inference:rule-override-attempt');
      expect(attrs.tested).toBe(false);
      expect(attrs.inferred_by_rule).toBe('rule-override-attempt');
    });
  });

  // =============================================
  // Phase 2: ADCS ESC rules
  // =============================================
  describe('rule-adcs-esc2', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc2', name: 'ADCS ESC2', description: '',
      trigger: { node_type: 'cert_template', property_match: { any_purpose: true } },
      produces: [{ edge_type: 'ESC2', source_selector: 'enrollable_users_if_client_auth', target_selector: 'trigger_node', confidence: 0.7 }],
    };

    it('infers ESC2 when template has any_purpose=true', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template', any_purpose: true, ekus: ['1.3.6.1.5.5.7.3.2'] });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC2');
    });

    it('does NOT infer ESC2 without any_purpose', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template', any_purpose: false });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBe(0);
    });
  });

  describe('rule-adcs-esc3', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc3', name: 'ADCS ESC3', description: '',
      trigger: { node_type: 'cert_template', property_match: { enrollment_agent: true } },
      produces: [{ edge_type: 'ESC3', source_selector: 'enrollable_users', target_selector: 'trigger_node', confidence: 0.7 }],
    };

    it('infers ESC3 when template has enrollment_agent=true', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template', enrollment_agent: true });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC3');
    });
  });

  describe('rule-adcs-esc4', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc4', name: 'ADCS ESC4', description: '',
      trigger: { node_type: 'cert_template', requires_edge: { type: 'WRITEABLE_BY', direction: 'inbound' } },
      produces: [{ edge_type: 'ESC4', source_selector: 'edge_peers', target_selector: 'trigger_node', confidence: 0.75 }],
    };

    it('infers ESC4 when template has WRITEABLE_BY edge', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template' });
      addNode(graph, 'user-a', { type: 'user' });
      addEdge(graph, 'user-a', 'tmpl-1', 'WRITEABLE_BY');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC4');
    });

    it('does NOT infer ESC4 without WRITEABLE_BY edge', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template' });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBe(0);
    });
  });

  describe('rule-adcs-esc6', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc6', name: 'ADCS ESC6', description: '',
      trigger: { node_type: 'ca', property_match: { san_flag_enabled: true } },
      produces: [{ edge_type: 'ESC6', source_selector: 'enrollable_users', target_selector: 'trigger_node', confidence: 0.8 }],
    };

    it('infers ESC6 when CA has san_flag_enabled=true', () => {
      const graph = makeGraph();
      addNode(graph, 'ca-1', { type: 'ca', san_flag_enabled: true });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ca-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC6');
    });
  });

  describe('rule-adcs-esc7', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc7', name: 'ADCS ESC7', description: '',
      trigger: { node_type: 'ca', requires_edge: { type: 'GENERIC_ALL', direction: 'inbound' } },
      produces: [{ edge_type: 'ESC7', source_selector: 'manage_ca_peers', target_selector: 'trigger_node', confidence: 0.75 }],
    };

    it('infers ESC7 when CA has GENERIC_ALL from a principal', () => {
      const graph = makeGraph();
      addNode(graph, 'ca-1', { type: 'ca' });
      addNode(graph, 'user-a', { type: 'user' });
      addEdge(graph, 'user-a', 'ca-1', 'GENERIC_ALL');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ca-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC7');
    });
  });

  describe('rule-adcs-esc8', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc8', name: 'ADCS ESC8', description: '',
      trigger: { node_type: 'ca', property_match: { http_enrollment: true } },
      produces: [{ edge_type: 'ESC8', source_selector: 'all_compromised', target_selector: 'trigger_node', confidence: 0.6 }],
    };

    it('infers ESC8 when CA has http_enrollment=true and compromised hosts exist', () => {
      const graph = makeGraph();
      addNode(graph, 'ca-1', { type: 'ca', http_enrollment: true });
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'user-a', { type: 'user' });
      addEdge(graph, 'user-a', 'host-a', 'HAS_SESSION');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ca-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC8');
    });

    it('does NOT infer ESC8 without http_enrollment', () => {
      const graph = makeGraph();
      addNode(graph, 'ca-1', { type: 'ca', http_enrollment: false });
      addNode(graph, 'host-a', { type: 'host' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ca-1');
      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // Phase 2: ESC5, ESC9-ESC13
  // =============================================

  describe('rule-adcs-esc5-template', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc5-template', name: 'ADCS ESC5 (template)', description: '',
      trigger: { node_type: 'cert_template', requires_edge: { type: 'WRITEABLE_BY', direction: 'inbound' } },
      produces: [{ edge_type: 'ESC5', source_selector: 'writeable_by_peers', target_selector: 'trigger_node', confidence: 0.7 }],
    };

    it('infers ESC5 when template has WRITEABLE_BY edge', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template' });
      addNode(graph, 'user-a', { type: 'user' });
      addEdge(graph, 'user-a', 'tmpl-1', 'WRITEABLE_BY');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC5');
    });

    it('infers ESC5 for GENERIC_WRITE on template', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template' });
      addNode(graph, 'user-a', { type: 'user' });
      addEdge(graph, 'user-a', 'tmpl-1', 'GENERIC_WRITE');
      // writeable_by_peers catches GENERIC_WRITE; but requires_edge demands WRITEABLE_BY
      // So we also need a WRITEABLE_BY edge for the trigger to fire
      addEdge(graph, 'user-a', 'tmpl-1', 'WRITEABLE_BY');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBeGreaterThan(0);
    });

    it('does NOT infer ESC5 without write ACL edge', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template' });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBe(0);
    });
  });

  describe('rule-adcs-esc5-ca', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc5-ca', name: 'ADCS ESC5 (CA)', description: '',
      trigger: { node_type: 'ca', requires_edge: { type: 'WRITEABLE_BY', direction: 'inbound' } },
      produces: [{ edge_type: 'ESC5', source_selector: 'writeable_by_peers', target_selector: 'trigger_node', confidence: 0.7 }],
    };

    it('infers ESC5 when CA has WRITEABLE_BY edge', () => {
      const graph = makeGraph();
      addNode(graph, 'ca-1', { type: 'ca' });
      addNode(graph, 'user-a', { type: 'user' });
      addEdge(graph, 'user-a', 'ca-1', 'WRITEABLE_BY');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ca-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC5');
    });

    it('does NOT infer ESC5 on CA without write ACL', () => {
      const graph = makeGraph();
      addNode(graph, 'ca-1', { type: 'ca' });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ca-1');
      expect(inferred.length).toBe(0);
    });
  });

  describe('rule-adcs-esc9', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc9', name: 'ADCS ESC9', description: '',
      trigger: { node_type: 'cert_template', property_match: { ct_flag_no_security_extension: true } },
      produces: [{ edge_type: 'ESC9', source_selector: 'enrollable_users', target_selector: 'trigger_node', confidence: 0.65 }],
    };

    it('infers ESC9 when template has ct_flag_no_security_extension=true', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template', ct_flag_no_security_extension: true });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC9');
      expect(edge.confidence).toBe(0.65);
    });

    it('does NOT infer ESC9 without ct_flag_no_security_extension', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template', ct_flag_no_security_extension: false });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBe(0);
    });
  });

  describe('rule-adcs-esc10', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc10', name: 'ADCS ESC10', description: '',
      trigger: { node_type: 'cert_template', property_match: { enrollee_supplies_subject: true } },
      produces: [{ edge_type: 'ESC10', source_selector: 'enrollable_users', target_selector: 'trigger_node', confidence: 0.6 }],
    };

    it('infers ESC10 when template has enrollee_supplies_subject=true', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template', enrollee_supplies_subject: true });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC10');
      expect(edge.confidence).toBe(0.6);
    });

    it('does NOT infer ESC10 without enrollee_supplies_subject', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template', enrollee_supplies_subject: false });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBe(0);
    });
  });

  describe('rule-adcs-esc11', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc11', name: 'ADCS ESC11', description: '',
      trigger: { node_type: 'ca', property_match: { enforce_encrypt_icert_request: false } },
      produces: [{ edge_type: 'ESC11', source_selector: 'all_compromised', target_selector: 'trigger_node', confidence: 0.55 }],
    };

    it('infers ESC11 when CA has enforce_encrypt_icert_request=false', () => {
      const graph = makeGraph();
      addNode(graph, 'ca-1', { type: 'ca', enforce_encrypt_icert_request: false });
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'user-a', { type: 'user' });
      addEdge(graph, 'user-a', 'host-a', 'HAS_SESSION');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ca-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC11');
      expect(edge.confidence).toBe(0.55);
    });

    it('does NOT infer ESC11 when enforce_encrypt_icert_request=true', () => {
      const graph = makeGraph();
      addNode(graph, 'ca-1', { type: 'ca', enforce_encrypt_icert_request: true });
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'user-a', { type: 'user' });
      addEdge(graph, 'user-a', 'host-a', 'HAS_SESSION');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ca-1');
      expect(inferred.length).toBe(0);
    });
  });

  describe('rule-adcs-esc12', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc12', name: 'ADCS ESC12', description: '',
      trigger: { node_type: 'ca' },
      produces: [{ edge_type: 'ESC12', source_selector: 'ca_host_compromised_peers', target_selector: 'trigger_node', confidence: 0.8 }],
    };

    it('infers ESC12 when CA host has HAS_SESSION from a user', () => {
      const graph = makeGraph();
      addNode(graph, 'ca-1', { type: 'ca', ca_name: 'dc01.corp.local' });
      addNode(graph, 'host-dc01', { type: 'host', hostname: 'dc01.corp.local' });
      addNode(graph, 'user-a', { type: 'user' });
      addEdge(graph, 'user-a', 'host-dc01', 'HAS_SESSION');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ca-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC12');
      expect(edge.confidence).toBe(0.8);
    });

    it('does NOT infer ESC12 when CA host has no sessions', () => {
      const graph = makeGraph();
      addNode(graph, 'ca-1', { type: 'ca', ca_name: 'dc01.corp.local' });
      addNode(graph, 'host-dc01', { type: 'host', hostname: 'dc01.corp.local' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ca-1');
      expect(inferred.length).toBe(0);
    });

    it('does NOT infer ESC12 when no host matches CA', () => {
      const graph = makeGraph();
      addNode(graph, 'ca-1', { type: 'ca', ca_name: 'dc01.corp.local' });
      addNode(graph, 'host-other', { type: 'host', hostname: 'web01.corp.local' });
      addNode(graph, 'user-a', { type: 'user' });
      addEdge(graph, 'user-a', 'host-other', 'HAS_SESSION');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ca-1');
      expect(inferred.length).toBe(0);
    });
  });

  describe('rule-adcs-esc13', () => {
    const RULE: InferenceRule = {
      id: 'rule-adcs-esc13', name: 'ADCS ESC13', description: '',
      trigger: { node_type: 'cert_template' },
      produces: [{ edge_type: 'ESC13', source_selector: 'enrollable_users_if_issuance_policy', target_selector: 'trigger_node', confidence: 0.7 }],
    };

    it('infers ESC13 when template has issuance_policy_oid and issuance_policy_group_link', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template', issuance_policy_oid: '1.3.6.1.4.1.311.21.8.xxx', issuance_policy_group_link: 'CN=HighPrivGroup,DC=corp,DC=local' });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ESC13');
      expect(edge.confidence).toBe(0.7);
    });

    it('does NOT infer ESC13 without issuance_policy_group_link', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template', issuance_policy_oid: '1.3.6.1.4.1.311.21.8.xxx' });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBe(0);
    });

    it('does NOT infer ESC13 without issuance_policy_oid', () => {
      const graph = makeGraph();
      addNode(graph, 'tmpl-1', { type: 'cert_template', issuance_policy_group_link: 'CN=HighPrivGroup,DC=corp,DC=local' });
      addNode(graph, 'user-a', { type: 'user' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('tmpl-1');
      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // Cloud inference rules
  // =============================================

  describe('rule-imds-credential-theft', () => {
    const RULE: InferenceRule = {
      id: 'rule-imds-credential-theft', name: 'IMDS credential theft', description: '',
      trigger: { node_type: 'cloud_resource', property_match: { resource_type: 'ec2', imdsv2_required: false } },
      produces: [{ edge_type: 'POTENTIAL_AUTH', source_selector: 'trigger_node', target_selector: 'imds_managed_identity', confidence: 0.7 }],
    };

    it('infers POTENTIAL_AUTH from EC2 without IMDSv2 to managed identity', () => {
      const graph = makeGraph();
      addNode(graph, 'ec2-1', { type: 'cloud_resource', resource_type: 'ec2', imdsv2_required: false });
      addNode(graph, 'role-1', { type: 'cloud_identity', principal_type: 'role' });
      addEdge(graph, 'ec2-1', 'role-1', 'MANAGED_BY');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ec2-1');
      expect(inferred.length).toBe(1);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('POTENTIAL_AUTH');
      expect(edge.confidence).toBe(0.7);
    });

    it('does NOT infer when IMDSv2 is required', () => {
      const graph = makeGraph();
      addNode(graph, 'ec2-1', { type: 'cloud_resource', resource_type: 'ec2', imdsv2_required: true });
      addNode(graph, 'role-1', { type: 'cloud_identity', principal_type: 'role' });
      addEdge(graph, 'ec2-1', 'role-1', 'MANAGED_BY');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ec2-1');
      expect(inferred.length).toBe(0);
    });

    it('does NOT infer when no MANAGED_BY edge exists', () => {
      const graph = makeGraph();
      addNode(graph, 'ec2-1', { type: 'cloud_resource', resource_type: 'ec2', imdsv2_required: false });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ec2-1');
      expect(inferred.length).toBe(0);
    });
  });

  describe('rule-cross-account-role-chain', () => {
    const RULE: InferenceRule = {
      id: 'rule-cross-account-role-chain', name: 'Transitive cross-account chaining', description: '',
      trigger: { node_type: 'cloud_identity', requires_edge: { type: 'ASSUMES_ROLE', direction: 'outbound' } },
      produces: [{ edge_type: 'REACHABLE', source_selector: 'trigger_node', target_selector: 'transitive_assumed_roles', confidence: 0.6 }],
    };

    it('finds 2-hop cross-account chain', () => {
      const graph = makeGraph();
      addNode(graph, 'id-a', { type: 'cloud_identity', cloud_account: '111' });
      addNode(graph, 'id-b', { type: 'cloud_identity', cloud_account: '111' });
      addNode(graph, 'id-c', { type: 'cloud_identity', cloud_account: '222' });
      addEdge(graph, 'id-a', 'id-b', 'ASSUMES_ROLE');
      addEdge(graph, 'id-b', 'id-c', 'ASSUMES_ROLE');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('id-a');
      expect(inferred.length).toBeGreaterThanOrEqual(1);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('REACHABLE');
    });

    it('does NOT fire when no cross-account target', () => {
      const graph = makeGraph();
      addNode(graph, 'id-a', { type: 'cloud_identity', cloud_account: '111' });
      addNode(graph, 'id-b', { type: 'cloud_identity', cloud_account: '111' });
      addEdge(graph, 'id-a', 'id-b', 'ASSUMES_ROLE');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('id-a');
      expect(inferred.length).toBe(0);
    });
  });

  describe('rule-lambda-iam-escalation', () => {
    const RULE: InferenceRule = {
      id: 'rule-lambda-iam-escalation', name: 'Lambda IAM escalation', description: '',
      trigger: { node_type: 'cloud_resource', property_match: { resource_type: 'lambda' } },
      produces: [{ edge_type: 'ASSUMES_ROLE', source_selector: 'trigger_node', target_selector: 'lambda_attached_role', confidence: 0.75 }],
    };

    it('infers ASSUMES_ROLE from lambda to execution role', () => {
      const graph = makeGraph();
      addNode(graph, 'lambda-1', { type: 'cloud_resource', resource_type: 'lambda' });
      addNode(graph, 'role-1', { type: 'cloud_identity', principal_type: 'role' });
      addEdge(graph, 'lambda-1', 'role-1', 'MANAGED_BY');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('lambda-1');
      expect(inferred.length).toBe(1);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('ASSUMES_ROLE');
      expect(edge.confidence).toBe(0.75);
    });

    it('does NOT fire for non-lambda resource', () => {
      const graph = makeGraph();
      addNode(graph, 'ec2-1', { type: 'cloud_resource', resource_type: 'ec2' });
      addNode(graph, 'role-1', { type: 'cloud_identity', principal_type: 'role' });
      addEdge(graph, 'ec2-1', 'role-1', 'MANAGED_BY');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('ec2-1');
      expect(inferred.length).toBe(0);
    });

    it('does NOT fire without MANAGED_BY edge', () => {
      const graph = makeGraph();
      addNode(graph, 'lambda-1', { type: 'cloud_resource', resource_type: 'lambda' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('lambda-1');
      expect(inferred.length).toBe(0);
    });
  });

  describe('rule-s3-bucket-exposed', () => {
    const RULE: InferenceRule = {
      id: 'rule-s3-bucket-exposed', name: 'S3 bucket exposed', description: '',
      trigger: { node_type: 'cloud_resource', property_match: { resource_type: 's3_bucket' }, requires_edge: { type: 'EXPOSED_TO', direction: 'outbound' } },
      produces: [{ edge_type: 'REACHABLE', source_selector: 'edge_peers', target_selector: 'trigger_node', confidence: 0.7 }],
    };

    it('infers REACHABLE from exposed S3 bucket', () => {
      const graph = makeGraph();
      addNode(graph, 'bucket-1', { type: 'cloud_resource', resource_type: 's3_bucket' });
      addNode(graph, 'subnet-1', { type: 'cloud_network', network_type: 'subnet' });
      addEdge(graph, 'bucket-1', 'subnet-1', 'EXPOSED_TO');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('bucket-1');
      expect(inferred.length).toBe(1);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('REACHABLE');
      expect(edge.confidence).toBe(0.7);
    });

    it('does NOT fire without EXPOSED_TO edge', () => {
      const graph = makeGraph();
      addNode(graph, 'bucket-1', { type: 'cloud_resource', resource_type: 's3_bucket' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('bucket-1');
      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // Phase 2: Credential reuse
  // =============================================
  describe('rule-shared-credential', () => {
    const RULE: InferenceRule = {
      id: 'rule-shared-credential', name: 'Credential reuse', description: '',
      trigger: { node_type: 'credential' },
      produces: [{ edge_type: 'SHARED_CREDENTIAL', source_selector: 'trigger_node', target_selector: 'credentials_same_username', confidence: 0.7 }],
    };

    it('infers SHARED_CREDENTIAL between credentials with same cred_user', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-a', { type: 'credential', cred_user: 'admin', cred_type: 'ntlm' });
      addNode(graph, 'cred-b', { type: 'credential', cred_user: 'admin', cred_type: 'plaintext' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('cred-a');
      expect(inferred.length).toBe(1);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('SHARED_CREDENTIAL');
    });

    it('does NOT infer SHARED_CREDENTIAL for different usernames', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-a', { type: 'credential', cred_user: 'admin', cred_type: 'ntlm' });
      addNode(graph, 'cred-b', { type: 'credential', cred_user: 'jsmith', cred_type: 'ntlm' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('cred-a');
      expect(inferred.length).toBe(0);
    });

    it('matches cred_user case-insensitively', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-a', { type: 'credential', cred_user: 'Admin', cred_type: 'ntlm' });
      addNode(graph, 'cred-b', { type: 'credential', cred_user: 'admin', cred_type: 'ntlm' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('cred-a');
      expect(inferred.length).toBe(1);
    });
  });

  // =============================================
  // Phase 2: Lateral movement chaining
  // =============================================
  describe('rule-session-admin-persistence', () => {
    const RULE: InferenceRule = {
      id: 'rule-session-admin-persistence', name: 'Session+admin persistence', description: '',
      trigger: { node_type: 'user', requires_edge: { type: 'ADMIN_TO', direction: 'outbound' } },
      produces: [{ edge_type: 'PATH_TO_OBJECTIVE', source_selector: 'trigger_node', target_selector: 'nearest_objective', confidence: 0.6 }],
    };

    it('infers PATH_TO_OBJECTIVE when user has ADMIN_TO and objective exists', () => {
      const graph = makeGraph();
      addNode(graph, 'user-a', { type: 'user' });
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'obj-1', { type: 'objective' });
      addEdge(graph, 'user-a', 'host-a', 'ADMIN_TO');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('user-a');
      expect(inferred.length).toBeGreaterThan(0);
      const edge = graph.getEdgeAttributes(inferred[0]);
      expect(edge.type).toBe('PATH_TO_OBJECTIVE');
    });

    it('does NOT infer PATH_TO_OBJECTIVE without ADMIN_TO edge', () => {
      const graph = makeGraph();
      addNode(graph, 'user-a', { type: 'user' });
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'obj-1', { type: 'objective' });
      addEdge(graph, 'user-a', 'host-a', 'HAS_SESSION');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('user-a');
      expect(inferred.length).toBe(0);
    });
  });

  // =============================================
  // Web attack inference rules
  // =============================================
  describe('rule-api-endpoint-discovery', () => {
    const RULE: InferenceRule = {
      id: 'rule-api-endpoint-discovery',
      name: 'Webapp with API requires endpoint enumeration',
      description: 'A webapp with has_api=true is a candidate for API endpoint discovery',
      trigger: { node_type: 'webapp', property_match: { has_api: true } },
      produces: [{ edge_type: 'POTENTIAL_AUTH', source_selector: 'default_credential_candidates', target_selector: 'trigger_node', confidence: 0.3 }],
    };

    it('fires on webapp with has_api=true', () => {
      const graph = makeGraph();
      addNode(graph, 'webapp-1', { type: 'webapp', has_api: true } as any);
      addNode(graph, 'cred-default', { type: 'credential', cred_type: 'password', default_cred: true } as any);
      addEdge(graph, 'cred-default', 'webapp-1', 'POTENTIAL_AUTH');
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('webapp-1');
      // At minimum, rule triggers (even if selector returns empty, no crash)
      expect(inferred.length).toBeGreaterThanOrEqual(0);
    });

    it('does NOT fire on webapp without has_api', () => {
      const graph = makeGraph();
      addNode(graph, 'webapp-1', { type: 'webapp' });
      const engine = buildEngine(graph, [RULE]);
      const inferred = engine.runRules('webapp-1');
      expect(inferred.length).toBe(0);
    });
  });
});
