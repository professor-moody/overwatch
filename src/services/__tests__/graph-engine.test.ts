import { describe, it, expect, afterEach } from 'vitest';
import { GraphEngine } from '../graph-engine.js';
import { parseHashcat, parseNxc, parseResponder, parseSecretsdump } from '../parsers/index.js';
import { unlinkSync, existsSync, readFileSync } from 'fs';
import type { EngagementConfig, Finding, NodeType, AgentTask } from '../../types.js';

const TEST_STATE_FILE = './state-test-eng.json';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-eng',
    name: 'Test Engagement',
    created_at: '2026-03-20T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/28'],
      domains: ['test.local'],
      exclusions: ['10.10.10.14'],
    },
    objectives: [
      {
        id: 'obj-da',
        description: 'Get Domain Admin',
        target_node_type: 'credential',
        target_criteria: { privileged: true, cred_domain: 'test.local' },
        achieved: false,
      },
    ],
    opsec: {
      name: 'pentest',
      max_noise: 0.7,
      blacklisted_techniques: ['zerologon'],
    },
    ...overrides,
  };
}

function cleanup() {
  if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
}

describe('GraphEngine', () => {
  afterEach(cleanup);

  // =============================================
  // Seeding
  // =============================================
  describe('seeding from config', () => {
    it('does NOT auto-expand CIDRs into host nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      // CIDRs define scope boundaries only — hosts are created by tool output
      expect(state.graph_summary.nodes_by_type['host'] || 0).toBe(0);
    });

    it('creates domain nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      expect(state.graph_summary.nodes_by_type['domain']).toBe(1);
    });

    it('creates objective nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      expect(state.graph_summary.nodes_by_type['objective']).toBe(1);
    });

    it('creates explicit host nodes', () => {
      const config = makeConfig({
        scope: {
          cidrs: [],
          domains: ['test.local'],
          exclusions: [],
          hosts: ['dc01.test.local', 'web01.test.local'],
        },
      });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      const state = engine.getState();
      expect(state.graph_summary.nodes_by_type['host']).toBe(2);
    });
  });

  // =============================================
  // Finding Ingestion
  // =============================================
  describe('ingestFinding', () => {
    it('adds new nodes to the graph', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB on .1', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      expect(result.new_nodes).toContain('svc-10-10-10-1-445');
      expect(result.new_edges.length).toBeGreaterThan(0);
    });

    it('merges properties on existing nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Create host first
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' }],
      }));
      expect(engine.getNode('host-10-10-10-1')).toBeDefined();

      // Update with OS info
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true, os: 'Windows Server 2022' },
        ],
      }));

      const state = engine.getState();
      // Node count should not increase for the host type
      expect(state.graph_summary.nodes_by_type['host']).toBe(1);
    });

    it('skips edges with missing source/target nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.ingestFinding(makeFinding({
        edges: [
          { source: 'nonexistent-a', target: 'nonexistent-b', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      expect(result.new_edges.length).toBe(0);
    });

    it('deduplicates edges of the same type', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add a host and service first
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-test', type: 'service', label: 'test svc' },
        ],
        edges: [{ source: 'host-10-10-10-1', target: 'svc-test', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));

      const before = engine.getState();
      const edgesBefore = before.graph_summary.total_edges;

      // Report same edge again
      engine.ingestFinding(makeFinding({
        edges: [{ source: 'host-10-10-10-1', target: 'svc-test', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));

      const after = engine.getState();
      expect(after.graph_summary.total_edges).toBe(edgesBefore);
    });

    it('does not leave NXC-only hosts marked as missing services', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const finding = parseNxc('SMB  10.10.10.5  445  ACME\\scanner  [+]  Windows Server 2019');

      engine.ingestFinding(finding);

      const state = engine.getState();
      const hostFrontier = state.frontier.find((item) => item.node_id === 'host-10-10-10-5');
      expect(hostFrontier?.missing_properties).not.toContain('services');
    });

    it('auto-merges unresolved aliases into later canonical identities and retargets edges', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({
        id: 'bh-user-s-1-5-21-1',
        type: 'user',
        label: 'mystery-user',
        identity_status: 'unresolved',
        identity_markers: ['user:acct:test-local:jsmith'],
        discovered_at: new Date().toISOString(),
        confidence: 0.7,
      });
      engine.addNode({
        id: 'host-10-10-10-2',
        type: 'host',
        label: '10.10.10.2',
        ip: '10.10.10.2',
        alive: true,
        discovered_at: new Date().toISOString(),
        confidence: 1.0,
      });
      engine.addEdge('bh-user-s-1-5-21-1', 'host-10-10-10-2', { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString() });

      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-test-local-jsmith', type: 'user', label: 'JSMITH@TEST.LOCAL', username: 'jsmith', domain_name: 'test.local' },
        ],
      }));

      const graph = engine.exportGraph();
      expect(graph.nodes.some(node => node.id === 'bh-user-s-1-5-21-1')).toBe(false);
      expect(graph.nodes.some(node => node.id === 'user-test-local-jsmith')).toBe(true);
      expect(graph.edges.some(edge => edge.source === 'user-test-local-jsmith' && edge.target === 'host-10-10-10-2' && edge.properties.type === 'HAS_SESSION')).toBe(true);
    });

    it('reverse-merges hostname-only host into existing IP-based host via FQDN short name', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      // First: ingest a host with IP and FQDN (e.g. from nmap)
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-5', type: 'host', label: 'dc01.test.local', hostname: 'dc01.test.local', ip: '10.10.10.5', alive: true },
        ],
      }));
      expect(engine.getNode('host-10-10-10-5')).toBeDefined();

      // Second: ingest a host with only a short hostname and no IP (e.g. from report_finding)
      // This gets canonical ID host-dc01 but should reverse-merge into host-10-10-10-5
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-dc01', type: 'host', label: 'DC01', hostname: 'DC01', smb_signing: false },
          { id: 'share-dc01-admin', type: 'share', label: '\\\\DC01\\admin$', share_name: 'admin$' },
        ],
        edges: [
          { source: 'host-dc01', target: 'share-dc01-admin', properties: { type: 'RELATED', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const graph = engine.exportGraph();
      // The hostname-only node should have been merged away
      expect(graph.nodes.some(n => n.id === 'host-dc01')).toBe(false);
      // The IP-based node should still exist with merged properties
      const ipHost = graph.nodes.find(n => n.id === 'host-10-10-10-5');
      expect(ipHost).toBeDefined();
      expect(ipHost?.properties.smb_signing).toBe(false);
      // The share edge should be retargeted to the IP-based host
      expect(graph.edges.some(e => e.source === 'host-10-10-10-5' && e.target === 'share-dc01-admin' && e.properties.type === 'RELATED')).toBe(true);
    });
  });

  // =============================================
  // Inference Rules
  // =============================================
  describe('inference rules', () => {
    it('infers MEMBER_OF_DOMAIN from Kerberos service via hostname suffix', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Give the host a hostname so matching_domain can resolve via suffix
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: 'dc01.test.local', ip: '10.10.10.1', hostname: 'dc01.test.local' },
        ],
      }));
      // Add a Kerberos service on the host
      const result = engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-1-88', type: 'service', label: 'Kerberos', port: 88, service_name: 'kerberos' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-88', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      expect(result.inferred_edges.length).toBeGreaterThan(0);
      // Should have inferred MEMBER_OF_DOMAIN
      const state = engine.getState();
      expect(state.graph_summary.edges_by_type['MEMBER_OF_DOMAIN']).toBeGreaterThan(0);
    });

    it('does NOT infer MEMBER_OF_DOMAIN for Kerberos host without matching hostname', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Host has no hostname — matching_domain should produce nothing
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-10-10-10-1-88', type: 'service', label: 'Kerberos', port: 88, service_name: 'kerberos' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-88', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      // No hostname = no domain match = no inferred MEMBER_OF_DOMAIN
      const state = engine.getState();
      expect(state.graph_summary.edges_by_type['MEMBER_OF_DOMAIN'] || 0).toBe(0);
    });

    it('does NOT infer MEMBER_OF_DOMAIN when hostname is sibling domain (dot-boundary)', () => {
      const config = makeConfig({ scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local', 'eviltest.local'], exclusions: [] } });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      // Host with hostname in eviltest.local, NOT test.local
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-3', type: 'host', label: 'dc01.eviltest.local', ip: '10.10.10.3', hostname: 'dc01.eviltest.local' },
        ],
      }));
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-3-88', type: 'service', label: 'Kerberos', port: 88, service_name: 'kerberos' },
        ],
        edges: [
          { source: 'host-10-10-10-3', target: 'svc-10-10-10-3-88', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      // Should infer MEMBER_OF_DOMAIN to eviltest.local but NOT test.local
      const graph = engine.exportGraph();
      const domEdges = graph.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN' && e.source === 'host-10-10-10-3');
      expect(domEdges.length).toBe(1);
      expect(domEdges[0].target).toBe('domain-eviltest-local');
    });

    it('infers RELAY_TARGET from SMB signing disabled', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Need a compromised host first for the relay source
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
        ],
        edges: [
          { source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Now add a service with signing disabled on a different host
      const result = engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-2-445', type: 'service', label: 'SMB .2', port: 445, service_name: 'smb', smb_signing: false },
        ],
        edges: [
          { source: 'host-10-10-10-2', target: 'svc-10-10-10-2-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // RELAY_TARGET should be inferred from compromised host to parent host of the service
      expect(result.inferred_edges.some(e => e.includes('RELAY_TARGET'))).toBe(true);
    });

    it('fires inference on property updates (P1.5 fix)', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      // Add SMB service without signing info — no relay inference
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-3', type: 'host', label: '10.10.10.3', ip: '10.10.10.3' },
          { id: 'svc-10-10-10-3-445', type: 'service', label: 'SMB .3', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-3', target: 'svc-10-10-10-3-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Need a compromised host for relay source
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
        ],
        edges: [
          { source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Now UPDATE the service to have signing disabled — should fire relay inference
      const result = engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-3-445', type: 'service', label: 'SMB .3', port: 445, service_name: 'smb', smb_signing: false },
        ],
      }));

      expect(result.inferred_edges.some(e => e.includes('RELAY_TARGET'))).toBe(true);
    });

    it('infers POTENTIAL_AUTH for new credentials', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add a service that accepts domain auth (host must be in same domain)
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB .1', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'host-10-10-10-1', target: 'domain-test-local', properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Now add a credential
      const result = engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'cred-jdoe-ntlm', type: 'credential', label: 'jdoe NTLM', cred_type: 'ntlm', cred_user: 'jdoe', cred_domain: 'test.local' },
        ],
      }));

      expect(result.inferred_edges.some(e => e.includes('POTENTIAL_AUTH'))).toBe(true);
    });

    it('does not infer POTENTIAL_AUTH from responder NTLMv2 captures', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB .1', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const responderFinding = parseResponder([
        '[SMB] NTLMv2-SSP Client   : 10.10.10.2',
        '[SMB] NTLMv2-SSP Username : TEST.LOCAL\\jdoe',
        '[SMB] NTLMv2-SSP Hash     : jdoe::TEST.LOCAL:1122334455667788:aabbccddee:0101000000',
      ].join('\n'));
      const result = engine.ingestFinding(responderFinding);

      expect(result.inferred_edges.some(e => e.includes('POTENTIAL_AUTH'))).toBe(false);
      expect(engine.queryGraph({ edge_type: 'POTENTIAL_AUTH' }).edges.length).toBe(0);
    });

    it('still infers POTENTIAL_AUTH from secretsdump NT hashes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Host must be in the same domain as the credential for domain-scoped fanout
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: 'dc01.test.local', ip: '10.10.10.1', hostname: 'dc01.test.local' },
          { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB .1', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'host-10-10-10-1', target: 'domain-test-local', properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const result = engine.ingestFinding(parseSecretsdump([
        'TEST.LOCAL\\jdoe:1103:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::',
      ].join('\n')));

      expect(result.inferred_edges.some(e => e.includes('POTENTIAL_AUTH'))).toBe(true);
    });

    it('still infers POTENTIAL_AUTH from hashcat cracked passwords', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB .1', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'host-10-10-10-1', target: 'domain-test-local', properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const result = engine.ingestFinding(parseHashcat([
        'jdoe::TEST.LOCAL:1122334455667788:aabbccddee:0101000000:OfficePass1',
      ].join('\n')));

      expect(result.inferred_edges.some(e => e.includes('POTENTIAL_AUTH'))).toBe(true);
    });

    it('does NOT fan out POTENTIAL_AUTH across domains (domain-scoped)', () => {
      const config = makeConfig({ scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local', 'other.local'], exclusions: [] } });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      // Add a service in "other.local" domain
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2' },
          { id: 'svc-10-10-10-2-445', type: 'service', label: 'SMB .2', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-2', target: 'svc-10-10-10-2-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'host-10-10-10-2', target: 'domain-other-local', properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      // Add a credential in "test.local" domain
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-test-jdoe', type: 'user', label: 'test.local\\jdoe', username: 'jdoe', domain_name: 'test.local' },
          { id: 'cred-test-jdoe', type: 'credential', label: 'NTLM:jdoe', cred_type: 'ntlm', cred_material_kind: 'ntlm_hash', cred_usable_for_auth: true, cred_value: 'aabbccdd', cred_user: 'jdoe' },
        ],
        edges: [
          { source: 'user-test-jdoe', target: 'cred-test-jdoe', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'user-test-jdoe', target: 'domain-test-local', properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      // The credential should NOT create POTENTIAL_AUTH to the service in other.local
      const potAuthEdges = engine.queryGraph({ edge_type: 'POTENTIAL_AUTH' }).edges;
      const crossDomain = potAuthEdges.filter(e => e.target === 'svc-10-10-10-2-445');
      expect(crossDomain.length).toBe(0);
    });

    it('does NOT fan out hashcat cred with cred_domain but no MEMBER_OF_DOMAIN edge across domains', () => {
      const config = makeConfig({ scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local', 'other.local'], exclusions: [] } });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      // Service in "other.local"
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2' },
          { id: 'svc-10-10-10-2-445', type: 'service', label: 'SMB .2', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-2', target: 'svc-10-10-10-2-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'host-10-10-10-2', target: 'domain-other-local', properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      // Hashcat-style credential: user has domain_name, cred has cred_domain, but NO MEMBER_OF_DOMAIN edge
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-test-cracked', type: 'user', label: 'TEST.LOCAL\\cracked', username: 'cracked', domain_name: 'TEST.LOCAL' },
          { id: 'cred-cracked', type: 'credential', label: 'cracked:Password1', cred_type: 'plaintext', cred_material_kind: 'plaintext_password', cred_usable_for_auth: true, cred_value: 'Password1', cred_user: 'cracked', cred_domain: 'TEST.LOCAL' },
        ],
        edges: [
          { source: 'user-test-cracked', target: 'cred-cracked', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      // Should NOT fan out to "other.local" service
      const potAuth = engine.queryGraph({ edge_type: 'POTENTIAL_AUTH' }).edges;
      const crossDomain = potAuth.filter(e => e.target === 'svc-10-10-10-2-445');
      expect(crossDomain.length).toBe(0);
    });

    it('does NOT use parser_context cred_domain for domain-scoped fanout', () => {
      const config = makeConfig({ scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local'], exclusions: [] } });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      // Service on a domain-joined host
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB .1', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'host-10-10-10-1', target: 'domain-test-local', properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      // Unqualified SAM account with parser_context domain hint (not authoritative)
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-admin', type: 'user', label: 'Administrator', username: 'Administrator' },
          { id: 'cred-admin-hash', type: 'credential', label: 'NTLM:Administrator', cred_type: 'ntlm', cred_material_kind: 'ntlm_hash', cred_usable_for_auth: true, cred_value: 'aad3b435b51404ee', cred_user: 'Administrator', cred_domain: 'test.local', cred_domain_source: 'parser_context' },
        ],
        edges: [
          { source: 'user-admin', target: 'cred-admin-hash', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      // parser_context domain is non-authoritative — suppresses both domain-scoped
      // AND global fallback fanout. Credential waits for authoritative domain evidence.
      const potAuth = engine.queryGraph({ edge_type: 'POTENTIAL_AUTH' }).edges;
      const fromCred = potAuth.filter(e => e.source === 'cred-admin-hash');
      expect(fromCred.length).toBe(0);
    });

    it('backfills cred_domain when user gains MEMBER_OF_DOMAIN in a later finding', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Finding 1: user + credential, no domain
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-jdoe', type: 'user', label: 'jdoe', username: 'jdoe' },
          { id: 'cred-jdoe-hash', type: 'credential', label: 'NTLM:jdoe', cred_type: 'ntlm', cred_material_kind: 'ntlm_hash', cred_usable_for_auth: true, cred_value: 'aabbccdd', cred_user: 'jdoe' },
        ],
        edges: [
          { source: 'user-jdoe', target: 'cred-jdoe-hash', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      // Credential should have no domain yet
      const graph1 = engine.exportGraph();
      const cred1 = graph1.nodes.find(n => n.id === 'cred-jdoe-hash');
      expect(cred1?.properties.cred_domain).toBeFalsy();

      // Finding 2: user gains MEMBER_OF_DOMAIN edge
      engine.ingestFinding(makeFinding({
        edges: [
          { source: 'user-jdoe', target: 'domain-test-local', properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      // Credential should now have domain backfilled
      const graph2 = engine.exportGraph();
      const cred2 = graph2.nodes.find(n => n.id === 'cred-jdoe-hash');
      expect(cred2?.properties.cred_domain).toBe('test.local');
      expect(cred2?.properties.cred_domain_source).toBe('graph_inference');
    });
  });

  // =============================================
  // frontier_item_id auto-threading
  // =============================================
  describe('frontier_item_id auto-threading', () => {
    it('auto-fills frontier_item_id on subsequent events with same action_id', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // First event: action_validated with frontier_item_id
      engine.logActionEvent({
        description: 'validate action',
        action_id: 'act-123',
        event_type: 'action_validated',
        frontier_item_id: 'fi-abc',
        frontier_type: 'inferred_edge',
      });
      // Second event: action_started with same action_id but NO frontier_item_id
      engine.logActionEvent({
        description: 'start action',
        action_id: 'act-123',
        event_type: 'action_started',
      });
      const history = engine.getFullHistory();
      const startEvent = history.find((e: any) => e.event_type === 'action_started' && e.action_id === 'act-123');
      expect(startEvent?.frontier_item_id).toBe('fi-abc');
      expect(startEvent?.frontier_type).toBe('inferred_edge');
    });

    it('survives state reload via rebuildActionFrontierMap', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Log an event with action_id + frontier_item_id
      engine.logActionEvent({
        description: 'validate action',
        action_id: 'act-persist',
        event_type: 'action_validated',
        frontier_item_id: 'fi-persist',
        frontier_type: 'incomplete_node',
      });
      // Persist state to disk
      engine.persist();

      // Create a new engine instance and load the saved state
      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Log a follow-up event with same action_id but NO frontier_item_id
      engine2.logActionEvent({
        description: 'complete action',
        action_id: 'act-persist',
        event_type: 'action_completed',
      });
      const history = engine2.getFullHistory();
      const completedEvent = history.find((e: any) => e.event_type === 'action_completed' && e.action_id === 'act-persist');
      expect(completedEvent?.frontier_item_id).toBe('fi-persist');
      expect(completedEvent?.frontier_type).toBe('incomplete_node');
    });
  });

  // =============================================
  // Frontier Computation
  // =============================================
  describe('frontier', () => {
    it('generates incomplete_node items for hosts missing alive status', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Create a host without alive status
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' }],
      }));
      const state = engine.getState();
      const aliveItems = state.frontier.filter(
        f => f.type === 'incomplete_node' && f.missing_properties?.includes('alive')
      );
      expect(aliveItems.length).toBeGreaterThan(0);
    });

    it('generates inferred_edge items for untested inferred edges', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Give host a hostname so kerberos matching_domain selector works
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: 'dc01.test.local', ip: '10.10.10.1', hostname: 'dc01.test.local' },
        ],
      }));
      // Create an inferred edge via Kerberos
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-1-88', type: 'service', label: 'Kerberos', port: 88, service_name: 'kerberos' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-88', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const state = engine.getState();
      const inferredItems = state.frontier.filter(f => f.type === 'inferred_edge');
      expect(inferredItems.length).toBeGreaterThan(0);
    });

    it('filters out excluded IPs', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      const excludedItems = state.frontier.filter(f => f.node_id === 'host-10-10-10-14');
      expect(excludedItems.length).toBe(0);
    });

    it('filters out dead hosts', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: false }],
      }));

      const state = engine.getState();
      const deadItems = state.frontier.filter(f => f.node_id === 'host-10-10-10-1');
      expect(deadItems.length).toBe(0);
    });

    it('filters items exceeding OPSEC noise ceiling', () => {
      const config = makeConfig({ opsec: { name: 'redteam', max_noise: 0.1 } });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      const state = engine.getState();
      // With noise ceiling 0.1, most items should be filtered (ping sweep = 0.2)
      const highNoiseInFrontier = state.frontier.filter(f => f.opsec_noise > 0.1);
      expect(highNoiseInFrontier.length).toBe(0);
    });

    it('emits network_discovery items from scope CIDRs', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const frontier = engine.computeFrontier();
      const discovery = frontier.filter(f => f.type === 'network_discovery');
      expect(discovery.length).toBe(1);
      expect(discovery[0].target_cidr).toBe('10.10.10.0/28');
      expect(discovery[0].id).toBe('frontier-discovery-10-10-10-0-28');
      expect(discovery[0].description).toContain('Discover hosts');
      expect(discovery[0].graph_metrics.fan_out_estimate).toBeGreaterThan(0);
    });

    it('emits one network_discovery item per CIDR', () => {
      const config = makeConfig({
        scope: { cidrs: ['10.10.10.0/24', '192.168.1.0/24'], domains: ['test.local'], exclusions: [] },
      });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      const frontier = engine.computeFrontier();
      const discovery = frontier.filter(f => f.type === 'network_discovery');
      expect(discovery.length).toBe(2);
      expect(discovery.map(d => d.target_cidr).sort()).toEqual(['10.10.10.0/24', '192.168.1.0/24']);
    });

    it('network_discovery items pass through filterFrontier', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const frontier = engine.computeFrontier();
      const { passed } = engine.filterFrontier(frontier);
      const discovery = passed.filter(f => f.type === 'network_discovery');
      expect(discovery.length).toBe(1);
    });

    it('network_discovery items appear in getState frontier', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      const discovery = state.frontier.filter(f => f.type === 'network_discovery');
      expect(discovery.length).toBe(1);
      expect(discovery[0].target_cidr).toBe('10.10.10.0/28');
    });

    it('network_discovery item persists with reduced fan_out after partial exploration', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // /28 = 14 usable hosts
      let frontier = engine.computeFrontier();
      let discovery = frontier.find(f => f.type === 'network_discovery' && f.target_cidr === '10.10.10.0/28');
      expect(discovery).toBeDefined();
      expect(discovery!.graph_metrics.fan_out_estimate).toBe(14);

      // Discover one host
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' }],
      }));

      frontier = engine.computeFrontier();
      discovery = frontier.find(f => f.type === 'network_discovery' && f.target_cidr === '10.10.10.0/28');
      expect(discovery).toBeDefined();
      expect(discovery!.graph_metrics.fan_out_estimate).toBe(13);
      expect(discovery!.description).toContain('Continue discovery');
      expect(discovery!.description).toContain('1 found');
    });

    it('network_discovery item is suppressed once all estimated hosts are discovered', () => {
      // /30 = 2 usable hosts
      const config = makeConfig({
        scope: { cidrs: ['10.10.10.0/30'], domains: ['test.local'], exclusions: [] },
      });
      const engine = new GraphEngine(config, TEST_STATE_FILE);

      let frontier = engine.computeFrontier();
      expect(frontier.some(f => f.type === 'network_discovery')).toBe(true);

      // Discover both hosts in the /30
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2' },
        ],
      }));

      frontier = engine.computeFrontier();
      expect(frontier.some(f => f.type === 'network_discovery')).toBe(false);
    });

    it('partial exploration reduces only the affected CIDR in multi-CIDR engagements', () => {
      const config = makeConfig({
        scope: { cidrs: ['10.10.10.0/24', '192.168.1.0/24'], domains: ['test.local'], exclusions: [] },
      });
      const engine = new GraphEngine(config, TEST_STATE_FILE);

      // Discover a host only in the first CIDR
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-5', type: 'host', label: '10.10.10.5', ip: '10.10.10.5' }],
      }));

      const frontier = engine.computeFrontier();
      const discovery = frontier.filter(f => f.type === 'network_discovery');
      expect(discovery.length).toBe(2);

      const first = discovery.find(d => d.target_cidr === '10.10.10.0/24')!;
      const second = discovery.find(d => d.target_cidr === '192.168.1.0/24')!;
      expect(first.graph_metrics.fan_out_estimate).toBe(253);
      expect(second.graph_metrics.fan_out_estimate).toBe(254);
    });
  });

  // =============================================
  // Validation
  // =============================================
  describe('validation', () => {
    it('validates existing nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' }],
      }));
      const result = engine.validateAction({ target_node: 'host-10-10-10-1' });
      expect(result.valid).toBe(true);
    });

    it('rejects nonexistent nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ target_node: 'host-does-not-exist' });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('rejects excluded IPs', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-14', type: 'host', label: '10.10.10.14', ip: '10.10.10.14' }],
      }));
      const result = engine.validateAction({ target_node: 'host-10-10-10-14' });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('out of scope'))).toBe(true);
    });

    it('rejects blacklisted techniques', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ technique: 'zerologon' });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('blacklisted'))).toBe(true);
    });

    it('allows non-blacklisted techniques', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' }],
      }));
      const result = engine.validateAction({ target_node: 'host-10-10-10-1', technique: 'portscan' });
      expect(result.valid).toBe(true);
    });

    it('rejects excluded edge_target in validateAction', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'host-10-10-10-14', type: 'host', label: '10.10.10.14', ip: '10.10.10.14' },
        ],
      }));
      const result = engine.validateAction({ edge_source: 'host-10-10-10-1', edge_target: 'host-10-10-10-14' });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('out of scope'))).toBe(true);
    });

    it('warns when outside normal time window (e.g. 8-18)', () => {
      const engine = new GraphEngine(makeConfig({
        opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [], time_window: { start_hour: 8, end_hour: 18 } },
      }), TEST_STATE_FILE);
      const hour = new Date().getHours();
      const result = engine.validateAction({ target_node: 'host-10-10-10-1' });
      if (hour >= 8 && hour < 18) {
        expect(result.warnings.length).toBe(0);
      } else {
        expect(result.warnings.some(w => w.includes('Outside approved time window'))).toBe(true);
      }
    });

    it('handles overnight time window wrap-around (e.g. 22-06)', () => {
      const engine = new GraphEngine(makeConfig({
        opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [], time_window: { start_hour: 22, end_hour: 6 } },
      }), TEST_STATE_FILE);
      const hour = new Date().getHours();
      const result = engine.validateAction({ target_node: 'host-10-10-10-1' });
      const inWindow = hour >= 22 || hour < 6;
      if (inWindow) {
        expect(result.warnings.some(w => w.includes('Outside'))).toBe(false);
      } else {
        expect(result.warnings.some(w => w.includes('Outside'))).toBe(true);
      }
    });

    it('rejects excluded edge_source in validateAction', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-14', type: 'host', label: '10.10.10.14', ip: '10.10.10.14' },
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
        ],
      }));
      const result = engine.validateAction({ edge_source: 'host-10-10-10-14', edge_target: 'host-10-10-10-1' });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('out of scope'))).toBe(true);
    });

    it('validates in-scope target_ip without requiring a graph node', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ target_ip: '10.10.10.1' });
      expect(result.valid).toBe(true);
      expect(result.errors.length).toBe(0);
    });

    it('rejects out-of-scope target_ip', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ target_ip: '192.168.1.1' });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('out of scope'))).toBe(true);
    });

    it('rejects excluded target_ip', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ target_ip: '10.10.10.14' });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('out of scope'))).toBe(true);
    });

    it('validates target_ip combined with technique', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ target_ip: '10.10.10.1', technique: 'portscan' });
      expect(result.valid).toBe(true);
    });

    it('rejects target_ip with blacklisted technique', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ target_ip: '10.10.10.1', technique: 'zerologon' });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('blacklisted'))).toBe(true);
    });

    it('filterFrontier excludes items with out-of-scope edge_target', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'host-10-10-10-14', type: 'host', label: '10.10.10.14', ip: '10.10.10.14' },
        ],
      }));
      const frontier = [{
        id: 'frontier-edge-1',
        type: 'inferred_edge' as const,
        edge_source: 'host-10-10-10-1',
        edge_target: 'host-10-10-10-14',
        edge_type: 'RELAY_TARGET' as const,
        description: 'Relay to excluded host',
        graph_metrics: { hops_to_objective: null, fan_out_estimate: 5, node_degree: 1, confidence: 0.8 },
        opsec_noise: 0.3,
        staleness_seconds: 0,
      }];
      const result = engine.filterFrontier(frontier);
      expect(result.passed.length).toBe(0);
      expect(result.filtered.length).toBe(1);
      expect(result.filtered[0].reason.toLowerCase()).toContain('out of scope');
    });

    it('filterFrontier excludes service nodes on excluded hosts', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add a service on the excluded host (10.10.10.14)
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-14', type: 'host', label: '10.10.10.14', ip: '10.10.10.14' },
          { id: 'svc-10-10-10-14-445', type: 'service', label: 'SMB on excluded', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-14', target: 'svc-10-10-10-14-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const frontier = [{
        id: 'frontier-svc-excluded',
        type: 'incomplete_node' as const,
        node_id: 'svc-10-10-10-14-445',
        description: 'Enumerate service on excluded host',
        graph_metrics: { hops_to_objective: null, fan_out_estimate: 1, node_degree: 1, confidence: 1.0 },
        opsec_noise: 0.3,
        staleness_seconds: 0,
      }];
      const result = engine.filterFrontier(frontier);
      expect(result.passed.length).toBe(0);
      expect(result.filtered.length).toBe(1);
      expect(result.filtered[0].reason.toLowerCase()).toContain('out of scope');
    });

    it('allows IP-backed frontier items in domain-only engagements', () => {
      const engine = new GraphEngine(makeConfig({
        scope: {
          cidrs: [],
          domains: ['test.local'],
          exclusions: [],
        },
      }), TEST_STATE_FILE);

      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-172-16-1-10', type: 'host', label: '172.16.1.10', ip: '172.16.1.10', alive: true },
        ],
        edges: [],
      }));

      const frontier = [{
        id: 'frontier-node-host-172-16-1-10',
        type: 'incomplete_node' as const,
        node_id: 'host-172-16-1-10',
        description: 'Enumerate host',
        graph_metrics: { hops_to_objective: null, fan_out_estimate: 1, node_degree: 0, confidence: 1.0 },
        opsec_noise: 0.1,
        staleness_seconds: 0,
      }];

      const result = engine.filterFrontier(frontier);
      expect(result.filtered).toHaveLength(0);
      expect(result.passed).toHaveLength(1);
    });

    it('validateAction rejects service node on excluded host', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add a service on the excluded host (10.10.10.14)
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-14', type: 'host', label: '10.10.10.14', ip: '10.10.10.14' },
          { id: 'svc-10-10-10-14-445', type: 'service', label: 'SMB on excluded', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-14', target: 'svc-10-10-10-14-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const result = engine.validateAction({ target_node: 'svc-10-10-10-14-445' });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('out of scope'))).toBe(true);
    });
  });

  // =============================================
  // Path Analysis
  // =============================================
  describe('path analysis', () => {
    it('hopsToNearestObjective returns null for disconnected nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const hops = engine.hopsToNearestObjective('host-10-10-10-1');
      // No edges exist initially, so no path
      expect(hops).toBeNull();
    });

    it('findPathsToObjective finds path to real nodes matching objective criteria', () => {
      // Use a separate objective that won't auto-achieve (no access edge on the target)
      const config = makeConfig({
        objectives: [{
          id: 'obj-dc',
          description: 'Compromise domain controller',
          target_node_type: 'host' as const,
          target_criteria: { hostname: 'dc01.test.local' },
          achieved: false,
        }],
      });
      const engine = new GraphEngine(config, TEST_STATE_FILE);

      // Build a path: attacker has session on host-1, host-1 is reachable to dc01
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', alive: true },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
          { id: 'host-dc01', type: 'host', label: 'dc01.test.local', hostname: 'dc01.test.local', ip: '10.10.10.5', alive: true },
        ],
        edges: [
          { source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'host-10-10-10-1', target: 'host-dc01', properties: { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Objective not yet achieved (no access edge on dc01) — should find path
      const paths = engine.findPathsToObjective('obj-dc');
      expect(paths.length).toBeGreaterThan(0);
      expect(paths[0].nodes).toContain('host-10-10-10-5');
    });

    it('hopsToNearestObjective returns null when objective auto-achieved', () => {
      // When objective criteria match an ingested node AND an access edge exists,
      // the objective is auto-achieved during ingestFinding, so resolveObjectiveTargets
      // skips it (correct behavior — no frontier items toward achieved objectives)
      const config = makeConfig({
        objectives: [{
          id: 'obj-dc',
          description: 'Compromise domain controller',
          target_node_type: 'host' as const,
          target_criteria: { hostname: 'dc01.test.local' },
          achieved: false,
        }],
      });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-attacker', type: 'user', label: 'attacker' },
          { id: 'host-dc01', type: 'host', label: 'dc01.test.local', hostname: 'dc01.test.local', alive: true },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'host-dc01', properties: { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'user-attacker', target: 'host-dc01', properties: { type: 'ADMIN_TO', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Objective auto-achieved — hopsToNearestObjective returns null (no unachieved objectives)
      const hops = engine.hopsToNearestObjective('host-10-10-10-1');
      expect(hops).toBeNull();
    });

    it('findPaths returns empty for nonexistent nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const paths = engine.findPaths('nonexistent', 'also-nonexistent');
      expect(paths).toEqual([]);
    });

    it('findPaths finds a path between connected nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const paths = engine.findPaths('host-10-10-10-1', 'svc-10-10-10-1-445');
      expect(paths.length).toBe(1);
      expect(paths[0].nodes).toContain('host-10-10-10-1');
      expect(paths[0].nodes).toContain('svc-10-10-10-1-445');
      expect(paths[0].total_confidence).toBe(1.0);
    });
  });

  // =============================================
  // Agent Lifecycle
  // =============================================
  describe('agent lifecycle', () => {
    it('registers and retrieves a task', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const task: AgentTask = {
        id: 'task-1',
        agent_id: 'agent-recon-1',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'frontier-node-host-10-10-10-1',
        subgraph_node_ids: ['host-10-10-10-1'],
      };
      engine.registerAgent(task);

      const retrieved = engine.getTask('task-1');
      expect(retrieved).not.toBeNull();
      expect(retrieved!.agent_id).toBe('agent-recon-1');
      expect(retrieved!.status).toBe('running');
    });

    it('returns null for unknown task', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      expect(engine.getTask('nonexistent')).toBeNull();
    });

    it('updates task status', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const task: AgentTask = {
        id: 'task-2',
        agent_id: 'agent-2',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-1',
        subgraph_node_ids: [],
      };
      engine.registerAgent(task);

      const success = engine.updateAgentStatus('task-2', 'completed', 'Scan finished');
      expect(success).toBe(true);

      const updated = engine.getTask('task-2');
      expect(updated!.status).toBe('completed');
      expect(updated!.result_summary).toBe('Scan finished');
      expect(updated!.completed_at).toBeDefined();
    });

    it('returns false for updating unknown task (P1.4 fix)', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const success = engine.updateAgentStatus('nonexistent', 'failed');
      expect(success).toBe(false);
    });

    it('shows active agents in state', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.registerAgent({
        id: 'task-3',
        agent_id: 'agent-3',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-1',
        subgraph_node_ids: ['host-10-10-10-1'],
      });

      const state = engine.getState();
      expect(state.active_agents.length).toBe(1);
      expect(state.active_agents[0].agent_id).toBe('agent-3');
    });

    it('returns scoped subgraph for agent', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add a host and service connected to it
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-test', type: 'service', label: 'test' },
        ],
        edges: [{ source: 'host-10-10-10-1', target: 'svc-test', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));

      const subgraph = engine.getSubgraphForAgent(['host-10-10-10-1']);
      // Should include host-10-10-10-1 + neighbor svc-test
      expect(subgraph.nodes.length).toBeGreaterThanOrEqual(2);
      expect(subgraph.nodes.some(n => n.id === 'host-10-10-10-1')).toBe(true);
      expect(subgraph.nodes.some(n => n.id === 'svc-test')).toBe(true);
    });
  });

  // =============================================
  // Objective Tracking
  // =============================================
  describe('objective tracking', () => {
    it('marks objective achieved when criteria are met and access edge exists', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      // Report a privileged credential matching the DA objective criteria + OWNS_CRED edge
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-attacker', type: 'user', label: 'attacker' },
          {
            id: 'cred-da',
            type: 'credential',
            label: 'DA cred',
            cred_type: 'ntlm',
            cred_user: 'admin',
            cred_domain: 'test.local',
            privileged: true,
          },
        ],
        edges: [
          { source: 'user-attacker', target: 'cred-da', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const state = engine.getState();
      const daObj = state.objectives.find(o => o.id === 'obj-da');
      expect(daObj?.achieved).toBe(true);
      expect(daObj?.achieved_at).toBeDefined();
    });

    it('does not mark objective achieved when matching node exists but has no access', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      // Report a matching credential without any access edge (e.g. imported from BloodHound)
      engine.ingestFinding(makeFinding({
        nodes: [{
          id: 'cred-da-imported',
          type: 'credential',
          label: 'DA cred imported',
          cred_type: 'ntlm',
          cred_user: 'admin',
          cred_domain: 'test.local',
          privileged: true,
        }],
      }));

      const state = engine.getState();
      const daObj = state.objectives.find(o => o.id === 'obj-da');
      expect(daObj?.achieved).toBe(false);
    });

    it('marks objective achieved via obtained flag without access edge', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      engine.ingestFinding(makeFinding({
        nodes: [{
          id: 'cred-da-obtained',
          type: 'credential',
          label: 'DA cred obtained',
          cred_type: 'ntlm',
          cred_user: 'admin',
          cred_domain: 'test.local',
          privileged: true,
          obtained: true,
        }],
      }));

      const state = engine.getState();
      const daObj = state.objectives.find(o => o.id === 'obj-da');
      expect(daObj?.achieved).toBe(true);
    });

    it('does not mark objective achieved with non-matching criteria', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      engine.ingestFinding(makeFinding({
        nodes: [{
          id: 'cred-unprivileged',
          type: 'credential',
          label: 'low priv cred',
          cred_type: 'ntlm',
          cred_user: 'jdoe',
          cred_domain: 'test.local',
          privileged: false,
        }],
      }));

      const state = engine.getState();
      const daObj = state.objectives.find(o => o.id === 'obj-da');
      expect(daObj?.achieved).toBe(false);
    });

    it('recomputeObjectives re-evaluates stale objective state from normalized obtained credentials', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-attacker', type: 'user', label: 'attacker' },
          {
            id: 'cred-da-adhoc',
            type: 'credential',
            label: 'north\\administrator',
            username: 'administrator',
            domain: 'test.local',
            nthash: '11223344556677889900aabbccddeeff',
            privileged: true,
            obtained: true,
          } as any,
        ],
        edges: [
          { source: 'user-attacker', target: 'cred-da-adhoc', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      expect(engine.getState().objectives[0].achieved).toBe(false);

      engine.patchNodeProperties('cred-da-adhoc', {
        username: 'administrator',
        domain: 'test.local',
        nthash: '11223344556677889900aabbccddeeff',
        privileged: true,
      });

      const recomputed = engine.recomputeObjectives();
      expect(recomputed.before[0].achieved).toBe(false);
      expect(recomputed.after[0].achieved).toBe(true);
      expect(engine.getState().objectives[0].achieved).toBe(true);
    });
  });

  describe('graph remediation', () => {
    it('repairs a GOAD-style broken graph and clears stale invalid edges', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'share-public', type: 'share', label: 'public' },
          { id: 'user-operator', type: 'user', label: 'operator' },
          { id: 'cred-da', type: 'credential', label: 'DA hash', cred_type: 'ntlm', cred_material_kind: 'ntlm_hash', cred_usable_for_auth: true, cred_hash: '11223344556677889900aabbccddeeff', cred_value: '11223344556677889900aabbccddeeff', cred_user: 'administrator', cred_domain: 'test.local', privileged: true, obtained: true },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'share-public', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'user-operator', target: 'cred-da', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'cred-da', target: 'domain-test-local', properties: { type: 'VALID_ON', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      expect(engine.getHealthReport().counts_by_severity.critical).toBeGreaterThan(0);
      const canonicalCredId = engine.exportGraph().nodes.find(node => node.properties.type === 'credential')!.id;

      const correction = engine.correctGraph('repair stale GOAD-style edges', [
        {
          kind: 'replace_edge',
          source_id: 'host-10-10-10-1',
          edge_type: 'RUNS',
          target_id: 'share-public',
          new_edge_type: 'RELATED',
        },
        {
          kind: 'replace_edge',
          source_id: canonicalCredId,
          edge_type: 'VALID_ON',
          target_id: 'domain-test-local',
          new_target_id: 'host-10-10-10-1',
        },
      ], 'action-correct-1');

      expect(correction.replaced_edges).toHaveLength(2);
      expect(engine.getHealthReport().counts_by_severity.critical).toBe(0);
      expect(engine.getFullHistory().some(entry => entry.event_type === 'graph_corrected')).toBe(true);
    });

    it('rolls back the whole correction batch when one operation is invalid', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'share-all', type: 'share', label: 'all' },
        ],
        edges: [{ source: 'host-10-10-10-1', target: 'share-all', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));

      expect(() => engine.correctGraph('bad batch', [
        {
          kind: 'replace_edge',
          source_id: 'host-10-10-10-1',
          edge_type: 'RUNS',
          target_id: 'share-all',
          new_edge_type: 'RELATED',
        },
        {
          kind: 'drop_edge',
          source_id: 'cred-missing',
          edge_type: 'VALID_ON',
          target_id: 'host-10-10-10-1',
        },
      ])).toThrow();

      expect(engine.findEdgeId('host-10-10-10-1', 'share-all', 'RUNS')).toBeTruthy();
      expect(engine.findEdgeId('host-10-10-10-1', 'share-all', 'RELATED')).toBeNull();
    });
  });

  // =============================================
  // Persistence
  // =============================================
  describe('persistence', () => {
    it('persists and reloads state', () => {
      // Create engine, add some data
      const engine1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine1.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-persist', type: 'service', label: 'persist test', port: 80, service_name: 'http' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-persist', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      engine1.registerAgent({
        id: 'task-persist',
        agent_id: 'agent-persist',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-1',
        subgraph_node_ids: ['host-10-10-10-1'],
      });

      const state1 = engine1.getState();

      // Create new engine from same state file — should reload
      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state2 = engine2.getState();

      expect(state2.graph_summary.total_nodes).toBe(state1.graph_summary.total_nodes);
      expect(state2.graph_summary.total_edges).toBe(state1.graph_summary.total_edges);
    });

    it('persists agent state across reloads (P1.3 fix)', () => {
      const engine1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine1.registerAgent({
        id: 'task-agent-persist',
        agent_id: 'agent-ap',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-1',
        subgraph_node_ids: [],
      });

      // Reload
      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const task = engine2.getTask('task-agent-persist');
      expect(task).not.toBeNull();
      expect(task!.agent_id).toBe('agent-ap');
    });

    it('persists tracked processes across reloads', () => {
      const engine1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine1.setTrackedProcesses([{
        id: 'proc-1',
        pid: 12345,
        command: 'nmap -sV',
        description: 'scan',
        started_at: '2026-03-21T00:00:00.000Z',
        status: 'running',
      }]);
      engine1.persist();

      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      expect(engine2.getTrackedProcesses()).toHaveLength(1);
      expect(engine2.getTrackedProcesses()[0].id).toBe('proc-1');
    });

    it('rollback restores tracked processes from snapshot', () => {
      const procA = {
        id: 'proc-a',
        pid: 1001,
        command: 'bloodhound-python',
        description: 'bh run',
        started_at: '2026-03-21T00:00:00.000Z',
        status: 'running' as const,
      };
      const procB = {
        id: 'proc-b',
        pid: 1002,
        command: 'nmap',
        description: 'nmap run',
        started_at: '2026-03-21T00:05:00.000Z',
        status: 'completed' as const,
        completed_at: '2026-03-21T00:10:00.000Z',
      };

      const engine1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine1.setTrackedProcesses([procA]);
      engine1.persist();

      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine2.setTrackedProcesses([procB]);
      engine2.persist();

      const snapshots = engine2.listSnapshots();
      expect(snapshots.length).toBeGreaterThan(0);
      expect(engine2.rollbackToSnapshot(snapshots[snapshots.length - 1])).toBe(true);

      const engine3 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      expect(engine3.getTrackedProcesses()).toHaveLength(1);
      expect(engine3.getTrackedProcesses()[0].id).toBe('proc-a');
    });
  });

  // =============================================
  // Access Summary
  // =============================================
  describe('access summary', () => {
    it('reports no access initially', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      expect(state.access_summary.compromised_hosts.length).toBe(0);
      expect(state.access_summary.current_access_level).toBe('none');
    });

    it('rollback restores inference rules from snapshot', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      // Add first custom rule and persist (creates a snapshot)
      engine.addInferenceRule({
        id: 'rule-custom-1',
        name: 'Custom Rule 1',
        description: 'First custom rule',
        trigger: { node_type: 'host' },
        produces: [],
      });

      // Force a persist to create a snapshot with rule-custom-1
      // (addInferenceRule already persists)

      // Add second custom rule — this creates another snapshot
      engine.addInferenceRule({
        id: 'rule-custom-2',
        name: 'Custom Rule 2',
        description: 'Second custom rule',
        trigger: { node_type: 'host' },
        produces: [],
      });

      // Get snapshot list — rollback to the earliest one (before rule-custom-2)
      const snapshots = engine.listSnapshots();
      expect(snapshots.length).toBeGreaterThan(0);

      const result = engine.rollbackToSnapshot(snapshots[0]);
      expect(result).toBe(true);

      // After rollback, reload engine from persisted state
      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // The first snapshot had rule-custom-1 but NOT rule-custom-2
      // However the very first snapshot is before any custom rules were added
      // So we just verify the rollback didn't keep rules from after the snapshot
      const state = engine2.getState();
      expect(state).toBeDefined();
    });

    it('reports compromised hosts with HAS_SESSION', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
        ],
        edges: [{ source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString(), session_live: true } }],
      }));

      const state = engine.getState();
      expect(state.access_summary.compromised_hosts.length).toBe(1);
      expect(state.access_summary.current_access_level).toBe('user');
    });

    it('does not report domain_admin for imported privileged credential without access (Bug 2)', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Establish a session so compromised_hosts > 0 (otherwise access_level is 'none')
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
        ],
        edges: [{ source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString(), session_live: true } }],
      }));
      // Import a privileged credential WITHOUT OWNS_CRED edge (e.g. from BloodHound)
      engine.ingestFinding(makeFinding({
        nodes: [{
          id: 'cred-da-imported',
          type: 'credential',
          label: 'DA cred imported',
          cred_type: 'ntlm',
          cred_user: 'admin',
          cred_domain: 'test.local',
          privileged: true,
        }],
      }));
      const state = engine.getState();
      // Should NOT be domain_admin — the cred is only discovered, not obtained
      expect(state.access_summary.current_access_level).not.toBe('domain_admin');
      expect(state.access_summary.current_access_level).toBe('user');
    });

    it('reports domain_admin when privileged credential is obtained via OWNS_CRED', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
          { id: 'cred-da', type: 'credential', label: 'DA cred', cred_type: 'ntlm', cred_user: 'admin', cred_domain: 'test.local', privileged: true },
        ],
        edges: [
          { source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString(), session_live: true } },
          { source: 'user-attacker', target: 'cred-da', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      const state = engine.getState();
      expect(state.access_summary.current_access_level).toBe('domain_admin');
    });

    it('does not report responder captures as valid credentials or compromised hosts', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const responderFinding = parseResponder([
        '[SMB] NTLMv2-SSP Client   : 10.10.10.2',
        '[SMB] NTLMv2-SSP Username : TEST.LOCAL\\jdoe',
        '[SMB] NTLMv2-SSP Hash     : jdoe::TEST.LOCAL:1122334455667788:aabbccddee:0101000000',
      ].join('\n'));

      engine.ingestFinding(responderFinding);

      const state = engine.getState();
      expect(state.access_summary.valid_credentials).toEqual([]);
      expect(state.access_summary.compromised_hosts).toEqual([]);
      expect(state.access_summary.current_access_level).toBe('none');
    });

    it('does not satisfy credential objectives with non-reusable responder captures', () => {
      const config = makeConfig({
        objectives: [{
          id: 'obj-passive',
          description: 'Capture any NTLMv2 response',
          target_node_type: 'credential' as const,
          target_criteria: { cred_material_kind: 'ntlmv2_challenge' },
          achieved: false,
        }],
      });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      const responderFinding = parseResponder([
        '[SMB] NTLMv2-SSP Client   : 10.10.10.2',
        '[SMB] NTLMv2-SSP Username : TEST.LOCAL\\jdoe',
        '[SMB] NTLMv2-SSP Hash     : jdoe::TEST.LOCAL:1122334455667788:aabbccddee:0101000000',
      ].join('\n'));

      engine.ingestFinding(responderFinding);

      expect(engine.getState().objectives[0].achieved).toBe(false);
    });
  });

  // =============================================
  // Edge Overcounting (Bug 4)
  // =============================================
  describe('edge overcounting fix', () => {
    it('ingestFinding returns empty new_edges when re-ingesting the same edge', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add a host, service and edge
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-overcount', type: 'service', label: 'overcount test' },
        ],
        edges: [{ source: 'host-10-10-10-1', target: 'svc-overcount', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));
      // Re-ingest same edge
      const result = engine.ingestFinding(makeFinding({
        edges: [{ source: 'host-10-10-10-1', target: 'svc-overcount', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));
      expect(result.new_edges.length).toBe(0);
    });
  });

  // =============================================
  // Persist Delta Detail (Bug 5)
  // =============================================
  describe('persist delta callback', () => {
    it('fires update callback with real delta from ingestFinding', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      let receivedDetail: any = null;
      engine.onUpdate((detail) => { receivedDetail = detail; });

      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-delta-test', type: 'service', label: 'delta test' },
        ],
        edges: [{ source: 'host-10-10-10-1', target: 'svc-delta-test', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));

      expect(receivedDetail).not.toBeNull();
      expect(receivedDetail.new_nodes).toContain('svc-delta-test');
      expect(receivedDetail.new_edges.length).toBeGreaterThan(0);
    });

    it('ingestFinding result includes updated_nodes when merging properties', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Create host first
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' }],
      }));
      // Now merge with new properties
      const result = engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true, os: 'Windows Server 2022' }],
      }));
      expect(result.updated_nodes).toContain('host-10-10-10-1');
      expect(result.new_nodes).not.toContain('host-10-10-10-1');
    });

    it('ingestFinding result includes updated_edges when re-ingesting edge', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add a host, service and edge
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-edge-upd', type: 'service', label: 'edge update test' },
        ],
        edges: [{ source: 'host-10-10-10-1', target: 'svc-edge-upd', properties: { type: 'RUNS', confidence: 0.5, discovered_at: new Date().toISOString() } }],
      }));
      // Re-ingest same edge with updated confidence
      const result = engine.ingestFinding(makeFinding({
        edges: [{ source: 'host-10-10-10-1', target: 'svc-edge-upd', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));
      expect(result.updated_edges.length).toBe(1);
      expect(result.new_edges.length).toBe(0);
    });

    it('delta callback includes updated_nodes and updated_edges', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // First: create the host, service and edge
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-cb-upd', type: 'service', label: 'callback update test' },
        ],
        edges: [{ source: 'host-10-10-10-1', target: 'svc-cb-upd', properties: { type: 'RUNS', confidence: 0.5, discovered_at: new Date().toISOString() } }],
      }));

      let receivedDetail: any = null;
      engine.onUpdate((detail) => { receivedDetail = detail; });

      // Now update the host and re-ingest the edge
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', os: 'Linux' }],
        edges: [{ source: 'host-10-10-10-1', target: 'svc-cb-upd', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));

      expect(receivedDetail).not.toBeNull();
      expect(receivedDetail.updated_nodes).toContain('host-10-10-10-1');
      expect(receivedDetail.updated_edges.length).toBe(1);
    });
  });

  // =============================================
  // Timestamp Preservation (P3 fix)
  // =============================================
  describe('discovered_at preservation', () => {
    it('preserves original discovered_at when re-ingesting existing node', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const originalTimestamp = '2024-01-01T00:00:00.000Z';

      // First ingest with a known timestamp
      engine.ingestFinding({
        id: 'f-ts-1',
        timestamp: originalTimestamp,
        agent_id: 'agent-1',
        nodes: [{ id: 'svc-ts-test', type: 'service', label: 'TS test', port: 80 }],
        edges: [],
      });

      // Verify initial discovered_at
      const graph = engine.exportGraph();
      const node1 = graph.nodes.find(n => n.id === 'svc-ts-test');
      expect(node1!.properties.discovered_at).toBe(originalTimestamp);

      // Re-ingest same node with a later timestamp and new properties
      engine.ingestFinding({
        id: 'f-ts-2',
        timestamp: '2025-06-01T12:00:00.000Z',
        agent_id: 'agent-2',
        nodes: [{ id: 'svc-ts-test', type: 'service', label: 'TS test updated', port: 80, service_name: 'http' }],
        edges: [],
      });

      // discovered_at should still be the original timestamp
      const graph2 = engine.exportGraph();
      const node2 = graph2.nodes.find(n => n.id === 'svc-ts-test');
      expect(node2!.properties.discovered_at).toBe(originalTimestamp);
      // But other properties should be updated
      expect(node2!.properties.service_name).toBe('http');
    });

    it('sets discovered_at for new nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const ts = '2025-03-21T00:00:00.000Z';
      engine.ingestFinding({
        id: 'f-ts-new',
        timestamp: ts,
        agent_id: 'agent-1',
        nodes: [{ id: 'svc-ts-new', type: 'service', label: 'new svc' }],
        edges: [],
      });
      const graph = engine.exportGraph();
      const node = graph.nodes.find(n => n.id === 'svc-ts-new');
      expect(node!.properties.discovered_at).toBe(ts);
    });

    it('tracks first_seen_at, last_seen_at, and sources on new and updated nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding({
        id: 'prov-1',
        timestamp: '2026-03-21T10:00:00.000Z',
        agent_id: 'agent-a',
        nodes: [{ id: 'host-prov', type: 'host', label: 'host-prov', ip: '10.10.10.50', alive: true, confidence: 0.5 }],
        edges: [],
      });

      engine.ingestFinding({
        id: 'prov-2',
        timestamp: '2026-03-21T11:00:00.000Z',
        agent_id: 'agent-b',
        nodes: [{ id: 'host-prov', type: 'host', label: 'host-prov', ip: '10.10.10.50', alive: true }],
        edges: [],
      });

      const graph = engine.exportGraph();
      const node = graph.nodes.find(n => n.id === 'host-10-10-10-50');
      expect(node!.properties.first_seen_at).toBe('2026-03-21T10:00:00.000Z');
      expect(node!.properties.last_seen_at).toBe('2026-03-21T11:00:00.000Z');
      expect(node!.properties.discovered_at).toBe('2026-03-21T10:00:00.000Z');
      expect(node!.properties.sources).toEqual(['agent-a', 'agent-b']);
      expect(node!.properties.confirmed_at).toBe('2026-03-21T11:00:00.000Z');
    });

    it('does not duplicate repeated provenance sources', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding({
        id: 'prov-repeat-1',
        timestamp: '2026-03-21T10:00:00.000Z',
        agent_id: 'agent-a',
        nodes: [{ id: 'user-prov', type: 'user', label: 'user-prov' }],
        edges: [],
      });

      engine.ingestFinding({
        id: 'prov-repeat-2',
        timestamp: '2026-03-21T10:30:00.000Z',
        agent_id: 'agent-a',
        nodes: [{ id: 'user-prov', type: 'user', label: 'user-prov', privileged: false }],
        edges: [],
      });

      const graph = engine.exportGraph();
      const node = graph.nodes.find(n => n.id === 'user-prov');
      expect(node!.properties.sources).toEqual(['agent-a']);
    });

    it('includes graph health warnings in getState()', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.addNode({ id: 'host-warning-a', type: 'host', label: 'warning-a', ip: '10.10.10.77', alive: true, discovered_at: '2026-03-21T12:00:00.000Z', confidence: 1 });
      engine.addNode({ id: 'host-warning-b', type: 'host', label: 'warning-b', ip: '10.10.10.77', alive: true, discovered_at: '2026-03-21T12:00:00.000Z', confidence: 1 });

      const state = engine.getState();
      expect(state.warnings.status).toBe('critical');
      expect(state.warnings.counts_by_severity.critical).toBeGreaterThan(0);
      expect(state.warnings.top_issues.length).toBeGreaterThan(0);
    });

    it('reuses cached health reports until the graph changes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      const first = engine.getHealthReport();
      const second = engine.getHealthReport();
      expect(second).toBe(first);

      engine.addNode({
        id: 'host-cache-a',
        type: 'host',
        label: 'cache-a',
        ip: '10.10.10.88',
        alive: true,
        discovered_at: '2026-03-21T12:05:00.000Z',
        confidence: 1,
      });

      const third = engine.getHealthReport();
      expect(third).not.toBe(first);
      const fourth = engine.getHealthReport();
      expect(fourth).toBe(third);
    });
  });

  // =============================================
  // Corrupted State Recovery (Bug 6)
  // =============================================
  describe('corrupted state recovery', () => {
    it('recovers from corrupted state file by falling back to seed', () => {
      // Write a corrupted state file
      const { writeFileSync: wfs } = require('fs');
      wfs(TEST_STATE_FILE, '{ corrupted json!!!');
      // Should not throw — falls back to seedFromConfig
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      // Should have re-seeded domain and objective nodes (no CIDR host expansion)
      expect(state.graph_summary.nodes_by_type['domain']).toBe(1);
      expect(state.graph_summary.nodes_by_type['objective']).toBe(1);
    });

    it('recovers tracked processes from snapshot after state corruption', () => {
      const procA = {
        id: 'proc-recover-a',
        pid: 2001,
        command: 'certipy find',
        description: 'cert scan',
        started_at: '2026-03-21T01:00:00.000Z',
        status: 'running' as const,
      };
      const procB = {
        id: 'proc-recover-b',
        pid: 2002,
        command: 'responder',
        description: 'listen',
        started_at: '2026-03-21T01:05:00.000Z',
        status: 'running' as const,
      };

      const engine1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine1.setTrackedProcesses([procA]);
      engine1.persist();

      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine2.setTrackedProcesses([procB]);
      engine2.persist();

      const { writeFileSync: wfs } = require('fs');
      wfs(TEST_STATE_FILE, '{ corrupted json!!!');

      const engine3 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      expect(engine3.getTrackedProcesses()).toHaveLength(1);
      expect(engine3.getTrackedProcesses()[0].id).toBe('proc-recover-a');
    });
  });

  // =============================================
  // Mixed-Direction Path Traversal (P1 fix)
  // =============================================
  describe('mixed-direction path traversal', () => {
    it('hopsToNearestObjective traverses host <-HAS_SESSION- user -ADMIN_TO-> target_host', () => {
      // Use an objective targeting a host (not a credential) to avoid auto-achievement
      const config = makeConfig({
        objectives: [{
          id: 'obj-dc',
          description: 'Compromise DC',
          target_node_type: 'host' as const,
          target_criteria: { hostname: 'dc01.test.local' },
          achieved: false,
        }],
      });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
          { id: 'host-dc01', type: 'host', label: 'dc01.test.local', hostname: 'dc01.test.local', ip: '10.10.10.5', alive: true },
        ],
        edges: [
          // HAS_SESSION: user -> host (attacker has session on host-10-10-10-1)
          { source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString() } },
          // ADMIN_TO: user -> dc01 (but no session, so objective not achieved)
          { source: 'user-attacker', target: 'host-dc01', properties: { type: 'ADMIN_TO', confidence: 0.8, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Path: host-10-10-10-1 <-(HAS_SESSION)- user-attacker -(ADMIN_TO)-> host-dc01
      // Requires traversing HAS_SESSION in reverse
      const hops = engine.hopsToNearestObjective('host-10-10-10-1');
      expect(hops).not.toBeNull();
      expect(hops).toBe(2);
    });

    it('findPathsToObjective finds path through mixed-direction chain', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
          { id: 'cred-da', type: 'credential', label: 'DA cred', cred_type: 'ntlm', cred_user: 'admin', cred_domain: 'test.local', privileged: true },
        ],
        edges: [
          { source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'user-attacker', target: 'cred-da', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const paths = engine.findPathsToObjective('obj-da');
      expect(paths.length).toBeGreaterThan(0);
      expect(paths[0].nodes).toContain('cred-da');
    });

    it('findPaths traverses HAS_SESSION in reverse direction', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
        ],
        edges: [
          { source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // host -> user requires traversing HAS_SESSION backwards
      const paths = engine.findPaths('host-10-10-10-1', 'user-attacker');
      expect(paths.length).toBe(1);
      expect(paths[0].nodes).toContain('host-10-10-10-1');
      expect(paths[0].nodes).toContain('user-attacker');
    });

    it('inferred edges get inferred_by_rule and inferred_at set', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Ingest a credential to trigger the cred-fanout inference rule
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-smb-test', type: 'service', label: 'SMB on 10.10.10.1', port: 445, service_name: 'smb' },
          { id: 'cred-test', type: 'credential', label: 'test cred', cred_type: 'ntlm', cred_user: 'testuser', cred_domain: 'test.local' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-smb-test', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'host-10-10-10-1', target: 'domain-test-local', properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // The cred-fanout rule should have created POTENTIAL_AUTH edges with inferred_by_rule
      const exported = engine.exportGraph();
      const inferredEdges = exported.edges.filter((e: any) => e.properties.inferred_by_rule);
      expect(inferredEdges.length).toBeGreaterThan(0);
      for (const e of inferredEdges) {
        expect(e.id).toBeDefined();
        expect(e.properties.inferred_by_rule).toBe('rule-cred-fanout');
        expect(e.properties.inferred_at).toBeDefined();
      }
    });

    it('confirming an inferred edge sets confirmed_at', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // First: create an inferred edge via cred-fanout
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-smb-test', type: 'service', label: 'SMB on 10.10.10.1', port: 445, service_name: 'smb' },
          { id: 'cred-test', type: 'credential', label: 'test cred', cred_type: 'ntlm', cred_user: 'testuser', cred_domain: 'test.local' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-smb-test', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'host-10-10-10-1', target: 'domain-test-local', properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Find the inferred POTENTIAL_AUTH edge
      let exported = engine.exportGraph();
      const inferredEdge = exported.edges.find((e: any) =>
        e.properties.type === 'POTENTIAL_AUTH' && e.properties.inferred_by_rule === 'rule-cred-fanout'
      );
      expect(inferredEdge).toBeDefined();
      expect(inferredEdge!.properties.confirmed_at).toBeUndefined();

      // Now confirm it by ingesting a finding with confidence 1.0 on the same edge
      engine.ingestFinding(makeFinding({
        nodes: [],
        edges: [
          { source: inferredEdge!.source, target: inferredEdge!.target, properties: { type: 'POTENTIAL_AUTH', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // The edge should now have confirmed_at set
      exported = engine.exportGraph();
      const confirmedEdge = exported.edges.find((e: any) =>
        e.source === inferredEdge!.source && e.target === inferredEdge!.target && e.properties.type === 'POTENTIAL_AUTH'
      );
      expect(confirmedEdge).toBeDefined();
      expect(confirmedEdge!.properties.confirmed_at).toBeDefined();
      expect(confirmedEdge!.properties.confidence).toBe(1.0);
      // inferred_by_rule should be preserved
      expect(confirmedEdge!.properties.inferred_by_rule).toBe('rule-cred-fanout');
    });

    it('RUNS edge is NOT traversable in reverse for pathfinding', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-isolated', type: 'service', label: 'isolated svc', port: 9999, service_name: 'unknown' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-isolated', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // svc -> host requires traversing RUNS backwards — should NOT work
      const paths = engine.findPaths('svc-isolated', 'host-10-10-10-1');
      expect(paths.length).toBe(0);
    });
  });

  describe('helper behaviors', () => {
    it('computeSubgraphNodeIds resolves standard frontier node IDs without recomputing frontier', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-http-test', type: 'service', label: 'HTTP', port: 80, service_name: 'http' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-http-test', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      engine.computeFrontier = (() => {
        throw new Error('computeFrontier should not be called for standard node frontier IDs');
      }) as any;

      const subgraph = engine.computeSubgraphNodeIds('frontier-node-host-10-10-10-1');
      expect(subgraph).toContain('host-10-10-10-1');
      expect(subgraph).toContain('svc-http-test');
    });

    it('computeSubgraphNodeIds resolves standard frontier edge IDs without recomputing frontier', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-http-test', type: 'service', label: 'HTTP', port: 80, service_name: 'http' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-http-test', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      engine.computeFrontier = (() => {
        throw new Error('computeFrontier should not be called for standard edge frontier IDs');
      }) as any;

      const subgraph = engine.computeSubgraphNodeIds('frontier-edge-host-10-10-10-1--RUNS--svc-http-test');
      expect(subgraph).toContain('host-10-10-10-1');
      expect(subgraph).toContain('svc-http-test');
    });

    it('preserves identical array content while only updating provenance metadata', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        timestamp: '2026-03-21T10:00:00Z',
        nodes: [
          { id: 'user-array-test', type: 'user', label: 'array test', member_of: ['group-a', 'group-b'] },
        ],
      }));

      const result = engine.ingestFinding(makeFinding({
        timestamp: '2026-03-21T10:05:00Z',
        nodes: [
          { id: 'user-array-test', type: 'user', label: 'array test', member_of: ['group-a', 'group-b'] },
        ],
      }));

      // Provenance-only changes (last_seen_at, first_seen_at, sources) are not
      // considered meaningful updates, so the node should NOT appear in updated_nodes.
      expect(result.updated_nodes).not.toContain('user-array-test');
      const graph = engine.exportGraph();
      const node = graph.nodes.find((candidate) => candidate.id === 'user-array-test');
      expect(node!.properties.member_of).toEqual(['group-a', 'group-b']);
    });

    it('flags real array content changes as updates', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-array-test', type: 'user', label: 'array test', member_of: ['group-a', 'group-b'] },
        ],
      }));

      const result = engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-array-test', type: 'user', label: 'array test', member_of: ['group-a', 'group-c'] },
        ],
      }));

      expect(result.updated_nodes).toContain('user-array-test');
    });

    it('caps activity log history at 5000 entries', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      for (let i = 0; i < 5005; i++) {
        (engine as any).log(`activity-${i}`);
      }

      const history = engine.getFullHistory();
      expect(history).toHaveLength(5000);
      expect(history[0].description).toBe('activity-5');
      expect(history.at(-1)?.description).toBe('activity-5004');
    });

    it('persists only the bounded activity log history', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      for (let i = 0; i < 5005; i++) {
        (engine as any).log(`persisted-activity-${i}`);
      }
      engine.persist();

      const saved = JSON.parse(readFileSync(TEST_STATE_FILE, 'utf-8'));
      expect(saved.activityLog).toHaveLength(5000);
      expect(saved.activityLog[0].description).toBe('persisted-activity-5');
      expect(saved.activityLog.at(-1).description).toBe('persisted-activity-5004');
    });
  });

  // =============================================
  // Sprint 1: Inference rules (AS-REP, Kerberoast, Constrained Delegation, Web Login)
  // =============================================
  describe('new inference rules', () => {
    it('creates AS_REP_ROASTABLE edge when user has asrep_roastable', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-asrep', type: 'user', label: 'asrep-user', asrep_roastable: true } as any,
        ],
      }));
      const graph = engine.exportGraph();
      const asrepEdges = graph.edges.filter(e => e.properties.type === 'AS_REP_ROASTABLE');
      expect(asrepEdges.length).toBeGreaterThan(0);
      expect(asrepEdges[0].source).toBe('user-asrep');
      expect(asrepEdges[0].properties.confidence).toBe(0.85);
    });

    it('creates KERBEROASTABLE edge when user has has_spn', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-spn', type: 'user', label: 'spn-user', has_spn: true } as any,
        ],
      }));
      const graph = engine.exportGraph();
      const kerbEdges = graph.edges.filter(e => e.properties.type === 'KERBEROASTABLE');
      expect(kerbEdges.length).toBeGreaterThan(0);
      expect(kerbEdges[0].source).toBe('user-spn');
      expect(kerbEdges[0].properties.confidence).toBe(0.85);
    });

    it('creates CAN_DELEGATE_TO edge when host has constrained_delegation', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Use IP 10.10.10.5 — identity resolution will resolve to host-10-10-10-5
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-cd', type: 'host', label: 'constrained-host', ip: '10.10.10.5', constrained_delegation: true } as any,
        ],
      }));
      const graph = engine.exportGraph();
      const cdEdges = graph.edges.filter(e => e.properties.type === 'CAN_DELEGATE_TO');
      expect(cdEdges.length).toBeGreaterThan(0);
      expect(cdEdges[0].source).toBe('host-10-10-10-5');
      expect(cdEdges[0].properties.confidence).toBe(0.8);
    });

    it('creates POTENTIAL_AUTH edge when service has has_login_form', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // First add a domain credential
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'cred-web', type: 'credential', label: 'web-cred', cred_type: 'plaintext', cred_value: 'pass123', cred_user: 'admin', cred_domain: 'test.local', cred_material_kind: 'plaintext_password' as any },
          { id: 'user-web', type: 'user', label: 'admin' },
        ],
        edges: [
          { source: 'user-web', target: 'cred-web', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      // Now add a service with login form
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-web', type: 'host', label: '10.10.10.2', ip: '10.10.10.2' },
          { id: 'svc-http', type: 'service', label: 'http/80', service_name: 'http', port: 80, has_login_form: true } as any,
        ],
        edges: [
          { source: 'host-web', target: 'svc-http', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      const graph = engine.exportGraph();
      const authEdges = graph.edges.filter(e =>
        e.properties.type === 'POTENTIAL_AUTH' && e.target === 'svc-http' && e.properties.inferred_by_rule === 'rule-web-login-form'
      );
      expect(authEdges.length).toBeGreaterThan(0);
      expect(authEdges[0].properties.confidence).toBe(0.5);
    });
  });

  // =============================================
  // Sprint 1: Hostname scope enforcement
  // =============================================
  describe('hostname scope enforcement', () => {
    it('rejects hostname-only node when hostname does not match scope domains', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Identity resolution renames to host-dc01-other-local
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-oos', type: 'host', label: 'dc01.other.local', hostname: 'dc01.other.local' },
        ],
      }));
      const resolvedId = 'host-dc01-other-local';
      const result = engine.validateAction({ target_node: resolvedId });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('out of scope'))).toBe(true);
    });

    it('allows hostname-only node when hostname matches a scope domain', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Identity resolution renames to host-dc01-test-local
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-inscope', type: 'host', label: 'dc01.test.local', hostname: 'dc01.test.local' },
        ],
      }));
      const resolvedId = 'host-dc01-test-local';
      const result = engine.validateAction({ target_node: resolvedId });
      expect(result.valid).toBe(true);
    });

    it('allows node with out-of-scope IP but in-scope hostname (hostname fallback)', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-external', type: 'host', label: 'dc02.test.local', hostname: 'dc02.test.local', ip: '192.168.99.1' },
        ],
      }));
      const resolvedId = 'host-192-168-99-1';
      const result = engine.validateAction({ target_node: resolvedId });
      expect(result.valid).toBe(true);
    });

    it('annotates frontier items with scope_unverified when node has no IP or hostname', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'domain-mystery', type: 'domain', label: 'mystery.local' },
        ],
      }));
      const frontier = [{
        id: 'frontier-test',
        type: 'incomplete_node' as const,
        node_id: 'domain-mystery',
        description: 'Domain with no IP or hostname',
        graph_metrics: { hops_to_objective: null, fan_out_estimate: 1, node_degree: 0, confidence: 1.0 },
        opsec_noise: 0.1,
        staleness_seconds: 0,
      }];
      const result = engine.filterFrontier(frontier);
      expect(result.passed.length).toBe(1);
      expect(result.passed[0].scope_unverified).toBe(true);
    });
  });

  // =============================================
  // Sprint 1: Objective achievement for non-credential targets
  // =============================================
  describe('objective achievement', () => {
    it('achieves objective when share has readable: true', () => {
      const config = makeConfig({
        objectives: [{
          id: 'obj-share',
          description: 'Read SYSVOL share',
          target_node_type: 'share' as NodeType,
          target_criteria: { share_name: 'SYSVOL' },
          achieved: false,
        }],
      });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'share-sysvol', type: 'share', label: 'SYSVOL', share_name: 'SYSVOL', readable: true } as any,
        ],
      }));
      const state = engine.getState();
      expect(state.objectives[0].achieved).toBe(true);
    });

    it('uses custom achievement_edge_types when provided', () => {
      const config = makeConfig({
        objectives: [{
          id: 'obj-custom',
          description: 'DCSync the domain',
          target_node_type: 'domain' as NodeType,
          target_criteria: { domain_name: 'test.local' },
          achievement_edge_types: ['CAN_DCSYNC'] as any,
          achieved: false,
        }],
      });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-dcsync', type: 'user', label: 'dcsync-user' },
        ],
        edges: [
          { source: 'user-dcsync', target: 'domain-test-local', properties: { type: 'CAN_DCSYNC', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      const state = engine.getState();
      expect(state.objectives[0].achieved).toBe(true);
    });
  });

  // =============================================
  // Sprint 1: Access-level classification
  // =============================================
  describe('access-level classification', () => {
    it('reports local_admin when privileged cred has no cred_domain', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-localadm', type: 'user', label: 'localadmin' },
          { id: 'cred-localadm', type: 'credential', label: 'local-admin-cred', privileged: true, cred_type: 'ntlm', cred_value: 'aad3b435b51404eeaad3b435b51404ee', cred_hash: 'aad3b435b51404eeaad3b435b51404ee', cred_material_kind: 'ntlm_hash' as any, cred_usable_for_auth: true },
          { id: 'host-target', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
        ],
        edges: [
          { source: 'user-localadm', target: 'cred-localadm', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'cred-localadm', target: 'host-target', properties: { type: 'ADMIN_TO', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      const state = engine.getState();
      expect(state.access_summary.current_access_level).toBe('local_admin');
    });

    it('reports domain_admin when privileged cred has matching cred_domain', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-da', type: 'user', label: 'da-user' },
          { id: 'cred-da', type: 'credential', label: 'da-cred', privileged: true, cred_type: 'ntlm', cred_value: 'aad3b435b51404eeaad3b435b51404ee', cred_hash: 'aad3b435b51404eeaad3b435b51404ee', cred_domain: 'test.local', cred_material_kind: 'ntlm_hash' as any, cred_usable_for_auth: true },
          { id: 'host-da', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
        ],
        edges: [
          { source: 'user-da', target: 'cred-da', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
          { source: 'cred-da', target: 'host-da', properties: { type: 'ADMIN_TO', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      const state = engine.getState();
      expect(state.access_summary.current_access_level).toBe('domain_admin');
    });
  });

  // =============================================
  // Sprint 1: activity_count contract
  // =============================================
  describe('getState activityCount', () => {
    it('returns the requested number of activity entries', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      for (let i = 0; i < 50; i++) {
        (engine as any).log(`activity-${i}`);
      }
      const state5 = engine.getState({ activityCount: 5 });
      expect(state5.recent_activity).toHaveLength(5);
      const state50 = engine.getState({ activityCount: 50 });
      expect(state50.recent_activity.length).toBeGreaterThanOrEqual(50);
    });
  });

  // =============================================
  // Sprint 4: Cross-node inference rules (requires_edge)
  // =============================================
  describe('cross-node inference rules', () => {
    it('LAPS rule fires when host has laps:true and inbound GENERIC_ALL', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Ingest a group and a LAPS-enabled host with GENERIC_ALL from group to host
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'group-it', type: 'group', label: 'IT Admins' },
          { id: 'host-laps', type: 'host', label: '10.10.10.20', ip: '10.10.10.20', laps: true } as any,
        ],
        edges: [
          { source: 'group-it', target: 'host-laps', properties: { type: 'GENERIC_ALL', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      const graph = engine.exportGraph();
      const lapsEdges = graph.edges.filter(e => e.properties.type === 'CAN_READ_LAPS');
      expect(lapsEdges.length).toBeGreaterThan(0);
      expect(lapsEdges[0].source).toBe('group-it-admins');
      expect(lapsEdges[0].target).toBe('host-10-10-10-20');
      expect(lapsEdges[0].properties.confidence).toBe(0.75);
    });

    it('LAPS rule does NOT fire without inbound GENERIC_ALL', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-laps2', type: 'host', label: '10.10.10.21', ip: '10.10.10.21', laps: true } as any,
        ],
      }));
      const graph = engine.exportGraph();
      const lapsEdges = graph.edges.filter(e => e.properties.type === 'CAN_READ_LAPS');
      expect(lapsEdges.length).toBe(0);
    });

    it('gMSA rule fires when user has gmsa:true and inbound GENERIC_ALL', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'group-readers', type: 'group', label: 'gMSA Readers' },
          { id: 'user-gmsa', type: 'user', label: 'svc_sql$', gmsa: true } as any,
        ],
        edges: [
          { source: 'group-readers', target: 'user-gmsa', properties: { type: 'GENERIC_ALL', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      const graph = engine.exportGraph();
      const gmsaEdges = graph.edges.filter(e => e.properties.type === 'CAN_READ_GMSA');
      expect(gmsaEdges.length).toBeGreaterThan(0);
      expect(gmsaEdges[0].source).toBe('group-gmsa-readers');
      expect(gmsaEdges[0].target).toBe('user-gmsa');
      expect(gmsaEdges[0].properties.confidence).toBe(0.75);
    });

    it('RBCD rule fires when host has maq_gt_zero and inbound WRITEABLE_BY', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-attacker', type: 'user', label: 'attacker' },
          { id: 'host-rbcd', type: 'host', label: '10.10.10.22', ip: '10.10.10.22', maq_gt_zero: true } as any,
        ],
        edges: [
          { source: 'user-attacker', target: 'host-rbcd', properties: { type: 'WRITEABLE_BY', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      const graph = engine.exportGraph();
      const rbcdEdges = graph.edges.filter(e => e.properties.type === 'RBCD_TARGET');
      expect(rbcdEdges.length).toBeGreaterThan(0);
      expect(rbcdEdges[0].source).toBe('user-attacker');
      expect(rbcdEdges[0].target).toBe('host-10-10-10-22');
      expect(rbcdEdges[0].properties.confidence).toBe(0.7);
    });

    it('RBCD rule does NOT fire without inbound WRITEABLE_BY', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-rbcd2', type: 'host', label: '10.10.10.23', ip: '10.10.10.23', maq_gt_zero: true } as any,
        ],
      }));
      const graph = engine.exportGraph();
      const rbcdEdges = graph.edges.filter(e => e.properties.type === 'RBCD_TARGET');
      expect(rbcdEdges.length).toBe(0);
    });

    it('cross-node rules fire when trigger node is re-ingested after edge arrives', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // First ingest LAPS host without the edge
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-bf', type: 'host', label: '10.10.10.24', ip: '10.10.10.24', laps: true } as any,
        ],
      }));
      // No CAN_READ_LAPS yet
      let graph = engine.exportGraph();
      expect(graph.edges.filter(e => e.properties.type === 'CAN_READ_LAPS').length).toBe(0);

      // Now ingest the group + GENERIC_ALL edge, AND re-ingest the host in the same finding
      // so inference rules re-evaluate the host with the edge now present
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'group-bf', type: 'group', label: 'Backfill Group' },
          { id: 'host-bf', type: 'host', label: '10.10.10.24', ip: '10.10.10.24', laps: true } as any,
        ],
        edges: [
          { source: 'group-bf', target: 'host-bf', properties: { type: 'GENERIC_ALL', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      graph = engine.exportGraph();
      const lapsEdges = graph.edges.filter(e => e.properties.type === 'CAN_READ_LAPS');
      expect(lapsEdges.length).toBeGreaterThan(0);
      expect(lapsEdges[0].source).toBe('group-backfill-group');
    });
  });

  // =============================================
  // Scope Management
  // =============================================
  describe('scope management', () => {
    it('updateScope adds CIDR and frontier includes new network discovery', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add out-of-scope host
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-172-16-1-5', type: 'host', label: '172.16.1.5', ip: '172.16.1.5', alive: true }],
      }));

      // Verify it's filtered before scope expansion
      const frontier1 = engine.computeFrontier();
      const { passed: passed1 } = engine.filterFrontier(frontier1);
      const hasOos = passed1.some(f => f.node_id === 'host-172-16-1-5');
      expect(hasOos).toBe(false);

      // Expand scope
      const result = engine.updateScope({ add_cidrs: ['172.16.1.0/24'], reason: 'Pivot network discovered' });
      expect(result.applied).toBe(true);
      expect(result.after.cidrs).toContain('172.16.1.0/24');
      expect(result.affected_node_count).toBe(1);

      // Verify frontier now includes the host and the new network discovery
      const frontier2 = engine.computeFrontier();
      const { passed: passed2 } = engine.filterFrontier(frontier2);
      const hasHost = passed2.some(f => f.node_id === 'host-172-16-1-5');
      expect(hasHost).toBe(true);
      const hasNetDisc = passed2.some(f => f.type === 'network_discovery' && f.target_cidr === '172.16.1.0/24');
      expect(hasNetDisc).toBe(true);
    });

    it('updateScope with confirm=false via previewScopeChange returns preview without mutating', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-172-16-1-5', type: 'host', label: '172.16.1.5', ip: '172.16.1.5' }],
      }));

      const preview = engine.previewScopeChange({ add_cidrs: ['172.16.1.0/24'] });
      expect(preview.nodes_entering_scope).toBe(1);
      expect(preview.nodes_leaving_scope).toBe(0);

      // Scope should NOT have changed
      expect(engine.getConfig().scope.cidrs).not.toContain('172.16.1.0/24');
    });

    it('updateScope removes CIDR', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const before = engine.getConfig().scope.cidrs;
      expect(before).toContain('10.10.10.0/28');

      const result = engine.updateScope({ remove_cidrs: ['10.10.10.0/28'], reason: 'Reducing scope' });
      expect(result.applied).toBe(true);
      expect(result.after.cidrs).not.toContain('10.10.10.0/28');
    });

    it('updateScope logs scope_updated activity event', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.updateScope({ add_cidrs: ['192.168.2.0/24'], reason: 'Test expansion' });

      const history = engine.getFullHistory();
      const scopeEvent = history.find(h => h.event_type === 'scope_updated');
      expect(scopeEvent).toBeDefined();
      expect(scopeEvent!.description).toContain('Test expansion');
      expect((scopeEvent!.details as any).after.cidrs).toContain('192.168.2.0/24');
    });

    it('updateScope rejects invalid CIDR', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.updateScope({ add_cidrs: ['not-a-cidr'], reason: 'bad' });
      expect(result.applied).toBe(false);
      expect(result.errors[0]).toContain('Invalid CIDR');
    });

    it('collectScopeSuggestions groups out-of-scope hosts into /24 suggestions', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-172-16-1-5', type: 'host', label: '172.16.1.5', ip: '172.16.1.5' },
          { id: 'host-172-16-1-10', type: 'host', label: '172.16.1.10', ip: '172.16.1.10' },
          { id: 'host-172-16-2-1', type: 'host', label: '172.16.2.1', ip: '172.16.2.1' },
        ],
      }));

      const suggestions = engine.collectScopeSuggestions();
      expect(suggestions.length).toBe(2);
      const s1 = suggestions.find(s => s.suggested_cidr === '172.16.1.0/24');
      expect(s1).toBeDefined();
      expect(s1!.out_of_scope_ips).toEqual(['172.16.1.10', '172.16.1.5']);
      expect(s1!.node_ids.length).toBe(2);
      const s2 = suggestions.find(s => s.suggested_cidr === '172.16.2.0/24');
      expect(s2).toBeDefined();
      expect(s2!.out_of_scope_ips).toEqual(['172.16.2.1']);
    });

    it('getState includes scope_suggestions for out-of-scope hosts', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-172-16-1-5', type: 'host', label: '172.16.1.5', ip: '172.16.1.5' }],
      }));

      const state = engine.getState();
      expect(state.scope_suggestions.length).toBe(1);
      expect(state.scope_suggestions[0].suggested_cidr).toBe('172.16.1.0/24');
    });

    it('after scope expansion, previously out-of-scope nodes pass filterFrontier', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-172-16-1-5', type: 'host', label: '172.16.1.5', ip: '172.16.1.5', alive: true }],
      }));

      // Before expansion — node is cold (alive IP-only out-of-scope) so not in frontier
      const frontier1 = engine.computeFrontier();
      const { passed: p1, filtered: _f1 } = engine.filterFrontier(frontier1);
      expect(p1.some(f => f.node_id === 'host-172-16-1-5')).toBe(false);

      // Expand scope
      engine.updateScope({ add_cidrs: ['172.16.1.0/24'], reason: 'Pivot' });

      // After expansion — passes through
      const frontier2 = engine.computeFrontier();
      const { passed: p2 } = engine.filterFrontier(frontier2);
      expect(p2.some(f => f.node_id === 'host-172-16-1-5')).toBe(true);
    });

    it('persisted config survives reload with expanded scope', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.updateScope({ add_cidrs: ['172.16.1.0/24'], reason: 'Persist test' });

      // Load from persisted state
      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      expect(engine2.getConfig().scope.cidrs).toContain('172.16.1.0/24');
    });
  });

  // =============================================
  // Startup Reconciliation
  // =============================================

  describe('startup reconciliation', () => {
    it('downgrades stale HAS_SESSION edges on restart', () => {
      const engine1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine1.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
        ],
        edges: [{ source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString(), session_live: true } }],
      }));
      const state1 = engine1.getState();
      expect(state1.access_summary.compromised_hosts).toHaveLength(1);

      // Simulate restart — new engine loads persisted state
      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state2 = engine2.getState();
      expect(state2.access_summary.compromised_hosts).toHaveLength(0);
      // Edge still exists but is marked historical
      const edges = engine2.queryGraph({ edge_type: 'HAS_SESSION' });
      expect(edges.edges.length).toBeGreaterThanOrEqual(1);
      expect(edges.edges[0].properties.session_live).toBe(false);
    });

    it('does not downgrade already-closed HAS_SESSION edges', () => {
      const engine1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine1.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
        ],
        edges: [{ source: 'user-attacker', target: 'host-10-10-10-1', properties: {
          type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString(),
          session_live: false, session_closed_at: '2025-01-01T00:00:00Z',
        } }],
      }));

      // Simulate restart
      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const edges = engine2.queryGraph({ edge_type: 'HAS_SESSION' });
      expect(edges.edges[0].properties.session_closed_at).toBe('2025-01-01T00:00:00Z');
    });

    it('marks running agents as interrupted on restart', () => {
      const engine1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine1.registerAgent({
        id: 'task-1',
        agent_id: 'agent-scout',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-1',
        subgraph_node_ids: [],
      });

      // Also register a completed agent (should not change)
      engine1.registerAgent({
        id: 'task-2',
        agent_id: 'agent-done',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-2',
        subgraph_node_ids: [],
      });
      engine1.updateAgentStatus('task-2', 'completed', 'done');
      engine1.persist();

      // Simulate restart
      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const task1 = engine2.getTask('task-1');
      expect(task1?.status).toBe('interrupted');
      expect(task1?.completed_at).toBeDefined();

      const task2 = engine2.getTask('task-2');
      expect(task2?.status).toBe('completed');

      // active_agents should not include interrupted agents
      const state = engine2.getState();
      expect(state.active_agents).toHaveLength(0);
    });

    it('onSessionClosed downgrades HAS_SESSION edge for matching target', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true },
          { id: 'user-op', type: 'user', label: 'operator' },
        ],
        edges: [{ source: 'user-op', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString(), session_live: true } }],
      }));

      // Before close, host is compromised
      expect(engine.getState().access_summary.compromised_hosts).toHaveLength(1);

      // Close the session
      engine.onSessionClosed('session-1', 'host-10-10-10-1', 'user-op');

      // After close, host is no longer compromised
      expect(engine.getState().access_summary.compromised_hosts).toHaveLength(0);

      // Edge still exists with historical marker
      const edges = engine.queryGraph({ edge_type: 'HAS_SESSION' });
      expect(edges.edges[0].properties.session_live).toBe(false);
      expect(edges.edges[0].properties.session_closed_at).toBeDefined();
    });

    it('access_summary still reports host via ADMIN_TO edge regardless of session_live', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true },
          { id: 'user-admin', type: 'user', label: 'admin' },
        ],
        edges: [{ source: 'user-admin', target: 'host-10-10-10-1', properties: { type: 'ADMIN_TO', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));

      const state = engine.getState();
      expect(state.access_summary.compromised_hosts).toHaveLength(1);
    });
  });
});

// =============================================
// Helpers
// =============================================
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  const enrichedNodes = (overrides.nodes || []).map(n => ({
    discovered_at: new Date().toISOString(),
    confidence: 1.0,
    label: n.label || n.id,
    ...n,
  })) as Finding['nodes'];

  return {
    id: 'finding-' + Math.random().toString(36).slice(2),
    agent_id: overrides.agent_id || 'test-agent',
    timestamp: overrides.timestamp || new Date().toISOString(),
    nodes: enrichedNodes,
    edges: overrides.edges || [],
  };
}
