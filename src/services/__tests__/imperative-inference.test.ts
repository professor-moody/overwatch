import { describe, it, expect, afterEach } from 'vitest';
import { GraphEngine } from '../graph-engine.js';
import { unlinkSync, existsSync } from 'fs';
import type { EngagementConfig, Finding } from '../../types.js';

const TEST_STATE_FILE = './state-test-imperative-inf.json';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-imp-inf',
    name: 'Imperative Inference Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  };
}

function cleanup() {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch { /* noop */ }
}

const now = new Date().toISOString();

function makeFinding(nodes: Finding['nodes'], edges: Finding['edges'] = []): Finding {
  return { id: `f-${Date.now()}-${Math.random()}`, agent_id: 'test', timestamp: now, nodes, edges };
}

// ============================================================
// inferPivotReachability
// ============================================================
describe('inferPivotReachability', () => {
  afterEach(cleanup);

  it('does not create REACHABLE edge when session confidence < 0.9', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-70', type: 'host', label: 'low-sess-a', ip: '10.10.10.70', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-71', type: 'host', label: 'low-sess-b', ip: '10.10.10.71', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'user-low-sess', type: 'user', label: 'low-sess', username: 'low-sess', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-low-sess', target: 'host-10-10-10-70', properties: { type: 'HAS_SESSION', confidence: 0.5, discovered_at: now } }],
    ));
    const edges = engine.queryGraph({ from_node: 'host-10-10-10-70', edge_type: 'REACHABLE' });
    expect(edges.edges.find(e => e.target === 'host-10-10-10-71')).toBeUndefined();
  });

  it('REACHABLE edge has confidence 0.6 and correct provenance', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-80', type: 'host', label: 'prov-a', ip: '10.10.10.80', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-81', type: 'host', label: 'prov-b', ip: '10.10.10.81', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'user-prov', type: 'user', label: 'prov', username: 'prov', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-prov', target: 'host-10-10-10-80', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } }],
    ));
    const edges = engine.queryGraph({ from_node: 'host-10-10-10-80', edge_type: 'REACHABLE' });
    const reachable = edges.edges.find(e => e.target === 'host-10-10-10-81');
    expect(reachable).toBeDefined();
    expect(reachable!.properties.confidence).toBe(0.6);
    expect(reachable!.properties.discovered_by).toBe('inference:pivot-reachability');
    expect(reachable!.properties.tested).toBe(false);
  });

  it('skips host nodes without an ip property', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-no-ip', type: 'host', label: 'no-ip', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-82', type: 'host', label: 'peer', ip: '10.10.10.82', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'user-sess-noip', type: 'user', label: 'u', username: 'u', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-sess-noip', target: 'host-no-ip', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } }],
    ));
    const edges = engine.queryGraph({ from_node: 'host-no-ip', edge_type: 'REACHABLE' });
    expect(edges.edges.length).toBe(0);
  });

  it('creates REACHABLE edges to multiple peers in the same subnet', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-90', type: 'host', label: 'multi-a', ip: '10.10.10.90', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-91', type: 'host', label: 'multi-b', ip: '10.10.10.91', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-92', type: 'host', label: 'multi-c', ip: '10.10.10.92', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'user-multi', type: 'user', label: 'multi', username: 'multi', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-multi', target: 'host-10-10-10-90', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } }],
    ));
    const edges = engine.queryGraph({ from_node: 'host-10-10-10-90', edge_type: 'REACHABLE' });
    const targets = edges.edges.map(e => e.target);
    expect(targets).toContain('host-10-10-10-91');
    expect(targets).toContain('host-10-10-10-92');
  });

  it('does not create REACHABLE edge to self', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-95', type: 'host', label: 'self-a', ip: '10.10.10.95', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'user-self', type: 'user', label: 'self', username: 'self', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-self', target: 'host-10-10-10-95', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } }],
    ));
    const edges = engine.queryGraph({ from_node: 'host-10-10-10-95', edge_type: 'REACHABLE' });
    expect(edges.edges.find(e => e.target === 'host-10-10-10-95')).toBeUndefined();
  });
});

// ============================================================
// inferDefaultCredentials
// ============================================================
describe('inferDefaultCredentials', () => {
  afterEach(cleanup);

  it('fires for each supported CMS type', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const cmsTypes = ['tomcat', 'jenkins', 'grafana', 'phpmyadmin'] as const;
    const expectedUsers: Record<string, string> = {
      tomcat: 'tomcat', jenkins: 'admin', grafana: 'admin', phpmyadmin: 'root',
    };
    for (const cms of cmsTypes) {
      engine.ingestFinding(makeFinding([{
        id: `webapp-${cms}`, type: 'webapp', label: `http://10.10.10.5/${cms}`,
        discovered_at: now, confidence: 1.0, cms_type: cms,
      }]));
    }
    for (const cms of cmsTypes) {
      const cred = engine.getNode(`cred-default-${cms}`);
      expect(cred).toBeDefined();
      expect(cred!.cred_user).toBe(expectedUsers[cms]);
      expect(cred!.cred_is_default_guess).toBe(true);
      expect(cred!.cred_material_kind).toBe('plaintext_password');
    }
  });

  it('sets cred_evidence_kind to manual on default credential nodes', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'webapp-grafana', type: 'webapp', label: 'http://10.10.10.5/grafana',
      discovered_at: now, confidence: 1.0, cms_type: 'grafana',
    }]));
    const cred = engine.getNode('cred-default-grafana');
    expect(cred).toBeDefined();
    expect(cred!.cred_evidence_kind).toBe('manual');
    expect(cred!.confidence).toBe(0.3);
  });

  it('creates POTENTIAL_AUTH edge with confidence 0.3', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'webapp-jenkins', type: 'webapp', label: 'http://10.10.10.5/jenkins',
      discovered_at: now, confidence: 1.0, cms_type: 'jenkins',
    }]));
    const edges = engine.queryGraph({ from_node: 'cred-default-jenkins', edge_type: 'POTENTIAL_AUTH' });
    const authEdge = edges.edges.find(e => e.target === 'webapp-jenkins');
    expect(authEdge).toBeDefined();
    expect(authEdge!.properties.confidence).toBe(0.3);
    expect(authEdge!.properties.inferred_by_rule).toBe('default-creds');
  });

  it('creates separate credentials for distinct CMS types in one ingestion', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([
      { id: 'webapp-tc', type: 'webapp', label: 'http://10.10.10.5/tomcat', discovered_at: now, confidence: 1.0, cms_type: 'tomcat' },
      { id: 'webapp-jk', type: 'webapp', label: 'http://10.10.10.5/jenkins', discovered_at: now, confidence: 1.0, cms_type: 'jenkins' },
    ]));
    expect(engine.getNode('cred-default-tomcat')).toBeDefined();
    expect(engine.getNode('cred-default-jenkins')).toBeDefined();
    expect(engine.getNode('cred-default-tomcat')!.cred_user).toBe('tomcat');
    expect(engine.getNode('cred-default-jenkins')!.cred_user).toBe('admin');
    const tcEdges = engine.queryGraph({ from_node: 'cred-default-tomcat', edge_type: 'POTENTIAL_AUTH' });
    expect(tcEdges.edges.some(e => e.target === 'webapp-tc')).toBe(true);
    const jkEdges = engine.queryGraph({ from_node: 'cred-default-jenkins', edge_type: 'POTENTIAL_AUTH' });
    expect(jkEdges.edges.some(e => e.target === 'webapp-jk')).toBe(true);
  });

  it('handles case-insensitive CMS type matching', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'webapp-WP', type: 'webapp', label: 'http://10.10.10.5/WP',
      discovered_at: now, confidence: 1.0, cms_type: 'WordPress',
    }]));
    const cred = engine.getNode('cred-default-wordpress');
    expect(cred).toBeDefined();
    expect(cred!.cred_user).toBe('admin');
  });
});

// ============================================================
// degradeExpiredCredentialEdges
// ============================================================
describe('degradeExpiredCredentialEdges', () => {
  afterEach(cleanup);

  it('degrades edges from stale credentials (not just expired)', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.addNode({
      id: 'cred-stale', type: 'credential', label: 'stale-cred',
      confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
      cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
      credential_status: 'stale',
    });
    engine.addNode({
      id: 'svc-stale-tgt', type: 'service', label: 'smb',
      confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
      service_name: 'smb', port: 445,
    });
    engine.addEdge('cred-stale', 'svc-stale-tgt', {
      type: 'POTENTIAL_AUTH', confidence: 0.8,
      discovered_at: '2026-01-01T00:00:00Z',
    });

    const degraded = engine.degradeExpiredCredentialEdges('cred-stale');
    expect(degraded.length).toBe(1);
    const graph = engine.exportGraph();
    const edge = graph.edges.find(e => e.source === 'cred-stale' && e.properties.type === 'POTENTIAL_AUTH');
    expect(edge!.properties.confidence).toBe(0.4);
  });

  it('degrades edges from rotated credentials', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.addNode({
      id: 'cred-rot', type: 'credential', label: 'rotated-cred',
      confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
      cred_type: 'plaintext', cred_material_kind: 'plaintext_password',
      credential_status: 'rotated',
    });
    engine.addNode({
      id: 'svc-rot-tgt', type: 'service', label: 'http',
      confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
      service_name: 'http', port: 80,
    });
    engine.addEdge('cred-rot', 'svc-rot-tgt', {
      type: 'POTENTIAL_AUTH', confidence: 0.6,
      discovered_at: '2026-01-01T00:00:00Z',
    });

    const degraded = engine.degradeExpiredCredentialEdges('cred-rot');
    expect(degraded.length).toBe(1);
    const graph = engine.exportGraph();
    const edge = graph.edges.find(e => e.source === 'cred-rot' && e.properties.type === 'POTENTIAL_AUTH');
    expect(edge!.properties.confidence).toBe(0.3);
  });

  it('degrades all POTENTIAL_AUTH edges from the same credential', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.addNode({
      id: 'cred-multi', type: 'credential', label: 'multi-cred',
      confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
      cred_type: 'ntlm', cred_material_kind: 'ntlm_hash',
      credential_status: 'expired',
    });
    engine.addNode({
      id: 'svc-m1', type: 'service', label: 'smb-1',
      confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
      service_name: 'smb', port: 445,
    });
    engine.addNode({
      id: 'svc-m2', type: 'service', label: 'smb-2',
      confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
      service_name: 'smb', port: 445,
    });
    engine.addEdge('cred-multi', 'svc-m1', {
      type: 'POTENTIAL_AUTH', confidence: 0.8,
      discovered_at: '2026-01-01T00:00:00Z',
    });
    engine.addEdge('cred-multi', 'svc-m2', {
      type: 'POTENTIAL_AUTH', confidence: 0.6,
      discovered_at: '2026-01-01T00:00:00Z',
    });

    const degraded = engine.degradeExpiredCredentialEdges('cred-multi');
    expect(degraded.length).toBe(2);

    const graph = engine.exportGraph();
    const e1 = graph.edges.find(e => e.source === 'cred-multi' && e.target === 'svc-m1' && e.properties.type === 'POTENTIAL_AUTH');
    const e2 = graph.edges.find(e => e.source === 'cred-multi' && e.target === 'svc-m2' && e.properties.type === 'POTENTIAL_AUTH');
    expect(e1!.properties.confidence).toBe(0.4);
    expect(e2!.properties.confidence).toBe(0.3);
  });

  it('returns empty array for non-existent node', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const degraded = engine.degradeExpiredCredentialEdges('nonexistent');
    expect(degraded.length).toBe(0);
  });

  it('returns empty array for non-credential node types', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.addNode({
      id: 'host-not-cred', type: 'host', label: 'host',
      confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
      ip: '10.10.10.1', alive: true,
    });
    const degraded = engine.degradeExpiredCredentialEdges('host-not-cred');
    expect(degraded.length).toBe(0);
  });

  it('degrades credentials expired by valid_until timestamp', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.addNode({
      id: 'cred-ts-exp', type: 'credential', label: 'ts-exp',
      confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
      cred_type: 'token', cred_material_kind: 'token',
      valid_until: '2020-01-01T00:00:00Z',
    });
    engine.addNode({
      id: 'svc-ts-tgt', type: 'service', label: 'api',
      confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z',
      service_name: 'http', port: 443,
    });
    engine.addEdge('cred-ts-exp', 'svc-ts-tgt', {
      type: 'POTENTIAL_AUTH', confidence: 0.9,
      discovered_at: '2026-01-01T00:00:00Z',
    });

    const degraded = engine.degradeExpiredCredentialEdges('cred-ts-exp');
    expect(degraded.length).toBe(1);
    const graph = engine.exportGraph();
    const edge = graph.edges.find(e => e.source === 'cred-ts-exp' && e.properties.type === 'POTENTIAL_AUTH');
    expect(edge!.properties.confidence).toBe(0.45);
  });
});
