import { describe, it, expect, afterEach } from 'vitest';
import { GraphEngine } from '../graph-engine.js';
import { FrontierComputer } from '../frontier.js';
import { DashboardServer } from '../dashboard-server.js';
import type { EngagementConfig, Finding } from '../../types.js';
import { unlinkSync, existsSync } from 'fs';

const TEST_STATE_FILE = './state-test-hardening.json';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-hardening',
    name: 'Hardening Test',
    created_at: '2026-03-29T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [{
      id: 'obj-1',
      description: 'Get DA',
      target_node_type: 'user',
      target_criteria: { privileged: true },
      achieved: false,
    }],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  } as EngagementConfig;
}

function cleanup() {
  if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
}

const now = new Date().toISOString();

function makeFinding(nodes: Finding['nodes'], edges: Finding['edges'] = []): Finding {
  return {
    id: `f-${Date.now()}`,
    agent_id: 'test-agent',
    timestamp: now,
    nodes,
    edges,
  };
}

// ============================================================
// H.3: Dashboard localhost bind
// ============================================================
describe('H.3 — Dashboard localhost bind', () => {
  afterEach(cleanup);

  it('default bound host is 127.0.0.1', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const dashboard = new DashboardServer(engine, 0);
    expect(dashboard.boundHost).toBe('127.0.0.1');
    expect(dashboard.address).toContain('127.0.0.1');
  });

  it('accepts custom host parameter', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const dashboard = new DashboardServer(engine, 0, '0.0.0.0');
    expect(dashboard.boundHost).toBe('0.0.0.0');
  });
});

// ============================================================
// H.4: Default-guess credentials excluded from login spray
// ============================================================
describe('H.4 — Default-guess credential exclusion', () => {
  afterEach(cleanup);

  it('inferDefaultCredentials marks credential with cred_is_default_guess', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'webapp-wp', type: 'webapp' as const, label: 'http://10.10.10.5/wp',
      discovered_at: now, confidence: 1.0, cms_type: 'wordpress',
    }]));
    const cred = engine.getNode('cred-default-wordpress');
    expect(cred).toBeDefined();
    expect(cred!.cred_is_default_guess).toBe(true);
  });

  it('web_form_credentials selector excludes default-guess credentials', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // Ingest a real plaintext credential + a webapp with login form + a default-cred webapp
    engine.ingestFinding(makeFinding([
      { id: 'cred-real', type: 'credential' as const, label: 'admin:password', discovered_at: now, confidence: 1.0, cred_type: 'plaintext', cred_material_kind: 'plaintext_password', cred_usable_for_auth: true, credential_status: 'active' },
      { id: 'webapp-wp', type: 'webapp' as const, label: 'http://10.10.10.5/wp', discovered_at: now, confidence: 1.0, cms_type: 'wordpress' },
      { id: 'webapp-login', type: 'webapp' as const, label: 'http://10.10.10.6/login', discovered_at: now, confidence: 1.0, has_login_form: true },
    ]));

    // Verify default-guess credential was created
    const defaultCred = engine.getNode('cred-default-wordpress');
    expect(defaultCred).toBeTruthy();
    expect(defaultCred!.cred_is_default_guess).toBe(true);

    // Query all POTENTIAL_AUTH edges and check which ones target webapp-login
    const allEdges = engine.queryGraph({ edge_type: 'POTENTIAL_AUTH' });
    const toLogin = allEdges.edges.filter(e => e.target === 'webapp-login');
    const sourcesToLogin = toLogin.map(e => e.source);

    // Real credential should have POTENTIAL_AUTH to webapp-login (from login-spray rule)
    expect(sourcesToLogin).toContain('cred-real');
    // Default-guess credential should NOT — inferDefaultCredentials targets only webapp-wp
    expect(sourcesToLogin).not.toContain('cred-default-wordpress');
  });
});

// ============================================================
// H.5: Superseded identity filtering
// ============================================================
describe('H.5 — Superseded identity filtering', () => {
  afterEach(cleanup);

  it('superseded nodes excluded from frontier', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // hostId('10.10.10.99') → 'host-10-10-10-99' (dots replaced with dashes)
    engine.ingestFinding(makeFinding([{
      id: 'host-10-10-10-99', type: 'host' as const, label: '10.10.10.99',
      discovered_at: now, confidence: 1.0, ip: '10.10.10.99',
    }]));
    const node = engine.getNode('host-10-10-10-99');
    expect(node).toBeTruthy();
    (engine as any).ctx.graph.mergeNodeAttributes('host-10-10-10-99', { identity_status: 'superseded' });

    const state = engine.getState();
    const frontierNodeIds = state.frontier.map(f => f.node_id).filter(Boolean);
    expect(frontierNodeIds).not.toContain('host-10-10-10-99');
  });

  it('edges with superseded endpoints excluded from edge queries', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // Ingest user, host, and a HAS_SESSION edge together (ingestFinding handles ID remapping)
    engine.ingestFinding(makeFinding(
      [
        { id: 'user-old@test.local', type: 'user' as const, label: 'old-user', discovered_at: now, confidence: 1.0 },
        { id: 'host-10.10.10.1', type: 'host' as const, label: '10.10.10.1', discovered_at: now, confidence: 1.0, ip: '10.10.10.1' },
      ],
      [{ source: 'user-old@test.local', target: 'host-10.10.10.1', properties: { type: 'HAS_SESSION' as const, confidence: 1.0 } }],
    ));
    // Verify edge exists before superseding
    const before = engine.queryGraph({ edge_type: 'HAS_SESSION' });
    expect(before.edges.length).toBe(1);

    // Find the resolved user ID and mark as superseded
    const userSource = before.edges[0].source;
    (engine as any).ctx.graph.mergeNodeAttributes(userSource, { identity_status: 'superseded' });

    const result = engine.queryGraph({ edge_type: 'HAS_SESSION' });
    expect(result.edges.length).toBe(0);
  });

  it('superseded nodes excluded from agent subgraph', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10.10.10.2', type: 'host' as const, label: '10.10.10.2', discovered_at: now, confidence: 1.0, ip: '10.10.10.2' },
        { id: 'user-stale@test.local', type: 'user' as const, label: 'stale-user', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-stale@test.local', target: 'host-10.10.10.2', properties: { type: 'HAS_SESSION' as const, confidence: 1.0 } }],
    ));
    // Find the resolved host and user IDs
    const edges = engine.queryGraph({ edge_type: 'HAS_SESSION' });
    expect(edges.edges.length).toBe(1);
    const hostId = edges.edges[0].target;
    const userId = edges.edges[0].source;

    (engine as any).ctx.graph.mergeNodeAttributes(userId, { identity_status: 'superseded' });

    const subgraph = engine.getSubgraphForAgent([hostId], { hops: 2 });
    const nodeIds = subgraph.nodes.map((n: { id: string }) => n.id);
    expect(nodeIds).toContain(hostId);
    expect(nodeIds).not.toContain(userId);
    // Edges to superseded nodes should also be excluded
    expect(subgraph.edges.length).toBe(0);
  });
});

// ============================================================
// H.6: SSH session confirmation
// ============================================================
describe('H.6 — SSH session confirmation', () => {
  afterEach(cleanup);

  it('unconfirmed session gets reduced confidence HAS_SESSION edge', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // Seed nodes
    engine.ingestFinding(makeFinding([
      { id: 'user-test', type: 'user' as const, label: 'testuser', discovered_at: now, confidence: 1.0 },
      { id: 'host-target', type: 'host' as const, label: '10.10.10.5', discovered_at: now, confidence: 1.0 },
    ]));

    // Simulate unconfirmed session
    engine.ingestSessionResult({
      success: true,
      confirmed: false,
      target_node: 'host-target',
      principal_node: 'user-test',
      session_id: 'sess-1',
    });

    const result = engine.queryGraph({ edge_type: 'HAS_SESSION' });
    expect(result.edges.length).toBe(1);
    expect(result.edges[0].properties.confidence).toBe(0.5);
    expect(result.edges[0].properties.session_unconfirmed).toBe(true);
  });

  it('confirmed session gets full confidence HAS_SESSION edge', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([
      { id: 'user-test', type: 'user' as const, label: 'testuser', discovered_at: now, confidence: 1.0 },
      { id: 'host-target', type: 'host' as const, label: '10.10.10.5', discovered_at: now, confidence: 1.0 },
    ]));

    engine.ingestSessionResult({
      success: true,
      confirmed: true,
      target_node: 'host-target',
      principal_node: 'user-test',
      session_id: 'sess-2',
    });

    const result = engine.queryGraph({ edge_type: 'HAS_SESSION' });
    expect(result.edges.length).toBe(1);
    expect(result.edges[0].properties.confidence).toBe(1.0);
    expect(result.edges[0].properties.session_unconfirmed).toBeUndefined();
  });

  it('confirmed session upgrades previously unconfirmed edge', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([
      { id: 'user-test', type: 'user' as const, label: 'testuser', discovered_at: now, confidence: 1.0 },
      { id: 'host-target', type: 'host' as const, label: '10.10.10.5', discovered_at: now, confidence: 1.0 },
    ]));

    // First: unconfirmed
    engine.ingestSessionResult({
      success: true,
      confirmed: false,
      target_node: 'host-target',
      principal_node: 'user-test',
      session_id: 'sess-3a',
    });

    // Second: confirmed
    engine.ingestSessionResult({
      success: true,
      confirmed: true,
      target_node: 'host-target',
      principal_node: 'user-test',
      session_id: 'sess-3b',
    });

    const result = engine.queryGraph({ edge_type: 'HAS_SESSION' });
    expect(result.edges.length).toBe(1);
    expect(result.edges[0].properties.confidence).toBe(1.0);
  });

  it('logs session_access_unconfirmed event for unconfirmed sessions', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([
      { id: 'user-test', type: 'user' as const, label: 'testuser', discovered_at: now, confidence: 1.0 },
      { id: 'host-target', type: 'host' as const, label: '10.10.10.5', discovered_at: now, confidence: 1.0 },
    ]));

    engine.ingestSessionResult({
      success: true,
      confirmed: false,
      target_node: 'host-target',
      principal_node: 'user-test',
      session_id: 'sess-4',
    });

    const history = engine.getFullHistory();
    const unconfirmedEvents = history.filter(e => e.event_type === 'session_access_unconfirmed');
    expect(unconfirmedEvents.length).toBeGreaterThanOrEqual(1);
    expect(unconfirmedEvents[0].description).toContain('unconfirmed');
  });
});
