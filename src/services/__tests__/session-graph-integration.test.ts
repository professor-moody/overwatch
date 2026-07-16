import { describe, it, expect, afterEach } from 'vitest';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig } from '../../types.js';
import { existsSync, mkdtempSync, rmSync, unlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const engines = new Set<GraphEngine>();
const testDirs = new Set<string>();
const statePaths = new WeakMap<GraphEngine, string>();

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-session-graph',
    name: 'Session Graph Integration Test',
    created_at: '2026-04-01T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/28'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [{
      id: 'obj-1',
      description: 'Test objective',
      target_node_type: 'credential',
      target_criteria: { privileged: true },
      achieved: false,
    }],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  };
}

function cleanup() {
  for (const engine of engines) engine.dispose();
  engines.clear();
  for (const dir of testDirs) rmSync(dir, { recursive: true, force: true });
  testDirs.clear();
}

function createEngine(config: EngagementConfig = makeConfig()): GraphEngine {
  const dir = mkdtempSync(join(tmpdir(), 'overwatch-session-graph-'));
  testDirs.add(dir);
  const statePath = join(dir, 'state.json');
  const engine = new GraphEngine(config, statePath);
  engines.add(engine);
  statePaths.set(engine, statePath);
  return engine;
}

function statePathFor(engine: GraphEngine): string {
  return statePaths.get(engine)!;
}

function seedHostAndUser(engine: GraphEngine) {
  engine.ingestFinding({
    id: 'f-seed', agent_id: 'test', timestamp: new Date().toISOString(),
    nodes: [
      { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
      { id: 'user-root', type: 'user', label: 'root', discovered_at: new Date().toISOString(), confidence: 1.0 },
    ],
    edges: [],
  });
}

function seedHostAndCredential(engine: GraphEngine) {
  engine.ingestFinding({
    id: 'f-seed-cred', agent_id: 'test', timestamp: new Date().toISOString(),
    nodes: [
      { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
      { id: 'cred-ssh-key', type: 'credential', label: 'root-ssh-key', cred_type: 'ssh_key', discovered_at: new Date().toISOString(), confidence: 1.0 },
    ],
    edges: [],
  });
}

// ============================================================
// 1. ingestSessionResult success path
// ============================================================
describe('ingestSessionResult success path', () => {
  afterEach(cleanup);

  it('creates HAS_SESSION edge with correct attributes', () => {
    const engine = createEngine();
    seedHostAndUser(engine);

    engine.ingestSessionResult({
      success: true,
      confirmed: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      session_id: 'sess-success-1',
      agent_id: 'agent-1',
      action_id: 'act-1',
      frontier_item_id: 'fi-1',
    });

    const graph = engine.exportGraph();
    const sessionEdge = graph.edges.find(e => e.properties.type === 'HAS_SESSION');
    expect(sessionEdge).toBeDefined();
    expect(sessionEdge!.source).toBe('user-root');
    expect(sessionEdge!.target).toBe('host-10-10-10-1');
    expect(sessionEdge!.properties.confidence).toBe(1.0);
    expect(sessionEdge!.properties.tested).toBe(true);
    expect(sessionEdge!.properties.test_result).toBe('success');
    expect(sessionEdge!.properties.confirmed_at).toBeDefined();
    expect(sessionEdge!.properties.discovered_by).toBe('session-manager');
  });

  it('keeps the HAS_SESSION edge live when one of two concurrent sessions closes (ref-count)', () => {
    const engine = createEngine();
    seedHostAndUser(engine);
    const base = { success: true, confirmed: true, target_node: 'host-10-10-10-1', principal_node: 'user-root' };
    engine.ingestSessionResult({ ...base, session_id: 'sess-A' });
    engine.ingestSessionResult({ ...base, session_id: 'sess-B' });

    const liveEdge = () => engine.exportGraph().edges.find(e => e.properties.type === 'HAS_SESSION')!;
    expect(liveEdge().properties.session_live).toBe(true);

    // Close A — B is still live, so the shared (principal→target) edge stays live.
    engine.onSessionClosed('sess-A', 'host-10-10-10-1', 'user-root');
    expect(liveEdge().properties.session_live).toBe(true);
    expect((liveEdge().properties as { live_session_ids?: string[] }).live_session_ids).toEqual(['sess-B']);

    // Close B — now no live sessions remain, so the edge goes historical.
    engine.onSessionClosed('sess-B', 'host-10-10-10-1', 'user-root');
    expect(liveEdge().properties.session_live).toBe(false);
    expect(liveEdge().properties.session_closed_at).toBeDefined();
  });

  it('keeps scalar generation attribution aligned with the remaining live reference', () => {
    const engine = createEngine();
    seedHostAndUser(engine);
    const base = {
      success: true,
      confirmed: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
    };
    engine.ingestSessionResult({
      ...base,
      session_id: 'listener-a:g3',
      listener_id: 'listener-a',
      connection_generation: 3,
    });
    engine.ingestSessionResult({
      ...base,
      session_id: 'listener-b:g8',
      listener_id: 'listener-b',
      connection_generation: 8,
    });

    const liveEdge = () => engine.exportGraph().edges.find(
      edge => edge.properties.type === 'HAS_SESSION',
    )!;
    expect(liveEdge().properties.live_session_refs).toEqual([
      {
        session_id: 'listener-a:g3',
        listener_id: 'listener-a',
        connection_generation: 3,
      },
      {
        session_id: 'listener-b:g8',
        listener_id: 'listener-b',
        connection_generation: 8,
      },
    ]);

    engine.onSessionClosed(
      'listener-b:g8',
      'host-10-10-10-1',
      'user-root',
    );
    expect(liveEdge().properties).toMatchObject({
      session_live: true,
      session_id: 'listener-a:g3',
      listener_id: 'listener-a',
      connection_generation: 3,
      live_session_ids: ['listener-a:g3'],
      live_session_refs: [{
        session_id: 'listener-a:g3',
        listener_id: 'listener-a',
        connection_generation: 3,
      }],
    });
  });

  it('logs session_access_confirmed with correct top-level action_id and frontier_item_id', () => {
    const engine = createEngine();
    seedHostAndUser(engine);

    engine.ingestSessionResult({
      success: true,
      confirmed: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      session_id: 'sess-success-2',
      agent_id: 'agent-1',
      action_id: 'act-42',
      frontier_item_id: 'fi-42',
    });

    const history = engine.getFullHistory();
    const event = history.find(e => e.event_type === 'session_access_confirmed');
    expect(event).toBeDefined();
    expect(event!.action_id).toBe('act-42');
    expect(event!.frontier_item_id).toBe('fi-42');
    expect(event!.agent_id).toBe('agent-1');
    expect(event!.description).toContain('host-10-10-10-1');
    expect(event!.description).toContain('succeeded');
  });

  it('does NOT create HAS_SESSION edge when confirmed=false', () => {
    const engine = createEngine();
    seedHostAndUser(engine);

    engine.ingestSessionResult({
      success: true,
      confirmed: false,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      session_id: 'sess-unconfirmed',
    });

    const graph = engine.exportGraph();
    const sessionEdge = graph.edges.find(e => e.properties.type === 'HAS_SESSION');
    expect(sessionEdge).toBeUndefined();

    // Should still log event as unconfirmed
    const events = engine.getFullHistory();
    const unconfirmedEvent = events.find(e =>
      e.event_type === 'session_access_unconfirmed'
    );
    expect(unconfirmedEvent).toBeDefined();
  });

  it('creates HAS_SESSION edge when principal_node is a credential', () => {
    const engine = createEngine();
    seedHostAndCredential(engine);

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'cred-ssh-key',
      session_id: 'sess-cred',
    });

    const graph = engine.exportGraph();
    const sessionEdge = graph.edges.find(e => e.properties.type === 'HAS_SESSION');
    expect(sessionEdge).toBeDefined();
    expect(sessionEdge!.source).toBe('cred-ssh-key');
    expect(sessionEdge!.target).toBe('host-10-10-10-1');
  });
});

// ============================================================
// 2. ingestSessionResult failure path
// ============================================================
describe('ingestSessionResult failure path', () => {
  afterEach(cleanup);

  it('logs session_error NOT session_access_confirmed', () => {
    const engine = createEngine();
    seedHostAndUser(engine);

    engine.ingestSessionResult({
      success: false,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      session_id: 'sess-fail-1',
      agent_id: 'agent-fail',
      action_id: 'act-fail',
      frontier_item_id: 'fi-fail',
    });

    const history = engine.getFullHistory();
    const errorEvent = history.find(e => e.event_type === 'session_error');
    expect(errorEvent).toBeDefined();
    expect(errorEvent!.description).toContain('failed');

    const confirmedEvent = history.find(e => e.event_type === 'session_access_confirmed');
    expect(confirmedEvent).toBeUndefined();
  });

  it('includes action_id and frontier_item_id at top level on failure', () => {
    const engine = createEngine();
    seedHostAndUser(engine);

    engine.ingestSessionResult({
      success: false,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      session_id: 'sess-fail-2',
      agent_id: 'agent-fail',
      action_id: 'act-fail-2',
      frontier_item_id: 'fi-fail-2',
    });

    const history = engine.getFullHistory();
    const errorEvent = history.find(e => e.event_type === 'session_error');
    expect(errorEvent).toBeDefined();
    expect(errorEvent!.action_id).toBe('act-fail-2');
    expect(errorEvent!.frontier_item_id).toBe('fi-fail-2');
    expect(errorEvent!.agent_id).toBe('agent-fail');
  });

  it('marks frontier edge as tested with failure', () => {
    const engine = createEngine();
    engine.ingestFinding({
      id: 'f-edge-setup', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
        { id: 'user-root', type: 'user', label: 'root', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [{
        source: 'user-root', target: 'host-10-10-10-1',
        properties: { type: 'POTENTIAL_AUTH', confidence: 0.5, discovered_at: new Date().toISOString(), discovered_by: 'inference' },
      }],
    });

    const graph = engine.exportGraph();
    const potentialEdge = graph.edges.find(e => e.properties.type === 'POTENTIAL_AUTH');
    expect(potentialEdge).toBeDefined();

    engine.ingestSessionResult({
      success: false,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      action_id: 'act-edge-fail',
      frontier_item_id: `frontier-edge-${potentialEdge!.id}`,
    });

    const updated = engine.exportGraph();
    const updatedEdge = updated.edges.find(e => e.id === potentialEdge!.id);
    expect(updatedEdge).toBeDefined();
    expect(updatedEdge!.properties.tested).toBe(true);
    expect(updatedEdge!.properties.test_result).toBe('failure');
  });

  it('does NOT create HAS_SESSION edge on failure', () => {
    const engine = createEngine();
    seedHostAndUser(engine);

    engine.ingestSessionResult({
      success: false,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      session_id: 'sess-fail-no-edge',
    });

    const graph = engine.exportGraph();
    const sessionEdge = graph.edges.find(e => e.properties.type === 'HAS_SESSION');
    expect(sessionEdge).toBeUndefined();
  });
});

// ============================================================
// 3. Non-eligible principal type (e.g. host)
// ============================================================
describe('ingestSessionResult with non-eligible principal type', () => {
  afterEach(cleanup);

  it('does NOT create HAS_SESSION edge when principal is a host', () => {
    const engine = createEngine();
    engine.ingestFinding({
      id: 'f-two-hosts', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
        { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      confirmed: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'host-10-10-10-2',
      session_id: 'sess-host-principal',
      agent_id: 'agent-host',
      action_id: 'act-host',
      frontier_item_id: 'fi-host',
    });

    const graph = engine.exportGraph();
    const sessionEdge = graph.edges.find(e => e.properties.type === 'HAS_SESSION');
    expect(sessionEdge).toBeUndefined();
  });

  it('still logs session_access_confirmed even without HAS_SESSION edge', () => {
    const engine = createEngine();
    engine.ingestFinding({
      id: 'f-host-only', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
        { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      confirmed: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'host-10-10-10-2',
      session_id: 'sess-host-log',
      agent_id: 'agent-host',
    });

    const history = engine.getFullHistory();
    const event = history.find(e => e.event_type === 'session_access_confirmed');
    expect(event).toBeDefined();
    expect(event!.description).toContain('succeeded');
  });

  it('still calls persist after ingest with non-eligible principal', () => {
    const engine = createEngine();
    engine.ingestFinding({
      id: 'f-host-persist', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
        { id: 'host-10-10-10-3', type: 'host', label: '10.10.10.3', ip: '10.10.10.3', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'host-10-10-10-3',
      session_id: 'sess-host-persist',
    });

    expect(existsSync(statePathFor(engine))).toBe(true);
  });

  it('does NOT create HAS_SESSION when principal is a service', () => {
    const engine = createEngine();
    engine.ingestFinding({
      id: 'f-svc-principal', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
        { id: 'svc-ssh', type: 'service', label: 'ssh', service_name: 'ssh', port: 22, protocol: 'tcp', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'svc-ssh',
      session_id: 'sess-svc-principal',
    });

    const graph = engine.exportGraph();
    const sessionEdge = graph.edges.find(e => e.properties.type === 'HAS_SESSION');
    expect(sessionEdge).toBeUndefined();
  });
});

// ============================================================
// 4. ingestSessionResult success calls persist()
// ============================================================
describe('ingestSessionResult calls persist', () => {
  afterEach(cleanup);

  it('state file exists after successful ingestSessionResult', () => {
    const engine = createEngine();
    seedHostAndUser(engine);

    // Delete state file to prove persist is called by ingestSessionResult
    if (existsSync(statePathFor(engine))) unlinkSync(statePathFor(engine));

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      session_id: 'sess-persist-check',
    });
    engine.flushNow();

    expect(existsSync(statePathFor(engine))).toBe(true);
  });

  it('state file exists after failed ingestSessionResult', () => {
    const engine = createEngine();
    seedHostAndUser(engine);

    if (existsSync(statePathFor(engine))) unlinkSync(statePathFor(engine));

    engine.ingestSessionResult({
      success: false,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      session_id: 'sess-persist-fail',
    });
    engine.flushNow();

    expect(existsSync(statePathFor(engine))).toBe(true);
  });
});

// ============================================================
// 5. has_session_edge_created telemetry accuracy
// ============================================================
describe('has_session_edge_created telemetry', () => {
  afterEach(cleanup);

  it('is true when edge was actually created (user principal)', () => {
    const engine = createEngine();
    seedHostAndUser(engine);

    engine.ingestSessionResult({
      success: true,
      confirmed: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      session_id: 'sess-telemetry-1',
    });

    const history = engine.getFullHistory();
    const event = history.find(e => e.event_type === 'session_access_confirmed');
    expect(event).toBeDefined();
    expect(event!.details).toBeDefined();
    expect((event!.details as Record<string, unknown>).has_session_edge_created).toBe(true);
  });

  it('is false when principal_node is absent (no edge created)', () => {
    const engine = createEngine();
    engine.ingestFinding({
      id: 'f-host-only', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 }],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      session_id: 'sess-telemetry-2',
    });

    const history = engine.getFullHistory();
    const event = history.find(e => e.event_type === 'session_access_confirmed');
    expect(event).toBeDefined();
    expect((event!.details as Record<string, unknown>).has_session_edge_created).toBe(false);
  });

  it('is false when principal_node is a host (non-eligible type)', () => {
    const engine = createEngine();
    engine.ingestFinding({
      id: 'f-two-hosts-t', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
        { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      confirmed: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'host-10-10-10-2',
      session_id: 'sess-telemetry-3',
    });

    const history = engine.getFullHistory();
    const event = history.find(e => e.event_type === 'session_access_confirmed');
    expect(event).toBeDefined();
    expect((event!.details as Record<string, unknown>).has_session_edge_created).toBe(false);
  });

  it('is false when principal_node does not exist in graph', () => {
    const engine = createEngine();
    engine.ingestFinding({
      id: 'f-solo-host', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 }],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-ghost',
      session_id: 'sess-telemetry-4',
    });

    const history = engine.getFullHistory();
    const event = history.find(e => e.event_type === 'session_access_confirmed');
    expect(event).toBeDefined();
    expect((event!.details as Record<string, unknown>).has_session_edge_created).toBe(false);
  });

  it('is true only for credential principal (valid source type)', () => {
    const engine = createEngine();
    seedHostAndCredential(engine);

    engine.ingestSessionResult({
      success: true,
      confirmed: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'cred-ssh-key',
      session_id: 'sess-telemetry-5',
    });

    const history = engine.getFullHistory();
    const event = history.find(e => e.event_type === 'session_access_confirmed');
    expect(event).toBeDefined();
    expect((event!.details as Record<string, unknown>).has_session_edge_created).toBe(true);
  });

  it('not present in session_error events (failure path)', () => {
    const engine = createEngine();
    seedHostAndUser(engine);

    engine.ingestSessionResult({
      success: false,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      session_id: 'sess-telemetry-fail',
    });

    const history = engine.getFullHistory();
    const errorEvent = history.find(e => e.event_type === 'session_error');
    expect(errorEvent).toBeDefined();
    // Failure path details should not contain has_session_edge_created
    const details = errorEvent!.details as Record<string, unknown> | undefined;
    expect(details?.has_session_edge_created).toBeUndefined();
  });
});
