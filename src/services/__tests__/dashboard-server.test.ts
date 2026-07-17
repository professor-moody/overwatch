import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { WebSocket } from 'ws';
import { execFileSync } from 'child_process';
import { PassThrough } from 'stream';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { basename, join } from 'path';
import { DashboardServer } from '../dashboard-server.js';
import { DashboardMainWebSocketHub } from '../dashboard-main-ws-hub.js';
import { GraphEngine } from '../graph-engine.js';
import { InProcessTapeController } from '../in-process-tape.js';
import type { EngagementConfig } from '../../types.js';
import { AgentDtoSchema, type SessionDto } from '../../contracts/dashboard-v1.js';

let testStateDir: string;
let TEST_STATE_FILE: string;

function makeConfig(overrides?: Partial<EngagementConfig>): EngagementConfig {
  return {
    id: 'test-dashboard',
    name: 'Dashboard Test Engagement',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/30'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [{
      id: 'obj-da',
      description: 'Get domain admin',
      target_node_type: 'credential' as const,
      target_criteria: { privileged: true, cred_domain: 'test.local' },
      achieved: false,
    }],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  };
}

const engines = new Set<GraphEngine>();

function trackedEngine(...args: ConstructorParameters<typeof GraphEngine>): GraphEngine {
  const engine = new GraphEngine(...args);
  engines.add(engine);
  return engine;
}

function cleanup() {
  if (testStateDir) rmSync(testStateDir, { recursive: true, force: true });
}

function sentMessages(mockClient: { send: ReturnType<typeof vi.fn> }): any[] {
  return mockClient.send.mock.calls.map(call => JSON.parse(call[0]));
}

function sentGraphUpdates(mockClient: { send: ReturnType<typeof vi.fn> }): any[] {
  return sentMessages(mockClient).filter(message => message.type === 'graph_update');
}

describe('DashboardServer', () => {
  let engine: GraphEngine;
  let dashboard: DashboardServer;

  beforeEach(() => {
    testStateDir = mkdtempSync(join(tmpdir(), 'overwatch-dashboard-test-'));
    TEST_STATE_FILE = join(testStateDir, 'state-test-dashboard.json');
    engine = trackedEngine(makeConfig(), TEST_STATE_FILE);
    dashboard = new DashboardServer(engine, 8384);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await dashboard.stop().catch(() => {});
    for (const liveEngine of engines) liveEngine.dispose();
    engines.clear();
    cleanup();
  });

  it('reports address property', () => {
    expect(dashboard.address).toBe('http://127.0.0.1:8384');
  });

  it('keeps degraded recovery state inspectable through GET /api/state', () => {
    const recovery = {
      outcome: 'incomplete' as const,
      source: 'snapshot' as const,
      complete: false,
      writable: false,
      reason: 'journal replay stopped at an unknown record',
      base_checkpoint: 4,
      highest_allocated_seq: 9,
      highest_on_disk_seq: 9,
      highest_contiguous_applied_seq: 6,
      consecutive_persistence_failures: 0,
      journal: {
        enabled: true,
        read: 5,
        attempted: 3,
        applied: 2,
        skipped: 1,
        failed: 0,
        malformed: false,
        preserved: true,
      },
    };
    vi.spyOn(engine, 'isPersistenceWritable').mockReturnValue(false);
    vi.spyOn(engine, 'getPersistenceRecoveryStatus').mockReturnValue(recovery);
    const req = { url: '/api/state', method: 'GET', headers: {} } as any;
    const res = {
      statusCode: 0,
      body: '',
      setHeader() {},
      writeHead(statusCode: number) { this.statusCode = statusCode; },
      end(body?: string) { this.body = body || ''; },
    };

    (dashboard as any).handleHttpRoute(req, res);

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).state.persistence_recovery).toEqual(recovery);
  });

  it('keeps scope preview available as a pure-read POST while degraded', async () => {
    vi.spyOn(engine, 'isPersistenceWritable').mockReturnValue(false);
    const preview = vi.spyOn(engine, 'previewScopeChange');
    const req = new PassThrough() as any;
    req.url = '/api/config/scope/preview';
    req.method = 'POST';
    req.headers = { 'content-type': 'application/json' };
    const res = {
      statusCode: 0,
      body: '',
      setHeader() {},
      writeHead(statusCode: number) { this.statusCode = statusCode; },
      end(body?: string) { this.body = body || ''; },
    };

    (dashboard as any).handleHttpRoute(req, res);
    req.end(JSON.stringify({
      cidrs: ['10.10.10.0/30', '10.20.0.0/16'],
      domains: ['test.local'],
      exclusions: [],
    }));
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(res.statusCode).toBe(200);
    expect(preview).toHaveBeenCalledWith(expect.objectContaining({
      add_cidrs: ['10.20.0.0/16'],
    }));
    expect(JSON.parse(res.body).added.cidrs).toEqual(['10.20.0.0/16']);
  });

  it('attributes dashboard tape toggles to dashboard', async () => {
    const tapeDir = mkdtempSync(join(tmpdir(), 'overwatch-dashboard-tape-'));
    const tape = new InProcessTapeController(engine, { defaultDir: tapeDir });
    dashboard.attachTape(tape);

    const req = new PassThrough() as any;
    req.headers = {};
    req.url = '/api/tape/toggle';
    req.method = 'POST';
    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) {
        this.body = body || '';
      },
      setHeader() {},
    };

    const pending = (dashboard as any).handleTapeToggle(req, res);
    req.end(JSON.stringify({ action: 'enable' }));
    await pending;

    expect(res.statusCode).toBe(200);
    const payload = JSON.parse(res.body);
    expect(payload.enabled).toBe(true);
    expect(payload.started_by).toBe('dashboard');
    expect(engine.getFullHistory().slice(-1)[0].details?.started_by).toBe('dashboard');

    await tape.disable();
    rmSync(tapeDir, { recursive: true, force: true });
  });

  it('streams dashboard bundle with manifest and journal entries', async () => {
    engine.addNode({
      id: 'host-bundle',
      type: 'host',
      label: 'bundle host',
      discovered_at: new Date().toISOString(),
      confidence: 1.0,
    });
    engine.persist();
    engine.flushNow();
    const journalName = TEST_STATE_FILE.replace(/\.json$/, '.journal.jsonl');
    engine.addNode({
      id: 'journal-only',
      type: 'host',
      label: 'journal-only',
      discovered_at: new Date().toISOString(),
      confidence: 1,
    });

    const chunks: Buffer[] = [];
    const res = new PassThrough() as any;
    res.headersSent = false;
    res.writeHead = (statusCode: number, headers?: Record<string, string>) => {
      res.statusCode = statusCode;
      res.headers = headers;
      res.headersSent = true;
    };
    res.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));

    await (dashboard as any).streamBundle({}, res);

    const tempDir = mkdtempSync(join(tmpdir(), 'overwatch-bundle-test-'));
    try {
      const archivePath = join(tempDir, 'bundle.tar.gz');
      writeFileSync(archivePath, Buffer.concat(chunks));
      const listing = execFileSync('tar', ['tzf', archivePath], { encoding: 'utf-8' }).split('\n').filter(Boolean);
      expect(res.statusCode).toBe(200);
      expect(listing).toContain(basename(TEST_STATE_FILE));
      expect(listing).toContain(basename(journalName));
      expect(listing).toContain('bundle-manifest.json');
      const manifest = JSON.parse(execFileSync(
        'tar',
        ['xOzf', archivePath, 'bundle-manifest.json'],
        { encoding: 'utf-8' },
      )) as Record<string, unknown>;
      expect(manifest).toMatchObject({
        state_version: 1,
        journal_version: 2,
      });
      expect(existsSync(join(testStateDir, 'bundle-manifest.json'))).toBe(false);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  }, 60_000);

  it('onGraphUpdate skips getState/exportGraph with zero clients', () => {
    const getStateSpy = vi.spyOn(engine, 'getState');
    const exportGraphSpy = vi.spyOn(engine, 'exportGraph');

    dashboard.onGraphUpdate({ new_nodes: ['test-node'] });
    dashboard.flush();

    expect(getStateSpy).not.toHaveBeenCalled();
    expect(exportGraphSpy).not.toHaveBeenCalled();
  });

  it('connected graph deltas resolve changed IDs without a full graph export', () => {
    const mockClient = {
      readyState: WebSocket.OPEN,
      send: vi.fn(),
      close: vi.fn(),
    };
    (dashboard as any).clients = new Set([mockClient]);
    const exportGraphSpy = vi.spyOn(engine, 'exportGraph');
    const selectionSpy = vi.spyOn(engine, 'exportGraphSelection');

    dashboard.onGraphUpdate({ updated_nodes: ['missing-final-node'] });
    dashboard.flush();

    expect(exportGraphSpy).not.toHaveBeenCalled();
    expect(selectionSpy).toHaveBeenCalledWith(expect.objectContaining({
      node_ids: ['missing-final-node'],
    }));
    const update = sentGraphUpdates(mockClient)[0];
    expect(update.data.delta.removed_nodes).toContain('missing-final-node');
  });

  it('sends changed-ID deltas before coalescing an expensive state refresh', () => {
    vi.useFakeTimers();
    try {
      const mockClient = {
        readyState: WebSocket.OPEN,
        send: vi.fn(),
        close: vi.fn(),
        on: vi.fn(),
      };
      (dashboard as any).mainHub.attachConnection(mockClient);
      mockClient.send.mockClear();
      const stateSpy = vi.spyOn(engine, 'getState');

      dashboard.onGraphUpdate({ updated_nodes: ['missing-fast-node'] });
      dashboard.flush();

      expect(stateSpy).not.toHaveBeenCalled();
      expect(JSON.parse(String(mockClient.send.mock.calls[0][0])).type).toBe('graph_update');

      vi.advanceTimersByTime(750);
      expect(stateSpy).toHaveBeenCalledTimes(1);
      expect(mockClient.send.mock.calls.map(call => JSON.parse(String(call[0])).type)).toContain('state_refresh');
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not postpone authoritative state refresh under sustained graph updates', () => {
    vi.useFakeTimers();
    try {
      const mockClient = {
        readyState: WebSocket.OPEN,
        send: vi.fn(),
        close: vi.fn(),
        on: vi.fn(),
      };
      (dashboard as any).mainHub.attachConnection(mockClient);
      mockClient.send.mockClear();

      dashboard.onGraphUpdate({ updated_nodes: ['sustained-1'] });
      dashboard.flush();
      vi.advanceTimersByTime(600);
      dashboard.onGraphUpdate({ updated_nodes: ['sustained-2'] });
      dashboard.flush();
      vi.advanceTimersByTime(149);
      expect(mockClient.send.mock.calls
        .map(call => JSON.parse(String(call[0])).type))
        .not.toContain('state_refresh');

      vi.advanceTimersByTime(1);
      expect(mockClient.send.mock.calls
        .map(call => JSON.parse(String(call[0])).type))
        .toContain('state_refresh');
    } finally {
      vi.useRealTimers();
    }
  });

  it('publishes ten changed communities without scanning a 50k assignment cache', () => {
    vi.useFakeTimers();
    const baselineState = (dashboard as any).buildFrontendState();
    const baselineGraph = engine.exportGraph({ includeDerivedCommunities: true });
    const hub = new DashboardMainWebSocketHub(engine, null, {
      buildState: () => baselineState,
      buildGraph: () => baselineGraph,
      runtimeBuild: {
        schema_version: 1,
        input_sha256: 'a'.repeat(64),
        runtime_pid: process.pid,
        runtime_started_at: '2026-07-17T00:00:00.000Z',
      },
      debounceMs: 0,
    });
    try {
      const mockClient = {
        readyState: WebSocket.OPEN,
        send: vi.fn(),
        close: vi.fn(),
        on: vi.fn(),
      };
      hub.attachConnection(mockClient as any);
      mockClient.send.mockClear();

      const allAssignments = new Map(
        Array.from({ length: 50_000 }, (_, index) => [`node-${index}`, index % 50] as const),
      );
      const scan = vi.spyOn(allAssignments, Symbol.iterator).mockImplementation(() => {
        throw new Error('full community cache scan attempted');
      });
      const changedAssignments = new Map(
        Array.from({ length: 10 }, (_, index) => [`node-${index * 2}`, index + 100] as const),
      );
      (engine as any).ctx.communityCache = allAssignments;
      (engine as any).communityAssignments = allAssignments;
      (engine as any).pendingCommunityChanges = changedAssignments;

      hub.onGraphUpdate({ updated_nodes: [baselineGraph.nodes[0].id] });
      hub.flush();
      const failedBroadcast = vi.spyOn(hub, 'broadcast').mockImplementationOnce(() => {
        throw new Error('synthetic socket failure');
      });
      expect(() => vi.advanceTimersByTime(750)).toThrow('synthetic socket failure');
      expect((engine as any).pendingCommunityChanges.size).toBe(10);
      failedBroadcast.mockRestore();

      hub.onGraphUpdate({ updated_nodes: [baselineGraph.nodes[0].id] });
      hub.flush();
      vi.advanceTimersByTime(750);

      const refresh = sentMessages(mockClient)
        .find(message => message.type === 'state_refresh');
      expect(scan).not.toHaveBeenCalled();
      expect(Object.keys(refresh.data.community_ids)).toHaveLength(10);
      expect(refresh.data.community_ids['node-18']).toBe(109);
      expect((engine as any).pendingCommunityChanges.size).toBe(0);
    } finally {
      hub.dispose();
      vi.useRealTimers();
    }
  });

  it('does not expand every incident edge for an ordinary high-degree node update', () => {
    const graph = (engine as any).ctx.graph;
    graph.addNode('delta-hub', {
      id: 'delta-hub', type: 'host', label: 'Delta hub',
      discovered_at: '2026-07-16T00:00:00.000Z', confidence: 1,
    });
    for (let index = 0; index < 2_000; index++) {
      const nodeId = `delta-spoke-${index}`;
      graph.addNode(nodeId, {
        id: nodeId, type: 'host', label: nodeId,
        discovered_at: '2026-07-16T00:00:00.000Z', confidence: 1,
      });
      graph.addEdgeWithKey(`delta-edge-${index}`, 'delta-hub', nodeId, {
        type: 'REACHABLE', confidence: 1, discovered_at: '2026-07-16T00:00:00.000Z',
      });
    }
    const mockClient = { readyState: WebSocket.OPEN, send: vi.fn(), close: vi.fn() };
    (dashboard as any).clients = new Set([mockClient]);

    dashboard.onGraphUpdate({ updated_nodes: ['delta-hub'] });
    dashboard.flush();

    const update = sentGraphUpdates(mockClient)[0];
    expect(update.data.delta.nodes).toHaveLength(1);
    expect(update.data.delta.edges).toHaveLength(0);
  });

  it('expands incident edges when a node is superseded and reactivated', () => {
    const graph = (engine as any).ctx.graph;
    graph.addNode('visibility-hub', {
      id: 'visibility-hub', type: 'host', label: 'Visibility hub',
      discovered_at: '2026-07-16T00:00:00.000Z', confidence: 1,
    });
    graph.addNode('visibility-spoke', {
      id: 'visibility-spoke', type: 'host', label: 'Visibility spoke',
      discovered_at: '2026-07-16T00:00:00.000Z', confidence: 1,
    });
    graph.addEdgeWithKey('visibility-edge', 'visibility-hub', 'visibility-spoke', {
      type: 'REACHABLE', confidence: 1, discovered_at: '2026-07-16T00:00:00.000Z',
    });
    const mockClient = { readyState: WebSocket.OPEN, send: vi.fn(), close: vi.fn() };
    (dashboard as any).clients = new Set([mockClient]);

    graph.setNodeAttribute('visibility-hub', 'identity_status', 'superseded');
    dashboard.onGraphUpdate({ updated_nodes: ['visibility-hub'] });
    dashboard.flush();
    expect(sentGraphUpdates(mockClient)[0].data.delta.removed_edges).toContain('visibility-edge');

    mockClient.send.mockClear();
    graph.removeNodeAttribute('visibility-hub', 'identity_status');
    dashboard.onGraphUpdate({ updated_nodes: ['visibility-hub'] });
    dashboard.flush();
    expect(sentGraphUpdates(mockClient)[0].data.delta.edges).toEqual([
      expect.objectContaining({ id: 'visibility-edge' }),
    ]);
  });

  it('replaces cold inventory only when its process-local revision changes', () => {
    const mockClient = {
      readyState: WebSocket.OPEN,
      send: vi.fn(),
      close: vi.fn(),
    };
    (dashboard as any).clients = new Set([mockClient]);
    (engine as any).ctx.coldStore.add({
      id: 'cold-delta-host',
      type: 'host',
      label: '10.10.10.3',
      discovered_at: '2026-07-16T00:00:00.000Z',
      last_seen_at: '2026-07-16T00:00:00.000Z',
    });

    dashboard.onGraphUpdate({});
    dashboard.flush();
    dashboard.onGraphUpdate({});
    dashboard.flush();

    const updates = sentGraphUpdates(mockClient);
    expect(updates).toHaveLength(2);
    expect(updates[0].data.detail.cold_nodes_changed).toBe(true);
    expect(updates[0].data.delta.cold_nodes).toEqual([
      expect.objectContaining({ id: 'cold-delta-host' }),
    ]);
    expect(updates[1].data.detail.cold_nodes_changed).toBeUndefined();
    expect(updates[1].data.delta.cold_nodes).toBeUndefined();
  });

  it('does not mark cold inventory changed during an unrelated durable transaction draft', () => {
    (engine as any).ctx.coldStore.add({
      id: 'cold-stable-host',
      type: 'host',
      label: '10.10.20.3',
      discovered_at: '2026-07-16T00:00:00.000Z',
      last_seen_at: '2026-07-16T00:00:00.000Z',
    });
    const revision = engine.getColdInventoryRevision();

    engine.ingestFinding({
      id: 'finding-unrelated-to-cold-store',
      agent_id: 'test-agent',
      timestamp: '2026-07-16T00:00:01.000Z',
      nodes: [{
        id: 'vuln-unrelated-to-cold-store',
        type: 'vulnerability',
        label: 'Unrelated finding',
      }],
      edges: [],
    });

    expect(engine.getColdInventoryRevision()).toBe(revision);
  });

  it('flush broadcasts accumulated graph updates through connected clients without sockets', () => {
    const mockClient = {
      readyState: WebSocket.OPEN,
      send: vi.fn(),
      close: vi.fn(),
    };
    (dashboard as any).clients = new Set([mockClient]);

    engine.ingestFinding({
      id: 'dashboard-broadcast-seed',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:00:00Z',
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
        { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB', port: 445, service_name: 'smb' },
      ],
      edges: [
        { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-03-21T10:00:00Z' } },
      ],
    });

    dashboard.onGraphUpdate({
      new_nodes: ['host-10-10-10-1'],
      updated_nodes: ['host-10-10-10-1'],
      new_edges: ['host-10-10-10-1--RUNS--svc-10-10-10-1-445'],
    });
    dashboard.onGraphUpdate({
      new_nodes: ['svc-10-10-10-1-445'],
      new_edges: ['host-10-10-10-1--RUNS--svc-10-10-10-1-445'],
    });

    dashboard.flush();

    const graphUpdates = sentGraphUpdates(mockClient);
    expect(graphUpdates).toHaveLength(1);
    const payload = graphUpdates[0];
    expect(payload.type).toBe('graph_update');
    expect(payload.data.state.lab_readiness).toBeDefined();
    expect(payload.data.delta.nodes.map((node: any) => node.id).sort()).toEqual([
      'host-10-10-10-1',
      'svc-10-10-10-1-445',
    ]);
    expect(payload.data.delta.edges[0].id).toBe('host-10-10-10-1--RUNS--svc-10-10-10-1-445');
  });

  it('flush clears pending updates after broadcast', () => {
    const mockClient = {
      readyState: WebSocket.OPEN,
      send: vi.fn(),
      close: vi.fn(),
    };
    (dashboard as any).clients = new Set([mockClient]);

    dashboard.onGraphUpdate({ new_nodes: ['host-10-10-10-1'] });
    dashboard.flush();
    dashboard.flush();

    expect(mockClient.send).toHaveBeenCalledTimes(1);
  });

  it('flush includes removed_nodes and removed_edges in delta', () => {
    const mockClient = {
      readyState: WebSocket.OPEN,
      send: vi.fn(),
      close: vi.fn(),
    };
    (dashboard as any).clients = new Set([mockClient]);

    // Seed graph with two nodes
    engine.ingestFinding({
      id: 'removal-seed',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:00:00Z',
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
        { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB', port: 445, service_name: 'smb' },
      ],
      edges: [
        { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-03-21T10:00:00Z' } },
      ],
    });

    // Simulate update with removals (as from identity reconciliation)
    dashboard.onGraphUpdate({
      updated_nodes: ['host-10-10-10-1'],
      removed_nodes: ['old-alias-node'],
      removed_edges: ['old-alias-edge'],
    });
    dashboard.flush();

    const graphUpdates = sentGraphUpdates(mockClient);
    expect(graphUpdates).toHaveLength(1);
    const payload = graphUpdates[0];
    expect(payload.data.delta.removed_nodes).toEqual(['old-alias-node']);
    expect(payload.data.delta.removed_edges).toEqual(['old-alias-edge']);
  });

  it('serveState includes history_count and browser community projection', () => {
    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) {
        this.body = body || '';
      },
      setHeader() {},
    };

    (dashboard as any).serveState(res);
    const payload = JSON.parse(res.body);
    expect(typeof payload.history_count).toBe('number');
    expect(payload.state).toBeDefined();
    expect(payload.graph).toBeDefined();
    expect(payload.graph.nodes.length).toBeGreaterThan(0);
    expect(payload.graph.nodes.every((node: any) =>
      typeof node.properties.community_id === 'number'
    )).toBe(true);
  });

  it('serveHistory returns full history with total count', () => {
    engine.ingestFinding({
      id: 'history-test',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:00:00Z',
      nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' }],
      edges: [],
    });

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) {
        this.body = body || '';
      },
      setHeader() {},
    };

    (dashboard as any).serveHistory('/api/history', res);
    const payload = JSON.parse(res.body);
    expect(payload.total).toBeGreaterThan(0);
    expect(Array.isArray(payload.entries)).toBe(true);
    expect(payload.entries.length).toBe(payload.total);
  });

  it('serveDecisionLog, serveActionExplanation, and serveTimeline expose read-only introspection views', () => {
    const decisionSpy = vi.spyOn(engine, 'getDecisionLog').mockReturnValue([{
      decision_id: 'act:act-1',
      action_id: 'act-1',
      opened_at: '2026-03-21T10:00:00Z',
      closed_at: '2026-03-21T10:01:00Z',
      outcome: 'open',
      stages: [],
    }]);
    const explainSpy = vi.spyOn(engine, 'explainAction').mockReturnValue({
      action_id: 'act-1',
      found: true,
      log_thought_chain: [],
      considered_alternatives: [],
      prior_actions_referenced: [],
    });
    const timelineSpy = vi.spyOn(engine, 'getTimeline').mockReturnValue([{
      entity_id: 'host-a',
      kind: 'node',
      became_true_at: '2026-03-21T10:00:00Z',
      evidence_refs: [],
    }]);

    const makeRes = () => ({
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) {
        this.body = body || '';
      },
      setHeader() {},
    });

    const decisionsRes = makeRes();
    (dashboard as any).serveDecisionLog('/api/decision-log?limit=5&action_id=act-1&outcome=open', decisionsRes);
    expect(decisionsRes.statusCode).toBe(200);
    expect(JSON.parse(decisionsRes.body).decisions[0].action_id).toBe('act-1');
    expect(decisionSpy).toHaveBeenCalledWith({ action_id: 'act-1', outcome: 'open', limit: 5 });

    const explainRes = makeRes();
    (dashboard as any).serveActionExplanation('act-1', explainRes);
    expect(explainRes.statusCode).toBe(200);
    expect(JSON.parse(explainRes.body).found).toBe(true);
    expect(explainSpy).toHaveBeenCalledWith('act-1');

    const timelineRes = makeRes();
    (dashboard as any).serveTimeline('/api/timeline?kind=node&entity_id=host-a&limit=3', timelineRes);
    expect(timelineRes.statusCode).toBe(200);
    expect(JSON.parse(timelineRes.body).entries[0].entity_id).toBe('host-a');
    expect(timelineSpy).toHaveBeenCalledWith({ entity_id: 'host-a', kind: 'node', limit: 3 });
  });

  it('serveHistory respects limit parameter', () => {
    // Ingest multiple findings to create activity
    for (let i = 0; i < 5; i++) {
      engine.ingestFinding({
        id: `limit-test-${i}`,
        agent_id: 'test-agent',
        timestamp: `2026-03-21T10:0${i}:00Z`,
        nodes: [{ id: `host-limit-${i}`, type: 'host', label: `10.10.10.${i}`, ip: `10.10.10.${i}` }],
        edges: [],
      });
    }

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) {
        this.body = body || '';
      },
      setHeader() {},
    };

    (dashboard as any).serveHistory('/api/history?limit=2', res);
    const payload = JSON.parse(res.body);
    expect(payload.entries.length).toBe(2);
    expect(payload.total).toBeGreaterThanOrEqual(5);
  });

  it('serveHistory filters by after/before parameters', () => {
    for (let i = 0; i < 3; i++) {
      engine.ingestFinding({
        id: `time-filter-${i}`,
        agent_id: 'test-agent',
        timestamp: `2026-03-21T1${i}:00:00Z`,
        nodes: [{ id: `host-tf-${i}`, type: 'host', label: `10.10.10.${i}`, ip: `10.10.10.${i}` }],
        edges: [],
      });
    }

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) {
        this.body = body || '';
      },
      setHeader() {},
    };

    // Filter to only entries after 11:00
    (dashboard as any).serveHistory('/api/history?after=2026-03-21T11:00:00Z', res);
    const payload = JSON.parse(res.body);
    // All returned entries should be after the threshold
    for (const entry of payload.entries) {
      expect(entry.timestamp > '2026-03-21T11:00:00Z').toBe(true);
    }
  });

  it('serveHistory event_types keeps tool runs from being crowded out by heartbeat/thought noise', () => {
    // Two real tool-run lifecycle events, buried in a burst of noise events that would
    // otherwise fill a tight limit window and hide the runs from the Analysis view.
    engine.logActionEvent({ description: 'nmap started', event_type: 'action_started', category: 'frontier', action_id: 'run-A', tool_name: 'nmap' });
    for (let i = 0; i < 20; i++) engine.logActionEvent({ description: 'beat', event_type: 'heartbeat', category: 'agent' });
    engine.logActionEvent({ description: 'nmap done', event_type: 'action_completed', category: 'frontier', action_id: 'run-A', tool_name: 'nmap', result_classification: 'success' });
    for (let i = 0; i < 20; i++) engine.logActionEvent({ description: 'thinking', event_type: 'thought', category: 'agent' });

    const res = {
      statusCode: 0, headers: {} as Record<string, string>, body: '' as string,
      writeHead(s: number, h: Record<string, string>) { this.statusCode = s; this.headers = h; },
      end(b?: string) { this.body = b || ''; }, setHeader() {},
    };

    // A tight limit that, WITHOUT the filter, would return only the newest noise events.
    (dashboard as any).serveHistory('/api/history?limit=5&event_types=action_started,action_completed', res);
    const payload = JSON.parse(res.body);
    // Only the requested types come back — no heartbeats/thoughts.
    expect(payload.entries.every((e: { event_type: string }) => e.event_type === 'action_started' || e.event_type === 'action_completed')).toBe(true);
    // Both lifecycle events of the run survive despite the 40 interleaved noise events.
    expect(payload.entries.filter((e: { action_id?: string }) => e.action_id === 'run-A').length).toBe(2);
    // total reflects the FILTERED count, so the client's "N runs" is meaningful.
    expect(payload.total).toBe(payload.entries.length);
  });

  it('serveHistory returns most recent entries first by default', () => {
    // Get the full history to see how many startup entries exist
    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) {
        this.body = body || '';
      },
      setHeader() {},
    };

    (dashboard as any).serveHistory('/api/history', res);
    const baseline = JSON.parse(res.body);
    const baselineCount = baseline.total;

    for (let i = 0; i < 5; i++) {
      engine.ingestFinding({
        id: `order-test-${i}`,
        agent_id: 'test-agent',
        timestamp: `2026-03-21T10:0${i}:00Z`,
        nodes: [{ id: `host-order-${i}`, type: 'host', label: `10.10.10.${i}`, ip: `10.10.10.${i}` }],
        edges: [],
      });
    }

    // Fetch full history to verify total grew
    (dashboard as any).serveHistory('/api/history', res);
    const full = JSON.parse(res.body);
    expect(full.total).toBeGreaterThan(baselineCount);
    expect(full.order).toBe('desc');

    // Default: limit=2 should return the two newest entries, newest first
    (dashboard as any).serveHistory('/api/history?limit=2', res);
    const page1 = JSON.parse(res.body);
    expect(page1.entries.length).toBe(2);
    expect(page1.order).toBe('desc');
    const firstTs = page1.entries[0].timestamp;
    const lastTs = page1.entries[page1.entries.length - 1].timestamp;
    expect(firstTs >= lastTs).toBe(true);

    // Explicit ascending order returns oldest first
    (dashboard as any).serveHistory('/api/history?limit=2&order=asc', res);
    const ascPage = JSON.parse(res.body);
    expect(ascPage.entries.length).toBe(2);
    expect(ascPage.order).toBe('asc');
    const ascFirst = ascPage.entries[0].timestamp;
    const ascLast = ascPage.entries[ascPage.entries.length - 1].timestamp;
    expect(ascFirst <= ascLast).toBe(true);
    // Asc page should still be the *most recent* slice (last N), just ordered oldest-first
    expect(ascLast).toBe(firstTs);
  });

  it('serveTelemetry returns tool_telemetry, inference_effectiveness, and health', () => {
    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) {
        this.body = body || '';
      },
      setHeader() {},
    };

    (dashboard as any).serveTelemetry(res);
    expect(res.statusCode).toBe(200);
    const payload = JSON.parse(res.body);
    // tool_telemetry may be null if no telemetry singleton is set
    expect(payload).toHaveProperty('inference_effectiveness');
    expect(payload).toHaveProperty('health');
    expect(payload.health).toHaveProperty('status');
    expect(payload.health).toHaveProperty('counts');
    expect(payload).toHaveProperty('graph_stats');
    expect(payload.graph_stats.total_nodes).toBeGreaterThanOrEqual(0);
  });

  it('graph_update WS payload includes history_count', () => {
    const mockClient = {
      readyState: WebSocket.OPEN,
      send: vi.fn(),
      close: vi.fn(),
    };
    (dashboard as any).clients = new Set([mockClient]);

    engine.ingestFinding({
      id: 'hc-ws-test',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:00:00Z',
      nodes: [{ id: 'host-hc-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' }],
      edges: [],
    });

    dashboard.onGraphUpdate({ new_nodes: ['host-hc-1'] });
    dashboard.flush();

    const graphUpdates = sentGraphUpdates(mockClient);
    expect(graphUpdates).toHaveLength(1);
    const payload = graphUpdates[0];
    expect(payload.type).toBe('graph_update');
    expect(typeof payload.data.history_count).toBe('number');
    expect(payload.data.history_count).toBeGreaterThan(0);
  });

  it('serveHistory ignores invalid limit parameter', () => {
    for (let i = 0; i < 3; i++) {
      engine.ingestFinding({
        id: `invalid-limit-${i}`,
        agent_id: 'test-agent',
        timestamp: `2026-03-21T1${i}:00:00Z`,
        nodes: [{ id: `host-il-${i}`, type: 'host', label: `10.10.10.${i}`, ip: `10.10.10.${i}` }],
        edges: [],
      });
    }

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) {
        this.body = body || '';
      },
      setHeader() {},
    };

    // NaN limit should be ignored (return all)
    (dashboard as any).serveHistory('/api/history?limit=abc', res);
    const payload1 = JSON.parse(res.body);
    expect(payload1.entries.length).toBe(payload1.total);

    // Negative limit should be ignored
    (dashboard as any).serveHistory('/api/history?limit=-5', res);
    const payload2 = JSON.parse(res.body);
    expect(payload2.entries.length).toBe(payload2.total);

    // Zero limit should be ignored
    (dashboard as any).serveHistory('/api/history?limit=0', res);
    const payload3 = JSON.parse(res.body);
    expect(payload3.entries.length).toBe(payload3.total);
  });

  it('serveHistory ignores invalid after/before parameters', () => {
    engine.ingestFinding({
      id: 'invalid-date-test',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:00:00Z',
      nodes: [{ id: 'host-idt-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' }],
      edges: [],
    });

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) {
        this.body = body || '';
      },
      setHeader() {},
    };

    // Invalid after param should be ignored (return all)
    (dashboard as any).serveHistory('/api/history?after=not-a-date', res);
    const payload = JSON.parse(res.body);
    expect(payload.entries.length).toBe(payload.total);
    expect(payload.total).toBeGreaterThan(0);
  });

  it('static file responses include Cache-Control header', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'overwatch-dashboard-cc-'));
    writeFileSync(join(tempDir, 'index.html'), '<html></html>', 'utf-8');

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: undefined as string | Buffer | undefined,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string | Buffer) {
        this.body = body;
      },
      setHeader() {},
    };

    (dashboard as any).dashboardDir = tempDir;
    (dashboard as any).serveStaticFile('/', res);

    expect(res.statusCode).toBe(200);
    expect(res.headers['Cache-Control']).toBe('no-cache');

    rmSync(tempDir, { recursive: true, force: true });
  });

  it('revalidates cached static files after a dashboard rebuild', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'overwatch-dashboard-cache-'));
    const indexPath = join(tempDir, 'index.html');
    writeFileSync(indexPath, '<html>old</html>', 'utf-8');

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: undefined as string | Buffer | undefined,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string | Buffer) {
        this.body = body;
      },
      setHeader() {},
    };

    (dashboard as any).dashboardDir = tempDir;
    (dashboard as any).serveStaticFile('/index.html', res);
    expect(res.body).toBe('<html>old</html>');

    writeFileSync(indexPath, '<html>new dashboard bundle</html>', 'utf-8');
    res.statusCode = 0;
    res.body = undefined;
    (dashboard as any).serveStaticFile('/index.html', res);

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('<html>new dashboard bundle</html>');

    rmSync(tempDir, { recursive: true, force: true });
  });

  it('stop() clears fileCache', async () => {
    // Populate cache by accessing it directly
    (dashboard as any).fileCache.set('test.html', { content: '<html></html>', mtimeMs: 1, size: 13 });
    expect((dashboard as any).fileCache.size).toBe(1);

    await dashboard.stop();
    expect((dashboard as any).fileCache.size).toBe(0);
  });

  it('refreshes community IDs after delivering the topology delta', () => {
    vi.useFakeTimers();
    try {
      const mockClient = {
        readyState: WebSocket.OPEN,
        send: vi.fn(),
        close: vi.fn(),
        on: vi.fn(),
      };
      (dashboard as any).mainHub.attachConnection(mockClient);
      mockClient.send.mockClear();

      // Seed two connected hosts so Louvain has edges to work with.
      engine.ingestFinding({
        id: 'community-delta-seed',
        agent_id: 'test-agent',
        timestamp: '2026-03-27T10:00:00Z',
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'host-10-10-10-2', properties: { type: 'REACHABLE', confidence: 1.0, discovered_at: '2026-03-27T10:00:00Z' } },
        ],
      });

      dashboard.onGraphUpdate({
        new_nodes: ['host-10-10-10-1', 'host-10-10-10-2'],
        new_edges: ['host-10-10-10-1--REACHABLE--host-10-10-10-2'],
      });
      dashboard.flush();

      const graphUpdates = sentGraphUpdates(mockClient);
      expect(graphUpdates).toHaveLength(1);
      expect(graphUpdates[0].data.delta.nodes.filter((node: any) => node.id.startsWith('host-'))).toHaveLength(2);

      vi.advanceTimersByTime(750);
      const refresh = mockClient.send.mock.calls
        .map(call => JSON.parse(String(call[0])))
        .find(message => message.type === 'state_refresh');
      expect(refresh).toBeDefined();
      const communities = refresh.data.community_ids;
      expect(typeof communities['host-10-10-10-1']).toBe('number');
      expect(communities['host-10-10-10-1']).toBe(communities['host-10-10-10-2']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('index.html serves SPA entry point directly', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'overwatch-dashboard-idx-'));
    writeFileSync(join(tempDir, 'index.html'), '<html>SPA</html>', 'utf-8');

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: undefined as string | Buffer | undefined,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string | Buffer) {
        this.body = body;
      },
      setHeader() {},
    };

    (dashboard as any).dashboardDir = tempDir;
    (dashboard as any).serveStaticFile('/index.html', res);

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('SPA');

    rmSync(tempDir, { recursive: true, force: true });
  });

  it('rejects path traversal attempts in static file serving', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'overwatch-dashboard-trav-'));
    writeFileSync(join(tempDir, 'index.html'), '<html></html>', 'utf-8');

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: undefined as string | Buffer | undefined,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string | Buffer) {
        this.body = body;
      },
      setHeader() {},
    };

    (dashboard as any).dashboardDir = tempDir;

    // In SPA mode, paths WITH extensions bypass the index.html rewrite and hit traversal checks
    const traversalPaths = [
      '/assets/../../etc/shadow.js',
      '/styles/../../../etc/passwd.css',
      '/img/..%2F..%2Fetc/hosts.png',
    ];

    for (const p of traversalPaths) {
      res.statusCode = 0;
      (dashboard as any).fileCache.clear();
      (dashboard as any).serveStaticFile(p, res);
      expect(res.statusCode).toBe(403);
    }

    rmSync(tempDir, { recursive: true, force: true });
  });

  it('serves binary assets without UTF-8 corruption', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'overwatch-dashboard-'));
    mkdirSync(join(tempDir, 'assets'));
    writeFileSync(join(tempDir, 'index.html'), '<html></html>', 'utf-8');
    const pngBytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff]);
    writeFileSync(join(tempDir, 'assets', 'test.png'), pngBytes);

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: undefined as string | Buffer | undefined,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string | Buffer) {
        this.body = body;
      },
      setHeader() {},
    };

    (dashboard as any).dashboardDir = tempDir;
    (dashboard as any).serveStaticFile('/assets/test.png', res);

    expect(res.statusCode).toBe(200);
    expect(res.headers['Content-Type']).toBe('image/png');
    expect(Buffer.isBuffer(res.body)).toBe(true);
    expect(res.body).toEqual(pngBytes);

    rmSync(tempDir, { recursive: true, force: true });
  });

  it('F22: CORS regex matches IPv6 loopback [::1]', () => {
    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      responseHeaders: {} as Record<string, string>,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) {
        this.body = body || '';
      },
      setHeader(key: string, val: string) {
        this.responseHeaders[key] = val;
      },
    };

    const reqIpv6 = {
      url: '/api/state',
      headers: { origin: 'http://[::1]:8384' },
    };

    (dashboard as any).handleHttp(reqIpv6, res);
    expect(res.responseHeaders['Access-Control-Allow-Origin']).toBe('http://[::1]:8384');
  });

  it('F22: CORS regex still matches localhost and 127.0.0.1', () => {
    for (const origin of ['http://localhost:3000', 'http://127.0.0.1:8384', 'https://localhost']) {
      const res: any = {
        responseHeaders: {},
        writeHead() {},
        end() {},
        setHeader(key: string, val: string) { this.responseHeaders[key] = val; },
      };

      (dashboard as any).handleHttp(
        { url: '/api/state', headers: { origin } },
        res,
      );
      expect(res.responseHeaders['Access-Control-Allow-Origin']).toBe(origin);
    }
  });

  it('F21: isLoopback identifies loopback addresses', () => {
    expect((dashboard as any).isLoopback('127.0.0.1')).toBe(true);
    expect((dashboard as any).isLoopback('::1')).toBe(true);
    expect((dashboard as any).isLoopback('localhost')).toBe(true);
    expect((dashboard as any).isLoopback('0.0.0.0')).toBe(false);
    expect((dashboard as any).isLoopback('10.10.10.5')).toBe(false);
  });

  it('normalizes same-origin authorities while rejecting foreign ports and non-HTTP schemes', () => {
    expect((dashboard as any).isAllowedWsOrigin('https://ops.example.test', 'ops.example.test:443')).toBe(true);
    expect((dashboard as any).isAllowedWsOrigin('https://ops.example.test', 'ops.example.test')).toBe(true);
    expect((dashboard as any).isAllowedWsOrigin('https://ops.example.test:444', 'ops.example.test:443')).toBe(false);
    expect((dashboard as any).isAllowedWsOrigin('ftp://ops.example.test', 'ops.example.test')).toBe(false);
    expect((dashboard as any).isAllowedWsOrigin('http://127.0.0.1:3000', 'localhost:8384')).toBe(true);
  });

  // ---- Terminal Multiplexer (WS bridge) ----

  it('serveSessions returns empty when no session manager', () => {
    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };

    // dashboard has no sessionManager by default
    (dashboard as any).serveSessions(res);
    const payload = JSON.parse(res.body);
    expect(payload).toEqual({ total: 0, active: 0, sessions: [] });
  });

  it('serveSessions returns session list when session manager is set', () => {
    const mockSessions = [
      { id: 'sess-1', state: 'connected', title: 'Shell', kind: 'pty' },
      { id: 'sess-2', state: 'closed', title: 'Old', kind: 'ssh' },
    ];
    (dashboard as any).sessionManager = {
      list: () => mockSessions,
    };

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };

    (dashboard as any).serveSessions(res);
    const payload = JSON.parse(res.body);
    expect(payload.total).toBe(2);
    expect(payload.active).toBe(1);
    expect(payload.sessions).toHaveLength(2);
  });

  it('readiness reports session lifecycle buckets without treating recovery states as closed', () => {
    (dashboard as any).sessionManager = {
      list: () => [
        { id: 'connected', state: 'connected' },
        { id: 'waiting', state: 'pending' },
        { id: 'resume', state: 'resume_available' },
        { id: 'interrupted', state: 'interrupted' },
        { id: 'error', state: 'error' },
        { id: 'closed', state: 'closed' },
      ],
    };
    const res = {
      statusCode: 0,
      body: '',
      writeHead(statusCode: number) { this.statusCode = statusCode; },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };

    (dashboard as any).serveReadiness(res);
    const payload = JSON.parse(res.body);
    expect(payload.sessions).toEqual({
      total: 6,
      active: 2,
      connected: 1,
      waiting: 1,
      resume_available: 1,
      interrupted: 1,
      error: 1,
      closed: 4,
      closed_exact: 1,
    });
  });

  it('handleSessionClose closes a session through the manager', () => {
    const close = vi.fn(() => ({
      metadata: { id: 'abc-123', state: 'closed', title: 'Shell', kind: 'pty' },
      final: { session_id: 'abc-123', start_pos: 0, end_pos: 0, text: '', truncated: false },
    }));
    (dashboard as any).sessionManager = { close };

    const req = { headers: {}, url: '/api/sessions/abc-123/close' } as any;
    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) { this.statusCode = statusCode; this.headers = headers; },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };

    (dashboard as any).handleSessionClose('abc-123', req, res);

    expect(close).toHaveBeenCalledWith('abc-123', 'dashboard', true);
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).metadata.state).toBe('closed');
  });

  it('handleSessionResume returns recovered listener metadata and maps conflicts', async () => {
    const resume = vi.fn()
      .mockResolvedValueOnce({
        metadata: {
          id: 'abc-123',
          state: 'pending',
          listener_id: 'abc-123',
          connection_generation: 2,
        },
      })
      .mockRejectedValueOnce(Object.assign(
        new Error('Session abc-123 is not an explicitly resumable listener.'),
        { code: 'SESSION_NOT_RESUMABLE' },
      ));
    (dashboard as any).sessionManager = { resume };
    const request = { headers: {}, url: '/api/sessions/abc-123/resume' } as any;
    const response = () => ({
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '',
      writeHead(statusCode: number, headers: Record<string, string>) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    });

    const ok = response();
    (dashboard as any).handleSessionResume('abc-123', request, ok);
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(ok.statusCode).toBe(200);
    expect(JSON.parse(ok.body)).toMatchObject({
      resumed: true,
      metadata: {
        id: 'abc-123',
        state: 'pending',
        connection_generation: 2,
      },
    });
    expect(resume).toHaveBeenCalledWith('abc-123', 'dashboard', true);

    const conflict = response();
    (dashboard as any).handleSessionResume('abc-123', request, conflict);
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(conflict.statusCode).toBe(409);
    expect(JSON.parse(conflict.body).code).toBe('SESSION_NOT_RESUMABLE');
  });

  it('handleSessionUpdate updates title and notes through the manager', async () => {
    const update = vi.fn(() => ({ id: 'abc-123', state: 'connected', title: 'New title', notes: 'keep' }));
    (dashboard as any).sessionManager = { update };

    const req = {
      headers: { 'content-type': 'application/json' },
      url: '/api/sessions/abc-123',
      on(event: string, cb: (chunk?: Buffer) => void) {
        if (event === 'data') cb(Buffer.from(JSON.stringify({ title: 'New title', notes: 'keep', ignored: true })));
        if (event === 'end') cb();
      },
    } as any;
    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) { this.statusCode = statusCode; this.headers = headers; },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };

    (dashboard as any).handleSessionUpdate('abc-123', req, res);
    await new Promise(r => setTimeout(r, 10));

    expect(update).toHaveBeenCalledWith('abc-123', { title: 'New title', notes: 'keep' }, 'dashboard', true);
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).metadata.title).toBe('New title');
  });

  it('rechecks persistence after an async session-update body before mutating metadata', async () => {
    const update = vi.fn();
    (dashboard as any).sessionManager = { update };
    const writable = vi.spyOn(engine, 'isPersistenceWritable').mockReturnValue(true);
    const req = new PassThrough() as any;
    req.headers = { 'content-type': 'application/json' };
    req.url = '/api/sessions/abc-123';
    const res = {
      statusCode: 0,
      body: '',
      writeHead(statusCode: number) { this.statusCode = statusCode; },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };

    (dashboard as any).handleSessionUpdate('abc-123', req, res);
    writable.mockReturnValue(false);
    req.end(JSON.stringify({ title: 'must-not-land' }));
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(update).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(503);
    expect(JSON.parse(res.body)).toMatchObject({ code: 'PERSISTENCE_READ_ONLY' });
  });

  it('does not leak a settings patch when persistence closes during body read', async () => {
    const before = JSON.parse(JSON.stringify(engine.getConfig().opsec));
    const writable = vi.spyOn(engine, 'isPersistenceWritable').mockReturnValue(true);
    const req = new PassThrough() as any;
    req.headers = { 'content-type': 'application/json' };
    req.url = '/api/settings';
    const res = {
      statusCode: 0,
      body: '',
      writeHead(statusCode: number) { this.statusCode = statusCode; },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };

    (dashboard as any).handleUpdateSettings(req, res);
    writable.mockReturnValue(false);
    req.end(JSON.stringify({ enabled: true, max_noise: 1.5 }));
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(engine.getConfig().opsec).toEqual(before);
    expect(res.statusCode).toBe(503);
    expect(JSON.parse(res.body)).toMatchObject({ code: 'PERSISTENCE_READ_ONLY' });
  });

  it('serveSessionBuffer reads tail text through the manager', () => {
    const read = vi.fn(() => ({
      session_id: 'abc-123',
      start_pos: 10,
      end_pos: 25,
      text: 'whoami\ncorp\\jdoe',
      truncated: false,
    }));
    (dashboard as any).sessionManager = { read };
    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) { this.statusCode = statusCode; this.headers = headers; },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };

    (dashboard as any).serveSessionBuffer('abc-123', '/api/sessions/abc-123/buffer?tail_bytes=2048', res);

    expect(read).toHaveBeenCalledWith('abc-123', undefined, 2048);
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).text).toContain('whoami');
  });

  it('serveSessionBuffer addresses the expected connection generation', () => {
    const read = vi.fn(() => ({
      session_id: 'abc-123',
      connection_id: 'abc-123:g2',
      connection_generation: 2,
      start_pos: 0,
      end_pos: 0,
      text: '',
      truncated: false,
    }));
    (dashboard as any).sessionManager = { read };
    const res = {
      statusCode: 0,
      body: '',
      writeHead(statusCode: number) { this.statusCode = statusCode; },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };

    (dashboard as any).serveSessionBuffer(
      'abc-123',
      '/api/sessions/abc-123/buffer?connection_id=abc-123%3Ag2&connection_generation=2',
      res,
    );

    expect(read).toHaveBeenCalledWith(
      'abc-123',
      undefined,
      undefined,
      {
        connection_id: 'abc-123:g2',
        connection_generation: 2,
      },
    );
    expect(res.statusCode).toBe(200);
  });

  it('serveSessionBuffer returns a generation conflict code for stale readers', () => {
    const stale = Object.assign(
      new Error('Session abc-123 connection generation changed.'),
      { code: 'SESSION_GENERATION_CHANGED' },
    );
    (dashboard as any).sessionManager = {
      read: vi.fn(() => {
        throw stale;
      }),
    };
    const res = {
      statusCode: 0,
      body: '',
      writeHead(statusCode: number) { this.statusCode = statusCode; },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };

    (dashboard as any).serveSessionBuffer(
      'abc-123',
      '/api/sessions/abc-123/buffer?connection_id=abc-123%3Ag1',
      res,
    );

    expect(res.statusCode).toBe(409);
    expect(JSON.parse(res.body)).toMatchObject({
      code: 'SESSION_GENERATION_CHANGED',
    });
  });

  it('serveFindingContext returns affected nodes and evidence chains', () => {
    engine.ingestFinding({
      id: 'finding-context-seed',
      agent_id: 'test-agent',
      action_id: 'act-context',
      timestamp: '2026-05-15T00:00:00Z',
      target_node_ids: ['host-context'],
      nodes: [
        { id: 'host-context', type: 'host', label: 'DC01.test.local', hostname: 'DC01', ip: '10.10.10.10', alive: true },
        { id: 'user-context', type: 'user', label: 'admin', username: 'admin' },
      ],
      edges: [
        { source: 'user-context', target: 'host-context', properties: { type: 'ADMIN_TO', confidence: 1.0, discovered_at: '2026-05-15T00:00:00Z' } },
      ],
    });

    const findingsRes = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) { this.statusCode = statusCode; this.headers = headers; },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };
    (dashboard as any).serveFindings(findingsRes);
    const findingId = JSON.parse(findingsRes.body).findings[0].id;

    const res = {
      statusCode: 0,
      headers: {} as Record<string, string>,
      body: '' as string,
      writeHead(statusCode: number, headers: Record<string, string>) { this.statusCode = statusCode; this.headers = headers; },
      end(body?: string) { this.body = body || ''; },
      setHeader() {},
    };
    (dashboard as any).serveFindingContext(findingId, res);

    const payload = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(payload.finding.id).toBe(findingId);
    expect(payload.affected_nodes.length).toBeGreaterThan(0);
    expect(payload.evidence_chains.length).toBeGreaterThan(0);
    expect(payload.report_ready).toBe(true);
  });

  const completeSessionMeta = (overrides: Partial<SessionDto> = {}): SessionDto => ({
    id: 'sess-1',
    state: 'connected',
    title: 'Shell',
    kind: 'pty',
    transport: 'pty',
    started_at: '2026-07-16T00:00:00.000Z',
    last_activity_at: '2026-07-16T00:00:00.000Z',
    capabilities: {},
    buffer_end_pos: 0,
    ...overrides,
  });

  it('handleSessionConnection closes with 4503 when no session manager', () => {
    const mockWs = {
      close: vi.fn(),
      on: vi.fn(),
      send: vi.fn(),
      readyState: WebSocket.OPEN,
    };

    (dashboard as any).handleSessionConnection(mockWs, 'fake-session-id');
    expect(mockWs.close).toHaveBeenCalledWith(4503, 'Session manager not available');
  });

  it('handleSessionConnection closes with 4404 when session not found', () => {
    (dashboard as any).sessionManager = {
      getSession: () => null,
    };

    const mockWs = {
      close: vi.fn(),
      on: vi.fn(),
      send: vi.fn(),
      readyState: WebSocket.OPEN,
    };

    (dashboard as any).handleSessionConnection(mockWs, 'nonexistent-id');
    expect(mockWs.close).toHaveBeenCalledWith(4404, 'Session not found');
  });

  it('handleSessionConnection closes with 4409 when session not connected', () => {
    (dashboard as any).sessionManager = {
      getSession: () => completeSessionMeta({ state: 'closed', title: 'Old' }),
    };

    const mockWs = {
      close: vi.fn(),
      on: vi.fn(),
      send: vi.fn(),
      readyState: WebSocket.OPEN,
    };

    (dashboard as any).handleSessionConnection(mockWs, 'sess-1');
    expect(mockWs.close).toHaveBeenCalledWith(4409, 'Session not connected (state: closed)');
  });

  it('handleSessionConnection sends initial output and starts polling', () => {
    vi.useFakeTimers();
    const mockMeta = completeSessionMeta();
    (dashboard as any).sessionManager = {
      getSession: () => mockMeta,
      read: vi.fn()
        .mockReturnValueOnce({ text: 'hello', end_pos: 5, start_pos: 0, truncated: false })  // initial tail
        .mockReturnValueOnce({ text: '', end_pos: 5, start_pos: 5, truncated: false })         // cursor init (0-byte)
        .mockReturnValueOnce({ text: ' world', end_pos: 11, start_pos: 5, truncated: false }), // poll
      write: vi.fn(),
      resize: vi.fn(),
    };

    const sent: string[] = [];
    const listeners: Record<string, Function[]> = {};
    const mockWs = {
      close: vi.fn(),
      on: vi.fn((event: string, cb: Function) => {
        if (!listeners[event]) listeners[event] = [];
        listeners[event].push(cb);
      }),
      send: vi.fn((data: string) => sent.push(data)),
      readyState: WebSocket.OPEN,
    };

    (dashboard as any).handleSessionConnection(mockWs, 'sess-1');

    // Should have sent session_meta + initial output
    expect(sent.length).toBe(2);
    expect(JSON.parse(sent[0]).type).toBe('session_meta');
    expect(JSON.parse(sent[1])).toEqual({ type: 'output', text: 'hello', end_pos: 5 });

    // Advance past poll interval
    vi.advanceTimersByTime(60);

    expect(sent.length).toBe(3);
    expect(JSON.parse(sent[2])).toEqual({ type: 'output', text: ' world', end_pos: 11 });

    // Should have poller registered
    expect((dashboard as any).sessionPollers.has(mockWs)).toBe(true);

    // Cleanup: trigger close handler
    listeners['close']?.[0]?.();
    expect((dashboard as any).sessionPollers.has(mockWs)).toBe(false);

    vi.useRealTimers();
  });

  it('closes a terminal WebSocket when its connection generation ends', () => {
    vi.useFakeTimers();
    let meta = completeSessionMeta({
      kind: 'socket',
      transport: 'tcp',
      connection_id: 'sess-1:g1',
      connection_generation: 1,
    });
    (dashboard as any).sessionManager = {
      getSession: () => meta,
      read: vi.fn().mockReturnValue({
        text: '',
        end_pos: 0,
        start_pos: 0,
        truncated: false,
      }),
      write: vi.fn(),
      resize: vi.fn(),
    };
    const listeners: Record<string, Function[]> = {};
    const mockWs = {
      close: vi.fn(),
      on: vi.fn((event: string, cb: Function) => {
        if (!listeners[event]) listeners[event] = [];
        listeners[event].push(cb);
      }),
      send: vi.fn(),
      readyState: WebSocket.OPEN,
    };

    (dashboard as any).handleSessionConnection(mockWs, 'sess-1');
    meta = {
      ...meta,
      connection_id: 'sess-1:g2',
      connection_generation: 2,
    };
    vi.advanceTimersByTime(60);

    expect(mockWs.send).toHaveBeenCalledWith(JSON.stringify({
      type: 'session_closed',
      connection_id: 'sess-1:g1',
    }));
    expect(mockWs.close).toHaveBeenCalledWith(4410, 'Session generation ended');
    expect((dashboard as any).sessionPollers.has(mockWs)).toBe(false);
    listeners.close?.[0]?.();
    vi.useRealTimers();
  });

  it('handleSessionConnection forwards input and resize messages', () => {
    vi.useFakeTimers();
    const mockMeta = completeSessionMeta();
    const writeSpy = vi.fn();
    const resizeSpy = vi.fn();
    (dashboard as any).sessionManager = {
      getSession: () => mockMeta,
      read: vi.fn().mockReturnValue({ text: '', end_pos: 0, start_pos: 0, truncated: false }),
      write: writeSpy,
      resize: resizeSpy,
    };

    const listeners: Record<string, Function[]> = {};
    const mockWs = {
      close: vi.fn(),
      on: vi.fn((event: string, cb: Function) => {
        if (!listeners[event]) listeners[event] = [];
        listeners[event].push(cb);
      }),
      send: vi.fn(),
      readyState: WebSocket.OPEN,
    };

    (dashboard as any).handleSessionConnection(mockWs, 'sess-1');

    // Find message handler
    const messageHandler = listeners['message']?.[0];
    expect(messageHandler).toBeDefined();

    // Send input
    messageHandler(JSON.stringify({ type: 'input', data: 'ls -la\n' }));
    expect(writeSpy).toHaveBeenCalledWith('sess-1', 'ls -la\n', 'dashboard', true);

    // Send resize
    messageHandler(JSON.stringify({ type: 'resize', cols: 120, rows: 40 }));
    expect(resizeSpy).toHaveBeenCalledWith('sess-1', 120, 40, 'dashboard', true);

    // Cleanup
    listeners['close']?.[0]?.();
    vi.useRealTimers();
  });

  it('blocks an existing session socket when persistence becomes read-only', () => {
    vi.useFakeTimers();
    const mockMeta = completeSessionMeta();
    const writeSpy = vi.fn();
    (dashboard as any).sessionManager = {
      getSession: () => mockMeta,
      read: vi.fn().mockReturnValue({ text: '', end_pos: 0, start_pos: 0, truncated: false }),
      write: writeSpy,
      resize: vi.fn(),
    };

    const writableSpy = vi.spyOn(engine, 'isPersistenceWritable').mockReturnValue(false);
    const listeners: Record<string, Function[]> = {};
    const sent: string[] = [];
    const mockWs = {
      close: vi.fn(),
      on: vi.fn((event: string, cb: Function) => {
        if (!listeners[event]) listeners[event] = [];
        listeners[event].push(cb);
      }),
      send: vi.fn((data: string) => sent.push(data)),
      readyState: WebSocket.OPEN,
    };

    (dashboard as any).handleSessionConnection(mockWs, 'sess-1');
    listeners.message[0](JSON.stringify({ type: 'input', data: 'id\n' }));

    expect(writeSpy).not.toHaveBeenCalled();
    expect(sent.map(message => JSON.parse(message))).toContainEqual(expect.objectContaining({
      type: 'error',
      code: 'PERSISTENCE_READ_ONLY',
    }));
    expect(mockWs.close).toHaveBeenCalledWith(4503, 'Persistence is read-only');

    listeners.close?.[0]?.();
    writableSpy.mockRestore();
    vi.useRealTimers();
  });

  it('session poller stops and notifies on read error', () => {
    vi.useFakeTimers();
    const mockMeta = completeSessionMeta();
    let readCallCount = 0;
    (dashboard as any).sessionManager = {
      getSession: () => mockMeta,
      read: vi.fn(() => {
        readCallCount++;
        if (readCallCount <= 2) return { text: '', end_pos: 0, start_pos: 0, truncated: false };
        throw new Error('Session closed');
      }),
      write: vi.fn(),
      resize: vi.fn(),
    };

    const sent: string[] = [];
    const mockWs = {
      close: vi.fn(),
      on: vi.fn(),
      send: vi.fn((data: string) => sent.push(data)),
      readyState: WebSocket.OPEN,
    };

    (dashboard as any).handleSessionConnection(mockWs, 'sess-1');
    expect((dashboard as any).sessionPollers.has(mockWs)).toBe(true);

    // Advance past poll to trigger error
    vi.advanceTimersByTime(60);

    // Should have sent session_closed message
    const closedMsg = sent.find(s => JSON.parse(s).type === 'session_closed');
    expect(closedMsg).toBeDefined();

    // Poller should be cleaned up
    expect((dashboard as any).sessionPollers.has(mockWs)).toBe(false);

    // WS should be closed
    expect(mockWs.close).toHaveBeenCalledWith(4410, 'Session closed');

    vi.useRealTimers();
  });

  // ============================================================
  // Agent REST Endpoints
  // ============================================================

  describe('Agent REST endpoints', () => {
    function mockRes() {
      return {
        statusCode: 0,
        headers: {} as Record<string, string>,
        body: '' as string,
        writeHead(statusCode: number, headers: Record<string, string>) { this.statusCode = statusCode; this.headers = headers; },
        end(body?: string) { this.body = body || ''; },
        setHeader() {},
      };
    }

    function registerTestAgent(overrides?: Partial<import('../../types.js').AgentTask>) {
      const task: import('../../types.js').AgentTask = {
        id: 'task-' + Math.random().toString(36).slice(2, 10),
        agent_id: 'agent-test-1',
        assigned_at: new Date().toISOString(),
        status: 'running',
        subgraph_node_ids: [],
        ...overrides,
      };
      engine.registerAgent(task);
      return task;
    }

    it('serveAgents returns all agents with enriched fields', () => {
      const task = registerTestAgent();
      registerTestAgent({ id: 'task-completed', agent_id: 'agent-test-2', status: 'completed' });

      const res = mockRes();
      (dashboard as any).serveAgents(res);

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body);
      expect(data.total).toBe(2);
      expect(data.agents).toHaveLength(2);

      const running = data.agents.find((a: any) => a.id === task.id);
      expect(running.elapsed_ms).toBeTypeOf('number');
      expect(running.elapsed_ms).toBeGreaterThanOrEqual(0);

      const completed = data.agents.find((a: any) => a.id === 'task-completed');
      expect(completed.elapsed_ms).toBeUndefined();
    });

    it('projects the same canonical AgentDto through REST, context, state, and WebSockets', () => {
      vi.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-07-15T12:00:00Z'));
      const task = registerTestAgent({
        id: 'task-canonical', agent_id: 'operator-label', assigned_at: '2026-07-15T11:55:00Z',
        heartbeat_at: '2026-07-15T11:59:30Z', heartbeat_ttl_seconds: 120,
        archetype: 'web_tester', objective: 'Inspect the app', model: 'test-model',
      });
      engine.logActionEvent({
        description: 'Found endpoint', event_type: 'finding_reported', category: 'finding',
        linked_agent_task_id: task.id, linked_finding_ids: ['finding-canonical'],
      });

      const agentRes = mockRes();
      (dashboard as any).serveAgents(agentRes);
      const restDto = AgentDtoSchema.parse(JSON.parse(agentRes.body).agents[0]);

      const contextRes = mockRes();
      (dashboard as any).serveAgentContext(task.id, contextRes);
      const contextDto = AgentDtoSchema.parse(JSON.parse(contextRes.body).task);

      const stateRes = mockRes();
      (dashboard as any).serveState(stateRes);
      const stateDto = AgentDtoSchema.parse(JSON.parse(stateRes.body).state.agents[0]);

      const socket = { readyState: WebSocket.OPEN, send: vi.fn(), close: vi.fn(), on: vi.fn() };
      (dashboard as any).wss.emit('connection', socket);
      const fullState = sentMessages(socket)[0];
      const fullStateDto = AgentDtoSchema.parse(fullState.data.state.agents[0]);

      engine.addNode({
        id: 'agent-dto-update', type: 'host', label: 'agent dto update', ip: '10.10.10.1',
        discovered_at: '2026-07-15T12:00:00Z', confidence: 1,
      });
      dashboard.onGraphUpdate({ new_nodes: ['agent-dto-update'] });
      dashboard.flush();
      const graphUpdate = sentMessages(socket).find(message => message.type === 'graph_update');
      const graphUpdateDto = AgentDtoSchema.parse(graphUpdate.data.state.agents[0]);

      expect(restDto).toEqual(contextDto);
      expect(restDto).toEqual(stateDto);
      expect(fullStateDto).toEqual(restDto);
      expect(graphUpdateDto).toEqual(restDto);
      expect(restDto).toMatchObject({
        task_id: 'task-canonical', agent_label: 'operator-label', lifecycle: 'live', findings_count: 1,
      });
    });

    it('serveAgentContext returns task and subgraph', () => {
      // Add a node so subgraph has something to traverse
      engine.ingestFinding({
        id: 'agent-ctx-seed',
        agent_id: 'test-agent',
        timestamp: new Date().toISOString(),
        nodes: [{ id: 'host-ctx-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' }],
        edges: [],
      });

      const task = registerTestAgent({ subgraph_node_ids: ['host-ctx-1'] });

      const res = mockRes();
      (dashboard as any).serveAgentContext(task.id, res);

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body);
      expect(data.task.id).toBe(task.id);
      expect(data.subgraph).toBeDefined();
      expect(data.subgraph.nodes).toBeDefined();
      expect(data.subgraph.edges).toBeDefined();
    });

    it('serveAgentContext returns 404 for missing task', () => {
      const res = mockRes();
      (dashboard as any).serveAgentContext('nonexistent', res);
      expect(res.statusCode).toBe(404);
    });

    it('handleAgentCancel cancels a running agent', () => {
      const task = registerTestAgent({ status: 'running' });

      const req = { headers: {}, url: '/api/agents/x/cancel' } as any;
      const res = mockRes();
      (dashboard as any).handleAgentCancel(task.id, req, res);

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body);
      expect(data.cancelled).toBe(true);
      expect(data.task.status).toBe('interrupted');

      // Verify persistence
      const updated = engine.getTask(task.id);
      expect(updated?.status).toBe('interrupted');
    });

    it('handleAgentCancel is idempotent for an already-terminal agent (200, not a 409 dead-end)', () => {
      const task = registerTestAgent({ status: 'completed' });

      const req = { headers: {}, url: '/api/agents/x/cancel' } as any;
      const res = mockRes();
      (dashboard as any).handleAgentCancel(task.id, req, res);

      // A terminal agent is already "cancelled" as far as the operator cares — return
      // success so the UI can proceed to remove it, instead of getting stuck on a 409.
      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body);
      expect(data.cancelled).toBe(true);
      expect(data.already_terminal).toBe(true);
    });

    it('handleAgentCancel still kills the process for an already-terminal agent (zombie reap)', () => {
      // A task can be 'interrupted' in the graph while its OS process is still alive
      // (the stuck case). Cancel must still attempt the kill, not skip it.
      const task = registerTestAgent({ status: 'interrupted' });
      const cancelHeadless = vi.fn(() => true);
      (dashboard as any).attachTaskExecution({ cancelHeadless, isHeadlessAvailable: () => true });
      const req = { headers: {}, url: '/api/agents/x/cancel' } as any;
      const res = mockRes();
      (dashboard as any).handleAgentCancel(task.id, req, res);
      expect(res.statusCode).toBe(200);
      expect(JSON.parse(res.body).already_terminal).toBe(true);
      expect(cancelHeadless).toHaveBeenCalledWith(task.id, expect.any(String));
    });

    it('handleAgentCancel forces a pending agent terminal even without a task-execution service', () => {
      const task = registerTestAgent({ status: 'pending' });
      const req = { headers: {}, url: '/api/agents/x/cancel' } as any;
      const res = mockRes();
      (dashboard as any).handleAgentCancel(task.id, req, res);
      expect(res.statusCode).toBe(200);
      expect(engine.getTask(task.id)?.status).toBe('interrupted');
    });

    it('handleAgentCancel returns 404 for missing task', () => {
      const req = { headers: {}, url: '/api/agents/x/cancel' } as any;
      const res = mockRes();
      (dashboard as any).handleAgentCancel('nonexistent', req, res);
      expect(res.statusCode).toBe(404);
    });
  });

  // ============================================================
  // Campaign REST Endpoints
  // ============================================================

  describe('Campaign REST endpoints', () => {
    function mockRes() {
      return {
        statusCode: 0,
        headers: {} as Record<string, string>,
        body: '' as string,
        writeHead(statusCode: number, headers: Record<string, string>) { this.statusCode = statusCode; this.headers = headers; },
        end(body?: string) { this.body = body || ''; },
        setHeader() {},
      };
    }

    function seedCampaign() {
      // We need frontier items first to create a campaign
      engine.ingestFinding({
        id: 'campaign-seed',
        agent_id: 'test-agent',
        timestamp: new Date().toISOString(),
        nodes: [
          { id: 'host-c-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1' },
          { id: 'svc-c-1', type: 'service', label: 'SMB', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-c-1', target: 'svc-c-1', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      });

      // Get frontier items to use in campaign
      const frontier = engine.computeFrontier();
      const itemIds = frontier.slice(0, 2).map(f => f.id);

      // Manually construct a campaign and inject into the planner
      const campaign: import('../../types.js').Campaign = {
        id: 'campaign-test-1',
        name: 'Test Enumeration',
        strategy: 'enumeration',
        status: 'draft',
        items: itemIds.length > 0 ? itemIds : ['item-1'],
        abort_conditions: [{ type: 'consecutive_failures', threshold: 3 }],
        progress: { total: itemIds.length || 1, completed: 0, succeeded: 0, failed: 0, consecutive_failures: 0 },
        created_at: new Date().toISOString(),
        findings: [],
      };

      // Register campaign directly in graph state
      (engine as any).campaignPlanner.campaigns.set(campaign.id, campaign);
      return campaign;
    }

    it('serveCampaigns returns enriched campaign list', () => {
      const campaign = seedCampaign();

      const res = mockRes();
      (dashboard as any).serveCampaigns(res);

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body);
      expect(data.total).toBeGreaterThanOrEqual(1);
      const found = data.campaigns.find((c: any) => c.id === campaign.id);
      expect(found).toBeDefined();
      expect(found.agent_count).toBe(0);
      expect(found.running_agents).toBe(0);
    });

    it('serveCampaignDetail returns campaign with agents and abort check', () => {
      const campaign = seedCampaign();

      const res = mockRes();
      (dashboard as any).serveCampaignDetail(campaign.id, res);

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body);
      expect(data.campaign.id).toBe(campaign.id);
      expect(data.agents).toEqual([]);
      expect(data.abort_check).toBeDefined();
      expect(data.abort_check.should_abort).toBe(false);
    });

    it('serveCampaignDetail returns 404 for missing campaign', () => {
      const res = mockRes();
      (dashboard as any).serveCampaignDetail('nonexistent', res);
      expect(res.statusCode).toBe(404);
    });

    it('handleCampaignAction activates a draft campaign', async () => {
      const campaign = seedCampaign();

      const bodyStr = JSON.stringify({ action: 'activate' });
      const req = {
        headers: {},
        url: '/api/campaigns/x/action',
        on: vi.fn((event: string, cb: Function) => {
          if (event === 'data') cb(Buffer.from(bodyStr));
          if (event === 'end') cb();
        }),
        destroy: vi.fn(),
      } as any;

      const res = mockRes();
      await (dashboard as any).handleCampaignAction(campaign.id, req, res);

      // Wait for async body reading
      await new Promise(r => setTimeout(r, 10));

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body);
      expect(data.action).toBe('activate');
      expect(data.campaign.status).toBe('active');
    });

    it('handleCampaignAction rejects invalid action', async () => {
      const campaign = seedCampaign();

      const bodyStr = JSON.stringify({ action: 'invalid' });
      const req = {
        headers: {},
        url: '/api/campaigns/x/action',
        on: vi.fn((event: string, cb: Function) => {
          if (event === 'data') cb(Buffer.from(bodyStr));
          if (event === 'end') cb();
        }),
        destroy: vi.fn(),
      } as any;

      const res = mockRes();
      await (dashboard as any).handleCampaignAction(campaign.id, req, res);
      await new Promise(r => setTimeout(r, 10));

      expect(res.statusCode).toBe(400);
    });

    it('handleCampaignDispatch dispatches agents for a campaign', async () => {
      // Need frontier items in the campaign
      engine.ingestFinding({
        id: 'dispatch-seed',
        agent_id: 'test-agent',
        timestamp: new Date().toISOString(),
        nodes: [
          { id: 'host-d-1', type: 'host', label: '10.10.10.2', ip: '10.10.10.2' },
          { id: 'svc-d-1', type: 'service', label: 'SSH', port: 22, service_name: 'ssh' },
        ],
        edges: [
          {
            source: 'host-d-1', target: 'svc-d-1',
            properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() },
          },
        ],
      });

      const frontier = engine.computeFrontier();
      const itemId = frontier[0]?.id || 'fallback-item';

      const campaign: import('../../types.js').Campaign = {
        id: 'campaign-dispatch-1',
        name: 'Dispatch Test',
        strategy: 'enumeration',
        status: 'draft',
        items: [itemId],
        abort_conditions: [],
        progress: { total: 1, completed: 0, succeeded: 0, failed: 0, consecutive_failures: 0 },
        created_at: new Date().toISOString(),
        findings: [],
      };
      (engine as any).campaignPlanner.campaigns.set(campaign.id, campaign);

      const bodyStr = JSON.stringify({});
      const req = {
        headers: {},
        url: '/api/campaigns/x/dispatch',
        on: vi.fn((event: string, cb: Function) => {
          if (event === 'data') cb(Buffer.from(bodyStr));
          if (event === 'end') cb();
        }),
        destroy: vi.fn(),
      } as any;

      const res = mockRes();
      await (dashboard as any).handleCampaignDispatch(campaign.id, req, res);
      await new Promise(r => setTimeout(r, 10));

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body);
      expect(data.campaign_id).toBe(campaign.id);
      expect(data.dispatched.length).toBeGreaterThanOrEqual(0);
    });

    it('replays a legacy persisted campaign-dispatch result with additive aliases absent', async () => {
      vi.spyOn((dashboard as any).dispatchCommands, 'dispatchCampaign').mockReturnValue({
        command_id: 'legacy-campaign-command',
        idempotency_key: 'legacy-campaign-key',
        status: 'succeeded',
        replayed: true,
        result: {
          campaign_id: 'campaign-legacy',
          strategy: 'enumeration',
          requested: 1,
          total_items: 1,
          dispatched: [{
            task_id: 'legacy-task',
            agent_id: 'legacy-label',
            frontier_item_id: 'frontier-legacy',
            scope_nodes: 1,
            archetype: 'recon_scanner',
          }],
          skipped: [],
        },
      });
      const bodyStr = JSON.stringify({});
      const req = {
        headers: {},
        url: '/api/campaigns/campaign-legacy/dispatch',
        on: vi.fn((event: string, cb: Function) => {
          if (event === 'data') cb(Buffer.from(bodyStr));
          if (event === 'end') cb();
        }),
        destroy: vi.fn(),
      } as any;
      const res = mockRes();

      await (dashboard as any).handleCampaignDispatch('campaign-legacy', req, res);
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(res.statusCode).toBe(200);
      expect(JSON.parse(res.body)).toMatchObject({
        command_id: 'legacy-campaign-command',
        replayed: true,
        dispatched: [{ task_id: 'legacy-task', agent_id: 'legacy-label' }],
      });
    });

    it('handleCampaignCreate creates a new campaign via POST', async () => {
      const bodyStr = JSON.stringify({
        name: 'Manual campaign',
        strategy: 'custom',
        item_ids: ['fi-1', 'fi-2'],
        abort_conditions: [{ type: 'consecutive_failures', threshold: 3 }],
      });
      const req = {
        headers: {},
        url: '/api/campaigns',
        on: vi.fn((event: string, cb: Function) => {
          if (event === 'data') cb(Buffer.from(bodyStr));
          if (event === 'end') cb();
        }),
        destroy: vi.fn(),
      } as any;

      const res = mockRes();
      await (dashboard as any).handleCampaignCreate(req, res);
      await new Promise(r => setTimeout(r, 10));

      expect(res.statusCode).toBe(201);
      const data = JSON.parse(res.body);
      expect(data.campaign.name).toBe('Manual campaign');
      expect(data.campaign.strategy).toBe('custom');
      expect(data.campaign.status).toBe('draft');
      expect(data.campaign.items).toEqual(['fi-1', 'fi-2']);
    });

    it('handleCampaignCreate rejects missing name', async () => {
      const bodyStr = JSON.stringify({ strategy: 'custom', item_ids: ['fi-1'] });
      const req = {
        headers: {},
        url: '/api/campaigns',
        on: vi.fn((event: string, cb: Function) => {
          if (event === 'data') cb(Buffer.from(bodyStr));
          if (event === 'end') cb();
        }),
        destroy: vi.fn(),
      } as any;

      const res = mockRes();
      await (dashboard as any).handleCampaignCreate(req, res);
      await new Promise(r => setTimeout(r, 10));

      expect(res.statusCode).toBe(400);
    });

    it('handleCampaignCreate rejects invalid strategy', async () => {
      const bodyStr = JSON.stringify({ name: 'Bad', strategy: 'bogus', item_ids: ['fi-1'] });
      const req = {
        headers: {},
        url: '/api/campaigns',
        on: vi.fn((event: string, cb: Function) => {
          if (event === 'data') cb(Buffer.from(bodyStr));
          if (event === 'end') cb();
        }),
        destroy: vi.fn(),
      } as any;

      const res = mockRes();
      await (dashboard as any).handleCampaignCreate(req, res);
      await new Promise(r => setTimeout(r, 10));

      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).error).toContain('Invalid strategy');
    });

    it('handleCampaignUpdate patches a draft campaign via PATCH', async () => {
      const campaign = seedCampaign();
      const bodyStr = JSON.stringify({ name: 'Updated name', abort_conditions: [{ type: 'time_limit_seconds', threshold: 600 }] });
      const req = {
        headers: {},
        url: `/api/campaigns/${campaign.id}`,
        on: vi.fn((event: string, cb: Function) => {
          if (event === 'data') cb(Buffer.from(bodyStr));
          if (event === 'end') cb();
        }),
        destroy: vi.fn(),
      } as any;

      const res = mockRes();
      await (dashboard as any).handleCampaignUpdate(campaign.id, req, res);
      await new Promise(r => setTimeout(r, 10));

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body);
      expect(data.campaign.name).toBe('Updated name');
      expect(data.campaign.abort_conditions[0].type).toBe('time_limit_seconds');
    });

    it('handleCampaignUpdate returns 409 for active campaign', async () => {
      const campaign = seedCampaign();
      engine.activateCampaign(campaign.id);

      const bodyStr = JSON.stringify({ name: 'Nope' });
      const req = {
        headers: {},
        url: `/api/campaigns/${campaign.id}`,
        on: vi.fn((event: string, cb: Function) => {
          if (event === 'data') cb(Buffer.from(bodyStr));
          if (event === 'end') cb();
        }),
        destroy: vi.fn(),
      } as any;

      const res = mockRes();
      await (dashboard as any).handleCampaignUpdate(campaign.id, req, res);
      await new Promise(r => setTimeout(r, 10));

      expect(res.statusCode).toBe(409);
    });

    it('handleCampaignDelete removes a draft campaign', () => {
      const campaign = seedCampaign();
      const req = { headers: {} } as any;
      const res = mockRes();

      (dashboard as any).handleCampaignDelete(campaign.id, req, res);

      expect(res.statusCode).toBe(200);
      expect(JSON.parse(res.body).deleted).toBe(true);
      expect(engine.getCampaign(campaign.id)).toBeNull();
    });

    it('handleCampaignDelete returns 409 for non-draft campaign', () => {
      const campaign = seedCampaign();
      engine.activateCampaign(campaign.id);

      const req = { headers: {} } as any;
      const res = mockRes();

      (dashboard as any).handleCampaignDelete(campaign.id, req, res);

      expect(res.statusCode).toBe(409);
    });

    it('handleCampaignDelete returns 404 for missing campaign', () => {
      const req = { headers: {} } as any;
      const res = mockRes();

      (dashboard as any).handleCampaignDelete('nonexistent', req, res);

      expect(res.statusCode).toBe(404);
    });

    it('handleCampaignClone duplicates a campaign as draft', () => {
      const campaign = seedCampaign();
      engine.activateCampaign(campaign.id);

      const req = { headers: {} } as any;
      const res = mockRes();

      (dashboard as any).handleCampaignClone(campaign.id, req, res);

      expect(res.statusCode).toBe(201);
      const data = JSON.parse(res.body);
      expect(data.campaign.name).toBe('Test Enumeration (copy)');
      expect(data.campaign.status).toBe('draft');
      expect(data.campaign.id).not.toBe(campaign.id);
    });

    it('handleCampaignClone returns 404 for missing campaign', () => {
      const req = { headers: {} } as any;
      const res = mockRes();

      (dashboard as any).handleCampaignClone('nonexistent', req, res);

      expect(res.statusCode).toBe(404);
    });
  });

  // ============================================================
  // Mutation Auth
  // ============================================================

  describe('Mutation auth', () => {
    it('checkMutationAuth passes on loopback', () => {
      const req = { headers: {}, url: '/' } as any;
      const res = {
        statusCode: 0,
        writeHead(code: number) { this.statusCode = code; },
        end() {},
        setHeader() {},
      };
      const result = (dashboard as any).checkMutationAuth(req, res);
      expect(result).toBe(true);
    });

    it('checkMutationAuth rejects on non-loopback without token', () => {
      // Create dashboard bound to non-loopback
      const nonLocalDashboard = new DashboardServer(engine, 0, '192.168.1.1');
      const req = { headers: {}, url: '/' } as any;
      const res = {
        statusCode: 0,
        body: '',
        writeHead(code: number) { this.statusCode = code; },
        end(b?: string) { this.body = b || ''; },
        setHeader() {},
      };

      const origToken = process.env.OVERWATCH_DASHBOARD_TOKEN;
      delete process.env.OVERWATCH_DASHBOARD_TOKEN;

      const result = (nonLocalDashboard as any).checkMutationAuth(req, res);
      expect(result).toBe(false);
      expect(res.statusCode).toBe(403);

      if (origToken) process.env.OVERWATCH_DASHBOARD_TOKEN = origToken;
    });

    it('checkMutationAuth accepts valid Bearer token', () => {
      const nonLocalDashboard = new DashboardServer(engine, 0, '192.168.1.1');
      const origToken = process.env.OVERWATCH_DASHBOARD_TOKEN;
      process.env.OVERWATCH_DASHBOARD_TOKEN = 'secret-test-token';

      const req = {
        headers: { authorization: 'Bearer secret-test-token', host: 'localhost' },
        url: '/',
      } as any;
      const res = {
        statusCode: 0,
        writeHead(code: number) { this.statusCode = code; },
        end() {},
        setHeader() {},
      };

      const result = (nonLocalDashboard as any).checkMutationAuth(req, res);
      expect(result).toBe(true);

      if (origToken) process.env.OVERWATCH_DASHBOARD_TOKEN = origToken;
      else delete process.env.OVERWATCH_DASHBOARD_TOKEN;
    });

    it.each([
      ['handleCreateEngagement', (d: any, req: any, res: any) => d.handleCreateEngagement(req, res)],
      ['handleUpdateEngagement', (d: any, req: any, res: any) => d.handleUpdateEngagement('eng-1', req, res)],
      ['handleGraphCorrect',     (d: any, req: any, res: any) => d.handleGraphCorrect(req, res)],
    ])('%s rejects unauthenticated non-loopback callers (regression)', async (_name, invoke) => {
      const nonLocalDashboard = new DashboardServer(engine, 0, '192.168.1.1');
      const origToken = process.env.OVERWATCH_DASHBOARD_TOKEN;
      delete process.env.OVERWATCH_DASHBOARD_TOKEN;

      const req = { headers: {}, url: '/', on: vi.fn() } as any;
      const res = {
        statusCode: 0,
        body: '',
        writeHead(code: number) { this.statusCode = code; },
        end(b?: string) { this.body = b || ''; },
        setHeader() {},
      };

      await invoke(nonLocalDashboard, req, res);
      expect(res.statusCode).toBe(403);

      if (origToken) process.env.OVERWATCH_DASHBOARD_TOKEN = origToken;
    });
  });

  // ============================================================
  // HTTP Routing
  // ============================================================

  describe('HTTP routing', () => {
    function mockReq(url: string, method: string = 'GET') {
      return {
        url,
        method,
        headers: { host: 'localhost', origin: '' },
        on: vi.fn(),
        destroy: vi.fn(),
      } as any;
    }

    function mockRes() {
      return {
        statusCode: 0,
        headers: {} as Record<string, string>,
        body: '' as string,
        writeHead(statusCode: number, headers?: Record<string, string>) { this.statusCode = statusCode; if (headers) this.headers = headers; },
        end(body?: string) { this.body = body || ''; },
        setHeader(_k: string, _v: string) { this.headers[_k] = _v; },
      };
    }

    it('routes GET /api/agents to serveAgents', () => {
      const spy = vi.spyOn(dashboard as any, 'serveAgents');
      const req = mockReq('/api/agents');
      const res = mockRes();
      (dashboard as any).handleHttp(req, res);
      expect(spy).toHaveBeenCalled();
    });

    it('routes GET /api/campaigns to serveCampaigns', () => {
      const spy = vi.spyOn(dashboard as any, 'serveCampaigns');
      const req = mockReq('/api/campaigns');
      const res = mockRes();
      (dashboard as any).handleHttp(req, res);
      expect(spy).toHaveBeenCalled();
    });

    it('routes OPTIONS to 204 preflight', () => {
      const req = mockReq('/api/agents', 'OPTIONS');
      const res = mockRes();
      (dashboard as any).handleHttp(req, res);
      expect(res.statusCode).toBe(204);
    });

    it('routes GET /api/campaigns/:id to serveCampaignDetail', () => {
      const spy = vi.spyOn(dashboard as any, 'serveCampaignDetail');
      const req = mockReq('/api/campaigns/abc-123-def');
      const res = mockRes();
      (dashboard as any).handleHttp(req, res);
      expect(spy).toHaveBeenCalledWith('abc-123-def', res);
    });

    it('routes POST /api/agents/:id/cancel to handleAgentCancel', () => {
      const spy = vi.spyOn(dashboard as any, 'handleAgentCancel');
      const req = mockReq('/api/agents/abc-123-def/cancel', 'POST');
      const res = mockRes();
      (dashboard as any).handleHttp(req, res);
      expect(spy).toHaveBeenCalledWith('abc-123-def', req, res);
    });

    it('routes non-uuid agent ids to the agent console endpoint', () => {
      const spy = vi.spyOn(dashboard as any, 'serveAgentConsole');
      const req = mockReq('/api/agents/task-web-1/console?limit=5');
      const res = mockRes();
      (dashboard as any).handleHttp(req, res);
      expect(spy).toHaveBeenCalledWith('task-web-1', '/api/agents/task-web-1/console?limit=5', res);
    });
  });

  // ============================================================
  // Read-side auth & misc dashboard fixes
  // ============================================================

  describe('non-loopback read auth', () => {
    let nlEngine: GraphEngine;
    let nlDashboard: DashboardServer;
    let nlState: string;

    beforeEach(() => {
      nlState = join(testStateDir, 'state-test-dashboard-nl.json');
      nlEngine = trackedEngine(makeConfig({ id: 'test-dashboard-nl' }), nlState);
      nlDashboard = new DashboardServer(nlEngine, 0, '0.0.0.0');
    });

    afterEach(async () => {
      delete process.env.OVERWATCH_DASHBOARD_TOKEN;
      await nlDashboard.stop().catch(() => {});
    });

    function nlReq(url: string, headers: Record<string, string> = {}) {
      return { url, method: 'GET', headers: { host: 'example.com', ...headers }, on: vi.fn(), destroy: vi.fn() } as any;
    }
    function nlRes() {
      return {
        statusCode: 0,
        headers: {} as Record<string, string>,
        body: '',
        writeHead(s: number, h?: Record<string, string>) { this.statusCode = s; if (h) this.headers = h; },
        end(b?: string) { this.body = b || ''; },
        setHeader(_k: string, _v: string) {},
      };
    }

    it('rejects /api/state without token when token is unset', () => {
      delete process.env.OVERWATCH_DASHBOARD_TOKEN;
      const res = nlRes();
      (nlDashboard as any).handleHttp(nlReq('/api/state'), res);
      expect(res.statusCode).toBe(403);
      expect(res.body).not.toContain('engagement');
    });

    it('rejects /api/state with wrong token', () => {
      process.env.OVERWATCH_DASHBOARD_TOKEN = 'right-token';
      const res = nlRes();
      (nlDashboard as any).handleHttp(nlReq('/api/state', { authorization: 'Bearer wrong-token' }), res);
      expect(res.statusCode).toBe(401);
    });

    it('accepts /api/state with correct Bearer token', () => {
      process.env.OVERWATCH_DASHBOARD_TOKEN = 'right-token';
      const res = nlRes();
      (nlDashboard as any).handleHttp(nlReq('/api/state', { authorization: 'Bearer right-token' }), res);
      expect(res.statusCode).toBe(200);
      expect(res.body).toContain('state');
    });

    it('protects the recovery status route with the same remote Bearer policy', () => {
      process.env.OVERWATCH_DASHBOARD_TOKEN = 'right-token';
      const rejected = nlRes();
      (nlDashboard as any).handleHttp(nlReq('/api/recovery'), rejected);
      expect(rejected.statusCode).toBe(401);

      const accepted = nlRes();
      (nlDashboard as any).handleHttp(
        nlReq('/api/recovery', { authorization: 'Bearer right-token' }),
        accepted,
      );
      expect(accepted.statusCode).toBe(200);
      expect(accepted.body).toContain('recovery');
      expect(accepted.headers['Cache-Control']).toBe('no-store');
    });

    it('accepts /api/state with token query param', () => {
      process.env.OVERWATCH_DASHBOARD_TOKEN = 'right-token';
      const res = nlRes();
      (nlDashboard as any).handleHttp(nlReq('/api/state?token=right-token'), res);
      expect(res.statusCode).toBe(200);
    });

    it('authenticates live HTTP/downloads and all three WebSocket channels with same-origin enforcement', async () => {
      const token = 'remote token+/=?';
      process.env.OVERWATCH_DASHBOARD_TOKEN = token;
      const sessionId = '00000000-0000-4000-8000-000000000001';
      const session = {
        id: sessionId,
        kind: 'pty',
        transport: 'pty',
        state: 'connected',
        title: 'Remote shell',
        connection_id: `${sessionId}:g2`,
        connection_generation: 2,
        started_at: '2026-07-16T00:00:00.000Z',
        last_activity_at: '2026-07-16T00:00:00.000Z',
        capabilities: {
          has_stdin: true,
          has_stdout: true,
          supports_resize: true,
          supports_signals: true,
        },
        buffer_end_pos: 0,
      };
      (nlDashboard as any).sessionManager = {
        list: () => [session],
        getSession: (id: string) => id === sessionId ? session : null,
        read: () => ({ text: '', end_pos: 0 }),
        write: vi.fn(), resize: vi.fn(), onEvent: vi.fn(),
      };
      nlEngine.getActionOutputBuffer().open('act-live');
      nlEngine.getActionOutputBuffer().append('act-live', 'stdout', 'live output');

      const started = await nlDashboard.start();
      expect(started.started).toBe(true);
      const port = new URL(nlDashboard.address).port;
      const httpBase = `http://127.0.0.1:${port}`;
      const wsBase = `ws://127.0.0.1:${port}`;
      const origin = httpBase;
      const tokenQuery = new URLSearchParams({ token }).toString();

      const stateResponse = await fetch(`${httpBase}/api/state`, {
        headers: { Authorization: `Bearer ${token}`, Origin: origin },
      });
      expect(stateResponse.status).toBe(200);
      const recoveryResponse = await fetch(`${httpBase}/api/recovery`, {
        headers: { Authorization: `Bearer ${token}`, Origin: origin },
      });
      expect(recoveryResponse.status).toBe(200);
      const reconciliationBody = JSON.stringify({
        resolution: 'use_state',
        expected_file_hash: 'a'.repeat(64),
        expected_state_hash: 'b'.repeat(64),
      });
      const acceptedReconciliation = await fetch(`${httpBase}/api/recovery/config/resolve`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          Origin: origin,
          'Content-Type': 'application/json',
        },
        body: reconciliationBody,
      });
      // There is no divergence in this fixture; 409 proves the request passed
      // both remote Bearer and same-origin gates and reached reconciliation.
      expect(acceptedReconciliation.status).toBe(409);
      const missingTokenReconciliation = await fetch(`${httpBase}/api/recovery/config/resolve`, {
        method: 'POST',
        headers: { Origin: origin, 'Content-Type': 'application/json' },
        body: reconciliationBody,
      });
      expect(missingTokenReconciliation.status).toBe(401);
      const foreignOriginReconciliation = await fetch(`${httpBase}/api/recovery/config/resolve`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          Origin: 'https://foreign.example.test',
          'Content-Type': 'application/json',
        },
        body: reconciliationBody,
      });
      expect(foreignOriginReconciliation.status).toBe(403);
      const bundleResponse = await fetch(`${httpBase}/api/bundle`, {
        headers: { Authorization: `Bearer ${token}`, Origin: origin },
      });
      expect(bundleResponse.status).toBe(200);
      await bundleResponse.body?.cancel();

      const openWithFirstMessage = (path: string, headers: Record<string, string> = { Origin: origin }) => new Promise<{ socket: WebSocket; message: any }>((resolve, reject) => {
        const socket = new WebSocket(`${wsBase}${path}${path.includes('?') ? '&' : '?'}${tokenQuery}`, {
          headers,
        });
        socket.once('message', raw => resolve({ socket, message: JSON.parse(String(raw)) }));
        socket.once('error', reject);
      });
      const main = await openWithFirstMessage('/ws');
      const sessionQuery = new URLSearchParams({
        connection_id: session.connection_id,
        connection_generation: String(session.connection_generation),
      });
      const sessionSocket = await openWithFirstMessage(
        `/ws/session/${sessionId}?${sessionQuery.toString()}`,
      );
      const action = await openWithFirstMessage('/ws/actions/act-live/output');
      expect(main.message.type).toBe('full_state');
      expect(main.message.data.graph.nodes.every((node: any) =>
        typeof node.properties.community_id === 'number'
      )).toBe(true);
      expect(sessionSocket.message.type).toBe('session_meta');
      expect(action.message).toMatchObject({ type: 'output', text: 'live output' });

      const mismatchedGenerationClose = await new Promise<number>((resolve, reject) => {
        const query = new URLSearchParams({
          token,
          connection_id: `${sessionId}:g1`,
          connection_generation: '1',
        });
        const socket = new WebSocket(`${wsBase}/ws/session/${sessionId}?${query.toString()}`, {
          headers: { Origin: origin },
        });
        socket.once('message', () => reject(new Error('stale generation received session output')));
        socket.once('close', code => resolve(code));
        socket.once('error', () => {});
      });
      expect(mismatchedGenerationClose).toBe(4409);

      const remoteHost = `ops.example.test:${port}`;
      const remoteOrigin = `http://${remoteHost}`;
      const remoteMain = await openWithFirstMessage('/ws', { Host: remoteHost, Origin: remoteOrigin });
      expect(remoteMain.message.type).toBe('full_state');

      const rejectedStatus = (url: string, rejectedOrigin: string, host?: string) => new Promise<number>((resolve, reject) => {
        const socket = new WebSocket(url, { headers: { ...(host ? { Host: host } : {}), Origin: rejectedOrigin } });
        socket.once('unexpected-response', (_req, response) => resolve(response.statusCode ?? 0));
        socket.once('open', () => reject(new Error('WebSocket unexpectedly opened')));
        socket.once('error', () => {});
      });
      expect(await rejectedStatus(`${wsBase}/ws?${new URLSearchParams({ token: 'wrong' })}`, origin)).toBe(401);
      expect(await rejectedStatus(`${wsBase}/ws?${tokenQuery}`, 'https://foreign.example.test')).toBe(403);
      expect(await rejectedStatus(`${wsBase}/ws?${tokenQuery}`, `http://foreign.example.test:${port}`, remoteHost)).toBe(403);

      main.socket.close();
      sessionSocket.socket.close();
      action.socket.close();
      remoteMain.socket.close();
    }, 30_000);

    it('does not gate /api/* on loopback binds', () => {
      // dashboard from outer beforeEach is loopback (127.0.0.1)
      const res = {
        statusCode: 0, headers: {} as Record<string, string>, body: '',
        writeHead(s: number, h?: Record<string, string>) { this.statusCode = s; if (h) this.headers = h; },
        end(b?: string) { this.body = b || ''; }, setHeader() {},
      };
      const req = { url: '/api/state', method: 'GET', headers: { host: 'localhost' }, on: vi.fn() } as any;
      delete process.env.OVERWATCH_DASHBOARD_TOKEN;
      (dashboard as any).handleHttp(req, res);
      expect(res.statusCode).toBe(200);
    });
  });

  describe('config validation error reporting', () => {
    it('surfaces validation error message instead of "Invalid JSON body"', async () => {
      const req: any = {
        url: '/api/config/scope',
        method: 'PATCH',
        headers: { host: 'localhost', 'content-type': 'application/json' },
        on(event: string, cb: (chunk?: Buffer) => void) {
          if (event === 'data') cb(Buffer.from(JSON.stringify({ cidrs: ['not-a-cidr', '10.10.10.0/30'] })));
          if (event === 'end') cb();
        },
      };
      const res: any = {
        statusCode: 0, headers: {}, body: '',
        writeHead(s: number, h?: Record<string, string>) { this.statusCode = s; if (h) this.headers = h; },
        end(b?: string) { this.body = b || ''; }, setHeader() {},
      };
      await (dashboard as any).handleUpdateScope(req, res);
      // Allow the readJsonBody promise to resolve
      await new Promise(r => setTimeout(r, 10));
      expect(res.statusCode).toBe(400);
      const payload = JSON.parse(res.body);
      expect(payload.error).toMatch(/CIDR|Scope|Invalid/i);
      expect(payload.error).not.toBe('Invalid JSON body');
    });
  });

  describe('OPSEC payload strict validation (P2 0.5)', () => {
    function patchConfig(body: Record<string, unknown>): Promise<{ status: number; payload: any }> {
      return new Promise(async (resolve) => {
        const req: any = {
          url: '/api/config',
          method: 'PATCH',
          headers: { host: 'localhost', 'content-type': 'application/json' },
          on(event: string, cb: (chunk?: Buffer) => void) {
            if (event === 'data') cb(Buffer.from(JSON.stringify(body)));
            if (event === 'end') cb();
          },
        };
        const res: any = {
          statusCode: 0, headers: {}, body: '',
          writeHead(s: number, h?: Record<string, string>) { this.statusCode = s; if (h) this.headers = h; },
          end(b?: string) { this.body = b || ''; }, setHeader() {},
        };
        await (dashboard as any).handleUpdateConfig(req, res);
        await new Promise(r => setTimeout(r, 10));
        resolve({ status: res.statusCode, payload: JSON.parse(res.body) });
      });
    }

    it('rejects OPSEC payload with the legacy approval_timeout_seconds key (400 + zod error)', async () => {
      const { status, payload } = await patchConfig({ opsec: { approval_timeout_seconds: 60 } });
      expect(status).toBe(400);
      expect(String(payload.error)).toContain('OPSEC validation failed');
      expect(String(payload.error)).toContain('approval_timeout_seconds');
    });

    it('rejects OPSEC payload with legacy time_window {start, end}', async () => {
      const { status, payload } = await patchConfig({ opsec: { time_window: { start: 9, end: 17 } } });
      expect(status).toBe(400);
      expect(String(payload.error)).toContain('OPSEC validation failed');
    });

    it('accepts the canonical keys (approval_timeout_ms + start_hour/end_hour)', async () => {
      const { status, payload } = await patchConfig({
        opsec: {
          approval_timeout_ms: 60_000,
          time_window: { start_hour: 9, end_hour: 17 },
        },
      });
      expect(status).toBe(200);
      expect(payload.updated).toBe(true);
      const cfg = engine.getConfig();
      expect(cfg.opsec.approval_timeout_ms).toBe(60_000);
      expect(cfg.opsec.time_window).toEqual({ start_hour: 9, end_hour: 17 });
    });
  });

  describe('scope updates route through engine.updateScope (P2 0.4)', () => {
    it('emits scope_updated audit event and promotes cold hosts when adding a CIDR', async () => {
      // Seed a cold host outside the current scope (10.20.0.5).
      (engine as any).ctx.coldStore.add({
        id: 'cold:10.20.0.5',
        type: 'host',
        label: '10.20.0.5',
        ip: '10.20.0.5',
        discovered_at: new Date().toISOString(),
        last_seen_at: new Date().toISOString(),
        provenance: 'test-seed',
        confidence: 1.0,
      });

      const req: any = {
        url: '/api/config/scope',
        method: 'PATCH',
        headers: { host: 'localhost', 'content-type': 'application/json' },
        on(event: string, cb: (chunk?: Buffer) => void) {
          if (event === 'data') cb(Buffer.from(JSON.stringify({
            cidrs: ['10.10.10.0/30', '10.20.0.0/24'],
            domains: ['test.local'],
            exclusions: [],
          })));
          if (event === 'end') cb();
        },
      };
      const res: any = {
        statusCode: 0, headers: {}, body: '',
        writeHead(s: number, h?: Record<string, string>) { this.statusCode = s; if (h) this.headers = h; },
        end(b?: string) { this.body = b || ''; }, setHeader() {},
      };
      await (dashboard as any).handleUpdateScope(req, res);
      await new Promise(r => setTimeout(r, 10));

      expect(res.statusCode).toBe(200);
      const payload = JSON.parse(res.body);
      expect(payload.applied).toBe(true);
      // Cold host got promoted into the live graph by the updateScope path.
      expect(payload.affected_node_count).toBeGreaterThanOrEqual(1);
      // scope_updated audit event was emitted.
      const events = engine.getFullHistory().filter(e => e.event_type === 'scope_updated');
      expect(events.length).toBeGreaterThan(0);
      expect((events[events.length - 1].details as any).reason).toContain('dashboard');
    });
  });

  describe('static file decode errors', () => {
    it('returns 400 (not crash) for malformed percent-encoded path', () => {
      const res: any = {
        statusCode: 0, headers: {}, body: '',
        writeHead(s: number, h?: Record<string, string>) { this.statusCode = s; if (h) this.headers = h; },
        end(b?: string) { this.body = b || ''; }, setHeader() {},
      };
      // %E0 is an invalid UTF-8 starter — decodeURIComponent throws URIError.
      // Use a path with an extension so the SPA fallback doesn't rewrite to /index.html.
      expect(() => (dashboard as any).serveStaticFile('/asset-%E0.js', res)).not.toThrow();
      expect(res.statusCode).toBe(400);
    });
  });

  describe('agent history task-link fallback', () => {
    it('serves derived agent console events for a task', () => {
      const taskId = '11111111-1111-1111-1111-111111111111';
      engine.registerAgent({
        id: taskId,
        agent_id: 'sub-recon-1',
        objective: 'Recon',
        subgraph_node_ids: [],
        status: 'running',
        assigned_at: new Date().toISOString(),
      } as any);
      engine.logActionEvent({
        description: 'I will enumerate SMB first.',
        event_type: 'thought',
        category: 'reasoning',
        provenance: 'agent',
        agent_id: 'sub-recon-1',
        details: { kind: 'plan' },
      });

      const res: any = {
        statusCode: 0, headers: {}, body: '',
        writeHead(s: number, h?: Record<string, string>) { this.statusCode = s; if (h) this.headers = h; },
        end(b?: string) { this.body = b || ''; }, setHeader() {},
      };
      (dashboard as any).serveAgentConsole(taskId, `/api/agents/${taskId}/console?limit=10`, res);
      expect(res.statusCode).toBe(200);
      const payload = JSON.parse(res.body);
      expect(payload.events.length).toBeGreaterThan(0);
      expect(payload.events.at(-1).kind).toBe('thought');
      expect(payload.events.at(-1).title).toBe('Plan');
    });

    it('broadcasts live agent console events from activity-only persists', () => {
      const mockClient = {
        readyState: WebSocket.OPEN,
        send: vi.fn(),
        close: vi.fn(),
      };
      (dashboard as any).clients = new Set([mockClient]);

      engine.logActionEvent({
        description: 'Agent decided to test SMB.',
        event_type: 'thought',
        category: 'reasoning',
        provenance: 'agent',
        agent_id: 'sub-recon-1',
        details: { kind: 'decision' },
      });
      engine.persist();

      const messages = mockClient.send.mock.calls.map(call => JSON.parse(call[0]));
      const consoleMessage = messages.find(message => message.type === 'agent_console_update');
      expect(consoleMessage).toBeDefined();
      expect(consoleMessage.data.events[0].kind).toBe('thought');
      expect(consoleMessage.data.events[0].agent_id).toBe('sub-recon-1');
    });

    it('includes events linked by linked_agent_task_id, not just agent_id', () => {
      const taskId = '11111111-1111-1111-1111-111111111111';
      engine.registerAgent({
        id: taskId,
        agent_id: 'sub-recon-1',
        objective: 'Recon',
        subgraph_node_ids: [],
        status: 'running',
        assigned_at: new Date().toISOString(),
      } as any);
      // log an event keyed by task id (linked_agent_task_id) but a *different*
      // agent_id (e.g. event was attributed to primary on behalf of the task)
      engine.logActionEvent({
        description: 'transcript submitted',
        event_type: 'agent_transcript_submitted',
        category: 'agent',
        provenance: 'agent',
        agent_id: 'primary',
        linked_agent_task_id: taskId,
      });
      const res: any = {
        statusCode: 0, headers: {}, body: '',
        writeHead(s: number, h?: Record<string, string>) { this.statusCode = s; if (h) this.headers = h; },
        end(b?: string) { this.body = b || ''; }, setHeader() {},
      };
      (dashboard as any).serveAgentHistory(taskId, res);
      expect(res.statusCode).toBe(200);
      const payload = JSON.parse(res.body);
      const types = payload.entries.map((e: any) => e.event_type);
      expect(types).toContain('agent_transcript_submitted');
    });
  });
});
