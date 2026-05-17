import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { WebSocket } from 'ws';
import { execFileSync } from 'child_process';
import { PassThrough } from 'stream';
import { unlinkSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-dashboard.json';

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

function cleanup() {
  for (const f of [TEST_STATE_FILE, TEST_STATE_FILE.replace(/\.json$/, '.journal.jsonl'), './bundle-manifest.json']) {
    try { if (existsSync(f)) unlinkSync(f); } catch {}
  }
}

describe('DashboardServer', () => {
  let engine: GraphEngine;
  let dashboard: DashboardServer;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    dashboard = new DashboardServer(engine, 8384);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await dashboard.stop().catch(() => {});
    cleanup();
  });

  it('reports address property', () => {
    expect(dashboard.address).toBe('http://127.0.0.1:8384');
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
    writeFileSync(journalName, JSON.stringify({
      seq: 1,
      ts: new Date().toISOString(),
      type: 'add_node',
      payload: { props: { id: 'journal-only' } },
    }) + '\n');

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
      expect(listing).toContain('state-test-dashboard.json');
      expect(listing).toContain('state-test-dashboard.journal.jsonl');
      expect(listing).toContain('bundle-manifest.json');
      expect(existsSync('./bundle-manifest.json')).toBe(false);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('onGraphUpdate skips getState/exportGraph with zero clients', () => {
    const getStateSpy = vi.spyOn(engine, 'getState');
    const exportGraphSpy = vi.spyOn(engine, 'exportGraph');

    dashboard.onGraphUpdate({ new_nodes: ['test-node'] });
    dashboard.flush();

    expect(getStateSpy).not.toHaveBeenCalled();
    expect(exportGraphSpy).not.toHaveBeenCalled();
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

    expect(mockClient.send).toHaveBeenCalledTimes(1);
    const payload = JSON.parse(mockClient.send.mock.calls[0][0]);
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

    expect(mockClient.send).toHaveBeenCalledTimes(1);
    const payload = JSON.parse(mockClient.send.mock.calls[0][0]);
    expect(payload.data.delta.removed_nodes).toEqual(['old-alias-node']);
    expect(payload.data.delta.removed_edges).toEqual(['old-alias-edge']);
  });

  it('serveState includes history_count', () => {
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

    expect(mockClient.send).toHaveBeenCalledTimes(1);
    const payload = JSON.parse(mockClient.send.mock.calls[0][0]);
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

  it('stop() clears fileCache', async () => {
    // Populate cache by accessing it directly
    (dashboard as any).fileCache.set('test.html', '<html></html>');
    expect((dashboard as any).fileCache.size).toBe(1);

    await dashboard.stop();
    expect((dashboard as any).fileCache.size).toBe(0);
  });

  it('delta nodes contain fresh community_id after graph topology change', () => {
    const mockClient = {
      readyState: WebSocket.OPEN,
      send: vi.fn(),
      close: vi.fn(),
    };
    (dashboard as any).clients = new Set([mockClient]);

    // Seed two connected hosts so Louvain has edges to work with
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

    expect(mockClient.send).toHaveBeenCalledTimes(1);
    const payload = JSON.parse(mockClient.send.mock.calls[0][0]);
    const deltaNodes = payload.data.delta.nodes;

    // Every delta node should have community_id materialized
    const hostNodes = deltaNodes.filter((n: any) => n.id.startsWith('host-'));
    expect(hostNodes.length).toBe(2);
    for (const node of hostNodes) {
      expect(typeof node.properties.community_id).toBe('number');
    }

    // Both hosts in the same connected component should share community_id
    expect(hostNodes[0].properties.community_id).toBe(hostNodes[1].properties.community_id);
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
      getSession: () => ({ id: 'sess-1', state: 'closed', title: 'Old' }),
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
    const mockMeta = { id: 'sess-1', state: 'connected', title: 'Shell', kind: 'pty' };
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

  it('handleSessionConnection forwards input and resize messages', () => {
    vi.useFakeTimers();
    const mockMeta = { id: 'sess-1', state: 'connected', title: 'Shell', kind: 'pty' };
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

  it('session poller stops and notifies on read error', () => {
    vi.useFakeTimers();
    const mockMeta = { id: 'sess-1', state: 'connected', title: 'Shell', kind: 'pty' };
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

    it('handleAgentCancel returns 409 for completed agent', () => {
      const task = registerTestAgent({ status: 'completed' });

      const req = { headers: {}, url: '/api/agents/x/cancel' } as any;
      const res = mockRes();
      (dashboard as any).handleAgentCancel(task.id, req, res);

      expect(res.statusCode).toBe(409);
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
  });

  // ============================================================
  // Read-side auth & misc dashboard fixes
  // ============================================================

  describe('non-loopback read auth', () => {
    let nlEngine: GraphEngine;
    let nlDashboard: DashboardServer;
    const NL_STATE = './state-test-dashboard-nl.json';

    beforeEach(() => {
      try { if (existsSync(NL_STATE)) unlinkSync(NL_STATE); } catch {}
      nlEngine = new GraphEngine(makeConfig({ id: 'test-dashboard-nl' }), NL_STATE);
      nlDashboard = new DashboardServer(nlEngine, 0, '0.0.0.0');
    });

    afterEach(async () => {
      delete process.env.OVERWATCH_DASHBOARD_TOKEN;
      await nlDashboard.stop().catch(() => {});
      try { if (existsSync(NL_STATE)) unlinkSync(NL_STATE); } catch {}
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

    it('accepts /api/state with token query param', () => {
      process.env.OVERWATCH_DASHBOARD_TOKEN = 'right-token';
      const res = nlRes();
      (nlDashboard as any).handleHttp(nlReq('/api/state?token=right-token'), res);
      expect(res.statusCode).toBe(200);
    });

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
