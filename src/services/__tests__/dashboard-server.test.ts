import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { WebSocket } from 'ws';
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
  for (const f of [TEST_STATE_FILE]) {
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

  it('serveHistory limit returns oldest entries first (forward pagination)', () => {
    for (let i = 0; i < 5; i++) {
      engine.ingestFinding({
        id: `order-test-${i}`,
        agent_id: 'test-agent',
        timestamp: `2026-03-21T10:0${i}:00Z`,
        nodes: [{ id: `host-order-${i}`, type: 'host', label: `10.10.10.${i}`, ip: `10.10.10.${i}` }],
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
    const page1 = JSON.parse(res.body);
    expect(page1.entries.length).toBe(2);
    // First page should be the oldest entries
    const firstTs = page1.entries[0].timestamp;
    const lastTs = page1.entries[page1.entries.length - 1].timestamp;
    expect(firstTs <= lastTs).toBe(true);

    // Second page using after= should return the next entries, not be empty
    (dashboard as any).serveHistory(`/api/history?limit=2&after=${lastTs}`, res);
    const page2 = JSON.parse(res.body);
    expect(page2.entries.length).toBeGreaterThan(0);
    // All page2 entries should be newer than page1's last entry
    for (const entry of page2.entries) {
      expect(entry.timestamp > lastTs).toBe(true);
    }
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
    expect(typeof payload.data.state.history_count).toBe('number');
    expect(payload.data.state.history_count).toBeGreaterThan(0);
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
    (dashboard as any).serveStaticFile('/index.html', res);

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
});
