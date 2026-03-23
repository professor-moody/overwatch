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
    expect(dashboard.address).toBe('http://localhost:8384');
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
