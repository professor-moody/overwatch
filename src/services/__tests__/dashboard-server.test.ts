import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig } from '../../types.js';
import { WebSocket } from 'ws';
import { createServer } from 'http';
import { unlinkSync, existsSync } from 'fs';

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
  // Clean up snapshots
  try {
    const { readdirSync } = require('fs');
    for (const f of readdirSync('.')) {
      if (f.startsWith('state-test-dashboard.snap-')) {
        try { unlinkSync(f); } catch {}
      }
    }
  } catch {}
}

describe('DashboardServer', () => {
  let engine: GraphEngine;
  let dashboard: DashboardServer;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
  });

  afterEach(async () => {
    if (dashboard) {
      await dashboard.stop();
    }
    cleanup();
  });

  it('start() returns { started: true } and sets running', async () => {
    dashboard = new DashboardServer(engine, 0); // ephemeral port
    const result = await dashboard.start();
    expect(result.started).toBe(true);
    expect(result.error).toBeUndefined();
    expect(dashboard.running).toBe(true);
  });

  it('start() returns { started: false } when port is occupied', async () => {
    // Occupy a port first
    const blocker = createServer();
    const blockerPort = await new Promise<number>((resolve) => {
      blocker.listen(0, () => {
        const addr = blocker.address();
        resolve(typeof addr === 'object' ? addr!.port : 0);
      });
    });

    try {
      dashboard = new DashboardServer(engine, blockerPort);
      const result = await dashboard.start();
      expect(result.started).toBe(false);
      expect(result.error).toBeDefined();
      expect(dashboard.running).toBe(false);
    } finally {
      blocker.close();
    }
  });

  it('serves HTML on GET /', async () => {
    dashboard = new DashboardServer(engine, 0);
    const result = await dashboard.start();
    expect(result.started).toBe(true);

    const res = await fetch(`${dashboard.address}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    const html = await res.text();
    expect(html).toContain('OVERWATCH');
    expect(html).toContain('sigma');
  });

  it('serves state JSON on GET /api/state', async () => {
    dashboard = new DashboardServer(engine, 0);
    await dashboard.start();

    const res = await fetch(`${dashboard.address}/api/state`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/json');
    const data = await res.json();
    expect(data.state).toBeDefined();
    expect(data.state.config).toBeDefined();
    expect(data.graph).toBeDefined();
    expect(data.graph.nodes).toBeInstanceOf(Array);
    expect(data.graph.edges).toBeInstanceOf(Array);
  });

  it('serves graph JSON on GET /api/graph', async () => {
    dashboard = new DashboardServer(engine, 0);
    await dashboard.start();

    const res = await fetch(`${dashboard.address}/api/graph`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.nodes).toBeInstanceOf(Array);
    expect(data.edges).toBeInstanceOf(Array);
    expect(data.nodes.length).toBeGreaterThan(0);
  });

  it('returns 404 for unknown paths', async () => {
    dashboard = new DashboardServer(engine, 0);
    await dashboard.start();

    const res = await fetch(`${dashboard.address}/unknown`);
    expect(res.status).toBe(404);
  });

  it('sends full_state on WebSocket connect', async () => {
    dashboard = new DashboardServer(engine, 0);
    await dashboard.start();

    const msg = await new Promise<any>((resolve, reject) => {
      const ws = new WebSocket(dashboard.address.replace('http', 'ws'));
      ws.on('message', (data) => {
        ws.close();
        resolve(JSON.parse(data.toString()));
      });
      ws.on('error', reject);
      setTimeout(() => { ws.close(); reject(new Error('timeout')); }, 3000);
    });

    expect(msg.type).toBe('full_state');
    expect(msg.data.state).toBeDefined();
    expect(msg.data.graph).toBeDefined();
    expect(msg.timestamp).toBeDefined();
  });

  it('broadcasts graph_update on engine persist', async () => {
    dashboard = new DashboardServer(engine, 0);
    await dashboard.start();
    engine.onUpdate((detail) => dashboard.onGraphUpdate(detail));

    // Connect WS and wait for initial full_state
    const ws = new WebSocket(dashboard.address.replace('http', 'ws'));
    await new Promise<void>((resolve, reject) => {
      ws.on('message', () => resolve()); // first message = full_state
      ws.on('error', reject);
      setTimeout(() => reject(new Error('timeout')), 3000);
    });

    // Now ingest a finding — this triggers persist() → onUpdate → broadcast
    const updatePromise = new Promise<any>((resolve, reject) => {
      ws.on('message', (data) => {
        ws.close();
        resolve(JSON.parse(data.toString()));
      });
      setTimeout(() => { ws.close(); reject(new Error('timeout')); }, 3000);
    });

    engine.ingestFinding({
      id: 'finding-test-1',
      timestamp: new Date().toISOString(),
      agent_id: 'test-agent',
      nodes: [
        { id: 'svc-test-1', type: 'service', label: 'SMB on 10.10.10.1', port: 445, service_name: 'smb' },
      ],
      edges: [
        { source: 'host-10-10-10-1', target: 'svc-test-1', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
      ],
    });

    const msg = await updatePromise;
    expect(msg.type).toBe('graph_update');
    expect(msg.data.delta.nodes.length).toBeGreaterThan(0);
  });

  it('tracks client count', async () => {
    dashboard = new DashboardServer(engine, 0);
    await dashboard.start();
    expect(dashboard.clientCount).toBe(0);

    const ws = new WebSocket(dashboard.address.replace('http', 'ws'));
    await new Promise<void>((resolve) => { ws.on('open', resolve); });
    expect(dashboard.clientCount).toBe(1);

    ws.close();
    // Wait for close to propagate
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
    expect(dashboard.clientCount).toBe(0);
  });

  it('onGraphUpdate skips getState/exportGraph with zero clients', async () => {
    dashboard = new DashboardServer(engine, 0);
    await dashboard.start();

    const getStateSpy = vi.spyOn(engine, 'getState');
    const exportGraphSpy = vi.spyOn(engine, 'exportGraph');

    // No WS clients connected — onGraphUpdate should short-circuit
    dashboard.onGraphUpdate({ new_nodes: ['test-node'] });

    expect(getStateSpy).not.toHaveBeenCalled();
    expect(exportGraphSpy).not.toHaveBeenCalled();

    getStateSpy.mockRestore();
    exportGraphSpy.mockRestore();
  });

  it('full_state payload has data.graph with nodes and edges', async () => {
    dashboard = new DashboardServer(engine, 0);
    await dashboard.start();

    const msg = await new Promise<any>((resolve, reject) => {
      const ws = new WebSocket(dashboard.address.replace('http', 'ws'));
      ws.on('message', (data) => {
        ws.close();
        resolve(JSON.parse(data.toString()));
      });
      ws.on('error', reject);
      setTimeout(() => { ws.close(); reject(new Error('timeout')); }, 3000);
    });

    expect(msg.type).toBe('full_state');
    expect(msg.data.graph).toBeDefined();
    expect(msg.data.graph.nodes).toBeInstanceOf(Array);
    expect(msg.data.graph.edges).toBeInstanceOf(Array);
    expect(msg.data.graph.nodes.length).toBeGreaterThan(0);
  });

  it('graph_update payload has data.delta with nodes and edges arrays', async () => {
    dashboard = new DashboardServer(engine, 0);
    await dashboard.start();
    engine.onUpdate((detail) => dashboard.onGraphUpdate(detail));

    const ws = new WebSocket(dashboard.address.replace('http', 'ws'));
    await new Promise<void>((resolve, reject) => {
      ws.on('message', () => resolve());
      ws.on('error', reject);
      setTimeout(() => reject(new Error('timeout')), 3000);
    });

    const updatePromise = new Promise<any>((resolve, reject) => {
      ws.on('message', (data) => {
        ws.close();
        resolve(JSON.parse(data.toString()));
      });
      setTimeout(() => { ws.close(); reject(new Error('timeout')); }, 3000);
    });

    engine.ingestFinding({
      id: 'finding-contract-1',
      timestamp: new Date().toISOString(),
      agent_id: 'test-agent',
      nodes: [
        { id: 'svc-contract-1', type: 'service', label: 'Contract test', port: 80, service_name: 'http' },
      ],
      edges: [
        { source: 'host-10-10-10-1', target: 'svc-contract-1', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
      ],
    });

    const msg = await updatePromise;
    expect(msg.type).toBe('graph_update');
    expect(msg.data.delta).toBeDefined();
    expect(msg.data.delta.nodes).toBeInstanceOf(Array);
    expect(msg.data.delta.edges).toBeInstanceOf(Array);
    expect(msg.data.state).toBeDefined();
  });

  it('graph_update delta includes updated nodes when properties change', async () => {
    dashboard = new DashboardServer(engine, 0);
    await dashboard.start();
    engine.onUpdate((detail) => dashboard.onGraphUpdate(detail));

    const ws = new WebSocket(dashboard.address.replace('http', 'ws'));
    await new Promise<void>((resolve, reject) => {
      ws.on('message', () => resolve());
      ws.on('error', reject);
      setTimeout(() => reject(new Error('timeout')), 3000);
    });

    const updatePromise = new Promise<any>((resolve, reject) => {
      ws.on('message', (data) => {
        ws.close();
        resolve(JSON.parse(data.toString()));
      });
      setTimeout(() => { ws.close(); reject(new Error('timeout')); }, 3000);
    });

    // Update existing host with OS info — should appear in delta
    engine.ingestFinding({
      id: 'finding-update-1',
      timestamp: new Date().toISOString(),
      agent_id: 'test-agent',
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true, os: 'Windows Server 2022' },
      ],
      edges: [],
    });

    const msg = await updatePromise;
    expect(msg.type).toBe('graph_update');
    const deltaNodeIds = msg.data.delta.nodes.map((n: any) => n.id);
    expect(deltaNodeIds).toContain('host-10-10-10-1');
  });

  it('reports address property', () => {
    dashboard = new DashboardServer(engine, 8384);
    expect(dashboard.address).toBe('http://localhost:8384');
  });
});
