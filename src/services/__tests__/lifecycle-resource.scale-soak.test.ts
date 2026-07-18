import { mkdtempSync, rmSync } from 'node:fs';
import { get as httpGet } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { WebSocket } from 'ws';
import type { EngagementConfig } from '../../types.js';
import { DashboardMainWebSocketHub } from '../dashboard-main-ws-hub.js';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';

const roots: string[] = [];
const engines: GraphEngine[] = [];
const TCP_RESOURCES = ['TCPServerWrap', 'TCPSocketWrap'] as const;

function activeResourceCounts(names: readonly string[]): Record<string, number> {
  const counts = Object.fromEntries(names.map(name => [name, 0])) as Record<string, number>;
  for (const resource of process.getActiveResourcesInfo()) {
    if (resource in counts) counts[resource]++;
  }
  return counts;
}

async function expectResourcesAtMost(baseline: Record<string, number>): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const current = activeResourceCounts(Object.keys(baseline));
    if (Object.entries(baseline).every(([name, count]) => current[name] <= count)) return;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  expect(activeResourceCounts(Object.keys(baseline))).toMatchObject(baseline);
}

function getStatus(url: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const request = httpGet(url, { agent: false }, response => {
      response.resume();
      response.once('end', () => resolve(response.statusCode ?? 0));
    });
    request.once('error', reject);
  });
}

function openSynchronizedSocket(url: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    let opened = false;
    let synchronized = false;
    const timeout = setTimeout(() => {
      socket.terminate();
      reject(new Error('dashboard WebSocket did not deliver full_state within five seconds'));
    }, 5_000);
    const finish = () => {
      if (!opened || !synchronized) return;
      clearTimeout(timeout);
      resolve(socket);
    };
    socket.once('open', () => {
      opened = true;
      finish();
    });
    socket.on('message', raw => {
      try {
        if ((JSON.parse(raw.toString()) as { type?: string }).type === 'full_state') {
          synchronized = true;
          finish();
        }
      } catch { /* a malformed message cannot satisfy synchronization */ }
    });
    socket.once('error', error => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

function waitForSocketClose(socket: WebSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    if (socket.readyState === WebSocket.CLOSED) {
      resolve();
      return;
    }
    const timeout = setTimeout(() => reject(new Error('dashboard WebSocket did not close')), 5_000);
    socket.once('close', () => {
      clearTimeout(timeout);
      resolve();
    });
  });
}

function openEngine(): GraphEngine {
  const root = mkdtempSync(join(tmpdir(), 'overwatch-lifecycle-soak-'));
  roots.push(root);
  const config: EngagementConfig = {
    id: 'lifecycle-resource-soak',
    name: 'Lifecycle resource soak',
    created_at: '2026-07-18T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  };
  const engine = new GraphEngine(config, join(root, 'state.json'));
  engines.push(engine);
  return engine;
}

afterEach(() => {
  for (const engine of engines.splice(0)) engine.dispose();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe.sequential('runtime lifecycle resource gate', () => {
  it('releases dashboard listeners and retry timers across repeated start/stop cycles', () => {
    const engine = openEngine();
    const context = (engine as any).ctx;
    const queryStore = engine.getAgentQueryStore() as any;
    const pendingQueue = engine.getPendingActionQueue() as any;
    const baselineUpdates = context.updateCallbacks.length;
    const baselineQueries = queryStore.listeners.size;
    const baselineTimeouts = process.getActiveResourcesInfo()
      .filter(resource => resource === 'Timeout').length;
    const cycles = process.env.OVERWATCH_SOAK_PROFILE === 'extended' ? 250 : 50;

    for (let cycle = 0; cycle < cycles; cycle++) {
      const hub = new DashboardMainWebSocketHub(engine, null, {
        buildState: () => { throw new Error('disposed timer unexpectedly fired'); },
        runtimeBuild: {
          schema_version: 1,
          input_sha256: 'a'.repeat(64),
          runtime_pid: process.pid,
          runtime_started_at: '2026-07-18T00:00:00.000Z',
          runtime_instance_id: '11111111-1111-4111-8111-111111111111',
        },
        debounceMs: 60_000,
      });
      hub.clients = new Set([{ readyState: 1, send() {}, close() {} } as any]);
      hub.onGraphUpdate({ updated_nodes: [`cycle-${cycle}`] });
      expect(context.updateCallbacks.length).toBe(baselineUpdates + 1);
      expect(queryStore.listeners.size).toBe(baselineQueries + 1);
      expect(pendingQueue.eventCallback).not.toBeNull();
      hub.dispose();
      expect(context.updateCallbacks.length).toBe(baselineUpdates);
      expect(queryStore.listeners.size).toBe(baselineQueries);
      expect(pendingQueue.eventCallback).toBeNull();
    }

    const remainingTimeouts = process.getActiveResourcesInfo()
      .filter(resource => resource === 'Timeout').length;
    expect(remainingTimeouts).toBeLessThanOrEqual(baselineTimeouts);
  });

  it('binds and closes the complete HTTP/WS dashboard lifecycle without retaining listeners', async () => {
    const engine = openEngine();
    const context = (engine as any).ctx;
    const queryStore = engine.getAgentQueryStore() as any;
    const pendingQueue = engine.getPendingActionQueue() as any;
    const baselineUpdates = context.updateCallbacks.length;
    const baselineQueries = queryStore.listeners.size;
    const baselineTimeouts = process.getActiveResourcesInfo()
      .filter(resource => resource === 'Timeout').length;
    const baselineTcp = activeResourceCounts(TCP_RESOURCES);
    const cycles = process.env.OVERWATCH_SOAK_PROFILE === 'extended' ? 50 : 10;

    for (let cycle = 0; cycle < cycles; cycle++) {
      const dashboard = new DashboardServer(engine, 0, '127.0.0.1');
      await expect(dashboard.start()).resolves.toEqual({ started: true });
      const socket = await openSynchronizedSocket(
        `${dashboard.address.replace(/^http/, 'ws')}/ws?contract=2`,
      );
      expect(dashboard.clientCount).toBe(1);
      expect(await getStatus(`${dashboard.address}/api/health`)).toBe(200);
      const socketClosed = waitForSocketClose(socket);
      await dashboard.stop();
      await socketClosed;
      expect(dashboard.running).toBe(false);
      expect(dashboard.clientCount).toBe(0);
      expect(context.updateCallbacks.length).toBe(baselineUpdates);
      expect(queryStore.listeners.size).toBe(baselineQueries);
      expect(pendingQueue.eventCallback).toBeNull();
      await expectResourcesAtMost(baselineTcp);
    }

    const remainingTimeouts = process.getActiveResourcesInfo()
      .filter(resource => resource === 'Timeout').length;
    expect(remainingTimeouts).toBeLessThanOrEqual(baselineTimeouts);
    expect(activeResourceCounts(TCP_RESOURCES)).toMatchObject(baselineTcp);
  }, 90_000);
});
