// ============================================================
// Live action-output WS bridge test (/ws/actions/:id/output).
// Boots a real DashboardServer, drives the engine's ActionOutputBuffer
// directly (standing in for a running process's tee), connects a WS
// client, and asserts incremental output frames + the action_done
// terminal frame. Mirrors dashboard-ws-integration.test.ts.
// ============================================================

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { WebSocket } from 'ws';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig } from '../../types.js';

let dashboard: DashboardServer;
let engine: GraphEngine;
let wsBase: string;
let tempDir: string;

function makeConfig(): EngagementConfig {
  return {
    id: 'action-ws',
    name: 'Action WS',
    created_at: '2026-05-09T00:00:00Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, enabled: true },
  } as EngagementConfig;
}

interface Frame { type: string; stream?: string; text?: string; end_pos?: number; dropped?: boolean }

function openClient(url: string): { ws: WebSocket; msgs: Frame[] } {
  const ws = new WebSocket(url);
  const msgs: Frame[] = [];
  ws.on('message', (d) => { try { msgs.push(JSON.parse(d.toString())); } catch { /* ignore */ } });
  return { ws, msgs };
}

async function waitUntil(fn: () => boolean, timeout = 3000): Promise<void> {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (fn()) return;
    await new Promise(r => setTimeout(r, 20));
  }
  throw new Error('timeout waiting for condition');
}

function awaitOpen(ws: WebSocket): Promise<void> {
  return new Promise((resolve, reject) => { ws.on('open', () => resolve()); ws.on('error', reject); });
}

function closeClient(ws: WebSocket): Promise<void> {
  if (ws.readyState === WebSocket.CLOSED) return Promise.resolve();
  return new Promise((resolve) => {
    ws.once('close', () => resolve());
    ws.close();
  });
}

beforeAll(async () => {
  tempDir = mkdtempSync(join(tmpdir(), 'overwatch-actionws-'));
  engine = new GraphEngine(makeConfig(), join(tempDir, 'state.json'));
  dashboard = new DashboardServer(engine, 0, '127.0.0.1');
  const result = await dashboard.start();
  if (!result.started) throw new Error(`dashboard failed to start: ${result.error}`);
  wsBase = dashboard.address.replace(/^http/, 'ws');
});

afterAll(async () => {
  await dashboard.stop().catch(() => {});
  engine.dispose();
  rmSync(tempDir, { recursive: true, force: true });
});

describe('/ws/actions/:id/output', () => {
  it('streams incremental stdout/stderr and a terminal action_done', async () => {
    const buf = engine.getActionOutputBuffer();
    buf.open('act_live1');
    buf.append('act_live1', 'stdout', 'line1\n');

    const { ws, msgs } = openClient(`${wsBase}/ws/actions/act_live1/output`);
    await awaitOpen(ws);

    // initial flush carries what was buffered before connect
    await waitUntil(() => msgs.some(m => m.type === 'output' && m.stream === 'stdout' && (m.text || '').includes('line1')));

    // post-connect appends arrive incrementally
    buf.append('act_live1', 'stdout', 'line2\n');
    await waitUntil(() => msgs.some(m => m.stream === 'stdout' && (m.text || '').includes('line2')));

    buf.append('act_live1', 'stderr', 'oops\n');
    await waitUntil(() => msgs.some(m => m.stream === 'stderr' && (m.text || '').includes('oops')));

    // finishing the action yields action_done
    buf.markDone('act_live1');
    await waitUntil(() => msgs.some(m => m.type === 'action_done'));

    expect(msgs.some(m => m.stream === 'stdout' && (m.text || '').includes('line1'))).toBe(true);
    expect(msgs.some(m => m.stream === 'stderr' && (m.text || '').includes('oops'))).toBe(true);
    expect(msgs.some(m => m.type === 'action_done')).toBe(true);
    await closeClient(ws);
  });

  it('sends action_done immediately for an unknown/evicted action', async () => {
    const { ws, msgs } = openClient(`${wsBase}/ws/actions/act_unknown/output`);
    await awaitOpen(ws);
    await waitUntil(() => msgs.some(m => m.type === 'action_done'));
    expect(msgs.some(m => m.type === 'action_done')).toBe(true);
    await closeClient(ws);
  });
});
