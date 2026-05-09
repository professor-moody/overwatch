// ============================================================
// Dashboard WebSocket push contract test.
//
// Companion to dashboard-api-integration.test.ts (HTTP). The dashboard
// pushes graph updates over WS in three message types:
//   - `full_state` on connect: { state, graph, history_count }
//   - `graph_update` on debounced mutation: { state, history_count,
//     detail, delta }
//   - `action_pending` / `action_resolved` on approval-queue events
//
// The frontend's ws-provider routes these into the engagement store.
// A drift in either direction (backend renames a field, frontend
// expects a different shape) silently strands the dashboard. This
// test boots a real DashboardServer + WS client, drives mutations
// through the engine, and asserts payload shapes pin against the
// audit-fix contract (state.agents, state.sessions, graph_summary
// nested keys, etc.).
// ============================================================

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, unlinkSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { WebSocket } from 'ws';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig } from '../../types.js';

let dashboard: DashboardServer;
let engine: GraphEngine;
let baseUrl: string;
let wsBase: string;
let tempDir: string;
let stateFile: string;

const NOW = '2026-05-09T00:00:00Z';

function makeConfig(): EngagementConfig {
  return {
    id: 'ws-integration',
    name: 'WS Integration',
    created_at: NOW,
    scope: { cidrs: ['10.0.0.0/24'], domains: ['acme.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, enabled: true },
  } as EngagementConfig;
}

function seed(eng: GraphEngine) {
  eng.addNode({
    id: 'host-jump', type: 'host',
    label: 'jumpbox.acme.local', ip: '10.0.0.5',
    discovered_at: NOW, confidence: 1.0,
  } as never);
  eng.addNode({
    id: 'cred-test', type: 'credential',
    label: 'test-cred', cred_type: 'token',
    cred_material_kind: 'oidc_access_token',
    credential_status: 'active',
    cred_token_expires_at: '2099-01-01T00:00:00Z',
    discovered_at: NOW, confidence: 1.0,
  } as never);
  // Trigger inference once so cross-tier-inference has a chance to
  // emit any inferred edges before the WS test starts.
  eng.ingestFinding({
    id: 'seed-trigger', agent_id: 'ws-seed', timestamp: NOW,
    nodes: [], edges: [],
  });
}

beforeAll(async () => {
  tempDir = mkdtempSync(join(tmpdir(), 'overwatch-ws-'));
  stateFile = join(tempDir, 'state.json');
  engine = new GraphEngine(makeConfig(), stateFile);
  seed(engine);
  dashboard = new DashboardServer(engine, 0, '127.0.0.1', undefined, undefined);
  // app.ts wires this in production; do it manually here so engine
  // mutations actually trigger dashboard graph_update pushes.
  engine.onUpdate(detail => dashboard.onGraphUpdate(detail));
  const result = await dashboard.start();
  if (!result.started) throw new Error(`dashboard failed to start: ${result.error}`);
  baseUrl = dashboard.address;
  wsBase = baseUrl.replace(/^http/, 'ws');
});

afterAll(async () => {
  await dashboard.stop().catch(() => {});
  if (existsSync(stateFile)) try { unlinkSync(stateFile); } catch { /* */ }
  if (tempDir && existsSync(tempDir)) try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* */ }
});

interface WsMessage {
  type: string;
  timestamp: string;
  data: Record<string, unknown>;
}

/**
 * Open a WS and immediately attach a message buffer. The server sends
 * `full_state` synchronously on connection-handler invocation, which
 * can land before a post-`open` listener registers — buffering avoids
 * the race.
 */
interface BufferedWs {
  ws: WebSocket;
  /** Wait for the first buffered or future message that matches `predicate`. */
  awaitMessage(predicate: (m: WsMessage) => boolean, timeoutMs?: number): Promise<WsMessage>;
  close(): void;
}

function openWs(): Promise<BufferedWs> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${wsBase}/ws`);
    const buffer: WsMessage[] = [];
    const waiters: Array<{
      predicate: (m: WsMessage) => boolean;
      resolve: (m: WsMessage) => void;
    }> = [];
    ws.on('message', (raw: Buffer) => {
      try {
        const msg = JSON.parse(raw.toString()) as WsMessage;
        // Drain any waiter whose predicate matches.
        for (let i = 0; i < waiters.length; i++) {
          if (waiters[i].predicate(msg)) {
            const w = waiters.splice(i, 1)[0];
            w.resolve(msg);
            return;
          }
        }
        buffer.push(msg);
      } catch { /* ignore parse errors */ }
    });

    function awaitMessage(predicate: (m: WsMessage) => boolean, timeoutMs = 4000): Promise<WsMessage> {
      // Drain the buffer first.
      for (let i = 0; i < buffer.length; i++) {
        if (predicate(buffer[i])) {
          const m = buffer.splice(i, 1)[0];
          return Promise.resolve(m);
        }
      }
      return new Promise<WsMessage>((res, rej) => {
        const entry = { predicate, resolve: res };
        waiters.push(entry);
        setTimeout(() => {
          const idx = waiters.indexOf(entry);
          if (idx >= 0) {
            waiters.splice(idx, 1);
            rej(new Error(`WS message matching predicate not received within ${timeoutMs}ms`));
          }
        }, timeoutMs);
      });
    }

    ws.once('open', () => resolve({
      ws,
      awaitMessage,
      close: () => ws.close(),
    }));
    ws.once('error', reject);
  });
}

// =============================================
// full_state contract
// =============================================

describe('WS full_state push on connect', () => {
  it('sends a full_state message with state, graph, history_count', async () => {
    const conn = await openWs();
    try {
      const msg = await conn.awaitMessage(m => m.type === 'full_state');
      expect(msg.data).toHaveProperty('state');
      expect(msg.data).toHaveProperty('graph');
      expect(msg.data).toHaveProperty('history_count');
      const state = msg.data.state as Record<string, unknown>;
      // Audit-fix invariants: these were missing/misnamed before the
      // dashboard wiring fix. Pin them so future drifts surface.
      expect(state).toHaveProperty('agents');
      expect(state).toHaveProperty('sessions');
      expect(state).toHaveProperty('graph_summary');
      const summary = state.graph_summary as Record<string, unknown>;
      expect(summary).toHaveProperty('nodes_by_type');
      // graph payload contains the seeded host + credential.
      const graph = msg.data.graph as { nodes: Array<{ id: string }>; edges: unknown[] };
      const ids = graph.nodes.map(n => n.id);
      expect(ids).toContain('host-jump');
      expect(ids).toContain('cred-test');
    } finally {
      conn.close();
    }
  }, 5_000);

  it('lab_readiness shape matches what the frontend re-keys to readiness', async () => {
    const conn = await openWs();
    try {
      const msg = await conn.awaitMessage(m => m.type === 'full_state');
      const state = msg.data.state as { lab_readiness?: { status: string; top_issues: string[] } };
      // Server emits lab_readiness with `top_issues`; the engagement
      // store re-keys it to readiness.{status, issues}. If the server
      // shape drifts, the store mapping silently breaks.
      if (state.lab_readiness) {
        expect(state.lab_readiness).toHaveProperty('status');
        expect(state.lab_readiness).toHaveProperty('top_issues');
        expect(Array.isArray(state.lab_readiness.top_issues)).toBe(true);
      }
    } finally {
      conn.close();
    }
  }, 5_000);
});

// =============================================
// graph_update contract
// =============================================

describe('WS graph_update push on mutation', () => {
  it('debounce-pushes a graph_update with state, delta, detail when nodes change', async () => {
    const conn = await openWs();
    try {
      // Drain the initial full_state so the next message we wait for
      // is the upcoming graph_update.
      await conn.awaitMessage(m => m.type === 'full_state');

      // Trigger a mutation. ingestFinding fires the engine's
      // graph-update accumulator → the dashboard debounces by 500ms.
      engine.ingestFinding({
        id: `ws-trigger-${Date.now()}`,
        agent_id: 'ws-test',
        timestamp: new Date().toISOString(),
        nodes: [{
          id: 'cred-new',
          type: 'credential',
          label: 'newly-added',
          cred_type: 'token',
          cred_material_kind: 'oidc_access_token',
          credential_status: 'active',
          cred_token_expires_at: '2099-01-01T00:00:00Z',
          discovered_at: new Date().toISOString(),
          confidence: 1.0,
        }],
        edges: [],
      });

      const msg = await conn.awaitMessage(m => m.type === 'graph_update', 4_000);
      expect(msg.data).toHaveProperty('state');
      expect(msg.data).toHaveProperty('history_count');
      expect(msg.data).toHaveProperty('detail');
      expect(msg.data).toHaveProperty('delta');

      const delta = msg.data.delta as { nodes: Array<{ id: string }>; edges: unknown[]; removed_nodes: string[]; removed_edges: string[] };
      expect(Array.isArray(delta.nodes)).toBe(true);
      expect(Array.isArray(delta.edges)).toBe(true);
      // The new credential should be in the delta (the panel uses delta
      // to merge into the cached graph rather than re-fetching).
      expect(delta.nodes.some(n => n.id === 'cred-new')).toBe(true);

      // State payload still carries the audit-fix keys.
      const state = msg.data.state as Record<string, unknown>;
      expect(state).toHaveProperty('agents');
      expect(state).toHaveProperty('sessions');
    } finally {
      conn.close();
    }
  }, 6_000);

  it('detail block names which nodes/edges were touched', async () => {
    const conn = await openWs();
    try {
      await conn.awaitMessage(m => m.type === 'full_state');

      engine.ingestFinding({
        id: `ws-detail-${Date.now()}`,
        agent_id: 'ws-test',
        timestamp: new Date().toISOString(),
        nodes: [{
          id: 'cred-detail',
          type: 'credential',
          label: 'detail-cred',
          cred_type: 'token',
          cred_material_kind: 'pat',
          credential_status: 'active',
          discovered_at: new Date().toISOString(),
          confidence: 1.0,
        }],
        edges: [],
      });

      const msg = await conn.awaitMessage(m => m.type === 'graph_update', 4_000);
      const detail = msg.data.detail as { new_nodes?: string[]; updated_nodes?: string[] };
      // Either new_nodes or updated_nodes should reference the new id.
      const referenced = [
        ...(detail.new_nodes ?? []),
        ...(detail.updated_nodes ?? []),
      ];
      expect(referenced).toContain('cred-detail');
    } finally {
      conn.close();
    }
  }, 6_000);
});

// =============================================
// state field stability across pushes
// =============================================

describe('WS state-payload stability', () => {
  it('full_state and graph_update emit the same top-level state keys', async () => {
    const conn = await openWs();
    try {
      const fullState = await conn.awaitMessage(m => m.type === 'full_state');
      engine.ingestFinding({
        id: `ws-stability-${Date.now()}`,
        agent_id: 'ws-test',
        timestamp: new Date().toISOString(),
        nodes: [{ id: 'cred-stab', type: 'credential', label: 's',
          cred_type: 'token', cred_material_kind: 'pat',
          credential_status: 'active',
          discovered_at: new Date().toISOString(), confidence: 1.0,
        }],
        edges: [],
      });
      const update = await conn.awaitMessage(m => m.type === 'graph_update', 4_000);

      const fullKeys = Object.keys((fullState.data.state as Record<string, unknown>) ?? {}).sort();
      const updateKeys = Object.keys((update.data.state as Record<string, unknown>) ?? {}).sort();
      // Pin: both pushes carry the same set of state fields. Drift
      // here breaks panels that read off the store after reconnects.
      expect(updateKeys).toEqual(fullKeys);
    } finally {
      conn.close();
    }
  }, 6_000);
});
