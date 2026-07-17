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
import { PlaybookRunService } from '../playbook-run-service.js';
import { MainWebSocketEventSchema } from '../../contracts/dashboard-v1.js';

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
  // DashboardServer constructor wires engine.onUpdate automatically.
  const result = await dashboard.start();
  if (!result.started) throw new Error(`dashboard failed to start: ${result.error}`);
  baseUrl = dashboard.address;
  wsBase = baseUrl.replace(/^http/, 'ws');
});

afterAll(async () => {
  // Resolve any approval timers still armed by seedApproval() so a future
  // submit-without-resolve test can't leak a 5-minute handle.
  try { engine.getPendingActionQueue().dispose(); } catch { /* */ }
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
  messages: WsMessage[];
  /** Wait for the first buffered or future message that matches `predicate`. */
  awaitMessage(predicate: (m: WsMessage) => boolean, timeoutMs?: number): Promise<WsMessage>;
  close(): void;
}

function openWs(): Promise<BufferedWs> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${wsBase}/ws`);
    const buffer: WsMessage[] = [];
    const messages: WsMessage[] = [];
    const waiters: Array<{
      predicate: (m: WsMessage) => boolean;
      resolve: (m: WsMessage) => void;
    }> = [];
    ws.on('message', (raw: Buffer) => {
      try {
        const msg = JSON.parse(raw.toString()) as WsMessage;
        messages.push(msg);
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
      messages,
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
      expect(msg.data.runtime_build).toMatchObject({
        input_sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        runtime_pid: process.pid,
      });
      expect(() => MainWebSocketEventSchema.parse(msg)).not.toThrow();
      const state = msg.data.state as Record<string, unknown>;
      // Audit-fix invariants: these were missing/misnamed before the
      // dashboard wiring fix. Pin them so future drifts surface.
      expect(state).toHaveProperty('agents');
      expect(state).toHaveProperty('playbook_runs');
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

  it('includes unresolved runtime ownership in the initial full state', async () => {
    engine.setRuntimeRuns([{
      run_id: 'runtime-ws-warning',
      kind: 'tracked_process',
      daemon_owner: 'daemon-old',
      command_fingerprint: 'a'.repeat(64),
      started_at: NOW,
      completed_at: NOW,
      lifecycle: 'unknown',
      finalization_status: 'unknown',
      recovery_warning: 'PID identity could not be verified.',
    }]);
    const conn = await openWs();
    try {
      const msg = await conn.awaitMessage(m => m.type === 'full_state');
      const state = msg.data.state as {
        persistence_recovery?: {
          runtime_ownership_warnings?: Array<{ run_id: string; message: string }>;
        };
      };
      expect(state.persistence_recovery?.runtime_ownership_warnings).toEqual([
        expect.objectContaining({
          run_id: 'runtime-ws-warning',
          message: 'PID identity could not be verified.',
        }),
      ]);
    } finally {
      conn.close();
      engine.setRuntimeRuns([]);
    }
  }, 5_000);
});

describe('WS durable playbook updates', () => {
  it('pushes owner-aware run changes without waiting for a graph mutation', async () => {
    const conn = await openWs();
    try {
      await conn.awaitMessage(message => message.type === 'full_state');
      const service = new PlaybookRunService(engine);
      const opened = service.open({
        definition: { definition_id: 'ws-playbook', definition_version: 1, provider: 'github', title: 'WS playbook' },
        credential_id: 'cred-test',
        normalized_inputs: {},
        steps: [{ step_id: 'whoami', step: 1, description: 'Resolve identity', runner: 'run_tool', binary: 'gh', args: ['api', '/user'], ready: true, status: 'ready' }],
      });
      const update = await conn.awaitMessage(message =>
        message.type === 'playbook_run_update'
        && (message.data.run as { run_id?: string } | undefined)?.run_id === opened.run.run_id);
      expect(update.data.run).toMatchObject({
        run_id: opened.run.run_id,
        report_status: 'generated',
      });
    } finally {
      conn.close();
    }
  });
});

// =============================================
// graph_update contract
// =============================================

describe('WS graph_update push on mutation', () => {
  it('keeps graph correction on the canonical delta path without a second full state', async () => {
    engine.addNode({
      id: 'graph-correction-ws-node',
      type: 'host',
      label: 'before WS correction',
      ip: '10.0.0.88',
      discovered_at: NOW,
      confidence: 1,
    });
    const conn = await openWs();
    try {
      await conn.awaitMessage(message => message.type === 'full_state');
      const transcriptStart = conn.messages.length;
      const response = await fetch(`${baseUrl}/api/graph/correct`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Overwatch-Command-Id': 'ws-graph-correction-command',
          'Idempotency-Key': 'ws-graph-correction-retry',
        },
        body: JSON.stringify({
          reason: 'prove graph correction keeps the dashboard synchronized',
          operations: [{
            kind: 'patch_node',
            node_id: 'graph-correction-ws-node',
            set_properties: { label: 'after WS correction' },
          }],
        }),
      });
      expect(response.status).toBe(200);

      const update = await conn.awaitMessage(message =>
        message.type === 'graph_update'
        && ((message.data.detail as { updated_nodes?: string[] } | undefined)?.updated_nodes ?? [])
          .includes('graph-correction-ws-node'));
      const delta = update.data.delta as { nodes: Array<{ id: string; properties?: { label?: string } }> };
      expect(delta.nodes).toContainEqual(expect.objectContaining({
        id: 'graph-correction-ws-node',
        properties: expect.objectContaining({ label: 'after WS correction' }),
      }));
      const updateIndex = conn.messages.indexOf(update);
      await conn.awaitMessage(message =>
        message.type === 'state_refresh'
        && conn.messages.indexOf(message) > updateIndex);
      expect(conn.ws.readyState).toBe(WebSocket.OPEN);
      expect(conn.messages.slice(transcriptStart).filter(message => message.type === 'full_state'))
        .toHaveLength(0);

      const replayStart = conn.messages.length;
      const replay = await fetch(`${baseUrl}/api/graph/correct`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Overwatch-Command-Id': 'ws-graph-correction-command',
          'Idempotency-Key': 'ws-graph-correction-retry',
        },
        body: JSON.stringify({
          reason: 'prove graph correction keeps the dashboard synchronized',
          operations: [{
            kind: 'patch_node',
            node_id: 'graph-correction-ws-node',
            set_properties: { label: 'after WS correction' },
          }],
        }),
      });
      expect(replay.status).toBe(200);
      expect(await replay.json()).toMatchObject({ replayed: true });
      dashboard.flush();
      await new Promise(resolve => setImmediate(resolve));
      expect(conn.messages.slice(replayStart).filter(message =>
        message.type === 'full_state' || message.type === 'graph_update'))
        .toHaveLength(0);
    } finally {
      conn.close();
    }
  }, 8_000);

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

// =============================================
// Dashboard approve/deny → action_resolved + durable record
//
// Phase 4b enables in-console (and in-Actions-panel) approve/deny buttons that
// POST /api/actions/:id/approve|deny. The console clears resolved approvals off
// the live `action_resolved` WS push, and the audit trail relies on the durable
// approval record flipping to approved/denied. Pin that the canonical
// resolveApprovalRequest path still fires both, so re-enabling the UI buttons
// can't silently break clear-on-WS or the audit record.
// =============================================

function seedApproval(actionId: string) {
  const action = {
    action_id: actionId,
    technique: 'credential_spray',
    target_node: 'host-jump',
    description: `spray creds (${actionId})`,
    validation_result: 'valid' as const,
    opsec_context: {
      noise_budget_remaining: 0.5,
      global_noise_spent: 0.2,
      recommended_approach: 'normal' as const,
      defensive_signals: [],
    },
  };
  // Durable record (audit trail) + live queue entry (what the dashboard serves
  // and what approve/deny resolves). submit() returns a promise that only
  // settles on resolution — capture it so the test can confirm + so the 5-min
  // timeout timer is cleared when we approve/deny.
  engine.recordApprovalRequest(action);
  const resolved = engine.getPendingActionQueue().submit(action);
  return resolved;
}

// NOTE: the action ids below are `act_<hex>` — the shape `deterministicActionId`
// produces for every nonce-bearing engagement (and the auto-minted nonce makes
// that the norm). The approve/deny route must accept the `act_` underscore; a
// hex-only route class silently 404s real actions, so these ids guard against
// that regression.
describe('WS action_resolved push + durable record on dashboard approve/deny', () => {
  it('approve emits action_resolved and flips the durable record to approved', async () => {
    const conn = await openWs();
    const resolved = seedApproval('act_deadbeef00010002');
    try {
      const res = await fetch(`${baseUrl}/api/actions/act_deadbeef00010002/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notes: 'reviewed in console' }),
      });
      expect(res.status).toBe(200);

      const msg = await conn.awaitMessage(
        m => m.type === 'action_resolved' && (m.data as { action_id?: string }).action_id === 'act_deadbeef00010002',
      );
      expect((msg.data as { status?: string }).status).toBe('approved');

      // The awaiting tool unblocks with the resolution, and the durable audit
      // record reflects the approval + operator notes.
      expect((await resolved).status).toBe('approved');
      const record = engine.getApprovalRequest('act_deadbeef00010002');
      expect(record?.status).toBe('approved');
      expect(record?.operator_notes).toBe('reviewed in console');
    } finally {
      conn.close();
    }
  }, 6_000);

  it('deny emits action_resolved and records the denial reason', async () => {
    const conn = await openWs();
    const resolved = seedApproval('act_deadbeef00020003');
    try {
      const res = await fetch(`${baseUrl}/api/actions/act_deadbeef00020003/deny`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'too noisy for this phase' }),
      });
      expect(res.status).toBe(200);

      const msg = await conn.awaitMessage(
        m => m.type === 'action_resolved' && (m.data as { action_id?: string }).action_id === 'act_deadbeef00020003',
      );
      expect((msg.data as { status?: string }).status).toBe('denied');

      expect((await resolved).status).toBe('denied');
      const record = engine.getApprovalRequest('act_deadbeef00020003');
      expect(record?.status).toBe('denied');
      expect(record?.reason).toBe('too noisy for this phase');
    } finally {
      conn.close();
    }
  }, 6_000);

  it('returns 404 when approving an unknown / already-resolved action', async () => {
    const res = await fetch(`${baseUrl}/api/actions/act_ffffffffffffffff/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(404);
  });
});

describe('request-boundary hardening (CSWSH + crash guard)', () => {
  function tryOpenWs(origin?: string, path = '/ws'): Promise<'open' | 'rejected'> {
    return new Promise((resolve) => {
      const ws = new WebSocket(`${wsBase}${path}`, origin ? { origin } : undefined);
      ws.on('open', () => { ws.close(); resolve('open'); });
      ws.on('error', () => resolve('rejected'));
      ws.on('unexpected-response', () => { try { ws.close(); } catch { /* */ } resolve('rejected'); });
    });
  }

  it('rejects a cross-origin WebSocket handshake (CSWSH), even on loopback', async () => {
    expect(await tryOpenWs('https://evil.example')).toBe('rejected');
  });

  it('allows a same-origin WebSocket handshake', async () => {
    // baseUrl is http://127.0.0.1:<port> → an allowed same-host Origin.
    expect(await tryOpenWs(baseUrl)).toBe('open');
  });

  it('allows a no-Origin (non-browser) WebSocket handshake', async () => {
    expect(await tryOpenWs(undefined)).toBe('open');
  });

  it('rejects WebSocket paths absent from the shared registry', async () => {
    expect(await tryOpenWs(undefined, '/ws/typo')).toBe('rejected');
  });

  it('a malformed %-escape path returns 400 and does NOT crash the server', async () => {
    const res = await fetch(`${baseUrl}/api/engagements/%E0%A4%A`);
    expect(res.status).toBe(400);
    // The daemon must still be serving after the bad request.
    const alive = await fetch(`${baseUrl}/api/state`);
    expect(alive.status).toBe(200);
  });
});
