// Reusable fixture for agent-capability evals: boot a real Overwatch HTTP app
// with the fake-claude binary, dispatch a single archetype task in a chosen
// fake mode, wait for it to finish, and hand back the engine for assertions.
// Factors the headless-runner integration boilerplate so a per-archetype eval
// is ~one call + a few assertions. The full agent path runs (bootstrap prompt →
// archetype allowlist → MCP tools → report_finding → graph mutation → close),
// so this regression-tests *capability*, not mocks.

import { resolve, join } from 'path';
import { readFileSync, mkdtempSync, rmSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { createOverwatchApp, startHttpApp, shutdownOverwatchApp, type OverwatchApp } from '../app.js';
import { parseEngagementConfig } from '../config.js';
import type { AdapterHandle, AgentTask } from '../types.js';
import type { SessionAdapterFactory } from '../services/session-manager.js';

/** A no-op local_pty adapter — registering it overrides the real LocalPtyAdapter
 *  so seeding a session never spawns node-pty (avoids the known CI flake) while
 *  still exercising the real SessionManager.create path. */
function mockPtyAdapter(): SessionAdapterFactory {
  const handle: AdapterHandle = {
    pid: 4242,
    capabilities: { has_stdin: true, has_stdout: true, supports_resize: true, supports_signals: true, tty_quality: 'full' },
    write() { /* discard */ },
    resize() { /* no-op */ },
    kill() { /* no-op */ },
    close() { /* no-op */ },
    onData() { /* no buffer activity needed for the eval */ },
    onExit() { /* never exits during the eval */ },
  };
  return { kind: 'local_pty', async spawn() { return handle; } };
}

const FAKE_CLAUDE = resolve('./src/test-support/fake-claude.mjs');
const rawConfig = readFileSync(resolve('./engagement.example.json'), 'utf-8');

export function waitFor(pred: () => boolean, timeoutMs = 15000): Promise<void> {
  return new Promise((res, rej) => {
    const start = Date.now();
    const tick = () => {
      if (pred()) return res();
      if (Date.now() - start > timeoutMs) return rej(new Error('waitFor timed out'));
      setTimeout(tick, 50);
    };
    tick();
  });
}

export interface ArchetypeEvalResult {
  app: OverwatchApp;
  task: AgentTask | null;
  cleanup: () => Promise<void>;
}

/**
 * Dispatch one archetype task driven by fake-claude in `fakeMode` and wait for a
 * terminal status. Returns the live app (for graph/finding assertions) + a
 * cleanup. Sets the fake-claude env globally — call serially within a file.
 */
export async function runArchetype(opts: {
  archetype: string;
  fakeMode: string;
  seedNodes?: Array<Record<string, unknown>>;
  /** Seed one open session (via a mock local_pty adapter) before dispatch — for
   *  session_shepherd, which has no tool to open sessions itself. */
  seedSession?: boolean;
  /** Scope the dispatched agent's subgraph to the seeded nodes (canonical ids) —
   *  for archetypes that READ their subgraph (e.g. cve_researcher finding its
   *  assigned service). Default false → scope-wide/empty subgraph. */
  scopeSeededNodes?: boolean;
  timeoutMs?: number;
}): Promise<ArchetypeEvalResult> {
  chmodSync(FAKE_CLAUDE, 0o755);
  process.env.OVERWATCH_CLAUDE_BINARY = FAKE_CLAUDE;
  process.env.OVERWATCH_FAKE_MODE = opts.fakeMode;

  const tempDir = mkdtempSync(join(tmpdir(), 'ow-archetype-eval-'));
  const config = parseEngagementConfig(rawConfig);
  const app = createOverwatchApp({
    config,
    skillDir: resolve('./skills'),
    dashboardPort: 0,
    stateFilePath: join(tempDir, `state-${config.id}.json`),
  });
  await startHttpApp(app, { port: 0, host: '127.0.0.1' });

  let seededNodeIds: string[] = [];
  if (opts.seedNodes?.length) {
    const ingest = app.engine.ingestFinding({
      id: `seed-${opts.archetype}`, agent_id: 'seed', timestamp: new Date().toISOString(),
      nodes: opts.seedNodes, edges: [],
    } as never);
    // Node ids canonicalize on ingest; capture the actual stored ids for scoping.
    seededNodeIds = (ingest as { new_nodes?: string[] }).new_nodes ?? [];
  }

  if (opts.seedSession) {
    app.sessionManager.registerAdapter(mockPtyAdapter());
    await app.sessionManager.create({ kind: 'local_pty', title: `eval-seed-${opts.archetype}` });
  }

  const taskId = `eval-${opts.archetype}`;
  app.engine.registerAgent({
    id: taskId,
    agent_id: `agent-${opts.archetype}`,
    assigned_at: new Date().toISOString(),
    status: 'running',
    subgraph_node_ids: opts.scopeSeededNodes ? seededNodeIds : [],
    backend: 'headless_mcp',
    archetype: opts.archetype,
  } as AgentTask);

  await waitFor(
    () => { const s = app.engine.getTask(taskId)?.status; return s === 'completed' || s === 'failed' || s === 'interrupted'; },
    opts.timeoutMs ?? 15000,
  ).catch(() => { /* leave the terminal-status assertion to the test */ });

  const cleanup = async () => {
    await shutdownOverwatchApp(app).catch(() => { /* ignore */ });
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  };
  return { app, task: app.engine.getTask(taskId), cleanup };
}
