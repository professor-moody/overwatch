// ============================================================
// Prompt behavior-eval — run a scenario + map it to a gradeable RunRecord
// ============================================================
// Boots a real Overwatch app, dispatches one sub-agent for a scenario (fake-claude
// for the deterministic smoke; real `claude` for the on-demand A/B), waits for a
// terminal status, then extracts a RunRecord (tool-call sequence + activity +
// graph delta + status) for the rubric grader, plus token usage for the budget.

import { resolve, join } from 'path';
import { readFileSync, existsSync, mkdtempSync, rmSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { createOverwatchApp, startHttpApp, shutdownOverwatchApp } from '../app.js';
import { parseEngagementConfig } from '../config.js';
import type { AgentTask } from '../types.js';
import type { RunRecord, ToolCall, ActivityLite } from '../services/eval-rubric.js';
import type { OrchRunRecord } from '../services/eval-orchestration-rubric.js';
import { recommendArchetype, isArchetypeId } from '../services/agent-archetypes.js';
import type { EvalScenario } from './eval-scenarios.js';

const FAKE_CLAUDE = resolve('./src/test-support/fake-claude.mjs');
const rawConfig = readFileSync(resolve('./engagement.example.json'), 'utf-8');

export interface EvalRunOptions {
  /** Agent binary. Default fake-claude (deterministic). Pass 'claude' for real. */
  claudeBinary?: string;
  /** Model passed to a real binary via `--model`. */
  model?: string;
  /** Hard turn cap (cost bound for real runs). Default 10. */
  maxTurns?: number;
  /** Sub_agent prompt variant ('control' | 'lean') — the A/B arm. Default 'control'. */
  variant?: string;
  timeoutMs?: number;
}

export interface EvalRunResult {
  record: RunRecord;
  /** Total tokens (input+output) parsed from the agent stream-json, 0 if absent. */
  usageTokens: number;
  /** total_cost_usd from the result event, if the binary reports it. */
  costUsd?: number;
  cleanup: () => Promise<void>;
}

function waitFor(pred: () => boolean, timeoutMs: number): Promise<void> {
  return new Promise((res) => {
    const start = Date.now();
    const tick = () => {
      if (pred() || Date.now() - start > timeoutMs) return res();
      setTimeout(tick, 50);
    };
    tick();
  });
}

/** Extract tool calls from claude/fake-claude stream-json — handles top-level
 *  tool_use lines AND assistant messages with nested content[].tool_use blocks. */
export function extractToolCalls(ndjson: string): ToolCall[] {
  const calls: ToolCall[] = [];
  const pull = (name: unknown, input: unknown) => {
    if (typeof name !== 'string') return;
    const i = (input ?? {}) as Record<string, unknown>;
    calls.push({
      tool: name.replace(/^mcp__overwatch__/, ''),
      action_id: typeof i.action_id === 'string' ? i.action_id : undefined,
      frontier_item_id: typeof i.frontier_item_id === 'string' ? i.frontier_item_id : undefined,
    });
  };
  for (const line of ndjson.split('\n')) {
    const t = line.trim();
    if (!t.startsWith('{')) continue;
    let rec: Record<string, unknown>;
    try { rec = JSON.parse(t); } catch { continue; }
    if (rec.type === 'tool_use' || rec.type === 'tool_call') { pull(rec.name ?? rec.tool_name, rec.input ?? rec.arguments); continue; }
    const msg = (rec.message ?? rec) as Record<string, unknown>;
    const content = msg.content;
    if (Array.isArray(content)) {
      for (const block of content) {
        const b = block as Record<string, unknown>;
        if (b && b.type === 'tool_use') pull(b.name, b.input);
      }
    }
  }
  return calls;
}

/** Best-effort token + cost accounting from the agent stream-json. The final
 *  `result` event carries cumulative usage, while each assistant message carries
 *  its own per-turn usage — so prefer the result total and only SUM per-turn
 *  usages as a fallback (summing both would double-count). */
function parseUsage(ndjson: string): { tokens: number; costUsd?: number } {
  const tokensOf = (u: Record<string, unknown>) => {
    const inT = Number(u.input_tokens ?? 0) + Number(u.cache_read_input_tokens ?? 0) + Number(u.cache_creation_input_tokens ?? 0);
    const outT = Number(u.output_tokens ?? 0);
    return (Number.isFinite(inT) ? inT : 0) + (Number.isFinite(outT) ? outT : 0);
  };
  let resultTokens = 0;
  let summedTokens = 0;
  let costUsd: number | undefined;
  for (const line of ndjson.split('\n')) {
    const t = line.trim();
    if (!t.startsWith('{')) continue;
    let rec: Record<string, unknown>;
    try { rec = JSON.parse(t); } catch { continue; }
    const usage = (rec.usage ?? (rec.message as Record<string, unknown> | undefined)?.usage) as Record<string, unknown> | undefined;
    if (usage) {
      if (rec.type === 'result') resultTokens = tokensOf(usage); // cumulative
      else summedTokens += tokensOf(usage);                      // per-turn fallback
    }
    if (typeof rec.total_cost_usd === 'number') costUsd = rec.total_cost_usd;
  }
  return { tokens: resultTokens || summedTokens, costUsd };
}

export async function runEvalScenario(scenario: EvalScenario, opts: EvalRunOptions = {}): Promise<EvalRunResult> {
  const binary = opts.claudeBinary ?? FAKE_CLAUDE;
  const usingFake = binary === FAKE_CLAUDE;
  if (usingFake) { chmodSync(FAKE_CLAUDE, 0o755); process.env.OVERWATCH_FAKE_MODE = scenario.fakeMode; }
  process.env.OVERWATCH_CLAUDE_BINARY = binary;
  // Selects the sub_agent prompt variant the in-process app's get_system_prompt
  // renders for this run (the A/B arm). The harness is single-process + serial
  // (one app per run, like the FAKE_MODE/binary env above), so an env selector is
  // sufficient; set it explicitly every run, and restore it in cleanup so the
  // arm never leaks into a later in-process get_system_prompt.
  const prevVariant = process.env.OVERWATCH_PROMPT_VARIANT;
  process.env.OVERWATCH_PROMPT_VARIANT = opts.variant ?? 'control';
  // Unattended eval against synthetic/unreachable targets: make tools fail fast
  // (real `claude` picks slow scans like nmap -p- that would otherwise run to the
  // 1-hour default and stall the whole run). Restored in cleanup.
  const prevActionTimeout = process.env.OVERWATCH_DEFAULT_ACTION_TIMEOUT_MS;
  if (!usingFake) process.env.OVERWATCH_DEFAULT_ACTION_TIMEOUT_MS = '20000';

  // Restore the env we mutated above — called from cleanup on success AND from the
  // catch below if anything between here and the return throws (e.g. an HTTP
  // port-bind failure), so a thrown run can't leak its arm/timeout into a later
  // in-process run or test.
  const restoreEnv = () => {
    if (prevVariant === undefined) delete process.env.OVERWATCH_PROMPT_VARIANT;
    else process.env.OVERWATCH_PROMPT_VARIANT = prevVariant;
    if (prevActionTimeout === undefined) delete process.env.OVERWATCH_DEFAULT_ACTION_TIMEOUT_MS;
    else process.env.OVERWATCH_DEFAULT_ACTION_TIMEOUT_MS = prevActionTimeout;
  };

  const tempDir = mkdtempSync(join(tmpdir(), 'ow-prompt-eval-'));
  const logDir = join(tempDir, 'agents');
  let app: ReturnType<typeof createOverwatchApp> | undefined;
  try {
    const config = parseEngagementConfig(rawConfig);
    // Unattended eval: shrink the operator-approval window so a gated run_bash/
    // run_tool auto-resolves in seconds instead of stalling on the 5-min default.
    config.opsec = { ...config.opsec, approval_timeout_ms: 3000 } as typeof config.opsec;
    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath: join(tempDir, `state-${config.id}.json`),
      taskExecution: {
        headless: {
          // Pass the binary through the structured option too (not only the env)
          // so the run doesn't depend on env-mutation ordering.
          claudeBinary: binary,
          logDir,
          maxTurns: opts.maxTurns ?? 10,
          // A real headless `claude -p` has no stdin to answer permission prompts,
          // so it would hang on the first tool call in the default mode. Bypass
          // claude's own gate (Overwatch's approval queue still applies); fake-claude
          // ignores claude flags, so leave it unset there.
          permissionMode: usingFake ? undefined : 'bypassPermissions',
          extraArgs: opts.model ? ['--model', opts.model] : undefined,
        },
      },
    });
    await startHttpApp(app, { port: 0, host: '127.0.0.1' });

    // Seed, capturing the canonical ids the engine assigned (ids canonicalize on
    // ingest, and cold-store nodes never appear in exportGraph until promoted), so
    // the post-run delta is genuinely the agent's work and the scope points at the
    // real seed nodes.
    let seededIds = new Set<string>();
    if (scenario.seedNodes?.length) {
      const ingest = app.engine.ingestFinding({ id: `seed-${scenario.id}`, agent_id: 'seed', timestamp: new Date().toISOString(), nodes: scenario.seedNodes, edges: [] } as never) as { new_nodes?: string[] };
      seededIds = new Set(ingest.new_nodes ?? []);
    }

    const taskId = `eval-${scenario.id}`;
    const agentId = `agent-${scenario.id}`;
    const scopedIds = scenario.scopeSeededNodes ? [...seededIds] : [];
    app.engine.registerAgent({
      id: taskId, agent_id: agentId, assigned_at: new Date().toISOString(), status: 'running',
      subgraph_node_ids: scopedIds, backend: 'headless_mcp', archetype: scenario.archetype,
      objective: scenario.objective,
    } as AgentTask);

    await waitFor(() => { const s = app!.engine.getTask(taskId)?.status; return s === 'completed' || s === 'failed' || s === 'interrupted'; }, opts.timeoutMs ?? 20000);

    const logPath = join(logDir, `${taskId}.ndjson`);
    const ndjson = existsSync(logPath) ? readFileSync(logPath, 'utf-8') : '';
    const { tokens, costUsd } = parseUsage(ndjson);

    // One agent + one seed per run, so "everything except the seed" is the agent's
    // work — robust regardless of how the headless path attributes the agent_id.
    const activity: ActivityLite[] = app.engine.getFullHistory()
      .filter(e => (e as { agent_id?: string }).agent_id !== 'seed')
      .map(e => ({ event_type: (e as { event_type?: string }).event_type, action_id: (e as { action_id?: string }).action_id, frontier_item_id: (e as { frontier_item_id?: string }).frontier_item_id }));

    const newNodeTypes = [...new Set(app.engine.exportGraph().nodes.filter(n => !seededIds.has(n.id)).map(n => n.properties.type as string))];

    const record: RunRecord = {
      toolCalls: extractToolCalls(ndjson),
      activity,
      taskStatus: app.engine.getTask(taskId)?.status ?? 'unknown',
      newNodeTypes,
    };

    const runningApp = app;
    const cleanup = async () => {
      restoreEnv();
      await shutdownOverwatchApp(runningApp).catch(() => { /* ignore */ });
      try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
    };
    return { record, usageTokens: tokens, costUsd, cleanup };
  } catch (err) {
    restoreEnv();
    if (app) await shutdownOverwatchApp(app).catch(() => { /* ignore */ });
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
    throw err;
  }
}

// ============================================================
// Orchestration eval — run a PRIMARY orchestrator (Move 3)
// ============================================================
// Boots an app whose runner default binary is fake-claude (so dispatched children
// are fake + cheap), seeds a multi-frontier graph, and runs ONE orchestrator task.
// The primary's binary overrides to the real `claude` for the A/B (default fake for
// the deterministic plumbing smoke). 'auto' fake mode: the primary (no archetype)
// orchestrates; children (archetype) land type-matched findings. Returns an
// OrchRunRecord for gradeOrchestration().

const ORCH_SEED_NODES: Array<Record<string, unknown>> = [
  { id: 'orch-host-a', type: 'host', label: '10.10.30.1', ip: '10.10.30.1', alive: true },
  { id: 'orch-host-b', type: 'host', label: '10.10.30.2', ip: '10.10.30.2', alive: true },
  { id: 'orch-web', type: 'webapp', label: 'http://10.10.30.3', url: 'http://10.10.30.3' },
  { id: 'orch-cred', type: 'credential', label: 'aws-key-orch', cred_type: 'token', cred_material_kind: 'token' },
];

export interface OrchEvalOptions {
  /** The PRIMARY's binary. Default fake-claude (deterministic smoke); pass 'claude' for the real A/B. */
  claudeBinary?: string;
  model?: string;
  maxTurns?: number;
  variant?: string;
  timeoutMs?: number;
}

export interface OrchEvalResult {
  record: OrchRunRecord;
  usageTokens: number;
  costUsd?: number;
  cleanup: () => Promise<void>;
}

export async function runOrchestrationScenario(opts: OrchEvalOptions = {}): Promise<OrchEvalResult> {
  const primaryBinary = opts.claudeBinary ?? FAKE_CLAUDE;
  const usingFakePrimary = primaryBinary === FAKE_CLAUDE;
  chmodSync(FAKE_CLAUDE, 0o755);

  const prev = {
    mode: process.env.OVERWATCH_FAKE_MODE,
    bin: process.env.OVERWATCH_CLAUDE_BINARY,
    variant: process.env.OVERWATCH_PROMPT_VARIANT,
    primaryVariant: process.env.OVERWATCH_PRIMARY_VARIANT,
    actionTimeout: process.env.OVERWATCH_DEFAULT_ACTION_TIMEOUT_MS,
  };
  // restoreEnv closes over `prev` (captured above) and only RESTORES, so it's safe to
  // define before the mutations — the mutations live inside the try so any throw (incl.
  // mkdtemp/createOverwatchApp) is caught and the env never leaks to a later in-process run.
  const restoreEnv = () => {
    const set = (k: string, v: string | undefined) => { if (v === undefined) delete process.env[k]; else process.env[k] = v; };
    set('OVERWATCH_FAKE_MODE', prev.mode);
    set('OVERWATCH_CLAUDE_BINARY', prev.bin);
    set('OVERWATCH_PROMPT_VARIANT', prev.variant);
    set('OVERWATCH_PRIMARY_VARIANT', prev.primaryVariant);
    set('OVERWATCH_DEFAULT_ACTION_TIMEOUT_MS', prev.actionTimeout);
  };

  let tempDir: string | undefined;
  let app: ReturnType<typeof createOverwatchApp> | undefined;
  try {
    // 'auto': primary (no archetype) orchestrates; children (archetype) land findings.
    // Runner default = fake so dispatched children are cheap; the primary task overrides
    // to the real binary for the A/B.
    process.env.OVERWATCH_FAKE_MODE = 'auto';
    process.env.OVERWATCH_CLAUDE_BINARY = FAKE_CLAUDE;
    // opts.variant drives the PRIMARY prompt (the thing under test). Children are fake
    // and never read a prompt, so the sub_agent variant is irrelevant here — pin it to
    // 'control' for determinism and route the A/B arm to the primary seam.
    process.env.OVERWATCH_PROMPT_VARIANT = 'control';
    process.env.OVERWATCH_PRIMARY_VARIANT = opts.variant ?? 'control';
    if (!usingFakePrimary) process.env.OVERWATCH_DEFAULT_ACTION_TIMEOUT_MS = '20000';

    tempDir = mkdtempSync(join(tmpdir(), 'ow-orch-eval-'));
    const logDir = join(tempDir, 'agents');
    const config = parseEngagementConfig(rawConfig);
    config.opsec = { ...config.opsec, approval_timeout_ms: 3000 } as typeof config.opsec;
    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath: join(tempDir, `state-${config.id}.json`),
      taskExecution: {
        headless: {
          claudeBinary: FAKE_CLAUDE,
          logDir,
          maxTurns: opts.maxTurns ?? 14,
          permissionMode: usingFakePrimary ? undefined : 'bypassPermissions',
          extraArgs: opts.model ? ['--model', opts.model] : undefined,
        },
      },
    });
    await startHttpApp(app, { port: 0, host: '127.0.0.1' });

    app.engine.ingestFinding({ id: 'seed-orch', agent_id: 'seed', timestamp: new Date().toISOString(), nodes: ORCH_SEED_NODES, edges: [] } as never);
    const beforeCount = app.engine.exportGraph().nodes.length;

    const taskId = 'eval-orch';
    app.engine.registerAgent({
      id: taskId, agent_id: 'agent-orch', assigned_at: new Date().toISOString(), status: 'running',
      subgraph_node_ids: [], backend: 'headless_mcp', orchestrator: true, claudeBinary: primaryBinary,
      objective: 'Manage the engagement: score the frontier, dispatch the right agents, synthesize findings, progress the objectives.',
    } as AgentTask);

    const deadline = opts.timeoutMs ?? (usingFakePrimary ? 30000 : 600000);
    await waitFor(() => { const s = app!.engine.getTask(taskId)?.status; return s === 'completed' || s === 'failed' || s === 'interrupted'; }, deadline);
    // Settle: wait until no headless process is active AND no child task is still
    // non-terminal. The second clause matters because a child dispatched past the
    // concurrency cap is queued (non-terminal) but not yet a running process, so
    // activeHeadlessCount() alone would read 0 and we'd grade before it lands.
    // Load-bearing invariant: register_agent launches children SYNCHRONOUSLY (engine
    // fireUpdateCallbacks → drainHeadless → registry.register), so by the time the
    // primary flips to a terminal status its dispatched children are already
    // registered here — if that launch path ever becomes async, add an explicit
    // "saw >=1 child" gate or this can return before children attach.
    const childrenSettled = () => app!.taskExecution.activeHeadlessCount() === 0
      && app!.engine.getAgentTasks().every(t => t.id === taskId || ['completed', 'failed', 'interrupted'].includes(t.status));
    await waitFor(childrenSettled, Math.min(deadline, 60000));

    const logPath = join(logDir, `${taskId}.ndjson`);
    const ndjson = existsSync(logPath) ? readFileSync(logPath, 'utf-8') : '';
    const { tokens, costUsd } = parseUsage(ndjson);
    const toolCalls = extractToolCalls(ndjson).map(c => ({ tool: c.tool }));

    // Dispatched children = every agent task other than the primary. (Children
    // registered via register_agent carry no persisted `backend` — it resolves to
    // headless at runtime when an endpoint is set — so don't filter on it.)
    const children = app.engine.getAgentTasks().filter(t => t.id !== taskId);
    const dispatches = children.map(c => {
      // Best-effort: did the child's archetype match what the production dispatch
      // resolver (resolveDispatchArchetype → recommendArchetype{frontierType,nodeType})
      // would pick for its frontier item? The frontier is RE-RESOLVED here at grading
      // time, so if the item has since been satisfied/dropped we fall back to "is a
      // typed (non-default) archetype" — the orchestrator did pick a real specialty.
      let matchedFrontier = !!c.archetype && isArchetypeId(c.archetype) && c.archetype !== 'default';
      if (c.frontier_item_id) {
        const fi = app!.engine.getFrontierItem(c.frontier_item_id);
        if (fi) {
          const nodeType = fi.node_id ? app!.engine.getNode(fi.node_id)?.type : undefined;
          matchedFrontier = c.archetype === recommendArchetype({ frontierType: fi.type, nodeType });
        }
      }
      return { archetype: c.archetype ?? 'default', matchedFrontier, target: c.frontier_item_id };
    });

    // newNodeCount = graph delta over the run. In the fake smoke the only post-seed
    // writer is the dispatched child, so this == children's findings; for a REAL
    // primary it also counts nodes the primary lands directly — i.e. it measures
    // "the engagement graph advanced", not "children specifically progressed it".
    // Orchestration-specific credit comes from the dispatch criteria, not this one.
    const afterCount = app.engine.exportGraph().nodes.length;
    const record: OrchRunRecord = { toolCalls, dispatches, newNodeCount: Math.max(0, afterCount - beforeCount) };

    const captured = { app, tempDir };
    const cleanup = async () => {
      restoreEnv();
      await shutdownOverwatchApp(captured.app).catch(() => { /* ignore */ });
      try { rmSync(captured.tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
    };
    return { record, usageTokens: tokens, costUsd, cleanup };
  } catch (err) {
    restoreEnv();
    if (app) await shutdownOverwatchApp(app).catch(() => { /* ignore */ });
    if (tempDir) { try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ } }
    throw err;
  }
}
