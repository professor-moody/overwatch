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

  const tempDir = mkdtempSync(join(tmpdir(), 'ow-prompt-eval-'));
  const logDir = join(tempDir, 'agents');
  const config = parseEngagementConfig(rawConfig);
  const app = createOverwatchApp({
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

  await waitFor(() => { const s = app.engine.getTask(taskId)?.status; return s === 'completed' || s === 'failed' || s === 'interrupted'; }, opts.timeoutMs ?? 20000);

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

  const cleanup = async () => {
    if (prevVariant === undefined) delete process.env.OVERWATCH_PROMPT_VARIANT;
    else process.env.OVERWATCH_PROMPT_VARIANT = prevVariant;
    await shutdownOverwatchApp(app).catch(() => { /* ignore */ });
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  };
  return { record, usageTokens: tokens, costUsd, cleanup };
}
