#!/usr/bin/env node
// ============================================================
// Orchestration behavior-eval — Tier-2 on-demand real-model runner. COST-BOUNDED.
// ============================================================
// Runs a REAL `claude` PRIMARY/orchestrator that dispatches FAKE children (cheap),
// and grades the run with the orchestration rubric (gradeOrchestration). This is the
// primary-prompt counterpart to prompt-eval.ts (which evals the SUB-AGENT prompt).
//
// Today it's a single-arm CALIBRATION/shakedown: the primary prompt has no variant
// yet, so there's nothing to A/B — the run validates the harness on a real model and
// shows whether the rubric criteria discriminate (orient/dispatch/synthesize). Move 4
// adds a primary prompt variant + the candidate-vs-control A/B here.
//
// NEVER runs in CI. Spends nothing until invoked with --real, and even then is bounded
// by a cheap default model, a per-run turn cap, a global token budget (adaptive pre-run
// gate + hard post-run stop), a small trial count, and a pre-run estimate + confirm.
//
//   npm run orch-eval                              # usage (no spend)
//   npm run orch-eval -- --real --yes              # one real primary run, children fake
//   npm run orch-eval -- --real --trials 3 --budget 600000 --yes

import { fileURLToPath } from 'url';
import { createInterface } from 'readline';
import { runOrchestrationScenario } from '../test-support/eval-run.js';
import { gradeOrchestration, type OrchRubricResult } from '../services/eval-orchestration-rubric.js';
import { percentile, EST_TOKENS_PER_RUN, DEFAULT_MODEL } from './prompt-eval-lib.js';

// An orchestrator's loop (orient → dispatch several children → synthesize) is heavier
// than a single sub-agent task, so the defaults are larger than prompt-eval's.
export const DEFAULT_ORCH_MAX_TURNS = 24;
export const DEFAULT_ORCH_TIMEOUT_MS = 900_000;   // 15 min — a real dispatch+synthesize loop is long
export const DEFAULT_ORCH_BUDGET = 400_000;       // tokens; cache-read inflates per-run counts

export interface OrchArgs {
  real: boolean;
  yes: boolean;
  model: string;
  trials: number;
  budget: number;
  maxTurns: number;
  timeoutMs: number;
}

/** NaN-safe arg parsing (a bad --budget must not silently disable the guard). */
export function parseOrchArgs(argv: string[]): OrchArgs {
  const get = (flag: string): string | undefined => { const i = argv.indexOf(flag); return i >= 0 ? argv[i + 1] : undefined; };
  const num = (v: string | undefined, d: number): number => { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : d; };
  return {
    real: argv.includes('--real'),
    yes: argv.includes('--yes'),
    model: get('--model') ?? DEFAULT_MODEL,
    trials: num(get('--trials'), 1),
    budget: num(get('--budget'), DEFAULT_ORCH_BUDGET),
    maxTurns: num(get('--max-turns'), DEFAULT_ORCH_MAX_TURNS),
    timeoutMs: num(get('--timeout-ms'), DEFAULT_ORCH_TIMEOUT_MS),
  };
}

function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return Promise.resolve(false);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(res => rl.question(question, ans => { rl.close(); res(/^y(es)?$/i.test(ans.trim())); }));
}

function printGrade(g: OrchRubricResult): void {
  console.log(`    overall ${g.overall.toFixed(3)}`);
  for (const c of g.criteria) console.log(`      ${c.criterion.padEnd(22)} ${c.score.toFixed(2)}  ${c.detail}`);
}

/** Mean of a list of orchestration grades (criteria are in fixed order). */
export function meanOrchGrade(grades: OrchRubricResult[]): OrchRubricResult {
  if (grades.length === 1) return grades[0];
  const n = grades.length;
  const criteria = grades[0].criteria.map((c, i) => ({
    criterion: c.criterion,
    weight: c.weight,
    score: grades.reduce((s, g) => s + g.criteria[i].score, 0) / n,
    detail: 'mean',
  }));
  return { overall: grades.reduce((s, g) => s + g.overall, 0) / n, criteria };
}

function printUsage(): void {
  console.log(`orch-eval — cost-bounded real-model orchestration eval (Tier 2, primary prompt)

  Runs a REAL claude PRIMARY that dispatches FAKE children, grades with the
  orchestration rubric. Single-arm calibration today; Move 4 adds the A/B.

  Usage:
    npm run orch-eval                            # this help (no spend)
    npm run orch-eval -- --real [options]        # run (spends tokens)

  Options:
    --real              actually run a real-model primary (required to spend)
    --yes               skip the interactive cost confirmation
    --model <id>        primary model (default: ${DEFAULT_MODEL} — cheap)
    --trials N          primary runs (default: 1)
    --budget <tokens>   hard token ceiling; aborts before exceeding (default: ${DEFAULT_ORCH_BUDGET})
    --max-turns N       per-run turn cap (default: ${DEFAULT_ORCH_MAX_TURNS})
    --timeout-ms N      per-run wall-clock cap (default: ${DEFAULT_ORCH_TIMEOUT_MS})

  Children always run fake-claude (cheap). Only the primary spends real tokens.`);
}

async function main(): Promise<void> {
  const args = parseOrchArgs(process.argv.slice(2));
  if (!args.real) { printUsage(); return; }

  console.log(`Plan: orchestration calibration — up to ${args.trials} real PRIMARY run(s) on "${args.model}" (children fake).`);
  console.log(`Cost guard: budget ${args.budget} tok · per-run cap ${args.maxTurns} turns · timeout ${args.timeoutMs}ms.`);
  if (!args.yes) {
    const ok = await confirm(`Proceed with up to ${args.trials} real primary run(s) on "${args.model}"? [y/N] `);
    if (!ok) { console.log('Aborted (pass --yes to skip this prompt).'); process.exit(0); }
  }

  // Budget: adaptive pre-run gate (p75 of observed runs, so one runaway can't strand
  // the rest) + a hard post-run stop. A run in flight is bounded only by --max-turns,
  // so total spend can exceed --budget by at most one run.
  const budget = { used: 0, cost: 0, runs: [] as number[] };
  const estPerRun = (): number => Math.max(EST_TOKENS_PER_RUN, percentile(budget.runs, 0.75));

  const grades: OrchRubricResult[] = [];
  for (let t = 0; t < args.trials; t++) {
    if (budget.used + estPerRun() > args.budget) {
      console.error(`\nBUDGET STOP before trial ${t + 1}: ${budget.used}/${args.budget} tokens used; next run would exceed the budget.`);
      process.exit(2);
    }
    const res = await runOrchestrationScenario({ claudeBinary: 'claude', model: args.model, maxTurns: args.maxTurns, timeoutMs: args.timeoutMs });
    budget.used += res.usageTokens;
    budget.runs.push(res.usageTokens);
    if (res.costUsd) budget.cost += res.costUsd;
    const g = gradeOrchestration(res.record);
    grades.push(g);
    // Calibration insight: the raw record tells us whether a real primary actually
    // orients/dispatches/synthesizes (the deferred rubric-threshold questions).
    const r = res.record;
    console.log(`\ntrial ${t + 1}/${args.trials}: ${res.usageTokens} tok · ${r.toolCalls.length} primary tool-calls · ${r.dispatches.length} dispatch(es) [${r.dispatches.map(d => `${d.archetype}${d.matchedFrontier ? '✓' : '✗'}`).join(', ')}] · +${r.newNodeCount} nodes`);
    printGrade(g);
    await res.cleanup();
    if (budget.used >= args.budget) {
      console.error(`\nBUDGET REACHED after trial ${t + 1}: ${budget.used}/${args.budget} tokens used; stopping.`);
      break;
    }
  }

  if (grades.length > 1) {
    console.log(`\nMean over ${grades.length} trials:`);
    printGrade(meanOrchGrade(grades));
  }
  console.log(`\nDone. ${budget.used} tokens used (budget ${args.budget})${budget.cost ? ` · ~$${budget.cost.toFixed(4)}` : ''}.`);
}

// Only run when invoked directly (not when imported by a test).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch(err => { console.error(err); process.exit(1); });
}
