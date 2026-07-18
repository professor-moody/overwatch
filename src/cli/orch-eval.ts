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
// by a cheap default model, Claude's in-flight dollar cap, a command-wide dollar
// ceiling, a per-run turn cap, a token-accounting batch gate, and confirmation.
//
//   npm run orch-eval                              # usage (no spend)
//   npm run orch-eval -- --real --yes              # one real primary run, children fake
//   npm run orch-eval -- --real --trials 3 --budget 600000 --yes

import { fileURLToPath } from 'url';
import { createInterface } from 'readline';
import { runOrchestrationScenario } from '../test-support/eval-run.js';
import type { EvalUsage } from '../test-support/eval-run.js';
import { gradeOrchestration, compareOrchGrades, type OrchRubricResult } from '../services/eval-orchestration-rubric.js';
import { PRIMARY_PROMPT_VARIANTS } from '../services/prompt-generator.js';
import {
  allocateRunBudgetUsd,
  chargeRunBudgetUsd,
  inspectClaudeBudgetCompatibility,
  percentile,
  EST_TOKENS_PER_RUN,
  DEFAULT_MAX_BUDGET_USD,
  DEFAULT_MAX_TOTAL_USD,
  DEFAULT_MODEL,
} from './prompt-eval-lib.js';

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
  maxBudgetUsd: number;
  maxTotalUsd: number;
  maxTurns: number;
  timeoutMs: number;
  /** Candidate primary variant to A/B vs control (e.g. 'contextfirst'); undefined = single-arm calibration. */
  variant?: string;
}

/** NaN-safe arg parsing (a bad --budget must not silently disable the guard). */
export function parseOrchArgs(argv: string[]): OrchArgs {
  const get = (flag: string): string | undefined => { const i = argv.indexOf(flag); return i >= 0 ? argv[i + 1] : undefined; };
  const num = (v: string | undefined, d: number): number => { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : d; };
  const money = (v: string | undefined, d: number): number => {
    if (v === undefined) return d;
    const n = Number(v);
    return Number.isFinite(n) && n >= 0 ? n : d;
  };
  return {
    real: argv.includes('--real'),
    yes: argv.includes('--yes'),
    model: get('--model') ?? DEFAULT_MODEL,
    trials: num(get('--trials'), 1),
    budget: num(get('--budget'), DEFAULT_ORCH_BUDGET),
    maxBudgetUsd: money(get('--max-budget-usd'), DEFAULT_MAX_BUDGET_USD),
    maxTotalUsd: money(get('--max-total-usd'), DEFAULT_MAX_TOTAL_USD),
    maxTurns: num(get('--max-turns'), DEFAULT_ORCH_MAX_TURNS),
    timeoutMs: num(get('--timeout-ms'), DEFAULT_ORCH_TIMEOUT_MS),
    variant: get('--variant'),
  };
}

function formatUsage(usage: EvalUsage): string {
  return `${usage.accountingTokens} accounting tok`
    + ` (input ${usage.inputTokens}, output ${usage.outputTokens},`
    + ` cache-read ${usage.cacheReadInputTokens}, cache-create ${usage.cacheCreationInputTokens})`;
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
  if (grades.length === 0) throw new Error('meanOrchGrade: no trials (an arm ran zero trials — budget too small for the plan)');
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
    npm run orch-eval                                  # this help (no spend)
    npm run orch-eval -- --real [options]              # calibration (control only)
    npm run orch-eval -- --real --variant contextfirst --trials 5 --yes   # A/B

  Options:
    --real              actually run a real-model primary (required to spend)
    --yes               skip the interactive cost confirmation
    --model <id>        primary model (default: ${DEFAULT_MODEL} — cheap)
    --trials N          primary runs per arm (default: 1; A/B wants ~5 — high variance)
    --budget <tokens>   token-accounting batch gate; not an in-flight spend cap (default: ${DEFAULT_ORCH_BUDGET})
    --max-budget-usd N  hard in-flight Claude spend cap per run (default: $${DEFAULT_MAX_BUDGET_USD.toFixed(2)})
    --max-total-usd N   maximum charged/reserved spend for this command (default: $${DEFAULT_MAX_TOTAL_USD.toFixed(2)})
    --max-turns N       per-run turn cap (default: ${DEFAULT_ORCH_MAX_TURNS})
    --timeout-ms N      per-run wall-clock cap (default: ${DEFAULT_ORCH_TIMEOUT_MS})
    --variant <name>    candidate primary prompt to A/B vs control: ${PRIMARY_PROMPT_VARIANTS.filter(v => v !== 'control').join(', ')}

  Children always run fake-claude (cheap). Only the primary spends real tokens.`);
}

async function main(): Promise<void> {
  const args = parseOrchArgs(process.argv.slice(2));
  if (!args.real) { printUsage(); return; }

  if (args.variant) {
    if (!PRIMARY_PROMPT_VARIANTS.includes(args.variant as never)) {
      console.error(`Unknown --variant "${args.variant}". Known: ${PRIMARY_PROMPT_VARIANTS.join(', ')}.`);
      process.exit(1);
    }
    if (args.variant === 'control') { console.error('--variant control is the baseline; pass a candidate (e.g. contextfirst) or omit --variant.'); process.exit(1); }
  }

  const arms = args.variant ? ['control', args.variant] : ['control'];
  const totalRuns = arms.length * args.trials;
  const maximumPossibleUsd = Math.min(totalRuns * args.maxBudgetUsd, args.maxTotalUsd);
  const mode = args.variant ? `A/B "${args.variant}" vs control` : 'control calibration';
  console.log(`Plan: orchestration ${mode} — up to ${totalRuns} real PRIMARY run(s) on "${args.model}" (children fake; ${args.trials}/arm).`);
  console.log(`Cost guard: $${args.maxBudgetUsd.toFixed(2)}/run · $${args.maxTotalUsd.toFixed(2)} command ceiling · maximum possible $${maximumPossibleUsd.toFixed(2)}.`);
  console.log(`Accounting gate: ${args.budget} tok · ${args.maxTurns} turns/run · ${args.timeoutMs}ms/run.`);
  const compatibility = inspectClaudeBudgetCompatibility('claude');
  if (!compatibility.ok) {
    console.error(`Real evaluation refused: ${compatibility.error}. Update Claude Code before using --real.`);
    process.exit(1);
  }
  if (maximumPossibleUsd <= 0) {
    console.error('Real evaluation refused: the configured dollar ceiling permits no run.');
    process.exit(2);
  }
  if (!args.yes) {
    const ok = await confirm(`Proceed with up to ${totalRuns} real primary run(s) (maximum $${maximumPossibleUsd.toFixed(2)}) on "${args.model}"? [y/N] `);
    if (!ok) { console.log('Aborted (pass --yes to skip this prompt).'); process.exit(0); }
  }

  // Token accounting uses an adaptive pre-run gate and is split equally per arm.
  // Dollar allowance is also split so the first arm (control) can't starve the
  // candidate — an A/B with control n=5 / candidate n=2 would be unfair. An arm that
  // exhausts its share BREAKS (keeps its trials) rather than process.exit, so the A/B
  // comparison still prints for whatever each arm completed.
  const budget = { used: 0, chargedUsd: 0, reportedUsd: 0, runs: [] as number[] };
  const perArmBudget = Math.floor(args.budget / arms.length);
  const perArmDollarBudget = args.maxTotalUsd / arms.length;
  const estPerRun = (): number => Math.max(EST_TOKENS_PER_RUN, percentile(budget.runs, 0.75));

  // Run one arm `args.trials` times → mean grade, bounded by its own per-arm budget share.
  const runArm = async (arm: string): Promise<OrchRubricResult> => {
    const grades: OrchRubricResult[] = [];
    let armUsed = 0;
    let armChargedUsd = 0;
    for (let t = 0; t < args.trials; t++) {
      if (armUsed + estPerRun() > perArmBudget) {
        console.error(`\nBUDGET STOP for [${arm}] before trial ${t + 1}: arm used ${armUsed}/${perArmBudget} (of ${args.budget} total); stopping this arm with ${grades.length} trial(s).`);
        break;
      }
      const assignedUsd = Math.min(
        allocateRunBudgetUsd(args.maxBudgetUsd, args.maxTotalUsd, budget.chargedUsd),
        allocateRunBudgetUsd(args.maxBudgetUsd, perArmDollarBudget, armChargedUsd),
      );
      if (assignedUsd <= 0) {
        console.error(`\nDOLLAR STOP for [${arm}] before trial ${t + 1}: arm charged/reserved $${armChargedUsd.toFixed(4)}/$${perArmDollarBudget.toFixed(2)}.`);
        break;
      }
      const res = await runOrchestrationScenario({
        claudeBinary: 'claude',
        model: args.model,
        maxTurns: args.maxTurns,
        maxBudgetUsd: assignedUsd,
        timeoutMs: args.timeoutMs,
        variant: arm,
      });
      armUsed += res.usageTokens;
      budget.used += res.usageTokens;
      budget.runs.push(res.usageTokens);
      const charge = chargeRunBudgetUsd(assignedUsd, res.costUsd);
      armChargedUsd += charge.chargedUsd;
      budget.chargedUsd += charge.chargedUsd;
      if (res.costUsd !== undefined) budget.reportedUsd += res.costUsd;
      const g = gradeOrchestration(res.record);
      grades.push(g);
      const r = res.record;
      console.log(`\n[${arm}] trial ${t + 1}/${args.trials}: ${formatUsage(res.usage)} · $${charge.chargedUsd.toFixed(4)} ${charge.source} · ${r.toolCalls.length} primary tool-calls · ${r.dispatches.length} dispatch(es) [${r.dispatches.map(d => `${d.archetype}${d.matchedFrontier ? '✓' : '✗'}`).join(', ')}] · +${r.newNodeCount} nodes`);
      printGrade(g);
      await res.cleanup();
      if (charge.chargedUsd > assignedUsd + 0.000001) {
        console.error(`Provider cost $${charge.chargedUsd.toFixed(6)} exceeded the assigned $${assignedUsd.toFixed(6)} in-flight cap; stopping.`);
        process.exit(2);
      }
    }
    if (grades.length < args.trials) console.error(`[${arm}] completed ${grades.length}/${args.trials} trials (budget-limited) — interpret the A/B with that asymmetry in mind.`);
    return meanOrchGrade(grades);
  };

  const control = await runArm('control');
  console.log(`\n=== control mean (${args.trials} trials) ===`);
  printGrade(control);

  if (args.variant) {
    const candidate = await runArm(args.variant);
    console.log(`\n=== ${args.variant} mean (${args.trials} trials) ===`);
    printGrade(candidate);
    const cmp = compareOrchGrades(control, candidate);
    const flag = cmp.regressions.length
      ? `REGRESSIONS — ${cmp.regressions.map(r => `${r.criterion} ${r.control.toFixed(2)}→${r.candidate.toFixed(2)}`).join(', ')}`
      : 'no per-criterion regressions';
    console.log(`\nA/B ${args.variant} vs control: overall ${control.overall.toFixed(3)} → ${candidate.overall.toFixed(3)} (Δ ${cmp.delta >= 0 ? '+' : ''}${cmp.delta.toFixed(3)}) · ${flag}`);
  }

  console.log(`\nDone. ${budget.used} accounting tokens (batch gate ${args.budget}) · $${budget.chargedUsd.toFixed(4)} charged/reserved${budget.reportedUsd ? ` ($${budget.reportedUsd.toFixed(4)} provider-reported)` : ''}.`);
}

// Only run when invoked directly (not when imported by a test).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch(err => { console.error(err); process.exit(1); });
}
