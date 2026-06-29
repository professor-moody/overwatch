#!/usr/bin/env node
// ============================================================
// Prompt behavior-eval — Tier-2 on-demand real-model runner. COST-BOUNDED.
// ============================================================
// Runs real `claude` sub-agents on the tiny scenario set, grades each with the
// deterministic rubric, and establishes/caches a control baseline per
// (scenario × model). When prompt step (b) adds a candidate prompt variant, the
// same machinery A/Bs candidate-vs-control and flags regressions (compareGrades).
//
// NEVER runs in CI. Spends nothing until invoked with --real, and even then is
// bounded by: a cheap default model, a per-run turn cap, a global token budget
// enforced as an adaptive pre-run gate PLUS a hard post-run stop (so overshoot is
// bounded by one run's --max-turns cost), tiny defaults, a pre-run estimate +
// confirmation, and a baseline cache so iterating doesn't repay for control.
//
//   npm run prompt-eval                       # usage (no spend)
//   npm run prompt-eval -- --real --yes       # establish/refresh control baselines
//   npm run prompt-eval -- --real --scenarios recon --trials 1 --budget 20000 --yes

import { mkdirSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { createInterface } from 'readline';
import { runEvalScenario } from '../test-support/eval-run.js';
import { gradeRun, type RubricResult } from '../services/eval-rubric.js';
import { EVAL_SCENARIOS } from '../test-support/eval-scenarios.js';
import {
  parseArgs, readBaseline, meanGrade, baselinePath,
  BASELINE_DIR, EST_TOKENS_PER_RUN, DEFAULT_MODEL, DEFAULT_TRIALS, DEFAULT_BUDGET, DEFAULT_MAX_TURNS,
} from './prompt-eval-lib.js';

function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return Promise.resolve(false);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(res => rl.question(question, ans => { rl.close(); res(/^y(es)?$/i.test(ans.trim())); }));
}

function printGrade(label: string, g: RubricResult): void {
  console.log(`  ${label}: overall ${g.overall.toFixed(3)}`);
  for (const c of g.criteria) console.log(`      ${c.criterion.padEnd(26)} ${c.score.toFixed(2)}`);
}

function printUsage(): void {
  console.log(`prompt-eval — cost-bounded real-model behavior eval (Tier 2)

  Establishes/caches a control baseline per (scenario × model) by running real
  claude sub-agents and grading them with the deterministic rubric.

  Usage:
    npm run prompt-eval                                  # this help (no spend)
    npm run prompt-eval -- --real [options]              # run (spends tokens)

  Options:
    --real                 actually run real-model sub-agents (required to spend)
    --yes                  skip the interactive cost confirmation
    --scenarios a,b        subset of: ${EVAL_SCENARIOS.map(s => s.id).join(', ')} (default: all)
    --model <id>           agent model (default: ${DEFAULT_MODEL} — cheap)
    --trials N             trials per cell (default: ${DEFAULT_TRIALS})
    --budget <tokens>      hard token ceiling; aborts before exceeding (default: ${DEFAULT_BUDGET})
    --max-turns N          per-run turn cap (default: ${DEFAULT_MAX_TURNS})
    --refresh-baseline     re-run + overwrite cached control baselines
    --variant <name>       candidate prompt to A/B vs control (requires prompt step (b))

  Cost controls: cheap default model, per-run turn cap, global token budget that
  aborts BEFORE an over-budget run, baseline cache (don't repay for control).`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (!args.real) { printUsage(); return; }
  if (!args.scenarios.length) { console.error('No matching scenarios. Known: ' + EVAL_SCENARIOS.map(s => s.id).join(', ')); process.exit(1); }

  if (args.variant) {
    console.error(`--variant "${args.variant}": candidate prompt variants require prompt step (b)'s variant seam, which is not built yet.`);
    console.error('Run without --variant to establish/refresh the control baseline now; the A/B activates when step (b) lands.');
    process.exit(1);
  }

  // needsControl + the per-scenario decision below both use readBaseline, so the
  // planned run count matches what actually executes (a corrupt cache counts as
  // "needs a run", consistently).
  const needsControl = args.scenarios.filter(s => args.refreshBaseline || !readBaseline(baselinePath(s.id, args.model)));
  const controlRuns = needsControl.length * args.trials;
  const estTokens = controlRuns * EST_TOKENS_PER_RUN;

  console.log(`Plan: ${controlRuns} real-model run(s) on model "${args.model}" (${needsControl.length} scenario(s) × ${args.trials} trial(s)).`);
  console.log(`Cost guard: budget ${args.budget} tok · rough est ~${estTokens} tok · per-run cap ${args.maxTurns} turns.`);
  if (!needsControl.length) console.log('All requested baselines are cached — nothing to run (use --refresh-baseline to re-run).');

  if (controlRuns > 0 && !args.yes) {
    const ok = await confirm(`Proceed with up to ${controlRuns} real-model runs (rough est ~${estTokens} tokens) on "${args.model}"? [y/N] `);
    if (!ok) { console.log('Aborted (pass --yes to skip this prompt).'); process.exit(0); }
  }

  let usedTokens = 0;
  let usedCostUsd = 0;
  let maxRunSeen = 0;
  // The budget is enforced two ways: a pre-run gate that adapts its per-run
  // estimate up to the heaviest run seen so far (so after one heavy run it stops
  // optimistically launching more), and a hard post-run stop the moment ACTUAL
  // cumulative spend reaches the budget. A run already in flight is bounded only
  // by --max-turns, so total spend can exceed --budget by at most one run.
  const estPerRun = () => Math.max(EST_TOKENS_PER_RUN, maxRunSeen);
  const wouldExceed = () => usedTokens + estPerRun() > args.budget;

  for (const scenario of args.scenarios) {
    const path = baselinePath(scenario.id, args.model);
    const cached = args.refreshBaseline ? null : readBaseline(path);
    if (cached) {
      console.log(`\n[${scenario.id}] cached baseline:`);
      printGrade('control', cached);
      continue;
    }

    const grades: RubricResult[] = [];
    for (let t = 0; t < args.trials; t++) {
      if (wouldExceed()) {
        console.error(`\nBUDGET STOP before [${scenario.id}] trial ${t + 1}: ${usedTokens}/${args.budget} tokens used; next run (est ~${estPerRun()}) would exceed the budget.`);
        process.exit(2);
      }
      const run = await runEvalScenario(scenario, { claudeBinary: 'claude', model: args.model, maxTurns: args.maxTurns });
      usedTokens += run.usageTokens;
      maxRunSeen = Math.max(maxRunSeen, run.usageTokens);
      if (run.costUsd) usedCostUsd += run.costUsd;
      const grade = gradeRun(run.record, scenario.rubric);
      grades.push(grade);
      await run.cleanup();
      console.log(`[${scenario.id}] trial ${t + 1}/${args.trials}: overall ${grade.overall.toFixed(3)} · ${run.usageTokens} tok · status ${run.record.taskStatus}`);
      if (usedTokens >= args.budget) {
        console.error(`\nBUDGET REACHED after [${scenario.id}] trial ${t + 1}: ${usedTokens}/${args.budget} tokens used; stopping (no baseline cached for this scenario).`);
        process.exit(2);
      }
    }

    const baseline = meanGrade(grades);
    mkdirSync(BASELINE_DIR, { recursive: true });
    writeFileSync(path, JSON.stringify({ scenario: scenario.id, model: args.model, trials: args.trials, grade: baseline }, null, 2) + '\n');
    console.log(`[${scenario.id}] cached baseline → ${path}`);
    printGrade('control (mean)', baseline);
  }

  console.log(`\nDone. ${usedTokens} tokens used (budget ${args.budget})${usedCostUsd ? ` · ~$${usedCostUsd.toFixed(4)}` : ''}.`);
}

// Only run when invoked directly (not when imported by a test).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch(err => { console.error(err); process.exit(1); });
}
