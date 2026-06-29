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
import { gradeRun, compareGrades, RUBRIC_CRITERIA, type RubricResult } from '../services/eval-rubric.js';
import { SUBAGENT_PROMPT_VARIANTS } from '../services/prompt-generator.js';
import { EVAL_SCENARIOS } from '../test-support/eval-scenarios.js';
import {
  parseArgs, readBaseline, isBaselineUsable, meanGrade, baselinePath,
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

  // --variant selects the candidate arm to A/B against control. 'control' itself
  // is the baseline, not a candidate.
  const variant = args.variant;
  if (variant) {
    if (!SUBAGENT_PROMPT_VARIANTS.includes(variant as never)) {
      console.error(`Unknown --variant "${variant}". Known: ${SUBAGENT_PROMPT_VARIANTS.join(', ')}.`);
      process.exit(1);
    }
    if (variant === 'control') { console.error('--variant control is the baseline; pass a candidate variant (e.g. lean) or omit --variant.'); process.exit(1); }
  }

  // A cached control is reused only if it's A/B-comparable: same trial count
  // (equal sample size) AND same rubric criteria. Otherwise it's re-run. Both the
  // plan count and the loop use this so they stay consistent. The candidate arm
  // always runs fresh (it's the thing under test — never cached).
  const usableControl = (s: typeof args.scenarios[number]) =>
    !args.refreshBaseline && isBaselineUsable(readBaseline(baselinePath(s.id, args.model)), args.trials, RUBRIC_CRITERIA);
  const needsControl = args.scenarios.filter(s => !usableControl(s));
  const controlRuns = needsControl.length * args.trials;
  const candidateRuns = variant ? args.scenarios.length * args.trials : 0;
  const totalRuns = controlRuns + candidateRuns;
  const estTokens = totalRuns * EST_TOKENS_PER_RUN;

  const mode = variant ? `A/B "${variant}" vs control` : 'control baseline';
  console.log(`Plan: ${mode} — ${totalRuns} real-model run(s) on "${args.model}" (${controlRuns} control + ${candidateRuns} candidate).`);
  console.log(`Cost guard: budget ${args.budget} tok · rough est ~${estTokens} tok · per-run cap ${args.maxTurns} turns.`);
  if (totalRuns === 0) { console.log('All requested baselines are cached and no candidate to run (use --refresh-baseline or --variant).'); return; }

  if (!args.yes) {
    const ok = await confirm(`Proceed with up to ${totalRuns} real-model runs (rough est ~${estTokens} tokens) on "${args.model}"? [y/N] `);
    if (!ok) { console.log('Aborted (pass --yes to skip this prompt).'); process.exit(0); }
  }

  // Budget enforced two ways: a pre-run gate whose per-run estimate adapts up to
  // the heaviest run seen (so after one heavy run it stops launching more), and a
  // hard post-run stop the moment ACTUAL cumulative spend reaches the budget. A
  // run in flight is bounded only by --max-turns, so total spend can exceed
  // --budget by at most one run.
  const budget = { used: 0, cost: 0, maxRun: 0 };
  const wouldExceed = () => budget.used + Math.max(EST_TOKENS_PER_RUN, budget.maxRun) > args.budget;

  // Run `args.trials` runs of one arm (variant) → mean grade. Honors the budget
  // (exits the process on breach, like the baseline-only path).
  const runArm = async (scenario: typeof args.scenarios[number], arm: string): Promise<RubricResult> => {
    const grades: RubricResult[] = [];
    for (let t = 0; t < args.trials; t++) {
      if (wouldExceed()) {
        console.error(`\nBUDGET STOP before [${scenario.id}] ${arm} trial ${t + 1}: ${budget.used}/${args.budget} tokens used; next run would exceed the budget.`);
        process.exit(2);
      }
      const run = await runEvalScenario(scenario, { claudeBinary: 'claude', model: args.model, maxTurns: args.maxTurns, variant: arm });
      budget.used += run.usageTokens;
      budget.maxRun = Math.max(budget.maxRun, run.usageTokens);
      if (run.costUsd) budget.cost += run.costUsd;
      const grade = gradeRun(run.record, scenario.rubric);
      grades.push(grade);
      await run.cleanup();
      console.log(`[${scenario.id}] ${arm} trial ${t + 1}/${args.trials}: overall ${grade.overall.toFixed(3)} · ${run.usageTokens} tok · status ${run.record.taskStatus}`);
      if (budget.used >= args.budget) {
        console.error(`\nBUDGET REACHED after [${scenario.id}] ${arm} trial ${t + 1}: ${budget.used}/${args.budget} tokens used; stopping.`);
        process.exit(2);
      }
    }
    return meanGrade(grades);
  };

  for (const scenario of args.scenarios) {
    const path = baselinePath(scenario.id, args.model);
    console.log(`\n[${scenario.id}]`);

    // Control arm: reuse the cache only if it's A/B-comparable, else run + cache.
    const cachedRec = args.refreshBaseline ? null : readBaseline(path);
    let control: RubricResult;
    if (usableControl(scenario) && cachedRec) {
      console.log('  control: cached baseline');
      control = cachedRec.grade;
    } else {
      if (cachedRec) console.log('  control: cached baseline not comparable (trial-count or rubric mismatch) — re-running');
      control = await runArm(scenario, 'control');
      mkdirSync(BASELINE_DIR, { recursive: true });
      writeFileSync(path, JSON.stringify({ scenario: scenario.id, model: args.model, trials: args.trials, grade: control }, null, 2) + '\n');
      console.log(`  cached baseline → ${path}`);
    }
    printGrade('control', control);

    // Candidate arm (always fresh) + A/B comparison.
    if (variant) {
      const candidate = await runArm(scenario, variant);
      printGrade(variant, candidate);
      const cmp = compareGrades(control, candidate);
      const flag = cmp.regressions.length
        ? `REGRESSIONS — ${cmp.regressions.map(r => `${r.criterion} ${r.control.toFixed(2)}→${r.candidate.toFixed(2)}`).join(', ')}`
        : 'no per-criterion regressions';
      console.log(`  A/B ${variant} vs control: overall ${control.overall.toFixed(3)} → ${candidate.overall.toFixed(3)} (Δ ${cmp.delta >= 0 ? '+' : ''}${cmp.delta.toFixed(3)}) · ${flag}`);
    }
  }

  console.log(`\nDone. ${budget.used} tokens used (budget ${args.budget})${budget.cost ? ` · ~$${budget.cost.toFixed(4)}` : ''}.`);
}

// Only run when invoked directly (not when imported by a test).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch(err => { console.error(err); process.exit(1); });
}
