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
// bounded by: a cheap default model, a hard per-run turn cap, a global token
// budget that aborts BEFORE a run that would exceed it, tiny defaults, a pre-run
// estimate + confirmation, and a baseline cache so iterating doesn't repay for
// control.
//
//   npm run prompt-eval                       # usage (no spend)
//   npm run prompt-eval -- --real --yes       # establish/refresh control baselines
//   npm run prompt-eval -- --real --scenarios recon --trials 1 --budget 20000 --yes

import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { createInterface } from 'readline';
import { runEvalScenario } from '../test-support/eval-run.js';
import { gradeRun, type RubricResult } from '../services/eval-rubric.js';
import { EVAL_SCENARIOS, getScenario, type EvalScenario } from '../test-support/eval-scenarios.js';

const BASELINE_DIR = 'eval-baselines';
const EST_TOKENS_PER_RUN = 15_000; // rough per-run estimate, for budgeting only
const DEFAULT_MODEL = 'haiku';     // cheap by default; override with --model
const DEFAULT_TRIALS = 2;
const DEFAULT_BUDGET = 50_000;     // hard token ceiling
const DEFAULT_MAX_TURNS = 10;

interface Args {
  real: boolean;
  yes: boolean;
  refreshBaseline: boolean;
  variant?: string;
  model: string;
  trials: number;
  budget: number;
  maxTurns: number;
  scenarios: EvalScenario[];
}

function parseArgs(argv: string[]): Args {
  const get = (flag: string) => { const i = argv.indexOf(flag); return i >= 0 ? argv[i + 1] : undefined; };
  const has = (flag: string) => argv.includes(flag);
  const scnArg = get('--scenarios');
  const scenarios = scnArg
    ? scnArg.split(',').map(s => s.trim()).filter(Boolean).map(getScenario).filter((s): s is EvalScenario => !!s)
    : EVAL_SCENARIOS;
  return {
    real: has('--real'),
    yes: has('--yes'),
    refreshBaseline: has('--refresh-baseline'),
    variant: get('--variant'),
    model: get('--model') ?? DEFAULT_MODEL,
    trials: Math.max(1, Number(get('--trials') ?? DEFAULT_TRIALS)),
    budget: Math.max(0, Number(get('--budget') ?? DEFAULT_BUDGET)),
    maxTurns: Math.max(1, Number(get('--max-turns') ?? DEFAULT_MAX_TURNS)),
    scenarios,
  };
}

/** Average per-criterion scores + overall across trials (weights are identical). */
function meanGrade(grades: RubricResult[]): RubricResult {
  const first = grades[0];
  const criteria = first.criteria.map((c, i) => ({
    ...c,
    score: grades.reduce((s, g) => s + g.criteria[i].score, 0) / grades.length,
    detail: `mean of ${grades.length} trial(s)`,
  }));
  return { overall: grades.reduce((s, g) => s + g.overall, 0) / grades.length, criteria };
}

function baselinePath(scenarioId: string, model: string): string {
  return join(BASELINE_DIR, `${scenarioId}.${model.replace(/[^\w.-]/g, '_')}.json`);
}

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

  const needsControl = args.scenarios.filter(s => args.refreshBaseline || !existsSync(baselinePath(s.id, args.model)));
  const controlRuns = needsControl.length * args.trials;
  const estTokens = controlRuns * EST_TOKENS_PER_RUN;

  console.log(`Plan: ${controlRuns} real-model run(s) on model "${args.model}" (${needsControl.length} scenario(s) × ${args.trials} trial(s)).`);
  console.log(`Cost guard: budget ${args.budget} tok · est ~${estTokens} tok · per-run cap ${args.maxTurns} turns.`);
  if (!needsControl.length) console.log('All requested baselines are cached — nothing to run (use --refresh-baseline to re-run).');

  if (controlRuns > 0 && !args.yes) {
    const ok = await confirm(`Proceed with up to ${controlRuns} real-model runs (~${estTokens} tokens) on "${args.model}"? [y/N] `);
    if (!ok) { console.log('Aborted (pass --yes to skip this prompt).'); process.exit(0); }
  }

  let usedTokens = 0;
  let usedCostUsd = 0;
  const wouldExceed = () => usedTokens + EST_TOKENS_PER_RUN > args.budget;

  for (const scenario of args.scenarios) {
    const path = baselinePath(scenario.id, args.model);
    if (!args.refreshBaseline && existsSync(path)) {
      const cached = JSON.parse(readFileSync(path, 'utf-8')) as { grade: RubricResult };
      console.log(`\n[${scenario.id}] cached baseline:`);
      printGrade('control', cached.grade);
      continue;
    }

    const grades: RubricResult[] = [];
    for (let t = 0; t < args.trials; t++) {
      if (wouldExceed()) {
        console.error(`\nBUDGET STOP before [${scenario.id}] trial ${t + 1}: ${usedTokens}/${args.budget} tokens used; a run would exceed the budget.`);
        process.exit(2);
      }
      const run = await runEvalScenario(scenario, { claudeBinary: 'claude', model: args.model, maxTurns: args.maxTurns });
      usedTokens += run.usageTokens;
      if (run.costUsd) usedCostUsd += run.costUsd;
      const grade = gradeRun(run.record, scenario.rubric);
      grades.push(grade);
      await run.cleanup();
      console.log(`[${scenario.id}] trial ${t + 1}/${args.trials}: overall ${grade.overall.toFixed(3)} · ${run.usageTokens} tok · status ${run.record.taskStatus}`);
    }

    const baseline = meanGrade(grades);
    mkdirSync(BASELINE_DIR, { recursive: true });
    writeFileSync(path, JSON.stringify({ scenario: scenario.id, model: args.model, trials: args.trials, grade: baseline }, null, 2) + '\n');
    console.log(`[${scenario.id}] cached baseline → ${path}`);
    printGrade('control (mean)', baseline);
  }

  console.log(`\nDone. ${usedTokens} tokens used (budget ${args.budget})${usedCostUsd ? ` · ~$${usedCostUsd.toFixed(4)}` : ''}.`);
}

main().catch(err => { console.error(err); process.exit(1); });
