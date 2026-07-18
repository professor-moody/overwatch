// ============================================================
// Prompt behavior-eval CLI — pure helpers (no side effects, no main()).
// ============================================================
// Split out from prompt-eval.ts so the arg parsing, budget defaults, baseline
// I/O, and trial averaging can be unit-tested without executing the CLI entry
// point (which runs on import).

import { execFileSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import type { RubricResult } from '../services/eval-rubric.js';
import { EVAL_SCENARIOS, getScenario, type EvalScenario } from '../test-support/eval-scenarios.js';

export const BASELINE_DIR = 'eval-baselines';
export const EST_TOKENS_PER_RUN = 15_000; // rough per-run estimate, for budgeting only
export const DEFAULT_MODEL = 'haiku';      // cheap by default; override with --model
export const DEFAULT_TRIALS = 2;
export const DEFAULT_BUDGET = 50_000;      // token budget (see prompt-eval.ts for enforcement)
export const DEFAULT_MAX_BUDGET_USD = 0.50;
export const DEFAULT_MAX_TOTAL_USD = 2.00;
export const DEFAULT_MAX_TURNS = 10;
export const DEFAULT_TIMEOUT_MS = 600_000;  // 10 min per run — a real claude sub-agent takes minutes (fake-claude finishes in <1s)

/** The legacy token gate controls whether another run may start. It is not an
 * in-flight limit and must never invalidate a completed, dollar-capped run. */
export function accountingBatchBlocksNextRun(
  usedTokens: number,
  estimatedNextRunTokens: number,
  budgetTokens: number,
): boolean {
  return usedTokens + estimatedNextRunTokens > budgetTokens;
}

export interface Args {
  real: boolean;
  yes: boolean;
  refreshBaseline: boolean;
  variant?: string;
  model: string;
  trials: number;
  budget: number;
  maxBudgetUsd: number;
  maxTotalUsd: number;
  maxTurns: number;
  timeoutMs: number;
  scenarios: EvalScenario[];
}

export function parseArgs(argv: string[]): Args {
  // Returns the token after `flag`, unless it's missing or is itself another
  // flag (so `--model --trials 1` doesn't swallow `--trials` as the model).
  const get = (flag: string) => {
    const i = argv.indexOf(flag);
    if (i < 0) return undefined;
    const v = argv[i + 1];
    return v && !v.startsWith('--') ? v : undefined;
  };
  const has = (flag: string) => argv.includes(flag);
  // Falls back to the default on a non-numeric value (Number('abc') is NaN, and
  // Math.max(1, NaN) is NaN — a NaN budget would silently disable the guard).
  const int = (raw: string | undefined, dflt: number) => {
    const n = Number(raw);
    return Number.isFinite(n) ? n : dflt;
  };
  const money = (raw: string | undefined, dflt: number) => {
    if (raw === undefined) return dflt;
    const n = Number(raw);
    return Number.isFinite(n) && n >= 0 ? n : dflt;
  };
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
    trials: Math.max(1, Math.floor(int(get('--trials'), DEFAULT_TRIALS))),
    budget: Math.max(0, Math.floor(int(get('--budget'), DEFAULT_BUDGET))),
    maxBudgetUsd: money(get('--max-budget-usd'), DEFAULT_MAX_BUDGET_USD),
    maxTotalUsd: money(get('--max-total-usd'), DEFAULT_MAX_TOTAL_USD),
    maxTurns: Math.max(1, Math.floor(int(get('--max-turns'), DEFAULT_MAX_TURNS))),
    timeoutMs: Math.max(1000, Math.floor(int(get('--timeout-ms'), DEFAULT_TIMEOUT_MS))),
    scenarios,
  };
}

export interface ClaudeBudgetCompatibility {
  ok: boolean;
  error?: string;
}

/** Real evaluation is permitted only when the installed Claude CLI exposes a
 * genuine in-flight dollar cap. Turns and post-run accounting are not spend
 * ceilings. */
export function inspectClaudeBudgetCompatibility(
  binary = 'claude',
  inspect: (binary: string) => string = candidate => execFileSync(candidate, ['--help'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 5_000,
  }),
): ClaudeBudgetCompatibility {
  try {
    const help = inspect(binary);
    return help.includes('--max-budget-usd')
      ? { ok: true }
      : { ok: false, error: `${binary} does not advertise --max-budget-usd` };
  } catch (error) {
    return {
      ok: false,
      error: `could not inspect ${binary}: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/** Allocate the next in-flight cap without ever assigning more than the
 * uncharged command allowance. Returns 0 when no additional run may start. */
export function allocateRunBudgetUsd(
  maxBudgetUsd: number,
  maxTotalUsd: number,
  chargedUsd: number,
): number {
  const remaining = Math.max(0, maxTotalUsd - chargedUsd);
  return Math.max(0, Math.min(maxBudgetUsd, remaining));
}

export interface ChargedRunBudget {
  chargedUsd: number;
  source: 'reported' | 'reserved_cap';
}

/** Missing provider cost is charged conservatively at the complete assigned
 * cap so a missing field can never reopen command budget. */
export function chargeRunBudgetUsd(
  assignedUsd: number,
  reportedUsd: number | undefined,
): ChargedRunBudget {
  if (reportedUsd !== undefined && Number.isFinite(reportedUsd) && reportedUsd >= 0) {
    return { chargedUsd: reportedUsd, source: 'reported' };
  }
  return { chargedUsd: assignedUsd, source: 'reserved_cap' };
}

export interface CachedBaseline {
  /** Trial count the baseline was averaged over (for fair-N A/B comparison). */
  trials: number;
  grade: RubricResult;
}

/** Read + validate a cached baseline; returns it or null if absent, corrupt, or
 *  an old/unknown shape (so the caller re-runs rather than crashing). */
export function readBaseline(path: string): CachedBaseline | null {
  if (!existsSync(path)) return null;
  try {
    const d = JSON.parse(readFileSync(path, 'utf-8')) as { trials?: number; grade?: RubricResult };
    if (!Array.isArray(d?.grade?.criteria)) return null;
    return { trials: typeof d.trials === 'number' ? d.trials : 0, grade: d.grade! };
  } catch {
    return null;
  }
}

/** A cached baseline is only A/B-comparable if it used the SAME trial count
 *  (equal sample size) AND the SAME rubric criteria (not recorded under an older
 *  rubric). Otherwise the caller must re-run control. */
export function isBaselineUsable(rec: CachedBaseline | null, trials: number, criteria: readonly string[]): boolean {
  if (!rec || rec.trials !== trials) return false;
  const got = rec.grade.criteria.map(c => c.criterion);
  return got.length === criteria.length && criteria.every((c, i) => got[i] === c);
}

export function baselinePath(scenarioId: string, model: string): string {
  return join(BASELINE_DIR, `${scenarioId}.${model.replace(/[^\w.-]/g, '_')}.json`);
}

/** Nearest-rank percentile of a numeric sample (p in [0,1]); 0 for an empty
 *  sample. Used for the budget guard's per-run estimate so ONE runaway run can't
 *  spike a max-based estimate and strand the rest of the batch. */
export function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.floor(p * sorted.length)));
  return sorted[idx];
}

/** Average per-criterion scores + overall across trials (weights are identical). */
export function meanGrade(grades: RubricResult[]): RubricResult {
  const first = grades[0];
  const criteria = first.criteria.map((c, i) => ({
    ...c,
    score: grades.reduce((s, g) => s + g.criteria[i].score, 0) / grades.length,
    detail: `mean of ${grades.length} trial(s)`,
  }));
  return { overall: grades.reduce((s, g) => s + g.overall, 0) / grades.length, criteria };
}
