// ============================================================
// Prompt behavior-eval CLI — pure helpers (no side effects, no main()).
// ============================================================
// Split out from prompt-eval.ts so the arg parsing, budget defaults, baseline
// I/O, and trial averaging can be unit-tested without executing the CLI entry
// point (which runs on import).

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import type { RubricResult } from '../services/eval-rubric.js';
import { EVAL_SCENARIOS, getScenario, type EvalScenario } from '../test-support/eval-scenarios.js';

export const BASELINE_DIR = 'eval-baselines';
export const EST_TOKENS_PER_RUN = 15_000; // rough per-run estimate, for budgeting only
export const DEFAULT_MODEL = 'haiku';      // cheap by default; override with --model
export const DEFAULT_TRIALS = 2;
export const DEFAULT_BUDGET = 50_000;      // token budget (see prompt-eval.ts for enforcement)
export const DEFAULT_MAX_TURNS = 10;

export interface Args {
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
    maxTurns: Math.max(1, Math.floor(int(get('--max-turns'), DEFAULT_MAX_TURNS))),
    scenarios,
  };
}

/** Read + validate a cached baseline; returns the grade or null if absent,
 *  corrupt, or an old/unknown shape (so the caller re-runs rather than crashing). */
export function readBaseline(path: string): RubricResult | null {
  if (!existsSync(path)) return null;
  try {
    const d = JSON.parse(readFileSync(path, 'utf-8')) as { grade?: RubricResult };
    return Array.isArray(d?.grade?.criteria) ? d.grade! : null;
  } catch {
    return null;
  }
}

export function baselinePath(scenarioId: string, model: string): string {
  return join(BASELINE_DIR, `${scenarioId}.${model.replace(/[^\w.-]/g, '_')}.json`);
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
