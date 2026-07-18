import { describe, it, expect } from 'vitest';
import { writeFileSync, mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  parseArgs, readBaseline, isBaselineUsable, meanGrade, baselinePath, percentile,
  allocateRunBudgetUsd, chargeRunBudgetUsd, inspectClaudeBudgetCompatibility,
  DEFAULT_MODEL, DEFAULT_TRIALS, DEFAULT_BUDGET, DEFAULT_MAX_BUDGET_USD,
  DEFAULT_MAX_TOTAL_USD, DEFAULT_MAX_TURNS, DEFAULT_TIMEOUT_MS,
} from '../prompt-eval-lib.js';
import { RUBRIC_CRITERIA, type RubricResult } from '../../services/eval-rubric.js';

describe('parseArgs', () => {
  it('applies cheap, bounded defaults', () => {
    const a = parseArgs([]);
    expect(a).toMatchObject({
      real: false,
      yes: false,
      model: DEFAULT_MODEL,
      trials: DEFAULT_TRIALS,
      budget: DEFAULT_BUDGET,
      maxBudgetUsd: DEFAULT_MAX_BUDGET_USD,
      maxTotalUsd: DEFAULT_MAX_TOTAL_USD,
      maxTurns: DEFAULT_MAX_TURNS,
      timeoutMs: DEFAULT_TIMEOUT_MS,
    });
    expect(a.scenarios.length).toBeGreaterThan(0);
  });

  it('parses --timeout-ms (real runs need minutes, not the 20s fake default)', () => {
    expect(parseArgs(['--timeout-ms', '900000']).timeoutMs).toBe(900000);
    expect(parseArgs(['--timeout-ms', 'abc']).timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    expect(parseArgs([]).timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
  });

  it('falls back to defaults on non-numeric values (a NaN budget would disable the guard)', () => {
    const a = parseArgs(['--real', '--trials', 'abc', '--budget', 'xyz', '--max-budget-usd', 'wat', '--max-total-usd', '-1', '--max-turns', 'foo']);
    expect(a.trials).toBe(DEFAULT_TRIALS);
    expect(a.budget).toBe(DEFAULT_BUDGET);
    expect(a.maxTurns).toBe(DEFAULT_MAX_TURNS);
    expect(a.maxBudgetUsd).toBe(DEFAULT_MAX_BUDGET_USD);
    expect(a.maxTotalUsd).toBe(DEFAULT_MAX_TOTAL_USD);
    expect(Number.isFinite(a.budget)).toBe(true);
  });

  it('parses explicit per-run and command dollar ceilings, including a deliberate zero', () => {
    expect(parseArgs(['--max-budget-usd', '0.25', '--max-total-usd', '1.5']))
      .toMatchObject({ maxBudgetUsd: 0.25, maxTotalUsd: 1.5 });
    expect(parseArgs(['--max-budget-usd', '0', '--max-total-usd', '0']))
      .toMatchObject({ maxBudgetUsd: 0, maxTotalUsd: 0 });
  });

  it('does not swallow the next flag as a value', () => {
    const a = parseArgs(['--model', '--trials', '1']);
    expect(a.model).toBe(DEFAULT_MODEL); // --trials was not consumed as the model
    expect(a.trials).toBe(1);
  });

  it('clamps trials/maxTurns to >= 1 and budget to >= 0', () => {
    const a = parseArgs(['--trials', '-5', '--max-turns', '0', '--budget', '-10']);
    expect(a.trials).toBe(1);
    expect(a.maxTurns).toBe(1);
    expect(a.budget).toBe(0);
  });

  it('resolves a scenario subset and drops unknown ids', () => {
    expect(parseArgs(['--scenarios', 'recon,web']).scenarios.map(s => s.id)).toEqual(['recon', 'web']);
    expect(parseArgs(['--scenarios', 'nope']).scenarios).toHaveLength(0);
  });

  it('parses the candidate --variant for the A/B arm', () => {
    expect(parseArgs(['--real', '--variant', 'lean']).variant).toBe('lean');
    expect(parseArgs(['--real']).variant).toBeUndefined();
  });
});

describe('real-model dollar guard', () => {
  it('requires Claude to advertise the in-flight dollar flag', () => {
    expect(inspectClaudeBudgetCompatibility('claude', () => '... --max-budget-usd <amount> ...')).toEqual({ ok: true });
    expect(inspectClaudeBudgetCompatibility('claude', () => '--max-turns 10')).toMatchObject({ ok: false });
    expect(inspectClaudeBudgetCompatibility('claude', () => { throw new Error('missing'); })).toMatchObject({ ok: false });
  });

  it('allocates no more than the per-run cap or remaining command allowance', () => {
    expect(allocateRunBudgetUsd(0.5, 2, 0)).toBe(0.5);
    expect(allocateRunBudgetUsd(0.5, 2, 1.8)).toBeCloseTo(0.2, 10);
    expect(allocateRunBudgetUsd(0.5, 2, 2)).toBe(0);
  });

  it('charges provider cost when present and reserves the full cap when absent', () => {
    expect(chargeRunBudgetUsd(0.5, 0.123)).toEqual({ chargedUsd: 0.123, source: 'reported' });
    expect(chargeRunBudgetUsd(0.5, 0)).toEqual({ chargedUsd: 0, source: 'reported' });
    expect(chargeRunBudgetUsd(0.5, undefined)).toEqual({ chargedUsd: 0.5, source: 'reserved_cap' });
  });

  it('stops cumulative allocation after missing costs reserve the command ceiling', () => {
    let chargedUsd = 0;
    const assigned: number[] = [];
    for (let run = 0; run < 5; run += 1) {
      const cap = allocateRunBudgetUsd(0.5, 2, chargedUsd);
      assigned.push(cap);
      if (cap === 0) break;
      chargedUsd += chargeRunBudgetUsd(cap, undefined).chargedUsd;
    }
    expect(assigned).toEqual([0.5, 0.5, 0.5, 0.5, 0]);
    expect(chargedUsd).toBe(2);
  });
});

describe('readBaseline', () => {
  it('returns null for missing, corrupt, or wrong-shape files (never throws); returns {trials,grade} when valid', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ow-baseline-'));
    try {
      expect(readBaseline(join(dir, 'missing.json'))).toBeNull();
      const corrupt = join(dir, 'corrupt.json'); writeFileSync(corrupt, '{ not json');
      expect(readBaseline(corrupt)).toBeNull();
      const wrong = join(dir, 'wrong.json'); writeFileSync(wrong, JSON.stringify({ foo: 1 }));
      expect(readBaseline(wrong)).toBeNull();
      const valid = join(dir, 'valid.json'); writeFileSync(valid, JSON.stringify({ trials: 3, grade: { overall: 0.5, criteria: [{ criterion: 'completed', score: 1, weight: 1, detail: '' }] } }));
      expect(readBaseline(valid)).toMatchObject({ trials: 3, grade: { overall: 0.5 } });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('isBaselineUsable', () => {
  const fullCriteria = RUBRIC_CRITERIA.map(criterion => ({ criterion, score: 1, weight: 1 / RUBRIC_CRITERIA.length, detail: '' }));
  const rec = (trials: number, criteria = fullCriteria) => ({ trials, grade: { overall: 1, criteria } });

  it('accepts a baseline with matching trials + matching rubric criteria', () => {
    expect(isBaselineUsable(rec(2), 2, RUBRIC_CRITERIA)).toBe(true);
  });
  it('rejects null', () => {
    expect(isBaselineUsable(null, 2, RUBRIC_CRITERIA)).toBe(false);
  });
  it('rejects a mismatched trial count (unequal sample size)', () => {
    expect(isBaselineUsable(rec(1), 5, RUBRIC_CRITERIA)).toBe(false);
  });
  it('rejects a baseline recorded under a different rubric', () => {
    const stale = rec(2, [{ criterion: 'completed', score: 1, weight: 1, detail: '' }]);
    expect(isBaselineUsable(stale, 2, RUBRIC_CRITERIA)).toBe(false);
  });
});

describe('meanGrade', () => {
  it('averages per-criterion scores + overall across trials', () => {
    const mk = (s: number): RubricResult => ({ overall: s, criteria: [{ criterion: 'completed', score: s, weight: 1, detail: '' }] });
    const m = meanGrade([mk(1), mk(0)]);
    expect(m.overall).toBe(0.5);
    expect(m.criteria[0].score).toBe(0.5);
  });
});

describe('percentile (budget guard estimate)', () => {
  it('returns 0 for an empty sample', () => {
    expect(percentile([], 0.75)).toBe(0);
  });
  it('p75 is robust to a single runaway outlier (vs max)', () => {
    // Nine ~450k runs + one 2.6M outlier: p75 stays near the typical run, max would
    // spike the estimate and strand the batch.
    const runs = [440, 450, 455, 448, 452, 460, 445, 449, 451, 2600].map(n => n * 1000);
    const p75 = percentile(runs, 0.75);
    expect(p75).toBeLessThan(500_000);          // not dominated by the 2.6M outlier
    expect(Math.max(...runs)).toBe(2_600_000);  // max would have been
  });
  it('p100 equals the max', () => {
    expect(percentile([10, 20, 30], 1)).toBe(30);
  });
});

describe('baselinePath', () => {
  it('sanitizes the model into the filename', () => {
    expect(baselinePath('recon', 'haiku')).toContain('recon.haiku.json');
    expect(baselinePath('web', 'claude haiku/4')).toBe('eval-baselines/web.claude_haiku_4.json');
  });
});
