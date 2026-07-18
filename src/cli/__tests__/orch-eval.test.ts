import { describe, it, expect } from 'vitest';
import {
  parseOrchArgs, meanOrchGrade,
  DEFAULT_ORCH_MAX_TURNS, DEFAULT_ORCH_TIMEOUT_MS, DEFAULT_ORCH_BUDGET,
} from '../orch-eval.js';
import { DEFAULT_MAX_BUDGET_USD, DEFAULT_MAX_TOTAL_USD } from '../prompt-eval-lib.js';
import { gradeOrchestration, type OrchRunRecord } from '../../services/eval-orchestration-rubric.js';

describe('parseOrchArgs', () => {
  it('defaults are safe (no --real → no spend; sane caps)', () => {
    const a = parseOrchArgs([]);
    expect(a.real).toBe(false);
    expect(a.yes).toBe(false);
    expect(a.model).toBe('haiku');
    expect(a.trials).toBe(1);
    expect(a.budget).toBe(DEFAULT_ORCH_BUDGET);
    expect(a.maxBudgetUsd).toBe(DEFAULT_MAX_BUDGET_USD);
    expect(a.maxTotalUsd).toBe(DEFAULT_MAX_TOTAL_USD);
    expect(a.maxTurns).toBe(DEFAULT_ORCH_MAX_TURNS);
    expect(a.timeoutMs).toBe(DEFAULT_ORCH_TIMEOUT_MS);
  });

  it('parses overrides', () => {
    const a = parseOrchArgs(['--real', '--yes', '--model', 'sonnet', '--trials', '3', '--budget', '600000', '--max-budget-usd', '0.25', '--max-total-usd', '1.25', '--max-turns', '30', '--timeout-ms', '120000']);
    expect(a).toMatchObject({ real: true, yes: true, model: 'sonnet', trials: 3, budget: 600000, maxBudgetUsd: 0.25, maxTotalUsd: 1.25, maxTurns: 30, timeoutMs: 120000 });
  });

  it('a NaN/garbage numeric arg falls back to the default (never disables the budget guard)', () => {
    const a = parseOrchArgs(['--budget', 'notanumber', '--max-budget-usd', 'wat', '--max-total-usd', '-1', '--trials', '-5', '--max-turns', '0']);
    expect(a.budget).toBe(DEFAULT_ORCH_BUDGET);   // not NaN/0 → guard stays armed
    expect(a.trials).toBe(1);                     // negative rejected
    expect(a.maxTurns).toBe(DEFAULT_ORCH_MAX_TURNS);
    expect(a.maxBudgetUsd).toBe(DEFAULT_MAX_BUDGET_USD);
    expect(a.maxTotalUsd).toBe(DEFAULT_MAX_TOTAL_USD);
  });

  it('accepts deliberate zero dollar ceilings so main refuses before launch', () => {
    expect(parseOrchArgs(['--max-budget-usd', '0', '--max-total-usd', '0']))
      .toMatchObject({ maxBudgetUsd: 0, maxTotalUsd: 0 });
  });
});

describe('meanOrchGrade', () => {
  const rec = (newNodeCount: number): OrchRunRecord => ({
    toolCalls: [{ tool: 'get_state' }, { tool: 'log_thought' }, { tool: 'register_agent' }, { tool: 'get_state' }],
    dispatches: [{ archetype: 'recon_scanner', matchedFrontier: true }],
    newNodeCount,
  });

  it('returns the single grade unchanged for one trial', () => {
    const g = gradeOrchestration(rec(2));
    expect(meanOrchGrade([g])).toBe(g);
  });

  it('averages overall + per-criterion across trials', () => {
    const g1 = gradeOrchestration(rec(2));   // objective_progress = 1
    const g2 = gradeOrchestration(rec(0));   // objective_progress = 0
    const m = meanOrchGrade([g1, g2]);
    expect(m.overall).toBeCloseTo((g1.overall + g2.overall) / 2, 6);
    const op = m.criteria.find(c => c.criterion === 'objective_progress')!;
    expect(op.score).toBeCloseTo(0.5, 6);
  });
});
