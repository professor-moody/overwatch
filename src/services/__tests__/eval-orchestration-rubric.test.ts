import { describe, it, expect } from 'vitest';
import { gradeOrchestration, compareOrchGrades, ORCH_CRITERIA, type OrchRunRecord } from '../eval-orchestration-rubric.js';

// A clean, efficient, adaptive orchestrator run: orient → reason → dispatch matched
// children at DISTINCT targets → re-orient (synthesize) → re-dispatch (adapt), findings
// landed. Scores 1.0 on every criterion including the discriminating ones.
const goodRun: OrchRunRecord = {
  toolCalls: [
    { tool: 'ToolSearch' },
    { tool: 'get_state' },
    { tool: 'log_thought' },
    { tool: 'register_agent' },   // first dispatch — 2 meaningful calls of preamble
    { tool: 'get_state' },        // synthesis: re-orient after dispatch
    { tool: 'register_agent' },   // adaptive: re-dispatch after synthesizing
    { tool: 'report_finding' },
  ],
  dispatches: [
    { archetype: 'recon_scanner', matchedFrontier: true, target: 'fi-1' },
    { archetype: 'web_tester', matchedFrontier: true, target: 'fi-2' },
  ],
  newNodeCount: 4,
};

describe('gradeOrchestration', () => {
  it('scores a clean, efficient, adaptive run at the top across all criteria', () => {
    const r = gradeOrchestration(goodRun);
    expect(r.overall).toBeCloseTo(1, 5);
    for (const c of r.criteria) expect(c.score).toBeCloseTo(1, 5);
    expect(r.criteria.map(c => c.criterion)).toEqual([...ORCH_CRITERIA]);
    expect(r.criteria.reduce((s, c) => s + c.weight, 0)).toBeCloseTo(1, 5);
  });

  it('dispatch_precision penalizes re-dispatching the same frontier item', () => {
    const run: OrchRunRecord = { ...goodRun, dispatches: [
      { archetype: 'web_tester', matchedFrontier: true, target: 'fi-1' },
      { archetype: 'web_tester', matchedFrontier: true, target: 'fi-1' }, // same target — spam
    ] };
    expect(gradeOrchestration(run).criteria.find(c => c.criterion === 'dispatch_precision')!.score).toBe(0.5);
  });

  it('dispatch_precision is neutral (1.0) when no dispatch carried a target', () => {
    const run: OrchRunRecord = { ...goodRun, dispatches: [{ archetype: 'recon_scanner', matchedFrontier: true }] };
    expect(gradeOrchestration(run).criteria.find(c => c.criterion === 'dispatch_precision')!.score).toBe(1);
  });

  it('orient_efficiency decays as the primary dawdles before its first dispatch', () => {
    const dawdle: OrchRunRecord = { ...goodRun, toolCalls: [
      { tool: 'get_state' }, { tool: 'get_state' }, { tool: 'log_thought' }, { tool: 'next_task' },
      { tool: 'get_state' }, { tool: 'log_thought' }, // 6 meaningful calls...
      { tool: 'register_agent' },                      // ...then first dispatch
    ] };
    // 6 preamble → 1 - (6-3)/5 = 0.4
    expect(gradeOrchestration(dawdle).criteria.find(c => c.criterion === 'orient_efficiency')!.score).toBeCloseTo(0.4, 5);
  });

  it('adaptive_synthesis grades fire-and-forget (0), synth-no-act (0.5), closed-loop (1)', () => {
    const find = (r: OrchRunRecord) => gradeOrchestration(r).criteria.find(c => c.criterion === 'adaptive_synthesis')!.score;
    const fireForget: OrchRunRecord = { ...goodRun, toolCalls: [{ tool: 'get_state' }, { tool: 'log_thought' }, { tool: 'register_agent' }] };
    const synthNoAct: OrchRunRecord = { ...goodRun, toolCalls: [{ tool: 'get_state' }, { tool: 'register_agent' }, { tool: 'get_state' }] };
    expect(find(fireForget)).toBe(0);
    expect(find(synthNoAct)).toBe(0.5);
    expect(find(goodRun)).toBe(1);
  });

  it('penalizes not orienting first', () => {
    const run: OrchRunRecord = { ...goodRun, toolCalls: [{ tool: 'register_agent' }, { tool: 'get_state' }] };
    expect(gradeOrchestration(run).criteria.find(c => c.criterion === 'orients')!.score).toBe(0);
  });

  it('penalizes dispatching without externalized reasoning', () => {
    const run: OrchRunRecord = { ...goodRun, toolCalls: [{ tool: 'get_state' }, { tool: 'register_agent' }, { tool: 'get_state' }] };
    expect(gradeOrchestration(run).criteria.find(c => c.criterion === 'externalizes_decisions')!.score).toBe(0);
  });

  it('scores archetype_match as the fraction of well-matched dispatches', () => {
    const run: OrchRunRecord = { ...goodRun, dispatches: [
      { archetype: 'recon_scanner', matchedFrontier: true },
      { archetype: 'default', matchedFrontier: false },
    ] };
    expect(gradeOrchestration(run).criteria.find(c => c.criterion === 'archetype_match')!.score).toBe(0.5);
  });

  it('penalizes fire-and-forget (no re-orientation after dispatch)', () => {
    const run: OrchRunRecord = { ...goodRun, toolCalls: [
      { tool: 'get_state' }, { tool: 'log_thought' }, { tool: 'register_agent' }, { tool: 'report_finding' },
    ] };
    expect(gradeOrchestration(run).criteria.find(c => c.criterion === 'synthesizes')!.score).toBe(0);
  });

  it('flags zero objective progress when no nodes landed', () => {
    expect(gradeOrchestration({ ...goodRun, newNodeCount: 0 }).criteria.find(c => c.criterion === 'objective_progress')!.score).toBe(0);
  });

  it('does not gate on completed status (no such criterion)', () => {
    expect(ORCH_CRITERIA).not.toContain('completed');
  });
});

describe('compareOrchGrades', () => {
  const lowEfficiency: OrchRunRecord = { ...goodRun, toolCalls: [
    { tool: 'get_state' }, { tool: 'get_state' }, { tool: 'log_thought' }, { tool: 'next_task' },
    { tool: 'get_state' }, { tool: 'log_thought' }, { tool: 'register_agent' }, { tool: 'get_state' }, { tool: 'register_agent' },
  ] };

  it('reports overall delta + per-criterion regressions', () => {
    const control = gradeOrchestration(goodRun);            // orient_efficiency 1.0
    const candidate = gradeOrchestration(lowEfficiency);    // orient_efficiency 0.4
    const cmp = compareOrchGrades(control, candidate);
    expect(cmp.delta).toBeLessThan(0);
    expect(cmp.regressions.map(r => r.criterion)).toContain('orient_efficiency');
  });

  it('reports no regressions + positive delta when the candidate improves', () => {
    const control = gradeOrchestration(lowEfficiency);
    const candidate = gradeOrchestration(goodRun);
    const cmp = compareOrchGrades(control, candidate);
    expect(cmp.delta).toBeGreaterThan(0);
    expect(cmp.regressions).toHaveLength(0);
  });
});
