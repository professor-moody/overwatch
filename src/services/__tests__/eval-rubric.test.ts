import { describe, it, expect } from 'vitest';
import { gradeRun, compareGrades, type RunRecord, type ScenarioRubric } from '../eval-rubric.js';

const scenario: ScenarioRubric = { id: 'recon', expectedNodeTypes: ['service'] };

// A clean, loop-compliant recon run.
const goodRun: RunRecord = {
  toolCalls: [
    { tool: 'ToolSearch' },
    { tool: 'get_agent_context' },
    { tool: 'validate_action', action_id: 'a1', frontier_item_id: 'f1' },
    { tool: 'run_tool', action_id: 'a1', frontier_item_id: 'f1' },
    { tool: 'parse_output', action_id: 'a1', frontier_item_id: 'f1' },
  ],
  activity: [
    { event_type: 'action_validated', action_id: 'a1', frontier_item_id: 'f1' },
    { event_type: 'action_started', action_id: 'a1', frontier_item_id: 'f1' },
    { event_type: 'action_completed', action_id: 'a1', frontier_item_id: 'f1' },
    { event_type: 'parse_output', action_id: 'a1', frontier_item_id: 'f1' },
  ],
  taskStatus: 'completed',
  newNodeTypes: ['service'],
};

describe('gradeRun', () => {
  it('scores a clean loop-compliant run at the top', () => {
    const r = gradeRun(goodRun, scenario);
    expect(r.overall).toBeCloseTo(1, 5);
    for (const c of r.criteria) expect(c.score).toBe(1);
    // weights normalize to 1
    expect(r.criteria.reduce((s, c) => s + c.weight, 0)).toBeCloseTo(1, 5);
  });

  it('penalizes executing without a prior validate_action', () => {
    const run: RunRecord = { ...goodRun, toolCalls: [
      { tool: 'get_agent_context' },
      { tool: 'run_tool', action_id: 'a1' }, // no validate_action first
    ] };
    const r = gradeRun(run, scenario);
    const vbe = r.criteria.find(c => c.criterion === 'validate_before_execute')!;
    expect(vbe.score).toBe(0);
    expect(r.overall).toBeLessThan(1);
  });

  it('penalizes not starting with context', () => {
    const run: RunRecord = { ...goodRun, toolCalls: [
      { tool: 'run_tool', action_id: 'a1' },
      { tool: 'validate_action', action_id: 'a1' },
    ] };
    expect(gradeRun(run, scenario).criteria.find(c => c.criterion === 'starts_with_context')!.score).toBe(0);
  });

  it('penalizes unthreaded action events', () => {
    const run: RunRecord = { ...goodRun, activity: [
      { event_type: 'action_started', action_id: 'a1' },          // no frontier_item_id
      { event_type: 'action_completed', action_id: 'a1', frontier_item_id: 'f1' },
    ] };
    expect(gradeRun(run, scenario).criteria.find(c => c.criterion === 'threads_frontier_item_id')!.score).toBe(0.5);
  });

  it('flags prose-only drift when discovery was expected but nothing landed', () => {
    const run: RunRecord = { ...goodRun, toolCalls: [
      { tool: 'get_agent_context' },
      { tool: 'validate_action', action_id: 'a1' },
      { tool: 'run_tool', action_id: 'a1' },
    ], activity: [{ event_type: 'action_completed', action_id: 'a1', frontier_item_id: 'f1' }], newNodeTypes: [] };
    const r = gradeRun(run, scenario);
    expect(r.criteria.find(c => c.criterion === 'lands_results')!.score).toBe(0);
    expect(r.criteria.find(c => c.criterion === 'objective_progress')!.score).toBe(0);
  });

  it('scores objective progress as the fraction of expected node types produced', () => {
    const r = gradeRun({ ...goodRun, newNodeTypes: ['service'] }, { id: 'x', expectedNodeTypes: ['service', 'credential'] });
    expect(r.criteria.find(c => c.criterion === 'objective_progress')!.score).toBe(0.5);
  });
});

describe('compareGrades', () => {
  it('flags a criterion regression in the candidate', () => {
    const control = gradeRun(goodRun, scenario);
    const degraded = gradeRun({ ...goodRun, toolCalls: [
      { tool: 'run_tool', action_id: 'a1' }, // dropped context-first + validate
    ] }, scenario);
    const cmp = compareGrades(control, degraded);
    expect(cmp.delta).toBeLessThan(0);
    expect(cmp.regressions.some(r => r.criterion === 'starts_with_context')).toBe(true);
    expect(cmp.regressions.some(r => r.criterion === 'validate_before_execute')).toBe(true);
  });

  it('reports no regression for an equivalent candidate', () => {
    const a = gradeRun(goodRun, scenario);
    const b = gradeRun(goodRun, scenario);
    expect(compareGrades(a, b).regressions).toHaveLength(0);
    expect(compareGrades(a, b).delta).toBeCloseTo(0, 5);
  });
});
