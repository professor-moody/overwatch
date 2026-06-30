import { describe, it, expect } from 'vitest';
import { gradeOrchestration, ORCH_CRITERIA, type OrchRunRecord } from '../eval-orchestration-rubric.js';

// A clean orchestrator run: orient → reason → dispatch matched children →
// re-orient (synthesize), with findings landed.
const goodRun: OrchRunRecord = {
  toolCalls: [
    { tool: 'ToolSearch' },
    { tool: 'get_state' },
    { tool: 'next_task' },
    { tool: 'log_thought' },
    { tool: 'register_agent' },
    { tool: 'get_state' }, // synthesis: re-orient after dispatch
    { tool: 'report_finding' },
  ],
  dispatches: [{ archetype: 'recon_scanner', matchedFrontier: true }, { archetype: 'web_tester', matchedFrontier: true }],
  newNodeCount: 4,
};

describe('gradeOrchestration', () => {
  it('scores a clean orchestration run at the top', () => {
    const r = gradeOrchestration(goodRun);
    expect(r.overall).toBeCloseTo(1, 5);
    for (const c of r.criteria) expect(c.score).toBe(1);
    expect(r.criteria.map(c => c.criterion)).toEqual([...ORCH_CRITERIA]);
    expect(r.criteria.reduce((s, c) => s + c.weight, 0)).toBeCloseTo(1, 5);
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
