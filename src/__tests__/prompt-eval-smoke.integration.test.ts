// ============================================================
// Prompt behavior-eval — pipeline plumbing smoke (fake claude)
// ============================================================
// Validates the run→record→grade PIPELINE end-to-end deterministically: seed a
// scenario, run a fake-claude sub-agent, map the run into a RunRecord, grade it.
// fake-claude is scripted (ignores prompt wording), so this proves the harness
// wiring — NOT real prompt behavior. The side-effect criteria (completed,
// objective_progress, lands_results) must reflect the fake run; the transcript
// criteria (starts_with_context, validate_before_execute) need a real model and
// are exercised by the Tier-2 CLI, not here.
import { describe, it, expect, afterEach, beforeAll } from 'vitest';
import { resolve } from 'path';
import { chmodSync } from 'fs';
import { createServer } from 'net';
import { runEvalScenario, extractToolCalls, type EvalRunResult } from '../test-support/eval-run.js';
import { EVAL_SCENARIOS } from '../test-support/eval-scenarios.js';
import { gradeRun } from '../services/eval-rubric.js';

const supportsLocalListen = await new Promise<boolean>((res) => {
  const srv = createServer();
  srv.on('error', () => { srv.close(); res(false); });
  srv.listen(0, '127.0.0.1', () => { srv.close(); res(true); });
});

describe.skipIf(!supportsLocalListen)('prompt-eval pipeline smoke (fake claude)', () => {
  let last: EvalRunResult | null = null;
  beforeAll(() => { chmodSync(resolve('./src/test-support/fake-claude.mjs'), 0o755); });
  afterEach(async () => { if (last) await last.cleanup(); last = null; });

  for (const scenario of EVAL_SCENARIOS) {
    it(`${scenario.id}: maps a fake run into a graded RunRecord`, async () => {
      last = await runEvalScenario(scenario);
      expect(last.record.taskStatus).toBe('completed');
      expect(last.record.newNodeTypes).toEqual(expect.arrayContaining(scenario.rubric.expectedNodeTypes ?? []));

      const grade = gradeRun(last.record, scenario.rubric);
      expect(grade.criteria).toHaveLength(6);
      expect(grade.overall).toBeGreaterThan(0);
      expect(grade.criteria.find(c => c.criterion === 'completed')!.score).toBe(1);
      expect(grade.criteria.find(c => c.criterion === 'objective_progress')!.score).toBe(1);
      expect(grade.criteria.find(c => c.criterion === 'lands_results')!.score).toBe(1);
    }, 30000);
  }

  it('extractToolCalls reads nested assistant tool_use blocks (real-claude shape)', () => {
    const ndjson = [
      JSON.stringify({ type: 'assistant', message: { content: [
        { type: 'text', text: 'orienting' },
        { type: 'tool_use', name: 'mcp__overwatch__get_agent_context', input: { task_id: 't1' } },
        { type: 'tool_use', name: 'mcp__overwatch__validate_action', input: { action_id: 'a1', frontier_item_id: 'f1' } },
      ] } }),
      JSON.stringify({ type: 'result', subtype: 'success' }),
    ].join('\n');
    const calls = extractToolCalls(ndjson);
    expect(calls.map(c => c.tool)).toEqual(['get_agent_context', 'validate_action']);
    expect(calls[1]).toMatchObject({ action_id: 'a1', frontier_item_id: 'f1' });
  });
});
