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
import { join, resolve } from 'path';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
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

  it('can explicitly preserve and finalize a fake run without retaining its runtime', async () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'ow-prompt-eval-artifact-smoke-'));
    try {
      last = await runEvalScenario(EVAL_SCENARIOS[0], {
        preserveArtifacts: true,
        artifactRoot: join(sandbox, 'artifacts'),
      });
      const grade = gradeRun(last.record, EVAL_SCENARIOS[0].rubric);
      const manifest = last.finalizeArtifacts({ grade });
      expect(manifest).toMatchObject({ outcome: 'completed', eligible_for_baseline: true });
      expect(JSON.parse(readFileSync(join(last.artifactDirectory!, 'grade.json'), 'utf8')))
        .toMatchObject({ outcome: 'completed', grade: { overall: grade.overall } });
    } finally {
      if (last) await last.cleanup();
      last = null;
      rmSync(sandbox, { recursive: true, force: true });
    }
  }, 30000);

  it('cancels a timed-out worker, waits for interruption, and preserves the terminal outcome', async () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'ow-prompt-eval-timeout-smoke-'));
    try {
      const timeoutScenario = { ...EVAL_SCENARIOS[0], id: 'recon-timeout', fakeMode: 'hang' };
      last = await runEvalScenario(timeoutScenario, {
        timeoutMs: 500,
        preserveArtifacts: true,
        artifactRoot: join(sandbox, 'artifacts'),
      });
      expect(last.outcome).toBe('timed_out');
      expect(last.record.taskStatus).toBe('interrupted');
      const grade = gradeRun(last.record, timeoutScenario.rubric);
      const manifest = last.finalizeArtifacts({ grade });
      expect(manifest).toMatchObject({
        outcome: 'timed_out',
        eligible_for_baseline: false,
      });
    } finally {
      if (last) await last.cleanup();
      last = null;
      rmSync(sandbox, { recursive: true, force: true });
    }
  }, 30000);
});
