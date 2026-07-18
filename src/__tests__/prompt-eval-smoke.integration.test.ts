// ============================================================
// Prompt behavior-eval — pipeline plumbing smoke (fake claude)
// ============================================================
// Validates the run→record→grade PIPELINE end-to-end deterministically: seed a
// scenario, run a fake-claude sub-agent, map the run into a RunRecord, grade it.
// fake-claude is scripted (ignores prompt wording), so this proves the harness
// wiring — NOT real prompt behavior. The side-effect criteria (completed,
// objective_progress, lands_results) must reflect the fake run. The hermetic
// recon fake also proves transcript extraction for the required call order, but
// only a Tier-2 real model run can prove that prompt wording caused the behavior.
import { describe, it, expect, afterEach, beforeAll } from 'vitest';
import { join, resolve } from 'path';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'fs';
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
      const priorHermeticEnv = {
        path: process.env.PATH,
        invocationLog: process.env.OVERWATCH_EVAL_NMAP_INVOCATION_LOG,
        fixtureFile: process.env.OVERWATCH_EVAL_NMAP_FIXTURE_FILE,
      };
      last = await runEvalScenario(scenario);
      expect(last.record.taskStatus).toBe('completed');
      expect(last.record.newNodeTypes).toEqual(expect.arrayContaining(scenario.rubric.expectedNodeTypes ?? []));

      const grade = gradeRun(last.record, scenario.rubric);
      expect(grade.criteria).toHaveLength(6);
      expect(grade.overall).toBeGreaterThan(0);
      expect(grade.criteria.find(c => c.criterion === 'completed')!.score).toBe(1);
      expect(grade.criteria.find(c => c.criterion === 'objective_progress')!.score).toBe(1);
      expect(grade.criteria.find(c => c.criterion === 'lands_results')!.score).toBe(1);

      if (scenario.hermeticTooling === 'nmap-recon') {
        expect(last.outcome).toBe('completed');
        expect(last.hermeticRecon).toBeDefined();
        expect(last.hermeticRecon!.servicePorts).toEqual([22, 80]);
        expect(last.hermeticRecon!.invocations).toHaveLength(1);
        expect(last.hermeticRecon!.invocations).toEqual(expect.arrayContaining([
          expect.objectContaining({
            shim: 'overwatch-hermetic-nmap',
            argv: ['-sV', '-oX', '-', '10.10.10.10'],
            network_activity: false,
          }),
        ]));
        expect(last.hermeticRecon!.invocations.every(invocation =>
          invocation.shim === 'overwatch-hermetic-nmap'
          && invocation.expected_target === '10.10.10.10'
          && invocation.network_activity === false)).toBe(true);
        const calls = last.record.toolCalls;
        expect(calls.map(call => call.tool)).toEqual([
          'get_agent_context',
          'validate_action',
          'run_tool',
          'submit_agent_transcript',
          'update_agent',
        ]);
        const validation = calls.find(call => call.tool === 'validate_action')!;
        const execution = calls.find(call => call.tool === 'run_tool')!;
        expect(validation.action_id).toBe(execution.action_id);
        expect(validation.frontier_item_id).toBe(last.hermeticRecon!.frontierItemId);
        expect(execution.frontier_item_id).toBe(last.hermeticRecon!.frontierItemId);

        const actionEvents = last.record.activity.filter(event =>
          event.action_id === execution.action_id
          && ['action_validated', 'action_started', 'action_completed', 'action_failed'].includes(event.event_type ?? ''));
        expect(actionEvents.length).toBeGreaterThanOrEqual(3);
        expect(actionEvents.every(event => event.frontier_item_id === last!.hermeticRecon!.frontierItemId)).toBe(true);

        const runtimeRoot = last.hermeticRecon!.runtimeRoot;
        expect(existsSync(last.hermeticRecon!.shimPath)).toBe(true);
        expect(existsSync(last.hermeticRecon!.fixturePath)).toBe(true);
        await last.cleanup();
        last = null;
        expect(existsSync(runtimeRoot)).toBe(false);
        expect(process.env.PATH).toBe(priorHermeticEnv.path);
        expect(process.env.OVERWATCH_EVAL_NMAP_INVOCATION_LOG).toBe(priorHermeticEnv.invocationLog);
        expect(process.env.OVERWATCH_EVAL_NMAP_FIXTURE_FILE).toBe(priorHermeticEnv.fixtureFile);
      }
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
