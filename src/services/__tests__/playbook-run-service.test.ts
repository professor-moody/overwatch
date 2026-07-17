import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import {
  finishPlaybookAttemptFromToolResponse,
  PlaybookRunError,
  PlaybookRunService,
} from '../playbook-run-service.js';
import type { PersistedPlaybookDefinitionV1 } from '../persisted-state.js';
import { withApplicationCommandInvocation } from '../application-command-service.js';
import { PlaybookCommandService } from '../playbook-command-service.js';

const definition: PersistedPlaybookDefinitionV1 = {
  definition_id: 'test-credential',
  definition_version: 1,
  provider: 'aws',
  title: 'Test credential expansion',
};

function config(): EngagementConfig {
  return {
    id: 'playbook-run-test',
    name: 'Playbook Run Test',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function baseSteps(bound = false): Array<Record<string, unknown>> {
  return [
    {
      step: 1,
      step_id: 'identity',
      description: 'Resolve identity',
      runner: 'run_bash',
      command: 'identity-command',
      parse_with: 'identity-parser',
      parser_context: { source_credential_id: 'cred-1' },
      depends_on: [],
      required_bindings: [],
      produces_bindings: ['account_id'],
      ready: true,
      status: 'ready',
    },
    {
      step: 2,
      step_id: 'inventory',
      description: 'Enumerate inventory',
      runner: 'run_bash',
      command: bound ? 'inventory-command' : null,
      parse_with: 'inventory-parser',
      depends_on: ['identity'],
      required_bindings: ['account_id'],
      ready: bound,
      status: bound ? 'ready' : 'blocked',
      blocked_reason: bound ? undefined : 'account_id is unresolved',
    },
  ];
}

describe('PlaybookRunService', () => {
  let directory: string;
  let statePath: string;
  let engines: GraphEngine[];

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-playbook-run-'));
    statePath = join(directory, 'state.json');
    engines = [];
  });

  afterEach(() => {
    for (const engine of engines) engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  function openEngine(): GraphEngine {
    const engine = new GraphEngine(config(), statePath);
    engines.push(engine);
    return engine;
  }

  function closeEngine(engine: GraphEngine): void {
    engine.dispose();
    engines.splice(engines.indexOf(engine), 1);
  }

  it('resumes the matching open run and appends immutable plan revisions', () => {
    const engine = openEngine();
    const service = new PlaybookRunService(engine);
    const first = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: { region: 'us-east-1' },
      steps: baseSteps(false),
    });
    expect(first.created).toBe(true);
    expect(first.run.plan_revisions).toHaveLength(1);
    expect(first.run.steps.find(step => step.step_id === 'inventory')?.status).toBe('blocked');

    const resumed = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: { region: 'us-east-1' },
      steps: baseSteps(true),
    });
    expect(resumed.created).toBe(false);
    expect(resumed.run.run_id).toBe(first.run.run_id);
    expect(resumed.run.plan_revisions).toHaveLength(2);
    expect(resumed.run.plan_revisions[0].steps[1].execution_template.command).toBeNull();
    expect(resumed.run.plan_revisions[1].steps[1].execution_template.command).toBe('inventory-command');
    // Dependency truth is server-owned: a resolved command is still blocked
    // until the identity step succeeds.
    expect(resumed.run.steps.find(step => step.step_id === 'inventory')?.status).toBe('blocked');
  });

  it('new_run creates a separate run without changing normalized-input matching', () => {
    const service = new PlaybookRunService(openEngine());
    const input = {
      definition,
      credential_id: 'cred-1',
      normalized_inputs: { region: 'us-east-1' },
      steps: baseSteps(false),
    };
    const first = service.open(input);
    const second = service.open({ ...input, new_run: true });
    expect(second.created).toBe(true);
    expect(second.run.run_id).not.toBe(first.run.run_id);
    expect(service.list({ credential_id: 'cred-1' })).toHaveLength(2);
  });

  it('enforces one active step and appends retry attempts without losing references', () => {
    const service = new PlaybookRunService(openEngine());
    const opened = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: baseSteps(true),
    });
    const claim = service.startStep(opened.run.run_id, 'identity');
    expect(claim.execution).toMatchObject({
      playbook_run_id: opened.run.run_id,
      playbook_step_id: 'identity',
      playbook_attempt_id: claim.attempt.attempt_id,
      command_id: claim.attempt.execution_command_id,
      idempotency_key: claim.attempt.execution_idempotency_key,
      parser_context: {
        playbook_run_id: opened.run.run_id,
        playbook_step_id: 'identity',
        playbook_attempt_id: claim.attempt.attempt_id,
      },
    });
    expect(() => service.startStep(opened.run.run_id, 'inventory')).toThrowError(PlaybookRunError);

    const failed = service.finishAttempt(opened.run.run_id, 'identity', claim.attempt.attempt_id, {
      execution_outcome: 'succeeded',
      parse_outcome: 'no_data',
      action_id: 'act-1',
      evidence_ids: ['ev-1'],
      finding_ids: [],
      error: 'The requested parser yielded no artifacts.',
    });
    expect(failed.status).toBe('failed');
    expect(failed.steps[0].status).toBe('failed');

    const retry = service.retryStep(opened.run.run_id, 'identity');
    const completed = service.finishAttempt(opened.run.run_id, 'identity', retry.attempt.attempt_id, {
      execution_outcome: 'succeeded',
      parse_outcome: 'ok',
      action_id: 'act-2',
      evidence_ids: ['ev-2'],
      finding_ids: ['finding-2'],
    });
    expect(completed.steps[0].attempts).toHaveLength(2);
    expect(completed.steps[0].attempts[0]).toMatchObject({ action_id: 'act-1', evidence_ids: ['ev-1'] });
    expect(completed.steps[0].attempts[1]).toMatchObject({ action_id: 'act-2', finding_ids: ['finding-2'] });
    expect(completed.steps.find(step => step.step_id === 'inventory')?.status).toBe('pending');
  });

  it('retains partial parse reporting while allowing retained artifacts to satisfy dependencies', () => {
    const service = new PlaybookRunService(openEngine());
    const opened = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: baseSteps(true),
    });
    const claim = service.startStep(opened.run.run_id, 'identity');
    const partial = service.finishAttempt(opened.run.run_id, 'identity', claim.attempt.attempt_id, {
      execution_outcome: 'succeeded',
      parse_outcome: 'partial',
      evidence_ids: ['ev-partial'],
      finding_ids: ['finding-partial'],
    });
    expect(partial.report_status).toBe('partial');
    expect(partial.steps[0].status).toBe('succeeded');
    expect(partial.steps[1].status).toBe('pending');
  });

  it('never reports a one-step partial parse as completed', () => {
    const service = new PlaybookRunService(openEngine());
    const opened = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: [baseSteps(true)[0]],
    });
    const claim = service.startStep(opened.run.run_id, 'identity');
    const partial = service.finishAttempt(opened.run.run_id, 'identity', claim.attempt.attempt_id, {
      execution_outcome: 'succeeded',
      parse_outcome: 'partial',
      evidence_ids: ['ev-partial'],
      finding_ids: ['finding-partial'],
    });
    expect(partial).toMatchObject({ status: 'succeeded', report_status: 'partial' });
  });

  it('records claim and executor ownership and lets an operator release an abandoned claim', () => {
    const engine = openEngine();
    const service = new PlaybookRunService(engine);
    const opened = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: [baseSteps(true)[0]],
    });
    const claim = withApplicationCommandInvocation({
      transport: 'dashboard', actor_task_id: 'task-dashboard', request_id: 'claim-1',
    }, () => service.startStep(opened.run.run_id, 'identity'));
    expect(claim.attempt).toMatchObject({
      claimed_via: 'dashboard',
      claimed_by_task_id: 'task-dashboard',
    });
    expect(() => withApplicationCommandInvocation({
      transport: 'mcp', actor_task_id: 'task-terminal', request_id: 'claim-2',
    }, () => service.startStep(opened.run.run_id, 'identity'))).toThrow(/task-dashboard via dashboard/);

    const released = service.interruptAttempt(opened.run.run_id, 'identity', 'Descriptor was not executed.');
    expect(released.steps[0].attempts[0]).toMatchObject({
      status: 'interrupted', error: 'Descriptor was not executed.',
    });
    const retry = withApplicationCommandInvocation({
      transport: 'mcp', actor_task_id: 'task-terminal', request_id: 'claim-3',
    }, () => service.retryStep(opened.run.run_id, 'identity'));
    const completed = withApplicationCommandInvocation({
      transport: 'mcp', actor_task_id: 'task-terminal', request_id: 'execute-1',
    }, () => service.finishAttempt(opened.run.run_id, 'identity', retry.attempt.attempt_id, {
      execution_outcome: 'succeeded', parse_outcome: 'ok',
    }));
    expect(completed.steps[0].attempts[1]).toMatchObject({
      claimed_via: 'mcp', claimed_by_task_id: 'task-terminal',
      executed_via: 'mcp', executed_by_task_id: 'task-terminal',
    });
  });

  it('replays a duplicate command claim without creating another attempt', () => {
    const engine = openEngine();
    const runs = new PlaybookRunService(engine);
    const commands = new PlaybookCommandService(engine);
    const opened = runs.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: [baseSteps(true)[0]],
    });
    const invoke = () => withApplicationCommandInvocation({
      transport: 'cli', actor_task_id: 'task-terminal', idempotency_key: 'same-claim', request_id: 'ignored',
    }, () => commands.start(opened.run.run_id, 'identity'));
    const first = invoke();
    const replay = invoke();
    expect(replay).toEqual(first);
    expect(runs.getDurable(opened.run.run_id).steps[0].attempts).toHaveLength(1);
  });

  it('retains skips and derives completed reporting when all work is terminal', () => {
    const service = new PlaybookRunService(openEngine());
    const opened = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: [baseSteps(true)[0]],
    });
    const skipped = service.skipStep(opened.run.run_id, 'identity', 'Not relevant to this engagement.');
    expect(skipped).toMatchObject({ status: 'succeeded', report_status: 'completed' });
    expect(skipped.steps[0]).toMatchObject({ status: 'skipped', blocked_reason: 'Not relevant to this engagement.' });
  });

  it('atomically marks active attempts interrupted on restart and resumes without rewriting them', () => {
    const firstEngine = openEngine();
    const firstService = new PlaybookRunService(firstEngine);
    const opened = firstService.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: [baseSteps(true)[0]],
    });
    const claim = firstService.startStep(opened.run.run_id, 'identity');
    closeEngine(firstEngine);

    const secondEngine = openEngine();
    const secondService = new PlaybookRunService(secondEngine);
    expect(secondService.recoverInterruptedRuns()).toBe(1);
    const interrupted = secondService.getDurable(opened.run.run_id);
    expect(interrupted.steps[0].attempts[0]).toMatchObject({
      attempt_id: claim.attempt.attempt_id,
      status: 'interrupted',
      execution_outcome: 'interrupted',
    });
    const resumed = secondService.resume(opened.run.run_id);
    expect(resumed.status).toBe('pending');
    expect(resumed.resume_count).toBe(1);
    expect(resumed.steps[0].attempts).toHaveLength(1);
    const retry = secondService.retryStep(opened.run.run_id, 'identity');
    expect(retry.attempt).toMatchObject({ attempt_number: 2, status: 'running' });
  });

  it('closes a claimed attempt from an instrumented tool response without persisting output', () => {
    const engine = openEngine();
    const service = new PlaybookRunService(engine);
    const opened = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: [baseSteps(true)[0]],
    });
    const claim = service.startStep(opened.run.run_id, 'identity');
    const completed = finishPlaybookAttemptFromToolResponse(engine, claim.execution, {
      content: [{
        type: 'text',
        text: JSON.stringify({
          action_id: 'act-auto',
          executed: true,
          stdout: 'sensitive output that must not enter playbook state',
          stdout_evidence_id: 'ev-auto',
          parse_summary: {
            parse_outcome: 'ok',
            finding_id: 'finding-auto',
          },
        }),
      }],
    });
    expect(completed?.steps[0].attempts[0]).toMatchObject({
      status: 'succeeded',
      action_id: 'act-auto',
      evidence_ids: ['ev-auto'],
      finding_ids: ['finding-auto'],
      parse_outcome: 'ok',
    });
    expect(JSON.stringify(completed)).not.toContain('sensitive output');
  });
});
