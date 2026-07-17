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
      bindings: { account_id: '123456789012' },
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

    service.beginAttemptExecution(claim.execution);
    const failed = service.finishAttempt(opened.run.run_id, 'identity', claim.attempt.attempt_id, {
      execution_outcome: 'succeeded',
      parse_outcome: 'no_data',
      action_id: claim.attempt.execution_action_id,
      evidence_ids: ['ev-1'],
      finding_ids: [],
      error: 'The requested parser yielded no artifacts.',
    });
    expect(failed.status).toBe('failed');
    expect(failed.steps[0].status).toBe('failed');
    expect(() => service.resume(opened.run.run_id)).toThrow(/cannot be resumed/);

    const retry = service.retryStep(opened.run.run_id, 'identity');
    service.beginAttemptExecution(retry.execution);
    const completed = service.finishAttempt(opened.run.run_id, 'identity', retry.attempt.attempt_id, {
      execution_outcome: 'succeeded',
      parse_outcome: 'ok',
      action_id: retry.attempt.execution_action_id,
      evidence_ids: ['ev-2'],
      finding_ids: ['finding-2'],
    });
    expect(completed.steps[0].attempts).toHaveLength(2);
    expect(completed.steps[0].attempts[0]).toMatchObject({ action_id: claim.attempt.execution_action_id, evidence_ids: ['ev-1'] });
    expect(completed.steps[0].attempts[1]).toMatchObject({ action_id: retry.attempt.execution_action_id, finding_ids: ['finding-2'] });
    expect(completed.steps.find(step => step.step_id === 'inventory')?.status).toBe('pending');
  });

  it('retains partial parse reporting while allowing retained artifacts to satisfy dependencies', () => {
    const service = new PlaybookRunService(openEngine());
    const opened = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      bindings: { account_id: '123456789012' },
      steps: baseSteps(true),
    });
    const claim = service.startStep(opened.run.run_id, 'identity');
    service.beginAttemptExecution(claim.execution);
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
    service.beginAttemptExecution(claim.execution);
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
    }, () => {
      service.beginAttemptExecution(retry.execution);
      return service.finishAttempt(opened.run.run_id, 'identity', retry.attempt.attempt_id, {
        execution_outcome: 'succeeded', parse_outcome: 'ok',
      });
    });
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

  it('retains skips without reporting an all-skipped run as executed completion', () => {
    const service = new PlaybookRunService(openEngine());
    const opened = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: [baseSteps(true)[0]],
    });
    const skipped = service.skipStep(opened.run.run_id, 'identity', 'Not relevant to this engagement.');
    expect(skipped).toMatchObject({ status: 'skipped', report_status: 'partial' });
    expect(skipped.steps[0]).toMatchObject({ status: 'skipped', blocked_reason: 'Not relevant to this engagement.' });
    expect(service.list({ open_only: true })).not.toContainEqual(expect.objectContaining({ run_id: opened.run.run_id }));
    expect(() => service.skipStep(opened.run.run_id, 'identity', 'Rewrite reason')).toThrow(/already skipped/);
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
    firstService.beginAttemptExecution(claim.execution);
    const recoveredEvidenceId = firstEngine.getEvidenceStore().store({
      action_id: claim.attempt.execution_action_id,
      evidence_type: 'command_output',
      raw_output: 'captured before the terminal playbook write',
    });
    firstEngine.logActionEvent({
      action_id: claim.attempt.execution_action_id,
      event_type: 'finding_ingested',
      description: 'Finding committed before restart',
      category: 'finding',
      linked_finding_ids: ['finding-before-restart'],
      result_classification: 'success',
    });
    firstEngine.logActionEvent({
      action_id: claim.attempt.execution_action_id,
      event_type: 'parse_output',
      description: 'A failed parse referenced no landed finding',
      category: 'finding',
      linked_finding_ids: ['phantom-no-data-finding'],
      result_classification: 'failure',
    });
    closeEngine(firstEngine);

    const secondEngine = openEngine();
    const secondService = new PlaybookRunService(secondEngine);
    expect(secondService.recoverInterruptedRuns()).toBe(1);
    const interrupted = secondService.getDurable(opened.run.run_id);
    expect(interrupted.steps[0].attempts[0]).toMatchObject({
      attempt_id: claim.attempt.attempt_id,
      status: 'interrupted',
      execution_outcome: 'interrupted',
      evidence_ids: [recoveredEvidenceId],
      finding_ids: ['finding-before-restart'],
    });
    const resumed = secondService.resume(opened.run.run_id);
    expect(resumed.status).toBe('pending');
    expect(resumed.resume_count).toBe(1);
    expect(resumed.steps[0].attempts).toHaveLength(1);
    expect(resumed.steps[0].completed_at).toBeUndefined();
    const retry = secondService.retryStep(opened.run.run_id, 'identity');
    expect(retry.attempt).toMatchObject({ attempt_number: 2, status: 'claimed' });
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
    service.beginAttemptExecution(claim.execution);
    const completed = finishPlaybookAttemptFromToolResponse(engine, claim.execution, {
      content: [{
        type: 'text',
        text: JSON.stringify({
          action_id: claim.attempt.execution_action_id,
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
      action_id: claim.attempt.execution_action_id,
      evidence_ids: ['ev-auto'],
      finding_ids: ['finding-auto'],
      parse_outcome: 'ok',
    });
    expect(JSON.stringify(completed)).not.toContain('sensitive output');
  });

  it('enforces server-resolved binding values even when a descriptor claims readiness', () => {
    const service = new PlaybookRunService(openEngine());
    const input = {
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: [{
        step: 1,
        step_id: 'bound-step',
        description: 'Bound step',
        command: 'run-bound-step',
        runner: 'run_bash',
        ready: true,
        status: 'ready',
        required_bindings: ['account_id', 'principal_kind=role'],
      }],
    };
    const blocked = service.open(input);
    expect(blocked.run.steps[0]).toMatchObject({
      status: 'blocked',
      blocked_reason: 'Waiting for bindings: account_id, principal_kind=role',
      resolved_bindings: {},
    });

    const rebound = service.open({
      ...input,
      bindings: { account_id: '123456789012', principal_kind: 'role' },
    });
    expect(rebound).toMatchObject({ created: false, run: { run_id: blocked.run.run_id } });
    expect(rebound.run.steps[0]).toMatchObject({
      status: 'pending',
      resolved_bindings: { account_id: '123456789012', principal_kind: 'role' },
    });
  });

  it('reuses a completed logical run when newly discovered bindings extend its immutable plan', () => {
    const service = new PlaybookRunService(openEngine());
    const first = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: { mode: 'discovery' },
      steps: [baseSteps(true)[0]],
    });
    const claim = service.startStep(first.run.run_id, 'identity');
    service.beginAttemptExecution(claim.execution);
    const completed = service.finishAttempt(first.run.run_id, 'identity', claim.attempt.attempt_id, {
      execution_outcome: 'succeeded', parse_outcome: 'ok', finding_ids: ['finding-identity'],
    });
    expect(completed.status).toBe('succeeded');

    const extended = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: { mode: 'discovery' },
      bindings: { account_id: '123456789012' },
      steps: [
        baseSteps(true)[0],
        {
          ...baseSteps(true)[1],
          depends_on: ['identity'],
          required_bindings: ['account_id'],
        },
      ],
    });
    expect(extended.created).toBe(false);
    expect(extended.run.run_id).toBe(first.run.run_id);
    expect(extended.run.plan_revisions).toHaveLength(2);
    expect(extended.run.steps[0].status).toBe('succeeded');
    expect(extended.run.steps[1].status).toBe('pending');
  });

  it('retains superseded steps as non-actionable history', () => {
    const service = new PlaybookRunService(openEngine());
    const first = service.open({
      definition, credential_id: 'cred-1', normalized_inputs: {},
      steps: [{ ...baseSteps(true)[0], step_id: 'step-a', command: 'command-a' }],
    });
    const claim = service.startStep(first.run.run_id, 'step-a');
    service.beginAttemptExecution(claim.execution);
    service.finishAttempt(first.run.run_id, 'step-a', claim.attempt.attempt_id, {
      execution_outcome: 'failed', error: 'retry later',
    });

    const narrowed = service.open({
      definition, credential_id: 'cred-1', normalized_inputs: {},
      steps: [{ ...baseSteps(true)[0], step_id: 'step-b', command: 'command-b' }],
    });
    expect(narrowed.run.current_plan_revision).toBe(2);
    expect(narrowed.run.steps.find(step => step.step_id === 'step-a')).toMatchObject({
      status: 'cancelled',
      blocked_reason: 'Superseded by playbook plan revision 2.',
      attempts: [{ status: 'failed', plan_revision: 1 }],
    });
    expect(() => service.startStep(first.run.run_id, 'step-a')).toThrow(/not actionable in current plan revision 2/);
    expect(() => service.retryStep(first.run.run_id, 'step-a')).toThrow(/not actionable in current plan revision 2/);
    expect(narrowed.run.plan_revisions[0].steps.map(step => step.step_id)).toContain('step-a');
    expect(narrowed.run.plan_revisions[1].steps.map(step => step.step_id)).not.toContain('step-a');
  });

  it('reactivates a superseded step only after a later plan emits it again', () => {
    const service = new PlaybookRunService(openEngine());
    const first = service.open({
      definition, credential_id: 'cred-1', normalized_inputs: {},
      steps: [{ ...baseSteps(true)[0], step_id: 'step-a', command: 'command-a' }],
    });
    service.open({
      definition, credential_id: 'cred-1', normalized_inputs: {},
      steps: [{ ...baseSteps(true)[0], step_id: 'step-b', command: 'command-b' }],
    });
    const restored = service.open({
      definition, credential_id: 'cred-1', normalized_inputs: {},
      steps: [{ ...baseSteps(true)[0], step_id: 'step-a', command: 'command-a' }],
    });

    expect(restored.run.steps.find(step => step.step_id === 'step-a')).toMatchObject({ status: 'pending' });
    expect(restored.run.steps.find(step => step.step_id === 'step-b')).toMatchObject({ status: 'cancelled' });
    const claim = service.startStep(first.run.run_id, 'step-a');
    expect(claim.attempt.plan_revision).toBe(restored.run.current_plan_revision);
  });

  it.each(['failed', 'succeeded'] as const)(
    'restores a re-emitted identical step to its retained %s outcome',
    outcome => {
      const service = new PlaybookRunService(openEngine());
      const first = service.open({
        definition, credential_id: 'cred-1', normalized_inputs: {},
        steps: [{ ...baseSteps(true)[0], step_id: 'repeat', command: 'repeat-command' }],
      });
      const claim = service.startStep(first.run.run_id, 'repeat');
      service.beginAttemptExecution(claim.execution);
      service.finishAttempt(first.run.run_id, 'repeat', claim.attempt.attempt_id, {
        execution_outcome: outcome === 'succeeded' ? 'succeeded' : 'failed',
        ...(outcome === 'succeeded' ? { parse_outcome: 'ok' as const } : { error: 'retry later' }),
      });
      service.open({
        definition, credential_id: 'cred-1', normalized_inputs: {},
        steps: [{ ...baseSteps(true)[0], step_id: 'replacement', command: 'replacement-command' }],
      });
      const restored = service.open({
        definition, credential_id: 'cred-1', normalized_inputs: {},
        steps: [{ ...baseSteps(true)[0], step_id: 'repeat', command: 'repeat-command' }],
      });

      expect(restored.run.steps.find(step => step.step_id === 'repeat')).toMatchObject({ status: outcome });
      if (outcome === 'failed') {
        const retry = service.retryStep(first.run.run_id, 'repeat');
        expect(retry.attempt).toMatchObject({ attempt_number: 2, plan_revision: restored.run.current_plan_revision });
      } else {
        expect(restored.run.status).toBe('succeeded');
        expect(() => service.startStep(first.run.run_id, 'repeat')).toThrow(/use retry for a prior failed attempt/);
        expect(() => service.retryStep(first.run.run_id, 'repeat')).toThrow(/only failed or interrupted steps can be retried/);
      }
    },
  );

  it('reopens a succeeded logical step when its execution semantics change', () => {
    const service = new PlaybookRunService(openEngine());
    const first = service.open({
      definition, credential_id: 'cred-1', normalized_inputs: {},
      steps: [{ ...baseSteps(true)[0], command: 'old-command' }],
    });
    const claim = service.startStep(first.run.run_id, 'identity');
    service.beginAttemptExecution(claim.execution);
    service.finishAttempt(first.run.run_id, 'identity', claim.attempt.attempt_id, {
      execution_outcome: 'succeeded', parse_outcome: 'ok',
    });

    const changed = service.open({
      definition, credential_id: 'cred-1', normalized_inputs: {},
      steps: [{ ...baseSteps(true)[0], command: 'new-command' }],
    });
    expect(changed.run).toMatchObject({ status: 'pending', current_plan_revision: 2 });
    expect(changed.run.steps[0]).toMatchObject({ status: 'pending', attempts: [{ status: 'succeeded' }] });
    const rerun = service.retryStep(first.run.run_id, 'identity');
    expect(rerun.attempt).toMatchObject({ attempt_number: 2, plan_revision: 2 });
    expect(rerun.attempt.execution_template_hash).not.toBe(claim.attempt.execution_template_hash);
  });

  it('records approval and execution transitions against the exact immutable plan revision', () => {
    const service = new PlaybookRunService(openEngine());
    const opened = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: [baseSteps(true)[0]],
    });
    const claim = service.startStep(opened.run.run_id, 'identity');
    expect(claim.attempt).toMatchObject({
      status: 'claimed',
      plan_revision: 1,
      execution_template_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    const awaiting = service.markAttemptExecutionState(claim.execution, 'awaiting_approval');
    expect(awaiting).toMatchObject({ status: 'awaiting_approval', steps: [{ status: 'awaiting_approval' }] });
    const running = service.markAttemptExecutionState(claim.execution, 'running');
    expect(running).toMatchObject({ status: 'running', steps: [{ status: 'running' }] });
  });

  it('accepts only exact credential environment resolution for a claimed runner', () => {
    const engine = openEngine();
    engine.addNode({
      id: 'cred-env', type: 'credential', label: 'Credential environment',
      confidence: 1, discovered_at: engine.now(), cred_type: 'token',
      cred_value: 'resolved-secret-value',
    } as any);
    const service = new PlaybookRunService(engine);
    const opened = service.open({
      definition,
      credential_id: 'cred-env',
      normalized_inputs: {},
      steps: [{
        step_id: 'credential-command', description: 'Use credential environment',
        runner: 'run_bash', command: 'credential-command',
        env_from_credential: { OVERWATCH_TOKEN: 'cred-env' },
        ready: true, status: 'ready',
      }],
    });
    const claim = service.startStep(opened.run.run_id, 'credential-command');
    expect(() => service.validateAttemptLinkage({
      ...claim.execution,
      env: { OVERWATCH_TOKEN: 'resolved-secret-value' },
      validate: true,
    } as any)).not.toThrow();
    for (const env of [
      { OVERWATCH_TOKEN: 'wrong-value' },
      { OVERWATCH_TOKEN: 'cred-env' },
      { OVERWATCH_TOKEN: 'resolved-secret-value', EXTRA: 'unexpected' },
      {},
    ]) {
      expect(() => service.validateAttemptLinkage({
        ...claim.execution, env, validate: true,
      } as any)).toThrow(/unclaimed execution field env/);
    }
  });

  it('seals direct-tool arguments as well as process runner descriptors', () => {
    const service = new PlaybookRunService(openEngine());
    const opened = service.open({
      definition: { ...definition, provider: 'oidc' },
      credential_id: 'cred-direct', normalized_inputs: {},
      steps: [{
        step_id: 'replay', description: 'Replay token', tool: 'validate_token_credential',
        args: { credential_id: 'cred-direct', provider: 'aws_sts' },
        ready: true, status: 'ready',
      }],
    });
    const claim = service.startStep(opened.run.run_id, 'replay');
    const args = claim.execution.args as Record<string, unknown>;
    expect(() => service.validateAttemptLinkage(args)).not.toThrow();
    for (const mutation of [
      { endpoint: 'https://example.invalid/' },
      { extra_args: ['--data', 'changed'] },
      { allow_audience_mismatch: true },
    ]) {
      expect(() => service.validateAttemptLinkage({ ...args, ...mutation }))
        .toThrow(/unclaimed execution field/);
    }
  });

  it('rejects terminal descriptors whose command has no matching replay response', () => {
    const engine = openEngine();
    const service = new PlaybookRunService(engine);
    const opened = service.open({
      definition, credential_id: 'cred-terminal-replay', normalized_inputs: {},
      steps: [{ ...baseSteps(true)[0], command: 'terminal-command' }],
    });
    const claim = service.startStep(opened.run.run_id, 'identity');
    service.beginAttemptExecution(claim.execution);
    service.finishAttempt(opened.run.run_id, 'identity', claim.attempt.attempt_id, {
      execution_outcome: 'interrupted', error: 'Daemon restarted before completion.',
    });
    engine.recordApplicationCommand({
      command_id: claim.attempt.execution_command_id,
      idempotency_key: 'idem-terminal-replay',
      input_sha256: 'a'.repeat(64),
      validated_input: {},
      command_kind: 'process.execute',
      transport: 'system',
      actor_task_id: null,
      action_id: claim.attempt.execution_action_id,
      status: 'succeeded',
      created_at: engine.now(),
      completed_at: engine.now(),
      result: {
        response_evidence_id: 'response-from-completed-process',
        action_id: claim.attempt.execution_action_id,
        is_error: false,
        executed: true,
      },
    });
    expect(() => service.validateAttemptLinkage(claim.execution))
      .toThrow(/only a matching succeeded command with a retained response can replay/);
    expect(service.getDurable(opened.run.run_id).steps[0].attempts).toEqual([
      expect.objectContaining({ status: 'interrupted', execution_outcome: 'interrupted' }),
    ]);
  });

  it('rejects success before execution but durably closes a pre-execution validation failure', () => {
    const service = new PlaybookRunService(openEngine());
    const opened = service.open({
      definition,
      credential_id: 'cred-1',
      normalized_inputs: {},
      steps: [baseSteps(true)[0]],
    });
    const claim = service.startStep(opened.run.run_id, 'identity');
    expect(() => service.finishAttempt(opened.run.run_id, 'identity', claim.attempt.attempt_id, {
      execution_outcome: 'succeeded', parse_outcome: 'ok',
    })).toThrow(/has not crossed the execution boundary/);
    const failed = service.finishAttempt(opened.run.run_id, 'identity', claim.attempt.attempt_id, {
      execution_outcome: 'failed', error: 'Validation failed before execution.',
    });
    expect(failed.steps[0].attempts[0]).toMatchObject({
      status: 'failed',
      execution_outcome: 'failed',
      error: 'Validation failed before execution.',
    });
  });
});
