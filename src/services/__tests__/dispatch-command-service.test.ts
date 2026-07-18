import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import { DispatchCommandService } from '../dispatch-command-service.js';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal } from '../mutation-journal.js';

function config(): EngagementConfig {
  return {
    id: 'dispatch-command-test',
    name: 'Dispatch command test',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

describe('DispatchCommandService canonical identity', () => {
  let directory: string;
  let engine: GraphEngine;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-dispatch-command-'));
    engine = new GraphEngine(config(), join(directory, 'state.json'));
    engine.addNode({
      id: 'host-dispatch',
      type: 'host',
      label: 'dispatch host',
      ip: '10.0.0.12',
      discovered_at: '2026-07-16T00:00:00.000Z',
      confidence: 1,
    });
  });

  afterEach(() => {
    engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  it('returns and replays task_id and agent_label with legacy aliases', () => {
    const service = new DispatchCommandService(engine);
    const metadata = {
      command_id: 'dispatch-canonical-command',
      idempotency_key: 'dispatch-canonical-retry',
      transport: 'dashboard' as const,
    };
    const input = {
      agent_label: 'planner-helper',
      target_node_ids: ['host-dispatch'],
      objective: 'Inspect the target',
    };
    const first = service.dispatch(input, metadata);
    const replay = service.dispatch(input, metadata);
    const task = first.result?.body.task as Record<string, unknown>;

    expect(task).toMatchObject({
      task_id: expect.any(String),
      agent_label: 'planner-helper',
      id: expect.any(String),
      agent_id: 'planner-helper',
    });
    expect(task.task_id).toBe(task.id);
    expect(replay).toMatchObject({
      replayed: true,
      result: first.result,
    });
    expect(engine.getTask(String(task.task_id))).toMatchObject(task);
  });

  it('returns and replays canonical identity for quick deploy', () => {
    const service = new DispatchCommandService(engine);
    const metadata = {
      command_id: 'quick-deploy-canonical-command',
      idempotency_key: 'quick-deploy-canonical-retry',
      transport: 'dashboard' as const,
    };
    const input = { target: '10.0.0.22' };
    const first = service.quickDeploy(input, metadata);
    const replay = service.quickDeploy(input, metadata);
    const task = first.result?.task as unknown as Record<string, unknown>;

    expect(task).toMatchObject({
      task_id: expect.any(String),
      agent_label: expect.stringMatching(/^quick-/),
      id: expect.any(String),
      agent_id: expect.stringMatching(/^quick-/),
    });
    expect(task.task_id).toBe(task.id);
    expect(task.agent_label).toBe(task.agent_id);
    expect(replay).toMatchObject({
      replayed: true,
      result: first.result,
    });
    expect(engine.getTask(String(task.task_id))).toMatchObject(task);
  });

  it('journals out-of-scope quick deploy as scope, agent patch, and bounded command delta', () => {
    const statePath = join(directory, 'state.json');
    const retainedPlan = engine.createCommandPlan({
      command: 'retain this plan',
      ops: [],
      ttlMs: 60_000,
    });
    engine.flushNow();
    const checkpoint = JSON.parse(readFileSync(statePath, 'utf8')) as {
      journalSnapshotSeq: number;
    };
    new DispatchCommandService(engine).quickDeploy(
      { target: '10.0.1.22' },
      {
        command_id: 'quick-deploy-bounded-command',
        idempotency_key: 'quick-deploy-bounded-retry',
        transport: 'dashboard',
      },
    );

    const transaction = new MutationJournal(statePath)
      .readTransactionsSince(checkpoint.journalSnapshotSeq)
      .find(candidate => candidate.operations.some(operation =>
        operation.type === 'scope_updated'))!;
    expect(transaction.operations.map(operation => operation.type)).toEqual([
      'activity_append',
      'application_command_change',
      'scope_updated',
    ]);
    const scopePayload = transaction.operations[2]?.payload as {
      state_patch?: { slices?: Record<string, unknown> };
    };
    expect(scopePayload.state_patch?.slices).toHaveProperty('agents');
    expect(JSON.stringify(transaction.operations)).not.toContain('applicationCommands');
    expect(engine.getCommandPlan(retainedPlan)).toMatchObject({
      command: 'retain this plan',
    });
  });

  it('rolls back leading command and activity deltas when live scope apply fails', () => {
    const statePath = join(directory, 'state.json');
    engine.flushNow();
    const historyBefore = engine.getFullHistory().length;
    const applyScope = engine.applyScopeUpdatedMutation.bind(engine);
    vi.spyOn(engine, 'applyScopeUpdatedMutation').mockImplementationOnce((payload, recovery) => {
      applyScope(payload, recovery);
      throw new Error('synthetic scope apply failure');
    });

    const service = new DispatchCommandService(engine);
    expect(() => service.quickDeploy(
      { target: '10.0.4.22' },
      {
        command_id: 'quick-deploy-rollback-command',
        idempotency_key: 'quick-deploy-rollback-retry',
        transport: 'dashboard',
      },
    )).toThrow('synthetic scope apply failure');
    expect(engine.getConfig().scope.cidrs).not.toContain('10.0.4.22/32');
    expect(engine.getAgentTasks()).toHaveLength(0);
    expect(engine.listApplicationCommands().find(command =>
      command.command_id === 'quick-deploy-rollback-command')).toBeUndefined();
    expect(engine.getFullHistory()).toHaveLength(historyBefore);
    expect(engine.getPersistenceRecoveryStatus()).toMatchObject({ writable: false });

    vi.restoreAllMocks();
    engine.dispose();
    engine = new GraphEngine(config(), statePath);
    expect(engine.getPersistenceRecoveryStatus()).toMatchObject({ writable: true, complete: true });
    expect(engine.getConfig().scope.cidrs).toContain('10.0.4.22/32');
    expect(engine.getAgentTasks()).toHaveLength(1);
    expect(engine.listApplicationCommands().find(command =>
      command.command_id === 'quick-deploy-rollback-command')).toMatchObject({
      status: 'succeeded',
    });
  });
});
