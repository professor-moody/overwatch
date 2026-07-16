import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';
import type { EngagementConfig } from '../../types.js';
import type { PendingAction } from '../pending-action-queue.js';
import {
  ApplicationCommandService,
  withApplicationCommandInvocation,
} from '../application-command-service.js';
import { GraphEngine } from '../graph-engine.js';
import {
  OperatorCommandError,
  OperatorCommandService,
} from '../operator-command-service.js';

function config(): EngagementConfig {
  return {
    id: 'operator-command-test',
    name: 'Operator command test',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, enabled: true },
  };
}

function pending(actionId: string): Omit<
  PendingAction,
  'status' | 'submitted_at' | 'timeout_at'
> {
  return {
    action_id: actionId,
    description: `approval ${actionId}`,
    validation_result: 'valid',
    opsec_context: {
      global_noise_spent: 0,
      noise_budget_remaining: 1,
      recommended_approach: 'normal',
      defensive_signals: [],
    },
  };
}

describe('OperatorCommandService', () => {
  let directory: string;
  let engine: GraphEngine;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-operator-command-'));
    engine = new GraphEngine(config(), join(directory, 'state.json'));
  });

  afterEach(() => {
    engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  it('preserves a failed confirmation status and code on replay', () => {
    const planId = 'failed-plan';
    new ApplicationCommandService(engine).executeSync({
      command_kind: 'operator.plan.confirm',
      input: { plan_id: planId },
      schema: z.object({ plan_id: z.string() }).strict(),
      metadata: {
        idempotency_key: `plan-confirm:${planId}`,
        plan_id: planId,
      },
      execute: () => {
        throw new OperatorCommandError(
          'plan is no longer open',
          'PLAN_ALREADY_RESOLVED',
          409,
        );
      },
    });

    expect(() => new OperatorCommandService(engine).confirmPlan(planId)).toThrow(
      expect.objectContaining({
        code: 'PLAN_ALREADY_RESOLVED',
        http_status: 409,
      }),
    );
  });

  it('returns the same grammar plan for an idempotent preview retry', () => {
    const service = new OperatorCommandService(engine);
    const invoke = () => withApplicationCommandInvocation({
      transport: 'dashboard',
      command_id: 'grammar-preview-command',
      idempotency_key: 'grammar-preview-retry',
    }, () => service.createGrammarPlan(
      'add scope 10.0.1.0/24',
      [{ op: 'scope', add_cidrs: ['10.0.1.0/24'] }],
    ));

    const first = invoke();
    const second = invoke();

    expect(first.result?.plan_id).toBeDefined();
    expect(second).toMatchObject({
      command_id: first.command_id,
      replayed: true,
      result: { plan_id: first.result?.plan_id },
    });
  });

  it('registers one durable planner task and reuses it across retries', () => {
    const service = new OperatorCommandService(engine);
    const state = { tasks: [], pendingActionIds: [] };
    const first = withApplicationCommandInvocation({
      transport: 'dashboard',
      command_id: 'planner-command-one',
      idempotency_key: 'planner-request-one',
    }, () => service.requestPlanner(
      'investigate the strange box',
      state,
      { runtime_available: true },
    ));
    const exactRetry = withApplicationCommandInvocation({
      transport: 'dashboard',
      command_id: 'planner-command-one',
      idempotency_key: 'planner-request-one',
    }, () => service.requestPlanner(
      'investigate the strange box',
      state,
      { runtime_available: true },
    ));
    const semanticRetry = withApplicationCommandInvocation({
      transport: 'dashboard',
      command_id: 'planner-command-two',
      idempotency_key: 'planner-request-two',
    }, () => service.requestPlanner(
      '  INVESTIGATE   the strange box ',
      state,
      { runtime_available: true },
    ));

    expect(first.status).toBe('accepted');
    expect(first.result?.planner_task_id).toBeDefined();
    expect(exactRetry).toMatchObject({
      command_id: first.command_id,
      replayed: true,
      result: { planner_task_id: first.result?.planner_task_id },
    });
    expect(semanticRetry).toMatchObject({
      command_id: first.command_id,
      replayed: true,
      result: { planner_task_id: first.result?.planner_task_id },
    });
    expect(engine.getAgentTasks().filter(task => task.role === 'planner'))
      .toHaveLength(1);
    expect(engine.getTask(first.result!.planner_task_id!)).toMatchObject({
      application_command_id: first.command_id,
      agent_label: expect.stringMatching(/^planner-/),
    });
  });

  it('records planner unavailability as durable terminal truth', () => {
    const execution = new OperatorCommandService(engine).requestPlanner(
      'investigate the strange box',
      { tasks: [], pendingActionIds: [] },
      { runtime_available: false },
      {
        command_id: 'planner-unavailable-command',
        idempotency_key: 'planner-unavailable',
        transport: 'dashboard',
      },
    );

    expect(execution).toMatchObject({
      command_id: 'planner-unavailable-command',
      status: 'failed',
      error: {
        code: 'PLANNER_UNAVAILABLE',
        message: expect.stringContaining('headless runtime'),
      },
    });
    expect(engine.getAgentTasks().filter(task => task.role === 'planner'))
      .toHaveLength(0);
  });

  it('delivers only one resolution when a plan contains approve and deny for one action', async () => {
    const action = pending('approval-duplicate');
    engine.recordApprovalRequest(action);
    const waiter = engine.getPendingActionQueue().submit(action);
    const plan = engine.getProposedPlanStore().add({
      command: 'resolve the action twice',
      summary: 'conflicting approval operations',
      ops: [
        { op: 'approve', action_id: action.action_id },
        { op: 'deny', action_id: action.action_id, reason: 'duplicate denial' },
      ],
    });

    const execution = new OperatorCommandService(engine).confirmPlan(plan.plan_id);
    expect(execution.result?.results).toEqual([
      expect.objectContaining({ ok: true }),
      expect.objectContaining({
        ok: false,
        error: 'the plan resolves this action more than once',
      }),
    ]);
    await expect(waiter).resolves.toMatchObject({ status: 'approved' });
    expect(engine.getApprovalRequest(action.action_id)?.status).toBe('approved');
  });
});
