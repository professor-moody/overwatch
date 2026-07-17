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
    expect(engine.getTask(first.result!.planner_task_id!)?.status).toBe('pending');
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
    expect(first.record.entity_refs?.planner_request_key)
      .toMatch(/^planner_[a-f0-9]{64}$/);
  });

  it('recovers a queued planner coherently and creates exactly one semantic retry after restart', () => {
    const stateFile = join(directory, 'state.json');
    const firstService = new OperatorCommandService(engine);
    const first = firstService.requestPlanner(
      'inspect the restart target',
      { tasks: [], pendingActionIds: [] },
      { runtime_available: true },
      {
        transport: 'dashboard',
        command_id: 'restart-planner-command',
        idempotency_key: 'restart-planner-request',
      },
    );
    const oldTaskId = first.result!.planner_task_id!;
    expect(engine.getTask(oldTaskId)?.status).toBe('pending');
    engine.flushNow();
    engine.dispose();

    engine = new GraphEngine(config(), stateFile);
    expect(new ApplicationCommandService(engine).recoverInterruptedCommands()).toBe(1);
    expect(engine.getApplicationCommandById(first.command_id)).toMatchObject({
      status: 'interrupted',
      error: { code: 'COMMAND_INTERRUPTED' },
    });
    expect(engine.getTask(oldTaskId)?.status).toBe('interrupted');

    const service = new OperatorCommandService(engine);
    const exactRetry = service.requestPlanner(
      'inspect the restart target',
      { tasks: [], pendingActionIds: [] },
      { runtime_available: true },
      {
        transport: 'dashboard',
        command_id: 'restart-planner-command',
        idempotency_key: 'restart-planner-request',
      },
    );
    expect(exactRetry).toMatchObject({
      command_id: first.command_id,
      status: 'interrupted',
      replayed: true,
      result: { planner_task_id: oldTaskId },
    });

    const semanticRetry = service.requestPlanner(
      '  INSPECT   THE RESTART TARGET ',
      { tasks: [], pendingActionIds: [] },
      { runtime_available: true },
      {
        transport: 'dashboard',
        command_id: 'restart-planner-command-2',
        idempotency_key: 'restart-planner-request-2',
      },
    );
    expect(semanticRetry.status).toBe('accepted');
    expect(semanticRetry.result?.planner_task_id).not.toBe(oldTaskId);
    expect(engine.getAgentTasks().filter(task => task.role === 'planner')).toHaveLength(2);
    expect(engine.getAgentTasks().filter(task =>
      task.role === 'planner' && task.status === 'pending')).toHaveLength(1);

    const staleProposal = withApplicationCommandInvocation({
      transport: 'mcp',
      actor_task_id: oldTaskId,
    }, () => service.submitProposal({
      task_id: oldTaskId,
      summary: 'stale worker proposal',
      ops: [{ op: 'scope', add_cidrs: ['10.66.0.0/24'] }],
    }));
    expect(staleProposal).toEqual({
      ok: false,
      error: expect.stringContaining(`planner task ${oldTaskId} is already interrupted`),
    });
    expect(engine.getProposedPlanStore().getOpen()).toHaveLength(0);
  });

  it('derives the canonical command from durable ownership when a planner omits it', () => {
    const service = new OperatorCommandService(engine);
    engine.registerAgent({
      id: 'target-task',
      task_id: 'target-task',
      agent_id: 'target-agent',
      agent_label: 'target-agent',
      assigned_at: engine.now(),
      status: 'running',
      backend: 'manual',
      subgraph_node_ids: [],
    });
    const requested = service.requestPlanner(
      'pause the target agent',
      {
        tasks: [{
          task_id: 'target-task',
          agent_label: 'target-agent',
          id: 'target-task',
          agent_id: 'target-agent',
          status: 'running',
        }],
        pendingActionIds: [],
      },
      { runtime_available: true },
      {
        transport: 'dashboard',
        command_id: 'canonical-planner-command',
        idempotency_key: 'canonical-planner-request',
      },
    );
    const plannerTaskId = requested.result!.planner_task_id!;
    const proposal = withApplicationCommandInvocation({
      transport: 'mcp',
      actor_task_id: plannerTaskId,
    }, () => service.submitProposal({
      summary: 'Pause the target.',
      ops: [{
        op: 'directive',
        task_id: 'target-task',
        agent_label: 'target-agent',
        kind: 'pause',
      }],
    }));

    expect(proposal.ok).toBe(true);
    const plan = proposal.ok
      ? engine.getProposedPlanStore().get(proposal.plan_id)
      : undefined;
    expect(plan).toMatchObject({
      command: 'pause the target agent',
      owner_task_id: plannerTaskId,
      command_id: requested.command_id,
    });

    const retry = service.requestPlanner(
      '  PAUSE   the target agent ',
      { tasks: [], pendingActionIds: [] },
      { runtime_available: true },
      {
        transport: 'dashboard',
        command_id: 'canonical-planner-retry',
        idempotency_key: 'canonical-planner-retry',
      },
    );
    expect(retry).toMatchObject({
      command_id: requested.command_id,
      result: { phase: 'plan_ready', plan_id: plan?.plan_id },
    });
    expect(engine.getAgentTasks().filter(task => task.role === 'planner'))
      .toHaveLength(1);
  });

  it('rejects a planner proposal that echoes a different operator command', () => {
    const service = new OperatorCommandService(engine);
    const requested = service.requestPlanner(
      'inspect alpha',
      { tasks: [], pendingActionIds: [] },
      { runtime_available: true },
      {
        command_id: 'mismatch-planner-command',
        idempotency_key: 'mismatch-planner-request',
      },
    );
    const plannerTaskId = requested.result!.planner_task_id!;
    const result = withApplicationCommandInvocation({
      transport: 'mcp',
      actor_task_id: plannerTaskId,
    }, () => service.submitProposal({
      command: 'inspect beta',
      summary: 'No-op scope preview.',
      ops: [{ op: 'scope', add_cidrs: ['10.0.0.0/24'] }],
    }));

    expect(result).toEqual({
      ok: false,
      error: `proposal command does not match owning planner command ${requested.command_id}`,
    });
    expect(engine.getProposedPlanStore().getOpen()).toHaveLength(0);
  });

  it('does not let an actorless MCP connection claim a planner with body aliases', () => {
    const service = new OperatorCommandService(engine);
    const requested = service.requestPlanner(
      'inspect the isolated target',
      { tasks: [], pendingActionIds: [] },
      { runtime_available: true },
      { command_id: 'isolated-command', idempotency_key: 'isolated-request' },
    );
    const plannerTaskId = requested.result!.planner_task_id!;
    const planner = engine.getTask(plannerTaskId)!;

    const result = withApplicationCommandInvocation({
      transport: 'mcp',
      actor_task_id: null,
    }, () => service.submitProposal({
      task_id: plannerTaskId,
      agent_id: planner.agent_id,
      summary: 'spoofed proposal',
      ops: [{ op: 'scope', add_cidrs: ['10.88.0.0/24'] }],
    }));

    expect(result).toEqual({
      ok: false,
      error: expect.stringContaining('authenticated planner task'),
    });
    expect(engine.getProposedPlanStore().getOpen()).toHaveLength(0);
    expect(engine.getApplicationCommandById(requested.command_id)?.status).toBe('accepted');
  });

  it('rejects a proposal from a planner task that already completed', () => {
    const service = new OperatorCommandService(engine);
    const requested = service.requestPlanner(
      'finish before proposing',
      { tasks: [], pendingActionIds: [] },
      { runtime_available: true },
      { command_id: 'completed-first-command', idempotency_key: 'completed-first-request' },
    );
    const plannerTaskId = requested.result!.planner_task_id!;
    expect(engine.updateAgentStatus(plannerTaskId, 'completed', 'incorrect early completion')).toBe(true);

    const result = withApplicationCommandInvocation({
      transport: 'mcp',
      actor_task_id: plannerTaskId,
    }, () => service.submitProposal({
      task_id: plannerTaskId,
      summary: 'late after completion',
      ops: [{ op: 'scope', add_cidrs: ['10.89.0.0/24'] }],
    }));

    expect(result).toEqual({
      ok: false,
      error: expect.stringContaining('already completed'),
    });
    expect(engine.getProposedPlanStore().getOpen()).toHaveLength(0);
  });

  it('surfaces ambiguous legacy active planners instead of choosing one by insertion order', () => {
    const commands = new ApplicationCommandService(engine);
    for (const suffix of ['a', 'b']) {
      commands.reserveSync({
        command_kind: 'operator.plan',
        input: { command: 'inspect the ambiguous host' },
        schema: z.object({ command: z.string() }).strict(),
        metadata: {
          command_id: `legacy-ambiguous-${suffix}`,
          idempotency_key: `legacy-ambiguous-${suffix}`,
        },
        reserve: () => ({
          status: 'accepted',
          result: { phase: 'planning_queued' },
        }),
      });
    }

    expect(() => new OperatorCommandService(engine).requestPlanner(
      'INSPECT   the ambiguous host',
      { tasks: [], pendingActionIds: [] },
      { runtime_available: true },
    )).toThrow(expect.objectContaining({
      code: 'PLANNER_REQUEST_AMBIGUOUS',
      http_status: 409,
    }));
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
