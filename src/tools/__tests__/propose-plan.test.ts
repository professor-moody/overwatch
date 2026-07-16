import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { z } from 'zod';
import { GraphEngine } from '../../services/graph-engine.js';
import { ApplicationCommandService } from '../../services/application-command-service.js';
import { recordProposedPlan, validateProposedOps } from '../propose-plan.js';
import type { EngagementConfig, AgentTask } from '../../types.js';
import type { OperatorOp } from '../../services/command-interpreter.js';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-pp', name: 'pp test', created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [], opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

const runningTask = (id: string, agent_id: string): AgentTask => ({
  id, agent_id, assigned_at: new Date().toISOString(), status: 'running', subgraph_node_ids: [],
});

describe('propose_plan — validation + recording', () => {
  let engine: GraphEngine;
  let testDir: string;
  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-propose-plan-'));
    engine = new GraphEngine(makeConfig(), join(testDir, 'state.json'));
  });
  afterEach(() => {
    engine.dispose();
    rmSync(testDir, { recursive: true, force: true });
  });

  it('validates + stores a plan that targets a real running task', () => {
    engine.registerAgent(runningTask('task-1', 'a1'));
    engine.registerAgent(runningTask('planner-task', 'planner-x'));
    const r = recordProposedPlan(engine, {
      agent_id: 'planner-x', task_id: 'planner-task', command: 'pause a1',
      summary: 'pause a1', ops: [{ op: 'directive', task_id: 'task-1', agent_label: 'a1', kind: 'pause' }],
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(engine.getProposedPlanStore().get(r.plan_id)).toMatchObject({
        command: 'pause a1',
        owner_task_id: 'planner-task',
        owner_agent_label: 'planner-x',
        source_task_id: 'planner-task',
        source_agent_id: 'planner-x',
      });
      expect(engine.getProposedPlanStore().getOpen()).toHaveLength(1);
    }
  });

  it('emits a plan_proposed activity event', () => {
    engine.registerAgent(runningTask('task-1', 'a1'));
    recordProposedPlan(engine, {
      summary: 'pause', ops: [{ op: 'directive', task_id: 'task-1', agent_label: 'a1', kind: 'pause' }],
    });
    const events = engine.getFullHistory().filter(e => e.event_type === 'plan_proposed');
    expect(events).toHaveLength(1);
  });

  it('returns the original plan when one planner command proposes twice', () => {
    engine.registerAgent(runningTask('task-1', 'a1'));
    const commands = new ApplicationCommandService(engine);
    commands.reserveSync({
      command_kind: 'operator.plan',
      input: { command: 'pause a1' },
      schema: z.object({ command: z.string() }).strict(),
      metadata: {
        command_id: 'planner-command-1',
        idempotency_key: 'planner-command-1',
      },
      reserve: () => ({
        status: 'running',
        result: { phase: 'planning_running', planner_task_id: 'planner-task' },
      }),
    });
    engine.registerAgent({
      ...runningTask('planner-task', 'planner-x'),
      role: 'planner',
      application_command_id: 'planner-command-1',
    });
    const args = {
      task_id: 'planner-task',
      command: 'pause a1',
      summary: 'pause a1',
      ops: [{ op: 'directive' as const, task_id: 'task-1', agent_label: 'a1', kind: 'pause' as const }],
    };

    const first = recordProposedPlan(engine, args);
    const second = recordProposedPlan(engine, {
      ...args,
      summary: 'a conflicting duplicate summary',
    });

    expect(first.ok).toBe(true);
    expect(second).toMatchObject({
      ok: true,
      plan_id: first.ok ? first.plan_id : '',
      summary: 'pause a1',
    });
    expect(engine.getProposedPlanStore().getOpen()).toHaveLength(1);
    expect(engine.getFullHistory().filter(event => event.event_type === 'plan_proposed')).toHaveLength(1);
  });

  it('infers exactly one matching command-owned planner when legacy input omits identity', () => {
    engine.registerAgent(runningTask('task-1', 'a1'));
    new ApplicationCommandService(engine).reserveSync({
      command_kind: 'operator.plan',
      input: { command: 'pause a1' },
      schema: z.object({ command: z.string() }).strict(),
      metadata: {
        command_id: 'planner-command-inferred',
        idempotency_key: 'planner-command-inferred',
      },
      reserve: () => ({
        status: 'running',
        result: {
          phase: 'planning_running',
          planner_task_id: 'planner-inferred',
        },
      }),
    });
    engine.registerAgent({
      ...runningTask('planner-inferred', 'planner-inferred'),
      role: 'planner',
      application_command_id: 'planner-command-inferred',
      objective: 'OPERATOR COMMAND (free-form): "pause a1"',
    });

    const result = recordProposedPlan(engine, {
      command: 'pause a1',
      summary: 'pause a1',
      ops: [{
        op: 'directive',
        task_id: 'task-1',
        agent_label: 'a1',
        kind: 'pause',
      }],
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(engine.getProposedPlanStore().get(result.plan_id)).toMatchObject({
        owner_task_id: 'planner-inferred',
        command_id: 'planner-command-inferred',
      });
    }
    expect(engine.getApplicationCommandById('planner-command-inferred')?.status)
      .toBe('succeeded');
  });

  it('rejects ownerless proposals when multiple command-owned planners match', () => {
    engine.registerAgent(runningTask('task-1', 'a1'));
    for (const suffix of ['a', 'b']) {
      const commandId = `planner-command-${suffix}`;
      new ApplicationCommandService(engine).reserveSync({
        command_kind: 'operator.plan',
        input: { command: 'pause a1' },
        schema: z.object({ command: z.string() }).strict(),
        metadata: {
          command_id: commandId,
          idempotency_key: commandId,
        },
        reserve: () => ({
          status: 'running',
          result: {
            phase: 'planning_running',
            planner_task_id: `planner-${suffix}`,
          },
        }),
      });
      engine.registerAgent({
        ...runningTask(`planner-${suffix}`, `planner-${suffix}`),
        role: 'planner',
        application_command_id: commandId,
        objective: 'OPERATOR COMMAND (free-form): "pause a1"',
      });
    }
    expect(recordProposedPlan(engine, {
      command: 'pause a1',
      summary: 'pause a1',
      ops: [{
        op: 'directive',
        task_id: 'task-1',
        agent_label: 'a1',
        kind: 'pause',
      }],
    })).toEqual({
      ok: false,
      error: 'planner task identity is ambiguous; pass the exact task_id',
    });
  });

  it('rejects a late proposal after its durable planner command failed', () => {
    engine.registerAgent(runningTask('task-1', 'a1'));
    const commands = new ApplicationCommandService(engine);
    commands.reserveSync({
      command_kind: 'operator.plan',
      input: { command: 'pause a1' },
      schema: z.object({ command: z.string() }).strict(),
      metadata: {
        command_id: 'planner-command-failed',
        idempotency_key: 'planner-command-failed',
      },
      reserve: () => ({
        status: 'accepted',
        result: { phase: 'planning_queued', planner_task_id: 'planner-failed' },
      }),
    });
    commands.transition('planner-command-failed', {
      status: 'failed',
      error: { code: 'PLANNER_NO_PLAN', message: 'planner failed' },
    });
    engine.registerAgent({
      ...runningTask('planner-failed', 'planner-failed'),
      role: 'planner',
      application_command_id: 'planner-command-failed',
    });

    const result = recordProposedPlan(engine, {
      task_id: 'planner-failed',
      command: 'pause a1',
      summary: 'late plan',
      ops: [{ op: 'directive', task_id: 'task-1', agent_label: 'a1', kind: 'pause' }],
    });

    expect(result).toEqual({
      ok: false,
      error: 'planner command planner-command-failed is already failed; no new plan can be attached',
    });
    expect(engine.getProposedPlanStore().getOpen()).toHaveLength(0);
  });

  it('attaches a scope-impact preview for a plan with a scope op', () => {
    // Seed an in-scope host, then preview an exclusion that would push it out.
    engine.ingestFinding({
      id: 'f1', agent_id: 'a1', timestamp: new Date().toISOString(),
      nodes: [{ id: 'host-10-10-10-50', type: 'host', label: '10.10.10.50', ip: '10.10.10.50', alive: true, discovered_at: new Date().toISOString(), confidence: 1.0 }], edges: [],
    } as never);
    const r = recordProposedPlan(engine, {
      summary: 'tighten scope', ops: [{ op: 'scope', add_exclusions: ['10.10.10.50'] }],
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.scope_preview).toBeDefined();
      // the seeded in-scope host transitions OUT under the proposed exclusion
      expect(r.scope_preview?.newly_excluded_count).toBeGreaterThanOrEqual(1);
      // the preview is persisted on the stored plan (the confirm UI reads it)
      expect(engine.getProposedPlanStore().get(r.plan_id)?.scope_preview?.newly_excluded_count).toBeGreaterThanOrEqual(1);
    }
  });

  it('omits scope_preview for a plan with no scope ops', () => {
    engine.registerAgent(runningTask('task-1', 'a1'));
    const r = recordProposedPlan(engine, {
      summary: 'pause', ops: [{ op: 'directive', task_id: 'task-1', agent_label: 'a1', kind: 'pause' }],
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.scope_preview).toBeUndefined();
  });

  it('REJECTS the whole plan when a directive targets a non-existent task', () => {
    const r = recordProposedPlan(engine, {
      summary: 'pause ghost', ops: [{ op: 'directive', task_id: 'ghost', agent_label: '?', kind: 'pause' }],
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected?.[0].reason).toMatch(/no agent task/);
    // nothing stored — a confirmed plan can never no-op
    expect(engine.getProposedPlanStore().size()).toBe(0);
  });

  it('rejects ambiguous legacy planner labels instead of guessing an owner', () => {
    engine.registerAgent(runningTask('planner-a', 'shared-planner'));
    engine.registerAgent(runningTask('planner-b', 'shared-planner'));
    engine.registerAgent(runningTask('task-1', 'target'));
    const result = recordProposedPlan(engine, {
      agent_id: 'shared-planner',
      summary: 'pause target',
      ops: [{ op: 'directive', task_id: 'task-1', agent_label: 'target', kind: 'pause' }],
    });
    expect(result).toEqual({
      ok: false,
      error: 'agent label "shared-planner" is ambiguous; pass the exact task_id',
    });
  });

  it('rejects conflicting planner identity aliases', () => {
    engine.registerAgent(runningTask('planner-task', 'planner-x'));
    engine.registerAgent(runningTask('task-1', 'target'));
    const result = recordProposedPlan(engine, {
      task_id: 'planner-task',
      agent_id: 'different-planner',
      summary: 'pause target',
      ops: [{ op: 'directive', task_id: 'task-1', agent_label: 'target', kind: 'pause' }],
    });
    expect(result).toEqual({
      ok: false,
      error: 'agent_id "different-planner" does not match planner task planner-task (planner-x)',
    });
  });

  it('REJECTS a directive that targets a task which is not running', () => {
    engine.registerAgent({ ...runningTask('task-done', 'a1'), status: 'completed' });
    const rejected = validateProposedOps(engine, [{ op: 'directive', task_id: 'task-done', agent_label: 'a1', kind: 'stop' }]);
    expect(rejected[0].reason).toMatch(/not running/);
  });

  it('REJECTS approve/deny of an action that is not pending', () => {
    const rejected = validateProposedOps(engine, [{ op: 'approve', action_id: 'nope' }]);
    expect(rejected[0].reason).toMatch(/no pending action/);
  });

  it('REJECTS a scope op that adds nothing', () => {
    const rejected = validateProposedOps(engine, [{ op: 'scope' } as OperatorOp]);
    expect(rejected[0].reason).toMatch(/adds nothing/);
  });

  it('REJECTS a dispatch op that targets an unknown node', () => {
    const rejected = validateProposedOps(engine, [{ op: 'dispatch', target_node_ids: ['ghost-node'] }]);
    expect(rejected[0].reason).toMatch(/unknown node/);
  });

  it('ACCEPTS a dispatch op against an existing node', () => {
    engine.addNode({
      id: 'host-1', type: 'host', label: '10.0.0.1', ip: '10.0.0.1',
      discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0,
    });
    const rejected = validateProposedOps(engine, [{ op: 'dispatch', target_node_ids: ['host-1'], archetype: 'recon_scanner' }]);
    expect(rejected).toHaveLength(0);
  });

  it('REJECTS an empty plan', () => {
    const r = recordProposedPlan(engine, { summary: 'empty', ops: [] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/at least one op/);
  });

  it('accepts a valid scope op (planner can widen scope)', () => {
    const rejected = validateProposedOps(engine, [{ op: 'scope', add_cidrs: ['10.50.0.0/16'] }]);
    expect(rejected).toHaveLength(0);
  });
});
