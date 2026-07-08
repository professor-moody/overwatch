import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../../services/graph-engine.js';
import { recordProposedPlan, validateProposedOps } from '../propose-plan.js';
import type { EngagementConfig, AgentTask } from '../../types.js';
import type { OperatorOp } from '../../services/command-interpreter.js';

const TEST_STATE_FILE = './state-test-propose-plan.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-pp', name: 'pp test', created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [], opsec: { name: 'pentest', max_noise: 0.7 },
  };
}
function cleanup() { try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch { /* ignore */ } }

const runningTask = (id: string, agent_id: string): AgentTask => ({
  id, agent_id, assigned_at: new Date().toISOString(), status: 'running', subgraph_node_ids: [],
});

describe('propose_plan — validation + recording', () => {
  let engine: GraphEngine;
  beforeEach(() => { cleanup(); engine = new GraphEngine(makeConfig(), TEST_STATE_FILE); });
  afterEach(() => { cleanup(); });

  it('validates + stores a plan that targets a real running task', () => {
    engine.registerAgent(runningTask('task-1', 'a1'));
    const r = recordProposedPlan(engine, {
      agent_id: 'planner-x', task_id: 'planner-task', command: 'pause a1',
      summary: 'pause a1', ops: [{ op: 'directive', task_id: 'task-1', agent_label: 'a1', kind: 'pause' }],
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(engine.getProposedPlanStore().get(r.plan_id)?.command).toBe('pause a1');
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
