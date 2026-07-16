import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { AgentManager } from '../agent-manager.js';
import type { AgentTask } from '../../types.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

function makeConfig(overrides: Record<string, unknown> = {}) {
  return {
    id: 'test-eng',
    name: 'Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
    ...overrides,
  } as any;
}

function makeTask(overrides: Partial<AgentTask> = {}): AgentTask {
  return {
    id: 'task-1',
    agent_id: 'agent-1',
    assigned_at: '2026-03-20T00:00:00Z',
    status: 'running',
    frontier_item_id: 'fi-1',
    subgraph_node_ids: ['n1'],
    ...overrides,
  };
}

function setup() {
  const graph = makeGraph();
  const ctx = new EngineContext(graph, makeConfig(), './state-test-agent-mgr.json');
  const mgr = new AgentManager(ctx);
  return { graph, ctx, mgr };
}

describe('AgentManager', () => {
  describe('register', () => {
    it('stores the task and makes it retrievable', () => {
      const { mgr } = setup();
      const task = makeTask();
      mgr.register(task);
      expect(mgr.getTask('task-1')).toBe(task);
      expect(task).toMatchObject({
        task_id: 'task-1',
        agent_label: 'agent-1',
        id: 'task-1',
        agent_id: 'agent-1',
      });
    });

    it('logs an agent_registered event', () => {
      const { mgr, ctx } = setup();
      mgr.register(makeTask({ skill: 'nmap_scan' }));
      const events = ctx.activityLog.filter(e => e.event_type === 'agent_registered');
      expect(events).toHaveLength(1);
      expect(events[0].description).toContain('agent-1');
      expect(events[0].details).toMatchObject({ skill: 'nmap_scan' });
    });

    it('overwrites when the same task id is registered twice', () => {
      const { mgr } = setup();
      mgr.register(makeTask({ skill: 'scan_a' }));
      const replacement = makeTask({ skill: 'scan_b' });
      mgr.register(replacement);
      expect(mgr.getTask('task-1')).toBe(replacement);
      expect(mgr.getAll()).toHaveLength(1);
    });

    describe('node-scoped dispatch dedup (no frontier_item_id)', () => {
      // A node-scoped dispatch (planner deploy-at-node) carries no frontier lease;
      // dedup stops a re-issued command from launching a duplicate at the same node.
      const nodeDispatch = (o: Partial<AgentTask>) =>
        makeTask({ frontier_item_id: undefined, archetype: 'recon_scanner', role: 'research', ...o });

      it('refuses a second running dispatch of the same archetype at the same node', () => {
        const { mgr } = setup();
        expect(mgr.register(nodeDispatch({ id: 't1', agent_id: 'a1', subgraph_node_ids: ['n1'] })).ok).toBe(true);
        const r = mgr.register(nodeDispatch({ id: 't2', agent_id: 'a2', subgraph_node_ids: ['n1'] }));
        expect(r.ok).toBe(false);
        expect(r.node_conflict).toMatchObject({ existing_task_id: 't1', existing_agent_id: 'a1', node_id: 'n1' });
        expect(mgr.getTask('t2')).toBeNull(); // not stored
      });

      it('allows a DIFFERENT archetype at the same node (web-crawl alongside a port-scan)', () => {
        const { mgr } = setup();
        mgr.register(nodeDispatch({ id: 't1', agent_id: 'a1', archetype: 'recon_scanner', subgraph_node_ids: ['n1'] }));
        const r = mgr.register(nodeDispatch({ id: 't2', agent_id: 'a2', archetype: 'web_prober', subgraph_node_ids: ['n1'] }));
        expect(r.ok).toBe(true);
      });

      it('allows a re-dispatch once the prior agent is terminal', () => {
        const { mgr } = setup();
        mgr.register(nodeDispatch({ id: 't1', agent_id: 'a1', subgraph_node_ids: ['n1'] }));
        mgr.updateStatus('t1', 'completed');
        const r = mgr.register(nodeDispatch({ id: 't2', agent_id: 'a2', subgraph_node_ids: ['n1'] }));
        expect(r.ok).toBe(true);
      });

      it('does NOT node-dedup frontier-scoped work (that has its own lease)', () => {
        const { mgr } = setup();
        // Two DIFFERENT frontier items that happen to seed the same node → both allowed;
        // the frontier lease, not node-dedup, governs frontier work.
        expect(mgr.register(makeTask({ id: 't1', agent_id: 'a1', frontier_item_id: 'fi-A', subgraph_node_ids: ['n1'] })).ok).toBe(true);
        expect(mgr.register(makeTask({ id: 't2', agent_id: 'a2', frontier_item_id: 'fi-B', subgraph_node_ids: ['n1'] })).ok).toBe(true);
      });
    });
  });

  describe('getTask', () => {
    it('returns null for unknown task id', () => {
      const { mgr } = setup();
      expect(mgr.getTask('nonexistent')).toBeNull();
    });

    it('resolves a unique legacy label but never guesses between duplicates', () => {
      const { mgr } = setup();
      mgr.register(makeTask({ id: 'task-a', agent_id: 'shared', frontier_item_id: 'fi-a' }));
      expect(mgr.resolveTaskReference('shared')).toMatchObject({
        status: 'unique_legacy_label',
        task: { task_id: 'task-a' },
      });
      mgr.register(makeTask({ id: 'task-b', agent_id: 'shared', frontier_item_id: 'fi-b' }));
      expect(mgr.resolveTaskReference('shared')).toEqual({
        status: 'ambiguous_legacy_label',
        candidate_task_ids: ['task-a', 'task-b'],
      });
      expect(mgr.resolveTaskReference('task-b')).toMatchObject({
        status: 'exact',
        task: { agent_label: 'shared' },
      });
    });
  });

  describe('updateStatus', () => {
    it('returns true and updates status on a known task', () => {
      const { mgr } = setup();
      mgr.register(makeTask());
      const ok = mgr.updateStatus('task-1', 'completed', 'done');
      expect(ok).toBe(true);
      const task = mgr.getTask('task-1')!;
      expect(task.status).toBe('completed');
      expect(task.result_summary).toBe('done');
      expect(task.completed_at).toBeDefined();
    });

    it('returns false for unknown task id', () => {
      const { mgr } = setup();
      expect(mgr.updateStatus('no-such-task', 'completed')).toBe(false);
    });

    it('sets completed_at when status is failed', () => {
      const { mgr } = setup();
      mgr.register(makeTask());
      mgr.updateStatus('task-1', 'failed', 'timeout');
      const task = mgr.getTask('task-1')!;
      expect(task.status).toBe('failed');
      expect(task.completed_at).toBeDefined();
    });

    it('does not set completed_at for non-terminal status', () => {
      const { mgr } = setup();
      mgr.register(makeTask({ status: 'pending' }));
      mgr.updateStatus('task-1', 'running');
      expect(mgr.getTask('task-1')!.completed_at).toBeUndefined();
    });

    it('sets completed_at for interrupted (so its attention card can age out)', () => {
      const { mgr } = setup();
      mgr.register(makeTask());
      mgr.updateStatus('task-1', 'interrupted', 'operator cancel');
      expect(mgr.getTask('task-1')!.completed_at).toBeDefined();
    });

    it('terminal is monotonic: a late completed does NOT overwrite an interrupt', () => {
      const { mgr } = setup();
      mgr.register(makeTask());
      expect(mgr.updateStatus('task-1', 'interrupted', 'cancelled')).toBe(true);
      // A natural completion arriving after the cancel must be swallowed.
      expect(mgr.updateStatus('task-1', 'completed', 'late done')).toBe(false);
      expect(mgr.getTask('task-1')!.status).toBe('interrupted'); // not a false success
    });

    it('terminal is monotonic: a late interrupt does not rewrite completed truth', () => {
      const { mgr } = setup();
      mgr.register(makeTask());
      mgr.updateStatus('task-1', 'completed', 'done');
      expect(mgr.updateStatus('task-1', 'interrupted', 'cancelled anyway')).toBe(false);
      expect(mgr.getTask('task-1')!.status).toBe('completed');
      expect(mgr.getTask('task-1')!.result_summary).toBe('done');
    });

    it('a completed/failed does not overwrite another terminal (no flip-flop)', () => {
      const { mgr } = setup();
      mgr.register(makeTask());
      mgr.updateStatus('task-1', 'completed');
      expect(mgr.updateStatus('task-1', 'failed')).toBe(false);
      expect(mgr.getTask('task-1')!.status).toBe('completed');
    });

    it('logs an agent_updated event with correct classification', () => {
      const { mgr, ctx } = setup();
      mgr.register(makeTask());
      mgr.updateStatus('task-1', 'completed', 'found creds');
      const events = ctx.activityLog.filter(e => e.event_type === 'agent_updated');
      expect(events).toHaveLength(1);
      expect(events[0].result_classification).toBe('success');
    });

    it('classifies failed status as failure', () => {
      const { mgr, ctx } = setup();
      mgr.register(makeTask());
      mgr.updateStatus('task-1', 'failed');
      const events = ctx.activityLog.filter(e => e.event_type === 'agent_updated');
      expect(events[0].result_classification).toBe('failure');
    });
  });

  describe('getRunningTaskForFrontierItem', () => {
    it('returns the running task matching the frontier item', () => {
      const { mgr } = setup();
      const task = makeTask({ frontier_item_id: 'fi-42', status: 'running' });
      mgr.register(task);
      expect(mgr.getRunningTaskForFrontierItem('fi-42')).toBe(task);
    });

    it('returns null when no running task matches', () => {
      const { mgr } = setup();
      mgr.register(makeTask({ frontier_item_id: 'fi-42', status: 'completed' }));
      expect(mgr.getRunningTaskForFrontierItem('fi-42')).toBeNull();
    });

    it('returns null when frontier item has no tasks', () => {
      const { mgr } = setup();
      expect(mgr.getRunningTaskForFrontierItem('fi-999')).toBeNull();
    });

    it('ignores tasks for a different frontier item', () => {
      const { mgr } = setup();
      mgr.register(makeTask({ id: 't1', frontier_item_id: 'fi-1', status: 'running' }));
      mgr.register(makeTask({ id: 't2', frontier_item_id: 'fi-2', status: 'running' }));
      const found = mgr.getRunningTaskForFrontierItem('fi-2')!;
      expect(found.id).toBe('t2');
    });
  });

  describe('getAll', () => {
    it('returns empty array when no agents registered', () => {
      const { mgr } = setup();
      expect(mgr.getAll()).toEqual([]);
    });

    it('returns all registered tasks', () => {
      const { mgr } = setup();
      // Distinct frontier_item_ids — P1.4 leases would otherwise refuse
      // duplicate registrations on the same frontier item.
      mgr.register(makeTask({ id: 't1', frontier_item_id: 'fi-A' }));
      mgr.register(makeTask({ id: 't2', frontier_item_id: 'fi-B' }));
      mgr.register(makeTask({ id: 't3', frontier_item_id: 'fi-C' }));
      expect(mgr.getAll()).toHaveLength(3);
    });
  });

  describe('ensureRunningAgent', () => {
    it('creates a synthetic running task for an unknown agent_id', () => {
      const { mgr } = setup();
      const task = mgr.ensureRunningAgent('subagent-nmap-1');
      expect(task).not.toBeNull();
      expect(task!.agent_id).toBe('subagent-nmap-1');
      expect(task!.status).toBe('running');
      expect(task!.skill).toBe('auto');
      expect(mgr.getAll()).toHaveLength(1);
    });

    it('is idempotent — second call returns the existing task', () => {
      const { mgr } = setup();
      const a = mgr.ensureRunningAgent('subagent-1')!;
      const b = mgr.ensureRunningAgent('subagent-1')!;
      expect(b.id).toBe(a.id);
      expect(mgr.getAll()).toHaveLength(1);
    });

    it('returns null for blank/missing agent_id', () => {
      const { mgr } = setup();
      expect(mgr.ensureRunningAgent(undefined)).toBeNull();
      expect(mgr.ensureRunningAgent('')).toBeNull();
      expect(mgr.ensureRunningAgent('   ')).toBeNull();
      expect(mgr.getAll()).toHaveLength(0);
    });

    it('does not collide with explicitly-registered agents on the same id', () => {
      const { mgr } = setup();
      mgr.register(makeTask({ id: 't1', agent_id: 'subagent-1', frontier_item_id: 'fi-A', status: 'running' }));
      const auto = mgr.ensureRunningAgent('subagent-1');
      expect(auto!.id).toBe('t1');
      expect(mgr.getAll()).toHaveLength(1);
    });

    it('does not guess when more than one running task shares a legacy label', () => {
      const { mgr, ctx } = setup();
      mgr.register(makeTask({ id: 't1', agent_id: 'shared', frontier_item_id: 'fi-A' }));
      mgr.register(makeTask({ id: 't2', agent_id: 'shared', frontier_item_id: 'fi-B' }));
      expect(mgr.ensureRunningAgent('shared')).toBeNull();
      expect(mgr.getAll()).toHaveLength(2);
      expect(ctx.activityLog.some(entry =>
        entry.event_type === 'instrumentation_warning'
        && entry.details?.reason === 'ambiguous_legacy_agent_label')).toBe(true);
    });
  });

  describe('centralized terminal transitions', () => {
    it('heartbeat reaping releases the lease and expires the task question through one transition path', () => {
      const { mgr, ctx } = setup();
      mgr.register(makeTask({
        heartbeat_at: '2026-03-20T00:00:00.000Z',
        heartbeat_ttl_seconds: 30,
      }));
      const query = ctx.agentQueryStore.add({
        owner_task_id: 'task-1',
        owner_agent_label: 'agent-1',
        question: 'continue?',
        now: Date.parse('2026-03-20T00:00:00.000Z'),
      });

      expect(mgr.reapStaleHeartbeats('2026-03-20T00:01:00.000Z')).toBe(1);
      expect(mgr.getTask('task-1')).toMatchObject({
        status: 'interrupted',
        completed_at: '2026-03-20T00:01:00.000Z',
      });
      expect(ctx.frontierLeases.list('2026-03-20T00:01:00.000Z')).toEqual([]);
      expect(ctx.agentQueryStore.get(query.query_id)).toMatchObject({
        status: 'expired',
        expired_at: Date.parse('2026-03-20T00:01:00.000Z'),
      });
    });

    it('startup reconciliation cannot rewrite an already-terminal task', () => {
      const { mgr } = setup();
      mgr.register(makeTask({ status: 'completed', completed_at: '2026-03-20T00:05:00.000Z' }));
      expect(mgr.reconcileOnStartup()).toBe(0);
      expect(mgr.getTask('task-1')).toMatchObject({
        status: 'completed',
        completed_at: '2026-03-20T00:05:00.000Z',
      });
    });
  });
});
