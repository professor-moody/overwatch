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
  });

  describe('getTask', () => {
    it('returns null for unknown task id', () => {
      const { mgr } = setup();
      expect(mgr.getTask('nonexistent')).toBeNull();
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
      mgr.register(makeTask({ id: 't1' }));
      mgr.register(makeTask({ id: 't2' }));
      mgr.register(makeTask({ id: 't3' }));
      expect(mgr.getAll()).toHaveLength(3);
    });
  });
});
