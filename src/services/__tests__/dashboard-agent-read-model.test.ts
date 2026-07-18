import { describe, expect, it, vi } from 'vitest';
import type { AgentTask, Campaign } from '../../types.js';
import type { ActivityLogEntry } from '../engine-context.js';
import {
  DashboardAgentReadModel,
  type DashboardAgentReadPort,
} from '../dashboard-agent-read-model.js';

const NOW = Date.parse('2026-07-17T12:00:00.000Z');

function task(overrides: Partial<AgentTask> = {}): AgentTask {
  return {
    id: 'task-1',
    agent_id: 'shared-label',
    assigned_at: '2026-07-17T11:55:00.000Z',
    status: 'running',
    subgraph_node_ids: ['host-1'],
    heartbeat_at: '2026-07-17T11:59:30.000Z',
    heartbeat_ttl_seconds: 120,
    ...overrides,
  };
}

function event(overrides: Partial<ActivityLogEntry> = {}): ActivityLogEntry {
  return {
    event_id: 'event-1',
    timestamp: '2026-07-17T11:57:00.000Z',
    description: 'Agent action',
    event_type: 'action_completed',
    category: 'agent',
    agent_id: 'shared-label',
    details: {},
    ...overrides,
  } as ActivityLogEntry;
}

function campaign(): Campaign {
  return {
    id: 'campaign-1',
    name: 'Agent campaign',
    strategy: 'custom',
    status: 'active',
    items: [],
    abort_conditions: [],
    progress: {
      total: 0,
      completed: 0,
      succeeded: 0,
      failed: 0,
      consecutive_failures: 0,
    },
    created_at: '2026-07-17T11:50:00.000Z',
    findings: [],
  };
}

function engineFixture(
  tasks: AgentTask[],
  history: ActivityLogEntry[],
  campaigns: Campaign[] = [],
) {
  const getSubgraphForAgent = vi.fn(() => ({
    nodes: [{
      id: 'host-1',
      properties: {
        id: 'host-1',
        type: 'host' as const,
        label: 'Host one',
        discovered_at: '2026-07-17T11:00:00.000Z',
        confidence: 1,
      },
    }],
    edges: [],
  }));
  const engine = {
    getAllAgents: () => tasks,
    getAgentTasks: () => tasks,
    getTask: (taskId: string) => tasks.find(candidate => candidate.id === taskId) ?? null,
    getFullHistory: () => history,
    listCampaigns: () => campaigns,
    getSubgraphForAgent,
  } satisfies DashboardAgentReadPort;
  return { engine, getSubgraphForAgent };
}

describe('DashboardAgentReadModel', () => {
  it('uses its injected clock for stable liveness and elapsed projections', () => {
    const running = task({ campaign_id: 'campaign-1' });
    const { engine, getSubgraphForAgent } = engineFixture([running], [], [campaign()]);
    const reads = new DashboardAgentReadModel(engine, { now: () => NOW });

    const listed = reads.listAgents();
    expect(listed).toMatchObject({
      total: 1,
      agents: [{
        task_id: 'task-1',
        agent_label: 'shared-label',
        lifecycle: 'live',
        live: true,
        elapsed_ms: 300_000,
        campaign: { id: 'campaign-1', name: 'Agent campaign' },
      }],
    });

    const context = reads.getAgentContext('task-1');
    expect(context?.task).toMatchObject({
      task_id: 'task-1',
      lifecycle: 'live',
      elapsed_ms: 300_000,
    });
    expect(context?.subgraph.nodes).toHaveLength(1);
    expect(getSubgraphForAgent).toHaveBeenCalledWith(['host-1'], { hops: 2 });
  });

  it('prefers exact task attribution and rejects ambiguous legacy labels', () => {
    const tasks = [task(), task({ id: 'task-2' })];
    const history = [
      event({ event_id: 'exact-1', linked_agent_task_id: 'task-1' }),
      event({ event_id: 'exact-2', linked_agent_task_id: 'task-2' }),
      event({ event_id: 'legacy-ambiguous' }),
    ];
    const { engine } = engineFixture(tasks, history);
    const reads = new DashboardAgentReadModel(engine, { now: () => NOW });

    expect(reads.getAgentHistory('task-1')?.entries.map(entry => entry.event_id))
      .toEqual(['exact-1']);
    expect(reads.getAgentConsole('task-1')?.events.map(entry => entry.id))
      .toEqual(['exact-1']);

    const unique = new DashboardAgentReadModel(
      engineFixture([tasks[0]], history).engine,
      { now: () => NOW },
    );
    expect(unique.getAgentHistory('task-1')?.entries.map(entry => entry.event_id))
      .toEqual(['exact-1', 'legacy-ambiguous']);
    expect(unique.getAgentConsole('task-1')?.events.map(entry => entry.id))
      .toEqual(['exact-1', 'legacy-ambiguous']);
  });

  it('keeps action-only rows after exact task attribution under duplicate labels', () => {
    const tasks = [task(), task({ id: 'task-2' })];
    const history = [
      event({
        event_id: 'action-start',
        action_id: 'action-1',
        linked_agent_task_id: 'task-1',
        event_type: 'action_started',
      }),
      event({
        event_id: 'action-result',
        action_id: 'action-1',
        agent_id: undefined,
        event_type: 'action_completed',
        timestamp: '2026-07-17T11:58:00.000Z',
      }),
    ];
    const reads = new DashboardAgentReadModel(
      engineFixture(tasks, history).engine,
      { now: () => NOW },
    );

    expect(reads.getAgentConsole('task-1')?.events.map(entry => entry.id))
      .toEqual(['action-start', 'action-result']);
    expect(reads.getAgentConsole('task-2')?.events).toEqual([]);
  });

  it('accepts the canonical task ID in agent_id and carries its action chain', () => {
    const tasks = [task(), task({ id: 'task-2' })];
    const history = [
      event({
        event_id: 'canonical-start',
        action_id: 'canonical-action',
        agent_id: 'task-1',
        event_type: 'action_started',
      }),
      event({
        event_id: 'canonical-result',
        action_id: 'canonical-action',
        agent_id: undefined,
        event_type: 'action_completed',
        timestamp: '2026-07-17T11:58:00.000Z',
      }),
    ];
    const reads = new DashboardAgentReadModel(
      engineFixture(tasks, history).engine,
      { now: () => NOW },
    );

    expect(reads.getAgentHistory('task-1')?.entries.map(entry => entry.event_id))
      .toEqual(['canonical-start', 'canonical-result']);
    expect(reads.getAgentConsole('task-1')?.events.map(entry => entry.id))
      .toEqual(['canonical-start', 'canonical-result']);
  });

  it('projects context against the full fleet so legacy labels stay ambiguous', () => {
    const tasks = [task(), task({ id: 'task-2' })];
    const history = [event({
      event_id: 'legacy-only',
      description: 'Legacy label activity',
      linked_finding_ids: ['finding-legacy'],
    })];
    const reads = new DashboardAgentReadModel(
      engineFixture(tasks, history).engine,
      { now: () => NOW },
    );

    const listedTask = reads.listAgents().agents.find(agent => agent.task_id === 'task-1');
    const contextTask = reads.getAgentContext('task-1')?.task;
    expect(contextTask).toEqual(listedTask);
    expect(contextTask).not.toHaveProperty('current_action');
    expect(contextTask?.findings_count).toBe(0);
  });

  it('preserves console ordering, cursor, and limit semantics', () => {
    const history = [
      event({
        event_id: 'event-3',
        timestamp: '2026-07-17T11:59:00.000Z',
        linked_agent_task_id: 'task-1',
      }),
      event({
        event_id: 'event-1',
        timestamp: '2026-07-17T11:57:00.000Z',
        linked_agent_task_id: 'task-1',
      }),
      event({
        event_id: 'event-2',
        timestamp: '2026-07-17T11:58:00.000Z',
        linked_agent_task_id: 'task-1',
      }),
    ];
    const { engine } = engineFixture([task()], history);
    const reads = new DashboardAgentReadModel(engine, { now: () => NOW });

    expect(reads.getAgentConsole('task-1', { limit: 2 })?.events.map(entry => entry.id))
      .toEqual(['event-2', 'event-3']);
    expect(reads.getAgentConsole('task-1', { after: 'event-1' })?.events.map(entry => entry.id))
      .toEqual(['event-2', 'event-3']);
    expect(reads.getAgentConsole('task-1', {
      after: '2026-07-17T11:58:00.000Z',
    })?.events.map(entry => entry.id)).toEqual(['event-3']);
    expect(reads.getOperatorConsole({ limit: 2 }).events.map(entry => entry.id))
      .toEqual(['event-2', 'event-3']);
  });

  it('returns null for missing task-scoped reads', () => {
    const reads = new DashboardAgentReadModel(
      engineFixture([], []).engine,
      { now: () => NOW },
    );

    expect(reads.getAgentContext('missing')).toBeNull();
    expect(reads.getAgentHistory('missing')).toBeNull();
    expect(reads.getAgentConsole('missing')).toBeNull();
  });
});
