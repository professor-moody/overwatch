import { describe, expect, it } from 'vitest';
import { AgentDtoSchema } from '../../contracts/dashboard-v1.js';
import { projectAgentDtos } from '../dashboard-agent-projector.js';
import type { AgentTask, Campaign } from '../../types.js';
import type { ActivityLogEntry } from '../engine-context.js';

const NOW = Date.parse('2026-07-15T12:00:00Z');

function task(overrides: Partial<AgentTask> = {}): AgentTask {
  return {
    id: 'task-1',
    agent_id: 'shared-label',
    assigned_at: '2026-07-15T11:55:00Z',
    status: 'running',
    subgraph_node_ids: ['host-1'],
    archetype: 'web_tester',
    objective: 'Inspect the application',
    model: 'test-model',
    heartbeat_at: '2026-07-15T11:59:30Z',
    heartbeat_ttl_seconds: 120,
    ...overrides,
  };
}

function event(overrides: Partial<ActivityLogEntry> = {}): ActivityLogEntry {
  return {
    event_id: 'event-1',
    timestamp: '2026-07-15T11:59:00Z',
    description: 'Found an exposed endpoint',
    event_type: 'finding_reported',
    category: 'finding',
    agent_id: 'shared-label',
    details: {},
    ...overrides,
  } as ActivityLogEntry;
}

function campaign(): Campaign {
  return {
    id: 'camp-1', name: 'Web review', strategy: 'custom', status: 'active', items: ['fi-1'],
    abort_conditions: [], progress: { total: 1, completed: 0, succeeded: 0, failed: 0, consecutive_failures: 0 },
    created_at: '2026-07-15T11:50:00Z', findings: [],
  };
}

describe('dashboard agent projector', () => {
  it('projects canonical identity, activity, campaign, model, and unique findings', () => {
    const projected = projectAgentDtos(
      [task({ campaign_id: 'camp-1', frontier_item_id: 'fi-1' })],
      [
        event({ linked_agent_task_id: 'task-1', linked_finding_ids: ['finding-1', 'finding-1'] }),
        event({ event_id: 'event-2', timestamp: '2026-07-15T11:59:10Z', linked_agent_task_id: 'task-1', linked_finding_ids: ['finding-2'] }),
      ],
      [campaign()],
      NOW,
    );

    expect(AgentDtoSchema.parse(projected[0])).toMatchObject({
      task_id: 'task-1', agent_label: 'shared-label', id: 'task-1', agent_id: 'shared-label',
      archetype: 'web_tester', objective: 'Inspect the application', model: 'test-model',
      campaign_id: 'camp-1', frontier_item_id: 'fi-1', lifecycle: 'live', live: true,
      findings_count: 2,
    });
    expect(projected[0].current_action).toBe('Found an exposed endpoint');
  });

  it('uses exact task attribution and refuses ambiguous legacy labels', () => {
    const tasks = [task(), task({ id: 'task-2' })];
    const projected = projectAgentDtos(tasks, [
      event({ linked_agent_task_id: 'task-2', linked_finding_ids: ['finding-exact'] }),
      event({ event_id: 'legacy', linked_agent_task_id: undefined, linked_finding_ids: ['finding-ambiguous'] }),
    ], [], NOW);

    expect(projected.find(item => item.task_id === 'task-1')?.findings_count).toBe(0);
    expect(projected.find(item => item.task_id === 'task-2')?.findings_count).toBe(1);
  });

  it('does not relabel an explicitly linked event when its task is outside the projection', () => {
    const [projected] = projectAgentDtos([task({ id: 'visible' })], [
      event({ linked_agent_task_id: 'filtered-out', linked_finding_ids: ['finding-other-task'] }),
    ], [], NOW);

    expect(projected.findings_count).toBe(0);
    expect(projected.last_finding_at).toBeUndefined();
  });

  it('attributes action-only findings through the exact action-to-task link', () => {
    const tasks = [task({ id: 'task-1' }), task({ id: 'task-2' })];
    const projected = projectAgentDtos(tasks, [
      event({
        event_id: 'started', category: 'agent', event_type: 'action_started',
        action_id: 'act-1', linked_agent_task_id: 'task-2', linked_finding_ids: [],
      }),
      event({
        event_id: 'finding', action_id: 'act-1', linked_agent_task_id: undefined,
        linked_finding_ids: ['finding-action-linked'],
      }),
    ], [], NOW);

    expect(projected.find(item => item.task_id === 'task-1')?.findings_count).toBe(0);
    expect(projected.find(item => item.task_id === 'task-2')?.findings_count).toBe(1);
  });

  it('derives stale liveness from heartbeat age without rewriting persisted status', () => {
    const [projected] = projectAgentDtos([
      task({ heartbeat_at: '2026-07-15T11:50:00Z', heartbeat_ttl_seconds: 60 }),
    ], [], [], NOW);
    expect(projected).toMatchObject({ status: 'running', lifecycle: 'stale', live: false });
  });

  it('omits invalid elapsed time instead of emitting NaN', () => {
    const [projected] = projectAgentDtos([task({ assigned_at: 'not-a-date' })], [], [], NOW);
    expect(projected.elapsed_ms).toBeUndefined();
  });

  it('projects durable work lineage and canonical merged-source links', () => {
    const signature = 'a'.repeat(64);
    const tasks = [
      task({
        id: 'canonical',
        work: { version: 1, root_task_id: 'root', signature },
      }),
      task({
        id: 'handoff-child',
        work: {
          version: 1,
          root_task_id: 'root',
          signature: 'b'.repeat(64),
          relation: {
            kind: 'handoff',
            source_task_id: 'canonical',
            created_at: '2026-07-15T11:58:00Z',
            summary: 'Continue the assessment.',
          },
        },
      }),
      task({
        id: 'duplicate',
        status: 'completed',
        work: {
          version: 1,
          root_task_id: 'root',
          signature,
          merged_into_task_id: 'canonical',
        },
      }),
    ];

    const projected = projectAgentDtos(tasks, [], [], NOW);
    expect(projected.find(item => item.task_id === 'canonical')).toMatchObject({
      work: { root_task_id: 'root', signature },
      merged_source_task_ids: ['duplicate'],
    });
    expect(projected.find(item => item.task_id === 'handoff-child')?.work?.relation).toEqual({
      kind: 'handoff',
      source_task_id: 'canonical',
      created_at: '2026-07-15T11:58:00Z',
      summary: 'Continue the assessment.',
    });
  });
});
