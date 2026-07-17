import { describe, expect, it } from 'vitest';
import { activityMatchesAgent, buildAgentConsoleEvents, buildOperatorConsoleEvents, activityToAgentConsoleEvent, OPERATOR_CONSOLE_SOURCE } from '../agent-console.js';
import type { ActivityLogEntry } from '../engine-context.js';
import type { AgentTask } from '../../types.js';

const task: AgentTask = {
  id: '11111111-1111-1111-1111-111111111111',
  agent_id: 'sub-recon-1',
  assigned_at: '2026-06-12T10:00:00Z',
  status: 'running',
  subgraph_node_ids: [],
};

function entry(partial: Partial<ActivityLogEntry>): ActivityLogEntry {
  return {
    event_id: partial.event_id || 'evt-1',
    timestamp: partial.timestamp || '2026-06-12T10:01:00Z',
    description: partial.description || 'event',
    event_type: partial.event_type || 'action_started',
    agent_id: partial.agent_id || task.agent_id,
    ...partial,
  };
}

describe('agent console helpers', () => {
  it('matches events by agent id, task id, and linked task id', () => {
    expect(activityMatchesAgent(entry({ agent_id: task.agent_id }), task)).toBe(true);
    expect(activityMatchesAgent(entry({ agent_id: task.id }), task)).toBe(true);
    expect(activityMatchesAgent(entry({ agent_id: 'primary', linked_agent_task_id: task.id }), task)).toBe(true);
    expect(activityMatchesAgent(entry({ agent_id: 'other-agent' }), task)).toBe(false);
  });

  it('derives readable console events with kind, severity, status, and links', () => {
    const events = buildAgentConsoleEvents([
      entry({
        event_id: 'thought-1',
        event_type: 'thought',
        category: 'reasoning',
        description: 'I will enumerate SMB first.',
        details: { kind: 'plan' },
      }),
      entry({
        event_id: 'action-1',
        event_type: 'action_failed',
        description: 'nmap failed on host-1',
        action_id: 'act-1',
        result_classification: 'failure',
        details: { evidence_id: 'ev-1', frontier_item_id: 'fi-1', target_node: 'host-1' },
      }),
      entry({
        event_id: 'parse-1',
        event_type: 'parse_output',
        description: 'Parsed 3 hosts',
        details: { session_id: 'sess-1' },
      }),
    ], task);

    expect(events.map(event => event.kind)).toEqual(['thought', 'action', 'finding']);
    expect(events[0].title).toBe('Plan');
    expect(events[1].severity).toBe('error');
    expect(events[1].status).toBe('failure');
    expect(events[1].links?.action_id).toBe('act-1');
    expect(events[1].links?.frontier_item_id).toBe('fi-1');
    expect(events[1].links?.evidence_id).toBe('ev-1');
    expect(events[1].links?.node_ids).toContain('host-1');
    expect(events[2].links?.session_id).toBe('sess-1');
  });

  it('returns oldest-to-newest rows after applying after and limit filters', () => {
    const events = buildAgentConsoleEvents([
      entry({ event_id: 'old', timestamp: '2026-06-12T10:01:00Z' }),
      entry({ event_id: 'middle', timestamp: '2026-06-12T10:02:00Z' }),
      entry({ event_id: 'new', timestamp: '2026-06-12T10:03:00Z' }),
    ], task, { after: '2026-06-12T10:01:30Z', limit: 1 });

    expect(events.map(event => event.id)).toEqual(['new']);
  });

  it('treats event ids as exclusive positional cursors', () => {
    const entries = [
      entry({ event_id: 'old', timestamp: '2026-06-12T10:01:00Z' }),
      entry({ event_id: 'middle', timestamp: '2026-06-12T10:02:00Z' }),
      entry({ event_id: 'new', timestamp: '2026-06-12T10:03:00Z' }),
    ];

    expect(buildAgentConsoleEvents(entries, task, { after: 'middle' })
      .map(event => event.id)).toEqual(['new']);
    expect(buildOperatorConsoleEvents(entries, [task], { after: 'middle' })
      .map(event => event.id)).toEqual(['new']);
  });
});

describe('activityToAgentConsoleEvent — WS-path attribution (3A.3)', () => {
  it('emits a PRIMARY event (no task, no agent_id) instead of dropping it', () => {
    // Regression: the WS push used to return null for primary events, so the
    // live console only showed sub-agents.
    const event = activityToAgentConsoleEvent(entry({
      event_id: 'primary-1', event_type: 'thought', category: 'reasoning',
      agent_id: undefined, source_kind: 'primary', description: 'considering the next move',
      operator_name: 'Lead', operator_model: 'claude-opus-4-8',
    }));
    expect(event).not.toBeNull();
    expect(event!.source_kind).toBe('primary');
    expect(event!.agent_id).toBe(OPERATOR_CONSOLE_SOURCE);
    expect(event!.source_label).toBe('Lead · claude-opus-4-8');
    expect(event!.kind).toBe('thought');
  });

  it('attributes a dashboard operator_command as a "command" event', () => {
    const event = activityToAgentConsoleEvent(entry({
      event_id: 'cmd-1', event_type: 'operator_command', agent_id: undefined,
      source_kind: 'dashboard', description: 'Operator command executed: pause agent',
      result_classification: 'success', details: { source: 'dashboard' },
    }));
    expect(event!.source_kind).toBe('dashboard');
    expect(event!.kind).toBe('command');
    expect(event!.title).toBe('Operator command');
  });

  it('a partial operator_command is a WARNING (not hidden from the errors filter)', () => {
    const event = activityToAgentConsoleEvent(entry({
      event_id: 'cmd-partial', event_type: 'operator_command', agent_id: undefined,
      source_kind: 'dashboard', result_classification: 'partial', description: 'some ops failed',
    }));
    expect(event!.severity).toBe('warning');
  });

  it('still attributes a subagent event to its task when given a task', () => {
    const event = activityToAgentConsoleEvent(entry({ event_id: 's-1', agent_id: task.agent_id }), task);
    expect(event!.source_kind).toBe('subagent');
    expect(event!.agent_id).toBe(task.id);
  });

  it('drops heartbeats', () => {
    expect(activityToAgentConsoleEvent(entry({ event_type: 'heartbeat', agent_id: undefined }))).toBeNull();
  });

  it('repairs legacy planner registration text without rewriting activity history', () => {
    const planner: AgentTask = {
      id: 'planner-task',
      task_id: 'planner-task',
      agent_id: 'planner-1234',
      agent_label: 'planner-1234',
      assigned_at: '2026-06-12T10:00:00Z',
      status: 'running',
      role: 'planner',
      subgraph_node_ids: [],
    };
    const [event] = buildOperatorConsoleEvents([
      entry({
        event_id: 'legacy-planner-dispatch',
        event_type: 'agent_registered',
        description: 'Agent dispatched: planner-1234 for undefined',
        agent_id: 'planner-1234',
        linked_agent_task_id: 'planner-task',
        details: { task_id: 'planner-task', role: 'planner' },
      }),
    ], [planner]);

    expect(event.summary).toBe('Agent dispatched: planner-1234 as operator planner');
  });

  it('repairs the oldest untyped planner dispatch rows and never renders undefined', () => {
    const planner = {
      id: 'planner-task-old',
      task_id: 'planner-task-old',
      agent_id: 'planner-old',
      agent_label: 'planner-old',
      assigned_at: '2026-06-12T10:00:00Z',
      status: 'interrupted',
      role: 'planner',
      subgraph_node_ids: [],
    } as AgentTask;
    const [event] = buildOperatorConsoleEvents([
      entry({
        event_id: 'oldest-planner-dispatch',
        event_type: undefined,
        category: 'agent',
        description: 'Agent dispatched: planner-old for undefined',
        agent_id: 'planner-old',
      }),
    ], [planner]);

    expect(event.summary).toBe('Agent dispatched: planner-old as operator planner');
    expect(event.summary).not.toContain('undefined');
  });
});
