import { describe, expect, it } from 'vitest';
import { buildOperatorConsoleEvents } from '../operator-console';
import type { ActivityEntry, AgentInfo } from '../types';

function activity(partial: Partial<ActivityEntry>): ActivityEntry {
  return {
    id: partial.id || partial.event_id || 'evt-1',
    event_id: partial.event_id || 'evt-1',
    event_type: partial.event_type || 'action_completed',
    timestamp: partial.timestamp || '2026-06-13T10:00:00Z',
    description: partial.description || 'Ran a command',
    details: partial.details || {},
    ...partial,
  };
}

function agent(partial: Partial<AgentInfo>): AgentInfo {
  return {
    task_id: partial.id || 'task-1',
    agent_label: partial.agent_id || 'agent-web-1',
    id: partial.id || 'task-1',
    agent_id: partial.agent_id || 'agent-web-1',
    status: partial.status || 'running',
    assigned_at: '2026-06-13T09:59:00Z',
    queued: false,
    lifecycle: 'live',
    live: true,
    subgraph_node_ids: [],
    findings_count: 0,
    objective: 'Enumerate web app',
    ...partial,
  };
}

describe('operator console event normalization', () => {
  it('shows primary operator output even when there are no subagents', () => {
    const [event] = buildOperatorConsoleEvents([
      activity({
        event_id: 'evt-primary',
        event_type: 'action_started',
        description: 'Full TCP scan started',
        operator_name: 'Lead',
        operator_model: 'claude-opus-4-8',
      }),
    ]);

    expect(event.source_kind).toBe('primary');
    expect(event.agent_id).toBe('operator');
    expect(event.source_label).toBe('Lead · claude-opus-4-8');
    expect(event.title).toBe('Action started');
  });

  it('keeps real subagents distinct from the primary operator', () => {
    const [event] = buildOperatorConsoleEvents([
      activity({
        event_id: 'evt-subagent',
        event_type: 'finding_ingested',
        agent_id: 'agent-web-1',
        description: 'Reported a web finding',
      }),
    ], { agents: [agent({ id: 'task-web', agent_id: 'agent-web-1' })] });

    expect(event.source_kind).toBe('subagent');
    expect(event.agent_id).toBe('agent-web-1');
    expect(event.source_label).toBe('agent-web-1');
    expect(event.kind).toBe('finding');
  });

  it('labels dashboard and runner events without pretending they are subagents', () => {
    const events = buildOperatorConsoleEvents([
      activity({
        event_id: 'evt-dashboard',
        event_type: 'action_validated',
        details: { source: 'dashboard' },
      }),
      activity({
        event_id: 'evt-runner',
        event_type: 'action_completed',
        details: { invoking_tool: 'credential-runner' },
      }),
    ]);

    expect(events.map(event => event.source_kind)).toEqual(['dashboard', 'runner']);
    expect(events.map(event => event.source_label)).toEqual(['Dashboard', 'Scripted runner']);
  });

  it('returns events oldest→newest (chronological) and keeps the newest N via limit', () => {
    const unordered = [
      activity({ event_id: 'e1', timestamp: '2026-06-13T10:00:00Z' }),
      activity({ event_id: 'e3', timestamp: '2026-06-13T10:02:00Z' }),
      activity({ event_id: 'e2', timestamp: '2026-06-13T10:01:00Z' }),
    ];
    // Display layers reverse/re-sort for newest-first; the builder itself stays
    // chronological so slice(-limit) keeps the NEWEST N (not the oldest).
    expect(buildOperatorConsoleEvents(unordered).map(e => e.timestamp)).toEqual([
      '2026-06-13T10:00:00Z', '2026-06-13T10:01:00Z', '2026-06-13T10:02:00Z',
    ]);
    expect(buildOperatorConsoleEvents(unordered, { limit: 2 }).map(e => e.timestamp)).toEqual([
      '2026-06-13T10:01:00Z', '2026-06-13T10:02:00Z',
    ]);
  });
});

describe('operator console — NL cockpit events (3A.3)', () => {
  it('an executed operator_command is a dashboard "command" event', () => {
    const [event] = buildOperatorConsoleEvents([
      activity({
        event_id: 'evt-cmd',
        event_type: 'operator_command',
        description: 'Operator command executed: pause the apache agent',
        source_kind: 'dashboard',
        result_classification: 'success',
        details: { source: 'dashboard', command: 'pause the apache agent' },
      }),
    ]);
    expect(event.kind).toBe('command');
    expect(event.title).toBe('Operator command');
    expect(event.source_kind).toBe('dashboard');
  });

  it('a plan_proposed event is a "command" event attributed to the planner subagent', () => {
    const [event] = buildOperatorConsoleEvents([
      activity({
        event_id: 'evt-plan',
        event_type: 'plan_proposed',
        agent_id: 'planner-1',
        description: 'Planner proposed a 1-op plan: pause apache',
      }),
    ], { agents: [agent({ id: 'planner-task', agent_id: 'planner-1' })] });
    expect(event.kind).toBe('command');
    expect(event.title).toBe('Plan proposed');
    expect(event.source_kind).toBe('subagent');
  });

  it('a partially-failed operator command surfaces as a WARNING (not hidden from the errors filter)', () => {
    const [event] = buildOperatorConsoleEvents([
      activity({
        event_id: 'evt-partial',
        event_type: 'operator_command',
        description: 'Operator command executed: approve two actions',
        source_kind: 'dashboard',
        result_classification: 'partial',
      }),
    ]);
    expect(event.severity).toBe('warning');
  });
});
