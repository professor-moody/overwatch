import { describe, expect, it } from 'vitest';
import { buildOperatorConsoleEvents } from '../operator-console';
import type { ActivityEntry, AgentInfo } from '../types';

function activity(partial: Partial<ActivityEntry>): ActivityEntry {
  return {
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
    id: partial.id || 'task-1',
    agent_id: partial.agent_id || 'agent-web-1',
    status: partial.status || 'running',
    task: partial.task || 'Enumerate web app',
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
});
