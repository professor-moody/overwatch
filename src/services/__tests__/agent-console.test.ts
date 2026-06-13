import { describe, expect, it } from 'vitest';
import { activityMatchesAgent, buildAgentConsoleEvents } from '../agent-console.js';
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
});
