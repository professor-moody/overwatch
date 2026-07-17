import { describe, it, expect } from 'vitest';
import { buildAgentThread, threadHasOpenQuestion } from '../agent-thread';
import type { AgentConsoleEvent } from '../types';
import type { AgentQuery } from '../api';

function ev(o: Partial<AgentConsoleEvent> & { id: string; timestamp: string }): AgentConsoleEvent {
  return { agent_id: 'recon-1', kind: 'action', severity: 'info', title: 'Event', summary: '', ...o } as AgentConsoleEvent;
}
function q(o: Partial<AgentQuery> = {}): AgentQuery {
  return { query_id: 'q1', task_id: 'task-1', agent_id: 'recon-1', question: 'spray creds?', status: 'open', created_at: Date.UTC(2026, 5, 17, 12, 0, 30), expires_at: Date.UTC(2026, 5, 17, 12, 30, 30), ...o };
}
const OPTS = { agentId: 'task-1', agentLabel: 'recon-1' };

describe('buildAgentThread', () => {
  it('classifies operator commands, agent actions, findings, and system notes into roles/kinds', () => {
    const t = buildAgentThread([
      ev({ id: 'c', timestamp: '2026-06-17T12:00:01Z', kind: 'command', source_kind: 'dashboard', title: 'You', summary: 'ping app01' }),
      ev({ id: 'a', timestamp: '2026-06-17T12:00:02Z', kind: 'action', source_kind: 'subagent', title: 'run_bash', summary: 'ping 10.20.0.20 → 0% loss', status: 'success', severity: 'success' }),
      ev({ id: 'f', timestamp: '2026-06-17T12:00:03Z', kind: 'finding', source_kind: 'subagent', title: 'Finding', summary: 'host alive' }),
      ev({ id: 's', timestamp: '2026-06-17T12:00:04Z', kind: 'system', source_kind: 'system', title: 'System', summary: 'awaiting operator' }),
    ], [], OPTS);
    expect(t.map(e => [e.kind, e.role])).toEqual([
      ['command', 'operator'],
      ['action', 'agent'],
      ['finding', 'agent'],
      ['note', 'system'],
    ]);
    // system note is secondary, the rest primary
    expect(t.find(e => e.id === 's')!.prominence).toBe('secondary');
    expect(t.find(e => e.id === 'a')!.prominence).toBe('primary');
  });

  it('interleaves the agent\'s open question chronologically and carries answer handles', () => {
    const t = buildAgentThread([
      ev({ id: 'c', timestamp: '2026-06-17T12:00:01Z', kind: 'command', source_kind: 'dashboard', summary: 'go' }),
      ev({ id: 'a', timestamp: '2026-06-17T12:01:00Z', kind: 'action', summary: 'done' }),
    ], [q()], OPTS); // question created 12:00:30 → between c and a
    expect(t.map(e => e.id)).toEqual(['c', 'question:q1', 'a']);
    const question = t.find(e => e.kind === 'question')!;
    expect(question.queryId).toBe('q1');
    expect(question.role).toBe('agent');
    expect(threadHasOpenQuestion(t)).toBe(true);
  });

  it('drops answered questions and questions for other agents', () => {
    const t = buildAgentThread([], [
      q({ query_id: 'answered', status: 'answered' }),
      q({ query_id: 'other', task_id: 'task-99', agent_id: 'web-2' }),
      q({ query_id: 'mine' }),
    ], OPTS);
    expect(t.map(e => e.queryId)).toEqual(['mine']);
  });

  it('orders oldest→newest (newest at the bottom for follow-to-bottom) and caps with limit', () => {
    const events = Array.from({ length: 5 }, (_, i) => ev({ id: `e${i}`, timestamp: `2026-06-17T12:0${i}:00Z`, summary: String(i) }));
    const t = buildAgentThread(events, [], { ...OPTS, limit: 3 });
    expect(t.map(e => e.id)).toEqual(['e2', 'e3', 'e4']);
  });

  it('keeps same-timestamp events in source (insertion) order, not by id', () => {
    // ids chosen so an id-sort would REVERSE the intended command→action order.
    const t = buildAgentThread([
      ev({ id: 'zzz-command', timestamp: '2026-06-17T12:00:01Z', kind: 'command', source_kind: 'dashboard', summary: 'go' }),
      ev({ id: 'aaa-action', timestamp: '2026-06-17T12:00:01Z', kind: 'action', summary: 'did it' }),
    ], [], OPTS);
    expect(t.map(e => e.id)).toEqual(['zzz-command', 'aaa-action']);
  });

  it('threadHasOpenQuestion is false with no questions', () => {
    expect(threadHasOpenQuestion(buildAgentThread([ev({ id: 'x', timestamp: '2026-06-17T12:00:00Z' })], [], OPTS))).toBe(false);
  });
});
