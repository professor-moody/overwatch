import { describe, it, expect } from 'vitest';
import { buildDecisionLog, queryDecisionLog } from '../decision-log.js';
import type { ActivityLogEntry } from '../engine-context.js';
import type { FrontierLinkageRecord } from '../frontier-linkage.js';

function ev(o: Partial<ActivityLogEntry> & { event_id: string; timestamp: string; description: string }): ActivityLogEntry {
  return o as ActivityLogEntry;
}

describe('buildDecisionLog (P3.1)', () => {
  it('groups events under the same action_id into one DecisionEntry', () => {
    const history = [
      ev({ event_id: 'e1', timestamp: '2026-01-01T10:00:00Z', description: 'agent registered',
        event_type: 'agent_registered', action_id: 'a1', frontier_item_id: 'fi-1', agent_id: 'agent-A' }),
      ev({ event_id: 'e2', timestamp: '2026-01-01T10:00:01Z', description: 'thinking',
        event_type: 'thought', action_id: 'a1', agent_id: 'agent-A' }),
      ev({ event_id: 'e3', timestamp: '2026-01-01T10:00:02Z', description: 'validated',
        event_type: 'action_validated', action_id: 'a1' }),
      ev({ event_id: 'e4', timestamp: '2026-01-01T10:00:03Z', description: 'started',
        event_type: 'action_started', action_id: 'a1' }),
      ev({ event_id: 'e5', timestamp: '2026-01-01T10:00:10Z', description: 'completed',
        event_type: 'action_completed', action_id: 'a1' }),
    ];
    const log = buildDecisionLog(history, []);
    expect(log).toHaveLength(1);
    const dec = log[0];
    expect(dec.action_id).toBe('a1');
    expect(dec.frontier_item_id).toBe('fi-1');
    expect(dec.agent_id).toBe('agent-A');
    expect(dec.outcome).toBe('completed');
    expect(dec.stages.map(s => s.stage)).toEqual([
      'agent_picked', 'log_thought', 'validated', 'started', 'completed',
    ]);
    // details_ref points back at the underlying event_id.
    expect(dec.stages[0].details_ref).toBe('e1');
    expect(dec.stages[4].details_ref).toBe('e5');
    expect(dec.opened_at).toBe('2026-01-01T10:00:00Z');
    expect(dec.closed_at).toBe('2026-01-01T10:00:10Z');
  });

  it('records denied outcome when validation carries approval_status=denied', () => {
    const history = [
      ev({ event_id: 'e1', timestamp: '2026-01-01T10:00:00Z', description: 'pending',
        event_type: 'action_validated', action_id: 'a-deny',
        details: { approval_status: 'denied', operator_notes: 'too risky' } }),
    ];
    const log = buildDecisionLog(history, []);
    expect(log[0].outcome).toBe('denied');
    expect(log[0].stages[0].stage).toBe('denied');
  });

  it('action_failed bubbles to outcome=failed', () => {
    const history = [
      ev({ event_id: 'e1', timestamp: '2026-01-01T10:00:00Z', description: 'started',
        event_type: 'action_started', action_id: 'a-bad' }),
      ev({ event_id: 'e2', timestamp: '2026-01-01T10:00:01Z', description: 'failed',
        event_type: 'action_failed', action_id: 'a-bad' }),
    ];
    const log = buildDecisionLog(history, []);
    expect(log[0].outcome).toBe('failed');
  });

  it('frontier-linkage records WITHOUT a downstream action become single-stage entries', () => {
    const linkage: FrontierLinkageRecord[] = [
      {
        frontier_item_id: 'fi-orphan',
        emitted_at: '2026-01-01T09:00:00Z',
        emitted_call_index: 1,
        last_seen_call_index: 6,
        linkage_status: 'dropped',
        status_set_at: '2026-01-01T09:30:00Z',
      },
    ];
    const log = buildDecisionLog([], linkage);
    expect(log).toHaveLength(1);
    expect(log[0].decision_id).toBe('fi:fi-orphan');
    expect(log[0].outcome).toBe('dropped');
    expect(log[0].stages.map(s => s.stage)).toEqual(['frontier_emitted', 'dropped']);
  });

  it('frontier items that DID produce an action are NOT duplicated as orphan entries', () => {
    const history = [
      ev({ event_id: 'e1', timestamp: '2026-01-01T10:00:00Z', description: 'registered',
        event_type: 'agent_registered', action_id: 'a1', frontier_item_id: 'fi-1' }),
    ];
    const linkage: FrontierLinkageRecord[] = [
      {
        frontier_item_id: 'fi-1',
        emitted_at: '2026-01-01T09:00:00Z',
        emitted_call_index: 1,
        last_seen_call_index: 2,
        linkage_status: 'pursued',
      },
    ];
    const log = buildDecisionLog(history, linkage);
    expect(log).toHaveLength(1);
    expect(log[0].action_id).toBe('a1');
    expect(log[0].decision_id).toBe('act:a1');
  });

  it('entries are sorted opened_at descending (newest first)', () => {
    const history = [
      ev({ event_id: 'old1', timestamp: '2026-01-01T01:00:00Z', description: 'old',
        event_type: 'action_started', action_id: 'old-act' }),
      ev({ event_id: 'new1', timestamp: '2026-01-01T05:00:00Z', description: 'new',
        event_type: 'action_started', action_id: 'new-act' }),
    ];
    const log = buildDecisionLog(history, []);
    expect(log[0].action_id).toBe('new-act');
    expect(log[1].action_id).toBe('old-act');
  });
});

describe('queryDecisionLog (P3.1)', () => {
  const history = [
    ev({ event_id: 'a', timestamp: '2026-01-01T10:00:00Z', description: 'a', event_type: 'action_started', action_id: 'act-A', agent_id: 'alice', frontier_item_id: 'fi-1' }),
    ev({ event_id: 'b', timestamp: '2026-01-01T10:00:01Z', description: 'b', event_type: 'action_completed', action_id: 'act-A' }),
    ev({ event_id: 'c', timestamp: '2026-01-01T11:00:00Z', description: 'c', event_type: 'action_started', action_id: 'act-B', agent_id: 'bob', frontier_item_id: 'fi-2' }),
    ev({ event_id: 'd', timestamp: '2026-01-01T11:00:01Z', description: 'd', event_type: 'action_failed', action_id: 'act-B' }),
  ];
  const decisions = buildDecisionLog(history, []);

  it('filters by action_id', () => {
    const r = queryDecisionLog(decisions, { action_id: 'act-A' });
    expect(r).toHaveLength(1);
    expect(r[0].action_id).toBe('act-A');
  });

  it('filters by agent_id', () => {
    const r = queryDecisionLog(decisions, { agent_id: 'bob' });
    expect(r).toHaveLength(1);
    expect(r[0].agent_id).toBe('bob');
  });

  it('filters by frontier_item_id', () => {
    const r = queryDecisionLog(decisions, { frontier_item_id: 'fi-2' });
    expect(r).toHaveLength(1);
    expect(r[0].action_id).toBe('act-B');
  });

  it('filters by outcome', () => {
    expect(queryDecisionLog(decisions, { outcome: 'completed' })).toHaveLength(1);
    expect(queryDecisionLog(decisions, { outcome: 'failed' })).toHaveLength(1);
  });

  it('respects limit', () => {
    expect(queryDecisionLog(decisions, { limit: 1 })).toHaveLength(1);
  });
});
