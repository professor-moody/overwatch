import { describe, it, expect } from 'vitest';
import { threadConsoleEvents } from '../activity-threads';
import type { AgentConsoleEvent } from '../types';

function ev(o: Partial<AgentConsoleEvent> & { id: string; timestamp: string }): AgentConsoleEvent {
  return {
    agent_id: 'recon-1',
    kind: 'action',
    severity: 'info',
    title: 'Event',
    summary: '',
    ...o,
  } as AgentConsoleEvent;
}

describe('threadConsoleEvents', () => {
  it('folds events sharing an action_id into one chronological thread', () => {
    const threads = threadConsoleEvents([
      ev({ id: 'e2', timestamp: '2026-06-17T12:00:02Z', title: 'started', links: { action_id: 'act-1' } }),
      ev({ id: 'e1', timestamp: '2026-06-17T12:00:01Z', title: 'directive', links: { action_id: 'act-1' } }),
      ev({ id: 'e3', timestamp: '2026-06-17T12:00:03Z', title: 'completed', links: { action_id: 'act-1' } }),
    ]);
    expect(threads).toHaveLength(1);
    expect(threads[0].id).toBe('act-1');
    expect(threads[0].threaded).toBe(true);
    expect(threads[0].count).toBe(3);
    expect(threads[0].events.map(e => e.id)).toEqual(['e1', 'e2', 'e3']); // chronological
    expect(threads[0].latest.id).toBe('e3');
  });

  it('keeps the loudest severity for the thread', () => {
    const threads = threadConsoleEvents([
      ev({ id: 'a', timestamp: '2026-06-17T12:00:01Z', severity: 'info', links: { action_id: 'x' } }),
      ev({ id: 'b', timestamp: '2026-06-17T12:00:02Z', severity: 'error', links: { action_id: 'x' } }),
      ev({ id: 'c', timestamp: '2026-06-17T12:00:03Z', severity: 'success', links: { action_id: 'x' } }),
    ]);
    expect(threads[0].severity).toBe('error');
  });

  it('treats a lone action_id event and event-less events as standalone (not threaded)', () => {
    const threads = threadConsoleEvents([
      ev({ id: 'lonely', timestamp: '2026-06-17T12:00:01Z', links: { action_id: 'solo' } }),
      ev({ id: 'thought', timestamp: '2026-06-17T12:00:02Z', kind: 'thought' }),
    ]);
    expect(threads).toHaveLength(2);
    expect(threads.every(t => !t.threaded && t.count === 1)).toBe(true);
    // standalone thread keyed by event id, not action id
    expect(threads.map(t => t.id).sort()).toEqual(['lonely', 'thought']);
  });

  it('orders threads newest-latest-event first', () => {
    const threads = threadConsoleEvents([
      ev({ id: 'old', timestamp: '2026-06-17T12:00:01Z' }),
      ev({ id: 'newA', timestamp: '2026-06-17T12:00:05Z', links: { action_id: 'k' } }),
      ev({ id: 'newB', timestamp: '2026-06-17T12:00:06Z', links: { action_id: 'k' } }),
    ]);
    // thread 'k' latest = 12:00:06 → first; 'old' single → after
    expect(threads[0].id).toBe('k');
    expect(threads[1].id).toBe('old');
  });
});
