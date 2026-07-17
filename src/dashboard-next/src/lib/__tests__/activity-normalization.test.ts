import { describe, expect, it } from 'vitest';
import { normalizeActivityEntries } from '../api';

describe('activity compatibility projection', () => {
  it('repairs untyped legacy planner dispatches returned by getHistory', () => {
    const [entry] = normalizeActivityEntries([{
      event_id: 'legacy-planner-row',
      timestamp: '2026-07-16T00:00:00.000Z',
      description: 'Agent dispatched: planner-old for undefined',
    } as any]);

    expect(entry.description).toBe('Agent dispatched: planner-old as operator planner');
    expect(entry.event_type).toBe('system');
  });
});
