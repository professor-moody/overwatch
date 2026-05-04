import { describe, it, expect } from 'vitest';
import { FrontierLinkageTracker, DEFAULT_DROP_THRESHOLD } from '../frontier-linkage.js';
import type { ActivityLogEntry } from '../engine-context.js';

function entry(partial: Partial<ActivityLogEntry> & { description: string; event_id: string }): ActivityLogEntry {
  return {
    timestamp: new Date().toISOString(),
    ...partial,
  } as ActivityLogEntry;
}

describe('FrontierLinkageTracker', () => {
  it('records emitted items and assigns sequential call indices', () => {
    const t = new FrontierLinkageTracker();
    const i1 = t.recordEmitted(['fi-a', 'fi-b']);
    const i2 = t.recordEmitted(['fi-a']);
    expect(i1).toBe(1);
    expect(i2).toBe(2);
    expect(t.size()).toBe(2);
    expect(t.get('fi-a')?.last_seen_call_index).toBe(2);
    expect(t.get('fi-b')?.last_seen_call_index).toBe(1);
  });

  it('upgrades status on validate / start / complete events', () => {
    const t = new FrontierLinkageTracker();
    t.recordEmitted(['fi-x']);

    t.observe(entry({ event_id: 'e1', description: 'validated', event_type: 'action_validated', frontier_item_id: 'fi-x' }));
    expect(t.get('fi-x')?.linkage_status).toBe('validated');

    t.observe(entry({ event_id: 'e2', description: 'started', event_type: 'action_started', frontier_item_id: 'fi-x' }));
    expect(t.get('fi-x')?.linkage_status).toBe('pursued');

    // Subsequent validated event must NOT downgrade pursued -> validated
    t.observe(entry({ event_id: 'e3', description: 'late validate', event_type: 'action_validated', frontier_item_id: 'fi-x' }));
    expect(t.get('fi-x')?.linkage_status).toBe('pursued');
  });

  it('marks rejected_explicit on log_thought rejection events', () => {
    const t = new FrontierLinkageTracker();
    t.recordEmitted(['fi-y']);
    t.observe(entry({
      event_id: 'e1',
      description: 'rejection',
      event_type: 'thought',
      frontier_item_id: 'fi-y',
      details: { kind: 'rejection', content: 'not worth the noise' } as any,
    }));
    expect(t.get('fi-y')?.linkage_status).toBe('rejected_explicit');
  });

  it('ignores events with no frontier_item_id', () => {
    const t = new FrontierLinkageTracker();
    t.recordEmitted(['fi-a']);
    t.observe(entry({ event_id: 'e1', description: 'unrelated', event_type: 'action_completed' }));
    expect(t.get('fi-a')?.linkage_status).toBe('open');
  });

  it('sweeps items dropped after the threshold without progress', () => {
    const t = new FrontierLinkageTracker();
    t.recordEmitted(['fi-a']); // call 1
    for (let i = 0; i < DEFAULT_DROP_THRESHOLD; i++) {
      t.recordEmitted(['fi-other']); // 2..6
    }
    const dropped = t.sweepDropped();
    expect(dropped.length).toBe(1);
    expect(dropped[0].frontier_item_id).toBe('fi-a');
    expect(t.get('fi-a')?.linkage_status).toBe('dropped');
    // Already-dropped items are not re-reported on subsequent sweeps
    const dropped2 = t.sweepDropped();
    expect(dropped2.length).toBe(0);
  });

  it('does not drop items that have already been pursued', () => {
    const t = new FrontierLinkageTracker();
    t.recordEmitted(['fi-a']);
    t.observe(entry({ event_id: 'e1', description: 'done', event_type: 'action_completed', frontier_item_id: 'fi-a' }));
    for (let i = 0; i < DEFAULT_DROP_THRESHOLD + 3; i++) {
      t.recordEmitted(['fi-other']);
    }
    expect(t.sweepDropped()).toEqual([]);
    expect(t.get('fi-a')?.linkage_status).toBe('pursued');
  });

  it('summary tallies status counts', () => {
    const t = new FrontierLinkageTracker();
    t.recordEmitted(['a', 'b', 'c', 'd']);
    t.observe(entry({ event_id: 'e1', description: '', event_type: 'action_validated', frontier_item_id: 'a' }));
    t.observe(entry({ event_id: 'e2', description: '', event_type: 'action_completed', frontier_item_id: 'b' }));
    t.observe(entry({ event_id: 'e3', description: '', event_type: 'thought', frontier_item_id: 'c', details: { kind: 'rejection' } as any }));
    const s = t.summary();
    expect(s.total).toBe(4);
    expect(s.open).toBe(1);
    expect(s.validated).toBe(1);
    expect(s.pursued).toBe(1);
    expect(s.rejected_explicit).toBe(1);
    expect(s.dropped).toBe(0);
  });

  it('serialize/deserialize round-trips', () => {
    const t = new FrontierLinkageTracker();
    t.recordEmitted(['a', 'b']);
    t.observe(entry({ event_id: 'e1', description: '', event_type: 'action_completed', frontier_item_id: 'a' }));
    const raw = t.serialize();

    const restored = FrontierLinkageTracker.deserialize(raw);
    expect(restored.callIndex()).toBe(t.callIndex());
    expect(restored.size()).toBe(2);
    expect(restored.get('a')?.linkage_status).toBe('pursued');
    expect(restored.get('b')?.linkage_status).toBe('open');
  });

  it('recording an item that was previously dropped resets it to open', () => {
    const t = new FrontierLinkageTracker();
    t.recordEmitted(['fi-a']);
    for (let i = 0; i < DEFAULT_DROP_THRESHOLD; i++) t.recordEmitted(['fi-other']);
    t.sweepDropped();
    expect(t.get('fi-a')?.linkage_status).toBe('dropped');

    t.recordEmitted(['fi-a']);
    expect(t.get('fi-a')?.linkage_status).toBe('open');
  });
});
