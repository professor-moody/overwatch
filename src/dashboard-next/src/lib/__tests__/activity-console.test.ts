import { describe, expect, it } from 'vitest';
import { classifyActivity, extractActivityLinks, filterActivity, selectDefaultActivityEntry, activityEntryKey, resolveSelectedActivityEntry } from '../activity-console';
import type { ActivityEntry } from '../types';

function entry(partial: Partial<ActivityEntry>): ActivityEntry {
  return {
    id: partial.id || 'evt-1',
    timestamp: partial.timestamp || '2026-05-15T10:00:00Z',
    event_type: partial.event_type || 'action_started',
    description: partial.description || 'started on host-1',
    ...partial,
  };
}

describe('activity console helpers', () => {
  it('classifies approvals, sessions, failures, findings, and lifecycle events', () => {
    expect(classifyActivity(entry({ event_type: 'action_validated', description: 'approval queued' }))).toBe('approval');
    expect(classifyActivity(entry({ event_type: 'session_opened', description: 'shell session opened' }))).toBe('session');
    expect(classifyActivity(entry({ event_type: 'action_failed', description: 'failed' }))).toBe('failed');
    expect(classifyActivity(entry({ event_type: 'finding_ingested', description: 'finding reported' }))).toBe('finding');
    expect(classifyActivity(entry({ event_type: 'action_completed', description: 'completed' }))).toBe('completed');
  });

  it('extracts action, agent, frontier, and graph links', () => {
    const links = extractActivityLinks(entry({
      action_id: 'act-1',
      agent_id: 'agent-1',
      description: 'checked host-1 and cred-admin',
      details: { frontier_item_id: 'fi-1', target_node: 'svc-rdp' },
    }));

    expect(links.actionId).toBe('act-1');
    expect(links.agentId).toBe('agent-1');
    expect(links.frontierItemId).toBe('fi-1');
    expect(links.nodeIds).toContain('svc-rdp');
    expect(links.nodeIds).toContain('host-1');
    expect(links.nodeIds).toContain('cred-admin');
  });

  it('filters by class and free text across extracted links', () => {
    const entries = [
      entry({ id: 'a', event_type: 'action_started', description: 'started host-1' }),
      entry({ id: 'b', event_type: 'action_failed', description: 'failed host-2' }),
    ];

    expect(filterActivity(entries, { classFilter: 'failed' }).map(e => e.id)).toEqual(['b']);
    expect(filterActivity(entries, { search: 'host-1' }).map(e => e.id)).toEqual(['a']);
  });

  it('selects the newest visible entry from newest-first history', () => {
    const entries = [
      entry({ id: 'new', timestamp: '2026-05-15T10:02:00Z' }),
      entry({ id: 'old', timestamp: '2026-05-15T10:00:00Z' }),
    ];

    expect(selectDefaultActivityEntry(entries)?.id).toBe('new');
    expect(selectDefaultActivityEntry([])).toBeNull();
  });

  it('resolves the selected entry by stable id across a poll re-fetch (no snap to newest)', () => {
    const first = [
      entry({ id: 'c', event_id: 'c', timestamp: '2026-05-15T10:02:00Z' }),
      entry({ id: 'b', event_id: 'b', timestamp: '2026-05-15T10:01:00Z' }),
      entry({ id: 'a', event_id: 'a', timestamp: '2026-05-15T10:00:00Z' }),
    ];
    const selectedId = activityEntryKey(first[2]); // the oldest row, 'a'
    // A poll replaces every entry with a structurally-equal NEW object reference.
    const refetched = first.map(e => ({ ...e }));
    // Reference identity is gone, but the id still resolves the same logical entry
    // instead of snapping to the newest (first).
    expect(resolveSelectedActivityEntry(refetched, selectedId)?.id).toBe('a');
    // Selection aged out of the window → fall back to the default (newest-first ⇒ first).
    expect(resolveSelectedActivityEntry(refetched, 'gone')?.id).toBe('c');
    // No selection → default.
    expect(resolveSelectedActivityEntry(refetched, null)?.id).toBe('c');
  });
});
