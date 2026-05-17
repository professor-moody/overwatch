import { describe, expect, it } from 'vitest';
import {
  addAttachedSession,
  groupSessions,
  relatedSessionActions,
  relatedSessionActivity,
  relatedSessionFrontier,
  removeAttachedSession,
  searchSession,
  sessionCopyFields,
  sortSessionsForWorkspace,
} from '../session-workspace';
import type { ActivityEntry, FrontierItem, PendingAction, SessionInfo } from '../types';

const session = (props: Partial<SessionInfo>): SessionInfo => ({
  id: 'session-1',
  kind: 'pty',
  state: 'connected',
  title: 'Shell',
  ...props,
});

const action = (props: Partial<PendingAction>): PendingAction => ({
  action_id: 'act-1',
  technique: 'test',
  target: 'host-a',
  noise_level: 0.1,
  description: 'test action',
  submitted_at: '2026-05-15T00:00:00Z',
  ...props,
});

const frontier = (props: Partial<FrontierItem>): FrontierItem => ({
  id: 'fi-1',
  type: 'incomplete_node',
  priority: 1,
  description: 'frontier',
  ...props,
});

const activity = (props: Partial<ActivityEntry>): ActivityEntry => ({
  id: 'evt-1',
  timestamp: '2026-05-15T00:00:00Z',
  event_type: 'action_started',
  description: 'started',
  ...props,
});

describe('session workspace helpers', () => {
  it('groups sessions by operator state', () => {
    const grouped = groupSessions([
      session({ id: 'live', state: 'connected' }),
      session({ id: 'pending', state: 'pending' }),
      session({ id: 'closed', state: 'closed' }),
      session({ id: 'error', state: 'error' }),
    ]);

    expect(grouped.live.map(s => s.id)).toEqual(['live']);
    expect(grouped.pending.map(s => s.id)).toEqual(['pending']);
    expect(grouped.closed.map(s => s.id)).toEqual(['closed', 'error']);
  });

  it('filters by target, owner, notes, and identifiers', () => {
    const s = session({
      id: 'session-alpha',
      target_node: 'host-dc01',
      credential_node: 'cred-1',
      claimed_by: 'agent-7',
      notes: 'interesting shell',
    });

    expect(searchSession(s, 'dc01')).toBe(true);
    expect(searchSession(s, 'agent-7')).toBe(true);
    expect(searchSession(s, 'interesting')).toBe(true);
    expect(searchSession(s, 'missing')).toBe(false);
  });

  it('sorts live before pending before closed and newest first inside groups', () => {
    const sorted = sortSessionsForWorkspace([
      session({ id: 'old-live', state: 'connected', last_activity_at: '2026-05-15T00:00:00Z' }),
      session({ id: 'closed', state: 'closed', last_activity_at: '2026-05-15T02:00:00Z' }),
      session({ id: 'new-live', state: 'connected', last_activity_at: '2026-05-15T03:00:00Z' }),
      session({ id: 'pending', state: 'pending', last_activity_at: '2026-05-15T04:00:00Z' }),
    ]);

    expect(sorted.map(s => s.id)).toEqual(['new-live', 'old-live', 'pending', 'closed']);
  });

  it('updates attached terminal id state without duplicates', () => {
    expect(addAttachedSession(['a'], 'a')).toEqual(['a']);
    expect(addAttachedSession(['a'], 'b')).toEqual(['a', 'b']);
    expect(removeAttachedSession(['a', 'b'], 'a')).toEqual(['b']);
  });

  it('extracts related actions, frontier items, activity, and copy fields', () => {
    const s = session({
      id: 'sess-1',
      action_id: 'act-1',
      frontier_item_id: 'fi-1',
      target_node: 'host-a',
    });

    expect(relatedSessionActions(s, [
      action({ action_id: 'act-1' }),
      action({ action_id: 'act-2', target: 'host-z', target_node: 'host-z' }),
    ]).map(item => item.action_id)).toEqual(['act-1']);

    expect(relatedSessionFrontier(s, [
      frontier({ id: 'fi-1' }),
      frontier({ id: 'fi-2', target_node: 'host-z' }),
    ]).map(item => item.id)).toEqual(['fi-1']);

    expect(relatedSessionActivity(s, [
      activity({ action_id: 'act-1' }),
      activity({ id: 'evt-2', details: { session_id: 'sess-1' } }),
      activity({ id: 'evt-3', action_id: 'act-x' }),
    ]).map(item => item.id)).toEqual(['evt-1', 'evt-2']);

    expect(sessionCopyFields(s).map(field => field.label)).toEqual(['Session', 'Action', 'Frontier', 'Target']);
  });
});
