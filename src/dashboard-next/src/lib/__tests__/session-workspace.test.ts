import { describe, expect, it } from 'vitest';
import {
  addAttachedSession,
  groupSessions,
  removeAttachedSession,
  searchSession,
  sortSessionsForWorkspace,
} from '../session-workspace';
import type { SessionInfo } from '../types';

const session = (props: Partial<SessionInfo>): SessionInfo => ({
  id: 'session-1',
  kind: 'pty',
  state: 'connected',
  title: 'Shell',
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
});
