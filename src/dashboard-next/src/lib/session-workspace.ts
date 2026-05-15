import type { SessionInfo } from './types';

export type SessionGroup = 'live' | 'pending' | 'closed';

export const SESSION_GROUP_LABELS: Record<SessionGroup, string> = {
  live: 'Live',
  pending: 'Pending',
  closed: 'Closed / Error',
};

export function groupForSession(session: SessionInfo): SessionGroup {
  if (session.state === 'connected') return 'live';
  if (session.state === 'pending') return 'pending';
  return 'closed';
}

export function sessionTitle(session: SessionInfo): string {
  return session.title || session.host || session.target_node || session.id.slice(0, 8);
}

export function searchSession(session: SessionInfo, query: string): boolean {
  if (!query) return true;
  const q = query.toLowerCase();
  return [
    session.id,
    session.title,
    session.kind,
    session.transport,
    session.host,
    session.user,
    session.agent_id,
    session.target_node,
    session.principal_node,
    session.credential_node,
    session.action_id,
    session.frontier_item_id,
    session.claimed_by,
    session.notes,
  ].some(value => typeof value === 'string' && value.toLowerCase().includes(q));
}

export function sortSessionsForWorkspace(sessions: SessionInfo[]): SessionInfo[] {
  return [...sessions].sort((a, b) => {
    const ga = groupForSession(a);
    const gb = groupForSession(b);
    if (ga !== gb) return ['live', 'pending', 'closed'].indexOf(ga) - ['live', 'pending', 'closed'].indexOf(gb);
    const ta = new Date(a.last_activity_at || a.started_at || a.created_at || 0).getTime();
    const tb = new Date(b.last_activity_at || b.started_at || b.created_at || 0).getTime();
    return tb - ta;
  });
}

export function groupSessions(sessions: SessionInfo[]): Record<SessionGroup, SessionInfo[]> {
  const result: Record<SessionGroup, SessionInfo[]> = { live: [], pending: [], closed: [] };
  for (const session of sessions) result[groupForSession(session)].push(session);
  return result;
}

export function addAttachedSession(attached: string[], sessionId: string): string[] {
  return attached.includes(sessionId) ? attached : [...attached, sessionId];
}

export function removeAttachedSession(attached: string[], sessionId: string): string[] {
  return attached.filter(id => id !== sessionId);
}
