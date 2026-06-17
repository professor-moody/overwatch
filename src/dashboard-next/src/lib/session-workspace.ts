import type { ActivityEntry, FrontierItem, PendingAction, SessionBufferResponse, SessionInfo } from './types';

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

export function sessionOperationalLabel(session: SessionInfo): string {
  const isListener = session.kind === 'socket' && session.mode === 'listen';
  if (isListener && session.state === 'pending') return 'listener waiting';
  if (isListener && session.state === 'connected') return 'shell connected';
  if (isListener && session.state === 'closed') return 'listener closed';
  if (isListener && session.state === 'error') return 'listener error';
  if (session.state === 'connected') return 'connected';
  if (session.state === 'pending') return 'pending';
  return session.state;
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
    session.bind_host,
    session.advertise_host,
    session.accept_mode,
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

/**
 * Sessions owned/claimed by a given agent. Phase 4b uses this to bridge the
 * Operator Console and the Sessions workspace: the focused agent shows an
 * "Open session →" chip, and a session shows a "view agent →" chip. Matches on
 * either the agent's task id or its display label, since `session.agent_id` /
 * `session.claimed_by` may carry either depending on who opened the session.
 */
export function sessionsForAgent(
  sessions: SessionInfo[],
  agent: { id?: string; agent_id?: string } | null | undefined,
): SessionInfo[] {
  if (!agent) return [];
  const ids = new Set(
    [agent.id, agent.agent_id].filter((v): v is string => typeof v === 'string' && v.length > 0),
  );
  if (ids.size === 0) return [];
  return sessions.filter(
    (session) =>
      (!!session.agent_id && ids.has(session.agent_id)) ||
      (!!session.claimed_by && ids.has(session.claimed_by)),
  );
}

export function addAttachedSession(attached: string[], sessionId: string): string[] {
  return attached.includes(sessionId) ? attached : [...attached, sessionId];
}

export function removeAttachedSession(attached: string[], sessionId: string): string[] {
  return attached.filter(id => id !== sessionId);
}

export function sessionSupportsResize(session: Pick<SessionInfo, 'capabilities'> | null | undefined): boolean {
  return session?.capabilities?.supports_resize === true;
}

export function relatedSessionActions(session: SessionInfo, actions: PendingAction[]): PendingAction[] {
  const ids = new Set([
    session.action_id,
    session.frontier_item_id,
    session.target_node,
    session.credential_node,
    session.principal_node,
  ].filter((value): value is string => typeof value === 'string' && value.length > 0));

  return actions.filter(action =>
    ids.has(action.action_id)
    || (!!action.frontier_item_id && ids.has(action.frontier_item_id))
    || (!!action.target_node && ids.has(action.target_node))
    || (!!action.target && ids.has(action.target)),
  );
}

export function relatedSessionFrontier(session: SessionInfo, frontier: FrontierItem[]): FrontierItem[] {
  const ids = new Set([
    session.frontier_item_id,
    session.target_node,
    session.credential_node,
    session.principal_node,
  ].filter((value): value is string => typeof value === 'string' && value.length > 0));

  return frontier.filter(item =>
    ids.has(item.id)
    || (!!item.frontier_item_id && ids.has(item.frontier_item_id))
    || (!!item.target_node && ids.has(item.target_node))
    || (!!item.node_id && ids.has(item.node_id))
    || (!!item.edge_source && ids.has(item.edge_source))
    || (!!item.edge_target && ids.has(item.edge_target)),
  );
}

export function relatedSessionActivity(session: SessionInfo, entries: ActivityEntry[]): ActivityEntry[] {
  const ids = new Set([
    session.id,
    session.action_id,
    session.frontier_item_id,
    session.agent_id,
    session.claimed_by,
    session.target_node,
  ].filter((value): value is string => typeof value === 'string' && value.length > 0));

  return entries.filter(entry => {
    if (entry.action_id && ids.has(entry.action_id)) return true;
    if (entry.agent_id && ids.has(entry.agent_id)) return true;
    if (entry.frontier_item_id && ids.has(entry.frontier_item_id)) return true;
    if (Array.isArray(entry.target_node_ids) && entry.target_node_ids.some(nodeId => ids.has(nodeId))) return true;
    const details = entry.details || {};
    return [
      details.session_id,
      details.action_id,
      details.frontier_item_id,
      details.target_node,
    ].some(value => typeof value === 'string' && ids.has(value));
  });
}

export function sessionCopyFields(session: SessionInfo): Array<{ label: string; value: string }> {
  return [
    { label: 'Session', value: session.id },
    session.action_id ? { label: 'Action', value: session.action_id } : null,
    session.frontier_item_id ? { label: 'Frontier', value: session.frontier_item_id } : null,
    session.target_node ? { label: 'Target', value: session.target_node } : null,
    session.bind_host ? { label: 'Bind', value: session.port ? `${session.bind_host}:${session.port}` : session.bind_host } : null,
    session.advertise_host ? { label: 'Callback', value: session.port ? `${session.advertise_host}:${session.port}` : session.advertise_host } : null,
  ].filter((field): field is { label: string; value: string } => field !== null);
}

export interface SessionBufferCommand {
  text: string;
  line: number;
}

export interface SessionBufferMatch {
  line: number;
  text: string;
}

const ANSI_RE = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;

export function cleanTerminalText(text: string): string {
  return text.replace(ANSI_RE, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

export function extractCommandLikeLines(buffer: SessionBufferResponse | null | undefined): SessionBufferCommand[] {
  if (!buffer?.text) return [];
  const lines = cleanTerminalText(buffer.text).split('\n');
  const commands: SessionBufferCommand[] = [];
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    const promptMatch = trimmed.match(/(?:^[$#]\s+|[>]\s+)([^>$#\n]{1,180})$/);
    const command = promptMatch?.[1]?.trim();
    if (!command) return;
    if (/^(Microsoft Windows|Last login|Connected to session|Session disconnected)/i.test(command)) return;
    if (command.length > 0) commands.push({ text: command, line: index + 1 });
  });
  return commands.slice(-12);
}

export function searchSessionBuffer(buffer: SessionBufferResponse | null | undefined, query: string): SessionBufferMatch[] {
  const q = query.trim().toLowerCase();
  if (!buffer?.text || !q) return [];
  return cleanTerminalText(buffer.text)
    .split('\n')
    .map((line, index) => ({ line: index + 1, text: line }))
    .filter(match => match.text.toLowerCase().includes(q))
    .slice(-25);
}
