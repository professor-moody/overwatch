import type { ActivityEntry } from './types';

export type ActivityClass = 'approval' | 'session' | 'started' | 'completed' | 'failed' | 'finding' | 'default';

export interface ActivityFilters {
  classFilter?: ActivityClass | '';
  search?: string;
}

export interface ActivityLinks {
  actionId?: string;
  agentId?: string;
  nodeIds: string[];
  frontierItemId?: string;
}

const NODE_TOKEN_RE = /\b(?:host|svc|user|cred|dc|web|db|fs|ws|node|idp|cloud)[-_][a-z0-9_.:-]+\b/gi;

export function classifyActivity(entry: ActivityEntry): ActivityClass {
  const desc = (entry.description || '').toLowerCase();
  const type = (entry.event_type || '').toLowerCase();
  if (type.includes('approval') || desc.includes('approval') || desc.includes('approved') || desc.includes('denied')) return 'approval';
  if (type.includes('session') || desc.includes('session')) return 'session';
  if (type.includes('started') || desc.includes('started')) return 'started';
  if (type.includes('completed') || desc.includes('completed')) return 'completed';
  if (type.includes('failed') || desc.includes('failed') || type.includes('error')) return 'failed';
  if (type.includes('finding') || desc.includes('finding') || desc.includes('reported') || desc.includes('parsed')) return 'finding';
  return 'default';
}

export function extractActivityLinks(entry: ActivityEntry): ActivityLinks {
  const details = entry.details || {};
  const nodeSet = new Set<string>();
  for (const value of [
    details.node_id,
    details.target_node,
    details.source_node,
    details.edge_source,
    details.edge_target,
    details.credential_node,
    details.principal_node,
  ]) {
    if (typeof value === 'string' && value.trim()) nodeSet.add(value.trim());
  }
  for (const match of `${entry.description || ''} ${entry.event_type || ''}`.matchAll(NODE_TOKEN_RE)) {
    nodeSet.add(match[0]);
  }

  return {
    actionId: entry.action_id || stringDetail(details.action_id),
    agentId: entry.agent_id || stringDetail(details.agent_id),
    frontierItemId: stringDetail(details.frontier_item_id),
    nodeIds: [...nodeSet],
  };
}

export function filterActivity(entries: ActivityEntry[], filters: ActivityFilters): ActivityEntry[] {
  const q = (filters.search || '').trim().toLowerCase();
  return entries.filter(entry => {
    if (filters.classFilter && classifyActivity(entry) !== filters.classFilter) return false;
    if (!q) return true;
    const links = extractActivityLinks(entry);
    return [
      entry.id,
      entry.event_type,
      entry.description,
      entry.action_id,
      entry.agent_id,
      links.frontierItemId,
      ...links.nodeIds,
    ].some(value => typeof value === 'string' && value.toLowerCase().includes(q));
  });
}

export function selectDefaultActivityEntry(entries: ActivityEntry[]): ActivityEntry | null {
  return entries[0] || null;
}

/**
 * Stable identity for an activity entry that survives polling re-fetches (which
 * replace every entry object). Prefers the server's event_id (always set on
 * /api/history rows), then id, then a composite. The index only feeds the
 * composite fallback, which real history rows never hit.
 */
export function activityEntryKey(entry: ActivityEntry, index = 0): string {
  const eventId = (entry as ActivityEntry & { event_id?: string }).event_id;
  return eventId || entry.id || `${entry.timestamp}-${entry.event_type}-${index}`;
}

/**
 * Resolve the operator's selected entry by stable id rather than object identity,
 * so a 5s poll that re-fetches structurally-equal entries doesn't drop the
 * selection (which would snap the detail pane back to the newest row). Falls back
 * to the default selection when the id is absent (e.g. the event aged out of the
 * fetched window).
 */
export function resolveSelectedActivityEntry(entries: ActivityEntry[], selectedId: string | null): ActivityEntry | null {
  if (selectedId) {
    const match = entries.find((entry, index) => activityEntryKey(entry, index) === selectedId);
    if (match) return match;
  }
  return selectDefaultActivityEntry(entries);
}

function stringDetail(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}
