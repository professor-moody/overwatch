import type { AgentConsoleEvent, AgentConsoleKind } from './types';

// Phase 5 (Mission Control) — collapse the noisy per-event activity stream into
// high-signal threads. Events that share an action_id (directive → acknowledged
// → action_started → action_completed, or validate → approve → execute) fold
// into one collapsible thread whose head is the latest event; everything else
// stays a standalone single-event thread. Pure transform over the canonical
// events projected by the server console endpoint and WebSocket stream.

export type ConsoleSeverity = AgentConsoleEvent['severity'];

export interface ActivityThread {
  /** action_id when the thread is an action lifecycle, else the lone event id. */
  id: string;
  actionId?: string;
  /** Chronological (oldest → newest). */
  events: AgentConsoleEvent[];
  /** The newest event — what the collapsed row shows. */
  latest: AgentConsoleEvent;
  startedAt: string;
  updatedAt: string;
  status?: string;
  count: number;
  /** Loudest severity in the thread, so a failed step keeps the thread loud. */
  severity: ConsoleSeverity;
  /** True when the thread bundles more than one event (offer expand). */
  threaded: boolean;
}

export type ActivityFilter = 'all' | AgentConsoleKind | 'warnings';

export const ACTIVITY_FILTERS: Array<{ id: ActivityFilter; label: string; kinds?: AgentConsoleKind[] }> = [
  { id: 'all', label: 'All' },
  { id: 'action', label: 'Actions' },
  { id: 'command', label: 'Commands' },
  { id: 'approval', label: 'Approvals' },
  { id: 'thought', label: 'Decisions' },
  { id: 'finding', label: 'Findings' },
  { id: 'session', label: 'Sessions', kinds: ['session', 'transcript'] },
  { id: 'system', label: 'System' },
  { id: 'warnings', label: 'Warnings / failures' },
];

const SEVERITY_RANK: Record<string, number> = { error: 3, warning: 2, success: 1, info: 0 };

function loudest(events: AgentConsoleEvent[]): ConsoleSeverity {
  let best: ConsoleSeverity = 'info';
  for (const e of events) {
    if ((SEVERITY_RANK[e.severity] ?? 0) > (SEVERITY_RANK[best] ?? 0)) best = e.severity;
  }
  return best;
}

function byTimestamp(a: AgentConsoleEvent, b: AgentConsoleEvent): number {
  return a.timestamp.localeCompare(b.timestamp);
}

/**
 * Fold events into threads. Events with a shared `links.action_id` group
 * together; events without one are their own single-event thread. Threads are
 * returned newest-latest-event first (matching the stream's reading order).
 */
export function threadConsoleEvents(events: AgentConsoleEvent[]): ActivityThread[] {
  const byAction = new Map<string, AgentConsoleEvent[]>();
  const singles: AgentConsoleEvent[] = [];

  for (const event of events) {
    const actionId = event.links?.action_id;
    if (actionId) {
      if (!byAction.has(actionId)) byAction.set(actionId, []);
      byAction.get(actionId)!.push(event);
    } else {
      singles.push(event);
    }
  }

  const threads: ActivityThread[] = [];

  for (const [actionId, grouped] of byAction) {
    // A lone event that merely references an action_id isn't a "thread" — only
    // bundle when there's a genuine lifecycle (≥2 events).
    if (grouped.length === 1) {
      singles.push(grouped[0]);
      continue;
    }
    const sorted = [...grouped].sort(byTimestamp);
    threads.push({
      id: actionId,
      actionId,
      events: sorted,
      latest: sorted[sorted.length - 1],
      startedAt: sorted[0].timestamp,
      updatedAt: sorted[sorted.length - 1].timestamp,
      status: sorted[sorted.length - 1].status,
      count: sorted.length,
      severity: loudest(sorted),
      threaded: true,
    });
  }

  for (const event of singles) {
    threads.push({
      id: event.id,
      ...(event.links?.action_id ? { actionId: event.links.action_id } : {}),
      events: [event],
      latest: event,
      startedAt: event.timestamp,
      updatedAt: event.timestamp,
      status: event.status,
      count: 1,
      severity: event.severity,
      threaded: false,
    });
  }

  // Newest activity first, by the thread's latest event.
  return threads.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt) || a.id.localeCompare(b.id));
}

/** Merge HTTP reconciliation and WebSocket events without duplicating IDs. */
export function mergeConsoleEvents(current: AgentConsoleEvent[], incoming: AgentConsoleEvent[], limit: number): AgentConsoleEvent[] {
  const merged = new Map<string, AgentConsoleEvent>();
  for (const event of current) merged.set(event.id, event);
  for (const event of incoming) merged.set(event.id, event);
  return [...merged.values()]
    .sort((left, right) => right.timestamp.localeCompare(left.timestamp) || left.id.localeCompare(right.id))
    .slice(0, limit);
}

/**
 * Count genuinely new projected events without trusting transport batch size.
 * Main-channel reconnects and periodic HTTP reconciliation may replay events;
 * only stable event IDs that have not been observed count as unseen activity.
 */
export function collectNewConsoleEventIds(
  knownIds: ReadonlySet<string>,
  incoming: AgentConsoleEvent[],
): string[] {
  const batchIds = new Set<string>();
  const newIds: string[] = [];
  for (const event of incoming) {
    if (knownIds.has(event.id) || batchIds.has(event.id)) continue;
    batchIds.add(event.id);
    newIds.push(event.id);
  }
  return newIds;
}

/** Search only server-projected safe metadata; raw event bodies are excluded. */
export function filterActivityThreads(threads: ActivityThread[], filter: ActivityFilter, search: string): ActivityThread[] {
  const option = ACTIVITY_FILTERS.find(candidate => candidate.id === filter);
  const query = search.trim().toLowerCase();
  return threads.filter(thread => {
    const events = thread.events;
    if (filter === 'warnings') {
      if (thread.severity !== 'warning' && thread.severity !== 'error') return false;
    } else if (filter !== 'all') {
      const kinds = option?.kinds ?? [filter as AgentConsoleKind];
      if (!events.some(event => kinds.includes(event.kind))) return false;
    }
    if (!query) return true;
    return events.some(event => safeActivitySearchText(event).includes(query));
  });
}

function safeActivitySearchText(event: AgentConsoleEvent): string {
  const links = event.links;
  return [
    event.title,
    event.summary,
    event.source_label,
    event.agent_id,
    links?.action_id,
    links?.session_id,
    links?.frontier_item_id,
    ...(links?.finding_ids || []),
    ...(links?.node_ids || []),
  ].filter(Boolean).join(' ').toLowerCase();
}
