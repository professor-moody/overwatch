import type { AgentConsoleEvent } from './types';

// Phase 5 (Mission Control) — collapse the noisy per-event activity stream into
// high-signal threads. Events that share an action_id (directive → acknowledged
// → action_started → action_completed, or validate → approve → execute) fold
// into one collapsible thread whose head is the latest event; everything else
// stays a standalone single-event thread. Pure transform over the events the
// console already builds (operator-console.ts / the agent console endpoint).

export type ConsoleSeverity = AgentConsoleEvent['severity'];

export interface ActivityThread {
  /** action_id when the thread is an action lifecycle, else the lone event id. */
  id: string;
  /** Chronological (oldest → newest). */
  events: AgentConsoleEvent[];
  /** The newest event — what the collapsed row shows. */
  latest: AgentConsoleEvent;
  count: number;
  /** Loudest severity in the thread, so a failed step keeps the thread loud. */
  severity: ConsoleSeverity;
  /** True when the thread bundles more than one event (offer expand). */
  threaded: boolean;
}

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
      events: sorted,
      latest: sorted[sorted.length - 1],
      count: sorted.length,
      severity: loudest(sorted),
      threaded: true,
    });
  }

  for (const event of singles) {
    threads.push({
      id: event.id,
      events: [event],
      latest: event,
      count: 1,
      severity: event.severity,
      threaded: false,
    });
  }

  // Newest activity first, by the thread's latest event.
  return threads.sort((a, b) => b.latest.timestamp.localeCompare(a.latest.timestamp));
}
