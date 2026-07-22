// ============================================================
// Overwatch — changes_since digest
//
// "What happened since you last looked?" over the activity log: new findings +
// which sub-agents completed since a timestamp + a recommendation. Pure and
// shared by get_state's changes_since branch (src/tools/state.ts) and the
// read-only NL `what changed` query (src/services/query-interpreter.ts), so the
// two never drift.
// ============================================================

import type { ActivityLogEntry } from './engine-context.js';

export interface ChangesSinceDigest {
  since: string;
  findings: number;
  agents_completed: number;
  completed_agent_ids: string[];
  total_events: number;
  recommendation: string;
}

/**
 * Compute the changes-since digest over `history` for entries strictly after
 * `since`. Returns null when `since` is not a parseable timestamp so the caller
 * can decide the fallback (get_state ignores it; the NL query degrades to no
 * window).
 */
export function computeChangesSince(history: ActivityLogEntry[], since: string): ChangesSinceDigest | null {
  const sinceMs = Date.parse(since);
  if (Number.isNaN(sinceMs)) return null;
  // Inclusive of the boundary millisecond: batched appliers stamp many events with one
  // timestamp, and the caller feeds a prior timestamp back as `since`, so a strict `>`
  // permanently drops an event landing exactly at `sinceMs` (the digest is a coarse
  // count, so at worst a boundary event is re-announced once — far better than a
  // silently missed completion).
  const recent = history.filter(h => Date.parse(h.timestamp) >= sinceMs);
  const isFinding = (h: ActivityLogEntry) =>
    h.category === 'finding' || (h.event_type ?? '').startsWith('finding');
  const findings = recent.filter(isFinding).length;
  const completedAgents = [...new Set(
    recent.filter(h => h.event_type === 'agent_transcript_submitted')
      .map(h => h.agent_id)
      .filter((v): v is string => !!v),
  )];
  const material = findings + completedAgents.length;
  return {
    since,
    findings,
    agents_completed: completedAgents.length,
    completed_agent_ids: completedAgents,
    total_events: recent.length,
    recommendation: material > 0
      ? 'New results since your last check — read the completed agents\' summaries/findings, re-rank the frontier, and re-dispatch or report before continuing.'
      : 'No new findings or agent completions since your last check.',
  };
}
