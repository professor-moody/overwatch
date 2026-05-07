// ============================================================
// Overwatch — Decision Log (P3.1)
//
// Derived view over the activity log + frontier-linkage state. Each
// `DecisionEntry` captures one decision's full chain:
//
//   frontier_emitted → agent_picked → log_thought* → validated
//   → approved/denied → started → completed/failed
//
// The activity log already records every stage as a discrete event;
// this module groups them by `action_id` (the natural key) and presents
// them as a single ordered timeline. Frontier items that were emitted
// but never claimed by an agent get a single-stage entry too, so
// "the agent ignored item X" is visible in the same view as "the agent
// pursued item Y to completion."
//
// Pure function — no I/O, no engine state mutation. Caller supplies
// the activity log and the frontier-linkage snapshot. The decision
// log is computed on demand; nothing is persisted separately.
// ============================================================

import type { ActivityLogEntry } from './engine-context.js';
import type { FrontierLinkageRecord } from './frontier-linkage.js';

export type DecisionStageKind =
  | 'frontier_emitted'
  | 'agent_picked'
  | 'log_thought'
  | 'validated'
  | 'approved'
  | 'denied'
  | 'started'
  | 'completed'
  | 'failed'
  | 'dropped';

export interface DecisionStage {
  stage: DecisionStageKind;
  timestamp: string;
  /** Pointer to the underlying activity log entry. Caller can dereference
   *  it via `history.find(e => e.event_id === details_ref)` for full detail. */
  details_ref?: string;
  /** Compact, view-friendly summary lifted from the underlying event. */
  summary?: string;
}

export interface DecisionEntry {
  /** Stable ID derived from action_id or frontier_item_id. */
  decision_id: string;
  frontier_item_id?: string;
  action_id?: string;
  agent_id?: string;
  opened_at: string;
  /** ISO timestamp of the latest stage; equals opened_at when only one stage. */
  closed_at: string;
  /** Final outcome class — derived from the last terminal stage. */
  outcome?: 'completed' | 'failed' | 'denied' | 'dropped' | 'open';
  stages: DecisionStage[];
}

const TERMINAL_STAGES: DecisionStageKind[] = ['completed', 'failed', 'denied', 'dropped'];

/**
 * Build the decision log from the activity log + frontier linkage map.
 *
 * Strategy:
 *   1. Group events by action_id where present (each action is a decision).
 *   2. For each frontier-linkage record without a downstream action,
 *      emit a synthetic decision entry with just the frontier_emitted /
 *      dropped stages.
 *   3. Within each entry, order stages by timestamp.
 */
export function buildDecisionLog(
  history: ActivityLogEntry[],
  frontierLinkage: Map<string, FrontierLinkageRecord> | FrontierLinkageRecord[],
): DecisionEntry[] {
  const byAction = new Map<string, DecisionEntry>();
  const seenFrontierItems = new Set<string>();

  for (const entry of history) {
    const stage = classifyEvent(entry);
    if (!stage) continue;

    if (entry.action_id) {
      const decisionId = `act:${entry.action_id}`;
      let dec = byAction.get(decisionId);
      if (!dec) {
        dec = {
          decision_id: decisionId,
          action_id: entry.action_id,
          frontier_item_id: entry.frontier_item_id,
          agent_id: entry.agent_id,
          opened_at: entry.timestamp,
          closed_at: entry.timestamp,
          outcome: 'open',
          stages: [],
        };
        byAction.set(decisionId, dec);
      }
      // Inherit fields the first event might have missed.
      if (!dec.frontier_item_id && entry.frontier_item_id) dec.frontier_item_id = entry.frontier_item_id;
      if (!dec.agent_id && entry.agent_id) dec.agent_id = entry.agent_id;
      if (entry.frontier_item_id) seenFrontierItems.add(entry.frontier_item_id);

      dec.stages.push({
        stage,
        timestamp: entry.timestamp,
        details_ref: entry.event_id,
        summary: shortSummary(entry),
      });
      if (entry.timestamp < dec.opened_at) dec.opened_at = entry.timestamp;
      if (entry.timestamp > dec.closed_at) dec.closed_at = entry.timestamp;
      if (TERMINAL_STAGES.includes(stage)) {
        dec.outcome = stage as DecisionEntry['outcome'];
      }
    }
  }

  // Frontier-linkage items that were emitted but never produced an
  // action_id. These show up as single-stage decisions so the operator
  // can see "frontier picked these but the agent didn't pursue them."
  const linkageRecords: FrontierLinkageRecord[] = Array.isArray(frontierLinkage)
    ? frontierLinkage
    : Array.from(frontierLinkage.values());

  for (const rec of linkageRecords) {
    if (seenFrontierItems.has(rec.frontier_item_id)) continue;
    const decisionId = `fi:${rec.frontier_item_id}`;
    const lastTs = rec.status_set_at ?? rec.emitted_at;
    const stages: DecisionStage[] = [
      {
        stage: 'frontier_emitted',
        timestamp: rec.emitted_at,
        summary: `Frontier item emitted (${rec.linkage_status})`,
      },
    ];
    if (rec.linkage_status === 'dropped') {
      stages.push({
        stage: 'dropped',
        timestamp: lastTs,
        summary: 'Item dropped without a follow-up action',
      });
    }
    byAction.set(decisionId, {
      decision_id: decisionId,
      frontier_item_id: rec.frontier_item_id,
      opened_at: rec.emitted_at,
      closed_at: lastTs,
      outcome: rec.linkage_status === 'dropped' ? 'dropped' : 'open',
      stages,
    });
  }

  // Sort entries' stages by timestamp; sort entries themselves by
  // opened_at descending so newest decisions appear first.
  const out: DecisionEntry[] = [];
  for (const dec of byAction.values()) {
    dec.stages.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    out.push(dec);
  }
  out.sort((a, b) => b.opened_at.localeCompare(a.opened_at));
  return out;
}

/**
 * Map a single activity event to a DecisionStage kind. Returns null when
 * the event isn't part of the decision lifecycle (e.g., raw graph
 * mutations, internal heartbeats).
 */
function classifyEvent(entry: ActivityLogEntry): DecisionStageKind | null {
  switch (entry.event_type) {
    case 'action_validated': {
      // The validation event also carries approval state for queued actions.
      const d = entry.details as { approval_status?: 'approved' | 'denied' | 'timeout' } | undefined;
      if (d?.approval_status === 'denied') return 'denied';
      if (d?.approval_status === 'approved' || d?.approval_status === 'timeout') return 'approved';
      return 'validated';
    }
    case 'action_started':   return 'started';
    case 'action_completed': return 'completed';
    case 'action_failed':    return 'failed';
    case 'agent_registered': return 'agent_picked';
    case 'thought':          return 'log_thought';
    case 'frontier_item_dropped': return 'dropped';
    default: return null;
  }
}

function shortSummary(entry: ActivityLogEntry): string {
  // Lift a one-line summary from the description; stages with rich detail
  // can carry the truncation cost when displayed.
  const d = entry.description ?? '';
  return d.length > 200 ? d.slice(0, 200) + '…' : d;
}

/**
 * Filter the decision log by query. All filters are ANDed; omit a field
 * to skip that filter.
 */
export interface DecisionLogQuery {
  frontier_item_id?: string;
  action_id?: string;
  agent_id?: string;
  outcome?: DecisionEntry['outcome'];
  limit?: number;
}

export function queryDecisionLog(decisions: DecisionEntry[], q: DecisionLogQuery): DecisionEntry[] {
  let out = decisions;
  if (q.frontier_item_id) out = out.filter(d => d.frontier_item_id === q.frontier_item_id);
  if (q.action_id) out = out.filter(d => d.action_id === q.action_id);
  if (q.agent_id) out = out.filter(d => d.agent_id === q.agent_id);
  if (q.outcome) out = out.filter(d => d.outcome === q.outcome);
  if (q.limit && out.length > q.limit) out = out.slice(0, q.limit);
  return out;
}
