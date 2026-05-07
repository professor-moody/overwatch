// ============================================================
// Overwatch — Action Introspection (P3.2)
//
// Answer "why did the agent do X?" for any action_id. Pulls together:
//   - The frontier item that motivated it (from actionFrontierMap)
//   - The full log_thought chain on that action_id
//   - The "considered alternatives" the agent recorded in those thoughts
//   - Prior action_ids referenced via `related_action_ids` in the
//     thoughts (causal chain)
//   - Validation + approval outcomes
//   - Final outcome (completed/failed/timeout/etc.)
//
// All data already lives in the activity log + actionFrontierMap; this
// module just projects it into a single answer-shaped record.
// ============================================================

import type { ActivityLogEntry } from './engine-context.js';
import type { FrontierItem } from '../types.js';

export interface ExplainActionResult {
  action_id: string;
  found: boolean;
  /** The action's authoring agent (if known). */
  agent_id?: string;
  frontier_item_id?: string;
  /** The full FrontierItem record at the time it was emitted, when we can recover it. */
  frontier_item?: FrontierItem;
  /** Every log_thought event on this action_id, oldest first. */
  log_thought_chain: Array<{
    event_id: string;
    timestamp: string;
    kind?: string;
    description: string;
    confidence?: number;
  }>;
  /** Flat list of alternatives the agent claimed to consider, deduplicated. */
  considered_alternatives: string[];
  /** Prior action_ids the thoughts referenced via `related_action_ids`. */
  prior_actions_referenced: string[];
  /** Validation outcome record (most recent action_validated event). */
  validation?: {
    event_id: string;
    timestamp: string;
    validation_result?: string;
    errors?: string[];
    warnings?: string[];
  };
  /** Approval outcome record, if the action went through the queue. */
  approval?: {
    event_id: string;
    timestamp: string;
    approval_status?: 'approved' | 'denied' | 'timeout';
    auto_approved?: boolean;
    operator_notes?: string;
    reason?: string;
  };
  /** Terminal outcome — the latest action_completed/action_failed event. */
  outcome?: {
    event_id: string;
    timestamp: string;
    classification?: 'success' | 'failure' | 'partial' | 'neutral';
    description: string;
  };
}

export function explainAction(
  history: ActivityLogEntry[],
  actionId: string,
  frontierItemLookup?: (id: string) => FrontierItem | undefined,
): ExplainActionResult {
  const events = history.filter(e => e.action_id === actionId);
  if (events.length === 0) {
    return {
      action_id: actionId,
      found: false,
      log_thought_chain: [],
      considered_alternatives: [],
      prior_actions_referenced: [],
    };
  }

  const sorted = [...events].sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  // Pull authoring agent + frontier_item_id from the first event that has them.
  const firstWithAgent = sorted.find(e => e.agent_id);
  const firstWithFrontier = sorted.find(e => e.frontier_item_id);
  const agent_id = firstWithAgent?.agent_id;
  const frontier_item_id = firstWithFrontier?.frontier_item_id;

  // log_thought chain.
  const thoughts = sorted.filter(e => e.event_type === 'thought');
  const log_thought_chain = thoughts.map(t => {
    const d = t.details as { kind?: string; confidence?: number } | undefined;
    return {
      event_id: t.event_id,
      timestamp: t.timestamp,
      kind: d?.kind,
      description: t.description,
      ...(d?.confidence !== undefined ? { confidence: d.confidence } : {}),
    };
  });

  // Alternatives + prior actions are stashed inside `details` on the thought.
  const altSet = new Set<string>();
  const priorSet = new Set<string>();
  for (const t of thoughts) {
    const d = t.details as {
      considered_alternatives?: unknown;
      related_action_ids?: unknown;
    } | undefined;
    if (d?.considered_alternatives && Array.isArray(d.considered_alternatives)) {
      for (const alt of d.considered_alternatives) {
        if (typeof alt === 'string' && alt.length > 0) altSet.add(alt);
      }
    }
    if (d?.related_action_ids && Array.isArray(d.related_action_ids)) {
      for (const ref of d.related_action_ids) {
        if (typeof ref === 'string' && ref.length > 0 && ref !== actionId) priorSet.add(ref);
      }
    }
  }

  // Validation: most recent action_validated.
  const validatedEvents = sorted.filter(e => e.event_type === 'action_validated');
  const lastValidated = validatedEvents[validatedEvents.length - 1];
  let validation: ExplainActionResult['validation'];
  let approval: ExplainActionResult['approval'];
  if (lastValidated) {
    const d = lastValidated.details as {
      errors?: string[];
      warnings?: string[];
      approval_status?: 'approved' | 'denied' | 'timeout';
      auto_approved?: boolean;
      operator_notes?: string;
      reason?: string;
    } | undefined;
    validation = {
      event_id: lastValidated.event_id,
      timestamp: lastValidated.timestamp,
      validation_result: lastValidated.validation_result,
      ...(d?.errors ? { errors: d.errors } : {}),
      ...(d?.warnings ? { warnings: d.warnings } : {}),
    };
    // Approval status rides on the validation event when it goes through the queue.
    if (d?.approval_status) {
      approval = {
        event_id: lastValidated.event_id,
        timestamp: lastValidated.timestamp,
        approval_status: d.approval_status,
        ...(d.auto_approved !== undefined ? { auto_approved: d.auto_approved } : {}),
        ...(d.operator_notes ? { operator_notes: d.operator_notes } : {}),
        ...(d.reason ? { reason: d.reason } : {}),
      };
    }
  }

  // Outcome: latest action_completed / action_failed.
  const terminalEvents = sorted.filter(e =>
    e.event_type === 'action_completed' || e.event_type === 'action_failed',
  );
  const lastTerminal = terminalEvents[terminalEvents.length - 1];
  let outcome: ExplainActionResult['outcome'];
  if (lastTerminal) {
    outcome = {
      event_id: lastTerminal.event_id,
      timestamp: lastTerminal.timestamp,
      classification: lastTerminal.result_classification,
      description: lastTerminal.description,
    };
  }

  // Frontier item lookup (best-effort): the frontier-item snapshot the
  // agent saw at registration time isn't persisted, so we resolve to the
  // current frontier-linkage record if the caller provides a lookup.
  const frontier_item = frontier_item_id && frontierItemLookup
    ? frontierItemLookup(frontier_item_id)
    : undefined;

  return {
    action_id: actionId,
    found: true,
    agent_id,
    frontier_item_id,
    ...(frontier_item ? { frontier_item } : {}),
    log_thought_chain,
    considered_alternatives: [...altSet],
    prior_actions_referenced: [...priorSet],
    validation,
    approval,
    outcome,
  };
}
