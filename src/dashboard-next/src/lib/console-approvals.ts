import type { PendingAction } from './types';
import {
  actionNodeId,
  actionNoise,
  classifyActionLifecycle,
  computeActionRisk,
  sortActionsForQueue,
  type ActionLifecycle,
  type ActionRisk,
} from './action-queue';

// Phase 4b — the Operator Console "Needs you" strip. Approvals are now actioned
// inline in the console (the canonical resolveApprovalRequest path, same as the
// terminal), so this builds a compact, risk-sorted view-model from the live
// pendingActions queue. The standalone Actions panel is the deep triage view;
// this is the at-a-glance "what needs a decision right now" lane.

export interface ConsoleApprovalItem {
  action_id: string;
  technique: string;
  /** Best human-facing target: node id, cidr, ip, or raw target string. */
  target: string;
  description: string;
  risk: ActionRisk;
  lifecycle: ActionLifecycle;
  noise: number;
  timeout_at?: string;
  submitted_at?: string;
}

export interface ConsoleApprovalsView {
  /** Risk-sorted items the operator should act on, capped to `limit`. */
  items: ConsoleApprovalItem[];
  /** Total pending approvals (>= items.length when capped). */
  total: number;
  /** How many are not shown because of the cap. */
  overflow: number;
  highCount: number;
  warningCount: number;
  timeoutSoonCount: number;
}

const DEFAULT_LIMIT = 4;

function consoleApprovalTarget(action: PendingAction): string {
  return (
    actionNodeId(action) ||
    action.target_ip ||
    action.target_cidr ||
    action.target ||
    'unknown target'
  );
}

export function toConsoleApprovalItem(action: PendingAction, now = Date.now()): ConsoleApprovalItem {
  return {
    action_id: action.action_id,
    technique: action.technique || 'unknown',
    target: consoleApprovalTarget(action),
    description: action.description || action.technique || action.action_id,
    risk: computeActionRisk(action),
    lifecycle: classifyActionLifecycle(action, now),
    noise: actionNoise(action),
    timeout_at: action.timeout_at,
    submitted_at: action.submitted_at,
  };
}

/**
 * Build the console "Needs you" approvals view-model. Sorts by risk (reusing the
 * Actions queue's canonical ordering so the console and the deep triage view
 * agree), caps to `limit` for the compact strip, and surfaces the counts the
 * header badge needs. Returns an empty view (total 0) when nothing is pending,
 * so the strip can hide itself.
 */
export function buildConsoleApprovals(
  pending: PendingAction[],
  opts: { limit?: number; now?: number } = {},
): ConsoleApprovalsView {
  const now = opts.now ?? Date.now();
  const limit = opts.limit ?? DEFAULT_LIMIT;
  const sorted = sortActionsForQueue(pending, 'risk');
  const items = sorted.slice(0, limit).map((action) => toConsoleApprovalItem(action, now));

  let highCount = 0;
  let warningCount = 0;
  let timeoutSoonCount = 0;
  for (const action of sorted) {
    if (computeActionRisk(action).label === 'HIGH') highCount += 1;
    if (action.validation_result === 'warning_only') warningCount += 1;
    if (classifyActionLifecycle(action, now) === 'timeout_soon') timeoutSoonCount += 1;
  }

  return {
    items,
    total: sorted.length,
    overflow: Math.max(0, sorted.length - items.length),
    highCount,
    warningCount,
    timeoutSoonCount,
  };
}

/**
 * Whether a deny is allowed to submit. Denies must carry a reason (audit
 * semantics: a denial without a stated reason is indistinguishable from a
 * mis-click in the durable record), so the UI gates the button on this.
 */
export function isDenyReasonValid(reason: string | null | undefined): boolean {
  return typeof reason === 'string' && reason.trim().length > 0;
}
