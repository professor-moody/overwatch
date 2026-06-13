import type { PendingAction } from './types';

export type ActionSortMode = 'risk' | 'arrival' | 'noise-desc' | 'timeout-asc';
export type ActionLifecycle = 'pending_terminal_approval' | 'timeout_soon' | 'blocked_warning' | 'high_risk';

export interface ActionRisk {
  label: 'LOW' | 'MED' | 'HIGH';
  cls: string;
  score: number;
}

export function actionNoise(action: PendingAction): number {
  return action.opsec_context?.noise_level ?? action.noise_level ?? 0;
}

export function computeActionRisk(action: PendingAction): ActionRisk {
  const opsec = action.opsec_context || {};
  const signals = (opsec.defensive_signals || []).length;
  const score = actionNoise(action) * 2 + signals + (action.validation_result === 'warning_only' ? 1 : 0);
  if (score >= 6) return { label: 'HIGH', cls: 'bg-destructive/10 text-destructive', score };
  if (score >= 3) return { label: 'MED', cls: 'bg-warning/10 text-warning', score };
  return { label: 'LOW', cls: 'bg-elevated text-muted-foreground', score };
}

export function actionNodeId(action: PendingAction): string | null {
  return action.target_node || action.target_cidr || action.target || null;
}

export function actionSubmittedTime(action: PendingAction): number {
  const time = new Date(action.submitted_at || 0).getTime();
  return Number.isFinite(time) ? time : 0;
}

export function actionTimeoutMs(action: PendingAction, now = Date.now()): number | null {
  if (!action.timeout_at) return null;
  const time = new Date(action.timeout_at).getTime();
  if (!Number.isFinite(time)) return null;
  return time - now;
}

export function classifyActionLifecycle(action: PendingAction, now = Date.now()): ActionLifecycle {
  const timeoutMs = actionTimeoutMs(action, now);
  if (timeoutMs !== null && timeoutMs <= 60_000) return 'timeout_soon';
  if (action.validation_result === 'warning_only') return 'blocked_warning';
  if (computeActionRisk(action).label === 'HIGH') return 'high_risk';
  return 'pending_terminal_approval';
}

export function terminalApprovalCommand(action: PendingAction, decision: 'approve' | 'deny' = 'approve'): string {
  const reason = decision === 'approve' ? 'reviewed in dashboard' : 'denied from dashboard review';
  return `${decision}_action action_id=${action.action_id} notes="${reason}"`;
}

export function terminalApprovalSummary(action: PendingAction): string {
  const target = actionNodeId(action) || action.target_ip || action.target_cidr || action.target || 'unknown-target';
  return [
    `action_id=${action.action_id}`,
    `technique=${action.technique || 'unknown'}`,
    `target=${target}`,
    `noise=${actionNoise(action).toFixed(2)}`,
  ].join(' ');
}

function timeoutTime(action: PendingAction): number {
  if (!action.timeout_at) return Infinity;
  const time = new Date(action.timeout_at).getTime();
  return Number.isFinite(time) ? time : Infinity;
}

function stableActionTieBreak(a: PendingAction, b: PendingAction): number {
  const submitted = actionSubmittedTime(b) - actionSubmittedTime(a);
  if (submitted !== 0) return submitted;
  return a.action_id.localeCompare(b.action_id);
}

export function sortActionsForQueue(list: PendingAction[], mode: ActionSortMode): PendingAction[] {
  const sorted = [...list];
  sorted.sort((a, b) => {
    if (mode === 'risk') {
      const risk = computeActionRisk(b).score - computeActionRisk(a).score;
      if (risk !== 0) return risk;
      const noise = actionNoise(b) - actionNoise(a);
      if (noise !== 0) return noise;
      return stableActionTieBreak(a, b);
    }
    if (mode === 'noise-desc') {
      const noise = actionNoise(b) - actionNoise(a);
      if (noise !== 0) return noise;
      return stableActionTieBreak(a, b);
    }
    if (mode === 'timeout-asc') {
      const timeout = timeoutTime(a) - timeoutTime(b);
      if (timeout !== 0) return timeout;
      return stableActionTieBreak(a, b);
    }
    return stableActionTieBreak(a, b);
  });
  return sorted;
}

export function groupActionsByTechnique(actions: PendingAction[]): Record<string, PendingAction[]> {
  const groups: Record<string, PendingAction[]> = {};
  for (const action of actions) {
    const key = action.technique || 'unknown';
    if (!groups[key]) groups[key] = [];
    groups[key].push(action);
  }
  return groups;
}

export function sortTechniqueGroups(groups: Record<string, PendingAction[]>): Array<[string, PendingAction[]]> {
  return Object.entries(groups).sort(([techA, a], [techB, b]) => {
    const risk = Math.max(...b.map(x => computeActionRisk(x).score)) - Math.max(...a.map(x => computeActionRisk(x).score));
    if (risk !== 0) return risk;
    if (b.length !== a.length) return b.length - a.length;
    return techA.localeCompare(techB);
  });
}
