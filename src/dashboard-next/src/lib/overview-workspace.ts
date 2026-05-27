import type { AccessSummary, ActivityEntry, FrontierItem, PendingAction, SessionInfo } from './types';
import type { TrustSignalDto } from './api';

export interface AttentionItem {
  id: string;
  label: string;
  tone: 'warning' | 'default';
  route: 'actions' | 'frontier' | 'settings';
  nodeId?: string;
  meta?: string;
}

export interface AccessFacts {
  level: string;
  liveSessions: number;
  hosts: number;
  validCredentials: number;
}

export interface VerificationItem {
  id: string;
  label: string;
  severity: TrustSignalDto['severity'];
  route: 'activity' | 'findings' | 'graph';
  nodeId?: string;
  meta?: string;
}

export function deriveAttentionItems({
  pendingActions,
  readinessIssues,
  frontier,
}: {
  pendingActions: PendingAction[];
  readinessIssues: string[];
  frontier: FrontierItem[];
}): AttentionItem[] {
  const items: AttentionItem[] = [];
  if (pendingActions.length > 0) {
    items.push({
      id: 'pending-actions',
      label: `${pendingActions.length} pending approval${pendingActions.length === 1 ? '' : 's'}`,
      tone: 'warning',
      route: 'actions',
    });
  }
  if (readinessIssues.length > 0) {
    items.push({
      id: 'readiness',
      label: `${readinessIssues.length} readiness warning${readinessIssues.length === 1 ? '' : 's'}`,
      tone: 'warning',
      route: 'settings',
    });
  }
  return items.concat(
    [...frontier]
      .sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0) || (a.frontier_item_id || a.id).localeCompare(b.frontier_item_id || b.id))
      .slice(0, 3)
      .map(item => ({
        id: item.frontier_item_id || item.id,
        label: item.description || item.id,
        tone: 'default' as const,
        route: 'frontier' as const,
        nodeId: item.target_node || item.node_id || item.edge_target,
        meta: (item.priority ?? 0).toFixed(1),
      })),
  );
}

export function deriveAccessFacts(accessSummary: AccessSummary, sessions: SessionInfo[]): AccessFacts {
  return {
    level: accessSummary.current_access_level,
    liveSessions: sessions.filter(s => s.state === 'connected').length,
    hosts: accessSummary.compromised_hosts.length,
    validCredentials: accessSummary.valid_credentials.length,
  };
}

export function deriveRecentChanges(recentActivity: ActivityEntry[], limit = 5): ActivityEntry[] {
  return recentActivity
    .filter(e => e.description || e.event_type)
    .slice(-limit)
    .reverse();
}

export function deriveVerificationItems(signals: TrustSignalDto[], limit = 4): VerificationItem[] {
  return [...signals]
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || (b.timestamp || '').localeCompare(a.timestamp || ''))
    .slice(0, limit)
    .map(signal => ({
      id: signal.id,
      label: signal.detail ? `${signal.label}: ${signal.detail}` : signal.label,
      severity: signal.severity,
      route: signal.node_ids?.[0] ? 'graph' : signal.finding_id ? 'findings' : 'activity',
      nodeId: signal.node_ids?.[0],
      meta: signal.timestamp ? signal.timestamp.slice(11, 16) : undefined,
    }));
}

function severityRank(severity: TrustSignalDto['severity']): number {
  if (severity === 'error') return 0;
  if (severity === 'warning') return 1;
  return 2;
}
