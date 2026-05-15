import type { AccessSummary, ActivityEntry, FrontierItem, PendingAction, SessionInfo } from './types';

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
