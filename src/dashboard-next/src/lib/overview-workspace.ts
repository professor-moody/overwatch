import type { AccessSummary, ActivityEntry, Campaign, ExportedNode, FrontierItem, PendingAction, SessionInfo } from './types';
import type { TrustSignalDto } from './api';
import { getEffectiveCredentialStatus } from './credential-display';
import { getFrontierKey, getFrontierNodeIds, getFrontierTargetCidr } from './frontier-workspace';

export interface AttentionItem {
  id: string;
  label: string;
  tone: 'warning' | 'default';
  route: 'actions' | 'credentials' | 'frontier' | 'sessions' | 'settings';
  nodeId?: string;
  meta?: string;
}

export interface AccessFacts {
  level: string;
  liveSessions: number;
  hosts: number;
  validCredentials: number;
  activeCampaigns: number;
  pausedCampaigns: number;
}

export interface VerificationItem {
  id: string;
  label: string;
  severity: TrustSignalDto['severity'];
  route: 'activity' | 'findings' | 'graph';
  nodeId?: string;
  meta?: string;
}

export interface NextActionItem {
  id: string;
  label: string;
  type: FrontierItem['type'];
  scoreMultiplier: number;
  reason: string;
  context: string;
  nodeIds: string[];
  primaryNode?: string;
  frontierItemId?: string;
}

export interface ChangedItem {
  id: string;
  label: string;
  detail?: string;
  source: 'activity' | 'trust';
  route: 'activity' | 'findings' | 'graph';
  tone: 'default' | 'warning';
  timestamp?: string;
  nodeId?: string;
  meta?: string;
}

export function deriveNowItems({
  pendingActions,
  readinessIssues,
  credentialNodes = [],
  sessions = [],
  nowMs = Date.now(),
}: {
  pendingActions: PendingAction[];
  readinessIssues: string[];
  credentialNodes?: ExportedNode[];
  sessions?: SessionInfo[];
  nowMs?: number;
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
  const expiredCredentials = credentialNodes.filter(node =>
    node.type === 'credential' && getEffectiveCredentialStatus(node, nowMs) === 'expired',
  );
  if (expiredCredentials.length > 0) {
    items.push({
      id: 'expired-credentials',
      label: `${expiredCredentials.length} expired credential${expiredCredentials.length === 1 ? '' : 's'}`,
      tone: 'warning',
      route: 'credentials',
      nodeId: expiredCredentials[0]?.id,
    });
  }
  const erroredSessions = sessions.filter(session => session.state === 'error');
  if (erroredSessions.length > 0) {
    items.push({
      id: 'session-errors',
      label: `${erroredSessions.length} session error${erroredSessions.length === 1 ? '' : 's'}`,
      tone: 'warning',
      route: 'sessions',
      nodeId: erroredSessions[0]?.target_node,
    });
  }
  return items;
}

export function deriveAttentionItems(args: Parameters<typeof deriveNowItems>[0] & { frontier?: FrontierItem[] }): AttentionItem[] {
  const nowItems = deriveNowItems(args);
  const frontierItems = deriveNextActionItems(args.frontier || [], 3).map(item => ({
    id: item.id,
    label: item.label,
    tone: 'default' as const,
    route: 'frontier' as const,
    nodeId: item.primaryNode,
    meta: `×${item.scoreMultiplier.toFixed(2)}`,
  }));
  return nowItems.concat(frontierItems);
}

export function deriveNextActionItems(frontier: FrontierItem[], limit = 5): NextActionItem[] {
  return frontier
    .slice(0, limit)
    .map(item => {
      const nodeIds = getFrontierNodeIds(item);
      return {
        id: getFrontierKey(item),
        label: item.description || item.id,
        type: item.type,
        scoreMultiplier: item.graph_metrics.confidence,
        reason: rankReason(item),
        context: actionContext(item),
        nodeIds,
        primaryNode: nodeIds[0],
        frontierItemId: item.id,
      };
    });
}

export function deriveAccessFacts(accessSummary: AccessSummary, sessions: SessionInfo[], campaigns: Campaign[] = []): AccessFacts {
  return {
    level: accessSummary.current_access_level,
    liveSessions: sessions.filter(s => s.state === 'connected').length,
    hosts: accessSummary.compromised_hosts.length,
    validCredentials: accessSummary.valid_credentials.length,
    activeCampaigns: campaigns.filter(c => c.status === 'active').length,
    pausedCampaigns: campaigns.filter(c => c.status === 'paused').length,
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

export function deriveChangedItems(
  recentActivity: ActivityEntry[],
  trustSignals: TrustSignalDto[],
  limit = 6,
): ChangedItem[] {
  const items: ChangedItem[] = [];
  for (const entry of recentActivity) {
    const rawLabel = entry.description || entry.event_type;
    const label = summarizeChangedLabel(rawLabel, 'activity');
    if (!label) continue;
    items.push({
      id: entry.event_id || entry.id,
      label,
      detail: rawLabel,
      source: 'activity',
      route: entry.target_node_ids?.[0] ? 'graph' : entry.event_type?.includes('finding') ? 'findings' : 'activity',
      tone: entry.result_classification === 'failure' ? 'warning' : 'default',
      timestamp: entry.timestamp,
      nodeId: entry.target_node_ids?.[0],
      meta: entry.timestamp ? entry.timestamp.slice(11, 16) : undefined,
    });
  }
  for (const signal of trustSignals) {
    const rawLabel = signal.detail ? `${signal.label}: ${signal.detail}` : signal.label;
    items.push({
      id: signal.id,
      label: summarizeChangedLabel(rawLabel, 'trust'),
      detail: rawLabel,
      source: 'trust',
      route: signal.node_ids?.[0] ? 'graph' : signal.finding_id ? 'findings' : 'activity',
      tone: signal.severity === 'info' ? 'default' : 'warning',
      timestamp: signal.timestamp,
      nodeId: signal.node_ids?.[0],
      meta: signal.timestamp ? signal.timestamp.slice(11, 16) : undefined,
    });
  }

  const deduped = new Map<string, ChangedItem>();
  for (const item of items.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))) {
    const key = `${item.route}:${item.nodeId || ''}:${item.label}`;
    if (!deduped.has(key)) deduped.set(key, item);
  }
  return [...deduped.values()].slice(0, limit);
}

export function summarizeChangedLabel(label: string, source: ChangedItem['source'] = 'activity'): string {
  const trimmed = label.trim();
  if (!trimmed) return trimmed;
  if (/CVSS/i.test(trimmed)) {
    if (/estimated/i.test(trimmed)) return 'Estimated CVSS requires verification';
    return 'CVSS scoring signal requires review';
  }
  if (/parser|malformed|skipped|missing object|ingest/i.test(trimmed)) {
    return sentenceLimit(stripCvssVectors(trimmed), 86);
  }
  if (source === 'trust') return sentenceLimit(stripCvssVectors(trimmed), 78);
  return sentenceLimit(stripCvssVectors(trimmed), 96);
}

function stripCvssVectors(value: string): string {
  return value
    .replace(/CVSS:3\.[01]\/[A-Z:\/.-]+/g, 'CVSS vector')
    .replace(/\s+/g, ' ')
    .trim();
}

function sentenceLimit(value: string, max: number): string {
  if (value.length <= max) return value;
  const slice = value.slice(0, max).trimEnd();
  return `${slice.replace(/[,:;.\s]+$/, '')}...`;
}

function severityRank(severity: TrustSignalDto['severity']): number {
  if (severity === 'error') return 0;
  if (severity === 'warning') return 1;
  return 2;
}

function rankReason(item: FrontierItem): string {
  const parts: string[] = [];
  const hops = item.graph_metrics?.hops_to_objective;
  const fanOut = item.graph_metrics?.fan_out_estimate;
  const confidence = item.graph_metrics?.confidence;

  if (typeof hops === 'number') parts.push(hops <= 1 ? 'near objective' : `${hops} hops to objective`);
  if (typeof fanOut === 'number' && fanOut > 0) parts.push(`${fanOut} follow-up${fanOut === 1 ? '' : 's'}`);
  if (typeof confidence === 'number' && confidence > 1) parts.push('planner boost');
  if (item.chain_id) parts.push('chain item');
  if (item.opsec_noise != null && item.opsec_noise <= 0.3) parts.push('low noise');
  return parts.length > 0 ? parts.join(' · ') : 'candidate order supplied by the engine';
}

function actionContext(item: FrontierItem): string {
  const nodeIds = getFrontierNodeIds(item);
  if (item.type === 'untested_edge' || item.type === 'inferred_edge' || item.type === 'cross_tier_pivot') {
    return `${nodeIds[0] ?? 'unknown'} -> ${nodeIds[1] ?? 'unknown'}`;
  }
  if (nodeIds[0]) return nodeIds[0];
  const cidr = getFrontierTargetCidr(item);
  if (cidr) return cidr;
  if (item.chain_id) return item.chain_id;
  return item.type.replace(/_/g, ' ');
}
