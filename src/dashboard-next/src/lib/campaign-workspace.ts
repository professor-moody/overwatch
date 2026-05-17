import type { Campaign, FrontierItem } from './types';
import {
  getFrontierKey,
  getFrontierNodeIds,
  getFrontierPrimaryNodeId,
  sortFrontierItems,
} from './frontier-workspace';

export type CampaignItemLike = FrontierItem | string;

export interface CampaignFrontierFilters {
  search?: string;
  type?: string;
  node?: string;
  minPriority?: number;
}

export interface CampaignPreviewMetrics {
  selectedCount: number;
  expectedAgentCount: number;
  maxPriority: number;
  avgPriority: number;
  avgNoise: number;
  nodeIds: string[];
  typeCounts: Record<string, number>;
}

export interface CampaignLifecycleAction {
  action: 'activate' | 'pause' | 'resume' | 'abort' | 'complete';
  label: string;
  tone: 'success' | 'warning' | 'destructive' | 'muted';
}

export function filterCampaignFrontierItems(
  items: FrontierItem[],
  filters: CampaignFrontierFilters = {},
): FrontierItem[] {
  const q = (filters.search || '').trim().toLowerCase();
  const nodeFilter = (filters.node || '').trim().toLowerCase();
  const minPriority = filters.minPriority ?? 0;

  return sortFrontierItems(items).filter(item => {
    if (filters.type && item.type !== filters.type) return false;
    if ((item.priority ?? 0) < minPriority) return false;
    if (nodeFilter && !getFrontierNodeIds(item).some(node => node.toLowerCase().includes(nodeFilter))) return false;
    if (!q) return true;
    return [
      getFrontierKey(item),
      item.description,
      item.type,
      ...getFrontierNodeIds(item),
    ].some(value => typeof value === 'string' && value.toLowerCase().includes(q));
  });
}

export function deriveCampaignPreviewMetrics(
  selectedItems: CampaignItemLike[],
  options: { maxAgents?: number } = {},
): CampaignPreviewMetrics {
  const nodeIds = new Set<string>();
  const typeCounts: Record<string, number> = {};
  let prioritySum = 0;
  let noiseSum = 0;
  let maxPriority = 0;

  for (const item of selectedItems) {
    if (typeof item === 'string') continue;
    const priority = item.priority ?? 0;
    const noise = item.opsec_noise ?? 0;
    prioritySum += priority;
    noiseSum += noise;
    maxPriority = Math.max(maxPriority, priority);
    typeCounts[item.type] = (typeCounts[item.type] || 0) + 1;
    for (const nodeId of getFrontierNodeIds(item)) nodeIds.add(nodeId);
  }

  const selectedCount = selectedItems.length;
  return {
    selectedCount,
    expectedAgentCount: selectedCount === 0 ? 0 : Math.min(options.maxAgents ?? 3, selectedCount),
    maxPriority,
    avgPriority: selectedCount > 0 ? prioritySum / selectedCount : 0,
    avgNoise: selectedCount > 0 ? noiseSum / selectedCount : 0,
    nodeIds: [...nodeIds],
    typeCounts,
  };
}

export function isCampaignDispatchReady(campaign: Campaign): boolean {
  return (campaign.status === 'draft' || campaign.status === 'active')
    && Array.isArray(campaign.items)
    && campaign.items.length > 0;
}

export function campaignLifecycleActions(campaign: Campaign): CampaignLifecycleAction[] {
  if (campaign.status === 'draft') {
    return [{ action: 'activate', label: 'Activate', tone: 'success' }];
  }
  if (campaign.status === 'active') {
    return [
      { action: 'pause', label: 'Pause', tone: 'warning' },
      { action: 'abort', label: 'Abort', tone: 'destructive' },
    ];
  }
  if (campaign.status === 'paused') {
    return [
      { action: 'resume', label: 'Resume', tone: 'success' },
      { action: 'abort', label: 'Abort', tone: 'destructive' },
    ];
  }
  return [];
}

export function campaignItemNodeLabel(item: FrontierItem): string {
  return getFrontierPrimaryNodeId(item) || 'unmapped';
}

export function resolveCampaignItems(items: CampaignItemLike[], frontier: FrontierItem[]): FrontierItem[] {
  const byId = new Map(frontier.map(item => [getFrontierKey(item), item]));
  return items
    .map(item => typeof item === 'string' ? byId.get(item) : item)
    .filter((item): item is FrontierItem => !!item);
}
