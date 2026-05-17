import { describe, expect, it } from 'vitest';
import {
  campaignLifecycleActions,
  deriveCampaignPreviewMetrics,
  filterCampaignFrontierItems,
  isCampaignDispatchReady,
} from '../campaign-workspace';
import type { Campaign, FrontierItem } from '../types';

const frontier = (props: Partial<FrontierItem>): FrontierItem => ({
  id: 'fi-1',
  type: 'incomplete_node',
  priority: 1,
  description: 'Inspect host',
  ...props,
});

const campaign = (props: Partial<Campaign>): Campaign => ({
  id: 'camp-1',
  name: 'Campaign',
  strategy: 'custom',
  status: 'draft',
  items: [],
  created_at: '2026-05-15T00:00:00Z',
  ...props,
});

describe('campaign workspace helpers', () => {
  it('filters frontier selections by type, node, priority, and text', () => {
    const items = [
      frontier({ id: 'high', type: 'credential_test', target_node: 'host-dc01', priority: 9, description: 'Validate token' }),
      frontier({ id: 'low', type: 'network_discovery', target_node: 'host-web01', priority: 2, description: 'Scan web' }),
    ];

    expect(filterCampaignFrontierItems(items, { type: 'credential_test' }).map(item => item.id)).toEqual(['high']);
    expect(filterCampaignFrontierItems(items, { node: 'web01' }).map(item => item.id)).toEqual(['low']);
    expect(filterCampaignFrontierItems(items, { minPriority: 5 }).map(item => item.id)).toEqual(['high']);
    expect(filterCampaignFrontierItems(items, { search: 'token' }).map(item => item.id)).toEqual(['high']);
  });

  it('derives dispatch preview metrics from selected items', () => {
    const metrics = deriveCampaignPreviewMetrics([
      frontier({ id: 'a', type: 'credential_test', target_node: 'host-a', priority: 10, opsec_noise: 0.2 }),
      frontier({ id: 'b', type: 'credential_test', target_node: 'host-b', priority: 4, opsec_noise: 0.6 }),
    ], { maxAgents: 1 });

    expect(metrics.selectedCount).toBe(2);
    expect(metrics.expectedAgentCount).toBe(1);
    expect(metrics.maxPriority).toBe(10);
    expect(metrics.avgPriority).toBe(7);
    expect(metrics.avgNoise).toBeCloseTo(0.4);
    expect(metrics.nodeIds).toEqual(['host-a', 'host-b']);
    expect(metrics.typeCounts.credential_test).toBe(2);
  });

  it('exposes dispatch readiness and lifecycle actions', () => {
    expect(isCampaignDispatchReady(campaign({ status: 'draft', items: [frontier({})] }))).toBe(true);
    expect(isCampaignDispatchReady(campaign({ status: 'completed', items: [frontier({})] }))).toBe(false);
    expect(campaignLifecycleActions(campaign({ status: 'active' })).map(action => action.action)).toEqual(['pause', 'abort']);
    expect(campaignLifecycleActions(campaign({ status: 'completed' }))).toEqual([]);
  });
});
