import { describe, expect, it } from 'vitest';
import {
  campaignLifecycleActions,
  deriveCampaignPreviewMetrics,
  filterCampaignFrontierItems,
  isCampaignDispatchReady,
} from '../campaign-workspace';
import type { Campaign, FrontierItem } from '../types';

const frontier = (props: Record<string, unknown> = {}): FrontierItem => ({
  id: 'fi-1',
  type: 'incomplete_node',
  node_id: 'host-1',
  description: 'Inspect host',
  graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 1 },
  opsec_noise: 0.2,
  staleness_seconds: 0,
  ...props,
} as FrontierItem);

const campaign = (props: Partial<Campaign>): Campaign => ({
  id: 'camp-1',
  name: 'Campaign',
  strategy: 'custom',
  status: 'draft',
  items: [],
  abort_conditions: [],
  progress: { total: 0, completed: 0, succeeded: 0, failed: 0, consecutive_failures: 0 },
  findings: [],
  created_at: '2026-05-15T00:00:00Z',
  ...props,
});

describe('campaign workspace helpers', () => {
  it('filters frontier selections by type, node, score multiplier, and text', () => {
    const items = [
      frontier({ id: 'high', type: 'credential_test', node_id: 'host-dc01', credential_id: 'cred-1', description: 'Validate token', graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 9 } }),
      frontier({ id: 'low', type: 'network_discovery', target_cidr: '10.0.0.0/24', description: 'Scan web', graph_metrics: { hops_to_objective: null, fan_out_estimate: 10, node_degree: 0, confidence: 2 } }),
    ];

    expect(filterCampaignFrontierItems(items, { type: 'credential_test' }).map(item => item.id)).toEqual(['high']);
    expect(filterCampaignFrontierItems(items, { node: 'dc01' }).map(item => item.id)).toEqual(['high']);
    expect(filterCampaignFrontierItems(items, { minScoreMultiplier: 5 }).map(item => item.id)).toEqual(['high']);
    expect(filterCampaignFrontierItems(items, { search: 'token' }).map(item => item.id)).toEqual(['high']);
  });

  it('derives dispatch preview metrics from selected items', () => {
    const metrics = deriveCampaignPreviewMetrics([
      frontier({ id: 'a', type: 'credential_test', node_id: 'host-a', credential_id: 'cred-a', graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 10 }, opsec_noise: 0.2 }),
      frontier({ id: 'b', type: 'credential_test', node_id: 'host-b', credential_id: 'cred-b', graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 4 }, opsec_noise: 0.6 }),
    ], { maxAgents: 1 });

    expect(metrics.selectedCount).toBe(2);
    expect(metrics.expectedAgentCount).toBe(1);
    expect(metrics.maxScoreMultiplier).toBe(10);
    expect(metrics.avgScoreMultiplier).toBe(7);
    expect(metrics.avgNoise).toBeCloseTo(0.4);
    expect(metrics.nodeIds).toEqual(['host-a', 'cred-a', 'host-b', 'cred-b']);
    expect(metrics.typeCounts.credential_test).toBe(2);
  });

  it('exposes dispatch readiness and lifecycle actions', () => {
    expect(isCampaignDispatchReady(campaign({ status: 'draft', items: ['fi-1'] }))).toBe(true);
    expect(isCampaignDispatchReady(campaign({ status: 'completed', items: ['fi-1'] }))).toBe(false);
    expect(isCampaignDispatchReady(campaign({ status: 'draft', items: ['fi-1'], child_count: 2 }))).toBe(false);
    expect(campaignLifecycleActions(campaign({ status: 'active' })).map(action => action.action)).toEqual(['pause', 'abort']);
    expect(campaignLifecycleActions(campaign({ status: 'completed' }))).toEqual([]);
  });
});
