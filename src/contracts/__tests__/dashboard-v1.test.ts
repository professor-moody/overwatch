import { describe, expect, it } from 'vitest';
import {
  CampaignActionRequestSchema,
  CampaignCreateRequestSchema,
  CampaignListResponseSchema,
  CampaignSplitRequestSchema,
  FRONTIER_TYPES,
  FrontierListDtoSchema,
  ObjectiveCreateRequestSchema,
  SettingsPatchSchema,
} from '../dashboard-v1.js';

const metrics = (confidence: number) => ({
  hops_to_objective: 1,
  fan_out_estimate: 2,
  node_degree: 3,
  confidence,
});

const base = (id: string, type: string, confidence: number) => ({
  id,
  type,
  description: `${type} candidate`,
  graph_metrics: metrics(confidence),
  opsec_noise: 0.2,
  staleness_seconds: 0,
});

const frontierFixtures = [
  { ...base('z-node', 'incomplete_node', 0.2), node_id: 'host-1' },
  { ...base('a-untested', 'untested_edge', 9), edge_source: 'cred-1', edge_target: 'host-1', edge_type: 'VALID_ON' },
  { ...base('m-inferred', 'inferred_edge', 1.2), edge_source: 'user-1', edge_target: 'host-2', edge_type: 'ADMIN_TO' },
  { ...base('b-cidr', 'network_discovery', 0.1), target_cidr: '10.0.0.0/24' },
  { ...base('pivot', 'network_pivot', 0.6), node_id: 'host-3', pivot_host_id: 'host-2', via_pivot: 'user-1' },
  { ...base('credential', 'credential_test', 0.5), node_id: 'service-1', credential_id: 'cred-1' },
  { ...base('idp', 'idp_enumeration', 0.7), node_id: 'idp-1' },
  { ...base('mfa', 'mfa_bypass_candidate', 0.4), node_id: 'cred-2', credential_id: 'cred-2' },
  { ...base('tier', 'cross_tier_pivot', 0.8), edge_source: 'app-1', edge_target: 'cloud-1', edge_type: 'BACKED_BY' },
  { ...base('cve', 'cve_research', 0.9), node_id: 'service-2' },
  { ...base('domain', 'domain_enumeration', 1), node_id: 'domain-1' },
];

describe('dashboard v1 contracts', () => {
  it('accepts every canonical frontier kind and target shape', () => {
    const parsed = FrontierListDtoSchema.parse(frontierFixtures);
    expect(parsed.map(item => item.type)).toEqual(FRONTIER_TYPES);
  });

  it('preserves server order regardless of ids and score multipliers', () => {
    const parsed = FrontierListDtoSchema.parse(frontierFixtures);
    expect(parsed.map(item => item.id)).toEqual(frontierFixtures.map(item => item.id));
    expect(parsed.map(item => item.graph_metrics.confidence)).toEqual(frontierFixtures.map(item => item.graph_metrics.confidence));
  });

  it('keeps mutation bodies strict', () => {
    expect(CampaignCreateRequestSchema.safeParse({ name: 'x', strategy: 'custom', item_ids: ['fi-1'], items: [] }).success).toBe(false);
    expect(CampaignActionRequestSchema.safeParse({ action: 'complete' }).success).toBe(false);
    expect(CampaignSplitRequestSchema.safeParse({ count: 1 }).success).toBe(false);
    expect(SettingsPatchSchema.safeParse({ enabled: true, time_window: null, ignored: true }).success).toBe(false);
  });

  it('matches core settings bounds without narrowing existing timeout compatibility', () => {
    expect(SettingsPatchSchema.safeParse({ max_noise: 1.5 }).success).toBe(false);
    expect(SettingsPatchSchema.safeParse({ time_window: { start_hour: 99, end_hour: 2.5 } }).success).toBe(false);
    expect(SettingsPatchSchema.safeParse({ approval_timeout_ms: 5_000 }).success).toBe(true);
    expect(SettingsPatchSchema.safeParse({ approval_timeout_ms: 7_200_000 }).success).toBe(true);
  });

  it('rejects objective graph vocabulary outside the canonical node and edge enums', () => {
    expect(ObjectiveCreateRequestSchema.safeParse({
      description: 'Reach admin', target_node_type: 'not_a_node',
    }).success).toBe(false);
    expect(ObjectiveCreateRequestSchema.safeParse({
      description: 'Reach admin', achievement_edge_types: ['NOT_AN_EDGE'],
    }).success).toBe(false);
    expect(ObjectiveCreateRequestSchema.safeParse({
      description: 'Reach admin', target_node_type: 'host', achievement_edge_types: ['ADMIN_TO'],
    }).success).toBe(true);
  });

  it('permits additive response fields while validating campaign envelopes', () => {
    const campaign = {
      id: 'camp-1', name: 'Campaign', strategy: 'custom', status: 'draft', items: ['fi-1'],
      abort_conditions: [], progress: { total: 1, completed: 0, succeeded: 0, failed: 0, consecutive_failures: 0 },
      findings: [], created_at: '2026-07-15T00:00:00Z',
      agent_count: 0, running_agents: 0, agents_total: 0, agents_active: 0,
      completion_pct: 0, findings_count: 0,
      opsec: {
        global_noise_spent: 0, noise_budget_remaining: 1, max_noise: 1,
        recommended_approach: 'normal', defensive_signals: [],
      },
      future_field: 'additive',
    };
    const parsed = CampaignListResponseSchema.parse({ campaigns: [campaign], total: 1, next_cursor: null });
    expect(parsed.campaigns[0].future_field).toBe('additive');
  });
});
