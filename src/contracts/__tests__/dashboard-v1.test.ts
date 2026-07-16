import { describe, expect, it } from 'vitest';
import {
  CampaignActionRequestSchema,
  CampaignCreateRequestSchema,
  CampaignListResponseSchema,
  CampaignSplitRequestSchema,
  ConfigDivergenceResolveRequestSchema,
  ConfigDivergenceResolveResponseSchema,
  FRONTIER_TYPES,
  FrontierListDtoSchema,
  ObjectiveCreateRequestSchema,
  RecoveryStatusResponseSchema,
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
    expect(ConfigDivergenceResolveRequestSchema.safeParse({
      resolution: 'use_state',
      expected_file_hash: 'a'.repeat(64),
      expected_state_hash: 'b'.repeat(64),
      ignored: true,
    }).success).toBe(false);
  });

  it('validates recovery reconciliation hashes and permits additive status fields', () => {
    expect(ConfigDivergenceResolveRequestSchema.safeParse({
      resolution: 'use_file',
      expected_file_hash: 'not-a-hash',
      expected_state_hash: 'b'.repeat(64),
    }).success).toBe(false);
    expect(ConfigDivergenceResolveRequestSchema.safeParse({
      resolution: 'use_file',
      expected_file_hash: 'a'.repeat(64),
      expected_state_hash: 'b'.repeat(64),
    }).success).toBe(true);

    const parsed = RecoveryStatusResponseSchema.parse({
      recovery: {
        outcome: 'incomplete',
        source: 'state',
        complete: false,
        writable: false,
        state_recovery: {
          outcome: 'clean',
          source: 'state',
          complete: true,
          writable: true,
          highest_allocated_logical_seq: 2,
          highest_allocated_frame_seq: 8,
          highest_physical_frame_seq: 8,
          highest_contiguous_applied_logical_seq: 2,
        },
        reason: 'configuration reconciliation is required',
        base_checkpoint: 2,
        highest_allocated_seq: 2,
        highest_allocated_logical_seq: 2,
        highest_allocated_frame_seq: 8,
        highest_on_disk_seq: 2,
        highest_physical_frame_seq: 8,
        highest_contiguous_applied_seq: 2,
        highest_contiguous_applied_logical_seq: 2,
        consecutive_persistence_failures: 0,
        journal: {
          enabled: true,
          format_version: 1,
          read: 0,
          attempted: 0,
          applied: 0,
          skipped: 0,
          failed: 0,
          malformed: false,
          preserved: true,
          future_journal_field: true,
        },
        state_migration: {
          status: 'blocked',
          supported_state_version: 1,
          supported_journal_version: 1,
          observed_state_version: 2,
          observed_journal_version: 0,
          migration_required: false,
          reason: 'future state version',
          future_migration_field: 'additive',
        },
        config_recovery: {
          status: 'diverged',
          resolution_required: true,
          intent_present: false,
          file_valid: true,
          file_revision: 2,
          state_revision: 1,
          file_hash: 'a'.repeat(64),
          state_hash: 'b'.repeat(64),
          allowed_resolutions: ['use_file', 'use_state'],
          conflicted_intent: {
            archive_path: '/tmp/engagement.json.write-intent.json.conflict-audit.json',
            intent_sha256: 'c'.repeat(64),
            intent_checksum: 'd'.repeat(64),
            reason: 'intent and file describe different durable states',
            observed_file_hash: 'a'.repeat(64),
            observed_state_hash: 'b'.repeat(64),
            future_conflict_field: 'additive',
          },
          future_config_field: 'additive',
        },
        future_recovery_field: 'additive',
      },
      future_envelope_field: 'additive',
    });
    expect(parsed.recovery.config_recovery?.future_config_field).toBe('additive');
    expect(parsed.recovery.state_migration?.future_migration_field).toBe('additive');
    expect(parsed.recovery.config_recovery?.conflicted_intent?.future_conflict_field).toBe('additive');
    expect(parsed.recovery.future_recovery_field).toBe('additive');
    expect(parsed.recovery).toMatchObject({
      highest_allocated_logical_seq: 2,
      highest_allocated_frame_seq: 8,
      highest_physical_frame_seq: 8,
      highest_contiguous_applied_logical_seq: 2,
      state_recovery: {
        highest_allocated_frame_seq: 8,
        highest_physical_frame_seq: 8,
      },
    });
    expect(RecoveryStatusResponseSchema.safeParse({
      recovery: {
        ...parsed.recovery,
        config_recovery: {
          ...parsed.recovery.config_recovery,
          conflicted_intent: {
            ...parsed.recovery.config_recovery?.conflicted_intent,
            intent_sha256: 'not-a-hash',
          },
        },
      },
    }).success).toBe(false);

    const resolution = ConfigDivergenceResolveResponseSchema.parse({
      resolved: true,
      mode: 'use_file',
      config: {
        id: 'engagement-1',
        config_revision: 3,
        config_hash: 'c'.repeat(64),
        future_config_key: true,
      },
      recovery: {
        status: 'recovered',
        resolution_required: false,
        intent_present: false,
        future_status_key: 'additive',
      },
      future_response_key: 'additive',
    });
    expect(resolution.recovery.future_status_key).toBe('additive');
    expect(resolution.future_response_key).toBe('additive');
    expect(ConfigDivergenceResolveResponseSchema.safeParse({
      resolved: true,
      mode: 'use_file',
      config: { id: 'engagement-1' },
      recovery: { status: 'recovered', resolution_required: false, intent_present: false },
    }).success).toBe(false);
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
