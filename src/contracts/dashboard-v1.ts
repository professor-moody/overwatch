import { z } from 'zod';
import { EDGE_TYPES, NODE_TYPES, edgeTypeSchema, nodeTypeSchema } from '../types.js';

const Sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);

/**
 * Browser-safe runtime contracts for the dashboard correctness slice.
 *
 * This is intentionally not the full endpoint registry planned for PR11. It
 * freezes the existing v1 wire envelopes for the surfaces corrected in PR3 so
 * the Node server and browser client validate the same shapes. Response
 * objects remain additive via passthrough(); mutation inputs are strict.
 */

export const FRONTIER_TYPES = [
  'incomplete_node',
  'untested_edge',
  'inferred_edge',
  'network_discovery',
  'network_pivot',
  'credential_test',
  'idp_enumeration',
  'mfa_bypass_candidate',
  'cross_tier_pivot',
  'cve_research',
  'domain_enumeration',
] as const;

export const FrontierTypeSchema = z.enum(FRONTIER_TYPES);
export type FrontierType = z.infer<typeof FrontierTypeSchema>;

export const FrontierGraphMetricsSchema = z.object({
  hops_to_objective: z.number().nullable(),
  fan_out_estimate: z.number(),
  node_degree: z.number(),
  confidence: z.number(),
}).passthrough();

const frontierBaseShape = {
  id: z.string().min(1),
  description: z.string(),
  graph_metrics: FrontierGraphMetricsSchema,
  opsec_noise: z.number(),
  staleness_seconds: z.number(),
  stale_credential: z.boolean().optional(),
  scope_unverified: z.boolean().optional(),
  community_id: z.number().optional(),
  community_unexplored_count: z.number().optional(),
  chain_id: z.string().optional(),
  chain_depth: z.number().optional(),
  chain_length: z.number().optional(),
  chain_completion_pct: z.number().optional(),
  chain_score: z.number().optional(),
  chain_target_objective: z.boolean().optional(),
  chain_template: z.string().optional(),
};

const nodeFrontierVariant = <T extends 'incomplete_node' | 'idp_enumeration' | 'cve_research' | 'domain_enumeration'>(type: T) =>
  z.object({
    ...frontierBaseShape,
    type: z.literal(type),
    node_id: z.string().min(1),
    missing_properties: z.array(z.string()).optional(),
  }).passthrough();

const edgeFrontierVariant = <T extends 'untested_edge' | 'inferred_edge' | 'cross_tier_pivot'>(type: T) =>
  z.object({
    ...frontierBaseShape,
    type: z.literal(type),
    edge_source: z.string().min(1),
    edge_target: z.string().min(1),
    edge_type: edgeTypeSchema,
  }).passthrough();

export const FrontierItemDtoSchema = z.discriminatedUnion('type', [
  nodeFrontierVariant('incomplete_node'),
  edgeFrontierVariant('untested_edge'),
  edgeFrontierVariant('inferred_edge'),
  z.object({
    ...frontierBaseShape,
    type: z.literal('network_discovery'),
    target_cidr: z.string().min(1),
    truncated: z.boolean().optional(),
    total_hosts: z.number().optional(),
    expanded_count: z.number().optional(),
  }).passthrough(),
  z.object({
    ...frontierBaseShape,
    type: z.literal('network_pivot'),
    node_id: z.string().min(1),
    pivot_host_id: z.string().min(1),
    via_pivot: z.string().min(1),
  }).passthrough(),
  z.object({
    ...frontierBaseShape,
    type: z.literal('credential_test'),
    credential_id: z.string().min(1),
    node_id: z.string().min(1),
  }).passthrough(),
  nodeFrontierVariant('idp_enumeration'),
  z.object({
    ...frontierBaseShape,
    type: z.literal('mfa_bypass_candidate'),
    credential_id: z.string().min(1),
    node_id: z.string().min(1),
  }).passthrough(),
  edgeFrontierVariant('cross_tier_pivot'),
  nodeFrontierVariant('cve_research'),
  nodeFrontierVariant('domain_enumeration'),
]);
export type FrontierItemDto = z.infer<typeof FrontierItemDtoSchema>;
export const FrontierListDtoSchema = z.array(FrontierItemDtoSchema);

export const RawGraphNodeDtoSchema = z.object({
  id: z.string(),
  properties: z.object({
    type: nodeTypeSchema,
    label: z.string(),
  }).passthrough(),
}).passthrough();

export const RawGraphEdgeDtoSchema = z.object({
  id: z.string().optional(),
  source: z.string(),
  target: z.string(),
  properties: z.object({ type: edgeTypeSchema }).passthrough(),
}).passthrough();

export const ColdNodeDtoSchema = z.object({
  id: z.string(),
  type: nodeTypeSchema,
  label: z.string(),
  ip: z.string().optional(),
  hostname: z.string().optional(),
  discovered_at: z.string(),
  last_seen_at: z.string(),
  subnet_cidr: z.string().optional(),
  provenance: z.string().optional(),
  alive: z.boolean().optional(),
  confidence: z.number().optional(),
  finding_id: z.string().optional(),
  action_id: z.string().optional(),
}).passthrough();

export const RawGraphDtoSchema = z.object({
  nodes: z.array(RawGraphNodeDtoSchema),
  edges: z.array(RawGraphEdgeDtoSchema),
  cold_nodes: z.array(ColdNodeDtoSchema).optional(),
}).passthrough();
export type RawGraphNodeDto = z.infer<typeof RawGraphNodeDtoSchema>;
export type RawGraphEdgeDto = z.infer<typeof RawGraphEdgeDtoSchema>;
export type ColdNodeDto = z.infer<typeof ColdNodeDtoSchema>;
export type RawGraphDto = z.infer<typeof RawGraphDtoSchema>;

export interface GraphNodeViewModel extends Record<string, unknown> {
  id: string;
  type: string;
  label: string;
}

export interface GraphEdgeViewModel extends Record<string, unknown> {
  id?: string;
  source: string;
  target: string;
  type: string;
}

export interface GraphViewModel {
  nodes: GraphNodeViewModel[];
  edges: GraphEdgeViewModel[];
  coldInventory: ColdNodeDto[];
}

export const CAMPAIGN_STRATEGIES = [
  'credential_spray',
  'enumeration',
  'post_exploitation',
  'network_discovery',
  'custom',
] as const;
export const CampaignStrategySchema = z.enum(CAMPAIGN_STRATEGIES);

export const CAMPAIGN_STATUSES = ['draft', 'active', 'paused', 'completed', 'aborted'] as const;
export const CampaignStatusSchema = z.enum(CAMPAIGN_STATUSES);

export const CampaignAbortConditionSchema = z.object({
  type: z.enum(['consecutive_failures', 'total_failures_pct', 'opsec_noise_ceiling', 'time_limit_seconds']),
  threshold: z.number(),
}).strict();
export type CampaignAbortCondition = z.infer<typeof CampaignAbortConditionSchema>;

export const CampaignProgressSchema = z.object({
  total: z.number().int().nonnegative(),
  completed: z.number().int().nonnegative(),
  succeeded: z.number().int().nonnegative(),
  failed: z.number().int().nonnegative(),
  consecutive_failures: z.number().int().nonnegative(),
}).passthrough();
export type CampaignProgress = z.infer<typeof CampaignProgressSchema>;

const campaignShape = {
  id: z.string(),
  name: z.string(),
  strategy: CampaignStrategySchema,
  status: CampaignStatusSchema,
  items: z.array(z.string()),
  item_status: z.record(z.enum(['succeeded', 'failed'])).optional(),
  abort_conditions: z.array(CampaignAbortConditionSchema),
  progress: CampaignProgressSchema,
  chain_id: z.string().optional(),
  stable_key: z.string().optional(),
  phase_id: z.string().optional(),
  parent_id: z.string().optional(),
  created_at: z.string(),
  started_at: z.string().optional(),
  completed_at: z.string().optional(),
  findings: z.array(z.string()),
};

export const CampaignDtoSchema = z.object(campaignShape).passthrough();
export const CampaignOpsecDtoSchema = z.object({
  global_noise_spent: z.number(),
  noise_budget_remaining: z.number(),
  max_noise: z.number(),
  recommended_approach: z.enum(['quiet', 'normal', 'loud']),
  defensive_signals: z.array(z.object({
    type: z.string(),
    host_id: z.string().optional(),
    domain: z.string().optional(),
    detected_at: z.string(),
    description: z.string(),
  }).passthrough()),
  time_window_remaining_hours: z.number().optional(),
  warning: z.string().optional(),
}).passthrough();

export const DashboardCampaignDtoSchema = z.object({
  ...campaignShape,
  agent_count: z.number().int().nonnegative(),
  running_agents: z.number().int().nonnegative(),
  agents_total: z.number().int().nonnegative(),
  agents_active: z.number().int().nonnegative(),
  completion_pct: z.number(),
  findings_count: z.number().int().nonnegative(),
  child_count: z.number().int().nonnegative().optional(),
  opsec: CampaignOpsecDtoSchema,
}).passthrough();
export type CampaignDto = z.infer<typeof CampaignDtoSchema>;
export type DashboardCampaignDto = z.infer<typeof DashboardCampaignDtoSchema>;

export const CampaignCreateRequestSchema = z.object({
  name: z.string().trim().min(1),
  strategy: CampaignStrategySchema,
  item_ids: z.array(z.string().min(1)).min(1),
  abort_conditions: z.array(CampaignAbortConditionSchema).optional(),
}).strict();

export const CampaignUpdateRequestSchema = z.object({
  name: z.string().trim().min(1).optional(),
  abort_conditions: z.array(CampaignAbortConditionSchema).optional(),
  add_items: z.array(z.string().min(1)).optional(),
  remove_items: z.array(z.string().min(1)).optional(),
}).strict();

export const CampaignActionRequestSchema = z.object({
  action: z.enum(['activate', 'pause', 'resume', 'abort']),
}).strict();

export const CampaignDispatchRequestSchema = z.object({
  max_agents: z.number().int().min(1).max(20).optional(),
  hops: z.number().int().min(0).max(5).optional(),
  skill: z.string().min(1).optional(),
}).strict();

export const CampaignSplitRequestSchema = z.object({
  count: z.number().int().min(2),
}).strict();

export const CampaignListResponseSchema = z.object({
  campaigns: z.array(DashboardCampaignDtoSchema),
  total: z.number().int().nonnegative(),
}).passthrough();
export type CampaignListResponse = z.infer<typeof CampaignListResponseSchema>;
export const CampaignCreateResponseSchema = z.object({ campaign: CampaignDtoSchema }).passthrough();
export const CampaignUpdateResponseSchema = z.object({ campaign: CampaignDtoSchema }).passthrough();
export const CampaignActionResponseSchema = z.object({
  action: z.enum(['activate', 'pause', 'resume', 'abort']),
  campaign: CampaignDtoSchema,
}).passthrough();
export const CampaignCloneResponseSchema = z.object({ campaign: CampaignDtoSchema }).passthrough();
export const CampaignDeleteResponseSchema = z.object({ deleted: z.literal(true) }).passthrough();
export const CampaignSplitResponseSchema = z.object({
  parent_id: z.string(),
  children: z.array(CampaignDtoSchema),
  count: z.number().int().nonnegative(),
}).passthrough();
export const CampaignChildrenResponseSchema = z.object({
  parent_id: z.string(),
  children: z.array(DashboardCampaignDtoSchema),
  derived_status: CampaignStatusSchema.nullable(),
  aggregated_progress: CampaignProgressSchema.nullable(),
}).passthrough();

export const CampaignDispatchResponseSchema = z.object({
  campaign_id: z.string(),
  strategy: z.string(),
  requested: z.number().int(),
  total_items: z.number().int(),
  dispatched: z.array(z.object({
    task_id: z.string(),
    agent_id: z.string(),
    frontier_item_id: z.string(),
    scope_nodes: z.number().int(),
    archetype: z.string(),
    skill: z.string().optional(),
  }).passthrough()),
  skipped: z.array(z.object({ frontier_item_id: z.string(), reason: z.string() }).passthrough()),
  warning: z.string().optional(),
  error: z.string().optional(),
}).passthrough();
export type CampaignDispatchResponse = z.infer<typeof CampaignDispatchResponseSchema>;

export const AgentStatusSchema = z.enum(['pending', 'running', 'completed', 'failed', 'interrupted']);
export const AgentDtoSchema = z.object({
  task_id: z.string(),
  agent_label: z.string(),
  id: z.string(),
  agent_id: z.string(),
  status: AgentStatusSchema,
  assigned_at: z.string(),
  completed_at: z.string().optional(),
  elapsed_ms: z.number().nonnegative().optional(),
  queued: z.boolean(),
  backend: z.enum(['scripted', 'headless_mcp', 'manual']).optional(),
  role: z.enum(['default', 'research', 'planner', 'orchestrator']).optional(),
  archetype: z.string().optional(),
  skill: z.string().optional(),
  objective: z.string().optional(),
  model: z.string().optional(),
  heartbeat_at: z.string().optional(),
  heartbeat_ttl_seconds: z.number().optional(),
  lifecycle: z.enum(['queued', 'live', 'stale', 'completed', 'failed', 'interrupted']),
  live: z.boolean(),
  subgraph_node_ids: z.array(z.string()),
  campaign_id: z.string().optional(),
  campaign: z.object({ id: z.string(), name: z.string(), strategy: z.string() }).passthrough().optional(),
  frontier_item_id: z.string().optional(),
  result_summary: z.string().optional(),
  current_action: z.string().optional(),
  current_action_type: z.string().optional(),
  current_action_at: z.string().optional(),
  last_finding_at: z.string().optional(),
  findings_count: z.number().int().nonnegative(),
}).passthrough();
export type AgentDto = z.infer<typeof AgentDtoSchema>;
export const AgentListResponseSchema = z.object({
  agents: z.array(AgentDtoSchema),
  total: z.number().int().nonnegative(),
}).passthrough();
export type AgentListResponse = z.infer<typeof AgentListResponseSchema>;

export const CampaignDetailResponseSchema = z.object({
  campaign: DashboardCampaignDtoSchema,
  agents: z.array(AgentDtoSchema),
  abort_check: z.record(z.unknown()).optional(),
  finding_details: z.array(z.object({
    id: z.string(),
    label: z.string(),
    type: z.string(),
    created_at: z.string().nullable(),
  }).passthrough()),
}).passthrough();
export type CampaignDetailResponse = z.infer<typeof CampaignDetailResponseSchema>;

export const TimeWindowSchema = z.object({
  start_hour: z.number().int().min(0).max(23),
  end_hour: z.number().int().min(0).max(23),
}).strict();

export const OpsecSettingsSchema = z.object({
  enabled: z.boolean(),
  max_noise: z.number().min(0).max(1),
  approval_mode: z.enum(['auto-approve', 'approve-critical', 'approve-all']),
  approval_timeout_ms: z.number().int().min(1_000),
  blacklisted_techniques: z.array(z.string()),
  time_window: TimeWindowSchema.nullable(),
}).passthrough();

export const SettingsDtoSchema = z.object({
  opsec: OpsecSettingsSchema,
  opsec_status: z.object({
    enabled: z.boolean(),
    inert: z.boolean(),
    configured_fields: z.array(z.string()),
  }).passthrough(),
  noise_state: z.object({
    global_noise_spent: z.number(),
    noise_ceiling_ratio: z.number(),
    per_host_ceiling_ratio: z.number(),
  }).passthrough(),
  profile: z.string(),
}).passthrough();
export type SettingsDto = z.infer<typeof SettingsDtoSchema>;

export const SettingsPatchSchema = z.object({
  enabled: z.boolean().optional(),
  max_noise: z.number().min(0).max(1).optional(),
  approval_mode: z.enum(['auto-approve', 'approve-critical', 'approve-all']).optional(),
  approval_timeout_ms: z.number().int().min(1_000).optional(),
  blacklisted_techniques: z.array(z.string()).optional(),
  time_window: TimeWindowSchema.nullable().optional(),
}).strict();
export const SettingsUpdateResultSchema = z.object({
  updated: z.boolean(),
  opsec: z.record(z.unknown()),
}).passthrough();

export const HealthIssueDtoSchema = z.object({
  severity: z.enum(['warning', 'critical']),
  check: z.string(),
  message: z.string(),
  node_ids: z.array(z.string()).optional(),
  edge_ids: z.array(z.string()).optional(),
  details: z.record(z.unknown()).optional(),
}).passthrough();
export const HealthReportDtoSchema = z.object({
  status: z.enum(['healthy', 'warning', 'critical']),
  counts_by_severity: z.object({ warning: z.number(), critical: z.number() }).passthrough(),
  issues: z.array(HealthIssueDtoSchema),
}).passthrough();
export const HealthDtoSchema = z.object({
  graph_stats: z.object({
    nodes: z.number(),
    edges: z.number(),
    node_types: z.record(z.number()),
  }).passthrough(),
  ad_context: z.boolean(),
  health_checks: HealthReportDtoSchema,
}).passthrough();
export type HealthDto = z.infer<typeof HealthDtoSchema>;

export const ObjectiveDtoSchema = z.object({
  id: z.string(),
  description: z.string(),
  achieved: z.boolean(),
  achieved_at: z.string().optional(),
  target_node_type: nodeTypeSchema.optional(),
  target_criteria: z.record(z.unknown()).optional(),
  achievement_edge_types: z.array(edgeTypeSchema).optional(),
}).passthrough();
export type ObjectiveDto = z.infer<typeof ObjectiveDtoSchema>;

export const ObjectiveCreateRequestSchema = z.object({
  description: z.string().trim().min(1),
  target_node_type: nodeTypeSchema.optional(),
  target_criteria: z.record(z.unknown()).optional(),
  achievement_edge_types: z.array(edgeTypeSchema).optional(),
}).strict();
export type ObjectiveCreateRequest = z.infer<typeof ObjectiveCreateRequestSchema>;
export const ObjectiveUpdateRequestSchema = ObjectiveCreateRequestSchema.partial().extend({
  achieved: z.boolean().optional(),
}).strict();
export type ObjectiveUpdateRequest = z.infer<typeof ObjectiveUpdateRequestSchema>;
export const OBJECTIVE_NODE_TYPES = NODE_TYPES;
export const OBJECTIVE_EDGE_TYPES = EDGE_TYPES;
export const ObjectiveCreateResponseSchema = z.object({ created: z.literal(true), objective: ObjectiveDtoSchema }).passthrough();
export const ObjectiveUpdateResponseSchema = z.object({ updated: z.literal(true) }).passthrough();
export const ObjectiveDeleteResponseSchema = z.object({ deleted: z.literal(true) }).passthrough();

export const FrontierWeightsDtoSchema = z.object({
  fan_out: z.record(z.number().nonnegative()),
  noise: z.record(z.number().min(0).max(1)),
}).passthrough();
export type FrontierWeightsDto = z.infer<typeof FrontierWeightsDtoSchema>;
export const FrontierWeightsPatchSchema = z.object({
  fan_out: z.record(z.number().nonnegative()).optional(),
  noise: z.record(z.number().min(0).max(1)).optional(),
}).strict();
export const FrontierWeightsUpdateResultSchema = z.object({
  updated: z.literal(true),
  weights: FrontierWeightsDtoSchema,
}).passthrough();
export const FrontierWeightsResetResultSchema = z.object({
  reset: z.literal(true),
  weights: FrontierWeightsDtoSchema,
}).passthrough();

export const DashboardErrorSchema = z.object({
  error: z.string(),
  code: z.string().optional(),
}).passthrough();

export const ConfigRecoveryStatusSchema = z.object({
  status: z.enum(['unmanaged', 'in_sync', 'recovered', 'diverged', 'write_incomplete']),
  resolution_required: z.boolean(),
  file_path: z.string().optional(),
  intent_path: z.string().optional(),
  intent_present: z.boolean(),
  file_valid: z.boolean().optional(),
  file_revision: z.number().int().positive().optional(),
  state_revision: z.number().int().positive().optional(),
  runtime_revision: z.number().int().positive().optional(),
  file_hash: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  state_hash: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  runtime_hash: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  reason: z.string().optional(),
  last_resolution: z.enum(['use_file', 'use_state']).optional(),
  allowed_resolutions: z.array(z.enum(['use_file', 'use_state'])).optional(),
  conflicted_intent: z.object({
    archive_path: z.string(),
    intent_sha256: Sha256Schema,
    intent_checksum: Sha256Schema.optional(),
    reason: z.string(),
    observed_file_hash: Sha256Schema,
    observed_state_hash: Sha256Schema,
  }).passthrough().optional(),
}).passthrough();
export type ConfigRecoveryStatusDto = z.infer<typeof ConfigRecoveryStatusSchema>;

export const StateMigrationStatusSchema = z.object({
  status: z.enum(['not_checked', 'current', 'backup_created', 'migrated', 'blocked']),
  supported_state_version: z.number().int().positive(),
  supported_journal_version: z.number().int().positive(),
  observed_state_version: z.number().int().nonnegative().optional(),
  // Zero is not a supported journal version, but it is a useful observed
  // value when an invalid on-disk discriminator forced read-only recovery.
  observed_journal_version: z.number().int().nonnegative().optional(),
  migration_required: z.boolean(),
  backup_path: z.string().optional(),
  backup_manifest_sha256: Sha256Schema.optional(),
  reason: z.string().optional(),
}).passthrough();
export type StateMigrationStatusDto = z.infer<typeof StateMigrationStatusSchema>;

export const RecoveryStatusDtoSchema = z.object({
  outcome: z.enum(['clean', 'recovered', 'incomplete', 'reinitialized']),
  source: z.enum(['fresh', 'state', 'snapshot', 'config']),
  complete: z.boolean(),
  writable: z.boolean(),
  reason: z.string().optional(),
  persistence_reason: z.string().optional(),
  state_recovery: z.object({
    outcome: z.enum(['clean', 'recovered', 'incomplete', 'reinitialized']),
    source: z.enum(['fresh', 'state', 'snapshot', 'config']),
    complete: z.boolean(),
    writable: z.boolean(),
    reason: z.string().optional(),
    highest_allocated_logical_seq: z.number().int().nonnegative().optional(),
    highest_allocated_frame_seq: z.number().int().nonnegative().optional(),
    highest_physical_frame_seq: z.number().int().nonnegative().optional(),
    highest_contiguous_applied_logical_seq: z.number().int().nonnegative().optional(),
  }).passthrough().optional(),
  base_checkpoint: z.number().int().nonnegative(),
  highest_allocated_seq: z.number().int().nonnegative(),
  highest_allocated_logical_seq: z.number().int().nonnegative().optional(),
  highest_allocated_frame_seq: z.number().int().nonnegative().optional(),
  highest_on_disk_seq: z.number().int().nonnegative(),
  highest_physical_frame_seq: z.number().int().nonnegative().optional(),
  highest_contiguous_applied_seq: z.number().int().nonnegative(),
  highest_contiguous_applied_logical_seq: z.number().int().nonnegative().optional(),
  consecutive_persistence_failures: z.number().int().nonnegative(),
  last_persistence_error: z.string().optional(),
  journal: z.object({
    enabled: z.boolean(),
    format_version: z.number().int().positive().optional(),
    path: z.string().optional(),
    read: z.number().int().nonnegative(),
    attempted: z.number().int().nonnegative(),
    applied: z.number().int().nonnegative(),
    skipped: z.number().int().nonnegative(),
    failed: z.number().int().nonnegative(),
    malformed: z.boolean(),
    preserved: z.boolean(),
  }).passthrough(),
  state_migration: StateMigrationStatusSchema.optional(),
  config_recovery: ConfigRecoveryStatusSchema.optional(),
  runtime_ownership_warnings: z.array(z.object({
    run_id: z.string(),
    pid: z.number().int().positive().optional(),
    lifecycle: z.string(),
    message: z.string(),
  }).passthrough()).optional(),
  coordination_warnings: z.array(z.object({
    warning_id: z.string(),
    relationship: z.string(),
    reference: z.string(),
    message: z.string(),
    candidate_task_ids: z.array(z.string()).optional(),
    payload: z.unknown().optional(),
  }).passthrough()).optional(),
}).passthrough();
export type RecoveryStatusDto = z.infer<typeof RecoveryStatusDtoSchema>;

export const RecoveryStatusResponseSchema = z.object({
  recovery: RecoveryStatusDtoSchema,
}).passthrough();
export type RecoveryStatusResponse = z.infer<typeof RecoveryStatusResponseSchema>;

export const ConfigDivergenceResolveRequestSchema = z.object({
  resolution: z.enum(['use_file', 'use_state']),
  expected_file_hash: z.string().regex(/^[0-9a-f]{64}$/),
  expected_state_hash: z.string().regex(/^[0-9a-f]{64}$/),
}).strict();
export type ConfigDivergenceResolveRequest = z.infer<typeof ConfigDivergenceResolveRequestSchema>;

export const ConfigDivergenceResolveResponseSchema = z.object({
  resolved: z.literal(true),
  mode: z.enum(['use_file', 'use_state']),
  config: z.object({
    id: z.string().min(1),
    config_revision: z.number().int().positive(),
    config_hash: z.string().regex(/^[0-9a-f]{64}$/),
  }).passthrough(),
  recovery: ConfigRecoveryStatusSchema,
}).passthrough();
export type ConfigDivergenceResolveResponse = z.infer<typeof ConfigDivergenceResolveResponseSchema>;
