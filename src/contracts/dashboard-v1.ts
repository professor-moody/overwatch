import { z } from 'zod';
import { EDGE_TYPES, NODE_TYPES, edgeTypeSchema, nodeTypeSchema } from '../types.js';

const Sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);

/**
 * Browser-safe runtime contracts for the compatibility-v1 dashboard API.
 * Response objects remain additive via passthrough(); mutation inputs are
 * strict where the public operation is defined as a strict mutation.
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

export const DispatchedAgentTaskSchema = z.object({
  task_id: z.string().optional(),
  agent_label: z.string().optional(),
  id: z.string(),
  agent_id: z.string(),
  assigned_at: z.string(),
  status: AgentStatusSchema,
  subgraph_node_ids: z.array(z.string()),
  frontier_item_id: z.string().optional(),
  campaign_id: z.string().optional(),
  archetype: z.string().optional(),
  skill: z.string().optional(),
  objective: z.string().optional(),
  model: z.string().optional(),
}).passthrough();
export type DispatchedAgentTask = z.infer<typeof DispatchedAgentTaskSchema>;

const DashboardCommandMetadataShape = {
  command_id: z.string(),
  idempotency_key: z.string(),
  replayed: z.boolean(),
};

const DispatchRefusalSchema = z.object({
  dispatched: z.literal(false),
  reason: z.string(),
  existing_task_id: z.string().optional(),
  existing_agent_id: z.string().optional(),
  node_id: z.string().optional(),
  cap_scope: z.string().optional(),
  cap_key: z.string().optional(),
  limit: z.number().int().nonnegative().optional(),
  current: z.number().int().nonnegative().optional(),
  ...DashboardCommandMetadataShape,
}).passthrough();

const DispatchErrorResponseSchema = z.object({
  error: z.string(),
  code: z.string().optional(),
  reason: z.string().optional(),
  command_id: z.string().optional(),
}).passthrough();

export const DispatchAgentResponseSchema = z.union([
  z.object({
    dispatched: z.literal(true),
    task: DispatchedAgentTaskSchema,
    skipped_existing: z.boolean().optional(),
    scope_warning: z.string().optional(),
    ...DashboardCommandMetadataShape,
  }).passthrough(),
  DispatchRefusalSchema,
  DispatchErrorResponseSchema,
]);
export type DispatchAgentResponse = z.infer<typeof DispatchAgentResponseSchema>;

export const DispatchBatchResponseSchema = z.object({
  dispatched: z.array(z.object({
    node_ids: z.array(z.string()),
    task_id: z.string(),
    agent_id: z.string(),
    archetype: z.string().optional(),
  }).passthrough()),
  skipped: z.array(z.object({
    node_ids: z.array(z.string()),
    reason: z.string(),
    existing_agent_id: z.string().optional(),
  }).passthrough()),
  deferred: z.array(z.object({
    node_ids: z.array(z.string()),
    reason: z.string(),
  }).passthrough()),
  summary: z.object({
    dispatched: z.number().int().nonnegative(),
    skipped: z.number().int().nonnegative(),
    deferred: z.number().int().nonnegative(),
    groups: z.number().int().nonnegative(),
  }).passthrough(),
  ...DashboardCommandMetadataShape,
}).passthrough();
export type DispatchBatchResponse = z.infer<typeof DispatchBatchResponseSchema>;

export const QuickDeployResponseSchema = z.union([
  z.object({
    dispatched: z.literal(true),
    task: DispatchedAgentTaskSchema,
    archetype: z.string(),
    scope: z.object({
      added_cidrs: z.array(z.string()),
      added_domains: z.array(z.string()),
      affected_node_count: z.number().int().nonnegative(),
    }).passthrough(),
    ...DashboardCommandMetadataShape,
  }).passthrough(),
  DispatchRefusalSchema,
  DispatchErrorResponseSchema,
]);
export type QuickDeployResponse = z.infer<typeof QuickDeployResponseSchema>;

export const AgentArchetypeSummarySchema = z.object({
  id: z.string(),
  label: z.string(),
  description: z.string(),
  role: z.string(),
  defaultSkill: z.string().optional(),
  suitableFor: z.object({
    frontierTypes: z.array(z.string()).optional(),
    nodeTypes: z.array(z.string()).optional(),
    rawTarget: z.boolean().optional(),
  }).passthrough(),
}).passthrough();
export type AgentArchetypeSummary = z.infer<typeof AgentArchetypeSummarySchema>;
export const AgentArchetypesResponseSchema = z.object({
  archetypes: z.array(AgentArchetypeSummarySchema),
  models: z.object({
    available: z.array(z.string()),
    default: z.string().optional(),
  }).passthrough().optional(),
}).passthrough();
export type AgentArchetypesResponse = z.infer<typeof AgentArchetypesResponseSchema>;

export const OperatorOpSchema = z.discriminatedUnion('op', [
  z.object({
    op: z.literal('directive'),
    task_id: z.string(),
    agent_label: z.string(),
    kind: z.string(),
    node_ids: z.array(z.string()).optional(),
    frontier_types: z.array(z.string()).optional(),
    note: z.string().optional(),
  }).passthrough(),
  z.object({
    op: z.literal('scope'),
    add_cidrs: z.array(z.string()).optional(),
    add_domains: z.array(z.string()).optional(),
    add_exclusions: z.array(z.string()).optional(),
  }).passthrough(),
  z.object({ op: z.literal('approve'), action_id: z.string(), notes: z.string().optional() }).passthrough(),
  z.object({ op: z.literal('deny'), action_id: z.string(), reason: z.string().optional() }).passthrough(),
  z.object({
    op: z.literal('dispatch'),
    target_node_ids: z.array(z.string()),
    archetype: z.string().optional(),
    skill: z.string().optional(),
    objective: z.string().optional(),
  }).passthrough(),
]);
export type OperatorOpDto = z.infer<typeof OperatorOpSchema>;

export const CommandOpResultSchema = z.object({
  op: OperatorOpSchema,
  ok: z.boolean(),
  detail: z.string().optional(),
  error: z.string().optional(),
}).passthrough();
export type CommandOpResultDto = z.infer<typeof CommandOpResultSchema>;

export const QueryAnswerSchema = z.object({
  kind: z.enum([
    'changes_since',
    'timeline',
    'list_nodes',
    'finding_readiness',
    'find_paths',
    'retrospective',
    'unanswerable',
  ]),
  summary: z.string(),
  rows: z.array(z.string()).optional(),
  total: z.number().int().nonnegative().optional(),
  note: z.string().optional(),
}).passthrough();
export type QueryAnswerDto = z.infer<typeof QueryAnswerSchema>;

export const ProposedPlanSchema = z.object({
  plan_id: z.string(),
  command_id: z.string().optional(),
  command: z.string(),
  ops: z.array(OperatorOpSchema),
  summary: z.string(),
  rationale: z.string().optional(),
  owner_task_id: z.string().optional(),
  owner_agent_label: z.string().optional(),
  source_task_id: z.string().optional(),
  source_agent_id: z.string().optional(),
  scope_preview: z.object({}).passthrough().optional(),
  created_at: z.number(),
  expires_at: z.number(),
  status: z.enum(['open', 'confirmed', 'denied', 'expired']),
  resolved_at: z.number().optional(),
  confirmed_at: z.number().optional(),
  denied_at: z.number().optional(),
  expired_at: z.number().optional(),
  acknowledged_at: z.number().optional(),
  execution_outcome: z.object({
    status: z.enum(['succeeded', 'partial', 'failed']),
    completed_at: z.number(),
    results: z.array(z.unknown()),
  }).passthrough().optional(),
  recovery_warning: z.string().optional(),
}).passthrough();
export type ProposedPlanDto = z.infer<typeof ProposedPlanSchema>;

export const CommandPreviewSchema = z.object({
  plan_id: z.string().optional(),
  ops: z.array(OperatorOpSchema),
  summary: z.string(),
  unresolved: z.array(z.object({ text: z.string(), reason: z.string() }).passthrough()),
  needs_planner: z.boolean(),
  planner_task_id: z.string().optional(),
  command_id: z.string().optional(),
  planner_status: z.string().optional(),
  planner_available: z.boolean().optional(),
  planner_plan: ProposedPlanSchema.optional(),
  query_answer: QueryAnswerSchema.optional(),
}).passthrough();
export type CommandPreviewDto = z.infer<typeof CommandPreviewSchema>;

export const CommandExecutionResponseSchema = z.object({
  executed: z.literal(true),
  results: z.array(CommandOpResultSchema),
  command_id: z.string(),
  idempotency_key: z.string(),
  replayed: z.boolean(),
}).passthrough();
export const CommandDenialResponseSchema = z.object({
  denied: z.literal(true),
  plan_id: z.string(),
  command_id: z.string(),
  idempotency_key: z.string(),
  replayed: z.boolean(),
}).passthrough();
export const InterpretCommandResponseSchema = z.union([
  CommandPreviewSchema,
  CommandExecutionResponseSchema,
  CommandDenialResponseSchema,
]);

export const ProposedPlansResponseSchema = z.object({
  plans: z.array(ProposedPlanSchema),
}).passthrough();

export const ApplicationCommandRecordSchema = z.object({
  command_id: z.string(),
  idempotency_key: z.string(),
  input_sha256: Sha256Schema,
  validated_input: z.unknown(),
  command_kind: z.string(),
  transport: z.enum(['mcp', 'dashboard', 'cli', 'planner', 'scripted_runner', 'headless_runner', 'system']),
  actor_task_id: z.string().nullable(),
  action_id: z.string().optional(),
  frontier_item_id: z.string().optional(),
  plan_id: z.string().optional(),
  status: z.enum(['accepted', 'running', 'succeeded', 'failed', 'interrupted']),
  created_at: z.string(),
  started_at: z.string().optional(),
  completed_at: z.string().optional(),
  result: z.unknown().optional(),
  error: z.object({
    code: z.string().optional(),
    message: z.string(),
    details: z.unknown().optional(),
  }).passthrough().optional(),
  entity_refs: z.record(z.union([z.string(), z.array(z.string())])).optional(),
}).passthrough();
export type ApplicationCommandRecordDto = z.infer<typeof ApplicationCommandRecordSchema>;
export const ApplicationCommandResponseSchema = z.object({
  command: ApplicationCommandRecordSchema,
}).passthrough();
export const ActiveApplicationCommandsResponseSchema = z.object({
  commands: z.array(ApplicationCommandRecordSchema),
}).passthrough();

/**
 * Repair the presentation of the legacy registration message that interpolated
 * an absent frontier id. The persisted activity row remains byte-for-byte
 * unchanged; HTTP snapshots and browser views use this display-only text.
 */
export function normalizeLegacyAgentDispatchDescription(entry: {
  event_type?: string;
  description: string;
  details?: Record<string, unknown>;
}): string {
  const legacyShape = /^Agent dispatched:\s*(.*?)\s+for undefined\s*$/i.exec(entry.description);
  // The oldest durable rows predate event_type. Restrict that compatibility
  // case to the exact historical sentence so unrelated untyped activity is not
  // rewritten. Explicit non-registration event types always remain untouched.
  if (
    !legacyShape
    || (entry.event_type !== undefined && entry.event_type !== 'agent_registered')
  ) {
    return entry.description;
  }
  const withoutUndefined = entry.description.replace(/\sfor undefined\s*$/i, '').trim();
  const planner = entry.details?.role === 'planner'
    || /^planner(?:-|\b)/i.test(legacyShape[1]);
  return planner
    ? `${withoutUndefined} as operator planner`
    : withoutUndefined;
}

export const AgentQuerySchema = z.object({
  query_id: z.string(),
  owner_task_id: z.string().optional(),
  owner_agent_label: z.string().optional(),
  task_id: z.string().optional(),
  agent_id: z.string().optional(),
  question: z.string(),
  options: z.array(z.string()).optional(),
  status: z.enum(['open', 'answered', 'expired']),
  answer: z.string().optional(),
  created_at: z.number(),
  expires_at: z.number(),
  answered_at: z.number().optional(),
  delivered_at: z.number().optional(),
  acknowledged_at: z.number().optional(),
  expired_at: z.number().optional(),
  recovery_warning: z.string().optional(),
}).passthrough();
export type AgentQueryDto = z.infer<typeof AgentQuerySchema>;
export const AgentQueriesResponseSchema = z.object({
  queries: z.array(AgentQuerySchema),
}).passthrough();

export const SessionStateSchema = z.enum([
  'pending',
  'connected',
  'resume_available',
  'interrupted',
  'closed',
  'error',
]);

export const SessionDtoSchema = z.object({
  id: z.string(),
  kind: z.string(),
  adapter: z.string().optional(),
  transport: z.string(),
  state: SessionStateSchema,
  listener_id: z.string().optional(),
  connection_generation: z.number().int().nonnegative().optional(),
  connection_id: z.string().optional(),
  connection_started_at: z.string().optional(),
  last_connection_id: z.string().optional(),
  last_connection_state: z.enum(['disconnected', 'interrupted', 'closed']).optional(),
  last_connection_closed_at: z.string().optional(),
  resume_policy: z.enum(['none', 'manual']).optional(),
  mode: z.enum(['connect', 'listen']).optional(),
  bind_host: z.string().optional(),
  advertise_host: z.string().optional(),
  accept_mode: z.enum(['single', 'rearm']).optional(),
  reachability_warnings: z.array(z.string()).optional(),
  auth_status: z.enum(['shell_confirmed', 'connected_unconfirmed', 'auth_prompt', 'auth_failed']).optional(),
  title: z.string(),
  host: z.string().optional(),
  user: z.string().optional(),
  port: z.number().int().optional(),
  pid: z.number().int().optional(),
  owner: z.string().optional(),
  agent_id: z.string().optional(),
  target_node: z.string().optional(),
  principal_node: z.string().optional(),
  credential_node: z.string().optional(),
  action_id: z.string().optional(),
  frontier_item_id: z.string().optional(),
  claimed_by: z.string().optional(),
  created_at: z.string().optional(),
  started_at: z.string(),
  last_activity_at: z.string(),
  closed_at: z.string().optional(),
  capabilities: z.object({
    has_stdin: z.boolean().optional(),
    has_stdout: z.boolean().optional(),
    supports_resize: z.boolean().optional(),
    supports_signals: z.boolean().optional(),
    tty_quality: z.string().optional(),
  }).passthrough(),
  buffer_end_pos: z.number().int().nonnegative(),
  notes: z.string().optional(),
  default_validation: z.object({
    technique: z.string().optional(),
    target_ip: z.string().optional(),
    target_url: z.string().optional(),
    allow_unverified_scope: z.boolean().optional(),
  }).passthrough().optional(),
}).passthrough();
export type SessionDto = z.infer<typeof SessionDtoSchema>;

export const SessionBufferResponseSchema = z.object({
  session_id: z.string(),
  connection_id: z.string().optional(),
  connection_generation: z.number().int().nonnegative().optional(),
  start_pos: z.number().int().nonnegative(),
  end_pos: z.number().int().nonnegative(),
  text: z.string(),
  truncated: z.boolean(),
  cursor_reset: z.boolean().optional(),
}).passthrough();
export type SessionBufferResponseDto = z.infer<typeof SessionBufferResponseSchema>;

export const SessionCloseResponseSchema = z.object({
  metadata: SessionDtoSchema,
  final: z.object({
    session_id: z.string(),
    connection_id: z.string().optional(),
    connection_generation: z.number().int().nonnegative().optional(),
    start_pos: z.number().int().nonnegative(),
    end_pos: z.number().int().nonnegative(),
    text: z.string(),
    truncated: z.boolean(),
  }).passthrough(),
}).passthrough();
export const SessionResumeResponseSchema = z.object({
  resumed: z.literal(true),
  metadata: SessionDtoSchema,
}).passthrough();
export const SessionUpdateResponseSchema = z.object({
  metadata: SessionDtoSchema,
}).passthrough();

export const PendingActionDtoSchema = z.object({
  action_id: z.string(),
  technique: z.string().optional(),
  target: z.string().optional(),
  target_node: z.string().optional(),
  target_ip: z.string().optional(),
  target_cidr: z.string().optional(),
  noise_level: z.number().optional(),
  description: z.string(),
  defense_context: z.string().optional(),
  submitted_at: z.string(),
  timeout_at: z.string().optional(),
  resolved_at: z.string().optional(),
  status: z.enum(['pending', 'approved', 'denied', 'timeout', 'aborted']).optional(),
  operator_notes: z.string().optional(),
  reason: z.string().optional(),
  auto_approved: z.boolean().optional(),
  unattended_execute: z.boolean().optional(),
  frontier_item_id: z.string().optional(),
  task_id: z.string().optional(),
  agent_label: z.string().optional(),
  agent_id: z.string().optional(),
  recovery_warning: z.string().optional(),
  validation_result: z.string().optional(),
  opsec_context: z.object({
    noise_level: z.number().optional(),
    noise_budget_remaining: z.number().optional(),
    recommended_approach: z.string().optional(),
    defensive_signals: z.array(z.object({
      type: z.enum(['lockout', 'connection_reset', 'honeypot', 'rate_limit', 'block']),
      host_id: z.string().optional(),
      domain: z.string().optional(),
      detected_at: z.string(),
      description: z.string(),
    }).passthrough()).optional(),
  }).passthrough().optional(),
}).passthrough();
export type PendingActionDto = z.infer<typeof PendingActionDtoSchema>;

export const ActivityEntryDtoSchema = z.object({
  event_id: z.string(),
  id: z.string().optional(),
  timestamp: z.string(),
  event_type: z.string().optional(),
  description: z.string(),
  action_id: z.string().optional(),
  agent_id: z.string().optional(),
  linked_agent_task_id: z.string().optional(),
  details: z.record(z.unknown()).optional(),
  source_kind: z.enum(['primary', 'subagent', 'runner', 'system', 'dashboard']).optional(),
  operator_model: z.string().optional(),
  operator_name: z.string().optional(),
  operator_session_id: z.string().optional(),
  frontier_item_id: z.string().optional(),
  target_node_ids: z.array(z.string()).optional(),
  result_classification: z.enum(['success', 'failure', 'partial', 'neutral']).optional(),
  validation_result: z.string().optional(),
}).passthrough();
export type ActivityEntryDto = z.infer<typeof ActivityEntryDtoSchema>;

export const AgentConsoleKindSchema = z.enum([
  'thought',
  'action',
  'approval',
  'finding',
  'session',
  'transcript',
  'system',
  'command',
]);
export const AgentConsoleSeveritySchema = z.enum(['info', 'success', 'warning', 'error']);
export const AgentConsoleEventDtoSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  agent_id: z.string(),
  source_kind: z.enum(['primary', 'subagent', 'runner', 'system', 'dashboard']).optional(),
  source_label: z.string().optional(),
  operator_name: z.string().optional(),
  operator_model: z.string().optional(),
  kind: AgentConsoleKindSchema,
  severity: AgentConsoleSeveritySchema,
  title: z.string(),
  summary: z.string(),
  status: z.string().optional(),
  links: z.object({
    action_id: z.string().optional(),
    frontier_item_id: z.string().optional(),
    evidence_id: z.string().optional(),
    session_id: z.string().optional(),
    finding_ids: z.array(z.string()).optional(),
    node_ids: z.array(z.string()).optional(),
  }).passthrough().optional(),
  raw: z.record(z.unknown()).optional(),
}).passthrough();
export type AgentConsoleEventDto = z.infer<typeof AgentConsoleEventDtoSchema>;

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
export const RuntimeBuildInfoDtoSchema = z.object({
  schema_version: z.number().int().positive(),
  git_sha: z.string().nullable().optional(),
  input_sha256: Sha256Schema,
  input_file_count: z.number().int().nonnegative().optional(),
  built_at: z.string().optional(),
  runtime_pid: z.number().int().nonnegative(),
  runtime_started_at: z.string(),
}).passthrough();
export type RuntimeBuildInfoDto = z.infer<typeof RuntimeBuildInfoDtoSchema>;
export const HealthDtoSchema = z.object({
  graph_stats: z.object({
    nodes: z.number(),
    edges: z.number(),
    node_types: z.record(z.number()),
  }).passthrough(),
  ad_context: z.boolean(),
  health_checks: HealthReportDtoSchema,
  runtime_build: RuntimeBuildInfoDtoSchema.optional(),
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

const GraphCorrectionOperationBaseSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('drop_node'),
    node_id: z.string().trim().min(1),
  }).strict(),
  z.object({
    kind: z.literal('drop_edge'),
    source_id: z.string().trim().min(1),
    edge_type: edgeTypeSchema,
    target_id: z.string().trim().min(1),
  }).strict(),
  z.object({
    kind: z.literal('replace_edge'),
    source_id: z.string().trim().min(1),
    edge_type: edgeTypeSchema,
    target_id: z.string().trim().min(1),
    new_source_id: z.string().trim().min(1).optional(),
    new_edge_type: edgeTypeSchema.optional(),
    new_target_id: z.string().trim().min(1).optional(),
    confidence: z.number().min(0).max(1).optional(),
    properties: z.record(z.unknown()).optional(),
  }).strict(),
  z.object({
    kind: z.literal('patch_node'),
    node_id: z.string().trim().min(1),
    set_properties: z.record(z.unknown()).optional(),
    unset_properties: z.array(z.string().trim().min(1)).optional(),
  }).strict(),
]);
export const GraphCorrectionOperationSchema =
  GraphCorrectionOperationBaseSchema.superRefine((operation, context) => {
    if (
      operation.kind === 'patch_node'
      && Object.keys(operation.set_properties ?? {}).length === 0
      && (operation.unset_properties?.length ?? 0) === 0
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          'patch_node requires set_properties and/or unset_properties',
      });
    }
  });
export type GraphCorrectionOperationDto = z.infer<
  typeof GraphCorrectionOperationSchema
>;
export const GraphCorrectionRequestSchema = z.object({
  reason: z.string().trim().min(1),
  action_id: z.string().trim().min(1).optional(),
  operations: z.array(GraphCorrectionOperationSchema).min(1),
}).strict();
export const GraphCorrectionResultSchema = z.object({
  dropped_nodes: z.array(z.string()),
  dropped_edges: z.array(z.string()),
  replaced_edges: z.array(z.object({
    old_edge_id: z.string(),
    new_edge_id: z.string(),
  }).strict()),
  patched_nodes: z.array(z.string()),
}).passthrough();
export type GraphCorrectionResultDto = z.infer<
  typeof GraphCorrectionResultSchema
>;

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

const ScopeConfigResponseSchema = z.object({
  cidrs: z.array(z.string()),
  domains: z.array(z.string()),
  exclusions: z.array(z.string()),
}).passthrough();

export const EngagementConfigResponseSchema = z.object({
  id: z.string(),
  name: z.string(),
  created_at: z.string(),
  config_revision: z.number().int().positive().optional(),
  config_hash: Sha256Schema.optional(),
  scope: ScopeConfigResponseSchema,
  objectives: z.array(ObjectiveDtoSchema),
  opsec: z.object({}).passthrough(),
  config_path: z.string().optional(),
  state_path: z.string().optional(),
}).passthrough();
export type EngagementConfigResponseDto = z.infer<typeof EngagementConfigResponseSchema>;

export const EngagementConfigUpdateResponseSchema = z.object({
  updated: z.boolean(),
  config: EngagementConfigResponseSchema,
  command_id: z.string(),
  idempotency_key: z.string(),
  replayed: z.boolean(),
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

export const PLAYBOOK_STATUSES = [
  'pending', 'blocked', 'awaiting_approval', 'running', 'succeeded',
  'failed', 'interrupted', 'skipped', 'cancelled',
] as const;
export const PlaybookStatusSchema = z.enum(PLAYBOOK_STATUSES);
export const PlaybookAttemptSchema = z.object({
  attempt_id: z.string(),
  attempt_number: z.number().int().positive(),
  status: z.enum(['claimed', 'awaiting_approval', 'running', 'succeeded', 'failed', 'interrupted', 'cancelled']),
  started_at: z.string(),
  claimed_via: z.enum(['mcp', 'dashboard', 'cli', 'planner', 'scripted_runner', 'headless_runner', 'system']),
  claimed_by_task_id: z.string().optional(),
  executed_via: z.enum(['mcp', 'dashboard', 'cli', 'planner', 'scripted_runner', 'headless_runner', 'system']).optional(),
  executed_by_task_id: z.string().optional(),
  execution_command_id: z.string(),
  execution_idempotency_key: z.string(),
  execution_action_id: z.string(),
  plan_revision: z.number().int().positive(),
  execution_template_hash: Sha256Schema,
  execution_started_at: z.string().optional(),
  completed_at: z.string().optional(),
  action_id: z.string().optional(),
  evidence_ids: z.array(z.string()),
  finding_ids: z.array(z.string()),
  execution_outcome: z.enum(['succeeded', 'failed', 'interrupted']).optional(),
  parse_outcome: z.enum(['ok', 'no_data', 'validation_failed', 'parser_exception', 'partial']).optional(),
  error: z.string().optional(),
}).passthrough();
export type PlaybookAttemptDto = z.infer<typeof PlaybookAttemptSchema>;

export const PlaybookStepRunSchema = z.object({
  step_id: z.string(),
  ordinal: z.number().int().positive(),
  description: z.string(),
  status: PlaybookStatusSchema,
  depends_on: z.array(z.string()),
  required_bindings: z.array(z.string()),
  produces_bindings: z.array(z.string()),
  resolved_bindings: z.record(z.unknown()),
  resolved_execution: z.record(z.unknown()).optional(),
  blocked_reason: z.string().optional(),
  attempts: z.array(PlaybookAttemptSchema),
  started_at: z.string().optional(),
  completed_at: z.string().optional(),
  updated_at: z.string(),
}).passthrough();
export type PlaybookStepRunDto = z.infer<typeof PlaybookStepRunSchema>;

export const PlaybookRunSchema = z.object({
  schema_version: z.literal(1),
  run_id: z.string(),
  definition: z.object({
    definition_id: z.string(),
    definition_version: z.number().int().positive(),
    provider: z.enum(['aws', 'github', 'entra', 'oidc']),
    title: z.string(),
  }).passthrough(),
  credential_id: z.string(),
  input_hash: Sha256Schema,
  normalized_inputs: z.record(z.unknown()),
  bindings: z.record(z.unknown()),
  plan_revisions: z.array(z.object({
    revision: z.number().int().positive(),
    created_at: z.string(),
    plan_hash: Sha256Schema,
    steps: z.array(z.object({
      step_id: z.string(),
      ordinal: z.number().int().positive(),
      description: z.string(),
      depends_on: z.array(z.string()),
      required_bindings: z.array(z.string()),
      produces_bindings: z.array(z.string()),
      execution_template: z.record(z.unknown()),
    }).passthrough()),
  }).passthrough()).min(1),
  current_plan_revision: z.number().int().positive(),
  steps: z.array(PlaybookStepRunSchema),
  status: PlaybookStatusSchema,
  report_status: z.enum(['generated', 'partial', 'completed']),
  created_at: z.string(),
  updated_at: z.string(),
  started_at: z.string().optional(),
  completed_at: z.string().optional(),
  resume_count: z.number().int().nonnegative(),
  recovery_warning: z.string().optional(),
}).passthrough();
export type PlaybookRunDto = z.infer<typeof PlaybookRunSchema>;

export const LegacyPlaybookRunSchema = z.object({
  run_id: z.string(),
  schema_version: z.undefined().optional(),
}).passthrough();
export const AnyPlaybookRunSchema = z.union([PlaybookRunSchema, LegacyPlaybookRunSchema]);
export const PlaybookRunListResponseSchema = z.object({
  runs: z.array(AnyPlaybookRunSchema),
  total: z.number().int().nonnegative(),
}).passthrough();
export type PlaybookRunListResponse = z.infer<typeof PlaybookRunListResponseSchema>;
export const PlaybookRunResponseSchema = z.object({ run: AnyPlaybookRunSchema }).passthrough();
export type PlaybookRunResponse = z.infer<typeof PlaybookRunResponseSchema>;
export const PlaybookStepClaimResponseSchema = z.object({
  run: PlaybookRunSchema,
  step: PlaybookStepRunSchema,
  attempt: PlaybookAttemptSchema,
  execution: z.record(z.unknown()),
}).passthrough();
export type PlaybookStepClaimResponse = z.infer<typeof PlaybookStepClaimResponseSchema>;
export const PlaybookSkipRequestSchema = z.object({ reason: z.string().max(2_000).optional() }).strict();

export const DashboardStateDtoSchema = z.object({
  engagement: z.object({
    id: z.string(),
    name: z.string(),
    profile: z.string().optional(),
    template: z.string().optional(),
    created_at: z.string().optional(),
  }).passthrough().optional(),
  config: z.object({
    id: z.string(),
    name: z.string(),
    profile: z.string().optional(),
    created_at: z.string().optional(),
    scope: z.object({}).passthrough().optional(),
    opsec: z.object({}).passthrough().optional(),
  }).passthrough(),
  access_summary: z.object({
    compromised_hosts: z.array(z.string()),
    valid_credentials: z.array(z.string()),
    current_access_level: z.string(),
  }).passthrough(),
  graph_summary: z.object({
    total_nodes: z.number().int().nonnegative(),
    total_edges: z.number().int().nonnegative(),
    confirmed_edges: z.number().int().nonnegative(),
    inferred_edges: z.number().int().nonnegative(),
    nodes_by_type: z.record(z.number().int().nonnegative()),
  }).passthrough(),
  objectives: z.array(ObjectiveDtoSchema),
  frontier: FrontierListDtoSchema,
  frontier_hidden: z.object({
    total: z.number().int().nonnegative(),
    by_reason: z.object({
      lease: z.number().int().nonnegative(),
      opsec: z.number().int().nonnegative(),
      dead_host: z.number().int().nonnegative(),
      scope: z.number().int().nonnegative(),
    }).passthrough(),
  }).passthrough(),
  active_agents: z.array(z.object({}).passthrough()),
  agents: z.array(AgentDtoSchema),
  recent_activity: z.array(z.object({
    event_id: z.string(),
    timestamp: z.string(),
    description: z.string(),
  }).passthrough()),
  campaigns: z.array(DashboardCampaignDtoSchema),
  sessions: z.array(SessionDtoSchema),
  pending_actions: z.array(PendingActionDtoSchema),
  playbook_runs: z.array(AnyPlaybookRunSchema).optional(),
  access_level: z.string().optional(),
  history_count: z.number().int().nonnegative().optional(),
  warnings: z.object({}).passthrough(),
  scope_suggestions: z.array(z.object({}).passthrough()),
  phases: z.array(z.object({}).passthrough()),
  lab_readiness: z.object({
    status: z.string(),
    top_issues: z.array(z.string()),
  }).passthrough(),
  persistence_recovery: RecoveryStatusDtoSchema.optional(),
}).passthrough();
export type DashboardStateDto = z.infer<typeof DashboardStateDtoSchema>;

export interface DashboardStateResponse {
  state: DashboardStateDto;
  graph: RawGraphDto;
  history_count: number;
  runtime_build?: RuntimeBuildInfoDto;
  [key: string]: unknown;
}
export const DashboardStateResponseSchema: z.ZodType<DashboardStateResponse> = z.object({
  state: DashboardStateDtoSchema,
  graph: RawGraphDtoSchema,
  history_count: z.number().int().nonnegative(),
  runtime_build: RuntimeBuildInfoDtoSchema.optional(),
}).passthrough();

export const GraphUpdateDetailDtoSchema = z.object({
  new_nodes: z.array(z.string()).optional(),
  updated_nodes: z.array(z.string()).optional(),
  new_edges: z.array(z.string()).optional(),
  updated_edges: z.array(z.string()).optional(),
  inferred_edges: z.array(z.string()).optional(),
  removed_nodes: z.array(z.string()).optional(),
  removed_edges: z.array(z.string()).optional(),
  cold_nodes_changed: z.boolean().optional(),
}).passthrough();

export const GraphDeltaDtoSchema = z.object({
  nodes: z.array(RawGraphNodeDtoSchema),
  edges: z.array(RawGraphEdgeDtoSchema),
  removed_nodes: z.array(z.string()),
  removed_edges: z.array(z.string()),
  cold_nodes: z.array(ColdNodeDtoSchema).optional(),
}).passthrough();

export interface GraphUpdateDataDto {
  state: DashboardStateDto;
  history_count: number;
  detail: z.infer<typeof GraphUpdateDetailDtoSchema>;
  delta: z.infer<typeof GraphDeltaDtoSchema>;
  [key: string]: unknown;
}
export const GraphUpdateDataDtoSchema: z.ZodType<GraphUpdateDataDto> = z.object({
  state: DashboardStateDtoSchema,
  history_count: z.number().int().nonnegative(),
  detail: GraphUpdateDetailDtoSchema,
  delta: GraphDeltaDtoSchema,
}).passthrough();

const timestampedMainEvent = <T extends string, S extends z.ZodTypeAny>(type: T, data: S) => z.object({
  type: z.literal(type),
  timestamp: z.string(),
  data,
}).passthrough();

export type MainWebSocketEvent =
  | { type: 'full_state'; timestamp: string; data: DashboardStateResponse; [key: string]: unknown }
  | { type: 'graph_update'; timestamp: string; data: GraphUpdateDataDto; [key: string]: unknown }
  | { type: 'agent_console_update'; timestamp: string; data: { events: AgentConsoleEventDto[]; [key: string]: unknown }; [key: string]: unknown }
  | { type: 'action_pending'; timestamp: string; data: PendingActionDto; [key: string]: unknown }
  | { type: 'action_resolved'; timestamp: string; data: { action_id: string; status: 'approved' | 'denied' | 'timeout' | 'aborted'; resolved_at: string; operator_notes?: string; reason?: string; auto_approved?: boolean; unattended_execute?: boolean; [key: string]: unknown }; [key: string]: unknown }
  | { type: 'session_update'; timestamp: string; data: { type: 'session_created' | 'session_updated' | 'session_closed'; session: SessionDto; sessions: SessionDto[]; [key: string]: unknown }; [key: string]: unknown }
  | { type: 'agent_query'; timestamp: string; data: Record<string, unknown>; [key: string]: unknown }
  | { type: 'playbook_run_update'; timestamp: string; data: { run: PlaybookRunDto; [key: string]: unknown }; [key: string]: unknown };

export const MainWebSocketEventSchema: z.ZodType<MainWebSocketEvent> = z.discriminatedUnion('type', [
  timestampedMainEvent('full_state', DashboardStateResponseSchema),
  timestampedMainEvent('graph_update', GraphUpdateDataDtoSchema),
  timestampedMainEvent('agent_console_update', z.object({
    events: z.array(AgentConsoleEventDtoSchema),
  }).passthrough()),
  timestampedMainEvent('action_pending', PendingActionDtoSchema),
  timestampedMainEvent('action_resolved', z.object({
    action_id: z.string(),
    status: z.enum(['approved', 'denied', 'timeout', 'aborted']),
    resolved_at: z.string(),
    operator_notes: z.string().optional(),
    reason: z.string().optional(),
    auto_approved: z.boolean().optional(),
    unattended_execute: z.boolean().optional(),
  }).passthrough()),
  timestampedMainEvent('session_update', z.object({
    type: z.enum(['session_created', 'session_updated', 'session_closed']),
    session: SessionDtoSchema,
    sessions: z.array(SessionDtoSchema),
  }).passthrough()),
  timestampedMainEvent('agent_query', z.record(z.unknown())),
  timestampedMainEvent('playbook_run_update', z.object({ run: PlaybookRunSchema }).passthrough()),
]);

export const SessionWebSocketClientEventSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('input'), data: z.string() }).strict(),
  z.object({
    type: z.literal('resize'),
    cols: z.number().int().positive(),
    rows: z.number().int().positive(),
  }).strict(),
]);
export type SessionWebSocketClientEvent = z.infer<typeof SessionWebSocketClientEventSchema>;

export const SessionWebSocketServerEventSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('session_meta'), data: SessionDtoSchema }).passthrough(),
  z.object({
    type: z.literal('output'),
    text: z.string(),
    end_pos: z.number().int().nonnegative(),
  }).passthrough(),
  z.object({
    type: z.literal('session_closed'),
    connection_id: z.string().optional(),
  }).passthrough(),
  z.object({
    type: z.literal('error'),
    op: z.string().optional(),
    code: z.string().optional(),
    error: z.string(),
    recovery: RecoveryStatusDtoSchema.optional(),
  }).passthrough(),
]);
export type SessionWebSocketServerEvent = z.infer<typeof SessionWebSocketServerEventSchema>;

export const ActionOutputWebSocketEventSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('output'),
    stream: z.enum(['stdout', 'stderr']),
    text: z.string(),
    end_pos: z.number().int().nonnegative(),
    dropped: z.boolean(),
  }).passthrough(),
  z.object({ type: z.literal('action_done') }).passthrough(),
]);
export type ActionOutputWebSocketEvent = z.infer<typeof ActionOutputWebSocketEventSchema>;

export const ActionOutputStreamDtoSchema = z.object({
  evidence_id: z.string().nullable(),
  text: z.string(),
  total_bytes: z.number().int().nonnegative(),
  truncated: z.boolean(),
  head_truncated: z.boolean(),
  dropped_bytes: z.number().int().nonnegative(),
  missing: z.boolean().optional(),
  capture_failed: z.boolean().optional(),
}).passthrough();

export const ActionOutputResponseSchema = z.object({
  action_id: z.string(),
  status: z.enum(['success', 'failure', 'partial', 'neutral', 'running']),
  event_type: z.string().optional(),
  timestamp: z.string().optional(),
  tool_name: z.string().optional(),
  command_repr: z.string().optional(),
  technique: z.string().optional(),
  invoking_tool: z.string().optional(),
  exit_code: z.number().int().optional(),
  signal: z.string().optional(),
  duration_ms: z.number().nonnegative().optional(),
  timed_out: z.boolean().optional(),
  target_node_ids: z.array(z.string()).optional(),
  target_ips: z.array(z.string()).optional(),
  target_cidrs: z.array(z.string()).optional(),
  agent_id: z.string().optional(),
  frontier_item_id: z.string().optional(),
  linked_finding_ids: z.array(z.string()).optional(),
  max_bytes: z.number().int().nonnegative(),
  stdout: ActionOutputStreamDtoSchema.nullable(),
  stderr: ActionOutputStreamDtoSchema.nullable(),
  capture_error: z.unknown().optional(),
}).passthrough();
export type ActionOutputResponseDto = z.infer<typeof ActionOutputResponseSchema>;

export const EvidenceRawResponseSchema = z.object({
  evidence_id: z.string().nullable(),
  text: z.string(),
  total_bytes: z.number().int().nonnegative(),
  offset: z.number().int().nonnegative(),
  bytes_read: z.number().int().nonnegative(),
  eof: z.boolean(),
  evidence_type: z.string().optional(),
  capture_error: z.string().optional(),
  action_id: z.string().optional(),
  finding_id: z.string().optional(),
}).passthrough();
export type EvidenceRawResponseDto = z.infer<typeof EvidenceRawResponseSchema>;

export const FindingClassificationSchema = z.object({
  cwe: z.string().optional(),
  cwe_name: z.string().optional(),
  owasp_category: z.string().optional(),
  nist_controls: z.array(z.string()),
  pci_requirements: z.array(z.string()),
  attack_techniques: z.array(z.object({ id: z.string(), name: z.string() }).passthrough()),
}).passthrough();

export const FindingPresentationSchema = z.object({
  title: z.string(),
  short_title: z.string().optional(),
  summary: z.string(),
  impact: z.string(),
  evidence_claim: z.string().optional(),
  technical_context: z.string().optional(),
  remediation_steps: z.array(z.string()),
}).passthrough();

export const FindingDtoSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  category: z.string(),
  tier: z.string().optional(),
  description: z.string(),
  affected_assets: z.array(z.string()),
  evidence: z.array(z.object({}).passthrough()),
  remediation: z.string(),
  presentation: FindingPresentationSchema.optional(),
  risk_score: z.number(),
  cvss_score: z.number().optional(),
  cvss_vector: z.string().optional(),
  cvss_estimated: z.boolean().optional(),
  classification: FindingClassificationSchema.optional(),
}).passthrough();
export type FindingDto = z.infer<typeof FindingDtoSchema>;

export const FindingSeveritySummarySchema = z.object({
  critical: z.number().int().nonnegative(),
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  low: z.number().int().nonnegative(),
  info: z.number().int().nonnegative(),
}).passthrough();

export const FindingsResponseSchema = z.object({
  findings: z.array(FindingDtoSchema),
  total: z.number().int().nonnegative(),
  severity_summary: FindingSeveritySummarySchema,
}).passthrough();
export type FindingsResponseDto = z.infer<typeof FindingsResponseSchema>;

export const ReportRecordSchema = z.object({
  id: z.string(),
  generated_at: z.string(),
  format: z.enum(['markdown', 'html', 'json', 'pdf']),
  redaction_mode: z.enum(['operator', 'client_safe']),
  profile: z.enum(['operator', 'client']).optional(),
  evidence_style: z.enum(['proof_cards', 'appendix', 'full_inline']).optional(),
  findings_count: z.number().int().nonnegative().optional(),
  evidence_count: z.number().int().nonnegative().optional(),
  filename: z.string(),
  size_bytes: z.number().int().nonnegative(),
  content_sha256: Sha256Schema,
  options: z.record(z.unknown()),
}).passthrough();
export type ReportRecordDto = z.infer<typeof ReportRecordSchema>;

export const ReportsListResponseSchema = z.object({
  reports: z.array(ReportRecordSchema),
  total: z.number().int().nonnegative(),
  total_bytes: z.number().int().nonnegative(),
}).passthrough();
export type ReportsListResponseDto = z.infer<typeof ReportsListResponseSchema>;

export const ReportRenderResponseSchema = z.object({
  report: ReportRecordSchema,
  findings_count: z.number().int().nonnegative(),
  evidence_count: z.number().int().nonnegative(),
  severity_summary: FindingSeveritySummarySchema,
}).passthrough();
export type ReportRenderResponseDto = z.infer<typeof ReportRenderResponseSchema>;

export const ReparseResponseSchema = z.object({
  parsed: z.boolean(),
  parse_status: z.enum(['ok', 'no_data', 'validation_failed', 'parser_exception', 'partial', 'no_parser']),
  parse_outcome: z.enum(['ok', 'no_data', 'validation_failed', 'parser_exception', 'partial']),
  isError: z.boolean(),
  tool: z.string(),
  action_id: z.string(),
  evidence_id: z.string().nullable().optional(),
  finding_id: z.string().optional(),
  nodes_parsed: z.number().int().nonnegative(),
  edges_parsed: z.number().int().nonnegative(),
  ingested: z.union([
    z.literal(false),
    z.object({
      new_nodes: z.number().int().nonnegative(),
      new_edges: z.number().int().nonnegative(),
      inferred_edges: z.number().int().nonnegative(),
    }).passthrough(),
  ]).optional(),
  validation_errors: z.array(z.unknown()).optional(),
  warnings: z.array(z.string()).optional(),
  error: z.string().optional(),
  parser_exception: z.string().optional(),
  supported_parsers: z.array(z.string()).optional(),
  failure_stage: z.enum(['context', 'parser_selection', 'finding_validation']).optional(),
  partial: z.literal(true).optional(),
  partial_reason: z.string().optional(),
  parse_stream: z.enum(['stdout', 'stderr', 'combined']).optional(),
  parsed_from_evidence: z.boolean().optional(),
  evidence_read_error: z.string().optional(),
  exit_code: z.number().int().nullable().optional(),
}).passthrough();
export type ReparseResponseDto = z.infer<typeof ReparseResponseSchema>;

export interface DashboardWebSocketDefinition {
  operation_id: string;
  path: string;
  client_events?: z.ZodTypeAny;
  server_events: z.ZodTypeAny;
}

export const DashboardWebSocketRegistry: Readonly<Record<'main' | 'session' | 'action_output', DashboardWebSocketDefinition>> = {
  main: {
    operation_id: 'dashboardMainSocket',
    path: '/ws',
    server_events: MainWebSocketEventSchema,
  },
  session: {
    operation_id: 'dashboardSessionSocket',
    path: '/ws/session/{session_id}',
    client_events: SessionWebSocketClientEventSchema,
    server_events: SessionWebSocketServerEventSchema,
  },
  action_output: {
    operation_id: 'dashboardActionOutputSocket',
    path: '/ws/actions/{action_id}/output',
    server_events: ActionOutputWebSocketEventSchema,
  },
} as const;

export type DashboardWebSocketChannel = keyof typeof DashboardWebSocketRegistry;
export interface DashboardWebSocketPathInputs {
  main: Record<string, never>;
  session: { session_id: string };
  action_output: { action_id: string };
}

export function buildDashboardWebSocketPath<T extends DashboardWebSocketChannel>(
  channel: T,
  input: DashboardWebSocketPathInputs[T],
): string {
  const params = input as Record<string, string>;
  return DashboardWebSocketRegistry[channel].path.replace(
    /\{([^}]+)\}/g,
    (_whole, name: string) => {
      const value = params[name];
      if (!value) throw new Error(`Missing WebSocket path parameter: ${name}`);
      return encodeURIComponent(value);
    },
  );
}

export interface MatchedDashboardWebSocketPath {
  channel: DashboardWebSocketChannel;
  params: Record<string, string>;
}

export function matchDashboardWebSocketPath(pathname: string): MatchedDashboardWebSocketPath | null {
  if (pathname === DashboardWebSocketRegistry.main.path) return { channel: 'main', params: {} };
  const candidates: Array<{
    channel: Exclude<DashboardWebSocketChannel, 'main'>;
    pattern: RegExp;
    parameter: string;
  }> = [
    { channel: 'session', pattern: /^\/ws\/session\/([^/]+)$/, parameter: 'session_id' },
    { channel: 'action_output', pattern: /^\/ws\/actions\/([^/]+)\/output$/, parameter: 'action_id' },
  ];
  for (const candidate of candidates) {
    const match = candidate.pattern.exec(pathname);
    if (!match) continue;
    try {
      const value = decodeURIComponent(match[1]);
      if (!value) return null;
      return { channel: candidate.channel, params: { [candidate.parameter]: value } };
    } catch {
      return null;
    }
  }
  return null;
}
