import { z } from 'zod';
import {
  ActionOutputResponseSchema,
  ActiveApplicationCommandsResponseSchema,
  ActivityEntryDtoSchema,
  AgentArchetypesResponseSchema,
  AgentDuplicatesResponseSchema,
  AgentDtoSchema,
  AgentConsoleEventDtoSchema,
  AgentHandoffRequestSchema,
  AgentHandoffResponseSchema,
  AgentListResponseSchema,
  AgentMergeRequestSchema,
  AgentMergeResponseSchema,
  AgentQueriesResponseSchema,
  AgentSplitRequestSchema,
  AgentSplitResponseSchema,
  AgentWorkMetadataSchema,
  ApplicationCommandResponseSchema,
  CampaignActionRequestSchema,
  CampaignActionResponseSchema,
  CampaignChildrenResponseSchema,
  CampaignCloneResponseSchema,
  CampaignCreateRequestSchema,
  CampaignCreateResponseSchema,
  CampaignDeleteResponseSchema,
  CampaignDetailResponseSchema,
  CampaignDispatchRequestSchema,
  CampaignDispatchResponseSchema,
  CampaignListResponseSchema,
  CampaignSplitRequestSchema,
  CampaignSplitResponseSchema,
  CampaignUpdateRequestSchema,
  CampaignUpdateResponseSchema,
  ConfigDivergenceResolveRequestSchema,
  ConfigDivergenceResolveResponseSchema,
  DashboardErrorSchema,
  DashboardStateResponseSchema,
  DispatchAgentResponseSchema,
  DispatchBatchResponseSchema,
  EngagementConfigResponseSchema,
  EngagementConfigUpdateResponseSchema,
  EvidenceRawResponseSchema,
  FindingsResponseSchema,
  FrontierWeightsDtoSchema,
  FrontierWeightsPatchSchema,
  FrontierWeightsResetResultSchema,
  FrontierWeightsUpdateResultSchema,
  GraphCorrectionRequestSchema,
  GraphCorrectionResultSchema,
  HealthDtoSchema,
  ObjectiveCreateRequestSchema,
  ObjectiveCreateResponseSchema,
  ObjectiveDeleteResponseSchema,
  ObjectiveUpdateRequestSchema,
  ObjectiveUpdateResponseSchema,
  PendingActionDtoSchema,
  PlaybookRunListResponseSchema,
  PlaybookRunResponseSchema,
  PlaybookSkipRequestSchema,
  PlaybookStatusSchema,
  PlaybookStepClaimResponseSchema,
  ProposedPlansResponseSchema,
  QuickDeployResponseSchema,
  RawGraphDtoSchema,
  RecoveryStatusResponseSchema,
  RuntimeBuildInfoDtoSchema,
  ReportRenderResponseSchema,
  ReportsListResponseSchema,
  ReparseResponseSchema,
  SessionBufferResponseSchema,
  SessionCloseResponseSchema,
  SessionDtoSchema,
  SessionResumeResponseSchema,
  SessionUpdateResponseSchema,
  SettingsDtoSchema,
  SettingsPatchSchema,
  SettingsUpdateResultSchema,
  InterpretCommandResponseSchema,
} from './dashboard-v1.js';

export const DASHBOARD_API_COMPATIBILITY_VERSION = 1 as const;
export type DashboardHttpMethod = 'GET' | 'POST' | 'PATCH' | 'DELETE';
export type DashboardResponseKind = 'json' | 'binary';

export interface DashboardEndpointDefinition<
  TOperationId extends string = string,
  TPath extends z.ZodTypeAny = z.ZodTypeAny,
  TQuery extends z.ZodTypeAny = z.ZodTypeAny,
  TBody extends z.ZodTypeAny = z.ZodTypeAny,
  TResponses extends Readonly<Record<number, z.ZodTypeAny>> = Readonly<Record<number, z.ZodTypeAny>>,
> {
  operation_id: TOperationId;
  method: DashboardHttpMethod;
  path: string;
  path_schema: TPath;
  query_schema: TQuery;
  body_schema: TBody;
  responses: TResponses;
  response_kind: DashboardResponseKind;
  summary: string;
}

function endpoint<
  const TOperationId extends string,
  TPath extends z.ZodTypeAny,
  TQuery extends z.ZodTypeAny,
  TBody extends z.ZodTypeAny,
  const TResponses extends Readonly<Record<number, z.ZodTypeAny>>,
>(definition: DashboardEndpointDefinition<TOperationId, TPath, TQuery, TBody, TResponses>) {
  return definition;
}

const EmptyPathSchema = z.object({}).strict();
const NoBodySchema = z.undefined();
const EmptyBodySchema = z.object({}).strict();
const OkResponseSchema = z.object({ ok: z.boolean() }).passthrough();
const ReportDeleteResponseSchema = z.object({
  deleted: z.boolean(),
  cleanup_complete: z.boolean().optional(),
  commit_durability: z.enum(['confirmed', 'uncertain']).optional(),
  reference_persisted: z.boolean().optional(),
  warning: z.string().optional(),
}).passthrough();

const queryInteger = (minimum = 0) => z.preprocess(
  value => value === undefined || value === '' ? undefined : Number(value),
  z.number().int().min(minimum).optional(),
);
const queryWithToken = <T extends z.ZodRawShape>(shape: T) => z.object({
  ...shape,
  token: z.string().optional(),
}).strict();
const EmptyQuerySchema = queryWithToken({});
const PlaybookRunsQuerySchema = queryWithToken({
  credential_id: z.string().optional(),
  status: PlaybookStatusSchema.optional(),
  open_only: z.preprocess(
    value => value === undefined || value === ''
      ? undefined
      : value === 'true'
        ? true
        : value === 'false'
          ? false
          : value,
    z.boolean().optional(),
  ),
});

const idPath = (name: string) => z.object({ [name]: z.string().min(1) }).strict();

const HistoryQuerySchema = queryWithToken({
  limit: queryInteger(1),
  after: z.string().optional(),
  before: z.string().optional(),
  event_types: z.string().optional(),
  order: z.enum(['asc', 'desc']).optional(),
});
const DecisionLogQuerySchema = queryWithToken({
  limit: queryInteger(1),
  action_id: z.string().optional(),
  frontier_item_id: z.string().optional(),
  agent_id: z.string().optional(),
  outcome: z.string().optional(),
});
const TimelineQuerySchema = queryWithToken({
  limit: queryInteger(1),
  entity_id: z.string().optional(),
  kind: z.enum(['node', 'edge']).optional(),
  since: z.string().optional(),
  at: z.string().optional(),
});
const FindPathsQuerySchema = queryWithToken({
  from: z.string().optional(),
  to: z.string().optional(),
  objective: z.string().optional(),
  optimize: z.enum(['confidence', 'stealth', 'balanced']).optional(),
  max: queryInteger(1),
});
const ConsoleQuerySchema = queryWithToken({
  limit: queryInteger(1),
  after: z.string().optional(),
});
const SessionBufferQuerySchema = queryWithToken({
  from: queryInteger(0),
  tail_bytes: queryInteger(0),
  connection_id: z.string().optional(),
  connection_generation: queryInteger(0),
});
const ActionOutputQuerySchema = queryWithToken({ max_bytes: queryInteger(1) });
const EvidenceRawQuerySchema = queryWithToken({
  max_bytes: queryInteger(1),
  offset: queryInteger(0),
});
const PathsQuerySchema = queryWithToken({
  limit: queryInteger(1),
  optimize: z.enum(['confidence', 'stealth', 'balanced']).optional(),
});
const TrustSignalsQuerySchema = queryWithToken({
  limit: queryInteger(1),
  node_id: z.string().optional(),
  finding_id: z.string().optional(),
  severity: z.enum(['error', 'warning', 'info']).optional(),
});
const ReportDownloadQuerySchema = queryWithToken({
  disposition: z.enum(['inline', 'attachment']).optional(),
});

const SessionListResponseSchema = z.object({
  sessions: z.array(SessionDtoSchema),
  total: z.number().int().nonnegative(),
  active: z.number().int().nonnegative(),
}).passthrough();
const HistoryResponseSchema = z.object({
  entries: z.array(ActivityEntryDtoSchema),
  total: z.number().int().nonnegative(),
  order: z.string().optional(),
}).passthrough();
const ConsoleResponseSchema = z.object({
  events: z.array(AgentConsoleEventDtoSchema),
  total: z.number().int().nonnegative(),
}).passthrough();
const PendingActionsResponseSchema = z.object({
  pending: z.array(PendingActionDtoSchema),
  recent: z.array(PendingActionDtoSchema).optional(),
  diagnostics: z.object({}).passthrough().optional(),
}).passthrough();

const DecisionLogResponseSchema = z.object({
  decisions: z.array(z.object({
    decision_id: z.string(),
    opened_at: z.string(),
    closed_at: z.string(),
    stages: z.array(z.object({}).passthrough()),
  }).passthrough()),
  total: z.number().int().nonnegative(),
}).passthrough();
const TimelineResponseSchema = z.object({
  entries: z.array(z.object({
    entity_id: z.string(),
    kind: z.enum(['node', 'edge']),
    became_true_at: z.string(),
    evidence_refs: z.array(z.string()),
  }).passthrough()),
  total: z.number().int().nonnegative(),
}).passthrough();
const ActionExplanationResponseSchema = z.object({
  action_id: z.string(),
  found: z.boolean(),
  log_thought_chain: z.array(z.object({}).passthrough()),
  considered_alternatives: z.array(z.string()),
  prior_actions_referenced: z.array(z.string()),
}).passthrough();
const AttackPathSchema = z.object({
  nodes: z.array(z.union([z.string(), z.object({
    id: z.string(),
    label: z.string().optional(),
    type: z.string().optional(),
    edge_type: z.string().optional(),
  }).passthrough()])),
}).passthrough();
const FindPathsResponseSchema = z.object({
  paths: z.array(AttackPathSchema),
  analysis_status: z.enum(['found', 'no_path', 'missing_endpoint', 'analysis_failed']),
  warnings: z.array(z.string()),
  count: z.number().int().nonnegative(),
}).passthrough();
const ObjectivePathsResponseSchema = z.object({
  objective_id: z.string(),
  paths: z.array(AttackPathSchema),
  count: z.number().int().nonnegative(),
}).passthrough();
const FleetDirectiveResponseSchema = z.object({
  ok: z.boolean(),
  applied: z.number().int().nonnegative(),
  total: z.number().int().nonnegative(),
}).passthrough();
const FleetDismissResponseSchema = z.object({
  ok: z.boolean(),
  dismissed: z.number().int().nonnegative(),
  total: z.number().int().nonnegative(),
}).passthrough();
const BatchResolutionResponseSchema = z.object({
  ok: z.boolean(),
  resolved: z.number().int().nonnegative(),
  total: z.number().int().nonnegative(),
}).passthrough();
const AnswerBatchResponseSchema = z.object({
  ok: z.boolean(),
  answered: z.number().int().nonnegative(),
}).passthrough();
const AgentContextResponseSchema = z.object({
  // The server now emits AgentDto. Keep the historical context shape readable
  // while rolling upgrades can still pair a new dashboard with an old daemon.
  task: z.union([
    AgentDtoSchema.extend({ work: AgentWorkMetadataSchema }),
    z.object({
      id: z.string(),
      agent_id: z.string(),
      // A payload that claims canonical identity must satisfy AgentDto above;
      // this branch is only for the pre-canonical compatibility envelope.
      task_id: z.never().optional(),
      agent_label: z.never().optional(),
      work: z.never().optional(),
    }).passthrough(),
  ]),
  subgraph: z.object({ nodes: z.array(z.unknown()), edges: z.array(z.unknown()) }).passthrough(),
}).passthrough();
const AgentDismissResponseSchema = z.object({
  dismissed: z.boolean(),
  task_id: z.string(),
  forced: z.boolean().optional(),
}).passthrough();
const AgentDirectiveResponseSchema = z.object({
  ok: z.boolean(),
  results: z.array(z.unknown()),
}).passthrough();
const ScopeSummarySchema = z.object({
  cidrs: z.array(z.string()),
  domains: z.array(z.string()),
  exclusions: z.array(z.string()),
}).passthrough();
const ScopePreviewResponseSchema = z.object({
  before: ScopeSummarySchema,
  after: ScopeSummarySchema,
  nodes_entering_scope: z.number().int().nonnegative(),
  nodes_leaving_scope: z.number().int().nonnegative(),
  pending_suggestions_resolved: z.array(z.string()),
  added: ScopeSummarySchema,
  removed: ScopeSummarySchema,
}).passthrough();
const ScopeUpdateResponseSchema = z.object({
  updated: z.boolean(),
  scope: ScopeSummarySchema,
  applied: z.boolean().optional(),
  affected_node_count: z.number().int().nonnegative().optional(),
}).passthrough();
const OpsecBudgetResponseSchema = z.object({
  global_noise_spent: z.number(),
  noise_budget_remaining: z.number(),
  max_noise: z.number(),
  recommended_approach: z.enum(['quiet', 'normal', 'loud']),
  defensive_signals: z.array(z.object({
    type: z.string(),
    detected_at: z.string(),
    description: z.string(),
  }).passthrough()),
  time_window_remaining_hours: z.number().optional(),
  warning: z.string().optional(),
}).passthrough();
const EngagementListItemSchema = z.object({
  id: z.string(),
  name: z.string(),
  scope_cidrs: z.array(z.string()),
  scope_domains: z.array(z.string()),
  objectives_count: z.number().int().nonnegative(),
  phases_count: z.number().int().nonnegative(),
}).passthrough();
const EngagementListResponseSchema = z.object({
  engagements: z.array(EngagementListItemSchema),
  active_id: z.string().nullable().optional(),
}).passthrough();
const EngagementTemplateSchema = z.object({
  id: z.string(),
  name: z.string(),
}).passthrough();
const EngagementTemplatesResponseSchema = z.object({
  templates: z.array(EngagementTemplateSchema),
  total: z.number().int().nonnegative(),
}).passthrough();
const EngagementFromTemplateResponseSchema = z.object({
  config: z.object({}).passthrough(),
  persisted: z.boolean(),
  engagement: EngagementListItemSchema.optional(),
}).passthrough();
const EngagementUpdateResponseSchema = z.object({ updated: z.boolean() }).passthrough();
const PhasesResponseSchema = z.object({
  phases: z.array(z.object({}).passthrough()),
  current_phase: z.unknown().optional(),
}).passthrough();
const ToolsResponseSchema = z.object({
  installed_count: z.number().int().nonnegative(),
  missing_count: z.number().int().nonnegative(),
  tools: z.array(z.object({
    name: z.string(),
    installed: z.boolean(),
  }).passthrough()),
}).passthrough();
const McpToolsResponseSchema = z.object({
  total: z.number().int().nonnegative(),
  registry_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  categories: z.record(z.number().int().nonnegative()),
  tools: z.array(z.object({
    name: z.string(),
    title: z.string().optional(),
    description: z.string(),
    category: z.string(),
    category_label: z.string(),
    category_order: z.number().int().nonnegative(),
    read_only: z.boolean(),
    destructive: z.boolean(),
    idempotent: z.boolean(),
    open_world: z.boolean(),
    input_schema_sha256: z.string().regex(/^[a-f0-9]{64}$/),
    output_schema_sha256: z.string().regex(/^[a-f0-9]{64}$/).nullable(),
    documentation: z.object({
      path: z.string(),
      purpose: z.string(),
    }).passthrough(),
    archetype_exposure: z.array(z.string()),
    persistence: z.object({
      mode: z.enum(['read', 'write', 'conditional']),
      allowed_during_recovery: z.boolean(),
    }).passthrough(),
  }).passthrough()),
}).passthrough();
const ReadinessResponseSchema = z.object({
  status: z.enum(['ready', 'warning', 'critical']),
  generated_at: z.string(),
  graph: z.object({}).passthrough(),
  api: z.object({}).passthrough(),
  tape: z.object({}).passthrough(),
  sessions: z.object({}).passthrough(),
  actions: z.object({}).passthrough(),
  agents: z.object({}).passthrough(),
  persistence: z.object({}).passthrough(),
  issues: z.array(z.string()),
}).passthrough();
const TrustSignalsResponseSchema = z.object({
  generated_at: z.string(),
  total: z.number().int().nonnegative(),
  counts: z.object({ error: z.number(), warning: z.number(), info: z.number() }).passthrough(),
  signals: z.array(z.object({}).passthrough()),
}).passthrough();
const InferenceRulesResponseSchema = z.object({
  rules: z.array(z.object({}).passthrough()),
  total: z.number().int().nonnegative(),
}).passthrough();
const TelemetryResponseSchema = z.object({
  tool_telemetry: z.unknown().nullable(),
  inference_effectiveness: z.array(z.unknown()),
  health: z.object({}).passthrough(),
  graph_stats: z.object({}).passthrough(),
  credential_coverage: z.unknown().nullable(),
}).passthrough();
const TapeStatusResponseSchema = z.object({
  enabled: z.boolean(),
  path: z.string().optional(),
  session_id: z.string().optional(),
  frame_count: z.number().int().nonnegative(),
  accepted_frame_count: z.number().int().nonnegative().optional(),
  dropped_frame_count: z.number().int().nonnegative().optional(),
  started_at: z.string().optional(),
  started_by: z.enum(['env', 'config', 'dashboard']).optional(),
  error: z.string().optional(),
}).passthrough();
const EvidenceChainsResponseSchema = z.object({
  node_id: z.string(),
  chains: z.array(z.object({
    activity_id: z.string(),
    timestamp: z.string(),
    event_type: z.string(),
    description: z.string(),
  }).passthrough()),
  count: z.number().int().nonnegative(),
}).passthrough();
const FindingContextResponseSchema = z.object({
  finding: z.object({}).passthrough(),
  affected_nodes: z.array(z.object({}).passthrough()),
  evidence_chains: z.array(EvidenceChainsResponseSchema),
  sessions: z.array(SessionDtoSchema),
  pending_actions: z.array(PendingActionDtoSchema),
  frontier: z.array(z.object({}).passthrough()),
  path_impacts: z.array(z.object({}).passthrough()),
  report_ready: z.boolean(),
}).passthrough();
const ActionResolutionResponseSchema = z.object({
  action_id: z.string(),
  status: z.enum(['approved', 'denied', 'timeout', 'aborted']),
}).passthrough();

const DirectiveBodySchema = z.object({
  kind: z.enum(['pause', 'resume', 'stop', 'narrow_scope', 'skip_types', 'prioritize', 'instruct']),
  node_ids: z.array(z.string()).optional(),
  frontier_types: z.array(z.string()).optional(),
  note: z.string().optional(),
}).strict();
const FleetDirectiveBodySchema = z.object({
  kind: z.enum(['pause', 'resume', 'stop', 'instruct']),
  note: z.string().optional(),
  campaign_id: z.string().optional(),
}).strict();
const DispatchBodySchema = z.object({
  target_node_ids: z.array(z.string()).optional(),
  skill: z.string().optional(),
  campaign_id: z.string().optional(),
  frontier_item_id: z.string().optional(),
  archetype: z.string().optional(),
  model: z.string().optional(),
}).strict();
const DispatchBatchBodySchema = z.object({
  target_node_ids: z.array(z.string()).min(1),
  mode: z.enum(['per-node', 'per-batch']).optional(),
  batch_size: z.number().int().positive().optional(),
  archetype: z.string().optional(),
  skill: z.string().optional(),
  model: z.string().optional(),
  objective: z.string().optional(),
}).strict();
const QuickDeployBodySchema = z.object({
  target: z.string().min(1),
  archetype: z.string().optional(),
  model: z.string().optional(),
}).strict();
const CommandBodySchema = z.union([
  z.object({ command: z.string().min(1) }).strict(),
  z.object({ confirm: z.literal(true), plan_id: z.string().min(1) }).strict(),
  z.object({ deny: z.literal(true), plan_id: z.string().min(1) }).strict(),
]);
const ApprovalBatchBodySchema = z.object({
  action_ids: z.array(z.string().min(1)).min(1),
  notes: z.string().optional(),
}).strict();
const DenialBatchBodySchema = z.object({
  action_ids: z.array(z.string().min(1)).min(1),
  reason: z.string().min(1),
}).strict();
const ScopeBodySchema = z.object({
  cidrs: z.array(z.string()).optional(),
  domains: z.array(z.string()).optional(),
  exclusions: z.array(z.string()).optional(),
  hosts: z.array(z.string()).optional(),
  url_patterns: z.array(z.string()).optional(),
  aws_accounts: z.array(z.string()).optional(),
  azure_subscriptions: z.array(z.string()).optional(),
  gcp_projects: z.array(z.string()).optional(),
  cross_tier_links: z.array(z.object({
    url_pattern: z.string().optional(),
    aws_account: z.string().optional(),
    azure_subscription: z.string().optional(),
    gcp_project: z.string().optional(),
    cloud_resource_prefix: z.string().optional(),
    idp_kind: z.string().optional(),
    tenant_id: z.string().optional(),
    notes: z.string().optional(),
  }).strict()).optional(),
}).strict();
const OpsecUpdateBodySchema = z.object({
  name: z.string().min(1).optional(),
  enabled: z.boolean().optional(),
  max_noise: z.number().min(0).max(1).optional(),
  approval_mode: z.enum(['auto-approve', 'approve-critical', 'approve-all']).optional(),
  approval_timeout_ms: z.number().int().min(1_000).optional(),
  time_window: z.object({
    start_hour: z.number().int().min(0).max(23),
    end_hour: z.number().int().min(0).max(23),
  }).strict().nullable().optional(),
  blacklisted_techniques: z.array(z.string()).optional(),
  notes: z.string().optional(),
}).strict();
const ObjectiveMutationBodySchema = z.object({
  id: z.string().min(1),
  description: z.string().min(1),
  target_node_type: z.string().optional(),
  target_criteria: z.record(z.unknown()).optional(),
  achievement_edge_types: z.array(z.string()).optional(),
  achieved: z.boolean().optional(),
  achieved_at: z.string().optional(),
}).strict();
const FailurePatternBodySchema = z.object({
  technique: z.string(),
  target_pattern: z.string().optional(),
  warning: z.string(),
}).strict();
const OperatorPolicyBodySchema = z.object({
  version: z.literal(1),
  approval_rules: z.array(z.object({
    match: z.object({
      host_class: z.enum(['in_scope', 'unverified', 'excluded']).optional(),
      network: z.string().optional(),
      technique: z.string().optional(),
    }).strict(),
    require: z.enum(['auto-approve', 'approve-critical', 'approve-all']),
  }).strict()).optional(),
  dispatch_limits: z.object({
    max_per_subnet: z.number().int().positive().optional(),
    max_per_target: z.number().int().positive().optional(),
    target_facing_archetypes: z.array(z.string()).optional(),
  }).strict().optional(),
}).strict();
const EngagementUpdateBodySchema = z.object({
  name: z.string().min(1).optional(),
  profile: z.enum(['goad_ad', 'single_host', 'network', 'web_app', 'cloud', 'hybrid']).optional(),
  community_resolution: z.number().min(0.1).max(10).optional(),
  max_prompt_tokens: z.number().int().min(1_000).max(100_000).optional(),
  iam_assume_depth: z.number().int().min(0).max(20).optional(),
  hash_chain_enabled: z.boolean().optional(),
  engagement_signing_key_id: z.string().nullable().optional(),
  subagent_isolation: z.enum(['in_process', 'process']).optional(),
  available_models: z.array(z.string()).optional(),
  default_agent_model: z.string().nullable().optional(),
  orchestrator: z.object({ enabled: z.boolean().optional() }).strict().nullable().optional(),
  cve_research: z.object({ enabled: z.boolean().optional() }).strict().nullable().optional(),
  postgres_dsn: z.string().nullable().optional(),
  tape: z.object({
    enabled: z.boolean().optional(),
    dir: z.string().optional(),
    file: z.string().optional(),
  }).strict().nullable().optional(),
  scope: ScopeBodySchema.optional(),
  opsec: OpsecUpdateBodySchema.optional(),
  failure_patterns: z.array(FailurePatternBodySchema).optional(),
  objectives: z.array(ObjectiveMutationBodySchema).optional(),
  phases: z.array(z.unknown()).optional(),
  operator_policy: OperatorPolicyBodySchema.nullable().optional(),
}).strict().refine(value => Object.keys(value).length > 0, {
  message: 'At least one supported engagement field is required',
});
const CreateEngagementBodySchema = z.object({
  name: z.string().min(1),
  profile: z.enum(['goad_ad', 'single_host', 'network', 'web_app', 'cloud', 'hybrid']).optional(),
  cidrs: z.array(z.string()).optional(),
  domains: z.array(z.string()).optional(),
  exclusions: z.array(z.string()).optional(),
  hosts: z.array(z.string()).optional(),
  url_patterns: z.array(z.string()).optional(),
  aws_accounts: z.array(z.string()).optional(),
  azure_subscriptions: z.array(z.string()).optional(),
  gcp_projects: z.array(z.string()).optional(),
  opsec_profile: z.string().optional(),
  opsec: OpsecUpdateBodySchema.optional(),
  objectives: z.array(ObjectiveMutationBodySchema).optional(),
  failure_patterns: z.array(FailurePatternBodySchema).optional(),
  phases: z.array(z.unknown()).optional(),
  template_id: z.string().optional(),
}).strict();
const ReparseBodySchema = z.object({
  tool_name: z.string().min(1),
  evidence_id: z.string().optional(),
  ingest: z.boolean().optional(),
  context: z.record(z.unknown()).optional(),
}).strict();
const ReportRenderBodySchema = z.object({
  format: z.enum(['md', 'markdown', 'html', 'json', 'pdf']).optional(),
  include_evidence: z.boolean().optional(),
  include_narrative: z.boolean().optional(),
  include_retrospective: z.boolean().optional(),
  include_compliance: z.boolean().optional(),
  include_attack_paths: z.boolean().optional(),
  include_attack_navigator: z.boolean().optional(),
  include_gap_analysis: z.boolean().optional(),
  client_safe: z.boolean().optional(),
  profile: z.enum(['operator', 'client']).optional(),
  evidence_style: z.enum(['proof_cards', 'appendix', 'full_inline']).optional(),
  theme: z.enum(['light', 'dark']).optional(),
  max_paths_per_objective: z.number().int().positive().optional(),
}).strict();

/**
 * Authoritative compatibility-v1 HTTP registry. Both the Node adapter and the
 * generated browser client consume this object; route names and envelopes must
 * therefore change here first.
 */
export const DASHBOARD_OPERATION_IDS = [
  'getRecovery', 'resolveConfigDivergence', 'getState', 'getGraph',
  'getHistory', 'getDecisionLog', 'getTimeline', 'findPaths', 'getSessions',
  'getAgents', 'getAgentDuplicates', 'handoffAgent', 'splitAgent', 'mergeAgent',
  'dispatchAgent', 'dispatchAgentBatch', 'quickDeployAgent',
  'getAgentArchetypes', 'issueFleetDirective', 'dismissFleetAgents',
  'approveActionsBatch', 'denyActionsBatch', 'interpretCommand',
  'getProposedPlans', 'getAgentQueries', 'answerAgentQueriesBatch',
  'getTemplates', 'getSettings', 'updateSettings', 'getConfig', 'updateConfig',
  'previewScope', 'updateScope', 'createObjective', 'getFrontierWeights',
  'updateFrontierWeights', 'resetFrontierWeights', 'getOpsecBudget', 'getHealth', 'getRuntime',
  'listEngagements', 'createEngagement', 'createEngagementFromTemplate',
  'createCampaign', 'listCampaigns', 'getPhases', 'getPendingActions', 'getTools',
  'getParsers', 'getMcpTools', 'getReadiness', 'getTrustSignals',
  'getInferenceRules', 'getTelemetry', 'exportGraph', 'correctGraph',
  'getTapeStatus', 'toggleTape', 'getFindings', 'listReports', 'renderReport',
  'bundleEngagement', 'getOperatorConsole', 'getActiveApplicationCommands', 'getApplicationCommand',
  'getAgentContext', 'getAgentHistory', 'getAgentConsole', 'cancelAgent',
  'dismissAgent', 'issueAgentDirective', 'answerAgentQuery', 'updateObjective',
  'deleteObjective', 'getCampaign', 'updateCampaign', 'deleteCampaign',
  'actOnCampaign', 'dispatchCampaign', 'cloneCampaign', 'splitCampaign',
  'getCampaignChildren', 'explainAction', 'getActionOutput', 'reparseAction',
  'getEvidenceRaw', 'getEvidenceImage', 'approveAction', 'denyAction',
  'closeSession', 'resumeSession', 'getSessionBuffer', 'updateSession',
  'getEvidenceChains', 'getObjectivePaths', 'getFindingContext',
  'downloadReport', 'deleteReport', 'getEngagement', 'updateEngagement',
  'listPlaybookRuns', 'getPlaybookRun', 'startPlaybookStep',
  'resumePlaybookRun', 'retryPlaybookStep', 'skipPlaybookStep', 'interruptPlaybookAttempt',
] as const;
export type DashboardOperationId = (typeof DASHBOARD_OPERATION_IDS)[number];

const DASHBOARD_BOUNDARY_EXEMPT_WRITE_OPERATIONS = new Set<DashboardOperationId>([
  'previewScope',
  'exportGraph',
]);

/**
 * Whether an endpoint invocation crosses the dashboard's durable mutation
 * boundary. HTTP method alone is deliberately insufficient: two POST-shaped
 * compatibility operations are pure previews/exports. Keeping this next to
 * the canonical registry makes new mutation routes fail the architecture
 * audit unless their semantics are consciously classified.
 */
export function dashboardEndpointMutatesDurableState(
  endpoint: DashboardEndpointDefinition,
): boolean {
  if (endpoint.method === 'GET') return false;
  return !DASHBOARD_BOUNDARY_EXEMPT_WRITE_OPERATIONS.has(
    endpoint.operation_id as DashboardOperationId,
  );
}

const dashboardCoreEndpoints = {
  getRecovery: endpoint({ operation_id: 'getRecovery', method: 'GET', path: '/api/recovery', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: RecoveryStatusResponseSchema }, response_kind: 'json', summary: 'Read persistence and configuration recovery status' }),
  resolveConfigDivergence: endpoint({ operation_id: 'resolveConfigDivergence', method: 'POST', path: '/api/recovery/config/resolve', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: ConfigDivergenceResolveRequestSchema, responses: { 200: ConfigDivergenceResolveResponseSchema }, response_kind: 'json', summary: 'Resolve configuration divergence' }),
  getState: endpoint({ operation_id: 'getState', method: 'GET', path: '/api/state', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: DashboardStateResponseSchema }, response_kind: 'json', summary: 'Read the authoritative dashboard snapshot' }),
  getGraph: endpoint({ operation_id: 'getGraph', method: 'GET', path: '/api/graph', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: RawGraphDtoSchema }, response_kind: 'json', summary: 'Read the raw graph' }),
  getHistory: endpoint({ operation_id: 'getHistory', method: 'GET', path: '/api/history', path_schema: EmptyPathSchema, query_schema: HistoryQuerySchema, body_schema: NoBodySchema, responses: { 200: HistoryResponseSchema }, response_kind: 'json', summary: 'Read activity history' }),
  getDecisionLog: endpoint({ operation_id: 'getDecisionLog', method: 'GET', path: '/api/decision-log', path_schema: EmptyPathSchema, query_schema: DecisionLogQuerySchema, body_schema: NoBodySchema, responses: { 200: DecisionLogResponseSchema }, response_kind: 'json', summary: 'Read decision traces' }),
  getTimeline: endpoint({ operation_id: 'getTimeline', method: 'GET', path: '/api/timeline', path_schema: EmptyPathSchema, query_schema: TimelineQuerySchema, body_schema: NoBodySchema, responses: { 200: TimelineResponseSchema }, response_kind: 'json', summary: 'Read entity timeline entries' }),
  findPaths: endpoint({ operation_id: 'findPaths', method: 'GET', path: '/api/find-paths', path_schema: EmptyPathSchema, query_schema: FindPathsQuerySchema, body_schema: NoBodySchema, responses: { 200: FindPathsResponseSchema }, response_kind: 'json', summary: 'Find graph paths' }),
  getSessions: endpoint({ operation_id: 'getSessions', method: 'GET', path: '/api/sessions', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: SessionListResponseSchema }, response_kind: 'json', summary: 'List sessions' }),
} as const;

const dashboardAgentCommandEndpoints = {
  getAgents: endpoint({ operation_id: 'getAgents', method: 'GET', path: '/api/agents', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: AgentListResponseSchema }, response_kind: 'json', summary: 'List projected agents' }),
  getAgentDuplicates: endpoint({ operation_id: 'getAgentDuplicates', method: 'GET', path: '/api/agents/duplicates', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: AgentDuplicatesResponseSchema }, response_kind: 'json', summary: 'List exact duplicate agent work groups' }),
  handoffAgent: endpoint({ operation_id: 'handoffAgent', method: 'POST', path: '/api/agents/{task_id}/handoff', path_schema: idPath('task_id'), query_schema: EmptyQuerySchema, body_schema: AgentHandoffRequestSchema, responses: { 200: AgentHandoffResponseSchema, 400: DashboardErrorSchema, 403: DashboardErrorSchema, 404: DashboardErrorSchema, 409: DashboardErrorSchema, 429: DashboardErrorSchema, 503: DashboardErrorSchema }, response_kind: 'json', summary: 'Hand terminal agent work to one successor' }),
  splitAgent: endpoint({ operation_id: 'splitAgent', method: 'POST', path: '/api/agents/{task_id}/split', path_schema: idPath('task_id'), query_schema: EmptyQuerySchema, body_schema: AgentSplitRequestSchema, responses: { 200: AgentSplitResponseSchema, 400: DashboardErrorSchema, 403: DashboardErrorSchema, 404: DashboardErrorSchema, 409: DashboardErrorSchema, 429: DashboardErrorSchema, 503: DashboardErrorSchema }, response_kind: 'json', summary: 'Split terminal node-scoped agent work into child tasks' }),
  mergeAgent: endpoint({ operation_id: 'mergeAgent', method: 'POST', path: '/api/agents/{task_id}/merge', path_schema: idPath('task_id'), query_schema: EmptyQuerySchema, body_schema: AgentMergeRequestSchema, responses: { 200: AgentMergeResponseSchema, 400: DashboardErrorSchema, 403: DashboardErrorSchema, 404: DashboardErrorSchema, 409: DashboardErrorSchema, 503: DashboardErrorSchema }, response_kind: 'json', summary: 'Merge terminal duplicate work into the canonical task' }),
  dispatchAgent: endpoint({ operation_id: 'dispatchAgent', method: 'POST', path: '/api/agents/dispatch', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: DispatchBodySchema, responses: { 201: DispatchAgentResponseSchema, 409: DispatchAgentResponseSchema, 429: DispatchAgentResponseSchema }, response_kind: 'json', summary: 'Dispatch one agent' }),
  dispatchAgentBatch: endpoint({ operation_id: 'dispatchAgentBatch', method: 'POST', path: '/api/agents/dispatch-batch', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: DispatchBatchBodySchema, responses: { 200: DispatchBatchResponseSchema }, response_kind: 'json', summary: 'Dispatch a batch of agents' }),
  quickDeployAgent: endpoint({ operation_id: 'quickDeployAgent', method: 'POST', path: '/api/agents/quick-deploy', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: QuickDeployBodySchema, responses: { 201: QuickDeployResponseSchema, 409: QuickDeployResponseSchema, 429: QuickDeployResponseSchema }, response_kind: 'json', summary: 'Scope a raw target and dispatch an agent' }),
  getAgentArchetypes: endpoint({ operation_id: 'getAgentArchetypes', method: 'GET', path: '/api/agent-archetypes', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: AgentArchetypesResponseSchema }, response_kind: 'json', summary: 'List agent archetypes and models' }),
  issueFleetDirective: endpoint({ operation_id: 'issueFleetDirective', method: 'POST', path: '/api/fleet/directive', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: FleetDirectiveBodySchema, responses: { 200: FleetDirectiveResponseSchema }, response_kind: 'json', summary: 'Steer the running fleet' }),
  dismissFleetAgents: endpoint({ operation_id: 'dismissFleetAgents', method: 'POST', path: '/api/fleet/dismiss', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: z.object({ campaign_id: z.string().optional() }).strict(), responses: { 200: FleetDismissResponseSchema }, response_kind: 'json', summary: 'Dismiss terminal agents' }),
  approveActionsBatch: endpoint({ operation_id: 'approveActionsBatch', method: 'POST', path: '/api/actions/approve-batch', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: ApprovalBatchBodySchema, responses: { 200: BatchResolutionResponseSchema }, response_kind: 'json', summary: 'Approve pending actions in bulk' }),
  denyActionsBatch: endpoint({ operation_id: 'denyActionsBatch', method: 'POST', path: '/api/actions/deny-batch', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: DenialBatchBodySchema, responses: { 200: BatchResolutionResponseSchema }, response_kind: 'json', summary: 'Deny pending actions in bulk' }),
  interpretCommand: endpoint({ operation_id: 'interpretCommand', method: 'POST', path: '/api/commands', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: CommandBodySchema, responses: { 200: InterpretCommandResponseSchema }, response_kind: 'json', summary: 'Preview, confirm, or deny an operator command' }),
  getActiveApplicationCommands: endpoint({ operation_id: 'getActiveApplicationCommands', method: 'GET', path: '/api/commands/active', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: ActiveApplicationCommandsResponseSchema }, response_kind: 'json', summary: 'List active durable planner commands' }),
  getProposedPlans: endpoint({ operation_id: 'getProposedPlans', method: 'GET', path: '/api/plans', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: ProposedPlansResponseSchema }, response_kind: 'json', summary: 'List open proposed plans' }),
  getAgentQueries: endpoint({ operation_id: 'getAgentQueries', method: 'GET', path: '/api/agent-queries', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: AgentQueriesResponseSchema }, response_kind: 'json', summary: 'List operator questions from agents' }),
} as const;

const PlaybookStepPathSchema = z.object({
  run_id: z.string().min(1),
  step_id: z.string().min(1),
}).strict();

const dashboardPlaybookEndpoints = {
  listPlaybookRuns: endpoint({ operation_id: 'listPlaybookRuns', method: 'GET', path: '/api/playbook-runs', path_schema: EmptyPathSchema, query_schema: PlaybookRunsQuerySchema, body_schema: NoBodySchema, responses: { 200: PlaybookRunListResponseSchema }, response_kind: 'json', summary: 'List durable credential playbook runs' }),
  getPlaybookRun: endpoint({ operation_id: 'getPlaybookRun', method: 'GET', path: '/api/playbook-runs/{run_id}', path_schema: idPath('run_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: PlaybookRunResponseSchema, 404: DashboardErrorSchema }, response_kind: 'json', summary: 'Read one durable credential playbook run' }),
} as const;

const dashboardPlaybookLifecycleEndpoints = {
  startPlaybookStep: endpoint({ operation_id: 'startPlaybookStep', method: 'POST', path: '/api/playbook-runs/{run_id}/steps/{step_id}/start', path_schema: PlaybookStepPathSchema, query_schema: EmptyQuerySchema, body_schema: z.union([NoBodySchema, EmptyBodySchema]), responses: { 200: PlaybookStepClaimResponseSchema, 400: DashboardErrorSchema, 404: DashboardErrorSchema, 409: DashboardErrorSchema, 503: DashboardErrorSchema }, response_kind: 'json', summary: 'Claim one ready playbook step' }),
  resumePlaybookRun: endpoint({ operation_id: 'resumePlaybookRun', method: 'POST', path: '/api/playbook-runs/{run_id}/resume', path_schema: idPath('run_id'), query_schema: EmptyQuerySchema, body_schema: z.union([NoBodySchema, EmptyBodySchema]), responses: { 200: PlaybookRunResponseSchema, 400: DashboardErrorSchema, 404: DashboardErrorSchema, 409: DashboardErrorSchema, 503: DashboardErrorSchema }, response_kind: 'json', summary: 'Resume an interrupted playbook run' }),
  retryPlaybookStep: endpoint({ operation_id: 'retryPlaybookStep', method: 'POST', path: '/api/playbook-runs/{run_id}/steps/{step_id}/retry', path_schema: PlaybookStepPathSchema, query_schema: EmptyQuerySchema, body_schema: z.union([NoBodySchema, EmptyBodySchema]), responses: { 200: PlaybookStepClaimResponseSchema, 400: DashboardErrorSchema, 404: DashboardErrorSchema, 409: DashboardErrorSchema, 503: DashboardErrorSchema }, response_kind: 'json', summary: 'Append a retry attempt for a playbook step' }),
  skipPlaybookStep: endpoint({ operation_id: 'skipPlaybookStep', method: 'POST', path: '/api/playbook-runs/{run_id}/steps/{step_id}/skip', path_schema: PlaybookStepPathSchema, query_schema: EmptyQuerySchema, body_schema: PlaybookSkipRequestSchema, responses: { 200: PlaybookRunResponseSchema, 400: DashboardErrorSchema, 404: DashboardErrorSchema, 409: DashboardErrorSchema, 503: DashboardErrorSchema }, response_kind: 'json', summary: 'Skip a playbook step' }),
  interruptPlaybookAttempt: endpoint({ operation_id: 'interruptPlaybookAttempt', method: 'POST', path: '/api/playbook-runs/{run_id}/steps/{step_id}/interrupt', path_schema: PlaybookStepPathSchema, query_schema: EmptyQuerySchema, body_schema: PlaybookSkipRequestSchema, responses: { 200: PlaybookRunResponseSchema, 400: DashboardErrorSchema, 404: DashboardErrorSchema, 409: DashboardErrorSchema, 503: DashboardErrorSchema }, response_kind: 'json', summary: 'Release an active playbook attempt as interrupted' }),
} as const;

const dashboardConfigEndpoints = {
  answerAgentQueriesBatch: endpoint({ operation_id: 'answerAgentQueriesBatch', method: 'POST', path: '/api/agent-queries/answer-batch', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: z.object({ query_ids: z.array(z.string()).min(1), answer: z.string().min(1) }).strict(), responses: { 200: AnswerBatchResponseSchema }, response_kind: 'json', summary: 'Answer multiple agent questions' }),
  getTemplates: endpoint({ operation_id: 'getTemplates', method: 'GET', path: '/api/templates', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: EngagementTemplatesResponseSchema }, response_kind: 'json', summary: 'List engagement templates' }),
  getSettings: endpoint({ operation_id: 'getSettings', method: 'GET', path: '/api/settings', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: SettingsDtoSchema }, response_kind: 'json', summary: 'Read dashboard settings' }),
  updateSettings: endpoint({ operation_id: 'updateSettings', method: 'PATCH', path: '/api/settings', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: SettingsPatchSchema, responses: { 200: SettingsUpdateResultSchema }, response_kind: 'json', summary: 'Update dashboard settings' }),
  getConfig: endpoint({ operation_id: 'getConfig', method: 'GET', path: '/api/config', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: EngagementConfigResponseSchema }, response_kind: 'json', summary: 'Read active engagement configuration' }),
  updateConfig: endpoint({ operation_id: 'updateConfig', method: 'PATCH', path: '/api/config', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: EngagementUpdateBodySchema, responses: { 200: EngagementConfigUpdateResponseSchema }, response_kind: 'json', summary: 'Update active engagement configuration' }),
  previewScope: endpoint({ operation_id: 'previewScope', method: 'POST', path: '/api/config/scope/preview', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: ScopeBodySchema, responses: { 200: ScopePreviewResponseSchema }, response_kind: 'json', summary: 'Preview a scope replacement' }),
  updateScope: endpoint({ operation_id: 'updateScope', method: 'PATCH', path: '/api/config/scope', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: ScopeBodySchema, responses: { 200: ScopeUpdateResponseSchema }, response_kind: 'json', summary: 'Replace engagement scope' }),
  createObjective: endpoint({ operation_id: 'createObjective', method: 'POST', path: '/api/config/objectives', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: ObjectiveCreateRequestSchema, responses: { 201: ObjectiveCreateResponseSchema }, response_kind: 'json', summary: 'Create an objective' }),
  getFrontierWeights: endpoint({ operation_id: 'getFrontierWeights', method: 'GET', path: '/api/frontier/weights', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: FrontierWeightsDtoSchema }, response_kind: 'json', summary: 'Read frontier weights' }),
  updateFrontierWeights: endpoint({ operation_id: 'updateFrontierWeights', method: 'PATCH', path: '/api/frontier/weights', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: FrontierWeightsPatchSchema, responses: { 200: FrontierWeightsUpdateResultSchema }, response_kind: 'json', summary: 'Update frontier weights' }),
  resetFrontierWeights: endpoint({ operation_id: 'resetFrontierWeights', method: 'POST', path: '/api/frontier/weights/reset', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: z.union([NoBodySchema, EmptyBodySchema]), responses: { 200: FrontierWeightsResetResultSchema }, response_kind: 'json', summary: 'Reset frontier weights' }),
  getOpsecBudget: endpoint({ operation_id: 'getOpsecBudget', method: 'GET', path: '/api/opsec/budget', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: OpsecBudgetResponseSchema }, response_kind: 'json', summary: 'Read OPSEC budget' }),
  getHealth: endpoint({ operation_id: 'getHealth', method: 'GET', path: '/api/health', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: HealthDtoSchema }, response_kind: 'json', summary: 'Read graph health' }),
  getRuntime: endpoint({ operation_id: 'getRuntime', method: 'GET', path: '/api/runtime', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: z.object({ runtime_build: RuntimeBuildInfoDtoSchema.optional() }).passthrough() }, response_kind: 'json', summary: 'Read lightweight daemon build identity' }),
} as const;

const dashboardEngagementEndpoints = {
  listEngagements: endpoint({ operation_id: 'listEngagements', method: 'GET', path: '/api/engagements', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: EngagementListResponseSchema }, response_kind: 'json', summary: 'List engagements' }),
  createEngagement: endpoint({ operation_id: 'createEngagement', method: 'POST', path: '/api/engagements', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: CreateEngagementBodySchema, responses: { 201: EngagementListItemSchema }, response_kind: 'json', summary: 'Create an engagement' }),
  createEngagementFromTemplate: endpoint({ operation_id: 'createEngagementFromTemplate', method: 'POST', path: '/api/engagements/from-template', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: z.object({ template_id: z.string().min(1), overrides: z.record(z.unknown()).optional() }).strict(), responses: { 201: EngagementFromTemplateResponseSchema }, response_kind: 'json', summary: 'Create an engagement from a template' }),
  createCampaign: endpoint({ operation_id: 'createCampaign', method: 'POST', path: '/api/campaigns', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: CampaignCreateRequestSchema, responses: { 201: CampaignCreateResponseSchema }, response_kind: 'json', summary: 'Create a campaign' }),
  listCampaigns: endpoint({ operation_id: 'listCampaigns', method: 'GET', path: '/api/campaigns', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: CampaignListResponseSchema }, response_kind: 'json', summary: 'List campaigns' }),
  getPhases: endpoint({ operation_id: 'getPhases', method: 'GET', path: '/api/phases', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: PhasesResponseSchema }, response_kind: 'json', summary: 'Read engagement phases' }),
  getPendingActions: endpoint({ operation_id: 'getPendingActions', method: 'GET', path: '/api/actions/pending', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: PendingActionsResponseSchema }, response_kind: 'json', summary: 'List pending actions' }),
} as const;

const dashboardToolingEndpoints = {
  getTools: endpoint({ operation_id: 'getTools', method: 'GET', path: '/api/tools', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: ToolsResponseSchema }, response_kind: 'json', summary: 'Check local tools' }),
  getParsers: endpoint({ operation_id: 'getParsers', method: 'GET', path: '/api/parsers', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: z.object({ parsers: z.array(z.string()) }).passthrough() }, response_kind: 'json', summary: 'List output parsers' }),
  getMcpTools: endpoint({ operation_id: 'getMcpTools', method: 'GET', path: '/api/mcp-tools', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: McpToolsResponseSchema }, response_kind: 'json', summary: 'List MCP tools' }),
  getReadiness: endpoint({ operation_id: 'getReadiness', method: 'GET', path: '/api/readiness', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: ReadinessResponseSchema }, response_kind: 'json', summary: 'Read dashboard readiness' }),
  getTrustSignals: endpoint({ operation_id: 'getTrustSignals', method: 'GET', path: '/api/trust-signals', path_schema: EmptyPathSchema, query_schema: TrustSignalsQuerySchema, body_schema: NoBodySchema, responses: { 200: TrustSignalsResponseSchema }, response_kind: 'json', summary: 'Read trust signals' }),
  getInferenceRules: endpoint({ operation_id: 'getInferenceRules', method: 'GET', path: '/api/inference-rules', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: InferenceRulesResponseSchema }, response_kind: 'json', summary: 'List inference rules' }),
  getTelemetry: endpoint({ operation_id: 'getTelemetry', method: 'GET', path: '/api/telemetry', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: TelemetryResponseSchema }, response_kind: 'json', summary: 'Read telemetry' }),
  exportGraph: endpoint({ operation_id: 'exportGraph', method: 'POST', path: '/api/graph/export', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: z.union([NoBodySchema, EmptyBodySchema]), responses: { 200: RawGraphDtoSchema }, response_kind: 'json', summary: 'Export the raw graph' }),
  correctGraph: endpoint({ operation_id: 'correctGraph', method: 'POST', path: '/api/graph/correct', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: GraphCorrectionRequestSchema, responses: { 200: GraphCorrectionResultSchema }, response_kind: 'json', summary: 'Apply graph corrections' }),
  getTapeStatus: endpoint({ operation_id: 'getTapeStatus', method: 'GET', path: '/api/tape', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: TapeStatusResponseSchema }, response_kind: 'json', summary: 'Read tape status' }),
  toggleTape: endpoint({ operation_id: 'toggleTape', method: 'POST', path: '/api/tape/toggle', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: z.object({ action: z.enum(['enable', 'disable']).optional(), dir: z.string().optional(), file: z.string().optional(), session_id: z.string().optional() }).strict(), responses: { 200: TapeStatusResponseSchema, 400: DashboardErrorSchema, 503: DashboardErrorSchema }, response_kind: 'json', summary: 'Set tape capture state (omitted action retains legacy toggle behavior)' }),
  getFindings: endpoint({ operation_id: 'getFindings', method: 'GET', path: '/api/findings', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: FindingsResponseSchema }, response_kind: 'json', summary: 'List findings' }),
  listReports: endpoint({ operation_id: 'listReports', method: 'GET', path: '/api/reports', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: ReportsListResponseSchema }, response_kind: 'json', summary: 'List reports' }),
  renderReport: endpoint({ operation_id: 'renderReport', method: 'POST', path: '/api/reports/render', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: ReportRenderBodySchema, responses: { 201: ReportRenderResponseSchema }, response_kind: 'json', summary: 'Render a report' }),
  bundleEngagement: endpoint({ operation_id: 'bundleEngagement', method: 'GET', path: '/api/bundle', path_schema: EmptyPathSchema, query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: z.unknown() }, response_kind: 'binary', summary: 'Download an engagement bundle' }),
} as const;

const dashboardAgentDetailEndpoints = {
  getOperatorConsole: endpoint({ operation_id: 'getOperatorConsole', method: 'GET', path: '/api/console', path_schema: EmptyPathSchema, query_schema: ConsoleQuerySchema, body_schema: NoBodySchema, responses: { 200: ConsoleResponseSchema }, response_kind: 'json', summary: 'Read server-projected operator console events' }),

  getApplicationCommand: endpoint({ operation_id: 'getApplicationCommand', method: 'GET', path: '/api/commands/{command_id}', path_schema: idPath('command_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: ApplicationCommandResponseSchema }, response_kind: 'json', summary: 'Read a durable application command' }),
  getAgentContext: endpoint({ operation_id: 'getAgentContext', method: 'GET', path: '/api/agents/{task_id}/context', path_schema: idPath('task_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: AgentContextResponseSchema }, response_kind: 'json', summary: 'Read agent context' }),
  getAgentHistory: endpoint({ operation_id: 'getAgentHistory', method: 'GET', path: '/api/agents/{task_id}/history', path_schema: idPath('task_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: HistoryResponseSchema }, response_kind: 'json', summary: 'Read agent activity history' }),
  getAgentConsole: endpoint({ operation_id: 'getAgentConsole', method: 'GET', path: '/api/agents/{task_id}/console', path_schema: idPath('task_id'), query_schema: ConsoleQuerySchema, body_schema: NoBodySchema, responses: { 200: ConsoleResponseSchema }, response_kind: 'json', summary: 'Read server-projected agent console events' }),
  cancelAgent: endpoint({ operation_id: 'cancelAgent', method: 'POST', path: '/api/agents/{task_id}/cancel', path_schema: idPath('task_id'), query_schema: EmptyQuerySchema, body_schema: z.union([NoBodySchema, EmptyBodySchema]), responses: { 200: OkResponseSchema }, response_kind: 'json', summary: 'Cancel an agent' }),
  dismissAgent: endpoint({ operation_id: 'dismissAgent', method: 'POST', path: '/api/agents/{task_id}/dismiss', path_schema: idPath('task_id'), query_schema: EmptyQuerySchema, body_schema: z.union([NoBodySchema, z.object({ force: z.boolean().optional() }).strict()]), responses: { 200: AgentDismissResponseSchema }, response_kind: 'json', summary: 'Dismiss an agent' }),
  issueAgentDirective: endpoint({ operation_id: 'issueAgentDirective', method: 'POST', path: '/api/agents/{task_id}/directive', path_schema: idPath('task_id'), query_schema: EmptyQuerySchema, body_schema: DirectiveBodySchema, responses: { 200: AgentDirectiveResponseSchema }, response_kind: 'json', summary: 'Steer an agent' }),
  answerAgentQuery: endpoint({ operation_id: 'answerAgentQuery', method: 'POST', path: '/api/agent-queries/{query_id}/answer', path_schema: idPath('query_id'), query_schema: EmptyQuerySchema, body_schema: z.object({ answer: z.string().min(1) }).strict(), responses: { 200: OkResponseSchema }, response_kind: 'json', summary: 'Answer one agent question' }),
  updateObjective: endpoint({ operation_id: 'updateObjective', method: 'PATCH', path: '/api/config/objectives/{objective_id}', path_schema: idPath('objective_id'), query_schema: EmptyQuerySchema, body_schema: ObjectiveUpdateRequestSchema, responses: { 200: ObjectiveUpdateResponseSchema }, response_kind: 'json', summary: 'Update an objective' }),
  deleteObjective: endpoint({ operation_id: 'deleteObjective', method: 'DELETE', path: '/api/config/objectives/{objective_id}', path_schema: idPath('objective_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: ObjectiveDeleteResponseSchema }, response_kind: 'json', summary: 'Delete an objective' }),
} as const;

const dashboardCampaignDetailEndpoints = {
  getCampaign: endpoint({ operation_id: 'getCampaign', method: 'GET', path: '/api/campaigns/{campaign_id}', path_schema: idPath('campaign_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: CampaignDetailResponseSchema }, response_kind: 'json', summary: 'Read campaign detail' }),
  updateCampaign: endpoint({ operation_id: 'updateCampaign', method: 'PATCH', path: '/api/campaigns/{campaign_id}', path_schema: idPath('campaign_id'), query_schema: EmptyQuerySchema, body_schema: CampaignUpdateRequestSchema, responses: { 200: CampaignUpdateResponseSchema }, response_kind: 'json', summary: 'Update a campaign' }),
  deleteCampaign: endpoint({ operation_id: 'deleteCampaign', method: 'DELETE', path: '/api/campaigns/{campaign_id}', path_schema: idPath('campaign_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: CampaignDeleteResponseSchema }, response_kind: 'json', summary: 'Delete a campaign' }),
  actOnCampaign: endpoint({ operation_id: 'actOnCampaign', method: 'POST', path: '/api/campaigns/{campaign_id}/action', path_schema: idPath('campaign_id'), query_schema: EmptyQuerySchema, body_schema: CampaignActionRequestSchema, responses: { 200: CampaignActionResponseSchema }, response_kind: 'json', summary: 'Change campaign lifecycle' }),
  dispatchCampaign: endpoint({ operation_id: 'dispatchCampaign', method: 'POST', path: '/api/campaigns/{campaign_id}/dispatch', path_schema: idPath('campaign_id'), query_schema: EmptyQuerySchema, body_schema: CampaignDispatchRequestSchema, responses: { 200: CampaignDispatchResponseSchema }, response_kind: 'json', summary: 'Dispatch campaign items' }),
  cloneCampaign: endpoint({ operation_id: 'cloneCampaign', method: 'POST', path: '/api/campaigns/{campaign_id}/clone', path_schema: idPath('campaign_id'), query_schema: EmptyQuerySchema, body_schema: z.union([NoBodySchema, EmptyBodySchema]), responses: { 201: CampaignCloneResponseSchema }, response_kind: 'json', summary: 'Clone a campaign' }),
  splitCampaign: endpoint({ operation_id: 'splitCampaign', method: 'POST', path: '/api/campaigns/{campaign_id}/split', path_schema: idPath('campaign_id'), query_schema: EmptyQuerySchema, body_schema: CampaignSplitRequestSchema, responses: { 201: CampaignSplitResponseSchema }, response_kind: 'json', summary: 'Split a campaign' }),
  getCampaignChildren: endpoint({ operation_id: 'getCampaignChildren', method: 'GET', path: '/api/campaigns/{campaign_id}/children', path_schema: idPath('campaign_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: CampaignChildrenResponseSchema }, response_kind: 'json', summary: 'Read campaign children' }),
  explainAction: endpoint({ operation_id: 'explainAction', method: 'GET', path: '/api/actions/{action_id}/explain', path_schema: idPath('action_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: ActionExplanationResponseSchema, 404: ActionExplanationResponseSchema }, response_kind: 'json', summary: 'Explain an action' }),
  getActionOutput: endpoint({ operation_id: 'getActionOutput', method: 'GET', path: '/api/actions/{action_id}/output', path_schema: idPath('action_id'), query_schema: ActionOutputQuerySchema, body_schema: NoBodySchema, responses: { 200: ActionOutputResponseSchema }, response_kind: 'json', summary: 'Read durable action output' }),
  reparseAction: endpoint({ operation_id: 'reparseAction', method: 'POST', path: '/api/actions/{action_id}/reparse', path_schema: idPath('action_id'), query_schema: EmptyQuerySchema, body_schema: ReparseBodySchema, responses: { 200: ReparseResponseSchema }, response_kind: 'json', summary: 'Reparse durable action output' }),
  getEvidenceRaw: endpoint({ operation_id: 'getEvidenceRaw', method: 'GET', path: '/api/evidence/{evidence_id}/raw', path_schema: idPath('evidence_id'), query_schema: EvidenceRawQuerySchema, body_schema: NoBodySchema, responses: { 200: EvidenceRawResponseSchema }, response_kind: 'json', summary: 'Read raw evidence text' }),
  getEvidenceImage: endpoint({ operation_id: 'getEvidenceImage', method: 'GET', path: '/api/evidence/{evidence_id}/image', path_schema: idPath('evidence_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: z.unknown() }, response_kind: 'binary', summary: 'Read image evidence' }),
} as const;

const dashboardFinalEndpoints = {
  approveAction: endpoint({ operation_id: 'approveAction', method: 'POST', path: '/api/actions/{action_id}/approve', path_schema: idPath('action_id'), query_schema: EmptyQuerySchema, body_schema: z.object({ notes: z.string().optional() }).strict(), responses: { 200: ActionResolutionResponseSchema }, response_kind: 'json', summary: 'Approve an action' }),
  denyAction: endpoint({ operation_id: 'denyAction', method: 'POST', path: '/api/actions/{action_id}/deny', path_schema: idPath('action_id'), query_schema: EmptyQuerySchema, body_schema: z.object({ reason: z.string().optional() }).strict(), responses: { 200: ActionResolutionResponseSchema }, response_kind: 'json', summary: 'Deny an action' }),
  closeSession: endpoint({ operation_id: 'closeSession', method: 'POST', path: '/api/sessions/{session_id}/close', path_schema: idPath('session_id'), query_schema: EmptyQuerySchema, body_schema: z.union([NoBodySchema, EmptyBodySchema]), responses: { 200: SessionCloseResponseSchema }, response_kind: 'json', summary: 'Close a session' }),
  resumeSession: endpoint({ operation_id: 'resumeSession', method: 'POST', path: '/api/sessions/{session_id}/resume', path_schema: idPath('session_id'), query_schema: EmptyQuerySchema, body_schema: z.union([NoBodySchema, EmptyBodySchema]), responses: { 200: SessionResumeResponseSchema }, response_kind: 'json', summary: 'Resume a session listener' }),
  getSessionBuffer: endpoint({ operation_id: 'getSessionBuffer', method: 'GET', path: '/api/sessions/{session_id}/buffer', path_schema: idPath('session_id'), query_schema: SessionBufferQuerySchema, body_schema: NoBodySchema, responses: { 200: SessionBufferResponseSchema }, response_kind: 'json', summary: 'Read session output' }),
  updateSession: endpoint({ operation_id: 'updateSession', method: 'PATCH', path: '/api/sessions/{session_id}', path_schema: idPath('session_id'), query_schema: EmptyQuerySchema, body_schema: z.object({ title: z.string().optional(), notes: z.string().optional() }).strict(), responses: { 200: SessionUpdateResponseSchema }, response_kind: 'json', summary: 'Update session metadata' }),
  getEvidenceChains: endpoint({ operation_id: 'getEvidenceChains', method: 'GET', path: '/api/evidence-chains/{node_id}', path_schema: idPath('node_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: EvidenceChainsResponseSchema }, response_kind: 'json', summary: 'Read evidence chains' }),
  getObjectivePaths: endpoint({ operation_id: 'getObjectivePaths', method: 'GET', path: '/api/paths/{objective_id}', path_schema: idPath('objective_id'), query_schema: PathsQuerySchema, body_schema: NoBodySchema, responses: { 200: ObjectivePathsResponseSchema }, response_kind: 'json', summary: 'Read paths to an objective' }),
  getFindingContext: endpoint({ operation_id: 'getFindingContext', method: 'GET', path: '/api/findings/{finding_id}/context', path_schema: idPath('finding_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: FindingContextResponseSchema }, response_kind: 'json', summary: 'Read finding context' }),
  downloadReport: endpoint({ operation_id: 'downloadReport', method: 'GET', path: '/api/reports/{report_id}', path_schema: idPath('report_id'), query_schema: ReportDownloadQuerySchema, body_schema: NoBodySchema, responses: { 200: z.unknown() }, response_kind: 'binary', summary: 'Download or open a report' }),
  deleteReport: endpoint({ operation_id: 'deleteReport', method: 'DELETE', path: '/api/reports/{report_id}', path_schema: idPath('report_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: ReportDeleteResponseSchema, 404: ReportDeleteResponseSchema }, response_kind: 'json', summary: 'Delete a report' }),
  getEngagement: endpoint({ operation_id: 'getEngagement', method: 'GET', path: '/api/engagements/{engagement_id}', path_schema: idPath('engagement_id'), query_schema: EmptyQuerySchema, body_schema: NoBodySchema, responses: { 200: EngagementConfigResponseSchema }, response_kind: 'json', summary: 'Read engagement configuration' }),
  updateEngagement: endpoint({ operation_id: 'updateEngagement', method: 'PATCH', path: '/api/engagements/{engagement_id}', path_schema: idPath('engagement_id'), query_schema: EmptyQuerySchema, body_schema: EngagementUpdateBodySchema, responses: { 200: EngagementUpdateResponseSchema }, response_kind: 'json', summary: 'Update engagement configuration' }),
} as const;

type DashboardHttpRegistryType =
  & typeof dashboardCoreEndpoints
  & typeof dashboardAgentCommandEndpoints
  & typeof dashboardPlaybookEndpoints
  & typeof dashboardPlaybookLifecycleEndpoints
  & typeof dashboardConfigEndpoints
  & typeof dashboardEngagementEndpoints
  & typeof dashboardToolingEndpoints
  & typeof dashboardAgentDetailEndpoints
  & typeof dashboardCampaignDetailEndpoints
  & typeof dashboardFinalEndpoints;

export const DashboardHttpRegistry: DashboardHttpRegistryType = {
  ...dashboardCoreEndpoints,
  ...dashboardAgentCommandEndpoints,
  ...dashboardPlaybookEndpoints,
  ...dashboardPlaybookLifecycleEndpoints,
  ...dashboardConfigEndpoints,
  ...dashboardEngagementEndpoints,
  ...dashboardToolingEndpoints,
  ...dashboardAgentDetailEndpoints,
  ...dashboardCampaignDetailEndpoints,
  ...dashboardFinalEndpoints,
};

export type DashboardEndpoint<T extends DashboardOperationId> = (typeof DashboardHttpRegistry)[T];
export type DashboardPathInput<T extends DashboardOperationId> = z.input<DashboardEndpoint<T>['path_schema']>;
export type DashboardQueryInput<T extends DashboardOperationId> = z.input<DashboardEndpoint<T>['query_schema']>;
export type DashboardBodyInput<T extends DashboardOperationId> = z.input<DashboardEndpoint<T>['body_schema']>;
type ResponseSchema<T extends DashboardOperationId> = DashboardEndpoint<T>['responses'][keyof DashboardEndpoint<T>['responses']] extends infer TSchema
  ? TSchema extends z.ZodTypeAny ? TSchema : never
  : never;
export type DashboardSuccessOutput<T extends DashboardOperationId> = z.output<ResponseSchema<T>>;

export interface MatchedDashboardEndpoint {
  operation_id: DashboardOperationId;
  endpoint: DashboardEndpoint<DashboardOperationId>;
  path_params: Record<string, string>;
}

interface CompiledEndpoint {
  operation_id: DashboardOperationId;
  endpoint: DashboardEndpoint<DashboardOperationId>;
  names: string[];
  pattern: RegExp;
  static_segments: number;
}

const compiledEndpoints: CompiledEndpoint[] = Object.entries(DashboardHttpRegistry)
  .map(([operationId, definition]) => {
    const names: string[] = [];
    const parts = definition.path.split('/').map(part => {
      const match = part.match(/^\{([^}]+)\}$/);
      if (!match) return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      names.push(match[1]);
      return '([^/]+)';
    });
    return {
      operation_id: operationId as DashboardOperationId,
      endpoint: definition as DashboardEndpoint<DashboardOperationId>,
      names,
      pattern: new RegExp(`^${parts.join('/')}$`),
      static_segments: parts.length - names.length,
    };
  })
  .sort((left, right) => right.static_segments - left.static_segments || right.endpoint.path.length - left.endpoint.path.length);

export function matchDashboardEndpoint(method: string, pathname: string): MatchedDashboardEndpoint | null {
  const normalizedMethod = method.toUpperCase();
  for (const compiled of compiledEndpoints) {
    if (compiled.endpoint.method !== normalizedMethod) continue;
    const match = compiled.pattern.exec(pathname);
    if (!match) continue;
    const encoded = Object.fromEntries(compiled.names.map((name, index) => [name, match[index + 1]]));
    let decoded: Record<string, string>;
    try {
      decoded = Object.fromEntries(Object.entries(encoded).map(([name, value]) => [name, decodeURIComponent(value)]));
    } catch {
      return null;
    }
    const parsed = compiled.endpoint.path_schema.safeParse(decoded);
    if (!parsed.success) return null;
    return {
      operation_id: compiled.operation_id,
      endpoint: compiled.endpoint,
      path_params: parsed.data,
    };
  }
  return null;
}

export function dashboardMethodsForPath(pathname: string): DashboardHttpMethod[] {
  const methods = new Set<DashboardHttpMethod>();
  for (const compiled of compiledEndpoints) {
    if (compiled.pattern.test(pathname)) methods.add(compiled.endpoint.method);
  }
  return [...methods].sort();
}

export function buildDashboardPath<T extends DashboardOperationId>(
  operationId: T,
  input: DashboardPathInput<T>,
): string {
  const endpointDefinition = DashboardHttpRegistry[operationId];
  const params = endpointDefinition.path_schema.parse(input) as Record<string, string>;
  return endpointDefinition.path.replace(/\{([^}]+)\}/g, (_whole, name: string) => encodeURIComponent(params[name]));
}

export interface DashboardRouteManifestEntry {
  operation_id: DashboardOperationId;
  method: DashboardHttpMethod;
  path: string;
  response_kind: DashboardResponseKind;
  success_statuses: number[];
  summary: string;
}

export function getDashboardRouteManifest(): DashboardRouteManifestEntry[] {
  return Object.entries(DashboardHttpRegistry).map(([operationId, definition]) => ({
    operation_id: operationId as DashboardOperationId,
    method: definition.method,
    path: definition.path,
    response_kind: definition.response_kind,
    success_statuses: Object.keys(definition.responses).map(Number).sort((left, right) => left - right),
    summary: definition.summary,
  }));
}

export function responseSchemaFor(
  endpointDefinition: DashboardEndpoint<DashboardOperationId>,
  status: number,
): z.ZodTypeAny | undefined {
  return (endpointDefinition.responses as Record<number, z.ZodTypeAny>)[status]
    ?? (status >= 400 ? DashboardErrorSchema : undefined);
}

export { DashboardErrorSchema };
