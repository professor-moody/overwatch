import type {
  EngagementState,
  ActivityEntry,
  DecisionLogEntry,
  ActionExplanation,
  TimelineEntry,
  SessionInfo,
  SessionBufferResponse,
  Campaign,
  PendingAction,
  ActionQueueDiagnostics,
  HealthStatus,
  EvidenceChainResponse,
  FindingContextResponse,
  AttackPath,
  FindPathsResponse,
  ScopeConfig,
  OpsecConfig,
  OpsecBudget,
  EngagementConfig,
  FrontierWeights,
  EngagementListItem,
  EngagementTemplate,
  EngagementDetail,
  ToolCheckResult,
  McpToolRegistryResponse,
  DashboardReadinessSummary,
  InferenceRuleInfo,
  TelemetrySummary,
  InferenceRuleEffectiveness,
  CredentialCoverage,
} from './types';
import {
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
  CommandDenialResponseSchema,
  CommandExecutionResponseSchema,
  CommandPreviewSchema,
  ConfigDivergenceResolveRequestSchema,
  ConfigDivergenceResolveResponseSchema,
  FindingDtoSchema,
  FindingsResponseSchema,
  FrontierWeightsPatchSchema,
  FrontierWeightsResetResultSchema,
  FrontierWeightsUpdateResultSchema,
  HealthDtoSchema,
  ObjectiveCreateRequestSchema,
  ObjectiveCreateResponseSchema,
  ObjectiveDeleteResponseSchema,
  ObjectiveUpdateRequestSchema,
  ObjectiveUpdateResponseSchema,
  PlaybookRunListResponseSchema,
  PlaybookRunResponseSchema,
  PlaybookStepClaimResponseSchema,
  RawGraphDtoSchema,
  RecoveryStatusResponseSchema,
  SettingsDtoSchema,
  SettingsPatchSchema,
  SettingsUpdateResultSchema,
  type ApplicationCommandRecordDto,
  type CampaignDetailResponse,
  type CampaignDispatchResponse,
  type CommandOpResultDto,
  type CommandPreviewDto,
  type ConfigDivergenceResolveRequest,
  type ConfigDivergenceResolveResponse,
  type GraphCorrectionOperationDto,
  type GraphCorrectionResultDto,
  type FindingsResponseDto,
  type ObjectiveCreateRequest,
  type ObjectiveUpdateRequest,
  type RawGraphDto,
  type RuntimeBuildInfoDto,
  type ProposedPlanDto,
  type PlaybookRunDto,
  type PlaybookStepClaimResponse,
  type ReportRecordDto,
  type ReportRenderResponseDto,
  type ReportsListResponseDto,
  type RecoveryStatusDto,
  type SettingsDto,
} from '@overwatch/dashboard-contracts';
import { buildDashboardPath } from '@overwatch/dashboard-api-contracts';
import {
  DashboardApiError,
  requestDashboardEndpoint,
  setDashboardApiErrorObserver,
  type GeneratedDashboardOutput,
  type GeneratedDashboardOperationId,
  type GeneratedDashboardRequestFor,
} from './api.generated';
import { createDashboardCommandId } from './dashboard-transport';
import { useEngagementStore } from '../stores/engagement-store';
import { normalizeActivityEntries } from './api/agents';

const BASE = '';

/** Same-origin URL for a screenshot evidence blob, rendered as an `<img>`. */
export function evidenceImageUrl(evidenceId: string): string {
  return `${BASE}${buildDashboardPath('getEvidenceImage', { evidence_id: evidenceId })}`;
}

export { DashboardApiError };
export { normalizeActivityEntries };
export {
  agentDisplayLabel,
  answerAgentQuery,
  answerAgentQueryBatch,
  cancelAgent,
  canonicalAgentTaskId,
  dispatchAgent,
  dispatchBatch,
  dispatchedAgentLabel,
  dismissAgent,
  fleetDirective,
  fleetDismiss,
  fleetInstruct,
  getAgentConsole,
  getAgentContext,
  getAgentDuplicates,
  getAgentHistory,
  getAgentQueries,
  getAgents,
  getArchetypes,
  getOperatorConsole,
  issueDirective,
  handoffAgentWork,
  mergeAgentWork,
  quickDeploy,
  resolveAgentReference,
  splitAgentWork,
  type AgentArchetypeSummary,
  type AgentDuplicatesResponse,
  type AgentHandoffRequest,
  type AgentHandoffResponse,
  type AgentMergeRequest,
  type AgentMergeResponse,
  type AgentQuery,
  type AgentReference,
  type AgentSplitRequest,
  type AgentSplitResponse,
  type DirectiveKind,
  type DispatchAgentResult,
  type DispatchBatchResult,
  type QuickDeployResult,
} from './api/agents';

setDashboardApiErrorObserver(error => {
  const body = error.body;
  if (!body || typeof body !== 'object' || !('recovery' in body)) return;
  const parsed = RecoveryStatusResponseSchema.safeParse({
    recovery: (body as { recovery?: unknown }).recovery,
  });
  if (parsed.success) {
    // A mutation can discover config divergence while the main WebSocket is
    // synchronized. Publish the structured 503 state immediately.
    useEngagementStore.getState().setPersistenceRecovery(parsed.data.recovery);
  }
});

async function request<T extends GeneratedDashboardOperationId>(
  operationId: T,
  input: GeneratedDashboardRequestFor<T> = {},
): Promise<GeneratedDashboardOutput<T>> {
  return requestDashboardEndpoint(operationId, input);
}

// --- State ---

export async function getState(signal?: AbortSignal): Promise<{
  state: EngagementState;
  graph: RawGraphDto;
  history_count: number;
  state_revision?: number;
  runtime_build: RuntimeBuildInfoDto;
}> {
  const response = await request('getState', { signal });
  if (response.runtime_build === undefined) {
    throw new Error('The dashboard state response is missing current runtime identity. Run `npm run upgrade`.');
  }
  return {
    ...response,
    state: response.state as unknown as EngagementState,
    graph: RawGraphDtoSchema.parse(response.graph),
    state_revision: response.state_revision,
    runtime_build: response.runtime_build,
  };
}

export async function getGraph(): Promise<RawGraphDto> {
  return RawGraphDtoSchema.parse(await request('getGraph'));
}

// --- Durable credential playbooks ---

export async function getPlaybookRuns(params: {
  credential_id?: string;
  status?: PlaybookRunDto['status'];
  open_only?: boolean;
} = {}): Promise<{ runs: PlaybookRunDto[]; total: number }> {
  const response = PlaybookRunListResponseSchema.parse(await request('listPlaybookRuns', { query: params }));
  return {
    runs: response.runs.filter((run): run is PlaybookRunDto => run.schema_version === 1),
    total: response.total,
  };
}

export async function getPlaybookRun(runId: string): Promise<PlaybookRunDto> {
  const response = PlaybookRunResponseSchema.parse(await request('getPlaybookRun', { path: { run_id: runId } }));
  if (response.run.schema_version !== 1) throw new Error('This is a legacy playbook placeholder; start a new run.');
  return response.run;
}

export async function startPlaybookStep(runId: string, stepId: string): Promise<PlaybookStepClaimResponse> {
  return PlaybookStepClaimResponseSchema.parse(await request('startPlaybookStep', { path: { run_id: runId, step_id: stepId }, body: {} }));
}

export async function resumePlaybookRun(runId: string): Promise<PlaybookRunDto> {
  const response = PlaybookRunResponseSchema.parse(await request('resumePlaybookRun', { path: { run_id: runId }, body: {} }));
  if (response.run.schema_version !== 1) throw new Error('This is a legacy playbook placeholder; start a new run.');
  return response.run;
}

export async function retryPlaybookStep(runId: string, stepId: string): Promise<PlaybookStepClaimResponse> {
  return PlaybookStepClaimResponseSchema.parse(await request('retryPlaybookStep', { path: { run_id: runId, step_id: stepId }, body: {} }));
}

export async function skipPlaybookStep(runId: string, stepId: string, reason?: string): Promise<PlaybookRunDto> {
  const response = PlaybookRunResponseSchema.parse(await request('skipPlaybookStep', {
    path: { run_id: runId, step_id: stepId },
    body: { reason },
  }));
  if (response.run.schema_version !== 1) throw new Error('This is a legacy playbook placeholder; start a new run.');
  return response.run;
}

export async function interruptPlaybookAttempt(runId: string, stepId: string, reason?: string): Promise<PlaybookRunDto> {
  const response = PlaybookRunResponseSchema.parse(await request('interruptPlaybookAttempt', {
    path: { run_id: runId, step_id: stepId },
    body: { reason },
  }));
  if (response.run.schema_version !== 1) throw new Error('This is a legacy playbook placeholder; start a new run.');
  return response.run;
}

// --- History ---

export async function getHistory(params?: {
  limit?: number;
  after?: string;
  before?: string;
  order?: 'asc' | 'desc';
  /** Restrict to these event types before the limit is applied — so `limit` counts
   *  the matching events, not the whole (heartbeat/thought-diluted) stream. */
  eventTypes?: string[];
}): Promise<{ entries: ActivityEntry[]; total: number }> {
  const response = await request('getHistory', { query: {
    limit: params?.limit,
    after: params?.after,
    before: params?.before,
    order: params?.order,
    event_types: params?.eventTypes?.join(','),
  } });
  return { ...response, entries: normalizeActivityEntries(response.entries) };
}

export async function getDecisionLog(params?: {
  limit?: number;
  action_id?: string;
  frontier_item_id?: string;
  agent_id?: string;
  outcome?: string;
}): Promise<{ decisions: DecisionLogEntry[]; total: number }> {
  return request('getDecisionLog', { query: params }) as unknown as Promise<{ decisions: DecisionLogEntry[]; total: number }>;
}

export async function explainAction(id: string): Promise<ActionExplanation> {
  return request('explainAction', { path: { action_id: id } }) as unknown as Promise<ActionExplanation>;
}

export async function getTimeline(params?: {
  limit?: number;
  entity_id?: string;
  kind?: 'node' | 'edge';
  since?: string;
  at?: string;
}): Promise<{ entries: TimelineEntry[]; total: number }> {
  return request('getTimeline', { query: params }) as unknown as Promise<{ entries: TimelineEntry[]; total: number }>;
}

// --- Sessions ---

export async function getSessions(): Promise<{ sessions: SessionInfo[]; total: number; active: number }> {
  return request('getSessions');
}

export async function closeSession(id: string): Promise<{ metadata: SessionInfo; final: { text: string; end_pos: number } }> {
  return request('closeSession', { path: { session_id: id } });
}

export async function resumeSession(id: string): Promise<{ resumed: true; metadata: SessionInfo }> {
  return request('resumeSession', { path: { session_id: id } });
}

export async function updateSession(id: string, body: { title?: string; notes?: string }): Promise<{ metadata: SessionInfo }> {
  return request('updateSession', { path: { session_id: id }, body });
}

export async function getSessionBuffer(id: string, params?: {
  from?: number;
  tailBytes?: number;
  connectionId?: string;
  connectionGeneration?: number;
}): Promise<SessionBufferResponse> {
  return request('getSessionBuffer', {
    path: { session_id: id },
    query: {
      from: params?.from,
      tail_bytes: params?.tailBytes,
      connection_id: params?.connectionId,
      connection_generation: params?.connectionGeneration,
    },
  });
}

// --- NL operator cockpit (Phase 3A) ---

export interface OperatorOp {
  op: 'directive' | 'scope' | 'approve' | 'deny' | 'dispatch';
  [key: string]: unknown;
}

export type CommandOpResult = CommandOpResultDto;

/** A read-only query answer rendered inline in the command bar (no confirm). */
export interface QueryAnswer {
  kind: 'changes_since' | 'timeline' | 'list_nodes' | 'finding_readiness' | 'find_paths' | 'retrospective' | 'unanswerable';
  summary: string;
  rows?: string[];
  total?: number;
  note?: string;
}

export type CommandPreview = CommandPreviewDto;

export type ProposedPlan = ProposedPlanDto;

/** Phase 1: interpret a free-form command into a previewable plan (no mutation). */
export async function previewCommand(command: string): Promise<CommandPreview> {
  const commandId = createDashboardCommandId();
  return CommandPreviewSchema.parse(await request('interpretCommand', {
    headers: {
      'Idempotency-Key': `operator-plan:${commandId}`,
      'X-Overwatch-Command-Id': commandId,
    },
    body: { command },
  }));
}

/** Phase 2: confirm + execute a previewed/proposed plan by id. */
export async function confirmCommand(planId: string): Promise<{ executed: boolean; results: CommandOpResult[] }> {
  return CommandExecutionResponseSchema.parse(await request('interpretCommand', {
    headers: {
      'Idempotency-Key': `plan-confirm:${planId}`,
      'X-Overwatch-Command-Id': createDashboardCommandId(),
    },
    body: { confirm: true, plan_id: planId },
  }));
}

/** Dismiss a planner-proposed plan without executing it. */
export async function denyCommandPlan(planId: string): Promise<{ denied: boolean }> {
  return CommandDenialResponseSchema.parse(await request('interpretCommand', {
    headers: {
      'Idempotency-Key': `plan-deny:${planId}`,
      'X-Overwatch-Command-Id': createDashboardCommandId(),
    },
    body: { deny: true, plan_id: planId },
  }));
}

/** Open planner-proposed plans awaiting operator confirmation. */
export async function getProposedPlans(signal?: AbortSignal): Promise<{ plans: ProposedPlan[] }> {
  return request('getProposedPlans', { signal });
}

export type ApplicationCommandRecord = ApplicationCommandRecordDto;

export async function getActiveApplicationCommands(
  signal?: AbortSignal,
): Promise<{ commands: ApplicationCommandRecord[] }> {
  return request('getActiveApplicationCommands', { signal });
}

export async function getApplicationCommand(
  commandId: string,
  signal?: AbortSignal,
): Promise<{ command: ApplicationCommandRecord }> {
  return request('getApplicationCommand', { path: { command_id: commandId }, signal });
}

// --- Campaigns ---

export async function getCampaigns(): Promise<{ campaigns: Campaign[]; total: number }> {
  return CampaignListResponseSchema.parse(await request('listCampaigns'));
}

export async function getCampaign(id: string): Promise<CampaignDetailResponse> {
  return CampaignDetailResponseSchema.parse(await request('getCampaign', { path: { campaign_id: id } }));
}

export async function createCampaign(body: {
  name: string;
  strategy: string;
  item_ids: string[];
  abort_conditions?: Array<{ type: 'consecutive_failures' | 'total_failures_pct' | 'opsec_noise_ceiling' | 'time_limit_seconds'; threshold: number }>;
}): Promise<Campaign> {
  const parsed = CampaignCreateRequestSchema.parse(body);
  const res = CampaignCreateResponseSchema.parse(await request('createCampaign', { body: parsed }));
  return res.campaign;
}

export async function updateCampaign(id: string, body: {
  name?: string;
  abort_conditions?: Array<{ type: 'consecutive_failures' | 'total_failures_pct' | 'opsec_noise_ceiling' | 'time_limit_seconds'; threshold: number }>;
  add_items?: string[];
  remove_items?: string[];
}): Promise<Campaign> {
  const parsed = CampaignUpdateRequestSchema.parse(body);
  const res = CampaignUpdateResponseSchema.parse(await request('updateCampaign', { path: { campaign_id: id }, body: parsed }));
  return res.campaign;
}

export async function deleteCampaign(id: string): Promise<{ deleted: true }> {
  return CampaignDeleteResponseSchema.parse(await request('deleteCampaign', { path: { campaign_id: id } }));
}

export async function campaignAction(id: string, action: 'activate' | 'pause' | 'resume' | 'abort'): Promise<Campaign> {
  const parsed = CampaignActionRequestSchema.parse({ action });
  const res = CampaignActionResponseSchema.parse(await request('actOnCampaign', { path: { campaign_id: id }, body: parsed }));
  return res.campaign;
}

export async function dispatchCampaign(id: string, body?: {
  max_agents?: number;
  hops?: number;   // server reads `hops` (was sent as scope_hops → ignored)
  skill?: string;
}): Promise<CampaignDispatchResponse> {
  const parsed = CampaignDispatchRequestSchema.parse(body ?? {});
  return CampaignDispatchResponseSchema.parse(await request('dispatchCampaign', { path: { campaign_id: id }, body: parsed }));
}

export async function cloneCampaign(id: string): Promise<Campaign> {
  const res = CampaignCloneResponseSchema.parse(await request('cloneCampaign', { path: { campaign_id: id } }));
  return res.campaign;
}

export async function splitCampaign(id: string, body: { count: number }): Promise<{ parent_id: string; children: Campaign[]; count: number }> {
  const parsed = CampaignSplitRequestSchema.parse(body);
  return CampaignSplitResponseSchema.parse(await request('splitCampaign', { path: { campaign_id: id }, body: parsed }));
}

export async function getCampaignChildren(id: string) {
  return CampaignChildrenResponseSchema.parse(await request('getCampaignChildren', { path: { campaign_id: id } }));
}

// --- Pending Actions ---

export async function getPendingActions(): Promise<{ pending: PendingAction[]; recent?: PendingAction[]; diagnostics?: ActionQueueDiagnostics }> {
  return request('getPendingActions');
}

export async function approveAction(id: string, modifications?: Record<string, unknown>): Promise<unknown> {
  return request('approveAction', { path: { action_id: id }, body: modifications || {} });
}

export async function denyAction(id: string, reason?: string): Promise<unknown> {
  return request('denyAction', { path: { action_id: id }, body: { reason } });
}

/** Bulk approve — routes each id through the same canonical resolve as the single path. */
export async function approveBatch(actionIds: string[], notes?: string): Promise<{ ok: boolean; resolved: number; total: number }> {
  return request('approveActionsBatch', { body: { action_ids: actionIds, notes } });
}

/** Bulk deny — one shared reason for all (required). */
export async function denyBatch(actionIds: string[], reason: string): Promise<{ ok: boolean; resolved: number; total: number }> {
  return request('denyActionsBatch', { body: { action_ids: actionIds, reason } });
}

// --- Config / Settings ---

export async function getRecovery(): Promise<RecoveryStatusDto> {
  return RecoveryStatusResponseSchema.parse(await request('getRecovery', { cache: 'no-store' })).recovery;
}

export async function resolveConfigDivergence(
  body: ConfigDivergenceResolveRequest,
): Promise<ConfigDivergenceResolveResponse> {
  const parsed = ConfigDivergenceResolveRequestSchema.parse(body);
  return ConfigDivergenceResolveResponseSchema.parse(await request('resolveConfigDivergence', { body: parsed }));
}

export async function getConfig(): Promise<EngagementConfig> {
  return request('getConfig');
}

export async function updateConfig(body: Partial<EngagementConfig>): Promise<{ updated: boolean }> {
  return request('updateConfig', {
    body: body as GeneratedDashboardRequestFor<'updateConfig'>['body'],
  });
}

export interface ScopeChangePreview {
  before: { cidrs: string[]; domains: string[]; exclusions: string[] };
  after: { cidrs: string[]; domains: string[]; exclusions: string[] };
  nodes_entering_scope: number;
  nodes_leaving_scope: number;
  pending_suggestions_resolved: string[];
  added: { cidrs: string[]; domains: string[]; exclusions: string[] };
  removed: { cidrs: string[]; domains: string[]; exclusions: string[] };
}

export interface ScopeUpdateResult {
  updated: boolean;
  scope: ScopeConfig;
  applied?: boolean;
  affected_node_count?: number;
}

/** Read-only dry-run: what would change if `body` (full-replacement scope) were applied. */
export async function previewScope(body: Partial<ScopeConfig>): Promise<ScopeChangePreview> {
  return request('previewScope', { body });
}

export async function updateScope(body: Partial<ScopeConfig>): Promise<ScopeUpdateResult> {
  return request('updateScope', { body });
}

export async function addObjective(body: ObjectiveCreateRequest) {
  const parsed = ObjectiveCreateRequestSchema.parse(body);
  return ObjectiveCreateResponseSchema.parse(await request('createObjective', { body: parsed }));
}

export async function updateObjective(id: string, body: ObjectiveUpdateRequest) {
  const parsed = ObjectiveUpdateRequestSchema.parse(body);
  return ObjectiveUpdateResponseSchema.parse(await request('updateObjective', { path: { objective_id: id }, body: parsed }));
}

export async function deleteObjective(id: string) {
  return ObjectiveDeleteResponseSchema.parse(await request('deleteObjective', { path: { objective_id: id } }));
}

export async function getSettings(): Promise<SettingsDto> {
  return SettingsDtoSchema.parse(await request('getSettings'));
}

export async function updateSettings(body: Partial<OpsecConfig>) {
  const parsed = SettingsPatchSchema.parse(body);
  return SettingsUpdateResultSchema.parse(await request('updateSettings', { body: parsed }));
}

export async function getFrontierWeights(): Promise<FrontierWeights> {
  return request('getFrontierWeights');
}

export async function updateFrontierWeights(body: Partial<FrontierWeights>) {
  const parsed = FrontierWeightsPatchSchema.parse(body);
  return FrontierWeightsUpdateResultSchema.parse(await request('updateFrontierWeights', { body: parsed }));
}

export async function resetFrontierWeights() {
  return FrontierWeightsResetResultSchema.parse(await request('resetFrontierWeights'));
}

// --- OPSEC Budget ---

export async function getOpsecBudget(): Promise<OpsecBudget> {
  return request('getOpsecBudget');
}

// --- Health ---

export async function getHealth(): Promise<HealthStatus> {
  return HealthDtoSchema.parse(await request('getHealth'));
}

// --- Templates ---

export async function getTemplates(): Promise<{ templates: EngagementTemplate[]; total: number }> {
  return request('getTemplates');
}

// --- Engagements ---

export async function getEngagements(): Promise<{ engagements: EngagementListItem[]; active_id?: string }> {
  const response = await request('listEngagements');
  return { ...response, active_id: response.active_id ?? undefined };
}

export async function createEngagement(
  body: NonNullable<GeneratedDashboardRequestFor<'createEngagement'>['body']>,
): Promise<EngagementListItem> {
  return request('createEngagement', { body });
}

export async function createEngagementFromTemplate(
  templateId: string,
  overrides?: Record<string, unknown>,
): Promise<{ config: unknown; persisted: boolean; engagement?: EngagementListItem }> {
  // The endpoint persists the built config and returns { config, persisted, engagement }
  // — not a bare EngagementListItem.
  return request('createEngagementFromTemplate', { body: { template_id: templateId, overrides } });
}

export async function getEngagement(id: string): Promise<EngagementDetail> {
  return request('getEngagement', { path: { engagement_id: id } });
}

export async function updateEngagement(id: string, body: Record<string, unknown>): Promise<{ updated: boolean }> {
  return request('updateEngagement', { path: { engagement_id: id }, body });
}

// --- Phases ---

export async function getPhases(): Promise<unknown> {
  return request('getPhases');
}

// --- Evidence ---

export async function getEvidenceChains(nodeId: string): Promise<EvidenceChainResponse> {
  return request('getEvidenceChains', { path: { node_id: nodeId } });
}

// --- Action output (Analysis workspace) ---

export interface ActionOutputStream {
  /** null when capture failed before an id was assigned (see capture_failed). */
  evidence_id: string | null;
  text: string;
  total_bytes: number;
  /** The inline capture buffer overflowed while the tool ran (full blob on disk). */
  truncated: boolean;
  /** This response is only a head slice of a larger blob (fetch more for the rest). */
  head_truncated: boolean;
  dropped_bytes: number;
  /** Evidence id was recorded but the blob file is missing/unreadable. */
  missing?: boolean;
  /** The tool produced output but the capture write failed — bytes are lost. */
  capture_failed?: boolean;
}

export interface ActionOutputResponse {
  action_id: string;
  status: 'success' | 'failure' | 'partial' | 'neutral' | 'running';
  event_type?: string;
  timestamp?: string;
  tool_name?: string;
  command_repr?: string;
  technique?: string;
  invoking_tool?: string;
  exit_code?: number;
  signal?: string;
  duration_ms?: number;
  timed_out?: boolean;
  target_node_ids?: string[];
  target_ips?: string[];
  target_cidrs?: string[];
  agent_id?: string;
  frontier_item_id?: string;
  linked_finding_ids?: string[];
  max_bytes: number;
  stdout: ActionOutputStream | null;
  stderr: ActionOutputStream | null;
  capture_error?: unknown;
}

export interface EvidenceRawResponse {
  evidence_id: string | null;
  text: string;
  total_bytes: number;
  offset: number;
  bytes_read: number;
  eof: boolean;
  evidence_type?: string;
  capture_error?: string;
  action_id?: string;
  finding_id?: string;
}

export interface ReparseResponse {
  parsed: boolean;
  parse_status: 'ok' | 'no_data' | 'validation_failed' | 'parser_exception' | 'partial' | 'no_parser';
  parse_outcome: 'ok' | 'no_data' | 'validation_failed' | 'parser_exception' | 'partial';
  isError: boolean;
  tool: string;
  action_id: string;
  evidence_id?: string | null;
  finding_id?: string;
  nodes_parsed: number;
  edges_parsed: number;
  ingested?: false | { new_nodes: number; new_edges: number; inferred_edges: number };
  validation_errors?: unknown[];
  warnings?: string[];
  error?: string;
  parser_exception?: string;
  supported_parsers?: string[];
  failure_stage?: 'context' | 'parser_selection' | 'finding_validation';
  partial?: true;
  partial_reason?: string;
  parse_stream?: 'stdout' | 'stderr' | 'combined';
  parsed_from_evidence?: boolean;
  evidence_read_error?: string;
  exit_code?: number | null;
}

export async function getParsers(): Promise<{ parsers: string[] }> {
  return request('getParsers');
}

export async function reparseAction(
  actionId: string,
  opts: { tool_name: string; evidence_id?: string; ingest?: boolean; context?: Record<string, unknown> },
): Promise<ReparseResponse> {
  return request('reparseAction', { path: { action_id: actionId }, body: opts });
}

export async function getActionOutput(actionId: string, maxBytes?: number): Promise<ActionOutputResponse> {
  return request('getActionOutput', { path: { action_id: actionId }, query: { max_bytes: maxBytes } });
}

export async function getEvidenceRaw(
  evidenceId: string,
  opts?: { maxBytes?: number; offset?: number },
): Promise<EvidenceRawResponse> {
  return request('getEvidenceRaw', {
    path: { evidence_id: evidenceId },
    query: { max_bytes: opts?.maxBytes, offset: opts?.offset },
  });
}

export async function getPaths(objectiveId: string, params?: {
  limit?: number;
  optimize?: 'confidence' | 'stealth' | 'balanced';
}): Promise<{ paths: AttackPath[] }> {
  return request('getObjectivePaths', { path: { objective_id: objectiveId }, query: params });
}

/** Structured path finder (the Attack Paths "Custom path" picker). Returns 200
 *  with analysis_status even for no_path/missing_endpoint, so the caller renders
 *  a directed empty state rather than throwing. */
export async function findPaths(params: {
  from?: string;
  to?: string;
  objective?: string;
  optimize?: 'confidence' | 'stealth' | 'balanced';
  max?: number;
}): Promise<FindPathsResponse> {
  return request('findPaths', { query: params });
}

// --- Tools ---

export async function getTools(): Promise<ToolCheckResult> {
  return request('getTools');
}

export async function getMcpTools(): Promise<McpToolRegistryResponse> {
  return request('getMcpTools');
}

export async function getReadiness(): Promise<DashboardReadinessSummary> {
  return request('getReadiness') as unknown as Promise<DashboardReadinessSummary>;
}

export type TrustSignalSeverity = 'error' | 'warning' | 'info';
export type TrustSignalSource = 'activity' | 'finding';

export interface TrustSignalDto {
  id: string;
  severity: TrustSignalSeverity;
  label: string;
  detail?: string;
  action?: string;
  timestamp?: string;
  source: TrustSignalSource;
  source_event?: {
    event_id?: string;
    event_type?: string;
    description?: string;
  };
  action_id?: string;
  frontier_item_id?: string;
  finding_id?: string;
  node_ids?: string[];
}

export interface TrustSignalsResponse {
  generated_at: string;
  total: number;
  counts: Record<TrustSignalSeverity, number>;
  signals: TrustSignalDto[];
}

export async function getTrustSignals(params?: {
  limit?: number;
  node_id?: string;
  finding_id?: string;
  severity?: TrustSignalSeverity;
}): Promise<TrustSignalsResponse> {
  return request('getTrustSignals', { query: params }) as unknown as Promise<TrustSignalsResponse>;
}

// --- Inference Rules ---

export async function getInferenceRules(): Promise<{ rules: InferenceRuleInfo[]; total: number }> {
  return request('getInferenceRules') as unknown as Promise<{ rules: InferenceRuleInfo[]; total: number }>;
}

// --- Graph Export ---

export async function exportGraphJson(): Promise<RawGraphDto> {
  return request('exportGraph');
}

// --- Graph Correct ---

export type GraphCorrectionOperation = GraphCorrectionOperationDto;
export type GraphCorrectionResult = GraphCorrectionResultDto;

export async function correctGraph(
  reason: string,
  operations: GraphCorrectionOperation[],
): Promise<GraphCorrectionResult> {
  return request('correctGraph', { body: { reason, operations } });
}

// --- Telemetry ---

export interface TelemetryResponse {
  tool_telemetry: TelemetrySummary | null;
  inference_effectiveness: InferenceRuleEffectiveness[];
  health: {
    status: 'healthy' | 'warning' | 'critical';
    counts: { warning: number; critical: number };
    top_issues: Array<{ check: string; severity: string; message: string; node_ids?: string[] }>;
  };
  graph_stats: {
    total_nodes: number;
    total_edges: number;
    confirmed_edges: number;
    inferred_edges: number;
  };
  credential_coverage: CredentialCoverage | null;
}

export async function getTelemetry(): Promise<TelemetryResponse> {
  return request('getTelemetry') as unknown as Promise<TelemetryResponse>;
}

// --- Tape recorder ---

export interface TapeStatus {
  enabled: boolean;
  path?: string | null;
  frame_count: number;
  accepted_frame_count?: number;
  dropped_frame_count?: number;
  session_id?: string | null;
  started_at?: string | null;
  started_by?: 'env' | 'config' | 'dashboard' | null;
  error?: string;
}

export async function getTapeStatus(): Promise<TapeStatus> {
  return request('getTapeStatus');
}

export async function toggleTape(opts?: {
  action?: 'enable' | 'disable';
  dir?: string;
  file?: string;
  session_id?: string;
}): Promise<TapeStatus> {
  // The shared request helper throws non-2xx responses; its generated return
  // union still includes documented 400/503 error bodies for lower-level
  // callers, so this ergonomic wrapper narrows the fulfilled value to 200.
  return request('toggleTape', { body: opts ?? {} }) as unknown as Promise<TapeStatus>;
}

// --- B.2 / B.3 Findings + Reports ---

export interface FindingClassificationLite {
  cwe?: { id: string; name: string };
  owasp_top_10?: { id: string; name: string };
  nist_800_53?: Array<{ id: string; name: string }>;
  pci_dss?: Array<{ id: string; requirement: string }>;
  attack_techniques?: Array<{ id: string; name: string }>;
}

export interface FindingPresentationDto {
  title: string;
  short_title?: string;
  summary: string;
  impact: string;
  evidence_claim?: string;
  technical_context?: string;
  remediation_steps: string[];
}

export interface FindingDto {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  tier?: string;
  description: string;
  affected_assets: string[];
  remediation: string;
  presentation?: FindingPresentationDto;
  risk_score: number;
  cvss_score?: number;
  cvss_vector?: string;
  cvss_estimated?: boolean;
  classification?: FindingClassificationLite;
}

export interface FindingsResponse {
  findings: FindingDto[];
  total: number;
  severity_summary: { critical: number; high: number; medium: number; low: number; info: number };
}

function normalizeFinding(
  { classification, ...finding }: FindingsResponseDto['findings'][number],
): FindingDto {
  return {
    ...finding,
    classification: classification
      ? {
          cwe: classification.cwe
            ? { id: classification.cwe, name: classification.cwe_name ?? classification.cwe }
            : undefined,
          owasp_top_10: classification.owasp_category
            ? {
                id: classification.owasp_category.split(/\s+/, 1)[0],
                name: classification.owasp_category,
              }
            : undefined,
          nist_800_53: classification.nist_controls.map(id => ({ id, name: id })),
          pci_dss: classification.pci_requirements.map(requirement => ({
            id: requirement,
            requirement,
          })),
          attack_techniques: classification.attack_techniques,
        }
      : undefined,
  };
}

export function normalizeFindingsResponse(wire: FindingsResponseDto): FindingsResponse {
  return {
    ...wire,
    findings: wire.findings.map(normalizeFinding),
  };
}

export async function getFindings(): Promise<FindingsResponse> {
  const wire = FindingsResponseSchema.parse(await request('getFindings'));
  return normalizeFindingsResponse(wire);
}

export async function getFindingContext(id: string): Promise<FindingContextResponse> {
  const response = await request('getFindingContext', { path: { finding_id: id } });
  const finding = normalizeFinding(FindingDtoSchema.parse(response.finding));
  return { ...response, finding } as unknown as FindingContextResponse;
}

export type ReportRecord = ReportRecordDto;
export type ReportsListResponse = ReportsListResponseDto;

export async function listReports(): Promise<ReportsListResponse> {
  return request('listReports');
}

export interface RenderReportBody {
  format?: 'markdown' | 'html' | 'json' | 'pdf';
  include_evidence?: boolean;
  include_narrative?: boolean;
  include_retrospective?: boolean;
  include_compliance?: boolean;
  include_attack_paths?: boolean;
  client_safe?: boolean;
  profile?: 'operator' | 'client';
  evidence_style?: 'proof_cards' | 'appendix' | 'full_inline';
  theme?: 'light' | 'dark';
  max_paths_per_objective?: number;
}

export async function renderReport(body: RenderReportBody): Promise<ReportRenderResponseDto> {
  return request('renderReport', { body });
}

/** Returns the absolute URL — caller can use `window.location.href = url` or `<a download>`. */
export function reportDownloadUrl(id: string): string {
  return buildDashboardPath('downloadReport', { report_id: id });
}

/** Returns an inline URL for browser-readable report formats. */
export function reportOpenUrl(id: string): string {
  return `${buildDashboardPath('downloadReport', { report_id: id })}?disposition=inline`;
}

export type ReportDeleteResult = GeneratedDashboardOutput<'deleteReport'>;

export async function deleteReport(id: string): Promise<ReportDeleteResult> {
  return request('deleteReport', { path: { report_id: id } });
}
