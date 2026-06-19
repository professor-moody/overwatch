import type {
  EngagementState,
  ExportedGraph,
  ActivityEntry,
  DecisionLogEntry,
  ActionExplanation,
  TimelineEntry,
  SessionInfo,
  SessionBufferResponse,
  AgentInfo,
  AgentConsoleEvent,
  Campaign,
  PendingAction,
  ActionQueueDiagnostics,
  HealthStatus,
  EvidenceChainResponse,
  FindingContextResponse,
  AttackPath,
  FrontierItem,
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

const BASE = '';

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${url}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`${res.status} ${res.statusText}: ${body}`);
  }
  return res.json() as Promise<T>;
}

// --- State ---

export async function getState(): Promise<{ state: EngagementState; graph: ExportedGraph; history_count: number }> {
  return fetchJson('/api/state');
}

export async function getGraph(): Promise<ExportedGraph> {
  return fetchJson('/api/graph');
}

// --- History ---

export async function getHistory(params?: {
  limit?: number;
  after?: string;
  before?: string;
}): Promise<{ entries: ActivityEntry[]; total: number }> {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.after) qs.set('after', params.after);
  if (params?.before) qs.set('before', params.before);
  const q = qs.toString();
  return fetchJson(`/api/history${q ? `?${q}` : ''}`);
}

export async function getDecisionLog(params?: {
  limit?: number;
  action_id?: string;
  frontier_item_id?: string;
  agent_id?: string;
  outcome?: string;
}): Promise<{ decisions: DecisionLogEntry[]; total: number }> {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.action_id) qs.set('action_id', params.action_id);
  if (params?.frontier_item_id) qs.set('frontier_item_id', params.frontier_item_id);
  if (params?.agent_id) qs.set('agent_id', params.agent_id);
  if (params?.outcome) qs.set('outcome', params.outcome);
  const q = qs.toString();
  return fetchJson(`/api/decision-log${q ? `?${q}` : ''}`);
}

export async function explainAction(id: string): Promise<ActionExplanation> {
  return fetchJson(`/api/actions/${encodeURIComponent(id)}/explain`);
}

export async function getTimeline(params?: {
  limit?: number;
  entity_id?: string;
  kind?: 'node' | 'edge';
  since?: string;
  at?: string;
}): Promise<{ entries: TimelineEntry[]; total: number }> {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.entity_id) qs.set('entity_id', params.entity_id);
  if (params?.kind) qs.set('kind', params.kind);
  if (params?.since) qs.set('since', params.since);
  if (params?.at) qs.set('at', params.at);
  const q = qs.toString();
  return fetchJson(`/api/timeline${q ? `?${q}` : ''}`);
}

// --- Sessions ---

export async function getSessions(): Promise<{ sessions: SessionInfo[]; total: number; active: number }> {
  return fetchJson('/api/sessions');
}

export async function closeSession(id: string): Promise<{ metadata: SessionInfo; final: { text: string; end_pos: number } }> {
  return fetchJson(`/api/sessions/${id}/close`, { method: 'POST' });
}

export async function updateSession(id: string, body: { title?: string; notes?: string }): Promise<{ metadata: SessionInfo }> {
  return fetchJson(`/api/sessions/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

export async function getSessionBuffer(id: string, params?: { from?: number; tailBytes?: number }): Promise<SessionBufferResponse> {
  const qs = new URLSearchParams();
  if (params?.from !== undefined) qs.set('from', String(params.from));
  if (params?.tailBytes !== undefined) qs.set('tail_bytes', String(params.tailBytes));
  const q = qs.toString();
  return fetchJson(`/api/sessions/${id}/buffer${q ? `?${q}` : ''}`);
}

// --- Agents ---

export async function getAgents(): Promise<{ agents: AgentInfo[] }> {
  return fetchJson('/api/agents');
}

export async function getAgentContext(agentId: string): Promise<unknown> {
  return fetchJson(`/api/agents/${agentId}/context`);
}

export async function cancelAgent(agentId: string): Promise<{ ok: boolean }> {
  return fetchJson(`/api/agents/${agentId}/cancel`, { method: 'POST' });
}

export type DirectiveKind = 'pause' | 'resume' | 'stop' | 'narrow_scope' | 'skip_types' | 'prioritize' | 'instruct';

/**
 * Steer a single running agent. Routes through the same validated executeOps
 * path as the command bar (POST /api/agents/:id/directive). 200 with the op
 * result, 409 if the agent isn't running, 400 on an unknown kind.
 */
export async function issueDirective(
  taskId: string,
  kind: DirectiveKind,
  opts: { node_ids?: string[]; frontier_types?: string[]; note?: string } = {},
): Promise<{ ok: boolean; results: unknown[] }> {
  return fetchJson(`/api/agents/${encodeURIComponent(taskId)}/directive`, {
    method: 'POST',
    body: JSON.stringify({ kind, ...opts }),
  });
}

/** Fleet-level steering: apply pause/resume/stop to ALL running agents (optionally one campaign). */
export async function fleetDirective(
  kind: 'pause' | 'resume' | 'stop',
  campaignId?: string,
): Promise<{ ok: boolean; applied: number; total: number }> {
  return fetchJson('/api/fleet/directive', {
    method: 'POST',
    body: JSON.stringify({ kind, campaign_id: campaignId }),
  });
}

export interface DispatchAgentResult {
  dispatched: boolean;
  task?: { id: string; agent_id: string };
  reason?: string;
  existing_task_id?: string;
  existing_agent_id?: string;
}

export interface AgentArchetypeSummary {
  id: string;
  label: string;
  description: string;
  role: string;
  defaultSkill?: string;
  suitableFor: { frontierTypes?: string[]; nodeTypes?: string[]; rawTarget?: boolean };
}

/** The agent-type catalog for the Deploy picker (Phase 5c). */
export async function getArchetypes(): Promise<{ archetypes: AgentArchetypeSummary[] }> {
  return fetchJson('/api/agent-archetypes');
}

export interface QuickDeployResult {
  dispatched: boolean;
  task?: { id: string; agent_id: string; archetype?: string; objective?: string };
  archetype?: string;
  scope?: { added_cidrs: string[]; added_domains: string[]; affected_node_count: number };
  reason?: string;
}

/** Ad-hoc real-time deploy: scope a raw IP/CIDR/domain + dispatch an agent at it.
 *  201 success and 409 refusal return structured results so the UI can render a
 *  clean toast; a 400 (e.g. engine scope validation rejecting a CIDR the loose
 *  client regex let through) is normalized to a non-dispatched result with the
 *  server's message; only unexpected statuses throw. */
export async function quickDeploy(body: { target: string; archetype?: string }): Promise<QuickDeployResult> {
  const res = await fetch(`${BASE}/api/agents/quick-deploy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (res.status === 201 || res.status === 409) {
    return res.json() as Promise<QuickDeployResult>;
  }
  if (res.status === 400) {
    const j = await res.json().catch(() => ({})) as { error?: string; reason?: string };
    return { dispatched: false, reason: j.reason || j.error || 'invalid request' };
  }
  const text = await res.text().catch(() => '');
  throw new Error(`${res.status} ${res.statusText}: ${text}`);
}

export async function dispatchAgent(body: {
  target_node_ids?: string[];
  skill?: string;
  campaign_id?: string;
  frontier_item_id?: string;
  archetype?: string;
}): Promise<DispatchAgentResult> {
  // The server (handleAgentDispatch) reads `target_node_ids` (400s on empty) and
  // returns 409 with { dispatched:false, reason:'frontier_lease_conflict', ... }
  // when the item is already leased. Treat that 409 as a STRUCTURED result (not
  // an exception) so callers can show "already being worked" cleanly; other
  // non-2xx still throw.
  const res = await fetch(`${BASE}/api/agents/dispatch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (res.status === 201 || res.status === 409) {
    return res.json() as Promise<DispatchAgentResult>;
  }
  const text = await res.text().catch(() => '');
  throw new Error(`${res.status} ${res.statusText}: ${text}`);
}

// --- NL operator cockpit (Phase 3A) ---

export interface OperatorOp {
  op: 'directive' | 'scope' | 'approve' | 'deny';
  [key: string]: unknown;
}

export interface CommandOpResult {
  op: OperatorOp;
  ok: boolean;
  detail?: string;
  error?: string;
}

/** A read-only query answer rendered inline in the command bar (no confirm). */
export interface QueryAnswer {
  kind: 'changes_since' | 'timeline' | 'list_nodes' | 'finding_readiness' | 'find_paths' | 'retrospective' | 'unanswerable';
  summary: string;
  rows?: string[];
  total?: number;
  note?: string;
}

export interface CommandPreview {
  plan_id?: string;
  ops: OperatorOp[];
  summary: string;
  unresolved: { text: string; reason: string }[];
  needs_planner: boolean;
  planner_task_id?: string;
  planner_available?: boolean;
  /** Present when the input was a read-only query; render directly, no confirm. */
  query_answer?: QueryAnswer;
}

export interface ProposedPlan {
  plan_id: string;
  command: string;
  ops: OperatorOp[];
  summary: string;
  rationale?: string;
  source_task_id?: string;
  source_agent_id?: string;
  created_at: number;
  status: string;
}

/** Phase 1: interpret a free-form command into a previewable plan (no mutation). */
export async function previewCommand(command: string): Promise<CommandPreview> {
  return fetchJson('/api/commands', { method: 'POST', body: JSON.stringify({ command }) });
}

/** Phase 2: confirm + execute a previewed/proposed plan by id. */
export async function confirmCommand(planId: string): Promise<{ executed: boolean; results: CommandOpResult[] }> {
  return fetchJson('/api/commands', { method: 'POST', body: JSON.stringify({ confirm: true, plan_id: planId }) });
}

/** Dismiss a planner-proposed plan without executing it. */
export async function denyCommandPlan(planId: string): Promise<{ denied: boolean }> {
  return fetchJson('/api/commands', { method: 'POST', body: JSON.stringify({ deny: true, plan_id: planId }) });
}

/** Open planner-proposed plans awaiting operator confirmation. */
export async function getProposedPlans(): Promise<{ plans: ProposedPlan[] }> {
  return fetchJson('/api/plans');
}

// --- Agent→operator question inbox (Phase 3D) ---

export interface AgentQuery {
  query_id: string;
  task_id?: string;
  agent_id?: string;
  question: string;
  options?: string[];
  status: string;
  answer?: string;
  created_at: number;
}

/** Open questions agents are waiting on. */
export async function getAgentQueries(): Promise<{ queries: AgentQuery[] }> {
  return fetchJson('/api/agent-queries');
}

/** Answer an agent's question — delivered to the agent on its next heartbeat. */
export async function answerAgentQuery(queryId: string, answer: string): Promise<{ ok: boolean }> {
  return fetchJson(`/api/agent-queries/${encodeURIComponent(queryId)}/answer`, {
    method: 'POST',
    body: JSON.stringify({ answer }),
  });
}

/** Answer-once fan-out: resolve a cluster of identical questions (asked by
 *  several agents) with one answer. Each still-running agent picks it up on its
 *  next heartbeat. */
export async function answerAgentQueryBatch(queryIds: string[], answer: string): Promise<{ ok: boolean; answered: number }> {
  return fetchJson('/api/agent-queries/answer-batch', {
    method: 'POST',
    body: JSON.stringify({ query_ids: queryIds, answer }),
  });
}

// --- Campaigns ---

export async function getCampaigns(): Promise<{ campaigns: Campaign[] }> {
  return fetchJson('/api/campaigns');
}

export async function getCampaign(id: string): Promise<Campaign> {
  return fetchJson(`/api/campaigns/${id}`);
}

export async function createCampaign(body: {
  name: string;
  strategy: string;
  item_ids?: string[];
  items?: FrontierItem[];
  abort_conditions?: unknown[];
}): Promise<Campaign> {
  return fetchJson('/api/campaigns', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function updateCampaign(id: string, body: Partial<Campaign>): Promise<Campaign> {
  return fetchJson(`/api/campaigns/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

export async function deleteCampaign(id: string): Promise<{ ok: boolean }> {
  return fetchJson(`/api/campaigns/${id}`, { method: 'DELETE' });
}

export async function campaignAction(id: string, action: 'activate' | 'pause' | 'resume' | 'abort' | 'complete'): Promise<Campaign> {
  return fetchJson(`/api/campaigns/${id}/action`, {
    method: 'POST',
    body: JSON.stringify({ action }),
  });
}

export async function dispatchCampaign(id: string, body?: {
  max_agents?: number;
  scope_hops?: number;
  skill?: string;
  throttle_seconds?: number;
}): Promise<unknown> {
  return fetchJson(`/api/campaigns/${id}/dispatch`, {
    method: 'POST',
    body: JSON.stringify(body || {}),
  });
}

export async function cloneCampaign(id: string): Promise<Campaign> {
  return fetchJson(`/api/campaigns/${id}/clone`, { method: 'POST' });
}

export async function splitCampaign(id: string, body: { item_ids: string[] }): Promise<Campaign> {
  return fetchJson(`/api/campaigns/${id}/split`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function getCampaignChildren(id: string): Promise<{ campaigns: Campaign[] }> {
  return fetchJson(`/api/campaigns/${id}/children`);
}

// --- Pending Actions ---

export async function getPendingActions(): Promise<{ pending: PendingAction[]; recent?: PendingAction[]; diagnostics?: ActionQueueDiagnostics }> {
  return fetchJson('/api/actions/pending');
}

export async function approveAction(id: string, modifications?: Record<string, unknown>): Promise<unknown> {
  return fetchJson(`/api/actions/${id}/approve`, {
    method: 'POST',
    body: JSON.stringify(modifications || {}),
  });
}

export async function denyAction(id: string, reason?: string): Promise<unknown> {
  return fetchJson(`/api/actions/${id}/deny`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

// --- Config / Settings ---

export async function getConfig(): Promise<EngagementConfig> {
  return fetchJson('/api/config');
}

export async function updateConfig(body: Partial<EngagementConfig>): Promise<{ updated: boolean }> {
  return fetchJson('/api/config', {
    method: 'PATCH',
    body: JSON.stringify(body),
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
  return fetchJson('/api/config/scope/preview', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function updateScope(body: Partial<ScopeConfig>): Promise<ScopeUpdateResult> {
  return fetchJson('/api/config/scope', {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

export async function addObjective(body: {
  description: string;
  target_node_type?: string;
  achievement_edge_types?: string[];
}): Promise<unknown> {
  return fetchJson('/api/config/objectives', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function updateObjective(id: string, body: Record<string, unknown>): Promise<unknown> {
  return fetchJson(`/api/config/objectives/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

export async function deleteObjective(id: string): Promise<unknown> {
  return fetchJson(`/api/config/objectives/${id}`, { method: 'DELETE' });
}

export async function getSettings(): Promise<{ settings: OpsecConfig & Record<string, unknown> }> {
  return fetchJson('/api/settings');
}

export async function updateSettings(body: Partial<OpsecConfig>): Promise<unknown> {
  return fetchJson('/api/settings', {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

export async function getFrontierWeights(): Promise<FrontierWeights> {
  return fetchJson('/api/frontier/weights');
}

export async function updateFrontierWeights(body: Partial<FrontierWeights>): Promise<{ updated: boolean }> {
  return fetchJson('/api/frontier/weights', {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

export async function resetFrontierWeights(): Promise<{ updated: boolean }> {
  return fetchJson('/api/frontier/weights/reset', { method: 'POST' });
}

// --- OPSEC Budget ---

export async function getOpsecBudget(): Promise<OpsecBudget> {
  return fetchJson('/api/opsec/budget');
}

// --- Agent History ---

export async function getAgentHistory(taskId: string): Promise<{ entries: ActivityEntry[]; total: number }> {
  return fetchJson(`/api/agents/${taskId}/history`);
}

export async function getAgentConsole(taskId: string, params?: {
  limit?: number;
  after?: string;
}): Promise<{ events: AgentConsoleEvent[]; total: number }> {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.after) qs.set('after', params.after);
  const q = qs.toString();
  return fetchJson(`/api/agents/${taskId}/console${q ? `?${q}` : ''}`);
}

// --- Health ---

export async function getHealth(): Promise<HealthStatus> {
  return fetchJson('/api/health');
}

// --- Templates ---

export async function getTemplates(): Promise<{ templates: EngagementTemplate[]; total: number }> {
  return fetchJson('/api/templates');
}

// --- Engagements ---

export async function getEngagements(): Promise<{ engagements: EngagementListItem[]; active_id?: string }> {
  return fetchJson('/api/engagements');
}

export async function createEngagement(body: Record<string, unknown>): Promise<EngagementListItem> {
  return fetchJson('/api/engagements', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function createEngagementFromTemplate(templateId: string, overrides?: Record<string, unknown>): Promise<EngagementListItem> {
  return fetchJson('/api/engagements/from-template', {
    method: 'POST',
    body: JSON.stringify({ template_id: templateId, overrides }),
  });
}

export async function getEngagement(id: string): Promise<EngagementDetail> {
  return fetchJson(`/api/engagements/${encodeURIComponent(id)}`);
}

export async function updateEngagement(id: string, body: Record<string, unknown>): Promise<{ updated: boolean }> {
  return fetchJson(`/api/engagements/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

// --- Phases ---

export async function getPhases(): Promise<unknown> {
  return fetchJson('/api/phases');
}

// --- Evidence ---

export async function getEvidenceChains(nodeId: string): Promise<EvidenceChainResponse> {
  return fetchJson(`/api/evidence-chains/${encodeURIComponent(nodeId)}`);
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
  parse_status: 'ok' | 'no_data' | 'validation_failed' | 'parser_exception' | 'no_parser';
  isError: boolean;
  tool: string;
  action_id: string;
  evidence_id?: string | null;
  finding_id?: string;
  nodes_parsed: number;
  edges_parsed: number;
  ingested?: { new_nodes: number; new_edges: number; inferred_edges: number };
  validation_errors?: unknown[];
  warnings?: string[];
  error?: string;
  supported_parsers?: string[];
}

export async function getParsers(): Promise<{ parsers: string[] }> {
  return fetchJson('/api/parsers');
}

export async function reparseAction(
  actionId: string,
  opts: { tool_name: string; evidence_id?: string; ingest?: boolean; context?: Record<string, unknown> },
): Promise<ReparseResponse> {
  return fetchJson(`/api/actions/${encodeURIComponent(actionId)}/reparse`, {
    method: 'POST',
    body: JSON.stringify(opts),
  });
}

export async function getActionOutput(actionId: string, maxBytes?: number): Promise<ActionOutputResponse> {
  const qs = maxBytes ? `?max_bytes=${maxBytes}` : '';
  return fetchJson(`/api/actions/${encodeURIComponent(actionId)}/output${qs}`);
}

export async function getEvidenceRaw(
  evidenceId: string,
  opts?: { maxBytes?: number; offset?: number },
): Promise<EvidenceRawResponse> {
  const qs = new URLSearchParams();
  if (opts?.maxBytes) qs.set('max_bytes', String(opts.maxBytes));
  if (opts?.offset) qs.set('offset', String(opts.offset));
  const q = qs.toString();
  return fetchJson(`/api/evidence/${encodeURIComponent(evidenceId)}/raw${q ? `?${q}` : ''}`);
}

export async function getPaths(objectiveId: string, params?: {
  limit?: number;
  optimize?: 'confidence' | 'stealth' | 'balanced';
}): Promise<{ paths: AttackPath[] }> {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.optimize) qs.set('optimize', params.optimize);
  const q = qs.toString();
  return fetchJson(`/api/paths/${encodeURIComponent(objectiveId)}${q ? `?${q}` : ''}`);
}

// --- Tools ---

export async function getTools(): Promise<ToolCheckResult> {
  return fetchJson('/api/tools');
}

export async function getMcpTools(): Promise<McpToolRegistryResponse> {
  return fetchJson('/api/mcp-tools');
}

export async function getReadiness(): Promise<DashboardReadinessSummary> {
  return fetchJson('/api/readiness');
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
  const qs = new URLSearchParams();
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.node_id) qs.set('node_id', params.node_id);
  if (params?.finding_id) qs.set('finding_id', params.finding_id);
  if (params?.severity) qs.set('severity', params.severity);
  const q = qs.toString();
  return fetchJson(`/api/trust-signals${q ? `?${q}` : ''}`);
}

// --- Inference Rules ---

export async function getInferenceRules(): Promise<{ rules: InferenceRuleInfo[]; total: number }> {
  return fetchJson('/api/inference-rules');
}

// --- Graph Export ---

export async function exportGraphJson(): Promise<ExportedGraph> {
  return fetchJson('/api/graph/export', { method: 'POST' });
}

// --- Graph Correct ---

export interface GraphCorrectionOperation {
  kind: 'drop_edge' | 'replace_edge' | 'patch_node';
  source_id?: string;
  target_id?: string;
  edge_type?: string;
  new_source_id?: string;
  new_target_id?: string;
  new_edge_type?: string;
  node_id?: string;
  patch?: Record<string, unknown>;
}

export interface GraphCorrectionResult {
  dropped_edges: string[];
  replaced_edges: Array<{ old_edge_id: string; new_edge_id: string }>;
  patched_nodes: string[];
}

export async function correctGraph(
  reason: string,
  operations: GraphCorrectionOperation[],
): Promise<GraphCorrectionResult> {
  return fetchJson('/api/graph/correct', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason, operations }),
  });
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
  return fetchJson('/api/telemetry');
}

// --- Tape recorder ---

export interface TapeStatus {
  enabled: boolean;
  path?: string | null;
  frame_count?: number;
  session_id?: string | null;
  started_at?: string | null;
  started_by?: 'env' | 'config' | 'dashboard' | null;
}

export async function getTapeStatus(): Promise<TapeStatus> {
  return fetchJson('/api/tape');
}

export async function toggleTape(opts?: {
  action?: 'enable' | 'disable';
  dir?: string;
  file?: string;
  session_id?: string;
}): Promise<TapeStatus> {
  return fetchJson('/api/tape/toggle', {
    method: 'POST',
    body: JSON.stringify(opts ?? {}),
  });
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

export async function getFindings(): Promise<FindingsResponse> {
  return fetchJson('/api/findings');
}

export async function getFindingContext(id: string): Promise<FindingContextResponse> {
  return fetchJson(`/api/findings/${encodeURIComponent(id)}/context`);
}

export interface ReportRecord {
  id: string;
  generated_at: string;
  format: 'markdown' | 'html' | 'json' | 'pdf';
  redaction_mode: 'operator' | 'client_safe';
  profile?: 'operator' | 'client';
  evidence_style?: 'proof_cards' | 'appendix' | 'full_inline';
  findings_count?: number;
  evidence_count?: number;
  filename: string;
  size_bytes: number;
  content_sha256: string;
  options: Record<string, unknown>;
}

export interface ReportsListResponse {
  reports: ReportRecord[];
  total: number;
  total_bytes: number;
}

export async function listReports(): Promise<ReportsListResponse> {
  return fetchJson('/api/reports');
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

export async function renderReport(body: RenderReportBody): Promise<{ report: ReportRecord; findings_count: number; evidence_count: number; severity_summary: FindingsResponse['severity_summary'] }> {
  return fetchJson('/api/reports/render', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/** Returns the absolute URL — caller can use `window.location.href = url` or `<a download>`. */
export function reportDownloadUrl(id: string): string {
  return `/api/reports/${id}`;
}

/** Returns an inline URL for browser-readable report formats. */
export function reportOpenUrl(id: string): string {
  return `/api/reports/${id}?disposition=inline`;
}

export async function deleteReport(id: string): Promise<{ deleted: boolean }> {
  return fetchJson(`/api/reports/${id}`, { method: 'DELETE' });
}
