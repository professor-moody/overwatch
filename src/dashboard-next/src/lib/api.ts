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
  Campaign,
  PendingAction,
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

export async function dispatchAgent(body: {
  node_ids?: string[];
  skill?: string;
  campaign_id?: string;
}): Promise<unknown> {
  return fetchJson('/api/agents/dispatch', {
    method: 'POST',
    body: JSON.stringify(body),
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

export async function getPendingActions(): Promise<{ pending: PendingAction[] }> {
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

export async function updateScope(body: Partial<ScopeConfig>): Promise<unknown> {
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

export async function renderReport(body: RenderReportBody): Promise<{ report: ReportRecord; findings_count: number; severity_summary: FindingsResponse['severity_summary'] }> {
  return fetchJson('/api/reports/render', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/** Returns the absolute URL — caller can use `window.location.href = url` or `<a download>`. */
export function reportDownloadUrl(id: string): string {
  return `/api/reports/${id}`;
}

export async function deleteReport(id: string): Promise<{ deleted: boolean }> {
  return fetchJson(`/api/reports/${id}`, { method: 'DELETE' });
}
