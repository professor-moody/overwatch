// Re-export and extend types from the backend for dashboard use.
// We define dashboard-specific interfaces here rather than importing
// directly from ../../types.ts (which uses Node16 module resolution).

// --- Node Types ---

export const NODE_TYPES = [
  'host', 'service', 'domain', 'user', 'group', 'credential',
  'share', 'certificate', 'ca', 'cert_template', 'pki_store', 'gpo', 'ou', 'subnet', 'objective',
  'webapp', 'vulnerability', 'api_endpoint',
  'cloud_identity', 'cloud_resource', 'cloud_policy', 'cloud_network',
  // Identity tier (Phase 1 enterprise readiness — SSO / IdP modeling). Mirrors
  // the backend union in src/types.ts.
  'idp', 'idp_application', 'idp_principal',
  'mock_service',
] as const;

export type NodeType = typeof NODE_TYPES[number];

// --- Graph Export Format (matches GraphEngine.exportGraph()) ---

export interface ExportedNode {
  id: string;
  type: NodeType;
  label: string;
  confidence: number;
  discovered_at: string;
  community_id?: number;
  [key: string]: unknown;
}

export interface ExportedEdge {
  id?: string;
  source: string;
  target: string;
  type: string;
  confirmed?: boolean;
  inferred?: boolean;
  confidence?: number;
  [key: string]: unknown;
}

export interface ExportedGraph {
  nodes: ExportedNode[];
  edges: ExportedEdge[];
}

// --- Frontier ---

export interface FrontierItem {
  id: string;
  type: 'incomplete_node' | 'untested_edge' | 'inferred_edge' | 'network_discovery' | 'credential_test';
  priority: number;
  description: string;
  target_node?: string;
  source_node?: string;
  node_id?: string;
  edge_source?: string;
  edge_target?: string;
  edge_type?: string;
  chain_id?: string;
  chain_depth?: number;
  chain_completion_pct?: number;
  frontier_item_id?: string;
  opsec_noise?: number;
  missing_properties?: string[];
  graph_metrics?: {
    hops_to_objective?: number;
    fan_out_estimate?: number;
    confidence?: number;
    node_degree?: number;
    [key: string]: unknown;
  };
}

// --- Objectives ---

export interface Objective {
  id: string;
  description: string;
  achieved: boolean;
  achieved_at?: string;
  target_node_type?: string;
  achievement_edge_types?: string[];
}

// --- Agents ---

export interface AgentInfo {
  id: string;
  agent_id?: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'interrupted';
  task: string;
  skill?: string;
  scope_node_ids?: string[];
  subgraph_node_ids?: string[];
  started_at?: string;
  assigned_at?: string;
  completed_at?: string;
  elapsed_ms?: number;
  findings_count?: number;
  result_summary?: string;
  campaign_id?: string;
  campaign?: { id: string; name: string; strategy: string };
  frontier_item_id?: string;
  // 3C "see everything": the agent's most recent activity, derived server-side.
  current_action?: string;
  current_action_type?: string;
  current_action_at?: string;
  last_finding_at?: string;
  queued?: boolean;
}

export type AgentConsoleKind =
  | 'thought'
  | 'action'
  | 'approval'
  | 'finding'
  | 'session'
  | 'transcript'
  | 'system'
  | 'command';

export type AgentConsoleSeverity = 'info' | 'success' | 'warning' | 'error';

export interface AgentConsoleLinks {
  action_id?: string;
  frontier_item_id?: string;
  evidence_id?: string;
  session_id?: string;
  finding_ids?: string[];
  node_ids?: string[];
}

export interface AgentConsoleEvent {
  id: string;
  timestamp: string;
  agent_id: string;
  source_kind?: 'primary' | 'subagent' | 'runner' | 'system' | 'dashboard';
  source_label?: string;
  kind: AgentConsoleKind;
  severity: AgentConsoleSeverity;
  title: string;
  summary: string;
  status?: string;
  links?: AgentConsoleLinks;
  raw?: Record<string, unknown>;
}

// --- Campaigns ---

export interface Campaign {
  id: string;
  name: string;
  strategy: 'credential_spray' | 'enumeration' | 'post_exploitation' | 'network_discovery' | 'custom';
  status: 'draft' | 'active' | 'paused' | 'completed' | 'aborted';
  items: Array<FrontierItem | string>;
  abort_conditions?: AbortCondition[];
  progress?: {
    total: number;
    completed: number;
    succeeded: number;
    failed: number;
    consecutive_failures: number;
  };
  created_at: string;
  started_at?: string;
  completed_at?: string;
  completion_pct?: number;
  findings_count?: number;
  agents_active?: number;
  agents_total?: number;
  agent_count?: number;
  running_agents?: number;
  parent_id?: string;
}

export interface AbortCondition {
  type: 'max_failures' | 'timeout' | 'custom';
  value: number | string;
  description?: string;
}

// --- Sessions ---

export interface SessionInfo {
  id: string;
  kind: string;
  transport?: string;
  state: 'pending' | 'connected' | 'closed' | 'error';
  mode?: 'connect' | 'listen';
  bind_host?: string;
  advertise_host?: string;
  accept_mode?: 'single' | 'rearm';
  reachability_warnings?: string[];
  auth_status?: 'shell_confirmed' | 'connected_unconfirmed' | 'auth_prompt' | 'auth_failed';
  title?: string;
  host?: string;
  user?: string;
  port?: number;
  pid?: number;
  owner?: string;
  agent_id?: string;
  target_node?: string;
  principal_node?: string;
  credential_node?: string;
  action_id?: string;
  frontier_item_id?: string;
  claimed_by?: string;
  created_at?: string;
  started_at?: string;
  last_activity_at?: string;
  closed_at?: string;
  capabilities?: {
    has_stdin?: boolean;
    has_stdout?: boolean;
    supports_resize?: boolean;
    supports_signals?: boolean;
    tty_quality?: string;
  };
  buffer_end_pos?: number;
  notes?: string;
  default_validation?: {
    technique?: string;
    target_ip?: string;
    target_url?: string;
    allow_unverified_scope?: boolean;
  };
}

export interface SessionBufferResponse {
  session_id: string;
  start_pos: number;
  end_pos: number;
  text: string;
  truncated: boolean;
}

// --- Pending Actions ---

export interface PendingAction {
  action_id: string;
  technique?: string;
  target?: string;
  target_node?: string;
  target_ip?: string;
  target_cidr?: string;
  noise_level?: number;
  description: string;
  defense_context?: string;
  submitted_at: string;
  timeout_at?: string;
  resolved_at?: string;
  status?: 'pending' | 'approved' | 'denied' | 'timeout';
  operator_notes?: string;
  reason?: string;
  auto_approved?: boolean;
  unattended_execute?: boolean;
  frontier_item_id?: string;
  agent_id?: string;
  validation_result?: string;
  opsec_context?: {
    noise_level?: number;
    noise_budget_remaining?: number;
    recommended_approach?: string;
    defensive_signals?: string[];
  };
  _formType?: 'approve' | 'deny';
}

// --- Activity Log ---

export interface ActivityEntry {
  id: string;
  timestamp: string;
  event_type: string;
  action_id?: string;
  description: string;
  agent_id?: string;
  details?: Record<string, unknown>;
  source_kind?: 'primary' | 'subagent' | 'runner' | 'system' | 'dashboard';
  operator_model?: string;
  operator_name?: string;
  operator_session_id?: string;
  frontier_item_id?: string;
  target_node_ids?: string[];
  event_id?: string;
  result_classification?: 'success' | 'failure' | 'partial' | 'neutral';
  validation_result?: string;
}

export interface ActionQueueDiagnostics {
  approval_mode?: 'auto-approve' | 'approve-critical' | 'approve-all';
  opsec_enabled?: boolean;
  websocket_connected?: boolean;
  latest_action_at?: string;
  latest_action_type?: string;
  latest_approval_at?: string;
  latest_approval_status?: string;
}

// --- Read-only introspection ---

export interface DecisionStage {
  stage: string;
  timestamp: string;
  details_ref?: string;
  summary?: string;
}

export interface DecisionLogEntry {
  decision_id: string;
  frontier_item_id?: string;
  action_id?: string;
  agent_id?: string;
  opened_at: string;
  closed_at: string;
  outcome?: 'completed' | 'failed' | 'denied' | 'dropped' | 'open';
  stages: DecisionStage[];
}

export interface ActionExplanation {
  action_id: string;
  found: boolean;
  agent_id?: string;
  frontier_item_id?: string;
  frontier_item?: FrontierItem;
  log_thought_chain: Array<{
    event_id: string;
    timestamp: string;
    kind?: string;
    description: string;
    confidence?: number;
  }>;
  considered_alternatives: string[];
  prior_actions_referenced: string[];
  validation?: {
    event_id: string;
    timestamp: string;
    validation_result?: string;
    errors?: string[];
    warnings?: string[];
  };
  approval?: {
    event_id: string;
    timestamp: string;
    approval_status?: 'approved' | 'denied' | 'timeout';
    auto_approved?: boolean;
    operator_notes?: string;
    reason?: string;
  };
  outcome?: {
    event_id: string;
    timestamp: string;
    classification?: 'success' | 'failure' | 'partial' | 'neutral';
    description: string;
  };
}

export interface TimelineEntry {
  entity_id: string;
  kind: 'node' | 'edge';
  became_true_at: string;
  became_false_at?: string;
  last_observed_at?: string;
  evidence_refs: string[];
  superseding_id?: string;
  invalidation_reason?: string;
}

// --- Engagement State (from get_state) ---

export interface EngagementState {
  engagement?: {
    id: string;
    name: string;
    profile?: string;
    template?: string;
    created_at?: string;
  };
  config?: {
    name: string;
    scope?: ScopeConfig;
    opsec?: OpsecConfig;
  };
  graph_summary?: {
    total_nodes: number;
    total_edges: number;
    confirmed_edges: number;
    inferred_edges: number;
    nodes_by_type: Record<string, number>;
    edges_by_type?: Record<string, number>;
    community_count?: number;
    largest_community_size?: number;
    unexplored_community_count?: number;
    cold_node_count?: number;
    cold_nodes_by_subnet?: Record<string, number>;
  };
  objectives?: Objective[];
  frontier?: FrontierItem[];
  agents?: AgentInfo[];
  campaigns?: Campaign[];
  sessions?: SessionInfo[];
  pending_actions?: PendingAction[];
  access_level?: string;
  history_count?: number;
  phases?: EngagementPhase[];
  inference_rule_effectiveness?: InferenceRuleEffectiveness[];
  /** Backend serializes this as `lab_readiness` with `top_issues`; the store re-keys both for the OverviewPanel. */
  lab_readiness?: {
    status: string;
    top_issues: string[];
  };
}

export type CampaignStrategy = 'credential_spray' | 'enumeration' | 'post_exploitation' | 'network_discovery' | 'custom';

export type PhaseCriterion =
  | { type: 'always' }
  | { type: 'phase_completed'; phase_id: string }
  | { type: 'objective_achieved'; objective_id: string }
  | { type: 'node_count'; node_type: string; min: number }
  | { type: 'access_level'; min_level: 'user' | 'local_admin' | 'domain_admin' };

export interface EngagementPhase {
  id: string;
  name: string;
  order: number;
  strategies: CampaignStrategy[];
  entry_criteria: PhaseCriterion[];
  exit_criteria: PhaseCriterion[];
  status?: 'pending' | 'active' | 'completed';
  started_at?: string;
  completed_at?: string;
}

export interface ScopeConfig {
  cidrs?: string[];
  domains?: string[];
  exclusions?: string[];
  hosts?: string[];
  url_patterns?: string[];
  aws_accounts?: string[];
  azure_subscriptions?: string[];
  gcp_projects?: string[];
}

export interface OpsecConfig {
  max_noise?: number;
  approval_mode?: 'auto-approve' | 'approve-critical' | 'approve-all';
  approval_timeout_ms?: number;
  time_window?: { start_hour: number; end_hour: number };
  blacklisted_techniques?: string[];
}

// --- WebSocket Messages ---

export type WsMessageType =
  | 'full_state'
  | 'graph_update'
  | 'agent_update'
  | 'agent_console_update'
  | 'objective_update'
  | 'session_update'
  | 'action_pending'
  | 'action_resolved'
  | 'campaign_update'
  // Phase 4 (enterprise): identity-tier graph updates carry their own
  // message type so the dashboard can refresh just the IdentityPanel
  // without forcing a full graph re-render. The payload mirrors
  // `graph_update` shape but is filtered to idp_* node types and the
  // identity-tier edges.
  | 'identity_update';

export interface WsMessage {
  type: WsMessageType;
  timestamp: string;
  data: unknown;
}

export interface FullStateData {
  state: EngagementState;
  graph: ExportedGraph;
  history_count: number;
}

export interface GraphUpdateData {
  state: EngagementState;
  history_count: number;
  detail: {
    new_nodes?: string[];
    updated_nodes?: string[];
    new_edges?: string[];
    updated_edges?: string[];
    inferred_edges?: string[];
    removed_nodes?: string[];
    removed_edges?: string[];
  };
  delta: {
    nodes: ExportedNode[];
    edges: ExportedEdge[];
    removed_nodes: string[];
    removed_edges: string[];
  };
}

// --- OPSEC Budget ---

export interface OpsecBudget {
  global_noise_spent: number;
  noise_budget_remaining: number;
  max_noise: number;
  recommended_approach: 'quiet' | 'normal' | 'loud';
  defensive_signals: DefensiveSignal[];
  time_window_remaining_hours?: number;
  warning?: string;
}

export interface DefensiveSignal {
  type: string;
  host_id?: string;
  domain?: string;
  detected_at: string;
  description: string;
}

// --- Access Summary ---

export interface AccessSummary {
  compromised_hosts: string[];
  valid_credentials: string[];
  current_access_level: string;
}

// --- Evidence ---

export interface EvidenceChainEntry {
  activity_id: string;
  timestamp: string;
  event_type: string;
  description: string;
  action_id?: string;
  agent_id?: string;
  tool?: string;
  command?: string;
  snippet?: string;
}

export interface EvidenceChainResponse {
  node_id: string;
  chains: EvidenceChainEntry[];
  count: number;
  node_props?: {
    type?: string;
    label?: string;
    os?: string;
    confidence?: number;
    chain_template?: string;
  };
  findings?: EvidenceFinding[];
}

export interface EvidenceFinding {
  finding_type?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  technique_id?: string;
  description?: string;
}

export interface FindingContextResponse {
  finding: import('./api').FindingDto;
  affected_nodes: Array<ExportedNode & { asset?: string }>;
  evidence_chains: EvidenceChainResponse[];
  sessions: SessionInfo[];
  pending_actions: PendingAction[];
  frontier: FrontierItem[];
  path_impacts: Array<{
    objective_id: string;
    objective: string;
    nodes: string[];
    total_confidence: number;
    total_opsec_noise: number;
  }>;
  report_ready: boolean;
}

export interface AttackPathNode {
  id: string;
  label?: string;
  type?: string;
  edge_type?: string;
}

export interface AttackPath {
  nodes: Array<AttackPathNode | string>;
  edges?: string[];
  confidence?: number;
  opsec_noise?: number;
  total_confidence?: number;
  total_opsec_noise?: number;
  hop_count?: number;
}

// --- Health ---

export interface HealthStatus {
  status: 'healthy' | 'warnings' | 'errors';
  checks: { name: string; status: string; message?: string }[];
  graph_stats?: {
    nodes: number;
    edges: number;
    node_types: Record<string, number>;
  };
  health_checks?: {
    warnings?: { message: string }[];
    errors?: { message: string }[];
  };
  ad_context?: boolean;
}

export interface EngagementConfig {
  id?: string;
  name: string;
  profile?: string;
  template?: string;
  created_at?: string;
  community_resolution?: number;
  scope?: ScopeConfig;
  opsec?: OpsecConfig;
  objectives?: Objective[];
  failure_patterns?: FailurePattern[];
  phases?: EngagementPhase[];
}

export interface FailurePattern {
  technique: string;
  target_pattern?: string;
  warning: string;
}

export interface FrontierWeights {
  fan_out: Record<string, number>;
  noise: Record<string, number>;
}

export interface EngagementListItem {
  id: string;
  name: string;
  is_active?: boolean;
  profile?: string;
  scope_cidrs: string[];
  scope_domains: string[];
  exclusions_count?: number;
  objectives_count: number;
  phases_count: number;
  created_at?: string;
  config_path?: string;
  state_path?: string;
}

export interface EngagementDetail extends EngagementConfig {
  id: string;
  config_path?: string;
  state_path?: string;
  is_active?: boolean;
}

export interface EngagementTemplate {
  id: string;
  name: string;
  description?: string;
  profile?: string;
  opsec?: OpsecConfig;
  objectives?: { description: string }[];
  phases?: EngagementPhase[];
  failure_patterns?: FailurePattern[];
}

// --- Tool Inventory ---

export interface ToolStatus {
  name: string;
  installed: boolean;
  version?: string;
  path?: string;
}

export interface ToolCheckResult {
  installed_count: number;
  missing_count: number;
  tools: ToolStatus[];
}

export interface McpToolInfo {
  name: string;
  title?: string;
  description: string;
  category: string;
  read_only?: boolean;
  destructive?: boolean;
  idempotent?: boolean;
  open_world?: boolean;
}

export interface McpToolRegistryResponse {
  total: number;
  categories: Record<string, number>;
  tools: McpToolInfo[];
}

export interface DashboardReadinessSummary {
  status: 'ready' | 'warning' | 'critical';
  generated_at: string;
  graph: {
    status: 'healthy' | 'warning' | 'critical';
    nodes: number;
    edges: number;
    counts_by_severity: Record<string, number>;
    top_issues: Array<{ severity: string; check: string; message: string }>;
  };
  api: {
    dashboard_running: boolean;
    websocket_clients: number;
    mcp_tools_registered: number;
  };
  tape: {
    enabled?: boolean;
    attached?: boolean;
    active?: boolean;
    started_by?: 'env' | 'config' | 'dashboard';
    file?: string;
    frame_count?: number;
    age_ms?: number;
    [key: string]: unknown;
  };
  sessions: {
    total: number;
    active: number;
    closed: number;
  };
  actions: {
    pending: number;
  };
  agents: {
    total: number;
    running: number;
    failed: number;
  };
  persistence: {
    dirty: boolean;
    last_flush_at?: string;
    flush_count?: number;
    last_flush_ms?: number;
  };
  issues: string[];
  dev?: Record<string, unknown>;
}

// --- Inference Rules ---

export interface InferenceRuleProduction {
  edge_type: string;
  source_selector: string;
  target_selector: string;
  confidence: number;
}

// --- Inference Rule Effectiveness (Sprint 7.9) ---

export interface InferenceRuleEffectiveness {
  rule_id: string;
  total: number;
  confirmed: number;
  unconfirmed: number;
  confirmation_rate: number;
}

// --- Tool Telemetry (Sprint 7.5) ---

export interface ToolStats {
  calls: number;
  errors: number;
  total_ms: number;
  avg_ms: number;
  last_error?: string;
}

export interface SequencePattern {
  sequence: string[];
  count: number;
}

export interface TelemetrySummary {
  tool_stats: Record<string, ToolStats>;
  total_calls: number;
  total_errors: number;
  unused_tools: string[];
  top_tools: Array<{ name: string; calls: number; avg_ms: number; error_rate: number }>;
  common_sequences: SequencePattern[];
}

// --- Credential Coverage Matrix ---

export interface CredentialCoverage {
  total_credentials: number;
  total_targets: number;
  tested_pairs: number;
  total_pairs: number;
  coverage_pct: number;
  top_untested: Array<{ credential: string; target: string; priority: number; service?: string }>;
}

export interface InferenceRuleInfo {
  id: string;
  name: string;
  description: string;
  trigger: {
    node_type?: string;
    edge_type?: string;
    property_match?: Record<string, unknown>;
  };
  produces: InferenceRuleProduction[];
  self_confirming?: boolean;
}
