// ============================================================
// Overwatch — Core Type Definitions
// ============================================================

import { z } from 'zod';

// --- Node Types ---

export const NODE_TYPES = [
  'host', 'service', 'domain', 'user', 'group', 'credential',
  'share', 'certificate', 'ca', 'cert_template', 'pki_store', 'gpo', 'ou', 'subnet', 'objective',
  'webapp', 'vulnerability',
  'cloud_identity', 'cloud_resource', 'cloud_policy', 'cloud_network'
] as const;
export type NodeType = typeof NODE_TYPES[number];
export const nodeTypeSchema = z.enum(NODE_TYPES);
const nonEmptyString = z.string().min(1);

export interface NodeProperties {
  // Common
  id: string;
  type: NodeType;
  label: string;
  discovered_by?: string;       // agent id that found this
  discovered_at: string;        // ISO timestamp
  first_seen_at?: string;       // first direct observation time
  last_seen_at?: string;        // most recent direct observation time
  confirmed_at?: string;        // node-level direct confirmation time
  sources?: string[];           // unique agents that contributed to this node
  confidence: number;           // 0.0 - 1.0
  notes?: string;
  identity_status?: 'canonical' | 'unresolved' | 'superseded';
  identity_family?: string;
  canonical_id?: string;
  identity_markers?: string[];
  superseded_by?: string;

  // Host
  ip?: string;
  hostname?: string;
  os?: string;
  os_version?: string;
  alive?: boolean;
  edr?: string;
  domain_joined?: boolean;
  // Linux host enrichment
  users_enumerated?: boolean;
  suid_checked?: boolean;
  has_suid_root?: boolean;
  suid_binaries?: string[];
  cron_checked?: boolean;
  cron_jobs?: string[];
  capabilities_checked?: boolean;
  interesting_capabilities?: string[];
  docker_socket_accessible?: boolean;
  kernel_version?: string;
  writable_paths?: string[];

  // Service
  port?: number;
  protocol?: string;            // tcp/udp
  service_name?: string;        // smb, http, ldap, kerberos, mssql, etc.
  version?: string;
  banner?: string;
  linked_servers?: string[];    // MSSQL linked server hostnames

  // Domain
  domain_name?: string;
  functional_level?: string;

  // User / Group
  username?: string;
  display_name?: string;
  enabled?: boolean;
  privileged?: boolean;
  sid?: string;
  member_of?: string[];         // group IDs

  // Credential
  cred_type?: 'plaintext' | 'cleartext' | 'ntlm' | 'ntlmv1_challenge' | 'ntlmv2_challenge' | 'aes256' | 'kerberos_tgt' | 'kerberos_tgs' | 'certificate' | 'token' | 'ssh_key';
  cred_value?: string;          // hash or redacted reference
  cred_hash?: string;           // normalized hash material for cracked/captured creds
  cred_user?: string;           // associated user node id
  cred_domain?: string;
  cred_domain_inferred?: boolean;
  cred_domain_source?: 'explicit' | 'graph_inference' | 'parser_context';
  cred_material_kind?: 'plaintext_password' | 'ntlm_hash' | 'ntlmv1_challenge' | 'ntlmv2_challenge' | 'aes256_key' | 'kerberos_tgt' | 'kerberos_tgs' | 'certificate' | 'token' | 'ssh_key';
  cred_usable_for_auth?: boolean;
  cred_evidence_kind?: 'capture' | 'crack' | 'dump' | 'spray_success' | 'manual';
  cred_is_default_guess?: boolean;
  observed_from_ip?: string;
  valid_until?: string;         // ISO timestamp — expiry for time-limited creds (TGT/TGS, tokens, certs)
  rotated_at?: string;          // ISO timestamp — when credential was observed as changed
  stale_at?: string;            // ISO timestamp — when credential became stale
  credential_status?: 'active' | 'stale' | 'expired' | 'rotated';
  dump_source_host?: string;

  // Share
  share_name?: string;
  share_path?: string;
  readable?: boolean;
  writable?: boolean;
  no_root_squash?: boolean;

  // Certificate
  template_name?: string;
  ca_name?: string;
  ca_kind?: 'enterprise_ca' | 'root_ca' | 'aia_ca';
  pki_store_kind?: 'ntauth_store' | 'issuance_policy';
  eku?: string[];
  enrollee_supplies_subject?: boolean;

  // Service — TLS enrichment
  tls_version?: string;
  cipher_suites?: string[];
  cert_subject?: string;
  cert_expiry?: string;
  cert_issuer?: string;

  // Subnet
  subnet_cidr?: string;

  // Webapp
  url?: string;
  technology?: string;
  framework?: string;
  auth_type?: string;
  has_api?: boolean;
  cms_type?: string;

  // Vulnerability
  cve?: string;
  cvss?: number;
  vuln_type?: string;
  exploitable?: boolean;
  exploit_available?: boolean;
  affected_component?: string;

  // Cloud Identity (IAM user, role, service account, managed identity)
  provider?: 'aws' | 'azure' | 'gcp';
  arn?: string;
  principal_type?: 'user' | 'role' | 'service_account' | 'managed_identity' | 'app';
  policies?: string[];
  mfa_enabled?: boolean;
  last_used?: string;
  cloud_account?: string;
  policies_enumerated?: boolean;

  // Cloud Resource (S3 bucket, EC2, Lambda, Azure VM, etc.)
  resource_type?: string;
  region?: string;
  public?: boolean;
  encrypted?: boolean;
  tags?: Record<string, string>;
  imdsv2_required?: boolean;

  // Cloud Policy (IAM policy, RBAC role assignment)
  policy_name?: string;
  effect?: 'allow' | 'deny';
  actions?: string[];
  resources?: string[];
  conditions?: string[];

  // Cloud Network (VPC, security group, subnet, firewall rule)
  network_type?: 'vpc' | 'security_group' | 'subnet' | 'firewall_rule';
  ingress_rules?: string[];
  egress_rules?: string[];

  // Objective
  objective_description?: string;
  objective_achieved?: boolean;
  objective_achieved_at?: string;

  // Extensible
  [key: string]: unknown;
}

// --- Edge Types ---

export const EDGE_TYPES = [
  // Network
  'REACHABLE', 'RUNS',
  // Domain membership
  'MEMBER_OF', 'MEMBER_OF_DOMAIN',
  // Access
  'ADMIN_TO', 'HAS_SESSION', 'CAN_RDPINTO', 'CAN_PSREMOTE',
  // Credential relationships
  'VALID_ON', 'OWNS_CRED', 'DERIVED_FROM', 'DUMPED_FROM',
  // AD attack paths
  'CAN_DCSYNC', 'DELEGATES_TO', 'WRITEABLE_BY', 'GENERIC_ALL',
  'GENERIC_WRITE', 'WRITE_OWNER', 'WRITE_DACL', 'ADD_MEMBER',
  'FORCE_CHANGE_PASSWORD', 'ALLOWED_TO_ACT',
  // ADCS
  'CAN_ENROLL', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC7', 'ESC8', 'ESC9', 'ESC10', 'ESC11', 'ESC13',
  'ISSUED_BY', 'OPERATES_CA',
  // Trust
  'TRUSTS', 'SAME_DOMAIN',
  // Roasting
  'AS_REP_ROASTABLE', 'KERBEROASTABLE',
  // Delegation
  'CAN_DELEGATE_TO',
  // ACL-derived
  'CAN_READ_LAPS', 'CAN_READ_GMSA', 'RBCD_TARGET',
  // Credential reuse
  'SHARED_CREDENTIAL',
  // Lateral movement
  'RELAY_TARGET', 'NULL_SESSION', 'POTENTIAL_AUTH', 'TESTED_CRED',
  // Web application surface
  'HOSTS', 'AUTHENTICATED_AS', 'VULNERABLE_TO', 'EXPLOITS',
  // Cloud infrastructure
  'ASSUMES_ROLE', 'HAS_POLICY', 'POLICY_ALLOWS', 'EXPOSED_TO', 'RUNS_ON', 'MANAGED_BY',
  // Objective
  'PATH_TO_OBJECTIVE',
  // Generic
  'RELATED'
] as const;
export type EdgeType = typeof EDGE_TYPES[number];
export const edgeTypeSchema = z.enum(EDGE_TYPES);

export interface EdgeProperties {
  type: EdgeType;
  confidence: number;           // 0.0 = hypothesis, 1.0 = confirmed
  discovered_by?: string;
  discovered_at: string;
  tested?: boolean;
  tested_at?: string;
  test_result?: 'success' | 'failure' | 'partial' | 'error';
  opsec_noise?: number;         // 0.0 (silent) to 1.0 (extremely loud)
  notes?: string;
  // Inference lifecycle tracking
  inferred_by_rule?: string;    // rule ID that created this edge
  inferred_at?: string;         // ISO timestamp when inferred
  confirmed_at?: string;        // ISO timestamp when confidence raised to 1.0
  // Pivot tracking
  via_pivot?: string;           // node ID of principal enabling pivot (on REACHABLE edges)
  [key: string]: unknown;
}

// --- Parser Context ---

export interface ParseContext {
  domain?: string;
  source_host?: string;
  domain_aliases?: Record<string, string>;
  // Cloud context (Sprint 11+)
  cloud_account?: string;
  cloud_region?: string;
  // Network context (Sprint 9+)
  network_zone?: string;
  [key: string]: unknown;
}

// --- Engagement Config ---

export interface EngagementObjective {
  id: string;
  description: string;
  target_node_type?: NodeType;
  target_criteria?: Record<string, unknown>;  // match against node props
  achievement_edge_types?: EdgeType[];        // custom edge types that count as "obtained" (default: HAS_SESSION, ADMIN_TO, OWNS_CRED)
  achieved: boolean;
  achieved_at?: string;
}

export interface OpsecProfile {
  name: string;                  // 'ctf' | 'pentest' | 'redteam' | 'assumed_breach'
  max_noise: number;             // hard ceiling, 0.0-1.0
  time_window?: {
    start_hour: number;          // 0-23
    end_hour: number;
  };
  blacklisted_techniques?: string[];
  notes?: string;
}

export interface EngagementConfig {
  id: string;
  name: string;
  created_at: string;
  profile?: LabProfile;
  scope: {
    cidrs: string[];
    domains: string[];
    exclusions: string[];
    hosts?: string[];
    aws_accounts?: string[];
    azure_subscriptions?: string[];
    gcp_projects?: string[];
    url_patterns?: string[];   // glob-like: "*.example.com", "app.corp.io/api/*"
  };
  objectives: EngagementObjective[];
  opsec: OpsecProfile;
  community_resolution?: number;  // Louvain resolution (default 1.0, lower → fewer/larger communities)
  failure_patterns?: { technique: string; target_pattern?: string; warning: string }[];  // Retrospective feedback for validation
}

export const engagementObjectiveSchema = z.object({
  id: nonEmptyString,
  description: nonEmptyString,
  target_node_type: nodeTypeSchema.optional(),
  target_criteria: z.record(z.unknown()).optional(),
  achievement_edge_types: z.array(edgeTypeSchema).optional(),
  achieved: z.boolean(),
  achieved_at: z.string().optional(),
});

export const opsecProfileSchema = z.object({
  name: nonEmptyString,
  max_noise: z.number().min(0).max(1),
  time_window: z.object({
    start_hour: z.number().int().min(0).max(23),
    end_hour: z.number().int().min(0).max(23),
  }).optional(),
  blacklisted_techniques: z.array(z.string()).optional(),
  notes: z.string().optional(),
});

export const engagementConfigSchema = z.object({
  id: nonEmptyString,
  name: nonEmptyString,
  created_at: z.string().min(1).refine(
    (val) => !isNaN(Date.parse(val)),
    { message: 'created_at must be a valid ISO-8601 date string' },
  ),
  profile: z.enum(['goad_ad', 'single_host', 'network', 'web_app', 'cloud', 'hybrid']).optional(),
  community_resolution: z.number().min(0.1).max(10).optional(),
  failure_patterns: z.array(z.object({
    technique: z.string(),
    target_pattern: z.string().optional(),
    warning: z.string(),
  })).optional(),
  scope: z.object({
    cidrs: z.array(z.string().regex(
      /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/,
      { message: 'Each CIDR must be in format X.X.X.X/N' },
    )).default([]),
    domains: z.array(z.string()),
    exclusions: z.array(z.string()),
    hosts: z.array(z.string()).optional(),
    aws_accounts: z.array(z.string()).optional(),
    azure_subscriptions: z.array(z.string()).optional(),
    gcp_projects: z.array(z.string()).optional(),
    url_patterns: z.array(z.string()).optional(),
  }),
  objectives: z.array(engagementObjectiveSchema),
  opsec: opsecProfileSchema,
});

export interface ExportedGraphNode {
  id: string;
  properties: NodeProperties;
}

export interface ExportedGraphEdge {
  id?: string;
  source: string;
  target: string;
  properties: EdgeProperties;
}

export interface ExportedGraph {
  nodes: ExportedGraphNode[];
  edges: ExportedGraphEdge[];
}

// --- Frontier + Scoring ---

export interface FrontierItem {
  id: string;
  type: 'incomplete_node' | 'untested_edge' | 'inferred_edge' | 'network_discovery' | 'network_pivot';
  node_id?: string;
  edge_source?: string;
  edge_target?: string;
  edge_type?: EdgeType;
  target_cidr?: string;
  missing_properties?: string[];
  via_pivot?: string;           // principal node ID enabling pivot
  pivot_host_id?: string;       // host with session enabling pivot
  description: string;
  graph_metrics: {
    hops_to_objective: number | null;
    fan_out_estimate: number;
    node_degree: number;
    confidence: number;
  };
  opsec_noise: number;
  staleness_seconds: number;
  stale_credential?: boolean;
  scope_unverified?: boolean;
  community_id?: number;
  community_unexplored_count?: number;
}

export interface ScoredTask {
  frontier_item: FrontierItem;
  llm_score?: number;            // 1-10 from LLM
  llm_reasoning?: string;
  llm_suggested_action?: string;
  validated: boolean;
  validation_errors?: string[];
}

// --- Agent Types ---

export interface AgentTask {
  id: string;
  agent_id: string;
  assigned_at: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'interrupted';
  frontier_item_id?: string;
  subgraph_node_ids: string[];
  skill?: string;
  completed_at?: string;
  result_summary?: string;
}

// --- Finding (reported by agents) ---

export interface Finding {
  id: string;
  agent_id: string;
  timestamp: string;
  action_id?: string;
  tool_name?: string;
  frontier_item_id?: string;
  target_node_ids?: string[];
  nodes: Array<Partial<NodeProperties> & { id: string; type: NodeType }>;
  edges: Array<{
    source: string;
    target: string;
    properties: Partial<EdgeProperties> & { type: EdgeType };
  }>;
  evidence?: {
    type: 'screenshot' | 'log' | 'file' | 'command_output';
    content: string;
    filename?: string;
  };
  raw_output?: string;
}

// --- Graph State Summary (returned by get_state) ---

export interface EngagementState {
  config: EngagementConfig;
  graph_summary: {
    total_nodes: number;
    nodes_by_type: Record<string, number>;
    total_edges: number;
    edges_by_type: Record<string, number>;
    confirmed_edges: number;
    inferred_edges: number;
    community_count: number;
    largest_community_size: number;
    unexplored_community_count: number;
    cold_node_count: number;
    cold_nodes_by_subnet?: Record<string, number>;
  };
  objectives: EngagementObjective[];
  frontier: FrontierItem[];
  active_agents: AgentTask[];
  recent_activity: Array<{
    event_id: string;
    timestamp: string;
    description: string;
    agent_id?: string;
    action_id?: string;
    event_type?: string;
    tool_name?: string;
    result_classification?: string;
  }>;
  access_summary: {
    compromised_hosts: string[];
    valid_credentials: string[];
    current_access_level: string;
  };
  warnings: HealthSummary;
  lab_readiness: LabReadinessSummary;
  scope_suggestions: ScopeSuggestion[];
}

// --- Scope Suggestions (surfaced by get_state for operator review) ---

export interface ScopeSuggestion {
  suggested_cidr: string;
  out_of_scope_ips: string[];
  node_ids: string[];
  first_seen_at: string;
  source_descriptions: string[];
}

export type LabProfile = 'goad_ad' | 'single_host' | 'network' | 'web_app' | 'cloud' | 'hybrid';

export function inferProfile(config: EngagementConfig): LabProfile {
  if (config.profile) return config.profile;
  const hasCloud = !!(config.scope.aws_accounts?.length
    || config.scope.azure_subscriptions?.length
    || config.scope.gcp_projects?.length);
  const hasDomains = config.scope.domains.length > 0;
  const hasUrls = !!(config.scope.url_patterns?.length);
  if (hasCloud && hasDomains) return 'hybrid';
  if (hasCloud) return 'cloud';
  if (hasUrls) return 'web_app';
  if (hasDomains) return 'goad_ad';
  return 'single_host';
}
export type LabReadinessStatus = 'ready' | 'warning' | 'blocked';

export interface LabReadinessCheck {
  name: string;
  status: 'pass' | 'warning' | 'fail';
  message: string;
  details?: Record<string, unknown>;
}

export interface LabReadinessSummary {
  status: LabReadinessStatus;
  top_issues: string[];
}

export interface LabPreflightReport {
  profile: LabProfile;
  status: LabReadinessStatus;
  graph_stage: 'empty' | 'seeded' | 'mid_run';
  checks: LabReadinessCheck[];
  missing_required_tools: string[];
  warnings: string[];
  recommended_next_steps: string[];
  dashboard: {
    enabled: boolean;
    running: boolean;
    address?: string;
  };
}

export type HealthSeverity = 'warning' | 'critical';
export type HealthStatus = 'healthy' | 'warning' | 'critical';

export interface HealthIssue {
  severity: HealthSeverity;
  check: string;
  message: string;
  node_ids?: string[];
  edge_ids?: string[];
  details?: Record<string, unknown>;
}

export interface HealthReport {
  status: HealthStatus;
  counts_by_severity: Record<HealthSeverity, number>;
  issues: HealthIssue[];
}

export interface HealthSummary {
  status: HealthStatus;
  counts_by_severity: Record<HealthSeverity, number>;
  top_issues: HealthIssue[];
}

// --- Inference Rule ---

export interface InferenceRule {
  id: string;
  name: string;
  description: string;
  trigger: {
    node_type?: NodeType;
    edge_type?: EdgeType;
    property_match?: Record<string, unknown>;
    requires_edge?: {
      type: EdgeType;
      direction: 'inbound' | 'outbound';
      peer_match?: Record<string, unknown>;
    };
  };
  produces: {
    edge_type: EdgeType;
    source_selector: string;     // e.g. 'trigger_node', 'domain_nodes'
    target_selector: string;
    confidence: number;
    properties?: Record<string, unknown>;
  }[];
}

// --- Graph Query (for query_graph tool) ---

export interface GraphQuery {
  // Find nodes matching criteria
  node_type?: NodeType;
  node_filter?: Record<string, unknown>;
  // Find edges matching criteria
  edge_type?: EdgeType;
  edge_filter?: Record<string, unknown>;
  // Traverse from a specific node
  from_node?: string;
  direction?: 'outbound' | 'inbound' | 'both';
  max_depth?: number;
  // Return options
  include_properties?: boolean;
  limit?: number;
}

export interface GraphQueryResult {
  nodes: Array<{ id: string; properties: NodeProperties }>;
  edges: Array<{ source: string; target: string; properties: EdgeProperties }>;
  paths?: Array<{ nodes: string[]; edges: EdgeType[]; total_confidence: number }>;
}

export type GraphCorrectionOperation =
  | {
      kind: 'drop_edge';
      source_id: string;
      edge_type: EdgeType;
      target_id: string;
    }
  | {
      kind: 'replace_edge';
      source_id: string;
      edge_type: EdgeType;
      target_id: string;
      new_source_id?: string;
      new_edge_type?: EdgeType;
      new_target_id?: string;
      confidence?: number;
      properties?: Record<string, unknown>;
    }
  | {
      kind: 'patch_node';
      node_id: string;
      set_properties?: Record<string, unknown>;
      unset_properties?: string[];
    };

// --- Retrospective Types ---

export interface InferenceRuleSuggestion {
  rule: InferenceRule;
  evidence: string;
  occurrences: number;
}

export interface SkillGapReport {
  unused_skills: string[];
  missing_skills: string[];
  failed_techniques: string[];
  mentioned_techniques: string[];
  skill_usage_counts: Record<string, number>;
}

export type AnalysisConfidence = 'low' | 'medium' | 'high';

export interface FrontierObservation {
  area: string;
  observation: string;
  evidence_count: number;
  confidence: AnalysisConfidence;
}

export interface ContextGap {
  area: string;
  gap: string;
  recommendation: string;
  severity: 'warning' | 'critical';
  confidence: AnalysisConfidence;
}

export interface OpsecObservation {
  observation: string;
  recommendation: string;
  confidence: AnalysisConfidence;
}

export interface LoggingQualityReport {
  status: 'good' | 'mixed' | 'weak';
  issues: string[];
  observations?: string[];
  recommendation: string;
}

export interface ContextImprovementReport {
  frontier_observations: FrontierObservation[];
  context_gaps: ContextGap[];
  opsec_observations: OpsecObservation[];
  logging_quality: LoggingQualityReport;
  recommendations: string[];
  success_by_frontier_type: Record<string, { total: number; successful: number }>;
}

export interface RLVRTrace {
  step: number;
  timestamp: string;
  state_summary: { nodes: number; edges: number; access_level: string; objectives_achieved: number };
  action: { type: string; target?: string; technique?: string; tool?: string };
  outcome: { new_nodes: number; new_edges: number; objective_achieved: boolean };
  reward: number;
  confidence: AnalysisConfidence;
  derived_from: 'structured' | 'text_heuristic' | 'mixed';
}

export interface TraceQualityReport {
  status: 'good' | 'mixed' | 'weak';
  issues: string[];
  total_actions: number;
  structured_count: number;
  mixed_count: number;
  heuristic_count: number;
}

export interface RetrospectiveResult {
  inference_suggestions: InferenceRuleSuggestion[];
  skill_gaps: SkillGapReport;
  context_improvements: ContextImprovementReport;
  report_markdown: string;
  training_traces: RLVRTrace[];
  trace_quality: TraceQualityReport;
  summary: string;
}

// ============================================================
// Session Manager Types
// ============================================================

export type SessionKind = 'ssh' | 'local_pty' | 'socket';
export type SessionState = 'pending' | 'connected' | 'closed' | 'error';
export type TtyQuality = 'none' | 'dumb' | 'partial' | 'full';

export interface SessionCapabilities {
  has_stdin: boolean;
  has_stdout: boolean;
  supports_resize: boolean;
  supports_signals: boolean;
  tty_quality: TtyQuality;
}

export interface SessionMetadata {
  id: string;
  kind: SessionKind;
  transport: string;
  state: SessionState;
  title: string;
  host?: string;
  user?: string;
  port?: number;
  pid?: number;
  agent_id?: string;
  target_node?: string;
  principal_node?: string;
  credential_node?: string;
  action_id?: string;
  frontier_item_id?: string;
  claimed_by?: string;
  started_at: string;
  last_activity_at: string;
  closed_at?: string;
  capabilities: SessionCapabilities;
  buffer_end_pos: number;
  notes?: string;
}

export interface SessionReadResult {
  session_id: string;
  start_pos: number;
  end_pos: number;
  text: string;
  truncated: boolean;
}

export interface AdapterHandle {
  pid?: number;
  capabilities: SessionCapabilities;
  write(data: string): void;
  resize?(cols: number, rows: number): void;
  kill?(signal?: string): void;
  close(): void;
  onData(cb: (chunk: string) => void): void;
  onExit(cb: (info: { exitCode?: number; signal?: number }) => void): void;
}
