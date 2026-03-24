// ============================================================
// Overwatch — Core Type Definitions
// ============================================================

import { z } from 'zod';

// --- Node Types ---

export const NODE_TYPES = [
  'host', 'service', 'domain', 'user', 'group', 'credential',
  'share', 'certificate', 'ca', 'cert_template', 'pki_store', 'gpo', 'ou', 'subnet', 'objective'
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

  // Service
  port?: number;
  protocol?: string;            // tcp/udp
  service_name?: string;        // smb, http, ldap, kerberos, mssql, etc.
  version?: string;
  banner?: string;

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
  cred_type?: 'plaintext' | 'ntlm' | 'ntlmv2_challenge' | 'aes256' | 'kerberos_tgt' | 'kerberos_tgs' | 'certificate' | 'token' | 'ssh_key';
  cred_value?: string;          // hash or redacted reference
  cred_hash?: string;           // normalized hash material for cracked/captured creds
  cred_user?: string;           // associated user node id
  cred_domain?: string;
  cred_material_kind?: 'plaintext_password' | 'ntlm_hash' | 'ntlmv2_challenge' | 'aes256_key' | 'kerberos_tgt' | 'kerberos_tgs' | 'certificate' | 'token' | 'ssh_key';
  cred_usable_for_auth?: boolean;
  cred_evidence_kind?: 'capture' | 'crack' | 'dump' | 'spray_success' | 'manual';
  observed_from_ip?: string;
  valid_until?: string;         // ISO timestamp — expiry for time-limited creds (TGT/TGS, tokens, certs)
  rotated_at?: string;          // ISO timestamp — when credential was observed as changed
  stale_at?: string;            // ISO timestamp — when credential became stale
  credential_status?: 'active' | 'stale' | 'expired' | 'rotated';

  // Share
  share_name?: string;
  share_path?: string;
  readable?: boolean;
  writable?: boolean;

  // Certificate
  template_name?: string;
  ca_name?: string;
  ca_kind?: 'enterprise_ca' | 'root_ca' | 'aia_ca';
  pki_store_kind?: 'ntauth_store' | 'issuance_policy';
  eku?: string[];
  enrollee_supplies_subject?: boolean;

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
  'VALID_ON', 'OWNS_CRED', 'DERIVED_FROM',
  // AD attack paths
  'CAN_DCSYNC', 'DELEGATES_TO', 'WRITEABLE_BY', 'GENERIC_ALL',
  'GENERIC_WRITE', 'WRITE_OWNER', 'WRITE_DACL', 'ADD_MEMBER',
  'FORCE_CHANGE_PASSWORD', 'ALLOWED_TO_ACT',
  // ADCS
  'CAN_ENROLL', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC6', 'ESC8',
  // Trust
  'TRUSTS', 'SAME_DOMAIN',
  // Roasting
  'AS_REP_ROASTABLE', 'KERBEROASTABLE',
  // Delegation
  'CAN_DELEGATE_TO',
  // ACL-derived
  'CAN_READ_LAPS', 'CAN_READ_GMSA', 'RBCD_TARGET',
  // Lateral movement
  'RELAY_TARGET', 'NULL_SESSION', 'POTENTIAL_AUTH',
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
  scope: {
    cidrs: string[];
    domains: string[];
    exclusions: string[];
    hosts?: string[];
  };
  objectives: EngagementObjective[];
  opsec: OpsecProfile;
}

export const engagementObjectiveSchema = z.object({
  id: nonEmptyString,
  description: nonEmptyString,
  target_node_type: nodeTypeSchema.optional(),
  target_criteria: z.record(z.unknown()).optional(),
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
  created_at: nonEmptyString,
  scope: z.object({
    cidrs: z.array(z.string()),
    domains: z.array(z.string()),
    exclusions: z.array(z.string()),
    hosts: z.array(z.string()).optional(),
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
  type: 'incomplete_node' | 'untested_edge' | 'inferred_edge';
  node_id?: string;
  edge_source?: string;
  edge_target?: string;
  edge_type?: EdgeType;
  missing_properties?: string[];
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
  status: 'pending' | 'running' | 'completed' | 'failed';
  frontier_item_id: string;
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
}

export type LabProfile = 'goad_ad' | 'single_host';
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
