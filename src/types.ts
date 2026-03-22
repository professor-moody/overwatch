// ============================================================
// Overwatch — Core Type Definitions
// ============================================================

import { z } from 'zod';

// --- Node Types ---

export const NODE_TYPES = [
  'host', 'service', 'domain', 'user', 'group', 'credential',
  'share', 'certificate', 'gpo', 'ou', 'subnet', 'objective'
] as const;
export type NodeType = typeof NODE_TYPES[number];
export const nodeTypeSchema = z.enum(NODE_TYPES);

export interface NodeProperties {
  // Common
  id: string;
  type: NodeType;
  label: string;
  discovered_by?: string;       // agent id that found this
  discovered_at: string;        // ISO timestamp
  confidence: number;           // 0.0 - 1.0
  notes?: string;

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
  cred_type?: 'plaintext' | 'ntlm' | 'aes256' | 'kerberos_tgt' | 'kerberos_tgs' | 'certificate' | 'token' | 'ssh_key';
  cred_value?: string;          // hash or redacted reference
  cred_user?: string;           // associated user node id
  cred_domain?: string;
  cred_material_kind?: 'plaintext_password' | 'ntlm_hash' | 'ntlmv2_challenge' | 'aes256_key' | 'kerberos_tgt' | 'kerberos_tgs' | 'certificate' | 'token' | 'ssh_key';
  cred_usable_for_auth?: boolean;
  cred_evidence_kind?: 'capture' | 'crack' | 'dump' | 'spray_success' | 'manual';
  observed_from_ip?: string;

  // Share
  share_name?: string;
  share_path?: string;
  readable?: boolean;
  writable?: boolean;

  // Certificate
  template_name?: string;
  ca_name?: string;
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
  'VALID_ON', 'OWNS_CRED',
  // AD attack paths
  'CAN_DCSYNC', 'DELEGATES_TO', 'WRITEABLE_BY', 'GENERIC_ALL',
  'GENERIC_WRITE', 'WRITE_OWNER', 'WRITE_DACL', 'ADD_MEMBER',
  'FORCE_CHANGE_PASSWORD', 'ALLOWED_TO_ACT',
  // ADCS
  'CAN_ENROLL', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC6', 'ESC8',
  // Trust
  'TRUSTS', 'SAME_DOMAIN',
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
    timestamp: string;
    description: string;
    agent_id?: string;
  }>;
  access_summary: {
    compromised_hosts: string[];
    valid_credentials: string[];
    current_access_level: string;
  };
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

export interface ScoringRecommendation {
  current_weights: Record<string, number>;
  suggested_weights: Record<string, number>;
  rationale: string[];
  success_by_frontier_type: Record<string, { total: number; successful: number }>;
}

export interface RLVRTrace {
  step: number;
  timestamp: string;
  state_summary: { nodes: number; edges: number; access_level: string; objectives_achieved: number };
  action: { type: string; target?: string; technique?: string; tool?: string };
  outcome: { new_nodes: number; new_edges: number; objective_achieved: boolean };
  reward: number;
}

export interface RetrospectiveResult {
  inference_suggestions: InferenceRuleSuggestion[];
  skill_gaps: SkillGapReport;
  scoring: ScoringRecommendation;
  report_markdown: string;
  training_traces: RLVRTrace[];
  summary: string;
}
