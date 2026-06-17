import type { AgentRole, FrontierItem, TaskBackend } from '../types.js';

// Phase 5c — data-driven agent archetypes ("agent types"). Replaces the
// hardcoded `allowedToolsFor` switch with a registry: each archetype is a real
// bundle of {legacy role + tool surface + backend + default skill/objective +
// scope strategy + what it's suitable for}. The recommender (recommendArchetype)
// reuses the campaign-planner frontier→strategy intuition to pick a default
// type for a target/task; the operator can always override (and `default` keeps
// the full surface as a safety valve if a narrow profile is too tight).
//
// Tool surfaces are REAL allowlist boundaries (per-tool `mcp__overwatch__*`
// prefixes passed to `claude -p --allowedTools`), not prompt guidance.

export type AgentArchetypeId =
  | 'default' | 'research' | 'planner'
  | 'recon_scanner' | 'web_tester' | 'credential_operator' | 'post_exploit'
  | 'cve_researcher' | 'pathfinder' | 'report_scribe';

export interface AgentArchetype {
  id: AgentArchetypeId;
  label: string;
  description: string;
  /** Legacy role bucket — back-compat + headless prompt framing. */
  role: AgentRole;
  /** Preferred backend; undefined = let TaskExecutionService auto-resolve. */
  backend?: TaskBackend;
  defaultSkill?: string;
  /** Objective template; `{target}` is substituted at dispatch. */
  defaultObjective?: string;
  scopeStrategy: 'subgraph' | 'cidr' | 'scope-wide';
  suitableFor: { frontierTypes?: FrontierItem['type'][]; nodeTypes?: string[]; rawTarget?: boolean };
  /** Tool surface. `full` = the whole `mcp__overwatch` server (the generic agent). */
  tools: { full: true } | { full: false; native: string[]; overwatch: string[] };
}

// --- tool groups (bare overwatch tool names) ---------------------------------

// Every reasoning agent needs these (read state, reason, report up, lifecycle).
const BASE = [
  'get_system_prompt', 'get_agent_context', 'query_graph', 'get_skill', 'next_task',
  'log_thought', 'agent_heartbeat', 'acknowledge_agent_directive', 'ask_operator',
  'submit_agent_transcript', 'update_agent', 'get_evidence',
];
// Instrumented, OPSEC-gated target execution + the action lifecycle around it.
const EXECUTE = ['run_bash', 'run_tool', 'validate_action', 'log_action_event', 'parse_output', 'report_finding', 'check_tools', 'track_process', 'check_processes'];
const SESSIONS = ['open_session', 'send_to_session', 'write_session', 'read_session', 'close_session', 'list_sessions', 'resize_session', 'signal_session', 'update_session'];
const CRED = ['validate_token_credential', 'exchange_refresh_token', 'expand_aws_credential', 'expand_entra_credential', 'expand_github_credential', 'expand_oidc_capture'];
const RECON = ['update_scope', 'find_paths', 'run_graph_health'];
// Read-only analysis surface — every member is readOnlyHint:true. (Deliberately
// excludes recompute_objectives, which persists, so read-only archetypes
// pathfinder/report_scribe stay non-mutating.)
const ANALYZE = ['find_paths', 'explain_action', 'get_decision_log', 'get_timeline', 'export_graph'];

// Legacy role surfaces — kept BYTE-IDENTICAL to the pre-registry allowedToolsFor
// (regression-locked in the tests) so existing headless agents are unchanged.
const RESEARCH_OVERWATCH = [
  'get_system_prompt', 'get_agent_context', 'query_graph', 'get_skill',
  'report_finding', 'research_cve', 'log_thought', 'agent_heartbeat',
  'acknowledge_agent_directive', 'ask_operator', 'submit_agent_transcript', 'update_agent', 'get_evidence',
];
const PLANNER_OVERWATCH = [
  'get_system_prompt', 'get_agent_context', 'query_graph', 'get_skill',
  'propose_plan', 'log_thought', 'agent_heartbeat',
  'acknowledge_agent_directive', 'ask_operator', 'submit_agent_transcript', 'update_agent',
];

const uniq = (xs: string[]): string[] => [...new Set(xs)];

const ARCHETYPES: Record<AgentArchetypeId, AgentArchetype> = {
  default: {
    id: 'default', label: 'General agent', role: 'default', scopeStrategy: 'subgraph',
    description: 'Full Overwatch surface. Use when no specialized type fits, or when a narrow type is too tight.',
    suitableFor: {}, tools: { full: true },
  },
  recon_scanner: {
    id: 'recon_scanner', label: 'Recon / scanner', role: 'default', scopeStrategy: 'cidr', defaultSkill: 'network_discovery',
    description: 'Network + service discovery: sweep a CIDR/IP, enumerate hosts, ports, and services. No shells, no credential handling.',
    defaultObjective: 'Discover and enumerate hosts and services for {target}; report what is alive and exposed.',
    suitableFor: { frontierTypes: ['network_discovery', 'incomplete_node'], nodeTypes: ['host', 'service'], rawTarget: true },
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...EXECUTE, ...RECON]) },
  },
  web_tester: {
    id: 'web_tester', label: 'Web app tester', role: 'default', scopeStrategy: 'subgraph', defaultSkill: 'webapp_testing',
    description: 'Web application testing: fuzz endpoints, probe auth, find web vulns. Can open sessions for exploitation.',
    defaultObjective: 'Test the web surface of {target} for exposed endpoints, auth weaknesses, and web vulnerabilities.',
    suitableFor: { frontierTypes: ['incomplete_node', 'untested_edge'], nodeTypes: ['webapp', 'url', 'service'] },
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...EXECUTE, ...SESSIONS]) },
  },
  credential_operator: {
    id: 'credential_operator', label: 'Credential operator', role: 'default', scopeStrategy: 'subgraph', defaultSkill: 'credential_spray',
    description: 'Validate, spray, and expand credentials/tokens (AWS/Entra/GitHub/OIDC). Focused on credential lifecycle, not broad recon.',
    defaultObjective: 'Validate and expand the credentials around {target}; map what access they unlock.',
    suitableFor: { frontierTypes: ['credential_test', 'inferred_edge'], nodeTypes: ['credential'] },
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...EXECUTE, ...CRED]) },
  },
  post_exploit: {
    id: 'post_exploit', label: 'Post-exploitation', role: 'default', scopeStrategy: 'subgraph', defaultSkill: 'post_exploitation',
    description: 'Work from a foothold: interactive sessions, lateral movement, local enumeration from compromised hosts.',
    defaultObjective: 'From the foothold at {target}, escalate and move laterally; capture credentials and reachable assets.',
    suitableFor: { frontierTypes: ['inferred_edge', 'network_pivot', 'cross_tier_pivot'], nodeTypes: ['host'] },
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...EXECUTE, ...SESSIONS, ...CRED]) },
  },
  cve_researcher: {
    id: 'cve_researcher', label: 'CVE researcher', role: 'research', backend: 'headless_mcp', scopeStrategy: 'subgraph', defaultSkill: 'cve-research',
    description: 'Read the public web for CVEs/PoCs and record findings. Never executes against targets.',
    defaultObjective: 'Research known vulnerabilities and exploits relevant to {target}; record findings with sources.',
    suitableFor: { frontierTypes: ['cve_research'] },
    tools: { full: false, native: ['WebSearch', 'WebFetch', 'ToolSearch'], overwatch: RESEARCH_OVERWATCH },
  },
  pathfinder: {
    id: 'pathfinder', label: 'Pathfinder', role: 'planner', scopeStrategy: 'scope-wide',
    description: 'Read-only attack-path analysis: find gaps and next hops to objectives, propose plans. Never executes.',
    defaultObjective: 'Analyze attack paths toward the objectives; surface the highest-value next hops as a proposed plan.',
    suitableFor: {},
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...ANALYZE, 'propose_plan']) },
  },
  report_scribe: {
    id: 'report_scribe', label: 'Report scribe', role: 'research', scopeStrategy: 'scope-wide',
    description: 'Read-only: turn confirmed graph state + evidence into draft report sections. Never executes against targets.',
    defaultObjective: 'Draft report sections from the confirmed findings and evidence in scope.',
    suitableFor: {},
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...ANALYZE, 'generate_report']) },
  },
  research: {
    id: 'research', label: 'Research (legacy role)', role: 'research', scopeStrategy: 'subgraph',
    description: 'Legacy research role — web research + finding recording, no target execution.',
    suitableFor: {}, tools: { full: false, native: ['WebSearch', 'WebFetch', 'ToolSearch'], overwatch: RESEARCH_OVERWATCH },
  },
  planner: {
    id: 'planner', label: 'Planner (legacy role)', role: 'planner', scopeStrategy: 'scope-wide',
    description: 'Legacy planner role — read state and propose plans, never executes or mutates.',
    suitableFor: {}, tools: { full: false, native: ['ToolSearch'], overwatch: PLANNER_OVERWATCH },
  },
};

export function listArchetypes(): AgentArchetype[] {
  return Object.values(ARCHETYPES);
}

export function getArchetype(id: string | undefined | null): AgentArchetype {
  return (id && ARCHETYPES[id as AgentArchetypeId]) || ARCHETYPES.default;
}

export function isArchetypeId(id: string | undefined | null): id is AgentArchetypeId {
  return !!id && id in ARCHETYPES;
}

/**
 * Build the `--allowedTools` surface string for an archetype OR a legacy role id.
 * Byte-identical to the pre-registry allowedToolsFor for default/research/planner.
 */
export function allowedToolsFor(idOrRole: AgentArchetypeId | AgentRole | string | undefined): string {
  const a = getArchetype(idOrRole);
  if (a.tools.full) return 'mcp__overwatch ToolSearch';
  const overwatch = a.tools.overwatch.map(t => `mcp__overwatch__${t}`).join(' ');
  return `${a.tools.native.join(' ')} ${overwatch}`.trim();
}

export interface RecommendInput {
  frontierType?: FrontierItem['type'];
  nodeType?: string;
  /** A raw IP/CIDR/domain target with no graph node yet (ad-hoc deploy). */
  rawTarget?: boolean;
}

/**
 * Recommend the default archetype for a target/task, mirroring the
 * campaign-planner frontier→strategy intuition. Falls back to `default`.
 */
export function recommendArchetype(input: RecommendInput): AgentArchetypeId {
  if (input.rawTarget) return 'recon_scanner';
  switch (input.frontierType) {
    case 'network_discovery': return 'recon_scanner';
    case 'incomplete_node': return input.nodeType === 'webapp' || input.nodeType === 'url' ? 'web_tester' : 'recon_scanner';
    case 'credential_test': return 'credential_operator';
    case 'inferred_edge': return 'credential_operator';
    case 'network_pivot':
    case 'cross_tier_pivot': return 'post_exploit';
    case 'cve_research': return 'cve_researcher';
    case 'idp_enumeration': return 'credential_operator';
    case 'untested_edge': return input.nodeType === 'webapp' || input.nodeType === 'url' ? 'web_tester' : 'post_exploit';
    default: break;
  }
  if (input.nodeType === 'credential') return 'credential_operator';
  if (input.nodeType === 'webapp' || input.nodeType === 'url') return 'web_tester';
  if (input.nodeType === 'host' || input.nodeType === 'service') return 'recon_scanner';
  return 'default';
}
