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
  | 'cve_researcher' | 'pathfinder' | 'report_scribe'
  | 'cloud_cartographer' | 'opsec_sentinel' | 'session_shepherd' | 'evidence_auditor'
  | 'osint_recon';

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
// Passive external-recon execution surface: the public-source OSINT binaries run
// through the instrumented argv runner (run_tool) — NO run_bash shell, NO
// interactive sessions, NO credential tools — plus the action lifecycle that turns
// their output into graph data. (subfinder, amass -passive, crt.sh via curl, whois,
// theHarvester, dnsx/httpx are all argv-form, so no shell is needed.)
const OSINT_EXECUTE = ['run_tool', 'validate_action', 'log_action_event', 'parse_output', 'report_finding', 'check_tools', 'track_process', 'check_processes'];
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
    id: 'recon_scanner', label: 'Recon / scanner', role: 'default', scopeStrategy: 'cidr', defaultSkill: 'network-recon',
    description: 'Network + service discovery: sweep a CIDR/IP, enumerate hosts, ports, and services. No shells, no credential handling.',
    defaultObjective: 'Discover and enumerate hosts and services for {target}; report what is alive and exposed.',
    suitableFor: { frontierTypes: ['network_discovery', 'incomplete_node'], nodeTypes: ['host', 'service'], rawTarget: true },
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...EXECUTE, ...RECON]) },
  },
  web_tester: {
    id: 'web_tester', label: 'Web app tester', role: 'default', scopeStrategy: 'subgraph', defaultSkill: 'web-discovery',
    description: 'Web application testing: fuzz endpoints, probe auth, find web vulns. Can open sessions for exploitation.',
    defaultObjective: 'Test the web surface of {target} for exposed endpoints, auth weaknesses, and web vulnerabilities.',
    suitableFor: { frontierTypes: ['incomplete_node', 'untested_edge'], nodeTypes: ['webapp', 'url', 'service'] },
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...EXECUTE, ...SESSIONS]) },
  },
  credential_operator: {
    id: 'credential_operator', label: 'Credential operator', role: 'default', scopeStrategy: 'subgraph', defaultSkill: 'password-spraying',
    description: 'Validate, spray, and expand credentials/tokens (AWS/Entra/GitHub/OIDC). Focused on credential lifecycle, not broad recon.',
    defaultObjective: 'Validate and expand the credentials around {target}; map what access they unlock.',
    suitableFor: { frontierTypes: ['credential_test', 'inferred_edge'], nodeTypes: ['credential'] },
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...EXECUTE, ...CRED]) },
  },
  post_exploit: {
    id: 'post_exploit', label: 'Post-exploitation', role: 'default', scopeStrategy: 'subgraph', defaultSkill: 'post-exploitation',
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
    id: 'pathfinder', label: 'Pathfinder', role: 'planner', scopeStrategy: 'scope-wide', defaultSkill: 'attack-path-planning',
    description: 'Read-only attack-path analysis: find gaps and next hops to objectives, propose plans. Never executes.',
    defaultObjective: 'Analyze attack paths toward the objectives; surface the highest-value next hops as a proposed plan.',
    suitableFor: {},
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...ANALYZE, 'propose_plan']) },
  },
  report_scribe: {
    id: 'report_scribe', label: 'Report scribe', role: 'research', scopeStrategy: 'scope-wide', defaultSkill: 'pentest-report-structure',
    description: 'Read-only: turn confirmed graph state + evidence into draft report sections. Never executes against targets.',
    defaultObjective: 'Draft report sections from the confirmed findings and evidence in scope.',
    suitableFor: {},
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...ANALYZE, 'generate_report']) },
  },
  cloud_cartographer: {
    id: 'cloud_cartographer', label: 'Cloud cartographer', role: 'default', scopeStrategy: 'subgraph', defaultSkill: 'cloud-federation-mapping',
    description: 'Enumerate cloud + identity (AWS/Entra/GitHub/OIDC): expand captured credentials, map federation and cloud-to-on-prem pivots.',
    defaultObjective: 'Expand the cloud credentials around {target} and map the access + federation they unlock.',
    suitableFor: { nodeTypes: ['credential', 'cloud_identity', 'cloud_resource', 'idp_application'] },
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...EXECUTE, ...CRED]) },
  },
  opsec_sentinel: {
    id: 'opsec_sentinel', label: 'OPSEC sentinel', role: 'research', scopeStrategy: 'scope-wide', defaultSkill: 'opsec-defense-signals',
    description: 'Read-only OPSEC monitor: track the noise budget + defensive signals, flag risk, and recommend an approach. Never executes.',
    defaultObjective: 'Assess the engagement OPSEC posture: noise spent, defensive signals, and the safest approach right now.',
    suitableFor: {},
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...ANALYZE, 'get_opsec_status']) },
  },
  session_shepherd: {
    id: 'session_shepherd', label: 'Session shepherd', role: 'default', scopeStrategy: 'scope-wide', defaultSkill: 'session-lifecycle-monitoring',
    description: 'Watch interactive sessions: read buffers, surface stale/orphaned sessions and their ownership. Read-only — no new target execution.',
    defaultObjective: 'Review the open sessions: which are live, stale, or orphaned, and what each is doing.',
    suitableFor: {},
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...ANALYZE, 'list_sessions', 'read_session']) },
  },
  evidence_auditor: {
    id: 'evidence_auditor', label: 'Evidence auditor', role: 'research', scopeStrategy: 'scope-wide', defaultSkill: 'evidence-auditing',
    description: 'Read-only: audit findings + their evidence chains for proof readiness; surface gaps before reporting. Never executes.',
    defaultObjective: 'Audit the confirmed findings and their evidence: which are client-ready vs. need more proof.',
    suitableFor: {},
    tools: { full: false, native: ['ToolSearch'], overwatch: uniq([...BASE, ...ANALYZE, 'get_finding_readiness']) },
  },
  osint_recon: {
    id: 'osint_recon', label: 'OSINT recon', role: 'research', backend: 'headless_mcp', scopeStrategy: 'scope-wide', defaultSkill: 'osint-recon',
    description: 'Passive external-recon: map the attack surface (subdomains, DNS, netblocks/ASNs, orgs, emails) from PUBLIC sources via run_tool (subfinder/amass/crt.sh/whois) + web research. No shells, no sessions, no credential tools.',
    defaultObjective: 'Map the external attack surface of {target} from public sources; record subdomains, domains, netblocks, organizations, and emails.',
    suitableFor: { frontierTypes: ['domain_enumeration'], nodeTypes: ['domain', 'organization', 'asn', 'email'] },
    tools: { full: false, native: ['WebSearch', 'WebFetch', 'ToolSearch'], overwatch: uniq([...BASE, ...OSINT_EXECUTE, ...RECON]) },
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

// Per-archetype headless bootstrap mission. Decoupled from the legacy `role`
// bucket so a specialized type gets a brief that matches its ACTUAL tools and
// job (e.g. pathfinder analyzes paths rather than translating operator
// commands; report_scribe drafts via generate_report rather than research_cve).
// The runner wraps this with the common preamble, the task objective, and a
// uniform submit/update close — so missions describe the role + tools only.
// Shared by cve_researcher AND the legacy `research` role — the automatic CVE
// dispatch (task-execution-service) registers role:'research' with no archetype,
// so this MUST carry the full research_cve arg shape + the "call once / empty
// list marks the service checked" instruction that retires the frontier item.
const CVE_MISSION =
  `YOUR ROLE IS CVE/EXPLOIT RESEARCH. Your assigned node is a service with a known product/version. Research the way an operator would: use WebSearch + WebFetch to find known vulnerabilities AND public proof-of-concept exploits for that exact product+version (vendor advisories, NVD, Exploit-DB, GitHub, packetstorm), judging whether each CVE actually applies to the discovered version. Do NOT run any target-facing tools — read-the-web + record-findings only. Record each credible candidate with research_cve({ service_id, candidates: [{ cve, title, cvss?, vuln_type?, exploit_available?, poc_url?, applicable, confidence?, notes }], summary }) — call it exactly once (or with an empty list if none apply) so the service is marked checked. Done when research_cve has been called for the service (with candidates, or an empty list if none apply).`;

const MISSIONS: Record<AgentArchetypeId, string> = {
  default:
    `Do only the work within your scoped subgraph and objective. Route every target-facing action through validate_action + run_tool/run_bash, turn raw output into graph data with parse_output/report_finding, and heartbeat periodically. Done when the scoped objective is satisfied and every useful discovery is in the graph (parse_output/report_finding), not just prose.`,
  recon_scanner:
    `YOUR ROLE IS RECON & SERVICE DISCOVERY. Sweep and enumerate the target's hosts, ports, and services using run_tool/run_bash (call validate_action first), then turn raw output into graph data with parse_output/report_finding. You have NO interactive sessions or credential tools — discovery only. Done when every live host/service in scope is a graph node with its ports/services recorded via report_finding — leave nothing only in stdout.`,
  web_tester:
    `YOUR ROLE IS WEB APPLICATION TESTING. Probe the target's web surface — endpoints, auth, and web vulnerabilities — via validate_action + run_tool/run_bash, and open_session/send_to_session for interactive exploitation when warranted. Record findings with parse_output/report_finding. Done when the target's endpoints and auth surface are mapped as nodes/edges and each candidate weakness is a finding with evidence.`,
  credential_operator:
    `YOUR ROLE IS CREDENTIAL OPERATIONS. Validate, spray, and expand credentials and tokens (validate_token_credential + the expand_* tools), and map the access they unlock. Record findings with report_finding. You have NO interactive sessions — credential lifecycle only. Done when each credential's validity and the access it unlocks is recorded as findings/edges (or the credential is marked invalid).`,
  post_exploit:
    `YOUR ROLE IS POST-EXPLOITATION FROM A FOOTHOLD. Work interactively via open_session/send_to_session: enumerate locally, move laterally, and capture credentials and reachable assets. Route execution through validate_action and record findings with report_finding. Done when the foothold's reachable assets, captured credentials, and lateral edges are recorded as graph findings.`,
  cve_researcher: CVE_MISSION,
  pathfinder:
    `YOUR ROLE IS READ-ONLY ATTACK-PATH ANALYSIS. Use query_graph + find_paths + get_agent_context to find the highest-value next hops and the gaps blocking progress toward the objectives, then surface them as a proposed plan via propose_plan({ agent_id, task_id, summary, rationale, ops }). You CANNOT execute against targets or mutate the graph (no run_bash/run_tool/sessions). You PROPOSE; the operator CONFIRMS. Done when a proposed plan of the highest-value next hops is submitted via propose_plan (or the transcript explains why no viable path exists).`,
  report_scribe:
    `YOUR ROLE IS REPORT DRAFTING (READ-ONLY). Read the confirmed graph state and evidence in scope (query_graph, get_evidence, explain_action, get_timeline) and draft report sections with generate_report. You CANNOT execute against targets or mutate the graph — synthesis only. Done when the requested report sections are drafted from confirmed findings and evidence via generate_report.`,
  cloud_cartographer:
    `YOUR ROLE IS CLOUD + IDENTITY CARTOGRAPHY. Expand captured cloud credentials/tokens with the expand_* tools (AWS/Entra/GitHub/OIDC), run the resulting recon via validate_action + run_tool, and turn output into graph data with parse_output/report_finding. Map federation (OIDC/SAML role assumption) and cloud-to-on-prem pivots. Done when each cloud credential's reachable resources, roles, and federation edges are recorded as graph findings.`,
  opsec_sentinel:
    `YOUR ROLE IS READ-ONLY OPSEC MONITORING. Use get_opsec_status (+ query_graph) to assess the noise budget spent, the defensive signals observed (lockouts, rate limits, honeypots, resets), and the recommended approach. You CANNOT execute against targets or mutate the graph. Done when you have reported the current OPSEC posture and any risk (budget near exhaustion, active defensive signals) as a finding/note for the operator.`,
  session_shepherd:
    `YOUR ROLE IS READ-ONLY SESSION OVERSIGHT. Use list_sessions + read_session (+ query_graph) to review the open interactive sessions: which are live, idle/stale, or orphaned (owner agent gone), and what each is doing. You do NOT run new target commands. Done when each open session's state and ownership is reported, with stale/orphaned ones flagged for the operator.`,
  evidence_auditor:
    `YOUR ROLE IS READ-ONLY EVIDENCE AUDITING. Start with get_finding_readiness for the per-finding readiness rollup (client_ready / needs_validation / draft + the concrete gaps), then drill in with get_evidence + query_graph + explain_action to confirm each chain's proof. You CANNOT execute against targets or mutate the graph. Done when each finding's proof readiness is assessed and the gaps are reported for the operator.`,
  osint_recon:
    `YOUR ROLE IS PASSIVE EXTERNAL-RECON (OSINT). Map the target's external attack surface from PUBLIC sources only — subdomains, DNS, netblocks/ASNs, organizations, and emails. Run the passive binaries via validate_action + run_tool (subfinder, amass with -passive, crt.sh via curl, whois, theHarvester) and use WebSearch/WebFetch for web OSINT; turn raw output into graph data with parse_output/report_finding. You have NO interactive sessions, NO credential tools, and NO raw shell — do NOT actively scan, brute-force, or exploit; public sources only. After enumerating a domain, stamp it (subdomains_enumerated_at) so its frontier item retires even if nothing new was found. Done when the in-scope external surface is on the graph (subdomains, domains, asns, orgs, emails via parse_output/report_finding) — leave nothing only in stdout.`,
  research: CVE_MISSION,
  planner:
    `YOUR ROLE IS OPERATOR-COMMAND PLANNING. Translate the free-form operator command in your objective into a plan of operator operations and submit it with propose_plan({ agent_id, task_id, command, summary, rationale, ops }) for the operator to confirm. You PROPOSE; the operator CONFIRMS; the dashboard EXECUTES. You CANNOT execute against targets or mutate the graph (no run_bash/run_tool/sessions). Use query_graph + get_agent_context to understand state, and reference ONLY the exact task_ids and action_ids listed in your objective. If the command cannot be expressed as the allowed ops, do NOT propose — explain why in submit_agent_transcript. Done when a plan of valid ops is submitted via propose_plan, or the transcript explains why the command can't be expressed.`,
};

/** The headless bootstrap mission for an archetype id or legacy role id. */
export function bootstrapMission(idOrRole: string | undefined | null): string {
  return MISSIONS[getArchetype(idOrRole).id];
}

// Per-archetype success criterion — the structured "done when" the agent should
// stop at. Mirrors each mission's closing "Done when …" clause, but as data the
// sub-agent prompt's Brief can render directly (so lean stops synthesizing a
// generic done-test from the frontier-item type — its known weak spot). Authored
// to match the missions above; keep them in sync. (Full consolidation onto the
// AgentArchetype record + AGENTS.md generation is a deferred follow-up.)
const DONE_TESTS: Record<AgentArchetypeId, string> = {
  default: 'the scoped objective is satisfied and every useful discovery is in the graph (parse_output/report_finding), not just prose',
  recon_scanner: 'every live host/service in scope is a graph node with its ports/services recorded via report_finding — nothing left only in stdout',
  web_tester: "the target's endpoints and auth surface are mapped as nodes/edges and each candidate weakness is a finding with evidence",
  credential_operator: "each credential's validity and the access it unlocks is recorded as findings/edges (or the credential is marked invalid)",
  post_exploit: "the foothold's reachable assets, captured credentials, and lateral edges are recorded as graph findings",
  cve_researcher: 'research_cve has been called for the service (with candidates, or an empty list if none apply)',
  pathfinder: 'a proposed plan of the highest-value next hops is submitted via propose_plan (or the transcript explains why no viable path exists)',
  report_scribe: 'the requested report sections are drafted from confirmed findings and evidence via generate_report',
  cloud_cartographer: "each cloud credential's reachable resources, roles, and federation edges are recorded as graph findings",
  opsec_sentinel: 'the current OPSEC posture and any risk (budget near exhaustion, active defensive signals) is reported for the operator',
  session_shepherd: "each open session's state and ownership is reported, with stale/orphaned ones flagged",
  evidence_auditor: "each finding's proof readiness is assessed and the gaps are reported for the operator",
  osint_recon: 'the in-scope external surface is on the graph (subdomains, domains, asns, orgs, emails via parse_output/report_finding) — nothing left only in stdout',
  research: 'research_cve has been called for the service (with candidates, or an empty list if none apply)',
  planner: "a plan of valid ops is submitted via propose_plan, or the transcript explains why the command can't be expressed",
};

/** The structured success criterion for an archetype id or legacy role id —
 *  registry-sourced, for the sub-agent prompt's "Done when" line. */
export function doneTestFor(idOrRole: string | undefined | null): string {
  return DONE_TESTS[getArchetype(idOrRole).id];
}

export function listArchetypes(): AgentArchetype[] {
  return Object.values(ARCHETYPES);
}

/** The sub-agent archetype catalog rendered as markdown, derived from the
 *  registry (label / id / target-facing-ness / description / done-test). This is
 *  the single source for the AGENTS.md "Sub-agent archetypes" section — a
 *  drift-check test asserts the checked-in section equals this, and
 *  `npm run gen:docs` regenerates it. Keeps the offline fallback in sync with the
 *  registry without hand-editing (the CLAUDE.md prompt-generator↔AGENTS.md triad). */
export function generateSubAgentArchetypeReference(): string {
  return listArchetypes()
    .map((a) => {
      const readOnly = isTargetFacing(a.id) ? '' : ' _(read-only)_';
      return `- **${a.label}** (\`${a.id}\`)${readOnly} — ${a.description} _Done when:_ ${doneTestFor(a.id)}.`;
    })
    .join('\n');
}

export function getArchetype(id: string | undefined | null): AgentArchetype {
  return (id && ARCHETYPES[id as AgentArchetypeId]) || ARCHETYPES.default;
}

export function isArchetypeId(id: string | undefined | null): id is AgentArchetypeId {
  return !!id && id in ARCHETYPES;
}

/**
 * Does an archetype run target-facing commands (vs. read-only analysis)? True iff
 * its tool surface includes execution (`run_bash`) or is the full default surface.
 * Used by the per-subnet/target dispatch cap — read-only archetypes (pathfinder,
 * report_scribe, opsec_sentinel, session_shepherd, evidence_auditor, cve_researcher,
 * research, planner) don't count toward target blast-radius limits. An operator
 * policy may override the classification with an explicit allow-list of ids.
 */
export function isTargetFacing(idOrRole: string | undefined | null, override?: string[]): boolean {
  const a = getArchetype(idOrRole);
  if (override && override.length > 0) return override.includes(a.id);
  return a.tools.full === true || a.tools.overwatch.includes('run_bash');
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
    case 'domain_enumeration': return 'osint_recon';
    case 'idp_enumeration': return 'credential_operator';
    case 'untested_edge': return input.nodeType === 'webapp' || input.nodeType === 'url' ? 'web_tester' : 'post_exploit';
    default: break;
  }
  if (input.nodeType === 'credential') return 'credential_operator';
  if (input.nodeType === 'webapp' || input.nodeType === 'url') return 'web_tester';
  if (input.nodeType === 'host' || input.nodeType === 'service') return 'recon_scanner';
  if (input.nodeType === 'domain' || input.nodeType === 'subdomain' || input.nodeType === 'organization' || input.nodeType === 'asn' || input.nodeType === 'email') return 'osint_recon';
  return 'default';
}
