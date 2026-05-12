// ============================================================
// Overwatch — Prompt Generator
// Generates dynamic system prompts from engagement state.
// ============================================================

import type { GraphEngine } from './graph-engine.js';
import type { EngagementConfig, EngagementState, AgentTask, LabProfile } from '../types.js';
import { inferProfile } from '../types.js';
import { timeToExpiry } from './credential-utils.js';
import { SkillIndex } from './skill-index.js';
import type { TechniqueStats } from './knowledge-base.js';

interface PromptContext {
  state: EngagementState;
  engine: GraphEngine;
}

export type PromptRole = 'primary' | 'sub_agent';

export interface GeneratePromptOptions {
  role: PromptRole;
  agent_id?: string;
  include_state?: boolean;
  include_tools?: boolean;
  max_prompt_tokens?: number;
}

// ============================================================
// Token estimation — chars/4 heuristic (good enough for budgeting)
// ============================================================

export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

// Section priority levels: higher priority = always included first
const enum SectionPriority {
  CRITICAL = 4,   // identity, core loop — cannot be trimmed
  HIGH = 3,       // tactical, anti-patterns, key principles
  MEDIUM = 2,     // tool table, state snapshot
  LOW = 1,        // situational awareness subsections
}

interface PrioritizedSection {
  content: string;
  priority: SectionPriority;
  label: string;
  summarizable?: boolean;  // can be replaced with a summary when over budget
}

export interface ToolEntry {
  name: string;
  description: string;
}

export function generateSystemPrompt(
  engine: GraphEngine,
  registeredTools: ToolEntry[],
  options: GeneratePromptOptions,
): string {
  const state = engine.getState({ activityCount: 10 });

  if (options.role === 'sub_agent') {
    return generateSubAgentPrompt(state, registeredTools, options, engine);
  }
  return generatePrimaryPrompt(state, registeredTools, options, engine);
}

// ============================================================
// Primary orchestrator prompt
// ============================================================

const DEFAULT_MAX_PROMPT_TOKENS = 8000;

function generatePrimaryPrompt(
  state: EngagementState,
  tools: ToolEntry[],
  options: GeneratePromptOptions,
  engine: GraphEngine,
): string {
  const profile = inferProfile(state.config);
  const ctx: PromptContext = { state, engine };
  const maxTokens = options.max_prompt_tokens ?? state.config.max_prompt_tokens ?? DEFAULT_MAX_PROMPT_TOKENS;

  // Build prioritized sections
  const prioritized: PrioritizedSection[] = [
    { content: generateIdentitySection(state.config), priority: SectionPriority.CRITICAL, label: 'identity' },
    { content: generateCoreLoopSection(profile, !!state.config.opsec?.enabled), priority: SectionPriority.CRITICAL, label: 'core_loop' },
    { content: generateTacticalSection(), priority: SectionPriority.HIGH, label: 'tactical' },
    { content: generateKeyPrinciplesSection(state.config), priority: SectionPriority.HIGH, label: 'key_principles' },
  ];

  if (options.include_tools !== false) {
    prioritized.push({ content: generateToolTableSection(tools), priority: SectionPriority.MEDIUM, label: 'tool_table', summarizable: true });
  }

  if (options.include_state !== false) {
    prioritized.push({ content: generateStateSnapshotSection(state), priority: SectionPriority.MEDIUM, label: 'state_snapshot' });
    prioritized.push({ content: generateSituationalSection(ctx), priority: SectionPriority.LOW, label: 'situational', summarizable: true });
  }

  const antiPatterns = generateAntiPatternsSection(ctx);
  if (antiPatterns) {
    prioritized.push({ content: antiPatterns, priority: SectionPriority.HIGH, label: 'anti_patterns' });
  }

  return assembleSectionsWithinBudget(prioritized, maxTokens);
}

function assembleSectionsWithinBudget(sections: PrioritizedSection[], maxTokens: number): string {
  // Sort by priority descending (CRITICAL first)
  const sorted = [...sections].sort((a, b) => b.priority - a.priority);

  let totalTokens = 0;
  const included: string[] = [];

  for (const section of sorted) {
    if (!section.content) continue;
    const sectionTokens = estimateTokens(section.content);

    if (totalTokens + sectionTokens <= maxTokens) {
      included.push(section.content);
      totalTokens += sectionTokens;
    } else if (section.priority === SectionPriority.CRITICAL) {
      // Critical sections are always included regardless of budget
      included.push(section.content);
      totalTokens += sectionTokens;
    } else if (section.summarizable) {
      // Try a compressed summary instead
      const summary = summarizeSection(section);
      const summaryTokens = estimateTokens(summary);
      if (totalTokens + summaryTokens <= maxTokens) {
        included.push(summary);
        totalTokens += summaryTokens;
      }
      // else: section is completely dropped
    }
    // else: non-summarizable section that doesn't fit is dropped
  }

  return included.join('\n\n');
}

function summarizeSection(section: PrioritizedSection): string {
  const lineCount = section.content.split('\n').length;
  switch (section.label) {
    case 'tool_table':
      // Count tool rows in the table
      const toolLines = section.content.split('\n').filter(l => l.startsWith('| `'));
      return `## Tool Reference\n\n${toolLines.length} tools available. Use \`get_system_prompt(include_tools=true)\` or check docs for full reference.`;
    case 'situational': {
      // Compress multi-section situational awareness to headlines
      const headings = section.content.split('\n')
        .filter(l => l.startsWith('### '))
        .map(l => l.replace('### ', '- '));
      if (headings.length === 0) return '';
      return `## Situational Awareness (compressed — ${lineCount} lines trimmed to fit token budget)\n\n${headings.join('\n')}\n\nUse \`get_state()\` for full details.`;
    }
    default:
      // Generic: take first 3 lines
      const firstLines = section.content.split('\n').slice(0, 3).join('\n');
      return `${firstLines}\n\n*(Section truncated to fit token budget — ${lineCount} lines total)*`;
  }
}

// ============================================================
// Sub-agent prompt
// ============================================================

function generateSubAgentPrompt(
  state: EngagementState,
  tools: ToolEntry[],
  options: GeneratePromptOptions,
  engine: GraphEngine,
): string {
  const sections: string[] = [];

  // Identity
  const agentContext = options.agent_id
    ? state.active_agents.find(a => a.id === options.agent_id || a.agent_id === options.agent_id)
    : undefined;

  sections.push(generateSubAgentIdentitySection(state.config, agentContext));

  // Scoped tool subset — must stay in sync with the sub-agent workflow
  // section below (and the AGENTS.md sub-agent tool list).
  const subAgentToolNames = new Set([
    'get_agent_context', 'validate_action', 'log_action_event', 'log_thought',
    'run_bash', 'run_tool',
    'parse_output', 'report_finding', 'submit_agent_transcript',
    'query_graph', 'get_skill',
    'open_session', 'write_session', 'read_session', 'send_to_session',
    'list_sessions', 'close_session', 'resize_session', 'signal_session',
    'update_session', 'get_evidence',
  ]);
  const scopedTools = tools.filter(t => subAgentToolNames.has(t.name));

  if (options.include_tools !== false) {
    sections.push(generateToolTableSection(scopedTools));
  }

  sections.push(generateSubAgentWorkflowSection());
  sections.push(generateTacticalSection());

  if (options.include_state !== false && agentContext) {
    sections.push(generateAgentContextSection(agentContext, state, engine));
  }

  return sections.join('\n\n');
}

// ============================================================
// Section generators
// ============================================================

function generateIdentitySection(config: EngagementConfig): string {
  const lines = [
    '# Overwatch — Primary Session Instructions',
    '',
    'You are an offensive security operator running an authorized engagement. Your state, memory, and reasoning substrate is the Overwatch MCP orchestrator server. You do NOT need to hold engagement state in your context — the graph holds everything.',
    '',
    '## Engagement Briefing',
    '',
    `- **Name:** ${config.name}`,
    `- **ID:** ${config.id}`,
  ];

  if (config.scope.cidrs.length > 0) {
    lines.push(`- **Scope CIDRs:** ${config.scope.cidrs.join(', ')}`);
  }
  if (config.scope.domains.length > 0) {
    lines.push(`- **Scope Domains:** ${config.scope.domains.join(', ')}`);
  }
  if (config.opsec && config.opsec.enabled) {
    lines.push(`- **OPSEC Profile:** ${config.opsec.name}`);
    if (config.opsec.blacklisted_techniques && config.opsec.blacklisted_techniques.length > 0) {
      lines.push(`- **OPSEC Blacklisted Techniques:** ${config.opsec.blacklisted_techniques.join(', ')}`);
    }
  }
  if (config.objectives && config.objectives.length > 0) {
    lines.push('', '### Objectives');
    for (const obj of config.objectives) {
      const status = obj.achieved ? '[DONE]' : '[    ]';
      lines.push(`- ${status} **${obj.description}**`);
    }
  }

  return lines.join('\n');
}

function generateCoreLoopSection(profile: LabProfile, opsecEnabled: boolean): string {
  const vetoNote = opsecEnabled ? 'out-of-scope, duplicates, and hard OPSEC vetoes are already removed' : 'out-of-scope and duplicate items are already removed';
  const opsecScoringLine = opsecEnabled ? "\n   - What's the risk/reward ratio given our OPSEC profile?" : '';
  const base = `## Core Loop

1. **Start every session** (including after compaction) by calling \`get_state()\`. This gives you the complete engagement briefing from the graph — scope, discoveries, access, objectives, frontier.

2. **Assess the frontier** by calling \`next_task()\`. You'll receive candidate actions pre-filtered by the deterministic layer (${vetoNote}). Everything else is yours to score.

3. **Score and prioritize** the candidates. For each, consider:
   - Does this open a multi-step attack chain?
   - What's the likely defensive posture of the target?
   - What sequencing makes sense (what should happen before what)?${opsecScoringLine}
   - Does this move us closer to an objective?

   **Externalize your reasoning.** Call \`log_thought({ kind: "decision", thought: "...", frontier_item_id, considered_alternatives: [...] })\` before you commit to a candidate. This is how the engagement retains a record of *why* you chose what you chose — essential for retrospective and for surviving compaction.

4. **Explore the graph** with \`query_graph()\` whenever the frontier doesn't capture a pattern you're seeing.

5. **Validate before executing** by calling \`validate_action()\` with your proposed action. **Always pass \`frontier_item_id\`** from \`next_task()\`.

6. **Log execution start** with \`log_action_event(event_type="action_started")\` before major execution. **Always pass both \`action_id\` and \`frontier_item_id\`.**

7. **Execute the action** using the appropriate tools.
   - For one-shot binary + argv invocations, prefer \`run_tool\` (no shell parsing, no injection risk) — it auto-runs validation, the approval gate, action_started/completed/failed logging, evidence capture, and optional \`parse_with\` ingest in a single call. Use \`run_bash\` only when you genuinely need shell features (pipes, redirects, globs).
   - For interactive or long-lived shells, use \`open_session\` + \`send_to_session\`.
   - For everything else (custom tooling, manual observations), follow the explicit validate → log_started → execute → parse/report → log_completed flow.

8. **Parse or report results immediately**:
   - Use \`parse_output()\` for supported parser output. **Always pass \`action_id\` and \`frontier_item_id\`.**
   - Use \`report_finding()\` for manual observations or already-structured data. **Always pass \`action_id\` and \`frontier_item_id\`.**

9. **Log the final outcome** with \`log_action_event(event_type="action_completed" | "action_failed")\`. **Always pass \`action_id\`.** (\`run_bash\` and \`run_tool\` do this for you.)

10. **Dispatch sub-agents** for parallel work using Overwatch's \`dispatch_agents()\` (or \`register_agent()\` for one-off). **Prefer Overwatch dispatch over the host runtime's built-in subagent/Task tool** — only Overwatch-registered agents carry a frontier_item_id, lease, and dashboard surface. A subagent spawned via the host runtime that calls \`run_bash\` directly will auto-register on first tool call (so it appears in the AgentsPanel), but it lacks skill/scope/lease metadata and will look like an anonymous worker.
   - **`credential_test` frontier items are automatically executed** by the scripted runner when the dashboard is running — token credentials with a `cred_value` are validated via curl through the approval gate without operator intervention. You do NOT need to dispatch agents or manually call `validate_token_credential` for these items; they resolve on their own. Call `get_state()` to see results after the runner finishes. Dispatch agents for credential_test items only if you need LLM reasoning (e.g., unusual audiences, custom parsers).

11. **Monitor and re-plan** by periodically calling \`get_state()\`.

12. **Repeat** until all objectives are achieved or the operator redirects.`;

  const profileHints = getProfileHints(profile);
  if (profileHints) {
    return base + '\n\n### Profile-Specific Guidance (' + profile + ')\n\n' + profileHints;
  }
  return base;
}

function getProfileHints(profile: LabProfile): string | null {
  switch (profile) {
    case 'goad_ad':
      return [
        '- Prioritize credential chain completion: if 2 of 3 hops are confirmed, the last hop is highest value.',
        '- Use BloodHound paths (`find_paths`) to identify shortest routes to DA/EA.',
        '- Sequence: enumerate → Kerberoast/ASREProast → credential spray → lateral movement → DCSync.',
        '- After every new credential, immediately evaluate POTENTIAL_AUTH edges it unlocks.',
        '- Check ADCS certificate templates — ESC1-ESC13 paths may bypass password requirements entirely.',
      ].join('\n');
    case 'web_app':
      return [
        '- **CVE-first**: When you identify a service + version, search for known CVEs *before* attempting brute-force or hash cracking.',
        '- Prioritize: authenticated re-scan > IDOR/auth bypass > SQLi/RCE > brute-force.',
        '- Check for default credentials on all identified web frameworks and CMS platforms.',
        '- After SQLi discovery, evaluate RCE potential (stacked queries, file write) before credential extraction.',
        '- API endpoint enumeration: look for `/api/`, `/v1/`, `/graphql` paths on every webapp.',
      ].join('\n');
    case 'cloud':
      return [
        '- **IAM first**: Enumerate IAM policies and role trust before testing network services.',
        '- Check for IMDS v1 on every EC2/VM instance — it\'s often the cheapest credential theft path.',
        '- Evaluate cross-account role chaining: `ASSUMES_ROLE` edges may span account boundaries.',
        '- Lambda/Functions with attached IAM roles are high-value targets for privilege escalation.',
        '- Check S3/Blob/GCS bucket policies for public access before attempting authenticated access.',
      ].join('\n');
    case 'hybrid':
      return [
        '- This engagement spans both on-prem and cloud — look for pivot points between the two.',
        '- AD Connect / Azure AD Sync services are high-value targets for credential bridging.',
        '- On-prem service accounts may have cloud IAM equivalents — check for credential reuse.',
        '- Cloud-to-on-prem: managed identities on VMs with AD access, Azure Arc agents.',
        '- On-prem-to-cloud: ADFS/PTA agents, Azure AD password hash sync.',
      ].join('\n');
    case 'network':
      return [
        '- Prioritize service enumeration across all subnets before deep-diving individual hosts.',
        '- Group hosts by service fingerprint — similar services likely share vulnerabilities.',
        '- Check for default SNMP communities, IPMI hash disclosure, UPnP on network devices.',
        '- Pivot through compromised hosts to reach isolated network segments.',
      ].join('\n');
    case 'single_host':
      return [
        '- Focus on thorough enumeration of all services on the target before exploitation.',
        '- Check all service versions against CVE databases — prioritize known RCE over brute-force.',
        '- Local privilege escalation: check SUID, capabilities, cron, writable paths, kernel version.',
        '- Enumerate all users and credentials — look for password reuse across services.',
      ].join('\n');
    default:
      return null;
  }
}

function generateKeyPrinciplesSection(config: EngagementConfig): string {
  const lines = [
    '## Key Principles',
    '',
    '- **The graph is your memory.** After compaction, `get_state()` reconstructs everything. The default invocation is now genuinely read-only — pass `{ snapshot: true }` at session bootstrap or when you want the call to also persist a state snapshot for retrospective fidelity.',
    '- **Report early, report often.** Every `report_finding()` call triggers inference rules.',
    '- **Use structured action logging.** `validate_action()` → `log_action_event()` for causal linkage.',
    '- **Thread `frontier_item_id` through every call.** Pass it to `validate_action`, `log_action_event`, `parse_output`, and `report_finding`. Without it, retrospective attribution falls back to text heuristics. The `validate_action` response returns `frontier_item_id` and `frontier_type` for easy reference.',
    '- **The deterministic layer is a guardrail, not a brain.** You do the offensive thinking. The `graph_metrics.confidence` field on a frontier item is a **score multiplier**, not a probability — KB and chain boosts can push it >1.0 to signal items the planner promotes. Treat it as relative ordering, not calibrated confidence.',
    '- **Validate before you execute.** Every significant action goes through `validate_action()` first. If `opsec_skipped: true` is returned, OPSEC enforcement is disabled for this engagement — your scope checks ran but blacklist/noise/time-window did not.',
    '- **Use `query_graph()` liberally.** The graph may contain patterns the frontier doesn\'t surface.',
    '',
    '### Sessions (interactive shells / sockets)',
    '',
    '- **Always pass `default_validation` to `open_session`** for SSH/socket-connect sessions: `{ technique, target_ip?, target_url?, allow_unverified_scope? }`. Every subsequent `send_to_session` inherits it and runs the full action lifecycle (validate → action_started → evidence → action_completed). Without it, sends require a per-call `technique`.',
    '- **`send_to_session` is the instrumented send.** It validates scope, persists captured output as evidence, and emits action_started/completed. Use `write_session` only for partial I/O (password prompts, REPL navigation) where lifecycle overhead is wrong.',
    '- **A closed session is dead.** Once a shell exits or the watchdog reaps the session, that `HAS_SESSION` edge is marked `session_live: false`. Frontier, path reachability, and objective achievement now ignore dead sessions. If you want to reach a host through a previous compromise, confirm the session is still live (or open a new one).',
    '- **Long-running sub-agents must call `agent_heartbeat({ task_id })` periodically.** Otherwise the watchdog interrupts the task and releases its frontier lease.',
    '',
    '### Visibility & audit',
    '',
    '- **`get_decision_log` / `get_timeline` / `explain_action`** are read-only views derived from the activity log. Use them when you need to answer "why did I take action X?", "what was true at time T?", or "what did the planner suggest before I overrode it?" — they\'re the human-facing audit surface.',
    '- **Engagements with `engagement_nonce` are deterministic and replayable.** Action IDs (`act_<sha256>…`) and event IDs are derived from the nonce + agent + sequence + command, not random. Evidence blobs are content-addressed by sha256 — identical scanner output dedups automatically. State is journaled (WAL) and survives mid-mutation crashes.',
    '- **Reports default to evidence-rich (operator-internal).** Pass `{ client_safe: true }` to `generate_report` for client deliverables — strips `cred_value`, raw stdout, and operator paths; outputs `report.client-safe.<ext>`. Reports persist to the engagement archive by default and are listable from the dashboard **Findings** tab → Reports section.',
  '- **Dashboard tabs:** Overview · Agents · Sessions · Actions · Frontier · Activity · Evidence · Identity · Credentials · Attack Paths · Findings · Campaigns. The **Credentials** tab shows all captured tokens/keys with status, reachability, and reveal/copy for `cred_value`. The **Findings** tab shows classified severity groups + report archive.',
    '',
    '### Scope guardrails',
    '',
    '- If you invoke a network-capable binary (`curl`, `ssh`, `nc`, `openssl`, …) without `target_url`/`target_ip` AND a non-target-facing technique label (`note`, `research`), the runner now fails closed when argv contains a URL/IP/hostname. Pass scope explicitly or set `allow_unverified_scope: true` if the tokens are intentional non-target references.',
  ];

  if (config.opsec && config.opsec.enabled) {
    lines.push(`- **Respect OPSEC.** Profile: ${config.opsec.name}. Max noise: ${config.opsec.max_noise}. Factor noise levels into your decisions.`);
  } else if (config.opsec && (config.opsec.max_noise !== undefined || (config.opsec.blacklisted_techniques?.length ?? 0) > 0)) {
    // Phase B: tell the model OPSEC is configured but inert so it doesn't
    // assume the configured ceiling is being enforced.
    lines.push('- **OPSEC enforcement is DISABLED for this engagement.** The configured noise ceiling, blacklist, and time window are visible in the config but inert — `validate_action` returns `opsec_skipped: true`. Set `opsec.enabled: true` on the engagement config to enforce.');
  }

  return lines.join('\n');
}

function generateToolTableSection(tools: ToolEntry[]): string {
  const lines = [
    '## Tool Reference',
    '',
    `${tools.length} tools available:`,
    '',
    '| Tool | Description |',
    '|------|-------------|',
  ];

  for (const tool of tools) {
    // Truncate description to first sentence for table compactness
    const desc = tool.description.split('\n')[0].slice(0, 120);
    lines.push(`| \`${tool.name}\` | ${desc} |`);
  }

  return lines.join('\n');
}

function generateStateSnapshotSection(state: EngagementState): string {
  const lines = [
    '## Current State Snapshot',
    '',
    `- **Nodes:** ${state.graph_summary.total_nodes} (${Object.entries(state.graph_summary.nodes_by_type).map(([t, c]) => `${c} ${t}`).join(', ')})`,
    `- **Edges:** ${state.graph_summary.total_edges} (${state.graph_summary.confirmed_edges} confirmed, ${state.graph_summary.inferred_edges} inferred)`,
    `- **Access Level:** ${state.access_summary.current_access_level}`,
  ];

  if (state.access_summary.compromised_hosts.length > 0) {
    lines.push(`- **Compromised Hosts:** ${state.access_summary.compromised_hosts.join(', ')}`);
  }
  if (state.access_summary.valid_credentials.length > 0) {
    lines.push(`- **Valid Credentials:** ${state.access_summary.valid_credentials.length}`);
  }

  lines.push(`- **Frontier Items:** ${state.frontier.length}`);
  lines.push(`- **Active Agents:** ${state.active_agents.length}`);

  if (state.objectives.length > 0) {
    const achieved = state.objectives.filter(o => o.achieved).length;
    lines.push(`- **Objectives:** ${achieved}/${state.objectives.length} achieved`);
  }

  if (state.warnings.top_issues.length > 0) {
    lines.push(`- **Warnings:** ${state.warnings.top_issues.length} (status: ${state.warnings.status})`);
  }

  return lines.join('\n');
}

function generateSubAgentIdentitySection(config: EngagementConfig, agent?: AgentTask): string {
  const lines = [
    '# Overwatch — Sub-Agent Instructions',
    '',
    'You are an Overwatch sub-agent working a specific task in an authorized offensive security engagement.',
    '',
    `- **Engagement:** ${config.name}`,
  ];

  if (agent) {
    lines.push(`- **Agent ID:** ${agent.agent_id}`);
    lines.push(`- **Task:** ${agent.frontier_item_id}`);
    if (agent.subgraph_node_ids && agent.subgraph_node_ids.length > 0) {
      lines.push(`- **Scoped Nodes:** ${agent.subgraph_node_ids.join(', ')}`);
    }
  }

  return lines.join('\n');
}

function generateSubAgentWorkflowSection(): string {
  return `## Workflow

1. Call \`get_agent_context\` to get your scoped subgraph view
2. Call \`log_thought({ kind: "plan", thought: "..." })\` to record your intended approach for this task
3. Call \`validate_action\` before executing any significant action
4. Call \`log_action_event(event_type="action_started")\` before execution
5. Execute the action — for one-shot binary invocations prefer \`run_tool\` (argv form, no shell), or \`run_bash\` when you need shell features; both auto-handle validation, the approval gate, action lifecycle logging, and evidence capture in a single call
6. Use \`parse_output()\` for supported tool output, or \`report_finding()\` for manual observations
7. Call \`log_action_event(event_type="action_completed" | "action_failed")\` when done (skip when using \`run_bash\` or \`run_tool\` — they log for you)
8. Call \`log_thought({ kind: "reflection", thought: "..." })\` summarizing what you learned before closing the task
9. Use \`query_graph()\` if you need more context
10. Use \`get_skill()\` for methodology guidance
11. **Before** the primary calls \`update_agent\` to close you out, call \`submit_agent_transcript({ agent_id, summary, transcript_jsonl?, key_thought_event_ids?, key_finding_ids? })\` so the primary session has your wrap-up linked to the agent task. Closing terminal status without first submitting will surface an \`instrumentation_warning\`.

Report every discovery immediately. When done, your task will be marked complete by the primary session.`;
}

function generateAgentContextSection(agent: AgentTask, state?: EngagementState, engine?: GraphEngine): string {
  const lines = [
    '## Agent Context',
    '',
    `- **Agent ID:** ${agent.agent_id}`,
    `- **Status:** ${agent.status}`,
    `- **Frontier Item:** ${agent.frontier_item_id}`,
  ];

  if (agent.subgraph_node_ids && agent.subgraph_node_ids.length > 0) {
    lines.push(`- **Scoped Nodes:** ${agent.subgraph_node_ids.join(', ')}`);
  }
  if (agent.skill) {
    lines.push(`- **Skill:** ${agent.skill}`);
  }

  // Enhanced: include task description from frontier if available
  if (state && agent.frontier_item_id) {
    const frontierItem = state.frontier.find(f => f.id === agent.frontier_item_id);
    if (frontierItem) {
      lines.push('');
      lines.push('### Task Details');
      lines.push(`- **Type:** ${frontierItem.type}`);
      lines.push(`- **Description:** ${frontierItem.description}`);
      if (frontierItem.graph_metrics.hops_to_objective != null) {
        lines.push(`- **Hops to Objective:** ${frontierItem.graph_metrics.hops_to_objective}`);
      }
      lines.push(`- **Expected Noise:** ${(frontierItem.opsec_noise * 100).toFixed(0)}%`);
      if (frontierItem.chain_id) {
        lines.push(`- **Chain:** ${frontierItem.chain_id} (depth ${frontierItem.chain_depth ?? '?'}/${frontierItem.chain_length ?? '?'}, ${((frontierItem.chain_completion_pct ?? 0) * 100).toFixed(0)}% complete)`);
      }
    }
  }

  // Skill reference: inline first 500 chars of skill content
  if (agent.skill && engine) {
    try {
      const skillIndex = new SkillIndex();
      const content = skillIndex.getSkillContent(agent.skill);
      if (content) {
        lines.push('');
        lines.push('### Skill Reference');
        const snippet = content.length > 500 ? content.slice(0, 500) + '...' : content;
        lines.push(snippet);
      }
    } catch { /* skill index unavailable — skip */ }
  }

  // Target node context: key properties of scoped nodes
  if (engine && agent.subgraph_node_ids && agent.subgraph_node_ids.length > 0) {
    const nodeSnippets: string[] = [];
    for (const nid of agent.subgraph_node_ids.slice(0, 3)) {
      const node = engine.getNode(nid);
      if (!node) continue;
      const props: string[] = [`type=${node.type}`, `label=${node.label}`];
      if (node.ip) props.push(`ip=${node.ip}`);
      if (node.hostname) props.push(`hostname=${node.hostname}`);
      if (node.services) props.push(`services=${node.services}`);
      if (node.version) props.push(`version=${node.version}`);
      if (node.os) props.push(`os=${node.os}`);
      if (node.cred_type) props.push(`cred_type=${node.cred_type}`);
      if (node.cred_material_kind) props.push(`cred_material_kind=${node.cred_material_kind}`);
      if (node.cred_audience) props.push(`cred_audience=${node.cred_audience}`);
      if (node.credential_status) props.push(`credential_status=${node.credential_status}`);
      nodeSnippets.push(`- \`${nid}\`: ${props.join(', ')}`);
    }
    if (nodeSnippets.length > 0) {
      lines.push('');
      lines.push('### Target Nodes');
      lines.push(...nodeSnippets);
      if (agent.subgraph_node_ids.length > 3) {
        lines.push(`- ... and ${agent.subgraph_node_ids.length - 3} more`);
      }
    }
  }

  return lines.join('\n');
}

// ============================================================
// Tactical Methodology — prevents common model mistakes
// ============================================================

function generateTacticalSection(): string {
  return `## Tactical Methodology

### Before Every Action
- **Check existing results first.** Before cracking a hash, use \`query_graph()\` to check if it's already been cracked. Before scanning a port, check if scan results already exist in the graph. Check log files and tool output directories from previous actions — tools like hashcat, nxc, and impacket leave results on disk.
- **CVE-first for identified services.** When you identify a service + version (especially running as root/SYSTEM), search for known CVEs *before* attempting brute-force, hash cracking, or manual exploitation. Known vulns are lower-noise and higher-reward than credential attacks.
- **Review tool artifacts.** After every action completes, check for output files, log files, and loot directories. Don't re-derive information that's already been captured.

### Prioritization Logic
- **Exploitation > brute-force.** A service running as root/SYSTEM with a known CVE is almost always higher priority than cracking a hash for the same service.
- **Authenticated access > re-authentication.** If you already have valid credentials for a service, use them. Don't attempt to crack hashes for services you can already access.
- **Quietest path wins.** When multiple attack paths exist to the same target, estimate noise for each and pick the quietest one that's likely to succeed.
- **Chain completion is high value.** If 2 of 3 hops in an attack chain are confirmed, the final hop is worth more than an isolated edge.

### Credential Awareness
- When a credential is cracked or captured, **immediately** evaluate all services it can authenticate to using \`query_graph()\`. Don't wait for the next frontier cycle.
- Track credential state: captured → cracking → cracked → used → expired. Don't attempt actions with expired credentials.
- Check for credential reuse: if \`user:password\` works on one service, test it against all services that user has POTENTIAL_AUTH edges to.

### Credential-Driven Playbooks
For captured cloud / SaaS credentials, prefer the **playbook tools** over re-deriving the canonical recon chain by hand. Each tool returns a numbered plan with per-step \`command\`, \`parse_with\` parser, technique tag, and expected node/edge shape — every step still goes through the existing \`run_bash\` / \`run_tool\` + approval flow.
- **\`expand_aws_credential({ credential_id })\`** — STS get-caller-identity → IAM summary → CloudFox inventory → S3/Lambda enumeration. Use as soon as an AWS access key, STS session, or assumed-role token lands in the graph.
- **\`expand_github_credential({ credential_id })\`** — /user → /user/orgs → /user/repos → per-repo: actions/secrets, branch/protection, deploy keys, OIDC trust customization. Pass \`candidate_repos: [...]\` to pre-expand specific repos.
- **\`expand_oidc_capture({ credential_id })\`** — for captured CI/CD OIDC tokens (GitHub Actions / GitLab CI / CircleCI). Walks inferred ASSUMES_ROLE edges, emits one \`validate_token_credential\` step per candidate cloud role. Successful replays mint temp AWS creds — chain into \`expand_aws_credential\` for the resulting session.
- **\`exchange_refresh_token({ credential_id, client_id })\`** — exchanges an Entra refresh token for a fresh access token. Approval-gated by default. Set \`REFRESH_TOKEN\` env var before running the emitted curl.
- **\`expand_entra_credential({ credential_id })\`** — /me → /users → /applications → /servicePrincipals → /groups. The CONSENT_ABUSE inference rule fires after step 4 lands and stamps high-priv apps for the FindingsPanel.

> **Scripted runner note:** simple token-validation steps (`credential_test` frontier items) are automatically executed by the dashboard's scripted runner — you only need the playbook tools for the multi-step enumeration phases (inventory, resource discovery, org-wide enum) that require LLM interpretation or chained follow-ups.

### Credentials Panel
The dashboard's **Credentials** tab surfaces all captured credential nodes in a flat, searchable view — filterable by status (active/stale/expired), sortable by recency/kind/status, with reachability badges for tokens confirmed via VALID_FOR_APP / ASSUMES_ROLE edges. Use it to spot gaps (tokens captured but never validated), prioritize expiring tokens, and reveal `cred_value` for manual use. No action needed from the model — it updates automatically as findings land.

### Reporting
- **\`generate_report\`** writes to the per-engagement archive by default (\`persist_to_archive: true\`); the returned \`report_id\` is fetchable via \`/api/reports/:id\` and shows up in the dashboard's Findings tab → Reports archive.
- **Formats:** \`markdown\`, \`html\`, \`json\`, \`pdf\`. PDFs are rendered through headless Chromium via puppeteer-core; if no chromium binary is available the tool returns a clear error pointing at \`PUPPETEER_EXECUTABLE_PATH\`.
- **\`include_attack_paths: true\` (default)** synthesizes per-objective attack chains from current access using \`find_paths\` and decorates each hop with confirmed-vs-inferred + per-edge confidence. Prefer the default — operator-facing reports without an attack-paths section read like inventory reports.
- The dashboard's Findings tab also exposes a "Generate Report" button; if you've already produced the right artifact, point operators there instead of re-rendering.`;
}

// ============================================================
// Situational Awareness — dynamic from engagement state
// ============================================================

function generateSituationalSection(ctx: PromptContext): string {
  const { state, engine } = ctx;
  const lines: string[] = [
    '## Situational Awareness',
    '',
    'The following is auto-generated from the current engagement state. Pay attention to these items.',
    '',
  ];

  let hasContent = false;

  // Phase context
  if (state.phases.length > 0 && state.current_phase) {
    const currentPhase = state.phases.find(p => p.id === state.current_phase);
    if (currentPhase) {
      lines.push(`### Current Phase: ${currentPhase.name}`);
      if (currentPhase.strategies.length > 0) {
        lines.push(`- **Focus strategies:** ${currentPhase.strategies.join(', ')}`);
      }
      if (!currentPhase.exit_criteria_met) {
        lines.push('- **Exit criteria not met** — continue working toward phase completion.');
      }
      const nextPhase = state.phases.find(p => p.order === currentPhase.order + 1);
      if (nextPhase) {
        lines.push(`- **Next phase:** ${nextPhase.name}${nextPhase.entry_criteria_met ? ' (ready to enter)' : ''}`);
      }
      lines.push('');
      hasContent = true;
    }
  }

  // Credential status
  if (state.access_summary.valid_credentials.length > 0) {
    lines.push(`### Active Credentials (${state.access_summary.valid_credentials.length})`);
    for (const cred of state.access_summary.valid_credentials.slice(0, 10)) {
      lines.push(`- ${cred}`);
    }
    if (state.access_summary.valid_credentials.length > 10) {
      lines.push(`- ... and ${state.access_summary.valid_credentials.length - 10} more`);
    }
    lines.push('');
    hasContent = true;
  }

  // Credential spray coverage
  if (state.credential_coverage && state.credential_coverage.total_pairs > 0) {
    const cc = state.credential_coverage;
    lines.push(`### Credential Spray Progress`);
    lines.push(`**${cc.tested_pairs}/${cc.total_pairs}** pairs tested (${cc.coverage_pct}% coverage) — ${cc.total_credentials} credentials × ${cc.total_targets} targets`);
    if (cc.top_untested.length > 0) {
      lines.push('');
      lines.push('Top untested combinations:');
      for (const pair of cc.top_untested.slice(0, 5)) {
        lines.push(`- **${pair.credential}** → ${pair.target}${pair.service ? ` (${pair.service})` : ''}`);
      }
    }
    lines.push('');
    hasContent = true;
  }

  // Compromised hosts
  if (state.access_summary.compromised_hosts.length > 0) {
    lines.push(`### Compromised Hosts (${state.access_summary.compromised_hosts.length})`);
    lines.push(`Access level: **${state.access_summary.current_access_level}**`);
    for (const host of state.access_summary.compromised_hosts.slice(0, 10)) {
      lines.push(`- ${host}`);
    }
    if (state.access_summary.compromised_hosts.length > 10) {
      lines.push(`- ... and ${state.access_summary.compromised_hosts.length - 10} more`);
    }
    lines.push('');
    hasContent = true;
  }

  // Recent activity — detect completed actions without follow-up
  const recentCompleted = state.recent_activity.filter(a =>
    a.event_type?.includes('completed') || a.description?.toLowerCase().includes('completed'));
  const recentParsed = state.recent_activity.filter(a =>
    a.event_type?.includes('finding') || a.description?.toLowerCase().includes('parsed') || a.description?.toLowerCase().includes('reported'));

  if (recentCompleted.length > recentParsed.length + 2) {
    lines.push('### ⚠ Unprocessed Results');
    lines.push(`${recentCompleted.length} actions completed recently but only ${recentParsed.length} findings parsed/reported. **Check for tool output that hasn't been ingested.** Look for log files, loot directories, and tool artifacts from completed actions.`);
    lines.push('');
    hasContent = true;
  }

  // Recent findings summary
  const findings = state.recent_activity.filter(a =>
    a.event_type?.includes('finding') || a.description?.toLowerCase().includes('finding'));
  if (findings.length > 0) {
    lines.push(`### Recent Findings (${findings.length})`);
    for (const f of findings.slice(-5)) {
      const timeStr = f.timestamp ? new Date(f.timestamp).toLocaleTimeString() : '';
      lines.push(`- ${timeStr ? `[${timeStr}] ` : ''}${f.description}`);
    }
    lines.push('');
    hasContent = true;
  }

  // OPSEC budget status (only when OPSEC enforcement is enabled)
  const opsecCtx = engine.getOpsecContext();
  if (state.config.opsec?.enabled && (opsecCtx.global_noise_spent > 0 || opsecCtx.defensive_signals.length > 0)) {
    const maxNoise = state.config.opsec?.max_noise ?? 1;
    const pct = maxNoise > 0 ? Math.round((opsecCtx.global_noise_spent / maxNoise) * 100) : 0;
    lines.push(`### OPSEC Budget`);
    lines.push(`- **Noise spent:** ${opsecCtx.global_noise_spent.toFixed(2)} / ${maxNoise} (${pct}%)`);
    lines.push(`- **Remaining:** ${opsecCtx.noise_budget_remaining.toFixed(2)}`);
    lines.push(`- **Recommended approach:** ${opsecCtx.recommended_approach}`);
    if (opsecCtx.time_window_remaining_hours !== undefined) {
      lines.push(`- **Time window remaining:** ${opsecCtx.time_window_remaining_hours.toFixed(1)}h`);
    }
    if (opsecCtx.warning) {
      lines.push(`- ⚠ **${opsecCtx.warning}**`);
    }
    if (opsecCtx.defensive_signals.length > 0) {
      lines.push(`- **Defensive signals (${opsecCtx.defensive_signals.length}):**`);
      for (const sig of opsecCtx.defensive_signals.slice(0, 5)) {
        const target = sig.host_id || sig.domain || 'global';
        lines.push(`  - ${sig.type} on ${target}: ${sig.description}`);
      }
    }
    lines.push('');
    hasContent = true;
  }

  // Active campaigns
  const campaigns = engine.listCampaigns();
  const activeCampaigns = campaigns.filter(c => c.status === 'active' || c.status === 'paused');
  if (activeCampaigns.length > 0) {
    lines.push(`### Active Campaigns (${activeCampaigns.length})`);
    for (const c of activeCampaigns.slice(0, 5)) {
      const pct = c.progress.total > 0 ? Math.round((c.progress.completed / c.progress.total) * 100) : 0;
      const status = c.status === 'paused' ? ' [PAUSED]' : '';
      lines.push(`- **${c.name}**${status}: ${c.progress.completed}/${c.progress.total} (${pct}%), ${c.findings.length} finding(s), ${c.progress.consecutive_failures} consecutive failures`);
      const abortThreshold = c.abort_conditions.find(ac => ac.type === 'consecutive_failures')?.threshold;
      if (abortThreshold && c.progress.consecutive_failures >= abortThreshold - 1) {
        lines.push(`  - ⚠ **Approaching abort threshold** (${c.progress.consecutive_failures}/${abortThreshold} consecutive failures)`);
      }
    }
    lines.push('');
    hasContent = true;
  }

  // Expiring credentials
  const expiringCreds: Array<{ label: string; minutesLeft: number }> = [];
  engine.getNodesByType('credential').forEach(node => {
    if (node.confidence < 0.9 || node.identity_status === 'superseded') return;
    const ttl = timeToExpiry(node);
    if (ttl < 2 * 60 * 60 * 1000 && ttl > 0) { // < 2 hours and not already expired
      expiringCreds.push({
        label: `${node.cred_user || node.label}`,
        minutesLeft: Math.round(ttl / 60000),
      });
    }
  });
  if (expiringCreds.length > 0) {
    expiringCreds.sort((a, b) => a.minutesLeft - b.minutesLeft);
    lines.push(`### ⚠ Expiring Credentials (${expiringCreds.length})`);
    for (const c of expiringCreds.slice(0, 5)) {
      lines.push(`- **${c.label}** expires in **${c.minutesLeft}m** — use it or lose it`);
    }
    lines.push('');
    hasContent = true;
  }

  // Services with version info but no CVE check
  const uncheckedServices: string[] = [];
  const vulnTargets = new Set<string>();
  const vulnEdgeResult = engine.queryGraph({ edge_type: 'VULNERABLE_TO' as import('../types.js').EdgeType });
  for (const e of vulnEdgeResult.edges) vulnTargets.add(e.source);
  const exploitEdgeResult = engine.queryGraph({ edge_type: 'EXPLOITS' as import('../types.js').EdgeType });
  for (const e of exploitEdgeResult.edges) vulnTargets.add(e.source);
  engine.getNodesByType('service').forEach(node => {
    if (!node.version || node.identity_status === 'superseded') return;
    if (!vulnTargets.has(node.id)) {
      uncheckedServices.push(`${node.label} (${node.version})`);
    }
  });
  if (uncheckedServices.length > 0) {
    lines.push(`### Services Without CVE Checks (${uncheckedServices.length})`);
    lines.push('These services have version info but no `VULNERABLE_TO` or `EXPLOITS` edges — prioritize CVE lookups:');
    for (const s of uncheckedServices.slice(0, 5)) {
      lines.push(`- ${s}`);
    }
    if (uncheckedServices.length > 5) {
      lines.push(`- ... and ${uncheckedServices.length - 5} more`);
    }
    lines.push('');
    hasContent = true;
  }

  // Scope suggestions
  if (state.scope_suggestions.length > 0) {
    lines.push(`### Scope Suggestions (${state.scope_suggestions.length})`);
    for (const s of state.scope_suggestions.slice(0, 3)) {
      lines.push(`- Consider adding **${s.suggested_cidr}** (${s.out_of_scope_ips.length} IPs discovered, ${s.source_descriptions[0] || 'unknown source'})`);
    }
    lines.push('');
    hasContent = true;
  }

  if (!hasContent) {
    return ''; // Don't emit an empty section
  }

  return lines.join('\n');
}

// ============================================================
// Anti-Patterns — from failure_patterns and common mistakes
// ============================================================

function generateAntiPatternsSection(ctx: PromptContext): string | null {
  const { state, engine } = ctx;
  const config = state.config;
  const lines: string[] = [
    '## Anti-Patterns — Do NOT Do These',
    '',
    '- **Do not crack hashes when the service has known CVEs.** Check CVE databases for the service version first.',
    '- **Do not re-scan ports or services that have already been scanned.** Use `query_graph()` to check existing results.',
    '- **Do not attempt authentication with expired or revoked credentials.** Check credential state first.',
    '- **Do not ignore completed tool output.** Always check for log files, loot directories, and output artifacts after every action.',
    '- **Do not skip version detection.** Always capture service version information — it unlocks CVE lookups and targeted exploitation.',
  ];

  // Append engagement-specific failure patterns
  if (config.failure_patterns && config.failure_patterns.length > 0) {
    lines.push('');
    lines.push('### Engagement-Specific Warnings');
    lines.push('');
    lines.push('These patterns have been identified from previous actions in this engagement:');
    for (const fp of config.failure_patterns) {
      const target = fp.target_pattern ? ` (target: \`${fp.target_pattern}\`)` : '';
      lines.push(`- **${fp.technique}**${target}: ${fp.warning}`);
    }
  }

  // Retrospective-sourced low-success techniques from knowledge base
  const kb = engine.getKB();
  if (kb) {
    const lowSuccess = kb.getAllTechniqueStats()
      .filter((t: TechniqueStats) => t.attempts >= 5 && t.success_rate < 0.2)
      .sort((a: TechniqueStats, b: TechniqueStats) => a.success_rate - b.success_rate)
      .slice(0, 5);
    if (lowSuccess.length > 0) {
      lines.push('');
      lines.push('### Low-Success Techniques (from knowledge base)');
      lines.push('');
      lines.push('These techniques have historically low success rates — consider alternatives:');
      for (const t of lowSuccess) {
        lines.push(`- **${t.name}**: ${t.successes}/${t.attempts} succeeded (${Math.round(t.success_rate * 100)}%) — avg noise ${t.avg_noise.toFixed(2)}`);
      }
    }
  }

  return lines.join('\n');
}
