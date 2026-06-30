// ============================================================
// Overwatch — Prompt Generator
// Generates dynamic system prompts from engagement state.
// ============================================================

import type { GraphEngine } from './graph-engine.js';
import type { EngagementConfig, EngagementState, AgentTask, LabProfile } from '../types.js';
import { inferProfile } from '../types.js';
import { timeToExpiry } from './credential-utils.js';
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
  /** Sub_agent prompt variant for the behavior-eval A/B (control = current,
   *  lean = step-(b) context-first restructure). Resolved from this option, then
   *  the OVERWATCH_PROMPT_VARIANT env, then 'control'. */
  variant?: PromptVariant;
}

// Sub_agent prompt variants. 'lean' is the step-(b) context-first restructure and
// is now the DEFAULT (promoted after a real-model behavior-eval A/B: it wins the
// 2×-weighted validate_before_execute criterion across scenarios + threading, net-
// positive overall — see docs/prompt-stepb-design.md). 'control' is the prior
// shipped prompt, kept reachable as a one-release rollback via
// OVERWATCH_PROMPT_VARIANT=control (or options.variant).
export type PromptVariant = 'control' | 'lean';
export const SUBAGENT_PROMPT_VARIANTS: readonly PromptVariant[] = ['control', 'lean'];
export const DEFAULT_SUBAGENT_VARIANT: PromptVariant = 'lean';
const KNOWN_VARIANTS: readonly string[] = SUBAGENT_PROMPT_VARIANTS;

export function resolveSubAgentVariant(options: GeneratePromptOptions): PromptVariant {
  if (options.variant && KNOWN_VARIANTS.includes(options.variant)) return options.variant;
  const env = process.env.OVERWATCH_PROMPT_VARIANT;
  if (env && KNOWN_VARIANTS.includes(env)) return env as PromptVariant;
  return DEFAULT_SUBAGENT_VARIANT;
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
  title?: string;
  description: string;
  category?: string;
  read_only?: boolean;
  destructive?: boolean;
  idempotent?: boolean;
  open_world?: boolean;
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

export const DEFAULT_MAX_PROMPT_TOKENS = 8000;

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

// Scoped sub-agent tool subset — must stay in sync with the sub-agent workflow
// section (and the AGENTS.md sub-agent tool list). Shared by both prompt variants.
const SUBAGENT_TOOL_NAMES = new Set([
  'get_agent_context', 'validate_action', 'log_action_event', 'log_thought',
  'run_bash', 'run_tool',
  'parse_output', 'report_finding', 'research_cve', 'propose_plan', 'submit_agent_transcript',
  'agent_heartbeat', 'acknowledge_agent_directive', 'ask_operator',
  'query_graph', 'get_skill',
  'open_session', 'write_session', 'read_session', 'send_to_session',
  'list_sessions', 'close_session', 'resize_session', 'signal_session',
  'update_session', 'get_evidence',
]);

function generateSubAgentPrompt(
  state: EngagementState,
  tools: ToolEntry[],
  options: GeneratePromptOptions,
  engine: GraphEngine,
): string {
  const agentContext = options.agent_id
    ? state.active_agents.find(a => a.id === options.agent_id || a.agent_id === options.agent_id)
    : undefined;
  const scopedTools = tools.filter(t => SUBAGENT_TOOL_NAMES.has(t.name));

  // Step (b): the 'lean' context-first restructure, piloted via the behavior-eval
  // harness. 'control' is the shipped linear assembly below.
  if (resolveSubAgentVariant(options) === 'lean') {
    return generateLeanSubAgentPrompt(state, scopedTools, options, engine, agentContext);
  }

  const sections: string[] = [];
  sections.push(generateSubAgentIdentitySection(state.config, agentContext));

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
// Step (b) — 'lean' context-first sub-agent prompt
// ============================================================
// Same affordances, restructured: lead with the brief (objective/done-when/
// scope), replace the 0..12 step list with 5 named loop phases, one motivated
// guardrails block, a worked trace, trimmed tactics. Preserves the five
// structural-guard literals (get_agent_context, validate_action, parse_output,
// report_finding, submit_agent_transcript). Piloted via the eval harness.

const CREDENTIAL_ARCHETYPES = new Set(['credential_operator', 'post_exploit', 'cloud_cartographer']);

function generateLeanSubAgentPrompt(
  state: EngagementState,
  scopedTools: ToolEntry[],
  options: GeneratePromptOptions,
  _engine: GraphEngine,
  agent?: AgentTask,
): string {
  const sections: string[] = [
    leanIdentitySection(),
  ];
  if (options.include_state !== false && agent) {
    sections.push(leanBriefSection(state, agent));
  }
  if (options.include_tools !== false) {
    sections.push(generateToolTableSection(scopedTools));
  }
  sections.push(leanLoopSection());
  sections.push(leanGuardrailsSection());
  sections.push(leanSteeringSection());
  sections.push(leanExampleSection());
  sections.push(leanTacticsSection(agent));
  return sections.join('\n\n');
}

function leanIdentitySection(): string {
  return `# Overwatch sub-agent

You run one scoped task in an authorized offensive engagement. Your memory is the Overwatch graph — orient from it, and land every result back into it. Anything you only describe in prose is invisible to the rest of the engagement.`;
}

function leanBriefSection(state: EngagementState, agent: AgentTask): string {
  const frontierItem = agent.frontier_item_id ? state.frontier.find(f => f.id === agent.frontier_item_id) : undefined;
  const lines = [
    '## Brief',
    '',
    `- **Engagement:** ${state.config.name}`,
    `- **Agent / Task:** ${agent.agent_id} · frontier ${agent.frontier_item_id ?? '(none)'}`,
  ];
  if (agent.archetype) lines.push(`- **Archetype:** ${agent.archetype}`);
  if (frontierItem) {
    lines.push(`- **Objective:** ${frontierItem.description}`);
    lines.push(`- **Done when:** the expected discoveries for this ${frontierItem.type} are landed as graph nodes/edges, or you have confirmed no in-scope path remains (report NO_PATH). Don't keep going past that.`);
  } else {
    lines.push('- **Objective:** see get_agent_context for your task.');
    lines.push('- **Done when:** the expected discoveries are landed in the graph, or no in-scope path remains (report NO_PATH).');
  }
  const scopeIds = agent.subgraph_node_ids ?? [];
  if (scopeIds.length) {
    // Cap the inline list so a scope-wide archetype (hundreds of nodes) can't
    // balloon the prompt; the full set is always live via get_agent_context.
    const SCOPE_CAP = 25;
    const shown = scopeIds.slice(0, SCOPE_CAP).join(', ');
    const more = scopeIds.length > SCOPE_CAP ? ` … and ${scopeIds.length - SCOPE_CAP} more` : '';
    lines.push(`- **Scope:** ${shown}${more} — acting outside your scoped nodes is a hard stop.`);
  } else {
    lines.push('- **Scope:** see get_agent_context; acting outside your scoped nodes is a hard stop.');
  }
  if (frontierItem) {
    if (frontierItem.graph_metrics.hops_to_objective != null) lines.push(`- **Hops to objective:** ${frontierItem.graph_metrics.hops_to_objective}`);
    lines.push(`- **Expected noise:** ${(frontierItem.opsec_noise * 100).toFixed(0)}%`);
  }
  if (agent.skill) lines.push(`- **Skill:** ${agent.skill} — fetch the full methodology with get_skill({ name }).`);

  // NOTE: this Brief deliberately lists scope by id but NOT the nodes' properties.
  // An earlier revision inlined the target-node details here, and the real-model
  // A/B showed it suppressed orient-first — the agent felt it already had its
  // context and skipped get_agent_context. Keeping the node details out (they come
  // from get_agent_context) forces a genuine orientation step.
  lines.push('');
  lines.push('**This Brief is only the spawn-time snapshot** — it names your scope by id but not the nodes\' properties or live state. Your **first action is `get_agent_context`** (loads the actual subgraph + the authoritative, current objective); do not act on this Brief alone.');
  return lines.join('\n');
}

function leanLoopSection(): string {
  return `## Loop

Reason briefly with \`log_thought\` before each phase; skip a phase only when its precondition is already met.

1. **ORIENT (always your first action)** — call \`get_agent_context\` before anything else. The Brief only lists your scope by id; this is where you load the actual node details, full subgraph, and current objective. Do not start with an execute. (Overwatch tools load on demand — the MCP server can boot \`status: pending\` with zero tools; if a tool you need isn't available, find it with \`ToolSearch\` before assuming it's absent.)
2. **VALIDATE** — call \`validate_action\` before any execute. It returns an \`action_id\` and echoes \`frontier_item_id\` — copy both into the calls that follow; don't invent them.
3. **EXECUTE** — prefer \`run_tool\` (binary + argv, no shell) or \`run_bash\` (only when you need shell features); both fold validation, the approval gate, action lifecycle logging, and evidence capture into one call. For custom tooling, do the manual \`validate_action\` → \`log_action_event(action_started)\` → execute → \`log_action_event(action_completed|action_failed)\` flow.
4. **LAND** — record results immediately: \`parse_output\` for supported tool output, \`report_finding\` for manual observations. Pass \`action_id\` + \`frontier_item_id\`. No prose-only findings — an unrecorded discovery doesn't exist.
5. **WRAP** — when Done-when is met (or you hit a terminal state), call \`submit_agent_transcript({ task_id, summary, key_finding_ids? })\` before the primary closes you out. Closing without it raises an \`instrumentation_warning\`.`;
}

function leanGuardrailsSection(): string {
  return `## Guardrails

- **Stay in scope** — act only on your scoped nodes; blast radius is bounded by scope, not by your judgment.
- **Validate before every execute, with the matching \`action_id\`** — one early \`validate_action\` does not cover later actions; each execute needs its own validated \`action_id\`.
- **Land results, don't narrate** — the planner reads the graph, not your prose; a finding you describe but never \`report_finding\`/\`parse_output\` is lost.
- **Heartbeat while long-running** — past ~a minute, call \`agent_heartbeat({ task_id })\` or the watchdog reaps your lease.`;
}

function leanSteeringSection(): string {
  return `## Steering & escalation

The \`agent_heartbeat\` response may carry operator steering — call \`acknowledge_agent_directive({ task_id, directive_id })\`, then honor it: \`pause\` (stop new actions, keep beating, poll for \`resume\`) · \`resume\` · \`stop\` (submit transcript, then stop) · \`narrow_scope\` (\`node_ids\` become authoritative scope) · \`skip_types\`/\`prioritize\` (by frontier type) · \`instruct\` (free-text in \`note\` — adjust within scope/OPSEC). Also watch \`pending_answer\` (the reply to an \`ask_operator\` question); act on it only when \`pending_answer.query_id\` matches yours, once.

Report terminal states — don't improvise past them:
- **NO_PATH** — no in-scope approach remains; say so rather than going out of scope.
- **BLOCKED** — a concrete barrier (missing tool, credential, or access); report the exact barrier.
- **AMBIGUOUS / risky-irreversible fork** — call \`ask_operator({ task_id, question, options? })\`, keep heartbeating, act when \`pending_answer.query_id\` matches; if no answer in a few minutes, take the safest in-scope choice and note it. Gate ask-vs-proceed on action class / reversibility / scope, not on how confident you feel.`;
}

function leanExampleSection(): string {
  return `## Example

<example>
get_agent_context(task_id)                      → objective: enumerate services on host h_3 (scope: [h_3])
log_thought({ kind: "plan", thought: "scan h_3 for services, land them" })
validate_action({ frontier_item_id: "f_12", action: "nmap -sV h_3" })   → { action_id: "a_7", frontier_item_id: "f_12" }
run_tool({ action_id: "a_7", frontier_item_id: "f_12", tool: "nmap", args: [...], parse_with: "nmap" })   → 3 services
parse_output(...)                               → lands 3 service nodes  (report_finding for manual observations)
log_thought({ kind: "reflection", thought: "3 services landed; objective met" })
submit_agent_transcript({ task_id, summary: "3 services on h_3", key_finding_ids: [...] })
</example>`;
}

function leanTacticsSection(agent?: AgentTask): string {
  const lines = [
    '## Tactics',
    '',
    '- Check the graph before acting — `query_graph()` to avoid re-scanning a port or re-cracking a hash already recorded; check tool output dirs from prior actions.',
    '- CVE-first for versioned services: a known CVE on a service+version is lower-noise and higher-reward than brute-force.',
    '- After a new credential lands, immediately evaluate the auth edges it unlocks (`query_graph`) — don\'t wait for the next cycle.',
    '- `run_tool` for argv (no shell parsing/injection); `run_bash` only for real shell features. `parse_output` for parser-supported output; `report_finding` for everything else.',
  ];
  if (agent?.archetype && CREDENTIAL_ARCHETYPES.has(agent.archetype)) {
    lines.push('- For captured cloud/SaaS credentials, prefer the playbook tools (`expand_aws_credential`, `expand_github_credential`, `expand_entra_credential`, `expand_oidc_capture`, `exchange_refresh_token`) over re-deriving the recon chain by hand — each returns a numbered plan whose steps still go through the `run_tool`/`run_bash` + approval flow.');
  }
  return lines.join('\n');
}

// ============================================================
// Section generators
// ============================================================

function generateIdentitySection(config: EngagementConfig): string {
  const lines = [
    '# Overwatch — Primary Session Instructions',
    '',
    'Authorized offensive-engagement operator. Your state + memory are the Overwatch MCP graph — it holds everything, so you do not carry engagement state in context.',
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
   - **\`credential_test\` frontier items are automatically executed** by the scripted runner when the dashboard is running — token credentials with a \`cred_value\` are validated via curl through the approval gate without operator intervention. You do NOT need to dispatch agents or manually call \`validate_token_credential\` for these items; they resolve on their own. Call \`get_state()\` to see results after the runner finishes. Dispatch agents for credential_test items only if you need LLM reasoning (e.g., unusual audiences, custom parsers).
   - **You don't pick the tool surface — dispatch does.** Each agent is auto-assigned the right **archetype** (a bounded tool surface + mission) from its frontier item: recon_scanner for network/host work, web_tester for webapps, credential_operator for credential/identity items, post_exploit for pivots, cve_researcher for CVE lookups, osint_recon for passive external recon (domains → subdomains/ASNs/orgs/emails); a campaign's strategy drives it too. Pass \`archetype\` only to override the auto-choice.

11. **Synthesize the moment a sub-agent finishes — don't wait a cycle.** Dispatch is fire-and-forget, so after dispatching, poll \`get_state({ since: <your last poll's timestamp> })\` — its \`changes_since\` digest tells you at a glance how many new findings landed and exactly which agents completed since you last looked, without scanning \`recent_activity\` (use \`get_history({ since, event_types: ["agent_transcript_submitted"] })\` for the raw completion entries). As soon as an agent completes (an \`agent_transcript_submitted\` event, or its status flips to \`completed\`/\`interrupted\`), **immediately** read its \`result_summary\` and the findings it landed, fold them into your picture, re-rank the frontier, and re-dispatch or report — exactly the way you act on a freshly captured credential, not on the next loop. Its findings have already recomputed the frontier; a newly-achievable objective or a fresh high-value target is worth acting on right now. An \`interrupted\` agent's partial work is **salvaged to evidence** (a transcript flagged \`salvaged\`) — read that before re-dispatching the same item, so you build on what it found instead of repeating it.

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
    '### Drift prevention invariants',
    '',
    '- Never answer engagement-state, recon, target, credential, frontier, or objective questions from memory alone. Refresh with `get_state()` first unless you just received fresh state in this turn.',
    '- Never leave useful recon output only in prose. If output contains hosts, services, vulnerabilities, credentials, sessions, access, or errors that affect trust in results, route it into the graph with `parse_output()`, `report_finding()`, or `ingest_json()`.',
    '- Never run target-facing commands through raw shell outside the Overwatch lifecycle. Use `run_tool`, `run_bash`, or session tools so scope validation, action logging, evidence capture, and parser/report follow-up stay intact.',
    '- If you cannot use Overwatch tools, say so explicitly and mark conclusions as unverified rather than presenting them as graph-backed state.',
    '',
    '### Sessions (interactive shells / sockets)',
    '',
    '- **Always pass `default_validation` to `open_session`** for SSH/socket-connect sessions: `{ technique, target_ip?, target_url?, allow_unverified_scope? }`. Every subsequent `send_to_session` inherits it and runs the full action lifecycle (validate → action_started → evidence → action_completed). Without it, sends require a per-call `technique`.',
    '- **For reverse-shell catchers, prefer `open_session({ kind: "socket", mode: "listen", bind_host, advertise_host, mock_service_purpose: "reverse_shell_catcher" })`** over raw `nc`. Reverse-shell catchers default to rearm mode, so a local test connection will not consume the listener.',
    '- **`send_to_session` is the instrumented send.** It validates scope, persists captured output as evidence, and emits action_started/completed. Use `write_session` only for partial I/O (password prompts, REPL navigation) where lifecycle overhead is wrong.',
    '- **A closed session is dead.** Once a shell exits or the watchdog reaps the session, that `HAS_SESSION` edge is marked `session_live: false`. Frontier, path reachability, and objective achievement now ignore dead sessions. If you want to reach a host through a previous compromise, confirm the session is still live (or open a new one).',
    '- **Long-running sub-agents must call `agent_heartbeat({ task_id })` periodically.** Otherwise the watchdog interrupts the task and releases its frontier lease.',
    '',
    '### Visibility & audit',
    '',
    '- **`get_decision_log` / `get_timeline` / `explain_action`** are read-only views derived from the activity log. Use them when you need to answer "why did I take action X?", "what was true at time T?", or "what did the planner suggest before I overrode it?" — they\'re the human-facing audit surface.',
    '- **Engagements with `engagement_nonce` are deterministic and replayable.** Action IDs (`act_<sha256>…`) and event IDs are derived from the nonce + agent + sequence + command, not random. Evidence blobs are content-addressed by sha256 — identical scanner output dedups automatically. State is journaled (WAL) and survives mid-mutation crashes. Use `verify_activity_chain()` during retrospectives or after suspected log tampering.',
    '- **Reports default to evidence-rich (operator-internal).** Pass `{ client_safe: true }` to `generate_report` for client deliverables — strips `cred_value`, raw stdout, and operator paths; outputs `report.client-safe.<ext>`. Reports persist to the engagement archive by default and are listable from the dashboard **Findings** tab → Reports section.',
    '- **Use the right export path.** `bundle_engagement()` creates a portable archive with state, evidence, reports, manifest, and the WAL journal. `export_graph()` is graph JSON only.',
    '- **Runtime-only connectors stay runtime-only.** `connect_postgres()` opens an in-process connection for this server session; only the redacted `postgres_dsn` display value survives config validation/reload. Reconnect after restart before `list_postgres_tables()` or `ingest_postgres_table()`.',
    '- **Use `ingest_json()` for one-off structured imports.** Prefer dedicated parsers when they exist; use generic JSON/JSONL mappings for unsupported tool output or custom datasets.',
    '- **Dashboard (console-first IA):** the **Console** is the home — the operator dispatches, steers, talks to, and approves agents there, leaving only to investigate. Nav is grouped **Console** (Console · Frontier · Approvals · Campaigns) · **Investigate** (Graph · Findings · Attack Paths · Evidence · Analysis · Identity · Credentials · Activity · Overview) · **Manage** (Sessions · Engagements · Settings · Smoke). In the Console: a pinned command bar, a Fleet roster (select an agent to focus it), a "Needs you" strip for inline approve/deny + agent questions + stuck-agent alerts (a heartbeating agent that has made no progress for a while), a **Deploy** button (type an IP/CIDR/domain → it is scoped + a recommended **agent type** is dispatched at it in one step, or pick the type — recon_scanner/web_tester/credential_operator/post_exploit/cve_researcher/osint_recon/pathfinder/report_scribe/cloud_cartographer/opsec_sentinel/session_shepherd/evidence_auditor; node IDs dispatch against existing nodes), an **Add Targets** button (paste IPs/CIDRs/domains → preview → add to scope), and the live activity stream. **Approvals** is the deep triage view (same approve/deny). **Credentials** shows captured tokens/keys with status, reachability, and reveal/copy for `cred_value`. **Findings** shows classified severity groups + report archive. **Analysis** is the run-centric output workspace — assess a tool run\'s raw stdout/stderr (live while running, durable after), re-parse it into the graph, and deploy a follow-up agent at what it found.',
    '',
    '### Scope guardrails',
    '',
    '- For subnet discovery, pass `target_cidr` explicitly (for example `run_tool({ binary: "nmap", args: ["-oX", "-", "10.10.110.0/24", "--exclude", "10.10.110.2"], technique: "host_discovery", target_cidr: "10.10.110.0/24" })`). CIDR targets are validated as ranges; scanner `--exclude` values are not treated as targets.',
    '- For local listener/bridge setup commands that mention operator-owned IPs or ports, pass `operator_infra: true` instead of broad `allow_unverified_scope`. Avoid `pkill -f` self-match patterns; prefer built-in listener lifecycle controls or port-specific cleanup such as `fuser -k <port>/tcp`.',
    '- If you invoke a network-capable binary (`curl`, `ssh`, `nc`, `openssl`, …) without `target_url`/`target_ip`/`target_cidr` AND a non-target-facing technique label (`note`, `research`), the runner now fails closed when argv contains a URL/IP/hostname. Pass scope explicitly or set `allow_unverified_scope: true` if the tokens are intentional non-target references.',
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

0. **Tool discovery.** Overwatch tools may not be enumerated up front — the MCP server can report \`status: pending\` with zero tools at startup, and tools load on demand. If a tool you need (\`get_agent_context\`, \`agent_heartbeat\`, \`validate_action\`, \`run_tool\`, \`run_bash\`, \`report_finding\`, \`submit_agent_transcript\`, \`update_agent\`, …) is not already available, use \`ToolSearch\` to find it by name before calling it. Do not assume the full tool list is present at boot.
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
11. If the task runs longer than roughly a minute, call \`agent_heartbeat({ task_id })\` periodically so the watchdog does not reap your lease. **Check the response for \`pending_directive\`** — operator steering. If present, call \`acknowledge_agent_directive({ task_id, directive_id })\` and then honor it:
    - \`pause\` → stop starting new actions; keep heartbeating; poll until you receive \`resume\`.
    - \`resume\` → continue.
    - \`stop\` → call \`submit_agent_transcript\` with what you have, then stop (the runtime will also terminate you).
    - \`narrow_scope\` → treat \`node_ids\` as your authoritative scope; do not act on nodes outside it.
    - \`skip_types\` → ignore frontier items whose type is in \`frontier_types\`.
    - \`prioritize\` → do frontier items whose type is in \`frontier_types\` first.
    - \`instruct\` → the operator's free-text instruction is in \`note\`; read it and adjust your approach accordingly (e.g. focus a technique, try a different path), staying within scope and OPSEC.
    Also watch for \`pending_answer\` on the heartbeat — the operator's reply to a question you asked via \`ask_operator\`. Act on it only when \`pending_answer.query_id\` matches the \`query_id\` your \`ask_operator\` call returned, and act on a given answer once.
12b. At a genuine fork you cannot resolve (ambiguous path, risky/irreversible step, missing context), call \`ask_operator({ task_id, question, options? })\` — note the returned \`query_id\` — then keep heartbeating (it's redelivered each beat, so a dropped response self-heals). When \`pending_answer.query_id\` matches, read \`pending_answer.answer\` and proceed. Bound your wait to a few minutes of heartbeats; if no answer arrives, make the safest reasonable choice and note that you proceeded without one. Don't ask for routine decisions — only real escalations.
12. **Before** the primary calls \`update_agent\` to close you out, call \`submit_agent_transcript({ task_id, summary, transcript_jsonl?, key_thought_event_ids?, key_finding_ids? })\` so the primary session has your wrap-up linked to the agent task. Use \`agent_id\` only as a legacy fallback if you do not have the task ID. Closing terminal status without first submitting will surface an \`instrumentation_warning\`.

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
      const content = engine.getSkillIndex()?.getSkillContent(agent.skill) ?? null;
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

> **Scripted runner note:** simple token-validation steps (\`credential_test\` frontier items) are automatically executed by the dashboard's scripted runner — you only need the playbook tools for the multi-step enumeration phases (inventory, resource discovery, org-wide enum) that require LLM interpretation or chained follow-ups.

### Data Import, Connectors, and Portability
- Use \`ingest_json()\` for unsupported JSON/JSONL output when no dedicated parser exists. Keep mappings explicit: node type, ID field/prefix, property fields, and parent edge shape.
- Use \`connect_postgres()\` only as a session-scoped connector. The live DSN/credentials are not persisted; reconnect after server restart before calling \`list_postgres_tables()\` or \`ingest_postgres_table()\`.
- Use \`bundle_engagement()\` for a portable archive with state, evidence, reports, manifest, and WAL journal. Use \`export_graph()\` only when you need graph JSON for external analysis.

### Credentials Panel
The dashboard's **Credentials** tab surfaces all captured credential nodes in a flat, searchable view — filterable by status (active/stale/expired), sortable by recency/kind/status, with reachability badges for tokens confirmed via VALID_FOR_APP / ASSUMES_ROLE edges. Use it to spot gaps (tokens captured but never validated), prioritize expiring tokens, and reveal \`cred_value\` for manual use. No action needed from the model — it updates automatically as findings land.

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
    lines.push('These versioned services have no `VULNERABLE_TO`/`EXPLOITS` edges yet. They are surfaced as `cve_research` frontier items and auto-dispatched to a headless web-research sub-agent (when enabled); you do not need to research them manually.');
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
