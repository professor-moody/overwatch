// ============================================================
// Overwatch — Prompt Generator
// Generates dynamic system prompts from engagement state.
// ============================================================

import type { GraphEngine } from './graph-engine.js';
import type { EngagementConfig, EngagementState, AgentTask } from '../types.js';

export type PromptRole = 'primary' | 'sub_agent';

export interface GeneratePromptOptions {
  role: PromptRole;
  agent_id?: string;
  include_state?: boolean;
  include_tools?: boolean;
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
    return generateSubAgentPrompt(state, registeredTools, options);
  }
  return generatePrimaryPrompt(state, registeredTools, options);
}

// ============================================================
// Primary orchestrator prompt
// ============================================================

function generatePrimaryPrompt(
  state: EngagementState,
  tools: ToolEntry[],
  options: GeneratePromptOptions,
): string {
  const sections: string[] = [];

  sections.push(generateIdentitySection(state.config));
  sections.push(generateCoreLoopSection());
  sections.push(generateKeyPrinciplesSection(state.config));

  if (options.include_tools !== false) {
    sections.push(generateToolTableSection(tools));
  }

  if (options.include_state !== false) {
    sections.push(generateStateSnapshotSection(state));
  }

  return sections.join('\n\n');
}

// ============================================================
// Sub-agent prompt
// ============================================================

function generateSubAgentPrompt(
  state: EngagementState,
  tools: ToolEntry[],
  options: GeneratePromptOptions,
): string {
  const sections: string[] = [];

  // Identity
  const agentContext = options.agent_id
    ? state.active_agents.find(a => a.id === options.agent_id || a.agent_id === options.agent_id)
    : undefined;

  sections.push(generateSubAgentIdentitySection(state.config, agentContext));

  // Scoped tool subset
  const subAgentToolNames = new Set([
    'get_agent_context', 'validate_action', 'log_action_event',
    'parse_output', 'report_finding', 'query_graph', 'get_skill',
    'open_session', 'write_session', 'read_session', 'send_to_session',
    'list_sessions', 'close_session', 'resize_session', 'signal_session',
    'update_session', 'get_evidence',
  ]);
  const scopedTools = tools.filter(t => subAgentToolNames.has(t.name));

  if (options.include_tools !== false) {
    sections.push(generateToolTableSection(scopedTools));
  }

  sections.push(generateSubAgentWorkflowSection());

  if (options.include_state !== false && agentContext) {
    sections.push(generateAgentContextSection(agentContext));
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
  if (config.opsec) {
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

function generateCoreLoopSection(): string {
  return `## Core Loop

1. **Start every session** (including after compaction) by calling \`get_state()\`. This gives you the complete engagement briefing from the graph — scope, discoveries, access, objectives, frontier.

2. **Assess the frontier** by calling \`next_task()\`. You'll receive candidate actions pre-filtered by the deterministic layer (out-of-scope, duplicates, and hard OPSEC vetoes are already removed). Everything else is yours to score.

3. **Score and prioritize** the candidates. For each, consider:
   - Does this open a multi-step attack chain?
   - What's the likely defensive posture of the target?
   - What sequencing makes sense (what should happen before what)?
   - What's the risk/reward ratio given our OPSEC profile?
   - Does this move us closer to an objective?

4. **Explore the graph** with \`query_graph()\` whenever the frontier doesn't capture a pattern you're seeing.

5. **Validate before executing** by calling \`validate_action()\` with your proposed action. **Always pass \`frontier_item_id\`** from \`next_task()\`.

6. **Log execution start** with \`log_action_event(event_type="action_started")\` before major execution. **Always pass both \`action_id\` and \`frontier_item_id\`.**

7. **Execute the action** using the appropriate tools.

8. **Parse or report results immediately**:
   - Use \`parse_output()\` for supported parser output. **Always pass \`action_id\` and \`frontier_item_id\`.**
   - Use \`report_finding()\` for manual observations or already-structured data. **Always pass \`action_id\` and \`frontier_item_id\`.**

9. **Log the final outcome** with \`log_action_event(event_type="action_completed" | "action_failed")\`. **Always pass \`action_id\`.**

10. **Dispatch sub-agents** for parallel work using \`register_agent()\`.

11. **Monitor and re-plan** by periodically calling \`get_state()\`.

12. **Repeat** until all objectives are achieved or the operator redirects.`;
}

function generateKeyPrinciplesSection(config: EngagementConfig): string {
  const lines = [
    '## Key Principles',
    '',
    '- **The graph is your memory.** After compaction, `get_state()` reconstructs everything.',
    '- **Report early, report often.** Every `report_finding()` call triggers inference rules.',
    '- **Use structured action logging.** `validate_action()` → `log_action_event()` for causal linkage.',
    '- **Thread `frontier_item_id` through every call.** Critical for retrospective attribution.',
    '- **The deterministic layer is a guardrail, not a brain.** You do the offensive thinking.',
    '- **Validate before you execute.** Every significant action goes through `validate_action()` first.',
    '- **Use `query_graph()` liberally.** The graph may contain patterns the frontier doesn\'t surface.',
  ];

  if (config.opsec) {
    lines.push(`- **Respect OPSEC.** Profile: ${config.opsec.name}. Max noise: ${config.opsec.max_noise}. Factor noise levels into your decisions.`);
  } else {
    lines.push('- **Respect OPSEC.** Check the engagement\'s OPSEC profile in `get_state()` and factor noise levels into your decisions.');
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
2. Call \`validate_action\` before executing any significant action
3. Call \`log_action_event(event_type="action_started")\` before execution
4. Execute the action
5. Use \`parse_output()\` for supported tool output, or \`report_finding()\` for manual observations
6. Call \`log_action_event(event_type="action_completed" | "action_failed")\` when done
7. Use \`query_graph()\` if you need more context
8. Use \`get_skill()\` for methodology guidance

Report every discovery immediately. When done, your task will be marked complete by the primary session.`;
}

function generateAgentContextSection(agent: AgentTask): string {
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

  return lines.join('\n');
}
