import { z } from 'zod';
import { FRONTIER_TYPES } from '../contracts/dashboard-v1.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { isIpInCidr } from '../services/cidr.js';
import type { ActivityLogEntry } from '../services/engine-context.js';
import type { AgentTask } from '../types.js';
import {
  DispatchCommandError,
  DispatchCommandService,
} from '../services/dispatch-command-service.js';
import { AgentLifecycleCommandService } from '../services/agent-lifecycle-command-service.js';

interface PriorActionOnScope {
  action_id?: string;
  at: string;
  technique?: string;
  tool?: string;
  result?: string;              // success | failure | partial | neutral
  targets: string[];            // the in-scope node(s)/target(s) this action touched
}

const PRIOR_ACTIONS_LIMIT = 25;
// Bound the lookback so a huge activity log doesn't cost O(N) per dispatch (sparse
// matches would otherwise scan the whole log). Prior actions older than this tail
// are ancient for grounding purposes.
const PRIOR_ACTIONS_SCAN_CAP = 4000;

function taskWireIdentity(task: AgentTask): {
  task_id: string;
  agent_label: string;
  id: string;
  agent_id: string;
} {
  const taskId = task.task_id ?? task.id;
  const agentLabel = task.agent_label ?? task.agent_id;
  return {
    task_id: taskId,
    agent_label: agentLabel,
    id: taskId,
    agent_id: agentLabel,
  };
}

/**
 * Recent completed/failed actions the agent's scope has already seen — so a dispatched
 * agent grounds in what's been run (digs into gaps instead of repeating scans). `match`
 * returns the in-scope target(s) an entry touched (by node id, or by CIDR/IP). Reverse-
 * scans a bounded tail of the activity log, dedups by action_id, returns chronological.
 */
function collectPriorActions(engine: GraphEngine, match: (e: ActivityLogEntry) => string[] | undefined): PriorActionOnScope[] {
  const out: PriorActionOnScope[] = [];
  const seen = new Set<string>();
  const hist = engine.getFullHistory();
  const stop = Math.max(0, hist.length - PRIOR_ACTIONS_SCAN_CAP);
  for (let i = hist.length - 1; i >= stop && out.length < PRIOR_ACTIONS_LIMIT; i--) {
    const e = hist[i];
    if (e.event_type !== 'action_completed' && e.event_type !== 'action_failed') continue;
    const hit = match(e);
    if (!hit || hit.length === 0) continue;
    if (e.action_id) {
      if (seen.has(e.action_id)) continue;   // one row per action, even if logged twice
      seen.add(e.action_id);
    }
    out.push({ action_id: e.action_id, at: e.timestamp, technique: e.technique, tool: e.tool_name, result: e.result_classification, targets: hit });
  }
  return out.reverse(); // chronological (oldest first)
}

/** Prior actions that touched any of the agent's scoped NODES. */
function buildPriorActionsOnScope(engine: GraphEngine, seedIds: string[]): PriorActionOnScope[] {
  if (seedIds.length === 0) return [];
  const scope = new Set(seedIds);
  return collectPriorActions(engine, e => e.target_node_ids?.filter(n => scope.has(n)));
}

/** Prior actions within a discovery CIDR — so a network_discovery agent doesn't
 *  re-enumerate a subnet a prior scan already covered. */
function buildPriorActionsForCidr(engine: GraphEngine, cidr: string | undefined): PriorActionOnScope[] {
  if (!cidr) return [];
  return collectPriorActions(engine, e => {
    const hits: string[] = [];
    if (e.target_cidrs?.includes(cidr)) hits.push(cidr);
    for (const ip of e.target_ips ?? []) { try { if (isIpInCidr(ip, cidr)) hits.push(ip); } catch { /* bad ip/cidr */ } }
    return hits;
  });
}

export function registerAgentTools(server: McpServer, engine: GraphEngine): void {
  const dispatchCommands = new DispatchCommandService(engine);
  const lifecycleCommands = new AgentLifecycleCommandService(engine);

  // ============================================================
  // Tool: register_agent
  // Primary session registers a sub-agent task.
  // ============================================================
  server.registerTool(
    'register_agent',
    {
      title: 'Register Agent',
      description: `Register a new sub-agent task. Called by the primary session when dispatching agents.

Provide the frontier item the agent should work on and the relevant node IDs for its scoped subgraph view.
The agent can then call get_agent_context with its task ID to receive its scoped view.`,
      inputSchema: {
        agent_label: z.string().optional().describe('Canonical human-readable label for the agent'),
        agent_id: z.string().optional().describe('Legacy alias for agent_label (retained for one minor release)'),
        frontier_item_id: z.string().optional().describe('ID of the frontier item this agent should work on (recommended for attribution)'),
        subgraph_node_ids: z.array(z.string()).default([]).describe('Optional node IDs relevant to this agent\'s task. Leave empty to auto-compute from the frontier item.'),
        skill: z.string().optional().describe('Skill/methodology to apply'),
        archetype: z.string().optional().describe('Optional agent-type override (e.g. recon_scanner, web_tester, credential_operator, post_exploit, cve_researcher). When omitted, the archetype is auto-selected from the frontier item type + node type.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('register_agent', async ({
      agent_label,
      agent_id: legacyAgentId,
      frontier_item_id,
      subgraph_node_ids,
      skill,
      archetype,
    }) => {
      if (!agent_label && !legacyAgentId) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: 'agent_label is required' }) }],
          isError: true,
        };
      }
      if (agent_label && legacyAgentId && agent_label !== legacyAgentId) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: 'agent_label and legacy agent_id must match when both are supplied',
            }),
          }],
          isError: true,
        };
      }
      const agent_id = agent_label ?? legacyAgentId!;
      const execution = dispatchCommands.register({
        agent_label: agent_id,
        frontier_item_id,
        target_node_ids: subgraph_node_ids,
        skill,
        archetype,
      }, { transport: 'mcp' });
      const body = execution.result!.body;
      const task = body.task as AgentTask | undefined;
      if (body.dispatched !== true || !task) {
        return {
          content: [{ type: 'text', text: JSON.stringify(body, null, 2) }],
          isError: true,
        };
      }
      return {
        content: [{
          type: 'text', text: JSON.stringify({
            ...taskWireIdentity(task),
            status: task.status,
            archetype: task.archetype,
            scope_node_count: task.subgraph_node_ids.length,
            ...(body.skipped_existing === true
              ? { skipped_existing: true }
              : {}),
            command_id: execution.command_id,
            replayed: execution.replayed,
            message: `Agent ${task.agent_label ?? task.agent_id} registered${frontier_item_id ? ` for task ${frontier_item_id}` : ''} as ${task.archetype}`,
          }, null, 2),
        }],
      };
    })
  );

  // ============================================================
  // Tool: dispatch_agents
  // Batch-register sub-agent tasks from the current filtered frontier.
  // ============================================================
  server.registerTool(
    'dispatch_agents',
    {
      title: 'Dispatch Agents',
      description: `Batch-register sub-agent tasks from the current filtered frontier.

Uses the same frontier computation and deterministic filtering path as next_task,
then registers up to count running agent tasks with auto-computed subgraph scopes.
Skips frontier items that already have a running agent or cannot be scoped.`,
      inputSchema: {
        count: z.number().int().min(1).max(20).default(3).describe('Maximum number of agents to dispatch'),
        strategy: z.enum(['top_priority', 'by_type']).default('top_priority').describe('How to choose frontier items'),
        types: z.array(z.enum(FRONTIER_TYPES)).optional().describe('Optional frontier types to include when dispatching'),
        skill: z.string().optional().describe('Optional skill override applied to each dispatched agent'),
        archetype: z.string().optional().describe('Optional agent-type override applied to every dispatched agent. When omitted, each agent\'s archetype is auto-selected from its frontier item type + node type.'),
        hops: z.number().int().min(1).max(5).default(2).describe('Hops to use when auto-computing subgraph scope'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      }
    },
    withErrorBoundary('dispatch_agents', async ({ count, strategy, types, skill, archetype, hops }) => {
      const execution = dispatchCommands.dispatchFrontierBatch({
        count,
        strategy,
        types,
        skill,
        archetype,
        hops,
      }, { transport: 'mcp' });
      const result: Record<string, unknown> = {
        ...execution.result,
        command_id: execution.command_id,
        replayed: execution.replayed,
      };
      if (execution.result?.dispatched.length === 0) {
        result.warning = 'No agents dispatched — all candidates were skipped or filtered';
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    })
  );

  // ============================================================
  // Tool: get_agent_context
  // Returns scoped subgraph view for a specific agent.
  // ============================================================
  server.registerTool(
    'get_agent_context',
    {
      title: 'Get Agent Context',
      description: `Returns the scoped subgraph view for a registered agent.

Agents call this to receive only the nodes and edges relevant to their task,
plus N-hop neighbors for context. Automatically includes credentials and services
connected to hosts in the subgraph. This keeps agent context focused and
prevents scope creep.

If the agent was registered without explicit subgraph_node_ids, the subgraph is
auto-computed from the frontier item's target node(s).`,
      inputSchema: {
        task_id: z.string().describe('Task ID returned from register_agent'),
        hops: z.number().int().min(1).max(5).default(2).describe('Number of hops from seed nodes to include'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('get_agent_context', async ({ task_id, hops }) => {
      const task = engine.getTask(task_id);
      if (!task) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: `Task not found: ${task_id}` }, null, 2)
          }],
          isError: true
        };
      }

      // Use snapshotted seeds, falling back to live computation for backward compat
      const seedIds = task.subgraph_node_ids.length > 0
        ? task.subgraph_node_ids
        : task.frontier_item_id ? engine.computeSubgraphNodeIds(task.frontier_item_id, hops) : [];

      // For network_discovery tasks with no backing nodes, return CIDR + scope context
      if (seedIds.length === 0 && task.frontier_item_id?.startsWith('frontier-discovery-')) {
        const frontierItem = engine.getFrontierItem(task.frontier_item_id);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ...taskWireIdentity(task),
              frontier_item_id: task.frontier_item_id,
              skill: task.skill,
              objective: task.objective,
              archetype: task.archetype,
              discovery_context: {
                target_cidr: frontierItem?.target_cidr,
                scope: engine.getState().config.scope,
              },
              subgraph: { nodes: [], edges: [] },
              prior_actions_on_scope: buildPriorActionsForCidr(engine, frontierItem?.target_cidr),
              message: `Network discovery task for ${frontierItem?.target_cidr || 'unknown CIDR'}`,
            }, null, 2)
          }]
        };
      }

      // No seeds. Two cases: an ad-hoc deploy (no frontier item — the target
      // lives in the objective), or a stale frontier item that no longer
      // resolves. Either way, return the objective + scope so the agent can act
      // rather than receiving an empty, contextless reply.
      if (seedIds.length === 0) {
        const adHoc = !task.frontier_item_id;
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ...taskWireIdentity(task),
              frontier_item_id: task.frontier_item_id,
              skill: task.skill,
              objective: task.objective,
              archetype: task.archetype,
              subgraph: { nodes: [], edges: [] },
              scope: engine.getState().config.scope,
              // No scoped nodes/CIDR to attribute prior actions to here — keep the field
              // present (honestly empty) so the agent doesn't read its ABSENCE as "nothing
              // done"; it should query_graph/get_history if it needs the wider picture.
              prior_actions_on_scope: [],
              ...(adHoc
                ? { message: 'Ad-hoc deploy with no pre-seeded graph nodes — work from the objective (your target is named there) and the engagement scope; discover and report findings as you go.' }
                : { warning: `Frontier item ${task.frontier_item_id} no longer resolves to any graph nodes. The frontier may have changed since task registration. Report this to the primary session.` }),
            }, null, 2)
          }]
        };
      }

      const subgraph = engine.getSubgraphForAgent(seedIds, { hops });

      // Prior actions already run against this agent's scope. The subgraph gives the
      // agent the RESULT nodes but not WHICH actions produced them — so without this an
      // agent can't tell "nmap already ran here, 3 services found" from "nothing done
      // yet", and it re-scans or misses the gaps. Surfacing the recent completed/failed
      // actions on-scope lets it dig into what's identified and run only what's missing.
      const priorActions = buildPriorActionsOnScope(engine, seedIds);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ...taskWireIdentity(task),
            frontier_item_id: task.frontier_item_id,
            skill: task.skill,
            // archetype + objective complete the context on the common (subgraph)
            // path too — the discovery / empty-subgraph branches already include
            // them, so the agent always knows its type + job.
            archetype: task.archetype,
            objective: task.objective,
            subgraph,
            prior_actions_on_scope: priorActions,
            message: `Subgraph context: ${subgraph.nodes.length} nodes, ${subgraph.edges.length} edges; ${priorActions.length} prior action(s) already run on your scope — review them to avoid repeating work and to find the gaps still worth doing.`
          }, null, 2)
        }]
      };
    })
  );

  // ============================================================
  // Tool: submit_agent_transcript
  // Sub-agent hands a structured wrap-up + raw transcript blob back
  // to the primary session before calling update_agent(done).
  // ============================================================
  server.registerTool(
    'submit_agent_transcript',
    {
      title: 'Submit Agent Transcript',
      description: `Sub-agent wrap-up: hand the primary session a short summary plus an optional raw transcript blob.

Call this **before** \`update_agent(status: "completed")\`. The transcript (if provided) is stored in evidence and an \`agent_transcript_submitted\` event links it to the agent task so retrospective analysis can attribute reasoning back to the sub-agent.

Fields:
- \`summary\` is required — a paragraph or two describing what the agent did, what it found, and what (if anything) is left.
- \`transcript_jsonl\` is optional but strongly recommended — raw JSONL of the sub-agent's tool I/O.
- \`key_thought_event_ids\` / \`key_finding_ids\` are optional pointers to events/findings the primary should look at first.`,
      inputSchema: {
        task_id: z.string().optional().describe('Agent task ID this transcript belongs to (preferred). Returned by register_agent as `task_id`.'),
        agent_id: z.string().optional().describe('Agent task ID this transcript belongs to. Accepted as a legacy alias for `task_id`; a legacy agent label resolves only when exactly one task has that label.'),
        summary: z.string().min(1).describe('Short wrap-up paragraph from the sub-agent'),
        transcript_jsonl: z.string().optional().describe('Raw JSONL transcript of the sub-agent run (stored as evidence)'),
        key_thought_event_ids: z.array(z.string()).optional().describe('Event IDs of the most important thoughts/decisions'),
        key_finding_ids: z.array(z.string()).optional().describe('Finding IDs the primary should review first'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('submit_agent_transcript', async ({ task_id, agent_id, summary, transcript_jsonl, key_thought_event_ids, key_finding_ids }) => {
      const lookupId = task_id ?? agent_id;
      if (!lookupId) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: 'Either task_id or agent_id is required' }, null, 2),
          }],
          isError: true,
        };
      }
      const execution = lifecycleCommands.submitTranscript({
        task_reference: lookupId,
        summary,
        transcript_jsonl,
        key_thought_event_ids,
        key_finding_ids,
      }, { transport: 'mcp' });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ...execution.result,
            command_id: execution.command_id,
            replayed: execution.replayed,
          }, null, 2),
        }],
      };
    }),
  );

  // ============================================================
  // Tool: update_agent
  // Update agent task status.
  // ============================================================
  server.registerTool(
    'update_agent',
    {
      title: 'Update Agent Status',
      description: 'Update the status of a running agent task. Call when an agent completes or fails.',
      inputSchema: {
        task_id: z.string().describe('Task ID to update'),
        status: z.enum(['completed', 'failed']).describe('New status'),
        summary: z.string().optional().describe('Brief summary of results or failure reason')
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('update_agent', async ({ task_id, status, summary }) => {
      const execution = lifecycleCommands.updateStatus({
        task_id,
        status,
        summary,
      }, { transport: 'mcp' });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ...execution.result,
            command_id: execution.command_id,
            replayed: execution.replayed,
          }, null, 2)
        }]
      };
    })
  );

  // ============================================================
  // Tool: dispatch_subnet_agents
  // Dispatch one sub-agent per scope CIDR for parallel enumeration.
  // ============================================================
  server.registerTool(
    'dispatch_subnet_agents',
    {
      title: 'Dispatch Subnet Agents',
      description: `Dispatch one sub-agent per scope CIDR for parallel network enumeration.

For each CIDR in the engagement scope, registers a sub-agent whose task is to
sweep and enumerate that subnet. Skips CIDRs that already have a running agent
or are fully discovered. Each agent receives the already-discovered nodes in
its CIDR as its scoped subgraph.`,
      inputSchema: {
        max_agents: z.number().int().min(1).max(20).default(8).describe('Maximum number of agents to dispatch'),
        skill: z.string().default('subnet-enumeration').describe('Skill/methodology to assign to each agent'),
        hops: z.number().int().min(1).max(5).default(2).describe('Hops for subgraph scope computation'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      }
    },
    withErrorBoundary('dispatch_subnet_agents', async ({ max_agents, skill, hops: _hops }) => {
      try {
        const execution = dispatchCommands.dispatchSubnets({
          max_agents,
          skill,
          hops: _hops,
        }, { transport: 'mcp' });
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ...execution.result,
              command_id: execution.command_id,
              replayed: execution.replayed,
            }, null, 2),
          }],
        };
      } catch (error) {
        if (!(error instanceof DispatchCommandError)) throw error;
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: error.message,
              code: error.code,
            }, null, 2),
          }],
          isError: true,
        };
      }
    })
  );

  // ============================================================
  // Tool: dispatch_campaign_agents
  // Dispatch sub-agents for each item in a campaign.
  // ============================================================
  server.registerTool(
    'dispatch_campaign_agents',
    {
      title: 'Dispatch Campaign Agents',
      description: `Dispatch sub-agents for each item in a campaign, using campaign-aware scoping.

Activates the campaign if it is in draft status, then registers one agent per
frontier item (up to max_agents). Scope computation is strategy-aware:
- credential_spray: credential + target services + parent hosts
- post_exploitation: host + all connected nodes
- enumeration/network_discovery/custom: N-hop subgraph from frontier seeds

Skips items that already have a running agent.`,
      inputSchema: {
        campaign_id: z.string().describe('ID of the campaign to dispatch agents for'),
        max_agents: z.number().int().min(1).max(20).default(8).describe('Maximum number of agents to dispatch'),
        hops: z.number().int().min(1).max(5).default(2).describe('Hops for subgraph scope computation'),
        skill: z.string().optional().describe('Optional skill override applied to each dispatched agent'),
        archetype: z.string().optional().describe('Optional agent-type override applied to every dispatched agent. When omitted, the archetype is derived from the campaign strategy (e.g. credential_spray → credential_operator).'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      }
    },
    withErrorBoundary('dispatch_campaign_agents', async ({ campaign_id, max_agents, hops, skill, archetype }) => {
      try {
        const execution = dispatchCommands.dispatchCampaign({
          campaign_id,
          max_agents,
          hops,
          skill,
          archetype,
        }, { transport: 'mcp' });
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ...execution.result,
              command_id: execution.command_id,
              replayed: execution.replayed,
            }, null, 2),
          }],
        };
      } catch (error) {
        if (!(error instanceof DispatchCommandError)) throw error;
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: error.message,
              campaign_id,
              code: error.code,
            }, null, 2),
          }],
          isError: true,
        };
      }
    })
  );

  // ============================================================
  // Tool: agent_heartbeat (P0.3)
  // Sub-agents call this periodically so the watchdog can distinguish
  // "still working" from "silently dead." Tasks that never heartbeat
  // are exempt from the watchdog (preserves backward-compat for
  // legacy in-process sub-agents that complete in one MCP turn).
  // ============================================================
  server.registerTool(
    'agent_heartbeat',
    {
      title: 'Agent Heartbeat',
      description: `Sub-agents call this periodically (recommended every 30–60 seconds) to signal liveness.

The runtime watchdog will mark agents as "interrupted" if their last heartbeat is older than \`heartbeat_ttl_seconds\` (default 120s). Agents that never heartbeat are exempt — tools that complete in a single MCP turn don't need to call this.

Returns the new heartbeat timestamp on success, or an error if the task is unknown / already in a terminal state.`,
      inputSchema: {
        task_id: z.string().describe('Task ID returned from register_agent'),
        acknowledged_query_id: z.string().optional().describe('Answer query_id already received and acted on; stops redelivery.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('agent_heartbeat', async ({ task_id, acknowledged_query_id }) => {
      const execution = lifecycleCommands.heartbeat({
        task_id,
        acknowledged_query_id,
      }, { transport: 'mcp' });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ...execution.result,
            command_id: execution.command_id,
            replayed: execution.replayed,
          }, null, 2),
        }],
      };
    }),
  );

  // ============================================================
  // ask_operator (3D) — a running sub-agent escalates a decision to the operator
  // and waits for an answer. Records a question; the answer comes back on the
  // agent's next agent_heartbeat as `pending_answer` (no new blocking transport).
  // ============================================================
  server.registerTool(
    'ask_operator',
    {
      title: 'Ask the Operator',
      description: `Escalate a decision to the human operator and WAIT for their answer. Use this at a genuine fork you can't resolve yourself (ambiguous path, risky/irreversible step, missing context) — not for routine work.

After calling this, keep calling \`agent_heartbeat({ task_id })\`; when the operator answers, the heartbeat response carries \`pending_answer: { query_id, question, answer }\`. Read the answer, proceed, then acknowledge it on a later heartbeat with \`agent_heartbeat({ task_id, acknowledged_query_id: query_id })\`. If no answer arrives before your task times out, make the safest reasonable choice and note that you proceeded without an answer.`,
      inputSchema: {
        task_id: z.string().describe('Your agent task id'),
        agent_id: z.string().optional().describe('Your agent id (for attribution)'),
        question: z.string().describe('The question for the operator — be specific and self-contained'),
        options: z.array(z.string()).optional().describe('Optional suggested answers the operator can pick from'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    withErrorBoundary('ask_operator', async ({ task_id, agent_id, question, options }) => {
      const execution = lifecycleCommands.askQuestion({
        task_id,
        agent_label: agent_id,
        question,
        options,
      }, { transport: 'mcp' });
      const query = execution.result!.query;
      return {
        content: [{ type: 'text', text: JSON.stringify({
          ok: true,
          query_id: query.query_id,
          status: 'open',
          command_id: execution.command_id,
          replayed: execution.replayed,
          note: 'Keep heartbeating; the answer arrives as pending_answer. After acting, acknowledge it with acknowledged_query_id on a later heartbeat.',
        }, null, 2) }],
      };
    }),
  );

  // ============================================================
  // manage_agent_directive — operator/primary steering of a running sub-agent.
  // acknowledge_agent_directive — sub-agent confirms it saw the directive.
  // ============================================================
  server.registerTool(
    'manage_agent_directive',
    {
      title: 'Manage Agent Directive',
      description: `Steer a running sub-agent. Issues a directive delivered to the agent on its next \`agent_heartbeat\`.

Kinds:
- \`pause\` / \`resume\` — halt/continue the agent (it keeps heartbeating while paused).
- \`stop\` — wrap up and exit; the runtime kills the headless process and marks the task interrupted.
- \`narrow_scope\` — restrict the agent to \`node_ids\`.
- \`skip_types\` — ignore frontier items of \`frontier_types\`.
- \`prioritize\` — do \`frontier_types\` first.
- \`instruct\` — free-text steer: the operator's instruction in \`note\`; the agent reads and honors it on its next heartbeat (e.g. "focus on SMB", "try password spray instead").

A new directive supersedes any still-pending one for the task (latest instruction wins).`,
      inputSchema: {
        task_id: z.string().describe('Agent task ID to steer'),
        kind: z.enum(['pause', 'resume', 'stop', 'narrow_scope', 'skip_types', 'prioritize', 'instruct'])
          .describe('The steering action'),
        node_ids: z.array(z.string()).optional().describe('narrow_scope: node ids to restrict to'),
        frontier_types: z.array(z.string()).optional().describe('skip_types / prioritize: frontier item types'),
        note: z.string().optional().describe('instruct: the free-text instruction; otherwise an optional human-readable note'),
        issued_by: z.string().optional().describe('Operator id (defaults to "primary")'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    withErrorBoundary('manage_agent_directive', async ({ task_id, kind, node_ids, frontier_types, note, issued_by }) => {
      const execution = lifecycleCommands.issueDirective({
        task_id,
        kind,
        node_ids,
        frontier_types,
        note,
        issued_by,
      }, { transport: 'mcp' });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ...execution.result,
            command_id: execution.command_id,
            replayed: execution.replayed,
            note: kind === 'stop'
              ? 'stop recorded — the task-execution service will kill the process and interrupt the task'
              : 'directive recorded — delivered to the agent on its next heartbeat',
          }, null, 2),
        }],
      };
    }),
  );

  server.registerTool(
    'acknowledge_agent_directive',
    {
      title: 'Acknowledge Agent Directive',
      description: `Sub-agents call this to confirm they received a steering directive (delivered via the \`pending_directive\` field on \`agent_heartbeat\`). After acknowledging, act on it: pause work, resume, narrow your scope, etc.`,
      inputSchema: {
        task_id: z.string().describe('Your agent task ID'),
        directive_id: z.string().describe('The directive id from agent_heartbeat.pending_directive'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('acknowledge_agent_directive', async ({ task_id, directive_id }) => {
      const execution = lifecycleCommands.acknowledgeDirective({
        task_id,
        directive_id,
      }, { transport: 'mcp' });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ...execution.result,
            command_id: execution.command_id,
            replayed: execution.replayed,
          }, null, 2),
        }],
      };
    }),
  );
}

// Backward-compatible helper for internal callers/tests. The canonical
// implementation lives in DispatchCommandService so every production adapter
// receives durable idempotency and one agents+campaigns transaction.
export type DispatchResult = import('../services/dispatch-command-service.js').CampaignAgentDispatchResponse & {
  error?: string;
};

export function dispatchCampaignAgents(
  engine: GraphEngine,
  campaign_id: string,
  options: { max_agents?: number; hops?: number; skill?: string; archetype?: string } = {},
): DispatchResult {
  try {
    return new DispatchCommandService(engine).dispatchCampaign({
      campaign_id,
      max_agents: options.max_agents,
      hops: options.hops,
      skill: options.skill,
      archetype: options.archetype,
    }, { transport: 'system' }).result!;
  } catch (error) {
    const campaign = engine.getCampaign(campaign_id);
    return {
      campaign_id,
      strategy: campaign?.strategy ?? '',
      requested: options.max_agents ?? 8,
      total_items: campaign?.items.length ?? 0,
      dispatched: [],
      skipped: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
