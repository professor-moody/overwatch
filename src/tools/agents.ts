import { z } from 'zod';
import { FRONTIER_TYPES } from '../contracts/dashboard-v1.js';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { isIpInCidr } from '../services/cidr.js';
import { recommendArchetype, isArchetypeId, type AgentArchetypeId, type RecommendInput } from '../services/agent-archetypes.js';
import type { ActivityLogEntry } from '../services/engine-context.js';
import type { AgentTask } from '../types.js';

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
      if (frontier_item_id) {
        const existing = engine.getRunningTaskForFrontierItem(frontier_item_id);
        if (existing) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                ...taskWireIdentity(existing),
                status: existing.status,
                skipped_existing: true,
                message: `A running agent is already assigned to ${frontier_item_id}`,
              }, null, 2)
            }]
          };
        }
      }

      // Eagerly snapshot seed node IDs when caller omits them, so the scope
      // survives frontier changes between registration and get_agent_context.
      let resolvedNodeIds = subgraph_node_ids || [];
      let scope_warning: string | undefined;
      if (frontier_item_id && resolvedNodeIds.length === 0 && !frontier_item_id.startsWith('frontier-discovery-')) {
        resolvedNodeIds = engine.computeSubgraphNodeIds(frontier_item_id, 2);
        if (resolvedNodeIds.length === 0) {
          scope_warning = `Frontier item ${frontier_item_id} resolved to zero seed nodes — the agent may lack graph context`;
        }
      }

      const resolvedArchetype = resolveDispatchArchetype(engine, {
        explicit: archetype,
        frontierItem: frontier_item_id ? engine.getFrontierItem(frontier_item_id) : undefined,
      });
      const task = buildTask(agent_id, frontier_item_id, resolvedNodeIds, skill, undefined, resolvedArchetype);
      const reg = engine.registerAgent(task);
      if (reg.cap_exceeded) {
        // Operator-policy dispatch cap: this subnet/target is at its concurrent
        // target-facing agent limit. Deferral, not failure — retry when one frees.
        const c = reg.cap_exceeded;
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ok: false,
              error: 'dispatch_cap_exceeded',
              cap_scope: c.scope,
              cap_key: c.key,
              limit: c.limit,
              current: c.current,
              message: `Dispatch cap: ${c.current}/${c.limit} target-facing agents already on ${c.scope} ${c.key}. Wait for one to finish or raise the operator policy limit.`,
            }, null, 2),
          }],
          isError: true,
        };
      }
      if (!reg.ok) {
        // Two refusal modes. node_conflict: a same-archetype agent is already at this
        // node (a node-scoped dispatch with no frontier item can't take a lease, so
        // it's node-deduped). lease_conflict (P1.4): another task holds this frontier
        // item's lease. Surface each accurately so the caller picks a different item/
        // node rather than racing or seeing a bogus "frontier item undefined".
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(reg.node_conflict
              ? {
                  ok: false,
                  error: 'node_dispatch_conflict',
                  node_id: reg.node_conflict.node_id,
                  existing_task_id: reg.node_conflict.existing_task_id,
                  existing_agent_id: reg.node_conflict.existing_agent_id,
                  message: `Node ${reg.node_conflict.node_id} is already being worked by agent ${reg.node_conflict.existing_agent_id}. Pick a different node or wait for it to finish.`,
                }
              : {
                  ok: false,
                  error: 'frontier_lease_conflict',
                  frontier_item_id,
                  existing_task_id: reg.lease_conflict?.existing_task_id,
                  existing_agent_id: reg.lease_conflict?.existing_agent_id,
                  message: `Frontier item ${frontier_item_id} is already leased by task ${reg.lease_conflict?.existing_task_id}. Pick a different item.`,
                }, null, 2),
          }],
          isError: true,
        };
      }

      const response: Record<string, unknown> = {
        task_id: task.id,
        agent_label: agent_id,
        id: task.id,
        agent_id,
        status: 'running',
        archetype: resolvedArchetype,
        scope_node_count: resolvedNodeIds.length,
        message: `Agent ${agent_id} registered${frontier_item_id ? ` for task ${frontier_item_id}` : ''} as ${resolvedArchetype}`,
      };
      if (scope_warning) response.scope_warning = scope_warning;

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(response, null, 2)
        }]
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
      const frontier = engine.computeFrontier();
      const { passed } = engine.filterFrontier(frontier);
      const typeOrder = types && types.length > 0 ? types : [...FRONTIER_TYPES];
      const allowedTypes = new Set(typeOrder);

      let candidates = passed.filter((item) => allowedTypes.has(item.type as typeof FRONTIER_TYPES[number]));
      if (strategy === 'by_type') {
        const queues = new Map(typeOrder.map((type) => [type, candidates.filter((item) => item.type === type)]));
        const ordered: typeof candidates = [];
        let madeProgress = true;
        while (madeProgress) {
          madeProgress = false;
          for (const type of typeOrder) {
            const queue = queues.get(type);
            if (queue && queue.length > 0) {
              ordered.push(queue.shift()!);
              madeProgress = true;
            }
          }
        }
        candidates = ordered;
      }

      const total_candidates = candidates.length;
      const dispatched: Array<{ task_id: string; agent_label: string; id: string; agent_id: string; frontier_item_id: string; frontier_type: string; archetype: string; skill?: string }> = [];
      const skipped_existing: Array<{ frontier_item_id: string; task_id: string; agent_label: string; id: string; agent_id: string }> = [];
      const skipped_unscoped: Array<{ frontier_item_id: string; frontier_type: string }> = [];
      const skipped_lease_conflict: Array<{ frontier_item_id: string; frontier_type: string; existing_task_id?: string; existing_agent_id?: string }> = [];
      const skipped_dispatch_cap: Array<{ frontier_item_id: string; frontier_type: string; cap_scope: string; cap_key: string; limit: number; current: number }> = [];

      for (const item of candidates) {
        if (dispatched.length >= count) break;

        const existing = engine.getRunningTaskForFrontierItem(item.id);
        if (existing) {
          skipped_existing.push({
            frontier_item_id: item.id,
            ...taskWireIdentity(existing),
          });
          continue;
        }

        const scope = engine.computeSubgraphNodeIds(item.id, hops);
        if (scope.length === 0 && item.type !== 'network_discovery') {
          skipped_unscoped.push({
            frontier_item_id: item.id,
            frontier_type: item.type,
          });
          continue;
        }

        const itemArchetype = resolveDispatchArchetype(engine, { explicit: archetype, frontierItem: item });
        const agent_id = `agent-${item.type.replace(/[^a-z]/g, '').slice(0, 6)}-${uuidv4().slice(0, 8)}`;
        const task = buildTask(agent_id, item.id, scope, skill, undefined, itemArchetype);
        // F2: registerAgent may refuse the task if the frontier lease was
        // grabbed by another caller in the same window. When that happens
        // the task is NOT inserted, so we must NOT report it as dispatched.
        const reg = engine.registerAgent(task);
        if (reg.cap_exceeded) {
          skipped_dispatch_cap.push({
            frontier_item_id: item.id,
            frontier_type: item.type,
            cap_scope: reg.cap_exceeded.scope,
            cap_key: reg.cap_exceeded.key,
            limit: reg.cap_exceeded.limit,
            current: reg.cap_exceeded.current,
          });
          continue;
        }
        if (!reg.ok) {
          skipped_lease_conflict.push({
            frontier_item_id: item.id,
            frontier_type: item.type,
            existing_task_id: reg.lease_conflict?.existing_task_id,
            existing_agent_id: reg.lease_conflict?.existing_agent_id,
          });
          continue;
        }
        dispatched.push({
          task_id: task.id,
          agent_label: task.agent_id,
          id: task.id,
          agent_id: task.agent_id,
          frontier_item_id: item.id,
          frontier_type: item.type,
          archetype: itemArchetype,
          skill,
        });
      }

      const result: Record<string, unknown> = {
        requested: count,
        strategy,
        types: [...typeOrder],
        total_candidates,
        dispatched,
        skipped_existing,
        skipped_unscoped,
        skipped_lease_conflict,
        skipped_dispatch_cap,
      };
      if (dispatched.length === 0) {
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
      // Resolve the target task. Historically this tool only accepted a
      // parameter named `agent_id` but used it as a *task* ID, which
      // tripped operators up since register_agent returns both. We now
      // prefer `task_id`, accept `agent_id` as a legacy alias, and as a
      // last resort resolve a legacy agent label only when it uniquely
      // identifies one task. Duplicate labels are reported as ambiguous.
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
      const resolution = engine.resolveAgentTaskReference(lookupId);
      if (resolution.status === 'ambiguous_legacy_label') {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: `Agent label is ambiguous: ${lookupId}`,
              candidate_task_ids: resolution.candidate_task_ids,
              hint: 'Pass the exact task_id returned by register_agent.',
            }, null, 2),
          }],
          isError: true,
        };
      }
      if (resolution.status === 'missing') {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: `Agent task not found: ${lookupId}` }, null, 2),
          }],
          isError: true,
        };
      }
      const task = resolution.task;
      const resolvedTaskId = task.task_id ?? task.id;
      const resolvedAgentId = task.agent_label ?? task.agent_id;

      let evidence_id: string | undefined;
      let transcript_bytes = 0;
      if (transcript_jsonl && transcript_jsonl.length > 0) {
        evidence_id = engine.getEvidenceStore().store({
          evidence_type: 'log',
          filename: 'agent_transcript.jsonl',
          content: transcript_jsonl,
        });
        transcript_bytes = transcript_jsonl.length;
      }

      const details: Record<string, unknown> = {
        summary,
        transcript_bytes,
      };
      if (evidence_id) details.evidence_id = evidence_id;
      if (key_thought_event_ids && key_thought_event_ids.length > 0) details.key_thought_event_ids = key_thought_event_ids;
      if (key_finding_ids && key_finding_ids.length > 0) details.key_finding_ids = key_finding_ids;

      const event = engine.logActionEvent({
        description: `Agent ${resolvedAgentId} submitted transcript: ${summary.slice(0, 120)}${summary.length > 120 ? '…' : ''}`,
        event_type: 'agent_transcript_submitted',
        category: 'agent',
        provenance: 'agent',
        agent_id: resolvedAgentId,
        linked_agent_task_id: resolvedTaskId,
        linked_finding_ids: key_finding_ids,
        details,
      });
      engine.persist();

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            task_id: resolvedTaskId,
            agent_label: resolvedAgentId,
            id: resolvedTaskId,
            agent_id: resolvedAgentId,
            event_id: event.event_id,
            evidence_id,
            transcript_bytes,
            submitted: true,
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
      // F6: validate task existence BEFORE running the transcript-missing
      // check. A typoed task_id used to pollute the activity log with a
      // missing-transcript warning for a task that never existed.
      const task = engine.getTask(task_id);
      if (!task) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: `Task not found: ${task_id}` }, null, 2),
          }],
          isError: true,
        };
      }

      // Visibility hook: warn (non-blocking) when an agent reaches a terminal
      // state without first calling submit_agent_transcript. Exact task linkage
      // wins; a legacy label-only event is accepted only when that label is
      // unique, never across duplicate task labels.
      let transcript_warning_emitted = false;
      if (status === 'completed' || status === 'failed') {
        const agentLabel = task.agent_label ?? task.agent_id;
        const uniqueLabel = engine.getAgentTasks()
          .filter(candidate => (candidate.agent_label ?? candidate.agent_id) === agentLabel).length === 1;
        const history = engine.getFullHistory();
        const submitted = history.some(e =>
          e.event_type === 'agent_transcript_submitted'
          && (
            e.linked_agent_task_id === task_id
            || e.agent_id === task_id
            || (uniqueLabel && e.agent_id === agentLabel)
          ),
        );
        if (!submitted) {
          engine.logActionEvent({
            description: `Agent ${task_id} closed with status "${status}" without calling submit_agent_transcript first`,
            event_type: 'instrumentation_warning',
            category: 'system',
            provenance: 'system',
            linked_agent_task_id: task_id,
            details: { warning: 'missing_agent_transcript', task_id, status },
          });
          transcript_warning_emitted = true;
        }
      }

      const updated = engine.updateAgentStatus(task_id, status, summary);
      if (!updated) {
        // updateAgentStatus can also reject (e.g. terminal-state idempotency).
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: `Task not updated: ${task_id}` }, null, 2),
          }],
          isError: true,
        };
      }
      const response: Record<string, unknown> = {
        ...taskWireIdentity(task),
        status,
        summary,
        updated: true,
      };
      if (transcript_warning_emitted) response.transcript_warning = 'Call submit_agent_transcript before update_agent on terminal status to keep the primary session in the loop.';
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(response, null, 2)
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
      const state = engine.getState();
      const cidrs = state.config.scope.cidrs;
      if (cidrs.length === 0) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: 'No CIDRs in engagement scope' }, null, 2)
          }],
          isError: true
        };
      }

      const rawFrontier = engine.computeFrontier();
      const { passed: frontier, filtered } = engine.filterFrontier(rawFrontier);
      const dispatched: Array<{ task_id: string; agent_label: string; id: string; agent_id: string; cidr: string; existing_nodes: number; skill: string }> = [];
      const skipped: Array<{ cidr: string; reason: string }> = [];

      const graphSnapshot = engine.exportGraph();

      for (const cidr of cidrs) {
        if (dispatched.length >= max_agents) break;

        // Check if a network_discovery frontier item exists AND passed OPSEC filtering
        const slug = cidr.replace(/[./]/g, '-');
        const frontierItemId = `frontier-discovery-${slug}`;
        const frontierItem = frontier.find(f => f.id === frontierItemId);

        // Check if it was filtered (e.g. OPSEC veto)
        if (!frontierItem && filtered.some(f => f.item.id === frontierItemId)) {
          skipped.push({ cidr, reason: 'filtered_by_opsec' });
          continue;
        }

        // Skip fully-discovered CIDRs (no frontier item means fully explored)
        if (!frontierItem) {
          skipped.push({ cidr, reason: 'fully_discovered' });
          continue;
        }

        // Skip CIDRs with a running agent
        const existing = engine.getRunningTaskForFrontierItem(frontierItemId);
        if (existing) {
          skipped.push({ cidr, reason: `running_agent: ${existing.agent_id}` });
          continue;
        }

        // Collect already-discovered node IDs in this CIDR
        const nodesInCidr: string[] = [];
        for (const node of graphSnapshot.nodes) {
          if (node.properties.type === 'host' && node.properties.ip && isIpInCidr(node.properties.ip, cidr)) {
            nodesInCidr.push(node.id);
          }
        }

        const subnetArchetype = resolveDispatchArchetype(engine, { frontierItem });
        const agent_id = `agent-subnet-${slug}-${uuidv4().slice(0, 8)}`;
        const task = buildTask(agent_id, frontierItemId, nodesInCidr, skill, undefined, subnetArchetype);
        // F2: registerAgent may refuse on frontier-lease conflict.
        const reg = engine.registerAgent(task);
        if (!reg.ok) {
          skipped.push({
            cidr,
            reason: reg.cap_exceeded
              ? `dispatch_cap: ${reg.cap_exceeded.current}/${reg.cap_exceeded.limit} on ${reg.cap_exceeded.scope} ${reg.cap_exceeded.key}`
              : `frontier_lease_conflict${reg.lease_conflict ? `: held by task ${reg.lease_conflict.existing_task_id}` : ''}`,
          });
          continue;
        }

        dispatched.push({
          task_id: task.id,
          agent_label: agent_id,
          id: task.id,
          agent_id,
          cidr,
          existing_nodes: nodesInCidr.length,
          skill,
        });
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            requested: max_agents,
            total_cidrs: cidrs.length,
            dispatched,
            skipped,
          }, null, 2)
        }]
      };
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
      const result = dispatchCampaignAgents(engine, campaign_id, { max_agents, hops, skill, archetype });

      if (result.error) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: result.error, campaign_id }, null, 2)
          }],
          isError: true
        };
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
      const currentTask = engine.getTask(task_id);
      if (!currentTask) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ ok: false, error: `task not found: ${task_id}` }, null, 2),
          }],
          isError: true,
        };
      }
      if (acknowledged_query_id) {
        const query = engine.getAgentQueryStore().get(acknowledged_query_id);
        const ownerTaskId = query?.owner_task_id ?? query?.task_id;
        if (!query || ownerTaskId !== task_id || query.status !== 'answered') {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                ok: false,
                error: `query answer not found for task ${task_id}: ${acknowledged_query_id}`,
              }, null, 2),
            }],
            isError: true,
          };
        }
      }
      const ok = engine.agentHeartbeat(task_id);
      if (!ok) {
        const task = engine.getTask(task_id);
        const reason = !task
          ? `task not found: ${task_id}`
          : `task is already in terminal state: ${task.status}`;
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ ok: false, error: reason }, null, 2),
          }],
          isError: true,
        };
      }
      const task = engine.getTask(task_id)!;
      const acknowledgedAnswer = acknowledged_query_id
        ? engine.getAgentQueryStore().acknowledge(acknowledged_query_id, task_id)
        : undefined;
      if (acknowledged_query_id && !acknowledgedAnswer) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ok: false,
              error: `query answer not found for task ${task_id}: ${acknowledged_query_id}`,
            }, null, 2),
          }],
          isError: true,
        };
      }
      // Deliver any pending operator steering directive on the heartbeat the
      // agent already runs — zero extra round-trips. The agent must
      // acknowledge_agent_directive and then act on it.
      const pending = engine.getPendingAgentDirective(task_id);
      // 3D: also deliver an answer to a question the agent asked via ask_operator.
      // The agent waits by heartbeating; this PEEKS (at-least-once) so a dropped
      // heartbeat self-heals on the next beat. The agent matches pending_answer.
      // query_id to its ask_operator query_id and acts on it once.
      const answered = engine.getAgentQueryStore().getAnswerForTask(task_id);
      if (answered) {
        engine.getAgentQueryStore().markDelivered(answered.query_id, task_id);
      }
      const pending_answer = answered
        ? { query_id: answered.query_id, question: answered.question, answer: answered.answer }
        : undefined;
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: true,
            task_id,
            agent_label: task.agent_label ?? task.agent_id,
            id: task.task_id ?? task.id,
            agent_id: task.agent_label ?? task.agent_id,
            heartbeat_at: task.heartbeat_at,
            heartbeat_ttl_seconds: task.heartbeat_ttl_seconds ?? 120,
            ...(acknowledged_query_id ? { acknowledged_query_id } : {}),
            ...(pending ? { pending_directive: pending } : {}),
            ...(pending_answer ? { pending_answer } : {}),
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
      const task = engine.getTask(task_id);
      if (!task) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ ok: false, error: `task not found: ${task_id}` }) }],
          isError: true,
        };
      }
      const taskLabel = task.agent_label ?? task.agent_id;
      if (agent_id && agent_id !== taskLabel) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ok: false,
              error: `agent_id "${agent_id}" does not match task ${task_id} (${taskLabel})`,
            }),
          }],
          isError: true,
        };
      }
      const query = engine.getAgentQueryStore().add({
        owner_task_id: task.task_id ?? task.id,
        owner_agent_label: taskLabel,
        question,
        options,
      });
      engine.logActionEvent({
        description: `Agent asked the operator: ${question}`,
        event_type: 'agent_query',
        category: 'agent',
        result_classification: 'neutral',
        agent_id: taskLabel,
        linked_agent_task_id: task_id,
        details: { reason: 'agent_query', query_id: query.query_id, question, options },
      });
      return {
        content: [{ type: 'text', text: JSON.stringify({
          ok: true,
          query_id: query.query_id,
          status: 'open',
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
      const task = engine.getTask(task_id);
      if (!task) {
        return { content: [{ type: 'text', text: JSON.stringify({ ok: false, error: `task not found: ${task_id}` }) }], isError: true };
      }
      // Directives are delivered on the agent's heartbeat, so only a running task
      // can ever receive one. Reject otherwise (mirrors the dashboard guard) so
      // we don't record directives that will never be delivered.
      if (task.status !== 'running') {
        return { content: [{ type: 'text', text: JSON.stringify({ ok: false, error: `task is not running (status: ${task.status}); directives are only delivered to running agents` }) }], isError: true };
      }
      const directive = engine.issueAgentDirective({ task_id, kind, node_ids, frontier_types, note, issued_by });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: true,
            directive,
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
      const directive = engine.acknowledgeAgentDirective(task_id, directive_id);
      if (!directive) {
        return { content: [{ type: 'text', text: JSON.stringify({ ok: false, error: 'directive not found' }) }], isError: true };
      }
      return { content: [{ type: 'text', text: JSON.stringify({ ok: true, directive }, null, 2) }] };
    }),
  );
}

// ============================================================
// Exported dispatch helper — used by both the MCP tool and the
// dashboard REST endpoint so the logic lives in one place.
// ============================================================

export interface DispatchResult {
  campaign_id: string;
  strategy: string;
  requested: number;
  total_items: number;
  dispatched: Array<{ task_id: string; agent_label: string; id: string; agent_id: string; frontier_item_id: string; scope_nodes: number; archetype: string; skill?: string }>;
  skipped: Array<{ frontier_item_id: string; reason: string }>;
  warning?: string;
  error?: string;
}

export function dispatchCampaignAgents(
  engine: GraphEngine,
  campaign_id: string,
  options: { max_agents?: number; hops?: number; skill?: string; archetype?: string } = {},
): DispatchResult {
  const max_agents = options.max_agents ?? 8;
  const hops = options.hops ?? 2;
  const skill = options.skill;
  const archetypeOverride = options.archetype;

  const campaign = engine.getCampaign(campaign_id);
  if (!campaign) {
    return { campaign_id, strategy: '', requested: max_agents, total_items: 0, dispatched: [], skipped: [], error: `Campaign not found: ${campaign_id}` };
  }

  if (campaign.status === 'paused' || campaign.status === 'aborted' || campaign.status === 'completed') {
    return { campaign_id, strategy: campaign.strategy, requested: max_agents, total_items: campaign.items.length, dispatched: [], skipped: [], error: `Campaign is ${campaign.status} — cannot dispatch agents` };
  }

  if (engine.getCampaignChildren(campaign_id).length > 0) {
    return {
      campaign_id,
      strategy: campaign.strategy,
      requested: max_agents,
      total_items: campaign.items.length,
      dispatched: [],
      skipped: [],
      error: 'Campaign has child campaigns — dispatch a child campaign instead',
    };
  }

  // F5: defer draft activation until at least one agent has been
  // successfully registered. Activating up front would mark the campaign
  // 'active' even when every dispatch attempt is skipped or refused —
  // operators then see a live campaign producing zero work.
  const wasDraft = campaign.status === 'draft';

  const dispatched: DispatchResult['dispatched'] = [];
  const skipped: DispatchResult['skipped'] = [];

  for (const itemId of campaign.items) {
    if (dispatched.length >= max_agents) break;

    // Skip items that already reached a terminal status in a prior dispatch.
    // Without this guard, calling dispatch_campaign_agents twice on the same
    // campaign re-issues completed work and can re-run scans / credential
    // checks that an earlier agent already finished.
    const itemStatus = campaign.item_status?.[itemId];
    if (itemStatus === 'succeeded' || itemStatus === 'failed') {
      skipped.push({ frontier_item_id: itemId, reason: `already_${itemStatus}` });
      continue;
    }

    const existing = engine.getRunningTaskForFrontierItem(itemId);
    if (existing) {
      skipped.push({ frontier_item_id: itemId, reason: `running_agent: ${existing.agent_id}` });
      continue;
    }

    const actionable = engine.getActionableFrontierItem(itemId);
    if (!actionable) {
      skipped.push({ frontier_item_id: itemId, reason: 'frontier_not_actionable' });
      continue;
    }

    const scope = computeCampaignScope(engine, campaign.strategy, itemId, hops);
    if (scope.length === 0 && actionable.type !== 'network_discovery') {
      skipped.push({ frontier_item_id: itemId, reason: 'frontier_unscoped' });
      continue;
    }

    const campaignArchetype = resolveDispatchArchetype(engine, {
      explicit: archetypeOverride,
      strategy: campaign.strategy,
      frontierItem: actionable,
    });
    const agent_id = `agent-campaign-${campaign.strategy.replace(/[^a-z]/g, '').slice(0, 6)}-${uuidv4().slice(0, 8)}`;
    const task = buildTask(agent_id, itemId, scope, skill, campaign_id, campaignArchetype);
    // F2: respect lease conflicts and don't claim success when the
    // task wasn't actually inserted.
    const reg = engine.registerAgent(task);
    if (!reg.ok) {
      skipped.push({
        frontier_item_id: itemId,
        reason: reg.cap_exceeded
          ? `dispatch_cap: ${reg.cap_exceeded.current}/${reg.cap_exceeded.limit} on ${reg.cap_exceeded.scope} ${reg.cap_exceeded.key}`
          : `frontier_lease_conflict${reg.lease_conflict ? `: held by task ${reg.lease_conflict.existing_task_id}` : ''}`,
      });
      continue;
    }

    dispatched.push({
      task_id: task.id,
      agent_label: agent_id,
      id: task.id,
      agent_id,
      frontier_item_id: itemId,
      scope_nodes: scope.length,
      archetype: campaignArchetype,
      skill,
    });
  }

  // F5: only activate the campaign once at least one agent is actually
  // running. If the dispatch produced nothing usable the campaign stays
  // 'draft' and the operator can investigate without a misleading
  // status badge in the dashboard.
  if (wasDraft && dispatched.length > 0) {
    engine.activateCampaign(campaign_id);
  }

  const result: DispatchResult = {
    campaign_id,
    strategy: campaign.strategy,
    requested: max_agents,
    total_items: campaign.items.length,
    dispatched,
    skipped,
  };
  if (dispatched.length === 0) {
    result.warning = 'No agents dispatched — all items were skipped';
  }
  return result;
}

function buildTask(agent_id: string, frontier_item_id: string | undefined, subgraph_node_ids: string[], skill?: string, campaign_id?: string, archetype?: string) {
  return {
    id: uuidv4(),
    agent_id,
    assigned_at: new Date().toISOString(),
    status: 'running' as const,
    frontier_item_id,
    campaign_id,
    subgraph_node_ids,
    skill,
    archetype,
  };
}

// Campaign strategy → the archetype whose tool surface + mission fit that
// strategy. (custom falls through to frontier-based recommendation.)
const STRATEGY_ARCHETYPE: Record<string, AgentArchetypeId> = {
  credential_spray: 'credential_operator',
  post_exploitation: 'post_exploit',
  enumeration: 'recon_scanner',
  network_discovery: 'recon_scanner',
};

/** Best-effort node type for a frontier item's seed, to sharpen archetype choice.
 * Reads the item's own node/edge handles (public) — enough for the cases
 * recommendArchetype keys on (webapp/url → web_tester, credential, host/service);
 * network_discovery has no seed node and resolves on frontier type alone. */
function frontierSeedNodeType(
  engine: GraphEngine,
  item?: { node_id?: string; target_node?: string; edge_target?: string; edge_source?: string } | null,
): string | undefined {
  const nodeId = item?.node_id || item?.target_node || item?.edge_target || item?.edge_source;
  return nodeId ? engine.getNode(nodeId)?.type : undefined;
}

/**
 * Pick the archetype for a dispatched task so the sub-agent gets the right tool
 * surface + mission instead of the full `default` surface. Precedence: an
 * explicit operator/agent override (if a known archetype) → a campaign
 * strategy's archetype → `recommendArchetype` over the frontier item type +
 * seed node type. Never throws; resolves to `default` only when nothing more
 * specific is known. (Backend resolution is unaffected — credential_test items
 * still run on the scripted runner; this only shapes the headless surface.)
 */
function resolveDispatchArchetype(engine: GraphEngine, opts: {
  explicit?: string;
  strategy?: string;
  frontierItem?: { type?: string; node_id?: string; target_node?: string; edge_target?: string; edge_source?: string } | null;
}): AgentArchetypeId {
  if (opts.explicit && isArchetypeId(opts.explicit)) return opts.explicit;
  if (opts.strategy && STRATEGY_ARCHETYPE[opts.strategy]) return STRATEGY_ARCHETYPE[opts.strategy];
  const nodeType = frontierSeedNodeType(engine, opts.frontierItem);
  return recommendArchetype({ frontierType: opts.frontierItem?.type as RecommendInput['frontierType'], nodeType });
}

/**
 * Compute subgraph scope for a campaign item using strategy-aware logic.
 */
function computeCampaignScope(
  engine: GraphEngine,
  strategy: string,
  frontierItemId: string,
  hops: number,
): string[] {
  if (strategy === 'credential_spray') {
    // Include the credential node, target service nodes, and their parent host nodes
    return computeSprayScope(engine, frontierItemId);
  }

  if (strategy === 'post_exploitation') {
    // Include the host and ALL directly connected nodes
    return computePostExploitScope(engine, frontierItemId);
  }

  // enumeration, network_discovery, custom: standard N-hop BFS
  return engine.computeSubgraphNodeIds(frontierItemId, hops);
}

function computeSprayScope(engine: GraphEngine, frontierItemId: string): string[] {
  const scope = new Set<string>();
  const graph = engine.exportGraph();

  // Resolve frontier item to get the edge endpoints
  // Spray targets are typically inferred_edge items (credential → service/host)
  const seeds = engine.computeSubgraphNodeIds(frontierItemId, 0);
  for (const s of seeds) scope.add(s);

  // Walk 1-hop from seeds: collect credentials, services, and their parent hosts
  for (const seed of seeds) {
    const nodeMap = new Map(graph.nodes.map(n => [n.id, n]));
    const node = nodeMap.get(seed);
    if (!node) continue;

    // Add the seed
    scope.add(seed);

    // Find edges involving this node
    for (const edge of graph.edges) {
      if (edge.source === seed || edge.target === seed) {
        const neighbor = edge.source === seed ? edge.target : edge.source;
        const neighborNode = nodeMap.get(neighbor);
        if (!neighborNode) continue;
        const ntype = neighborNode.properties.type;
        if (ntype === 'credential' || ntype === 'service' || ntype === 'host' || ntype === 'user') {
          scope.add(neighbor);
          // If service, also include parent host
          if (ntype === 'service') {
            for (const e2 of graph.edges) {
              if ((e2.source === neighbor || e2.target === neighbor) && e2.properties.type === 'RUNS') {
                scope.add(e2.source === neighbor ? e2.target : e2.source);
              }
            }
          }
        }
      }
    }
  }

  return [...scope];
}

function computePostExploitScope(engine: GraphEngine, frontierItemId: string): string[] {
  const scope = new Set<string>();
  const seeds = engine.computeSubgraphNodeIds(frontierItemId, 0);
  for (const s of seeds) scope.add(s);

  // Get ALL direct neighbors (1-hop, no limit on type)
  const allNodes = engine.computeSubgraphNodeIds(frontierItemId, 1);
  for (const n of allNodes) scope.add(n);

  return [...scope];
}
