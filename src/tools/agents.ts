import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { isIpInCidr } from '../services/cidr.js';

export function registerAgentTools(server: McpServer, engine: GraphEngine): void {
  const FRONTIER_TYPES = ['incomplete_node', 'untested_edge', 'inferred_edge', 'network_discovery', 'network_pivot'] as const;

  function buildTask(agent_id: string, frontier_item_id: string, subgraph_node_ids: string[], skill?: string) {
    return {
      id: uuidv4(),
      agent_id,
      assigned_at: new Date().toISOString(),
      status: 'running' as const,
      frontier_item_id,
      subgraph_node_ids,
      skill,
    };
  }

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
        agent_id: z.string().describe('Unique identifier for the agent'),
        frontier_item_id: z.string().describe('ID of the frontier item this agent should work on'),
        subgraph_node_ids: z.array(z.string()).default([]).describe('Optional node IDs relevant to this agent\'s task. Leave empty to auto-compute from the frontier item.'),
        skill: z.string().optional().describe('Skill/methodology to apply')
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('register_agent', async ({ agent_id, frontier_item_id, subgraph_node_ids, skill }) => {
      const existing = engine.getRunningTaskForFrontierItem(frontier_item_id);
      if (existing) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              task_id: existing.id,
              agent_id: existing.agent_id,
              status: existing.status,
              skipped_existing: true,
              message: `A running agent is already assigned to ${frontier_item_id}`,
            }, null, 2)
          }]
        };
      }

      const task = buildTask(agent_id, frontier_item_id, subgraph_node_ids || [], skill);
      engine.registerAgent(task);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            task_id: task.id,
            agent_id,
            status: 'running',
            message: `Agent ${agent_id} registered for task ${frontier_item_id}`
          }, null, 2)
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
        hops: z.number().int().min(1).max(5).default(2).describe('Hops to use when auto-computing subgraph scope'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      }
    },
    withErrorBoundary('dispatch_agents', async ({ count, strategy, types, skill, hops }) => {
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
      const dispatched: Array<{ task_id: string; agent_id: string; frontier_item_id: string; frontier_type: string; skill?: string }> = [];
      const skipped_existing: Array<{ frontier_item_id: string; task_id: string; agent_id: string }> = [];
      const skipped_unscoped: Array<{ frontier_item_id: string; frontier_type: string }> = [];

      for (const item of candidates) {
        if (dispatched.length >= count) break;

        const existing = engine.getRunningTaskForFrontierItem(item.id);
        if (existing) {
          skipped_existing.push({
            frontier_item_id: item.id,
            task_id: existing.id,
            agent_id: existing.agent_id,
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

        const agent_id = `agent-${item.type.replace(/[^a-z]/g, '').slice(0, 6)}-${uuidv4().slice(0, 8)}`;
        const task = buildTask(agent_id, item.id, scope, skill);
        engine.registerAgent(task);
        dispatched.push({
          task_id: task.id,
          agent_id: task.agent_id,
          frontier_item_id: item.id,
          frontier_type: item.type,
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

      // Auto-compute subgraph if no explicit node IDs were provided
      const seedIds = task.subgraph_node_ids.length > 0
        ? task.subgraph_node_ids
        : engine.computeSubgraphNodeIds(task.frontier_item_id, hops);

      // For network_discovery tasks with no backing nodes, return CIDR + scope context
      if (seedIds.length === 0 && task.frontier_item_id.startsWith('frontier-discovery-')) {
        const frontierItem = engine.getFrontierItem(task.frontier_item_id);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              task_id: task.id,
              agent_id: task.agent_id,
              frontier_item_id: task.frontier_item_id,
              skill: task.skill,
              discovery_context: {
                target_cidr: frontierItem?.target_cidr,
                scope: engine.getState().config.scope,
              },
              subgraph: { nodes: [], edges: [] },
              message: `Network discovery task for ${frontierItem?.target_cidr || 'unknown CIDR'}`,
            }, null, 2)
          }]
        };
      }

      const subgraph = engine.getSubgraphForAgent(seedIds, { hops });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            task_id: task.id,
            agent_id: task.agent_id,
            frontier_item_id: task.frontier_item_id,
            skill: task.skill,
            subgraph,
            message: `Subgraph context: ${subgraph.nodes.length} nodes, ${subgraph.edges.length} edges`
          }, null, 2)
        }]
      };
    })
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
      const updated = engine.updateAgentStatus(task_id, status, summary);
      if (!updated) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: `Task not found: ${task_id}` }, null, 2)
          }],
          isError: true
        };
      }
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ task_id, status, summary, updated: true }, null, 2)
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
      const dispatched: Array<{ task_id: string; agent_id: string; cidr: string; existing_nodes: number; skill: string }> = [];
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

        const agent_id = `agent-subnet-${slug}-${uuidv4().slice(0, 8)}`;
        const task = buildTask(agent_id, frontierItemId, nodesInCidr, skill);
        engine.registerAgent(task);

        dispatched.push({
          task_id: task.id,
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
}
