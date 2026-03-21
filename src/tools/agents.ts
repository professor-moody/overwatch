import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

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
        agent_id: z.string().describe('Unique identifier for the agent'),
        frontier_item_id: z.string().describe('ID of the frontier item this agent should work on'),
        subgraph_node_ids: z.array(z.string()).describe('Node IDs relevant to this agent\'s task'),
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
      const task = {
        id: uuidv4(),
        agent_id,
        assigned_at: new Date().toISOString(),
        status: 'running' as const,
        frontier_item_id,
        subgraph_node_ids,
        skill
      };
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
        idempotentHint: true,
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
}
