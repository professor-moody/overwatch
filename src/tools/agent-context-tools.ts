import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { isIpInCidr } from '../services/cidr.js';
import type { ActivityLogEntry } from '../services/engine-context.js';
import { taskWireIdentity } from './_agent-tool-shared.js';
import { withErrorBoundary } from './error-boundary.js';

interface PriorActionOnScope {
  action_id?: string;
  at: string;
  technique?: string;
  tool?: string;
  result?: string;
  targets: string[];
}

const PRIOR_ACTIONS_LIMIT = 25;
const PRIOR_ACTIONS_SCAN_CAP = 4000;

function collectPriorActions(
  engine: GraphEngine,
  match: (entry: ActivityLogEntry) => string[] | undefined,
): PriorActionOnScope[] {
  const out: PriorActionOnScope[] = [];
  const seen = new Set<string>();
  const history = engine.getFullHistory();
  const stop = Math.max(0, history.length - PRIOR_ACTIONS_SCAN_CAP);
  for (let index = history.length - 1; index >= stop && out.length < PRIOR_ACTIONS_LIMIT; index--) {
    const entry = history[index];
    if (entry.event_type !== 'action_completed' && entry.event_type !== 'action_failed') continue;
    const targets = match(entry);
    if (!targets || targets.length === 0) continue;
    if (entry.action_id) {
      if (seen.has(entry.action_id)) continue;
      seen.add(entry.action_id);
    }
    out.push({
      action_id: entry.action_id,
      at: entry.timestamp,
      technique: entry.technique,
      tool: entry.tool_name,
      result: entry.result_classification,
      targets,
    });
  }
  return out.reverse();
}

function buildPriorActionsOnScope(engine: GraphEngine, seedIds: string[]): PriorActionOnScope[] {
  if (seedIds.length === 0) return [];
  const scope = new Set(seedIds);
  return collectPriorActions(engine, entry => entry.target_node_ids?.filter(id => scope.has(id)));
}

function buildPriorActionsForCidr(
  engine: GraphEngine,
  cidr: string | undefined,
): PriorActionOnScope[] {
  if (!cidr) return [];
  return collectPriorActions(engine, entry => {
    const hits: string[] = [];
    if (entry.target_cidrs?.includes(cidr)) hits.push(cidr);
    for (const ip of entry.target_ips ?? []) {
      try {
        if (isIpInCidr(ip, cidr)) hits.push(ip);
      } catch {
        // Ignore malformed historic target data.
      }
    }
    return hits;
  });
}

export function registerAgentContextTool(server: McpServer, engine: GraphEngine): void {
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
        openWorldHint: false,
      },
    },
    withErrorBoundary('get_agent_context', async ({ task_id, hops }) => {
      const task = engine.getTask(task_id);
      if (!task) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Task not found: ${task_id}` }, null, 2) }],
          isError: true,
        };
      }

      const seedIds = task.subgraph_node_ids.length > 0
        ? task.subgraph_node_ids
        : task.frontier_item_id
          ? engine.computeSubgraphNodeIds(task.frontier_item_id, hops)
          : [];

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
            }, null, 2),
          }],
        };
      }

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
              prior_actions_on_scope: [],
              ...(adHoc
                ? { message: 'Ad-hoc deploy with no pre-seeded graph nodes — work from the objective (your target is named there) and the engagement scope; discover and report findings as you go.' }
                : { warning: `Frontier item ${task.frontier_item_id} no longer resolves to any graph nodes. The frontier may have changed since task registration. Report this to the primary session.` }),
            }, null, 2),
          }],
        };
      }

      const subgraph = engine.getSubgraphForAgent(seedIds, { hops });
      const priorActions = buildPriorActionsOnScope(engine, seedIds);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ...taskWireIdentity(task),
            frontier_item_id: task.frontier_item_id,
            skill: task.skill,
            archetype: task.archetype,
            objective: task.objective,
            subgraph,
            prior_actions_on_scope: priorActions,
            message: `Subgraph context: ${subgraph.nodes.length} nodes, ${subgraph.edges.length} edges; ${priorActions.length} prior action(s) already run on your scope — review them to avoid repeating work and to find the gaps still worth doing.`,
          }, null, 2),
        }],
      };
    }),
  );
}
