import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { nodeTypeSchema, edgeTypeSchema } from '../types.js';
import type { NodeType, EdgeType } from '../types.js';

export function registerExplorationTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: query_graph
  // Full graph access for the LLM — explore any path, any relationship.
  // ============================================================
  server.registerTool(
    'query_graph',
    {
      title: 'Query Graph',
      description: `Direct access to the engagement graph for open-ended analysis.

Use this to explore relationships the frontier might not surface:
- "Show me all credentials and what services they're valid on"
- "What's connected to host X within 3 hops?"
- "Find all ADCS-related edges"
- "Show me every node with unconstrained delegation"
- "What paths exist from my current access to the domain controller?"

This tool gives you the FULL graph — no filtering, no scoring. Use it when the frontier
items don't capture a pattern you're seeing, or when you want to reason about the
graph structure directly.

You can query by node type, filter by properties, traverse from a specific node,
filter edges by type, or combine these. Results include full properties.`,
      inputSchema: {
        node_type: nodeTypeSchema
          .optional().describe('Filter nodes by type'),
        node_filter: z.record(z.unknown())
          .optional().describe('Filter nodes by property values, e.g. {"service_name": "smb", "smb_signing": false}'),
        edge_type: edgeTypeSchema
          .optional().describe('Filter edges by type'),
        edge_filter: z.record(z.unknown())
          .optional().describe('Filter edges by property values'),
        from_node: z.string()
          .optional().describe('Start traversal from this node ID'),
        direction: z.enum(['outbound', 'inbound', 'both'])
          .default('both').describe('Traversal direction from from_node'),
        max_depth: z.number().int().min(1).max(10)
          .default(2).describe('Max traversal depth from from_node'),
        limit: z.number().int().min(1).max(500)
          .default(100).describe('Max results to return')
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      const result = engine.queryGraph({
        node_type: params.node_type as NodeType | undefined,
        node_filter: params.node_filter,
        edge_type: params.edge_type as EdgeType | undefined,
        edge_filter: params.edge_filter,
        from_node: params.from_node,
        direction: params.direction,
        max_depth: params.max_depth,
        limit: params.limit
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            nodes_found: result.nodes.length,
            edges_found: result.edges.length,
            ...result
          }, null, 2)
        }]
      };
    }
  );

  // ============================================================
  // Tool: find_paths
  // Shortest path analysis between nodes or to objectives.
  // ============================================================
  server.registerTool(
    'find_paths',
    {
      title: 'Find Attack Paths',
      description: `Find paths through the graph from current access to objectives or between specific nodes.

Use this to:
- Find the shortest path from compromised hosts to an objective
- Evaluate if a newly discovered credential opens a path
- Compare multiple potential attack routes by confidence

Returns paths with per-hop confidence scores and total path confidence.`,
      inputSchema: {
        objective_id: z.string().optional().describe('Find paths to this objective node'),
        from_node: z.string().optional().describe('Find paths from this specific node'),
        to_node: z.string().optional().describe('Find paths to this specific node'),
        max_paths: z.number().int().min(1).max(20).default(5)
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async ({ objective_id, from_node, to_node, max_paths }) => {
      let paths;
      if (objective_id) {
        paths = engine.findPathsToObjective(objective_id, max_paths);
      } else if (from_node && to_node) {
        paths = engine.findPaths(from_node, to_node, max_paths);
      } else {
        // Find paths to all active objectives
        const state = engine.getState();
        paths = [];
        for (const obj of state.objectives.filter(o => !o.achieved)) {
          const objPaths = engine.findPathsToObjective(obj.id, max_paths);
          paths.push(...objPaths.map(p => ({ ...p, objective: obj.description })));
        }
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ paths_found: paths.length, paths }, null, 2)
        }]
      };
    }
  );
}
