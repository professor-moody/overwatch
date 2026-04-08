import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { nodeTypeSchema, edgeTypeSchema } from '../types.js';
import type { NodeType, EdgeType } from '../types.js';
import { withErrorBoundary } from './error-boundary.js';

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

Use structured selectors to explore relationships the frontier might not surface:
- \`{ "node_type": "credential" }\`
- \`{ "node_type": "credential", "node_filter": { "privileged": true } }\`
- \`{ "from_node": "host-10-10-10-10", "max_depth": 3 }\`
- \`{ "edge_type": "ESC8" }\`
- \`{ "node_type": "host", "node_filter": { "unconstrained_delegation": true } }\`

This tool gives you the FULL graph — no filtering, no scoring. Use it when the frontier
items don't capture a pattern you're seeing, or when you want to reason about the
graph structure directly.

You can query by node type, filter by properties, traverse from a specific node,
filter edges by type, or combine these. Results include full properties.

Use structured selectors — free-text query payloads are not supported.`,
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
    withErrorBoundary('query_graph', async (params) => {
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
    })
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
        max_paths: z.number().int().min(1).max(20).default(5),
        optimize: z.enum(['confidence', 'stealth', 'balanced']).default('confidence').describe('Path optimization strategy: confidence (default) picks highest-confidence paths, stealth picks lowest-noise paths, balanced weighs both equally')
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('find_paths', async ({ objective_id, from_node, to_node, max_paths, optimize }) => {
      let paths;
      if (objective_id) {
        paths = engine.findPathsToObjective(objective_id, max_paths, optimize);
      } else if (from_node && to_node) {
        paths = engine.findPaths(from_node, to_node, max_paths, optimize);
      } else if (from_node && !to_node) {
        const state = engine.getState();
        const unachieved = state.objectives.filter(o => !o.achieved);
        if (unachieved.length === 0) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: 'No unachieved objectives to path toward. Provide both from_node and to_node for point-to-point paths.' }, null, 2) }],
            isError: true,
          };
        }
        paths = [];
        for (const obj of unachieved) {
          const targetNodes = engine.queryGraph({ node_type: obj.target_node_type, node_filter: obj.target_criteria }).nodes.map(n => n.id);
          for (const tn of targetNodes) {
            const objPaths = engine.findPaths(from_node, tn, max_paths, optimize);
            paths.push(...objPaths.map(p => ({ ...p, objective: obj.description })));
          }
        }
      } else {
        const state = engine.getState();
        paths = [];
        for (const obj of state.objectives.filter(o => !o.achieved)) {
          const objPaths = engine.findPathsToObjective(obj.id, max_paths, optimize);
          paths.push(...objPaths.map(p => ({ ...p, objective: obj.description })));
        }
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ paths_found: paths.length, paths }, null, 2)
        }]
      };
    })
  );
}
