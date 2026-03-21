import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { nodeTypeSchema, edgeTypeSchema } from '../types.js';
import type { Finding, NodeType, EdgeType } from '../types.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerFindingTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: report_finding
  // Agents report discoveries here. Updates graph + runs inference.
  // ============================================================
  server.registerTool(
    'report_finding',
    {
      title: 'Report Finding',
      description: `Report a discovery from agent execution. This is how new information enters the graph.

Submit nodes (hosts, services, credentials, users, etc.) and edges (relationships between them).
The orchestrator will:
1. Add/update nodes and edges in the graph
2. Run inference rules to generate new hypothetical edges
3. Re-evaluate objectives
4. Persist state to disk

Always report findings as they occur — do not batch them. Interim reporting enables
reactive re-planning by the primary session.

Returns: Summary of what was added/updated and any new inferred edges.`,
      inputSchema: {
        agent_id: z.string().describe('ID of the reporting agent'),
        nodes: z.array(z.object({
          id: z.string().describe('Unique node ID, e.g. host-10-10-10-5, svc-10-10-10-5-445'),
          type: nodeTypeSchema,
          label: z.string().describe('Human-readable label'),
          properties: z.record(z.unknown()).optional().describe('Additional properties as key-value pairs')
        })).default([]).describe('New or updated nodes to add to the graph'),
        edges: z.array(z.object({
          source: z.string().describe('Source node ID'),
          target: z.string().describe('Target node ID'),
          type: edgeTypeSchema,
          confidence: z.number().min(0).max(1).default(1.0),
          properties: z.record(z.unknown()).optional()
        })).default([]).describe('New or updated edges'),
        evidence: z.object({
          type: z.enum(['screenshot', 'log', 'file', 'command_output']),
          content: z.string(),
          filename: z.string().optional()
        }).optional().describe('Supporting evidence'),
        raw_output: z.string().optional().describe('Raw command/tool output for logging')
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('report_finding', async ({ agent_id, nodes, edges, evidence, raw_output }) => {
      const finding: Finding = {
        id: uuidv4(),
        agent_id,
        timestamp: new Date().toISOString(),
        nodes: nodes.map(n => ({
          id: n.id,
          type: n.type as NodeType,
          label: n.label,
          ...n.properties
        })),
        edges: edges.map(e => ({
          source: e.source,
          target: e.target,
          properties: {
            type: e.type as EdgeType,
            confidence: e.confidence,
            ...e.properties
          }
        })),
        evidence,
        raw_output
      };

      const result = engine.ingestFinding(finding);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            finding_id: finding.id,
            new_nodes: result.new_nodes,
            new_edges: result.new_edges,
            inferred_edges: result.inferred_edges,
            message: `Ingested: ${result.new_nodes.length} new nodes, ${result.new_edges.length} new edges, ${result.inferred_edges.length} inferred edges`
          }, null, 2)
        }]
      };
    })
  );
}
