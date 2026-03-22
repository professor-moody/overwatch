import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { edgeTypeSchema } from '../types.js';
import { withErrorBoundary } from './error-boundary.js';

const graphCorrectionOperationSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('drop_edge'),
    source_id: z.string(),
    edge_type: edgeTypeSchema,
    target_id: z.string(),
  }),
  z.object({
    kind: z.literal('replace_edge'),
    source_id: z.string(),
    edge_type: edgeTypeSchema,
    target_id: z.string(),
    new_source_id: z.string().optional(),
    new_edge_type: edgeTypeSchema.optional(),
    new_target_id: z.string().optional(),
    confidence: z.number().min(0).max(1).optional(),
    properties: z.record(z.unknown()).optional(),
  }),
  z.object({
    kind: z.literal('patch_node'),
    node_id: z.string(),
    set_properties: z.record(z.unknown()).optional(),
    unset_properties: z.array(z.string()).optional(),
  }),
]);

export function registerRemediationTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'correct_graph',
    {
      title: 'Correct Graph State',
      description: `Repair existing graph state explicitly and transactionally.

Use this for cleanup and remediation when the graph already contains bad data.
Supported operations:
- drop stale or invalid edges
- replace an edge with the correct type/source/target
- patch node properties, including normalized credential fields

This is not a normal reporting path. Use report_finding and parse_output for new discoveries.`,
      inputSchema: {
        reason: z.string().describe('Operator-provided reason for the correction batch.'),
        action_id: z.string().optional().describe('Action ID to link this correction back to the triggering workflow.'),
        operations: z.array(graphCorrectionOperationSchema)
          .min(1)
          .describe('Transactional graph correction operations to apply.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('correct_graph', async ({ reason, action_id, operations }) => {
      const result = engine.correctGraph(reason, operations, action_id);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            action_id,
            reason,
            ...result,
          }, null, 2),
        }],
      };
    }),
  );
}
