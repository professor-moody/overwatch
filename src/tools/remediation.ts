import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { GraphCorrectionOperationSchema } from '../contracts/dashboard-v1.js';
import { GraphCorrectionCommandService } from '../services/graph-correction-command-service.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerRemediationTools(
  server: McpServer,
  engine: GraphEngine,
  commands: Pick<
    GraphCorrectionCommandService,
    'correct'
  > = new GraphCorrectionCommandService(engine),
): void {
  server.registerTool(
    'correct_graph',
    {
      title: 'Correct Graph State',
      description: `Repair existing graph state explicitly and transactionally.

Use this for cleanup and remediation when the graph already contains bad data.
Supported operations:
- drop stale or invalid nodes, including as part of an atomic mixed correction
- drop stale or invalid edges
- replace an edge with the correct type/source/target
- patch node properties, including normalized credential fields

This is not a normal reporting path. Use report_finding and parse_output for new discoveries.`,
      inputSchema: {
        reason: z.string().trim().min(1).describe('Operator-provided reason for the correction batch.'),
        action_id: z.string().optional().describe('Action ID to link this correction back to the triggering workflow.'),
        operations: z.array(GraphCorrectionOperationSchema)
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
      const execution = commands.correct({
        reason,
        action_id,
        operations,
      }, {
        transport: 'mcp',
        action_id,
      });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            action_id,
            reason,
            ...execution.result,
            command_id: execution.command_id,
            idempotency_key: execution.idempotency_key,
            replayed: execution.replayed,
          }, null, 2),
        }],
      };
    }),
  );
}
