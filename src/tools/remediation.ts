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

  server.registerTool(
    'promote_claim',
    {
      title: 'Promote a Claim',
      description: `Durably record an explicit operator/agent judgment about a node or edge's standing (claim lifecycle Phase 2b).

Use this to correct a mis-derived claim, or to record a verification/refutation outcome, so it survives across the engagement rather than being re-derived from signals each time. States:
- validated — actively tested and confirmed
- observed  — passively confirmed
- exploited — exploitation confirmed
- refuted   — tested and disproven
- stale     — was true but has decayed

refuted/stale are authoritative (they override any derived positive); observed/validated set a floor a stronger real signal (an actual exploitation) can still raise. Objective and path evaluation honor the promotion: path-finding stops routing through a refuted access edge immediately, and a validated promotion can complete a not-yet-achieved objective. Target exactly one of node_id or edge_id.`,
      inputSchema: {
        state: z.enum(['observed', 'validated', 'exploited', 'refuted', 'stale'])
          .describe('The promoted standing.'),
        reason: z.string().trim().min(1)
          .describe('Why — the judgment behind this promotion; required for auditability.'),
        node_id: z.string().optional().describe('Target node id (exactly one of node_id / edge_id).'),
        edge_id: z.string().optional().describe('Target edge id (exactly one of node_id / edge_id).'),
        agent_id: z.string().optional()
          .describe('If an agent is promoting, its id (attributes the promotion to that agent); omit for an operator.'),
        valid_until: z.string().optional()
          .describe('Optional ISO timestamp after which the claim decays to stale.'),
        action_id: z.string().optional().describe('Action ID to link this promotion back to the triggering workflow.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        // NOT idempotent: each call restamps the promotion's `at` and emits a fresh
        // claim_promoted event, and the merge/audit/reconcile are separate durable writes. A
        // transactional, dedup-keyed command service is the tracked follow-up.
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('promote_claim', async ({ state, reason, node_id, edge_id, agent_id, valid_until, action_id }) => {
      if ((node_id ? 1 : 0) + (edge_id ? 1 : 0) !== 1) {
        throw new Error('promote_claim requires exactly one of node_id or edge_id');
      }
      const result = engine.promoteClaim({
        node_id,
        edge_id,
        state,
        reason,
        by_kind: agent_id ? 'agent' : 'operator',
        by: agent_id,
        valid_until,
        action_id,
      });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }),
  );
}
