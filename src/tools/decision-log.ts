// ============================================================
// Overwatch — get_decision_log MCP tool (P3.1)
//
// Exposes the derived decision log from `services/decision-log.ts` as
// an MCP tool. Filters: frontier_item_id, action_id, agent_id, outcome,
// limit. The tool is read-only and side-effect-free.
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerDecisionLogTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'get_decision_log',
    {
      title: 'Get Decision Log',
      description: `Returns the derived decision log: each entry is one decision (frontier item or action) with its full chain of stages — frontier_emitted → agent_picked → log_thought → validated → approved/denied → started → completed/failed.

Use this to answer "what did the agent do and why?" Each decision entry references the underlying activity-log events by event_id (\`stages[i].details_ref\`); call \`get_history\` to drill into a specific stage's full payload.

All filters are optional; combining them ANDs the conditions. Default limit: 50.`,
      inputSchema: {
        frontier_item_id: z.string().optional().describe('Filter to decisions touching this frontier item'),
        action_id: z.string().optional().describe('Filter to a specific action_id'),
        agent_id: z.string().optional().describe('Filter to decisions made by this agent'),
        outcome: z.enum(['completed', 'failed', 'denied', 'dropped', 'open']).optional()
          .describe('Filter by terminal outcome'),
        limit: z.number().int().min(1).max(500).default(50)
          .describe('Maximum number of entries (newest first)'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('get_decision_log', async ({ frontier_item_id, action_id, agent_id, outcome, limit }) => {
      const decisions = engine.getDecisionLog({
        frontier_item_id,
        action_id,
        agent_id,
        outcome,
        limit,
      });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            count: decisions.length,
            decisions,
          }, null, 2),
        }],
      };
    }),
  );
}
