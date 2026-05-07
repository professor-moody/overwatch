// ============================================================
// Overwatch — explain_action MCP tool (P3.2)
//
// "Why did the agent do X?" Returns the frontier item that motivated
// the action, the log_thought chain on it, alternatives considered,
// prior actions referenced, validation/approval state, and final outcome.
// All derived from the activity log; read-only.
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerIntrospectionTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'explain_action',
    {
      title: 'Explain Action',
      description: `Returns the full "why" for any action_id: the frontier item that motivated it, the agent's recorded thoughts and considered alternatives, prior action references, validation and approval state, and the terminal outcome.

Use this to drill into a specific action when reviewing decisions in the dashboard or building a retrospective. The response references underlying activity log events by event_id; combine with \`get_history\` for raw event payloads.

Returns \`{found: false}\` when the action_id is unknown — the engine doesn't synthesize answers for actions that never happened.`,
      inputSchema: {
        action_id: z.string().describe('The action_id to explain (from any node/edge\'s discovered_by_action_id, or from a decision_log entry).'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('explain_action', async ({ action_id }) => {
      const explanation = engine.explainAction(action_id);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(explanation, null, 2),
        }],
        ...(explanation.found ? {} : { isError: true }),
      };
    }),
  );
}
