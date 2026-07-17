import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentLifecycleCommandService } from '../services/agent-lifecycle-command-service.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerUpdateAgentTool(
  server: McpServer,
  lifecycleCommands: AgentLifecycleCommandService,
): void {
  server.registerTool(
    'update_agent',
    {
      title: 'Update Agent Status',
      description: 'Update the status of a running agent task. Call when an agent completes or fails.',
      inputSchema: {
        task_id: z.string().describe('Task ID to update'),
        status: z.enum(['completed', 'failed']).describe('New status'),
        summary: z.string().optional().describe('Brief summary of results or failure reason'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('update_agent', async ({ task_id, status, summary }) => {
      const execution = lifecycleCommands.updateStatus({
        task_id,
        status,
        summary,
      }, { transport: 'mcp' });
      return {
        content: [{ type: 'text', text: JSON.stringify({
          ...execution.result,
          command_id: execution.command_id,
          replayed: execution.replayed,
        }, null, 2) }],
      };
    }),
  );
}

export function registerAgentHeartbeatTool(
  server: McpServer,
  lifecycleCommands: AgentLifecycleCommandService,
): void {
  server.registerTool(
    'agent_heartbeat',
    {
      title: 'Agent Heartbeat',
      description: `Sub-agents call this periodically (recommended every 30–60 seconds) to signal liveness.

The runtime watchdog will mark agents as "interrupted" if their last heartbeat is older than \`heartbeat_ttl_seconds\` (default 120s). Agents that never heartbeat are exempt — tools that complete in a single MCP turn don't need to call this.

Returns the new heartbeat timestamp on success, or an error if the task is unknown / already in a terminal state.`,
      inputSchema: {
        task_id: z.string().describe('Task ID returned from register_agent'),
        acknowledged_query_id: z.string().optional().describe('Answer query_id already received and acted on; stops redelivery.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('agent_heartbeat', async ({ task_id, acknowledged_query_id }) => {
      const execution = lifecycleCommands.heartbeat({
        task_id,
        acknowledged_query_id,
      }, { transport: 'mcp' });
      return {
        content: [{ type: 'text', text: JSON.stringify({
          ...execution.result,
          command_id: execution.command_id,
          replayed: execution.replayed,
        }, null, 2) }],
      };
    }),
  );
}
