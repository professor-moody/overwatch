import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

const actionEventTypeSchema = z.enum([
  'action_planned',
  'action_started',
  'action_completed',
  'action_failed',
]);

const resultClassificationSchema = z.enum(['success', 'failure', 'partial', 'neutral']);

export function registerLoggingTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'log_action_event',
    {
      title: 'Log Action Event',
      description: `Record a structured action lifecycle event for work Overwatch cannot observe directly.

Use this to tie together:
- what Claude planned
- what tool actually ran
- which targets were involved
- whether the action completed or failed
- what later findings should be attributed back to the action

Recommended flow:
1. \`action_planned\` before major execution
2. \`action_started\` when a real tool launches
3. \`action_completed\` or \`action_failed\` when the action resolves`,
      inputSchema: {
        action_id: z.string().optional().describe('Stable action ID. Required for non-planned events.'),
        event_type: actionEventTypeSchema.describe('Lifecycle event to record.'),
        description: z.string().optional().describe('Human-readable description of the action event. Auto-defaults from event_type if omitted.'),
        agent_id: z.string().optional().describe('Agent or session responsible for the action.'),
        tool_name: z.string().optional().describe('Tool actually used, e.g. nmap, nxc, bloodhound-python.'),
        technique: z.string().optional().describe('Technique category, e.g. password-spray, smb-enum.'),
        target_node_ids: z.array(z.string()).default([]).describe('Primary graph node IDs targeted by this action.'),
        target_ips: z.array(z.string()).optional().describe('Raw IP addresses targeted (pre-discovery, when no graph node exists yet).'),
        frontier_item_id: z.string().optional().describe('Frontier item this action came from, if applicable.'),
        linked_agent_task_id: z.string().optional().describe('Associated agent task ID when this action belongs to a sub-agent.'),
        result_classification: resultClassificationSchema.optional().describe('Outcome classification for completed or failed actions.'),
        details: z.record(z.unknown()).optional().describe('Additional structured context for the action event.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('log_action_event', async ({
      action_id,
      event_type,
      description,
      agent_id,
      tool_name,
      technique,
      target_node_ids,
      target_ips,
      frontier_item_id,
      linked_agent_task_id,
      result_classification,
      details,
    }) => {
      if (event_type !== 'action_planned' && !action_id) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: 'action_id is required for non-planned action events' }, null, 2),
          }],
          isError: true,
        };
      }

      const normalizedActionId = action_id || uuidv4();
      const defaultDescriptions: Record<string, string> = {
        action_planned: 'Action planned',
        action_started: 'Action started',
        action_completed: 'Action completed',
        action_failed: 'Action failed',
      };
      const resolvedDescription = description || defaultDescriptions[event_type] || event_type;
      const frontierType = frontier_item_id ? engine.getFrontierItem(frontier_item_id)?.type : undefined;
      const event = engine.logActionEvent({
        description: resolvedDescription,
        agent_id,
        action_id: normalizedActionId,
        event_type,
        category: 'frontier',
        frontier_type: frontierType,
        tool_name,
        technique,
        target_node_ids: target_node_ids.length > 0 ? target_node_ids : undefined,
        target_ips,
        frontier_item_id,
        linked_agent_task_id,
        result_classification,
        details,
      });
      engine.persist();

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            event_id: event.event_id,
            action_id: normalizedActionId,
            event_type: event.event_type,
            frontier_type: event.frontier_type,
            tool_name: event.tool_name,
            result_classification: event.result_classification,
          }, null, 2),
        }],
      };
    }),
  );
}
