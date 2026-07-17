import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentLifecycleCommandService } from '../services/agent-lifecycle-command-service.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerAgentTranscriptTool(
  server: McpServer,
  lifecycleCommands: AgentLifecycleCommandService,
): void {
  server.registerTool(
    'submit_agent_transcript',
    {
      title: 'Submit Agent Transcript',
      description: `Sub-agent wrap-up: hand the primary session a short summary plus an optional raw transcript blob.

Call this **before** \`update_agent(status: "completed")\`. The transcript (if provided) is stored in evidence and an \`agent_transcript_submitted\` event links it to the agent task so retrospective analysis can attribute reasoning back to the sub-agent.

Fields:
- \`summary\` is required — a paragraph or two describing what the agent did, what it found, and what (if anything) is left.
- \`transcript_jsonl\` is optional but strongly recommended — raw JSONL of the sub-agent's tool I/O.
- \`key_thought_event_ids\` / \`key_finding_ids\` are optional pointers to events/findings the primary should look at first.
- Planner workers set \`planner_outcome: "unexpressible"\` only when the operator command genuinely cannot map to an allowed operation.`,
      inputSchema: {
        task_id: z.string().optional().describe('Agent task ID this transcript belongs to (preferred). Returned by register_agent as `task_id`.'),
        agent_id: z.string().optional().describe('Agent task ID this transcript belongs to. Accepted as a legacy alias for `task_id`; a legacy agent label resolves only when exactly one task has that label.'),
        summary: z.string().min(1).describe('Short wrap-up paragraph from the sub-agent'),
        transcript_jsonl: z.string().optional().describe('Raw JSONL transcript of the sub-agent run (stored as evidence)'),
        key_thought_event_ids: z.array(z.string()).optional().describe('Event IDs of the most important thoughts/decisions'),
        key_finding_ids: z.array(z.string()).optional().describe('Finding IDs the primary should review first'),
        planner_outcome: z.literal('unexpressible').optional().describe('Planner-only structured conclusion when no allowed operation can represent the command'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('submit_agent_transcript', async ({
      task_id,
      agent_id,
      summary,
      transcript_jsonl,
      key_thought_event_ids,
      key_finding_ids,
      planner_outcome,
    }) => {
      const lookupId = task_id ?? agent_id;
      if (!lookupId) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            error: 'Either task_id or agent_id is required',
          }, null, 2) }],
          isError: true,
        };
      }
      const execution = lifecycleCommands.submitTranscript({
        task_reference: lookupId,
        summary,
        transcript_jsonl,
        key_thought_event_ids,
        key_finding_ids,
        planner_outcome,
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
