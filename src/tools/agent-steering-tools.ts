import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentLifecycleCommandService } from '../services/agent-lifecycle-command-service.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerAskOperatorTool(
  server: McpServer,
  lifecycleCommands: AgentLifecycleCommandService,
): void {
  server.registerTool(
    'ask_operator',
    {
      title: 'Ask the Operator',
      description: `Escalate a decision to the human operator and WAIT for their answer. Use this at a genuine fork you can't resolve yourself (ambiguous path, risky/irreversible step, missing context) — not for routine work.

After calling this, keep calling \`agent_heartbeat({ task_id })\`; when the operator answers, the heartbeat response carries \`pending_answer: { query_id, question, answer }\`. Read the answer, proceed, then acknowledge it on a later heartbeat with \`agent_heartbeat({ task_id, acknowledged_query_id: query_id })\`. If no answer arrives before your task times out, make the safest reasonable choice and note that you proceeded without an answer.`,
      inputSchema: {
        task_id: z.string().describe('Your agent task id'),
        agent_id: z.string().optional().describe('Your agent id (for attribution)'),
        question: z.string().describe('The question for the operator — be specific and self-contained'),
        options: z.array(z.string()).optional().describe('Optional suggested answers the operator can pick from'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('ask_operator', async ({ task_id, agent_id, question, options }) => {
      const execution = lifecycleCommands.askQuestion({
        task_id,
        agent_label: agent_id,
        question,
        options,
      }, { transport: 'mcp' });
      const query = execution.result!.query;
      return {
        content: [{ type: 'text', text: JSON.stringify({
          ok: true,
          query_id: query.query_id,
          status: 'open',
          command_id: execution.command_id,
          replayed: execution.replayed,
          note: 'Keep heartbeating; the answer arrives as pending_answer. After acting, acknowledge it with acknowledged_query_id on a later heartbeat.',
        }, null, 2) }],
      };
    }),
  );
}

export function registerManageAgentDirectiveTool(
  server: McpServer,
  lifecycleCommands: AgentLifecycleCommandService,
): void {
  server.registerTool(
    'manage_agent_directive',
    {
      title: 'Manage Agent Directive',
      description: `Steer a running sub-agent. Issues a directive delivered to the agent on its next \`agent_heartbeat\`.

Kinds:
- \`pause\` / \`resume\` — halt/continue the agent (it keeps heartbeating while paused).
- \`stop\` — wrap up and exit; the runtime kills the headless process and marks the task interrupted.
- \`narrow_scope\` — restrict the agent to \`node_ids\`.
- \`skip_types\` — ignore frontier items of \`frontier_types\`.
- \`prioritize\` — do \`frontier_types\` first.
- \`instruct\` — free-text steer: the operator's instruction in \`note\`; the agent reads and honors it on its next heartbeat (e.g. "focus on SMB", "try password spray instead").

A new directive supersedes any still-pending one for the task (latest instruction wins).`,
      inputSchema: {
        task_id: z.string().describe('Agent task ID to steer'),
        kind: z.enum(['pause', 'resume', 'stop', 'narrow_scope', 'skip_types', 'prioritize', 'instruct'])
          .describe('The steering action'),
        node_ids: z.array(z.string()).optional().describe('narrow_scope: node ids to restrict to'),
        frontier_types: z.array(z.string()).optional().describe('skip_types / prioritize: frontier item types'),
        note: z.string().optional().describe('instruct: the free-text instruction; otherwise an optional human-readable note'),
        issued_by: z.string().optional().describe('Operator id (defaults to "primary")'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('manage_agent_directive', async ({
      task_id,
      kind,
      node_ids,
      frontier_types,
      note,
      issued_by,
    }) => {
      const execution = lifecycleCommands.issueDirective({
        task_id,
        kind,
        node_ids,
        frontier_types,
        note,
        issued_by,
      }, { transport: 'mcp' });
      return {
        content: [{ type: 'text', text: JSON.stringify({
          ...execution.result,
          command_id: execution.command_id,
          replayed: execution.replayed,
          note: kind === 'stop'
            ? 'stop recorded — the task-execution service will kill the process and interrupt the task'
            : 'directive recorded — delivered to the agent on its next heartbeat',
        }, null, 2) }],
      };
    }),
  );
}

export function registerAcknowledgeAgentDirectiveTool(
  server: McpServer,
  lifecycleCommands: AgentLifecycleCommandService,
): void {
  server.registerTool(
    'acknowledge_agent_directive',
    {
      title: 'Acknowledge Agent Directive',
      description: `Sub-agents call this to confirm they received a steering directive (delivered via the \`pending_directive\` field on \`agent_heartbeat\`). After acknowledging, act on it: pause work, resume, narrow your scope, etc.`,
      inputSchema: {
        task_id: z.string().describe('Your agent task ID'),
        directive_id: z.string().describe('The directive id from agent_heartbeat.pending_directive'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('acknowledge_agent_directive', async ({ task_id, directive_id }) => {
      const execution = lifecycleCommands.acknowledgeDirective({
        task_id,
        directive_id,
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
