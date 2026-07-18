import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  AgentHandoffRequestSchema,
  AgentMergeRequestSchema,
  AgentSplitRequestSchema,
} from '../contracts/dashboard-v1.js';
import type { AgentWorkCommandService } from '../services/agent-work-command-service.js';
import { toolText } from './_tool-output.js';
import { withErrorBoundary } from './error-boundary.js';

const CommandMetadataShape = {
  command_id: z.string().trim().min(1).optional()
    .describe('Stable application-command ID for correlation and safe retries.'),
  idempotency_key: z.string().trim().min(1).optional()
    .describe('Stable retry key. Identical retries return the original durable result.'),
  retry_token: z.string().trim().min(1).optional()
    .describe('Opaque retry token returned by an earlier invocation whose response was lost.'),
};

function mutationResult<T>(execution: {
  command_id: string;
  idempotency_key: string;
  retry_token: string;
  replayed: boolean;
  result?: T;
}) {
  return toolText({
    ...execution.result,
    command_id: execution.command_id,
    idempotency_key: execution.idempotency_key,
    retry_token: execution.retry_token,
    replayed: execution.replayed,
  });
}

/** MCP adapters for durable future-work shaping. All mutations delegate to the
 * transport-neutral AgentWorkCommandService; this module owns schemas and wire
 * formatting only. */
export function registerAgentWorkTools(
  server: McpServer,
  commands: Pick<
    AgentWorkCommandService,
    'findDuplicates' | 'handoff' | 'split' | 'merge'
  >,
): void {
  server.registerTool(
    'find_duplicate_agent_work',
    {
      title: 'Find Duplicate Agent Work',
      description: `Find groups of agent tasks that have the same canonical work signature.

This is an exact, conservative comparison of scope, frontier/campaign linkage,
agent type, role, skill, and objective. It does not mutate or hide any task.
This fleet-wide inspection is restricted to the operator or an orchestrator task.`,
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('find_duplicate_agent_work', async () =>
      toolText(commands.findDuplicates())),
  );

  server.registerTool(
    'handoff_agent_work',
    {
      title: 'Handoff Agent Work',
      description: `Create one durable successor for a terminal agent task.

Cancel or otherwise finish the source task and wait for its runtime resources to
settle before calling this tool. Historical evidence, findings, transcripts,
approvals, sessions, and process ownership remain attributed to the source task.`,
      inputSchema: {
        source_task_id: z.string().trim().min(1).describe('Terminal source task to hand off.'),
        ...AgentHandoffRequestSchema.shape,
        ...CommandMetadataShape,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('handoff_agent_work', async ({
      source_task_id,
      command_id,
      idempotency_key,
      retry_token,
      ...body
    }) => mutationResult(commands.handoff(source_task_id, body, {
      transport: 'mcp',
      command_id,
      idempotency_key,
      retry_token,
    }))),
  );

  server.registerTool(
    'split_agent_work',
    {
      title: 'Split Agent Work',
      description: `Split one terminal ad-hoc node task into two to twenty durable child tasks.

Child node scopes must be non-empty, pairwise disjoint, and together cover the
source scope exactly. PR9 deliberately rejects frontier- or campaign-linked
sources so split work cannot duplicate a live lease or campaign assignment.`,
      inputSchema: {
        source_task_id: z.string().trim().min(1).describe('Terminal ad-hoc node task to split.'),
        ...AgentSplitRequestSchema.shape,
        ...CommandMetadataShape,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('split_agent_work', async ({
      source_task_id,
      command_id,
      idempotency_key,
      retry_token,
      ...body
    }) => mutationResult(commands.split(source_task_id, body, {
      transport: 'mcp',
      command_id,
      idempotency_key,
      retry_token,
    }))),
  );

  server.registerTool(
    'merge_duplicate_agent_work',
    {
      title: 'Merge Duplicate Agent Work',
      description: `Mark terminal exact-duplicate agent tasks as merged into one canonical task.

The command never deletes or relabels historical task artifacts. Every duplicate
must have the canonical task's exact server-derived work signature and own no
live runtime resources.`,
      inputSchema: {
        canonical_task_id: z.string().trim().min(1).describe('Task retained as the canonical work item.'),
        ...AgentMergeRequestSchema.shape,
        ...CommandMetadataShape,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('merge_duplicate_agent_work', async ({
      canonical_task_id,
      command_id,
      idempotency_key,
      retry_token,
      ...body
    }) => mutationResult(commands.merge(canonical_task_id, body, {
      transport: 'mcp',
      command_id,
      idempotency_key,
      retry_token,
    }))),
  );
}
