import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import {
  PlaybookRunError,
  PlaybookRunService,
} from '../services/playbook-run-service.js';
import { PlaybookCommandService } from '../services/playbook-command-service.js';
import { withErrorBoundary } from './error-boundary.js';

const statusSchema = z.enum([
  'pending',
  'blocked',
  'awaiting_approval',
  'running',
  'succeeded',
  'failed',
  'interrupted',
  'skipped',
  'cancelled',
]);

function response(value: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] };
}

function runError(error: unknown) {
  if (!(error instanceof PlaybookRunError)) throw error;
  return {
    ...response({ error: error.message, code: error.code }),
    isError: true,
  };
}

export function registerPlaybookRunTools(server: McpServer, engine: GraphEngine): void {
  const service = new PlaybookRunService(engine);
  const commands = new PlaybookCommandService(engine);

  server.registerTool(
    'list_playbook_runs',
    {
      title: 'List Playbook Runs',
      description: 'List durable credential-playbook runs, their step states, and append-only attempts.',
      inputSchema: {
        credential_id: z.string().min(1).optional(),
        status: statusSchema.optional(),
        open_only: z.boolean().default(false),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('list_playbook_runs', async params => {
      const runs = service.list(params);
      return response({ runs, total: runs.length });
    }),
  );

  server.registerTool(
    'get_playbook_run',
    {
      title: 'Get Playbook Run',
      description: 'Inspect one durable credential-playbook run, including every retained plan revision and attempt.',
      inputSchema: { run_id: z.string().min(1) },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('get_playbook_run', async ({ run_id }) => {
      try {
        return response({ run: service.get(run_id) });
      } catch (error) {
        return runError(error);
      }
    }),
  );

  server.registerTool(
    'start_playbook_step',
    {
      title: 'Start Playbook Step',
      description: `Reserve exactly one ready playbook step and return its resolved execution descriptor.

Pass the returned playbook_run_id, playbook_step_id, and playbook_attempt_id
through the indicated runner. Only one attempt may be active in a run.`,
      inputSchema: { run_id: z.string().min(1), step_id: z.string().min(1), task_id: z.string().min(1).optional() },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    withErrorBoundary('start_playbook_step', async ({ run_id, step_id }) => {
      try {
        return response(commands.start(run_id, step_id));
      } catch (error) {
        return runError(error);
      }
    }),
  );

  server.registerTool(
    'resume_playbook_run',
    {
      title: 'Resume Playbook Run',
      description: 'Re-open interrupted steps after restart. This never rewrites or extends prior attempts.',
      inputSchema: { run_id: z.string().min(1), task_id: z.string().min(1).optional() },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('resume_playbook_run', async ({ run_id }) => {
      try {
        return response({ run: commands.resume(run_id) });
      } catch (error) {
        return runError(error);
      }
    }),
  );

  server.registerTool(
    'retry_playbook_step',
    {
      title: 'Retry Playbook Step',
      description: 'Append a new attempt for a failed or interrupted step and return its resolved execution descriptor.',
      inputSchema: { run_id: z.string().min(1), step_id: z.string().min(1), task_id: z.string().min(1).optional() },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    withErrorBoundary('retry_playbook_step', async ({ run_id, step_id }) => {
      try {
        return response(commands.retry(run_id, step_id));
      } catch (error) {
        return runError(error);
      }
    }),
  );

  server.registerTool(
    'skip_playbook_step',
    {
      title: 'Skip Playbook Step',
      description: 'Skip one non-terminal step while retaining the reason and every prior attempt.',
      inputSchema: {
        run_id: z.string().min(1),
        step_id: z.string().min(1),
        task_id: z.string().min(1).optional(),
        reason: z.string().max(2_000).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('skip_playbook_step', async ({ run_id, step_id, reason }) => {
      try {
        return response({ run: commands.skip(run_id, step_id, reason) });
      } catch (error) {
        return runError(error);
      }
    }),
  );

  server.registerTool(
    'interrupt_playbook_attempt',
    {
      title: 'Interrupt Playbook Attempt',
      description: 'Release an active step claim that will not be executed or completed. The retained attempt becomes interrupted and can be retried.',
      inputSchema: {
        run_id: z.string().min(1),
        step_id: z.string().min(1),
        task_id: z.string().min(1).optional(),
        reason: z.string().max(2_000).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('interrupt_playbook_attempt', async ({ run_id, step_id, reason }) => {
      try {
        return response({ run: commands.interrupt(run_id, step_id, reason) });
      } catch (error) {
        return runError(error);
      }
    }),
  );

  server.registerTool(
    'complete_playbook_attempt',
    {
      title: 'Complete Playbook Attempt',
      description: 'Record the durable outcome and evidence/finding references for a claimed playbook attempt.',
      inputSchema: {
        run_id: z.string().min(1),
        step_id: z.string().min(1),
        attempt_id: z.string().min(1),
        task_id: z.string().min(1).optional(),
        execution_outcome: z.enum(['succeeded', 'failed', 'interrupted']),
        parse_outcome: z.enum(['ok', 'no_data', 'validation_failed', 'parser_exception', 'partial']).optional(),
        action_id: z.string().min(1).optional(),
        evidence_ids: z.array(z.string().min(1)).default([]),
        finding_ids: z.array(z.string().min(1)).default([]),
        error: z.string().max(8_000).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('complete_playbook_attempt', async params => {
      try {
        return response({
          run: service.finishAttempt(params.run_id, params.step_id, params.attempt_id, params),
        });
      } catch (error) {
        return runError(error);
      }
    }),
  );
}
