import { z } from 'zod';
import type { PersistedDurablePlaybookRunV1 } from './persisted-state.js';
import type { GraphEngine } from './graph-engine.js';
import {
  ApplicationCommandService,
  type ApplicationCommandExecution,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import {
  PlaybookRunError,
  PlaybookRunService,
  type OpenPlaybookInput,
  type PlaybookStepClaim,
} from './playbook-run-service.js';

const DefinitionSchema = z.object({
  definition_id: z.string().min(1),
  definition_version: z.number().int().positive(),
  provider: z.enum(['aws', 'github', 'entra', 'oidc']),
  title: z.string().min(1),
}).strict();

const OpenSchema = z.object({
  definition: DefinitionSchema,
  credential_id: z.string().min(1),
  normalized_inputs: z.record(z.unknown()),
  steps: z.array(z.record(z.unknown())),
  new_run: z.boolean().optional(),
}).strict();

const StepSchema = z.object({
  run_id: z.string().min(1),
  step_id: z.string().min(1),
}).strict();

const RunSchema = z.object({ run_id: z.string().min(1) }).strict();
const StepReasonSchema = StepSchema.extend({ reason: z.string().max(2_000).optional() }).strict();

type OpenResult = { run: PersistedDurablePlaybookRunV1; created: boolean };

/** Transport-neutral, idempotent command facade for durable playbook state.
 * The run service owns domain rules; this facade stores the original result so
 * a retried HTTP/MCP/CLI command never creates a second claim or new run. */
export class PlaybookCommandService {
  private readonly runs: PlaybookRunService;
  private readonly commands: ApplicationCommandService;

  constructor(engine: GraphEngine) {
    this.runs = new PlaybookRunService(engine, false);
    this.commands = new ApplicationCommandService(engine);
  }

  open(input: OpenPlaybookInput, metadata: ApplicationCommandMetadata = {}): OpenResult {
    return this.resultAndPublish(this.commands.executeSync({
      command_kind: 'playbook.open',
      input,
      schema: OpenSchema,
      metadata,
      state_keys: ['playbook_runs'],
      execute: parsed => this.runs.open(parsed),
      record: (_parsed, result) => ({
        entity_refs: { run_id: result.run.run_id, credential_id: result.run.credential_id },
      }),
    }));
  }

  start(runId: string, stepId: string, metadata: ApplicationCommandMetadata = {}): PlaybookStepClaim {
    return this.stepCommand('playbook.step.start', runId, stepId, false, metadata);
  }

  retry(runId: string, stepId: string, metadata: ApplicationCommandMetadata = {}): PlaybookStepClaim {
    return this.stepCommand('playbook.step.retry', runId, stepId, true, metadata);
  }

  resume(runId: string, metadata: ApplicationCommandMetadata = {}): PersistedDurablePlaybookRunV1 {
    const input = { run_id: runId };
    return this.resultAndPublish(this.commands.executeSync({
      command_kind: 'playbook.resume', input, schema: RunSchema, metadata,
      state_keys: ['playbook_runs'],
      execute: parsed => ({ run: this.runs.resume(parsed.run_id) }),
      record: (_parsed, result) => ({ entity_refs: { run_id: result.run.run_id } }),
    })).run;
  }

  skip(runId: string, stepId: string, reason?: string, metadata: ApplicationCommandMetadata = {}): PersistedDurablePlaybookRunV1 {
    return this.stepMutation('playbook.step.skip', runId, stepId, reason, metadata,
      parsed => this.runs.skipStep(parsed.run_id, parsed.step_id, parsed.reason));
  }

  interrupt(runId: string, stepId: string, reason?: string, metadata: ApplicationCommandMetadata = {}): PersistedDurablePlaybookRunV1 {
    return this.stepMutation('playbook.step.interrupt', runId, stepId, reason, metadata,
      parsed => this.runs.interruptAttempt(parsed.run_id, parsed.step_id, parsed.reason));
  }

  private stepCommand(
    kind: 'playbook.step.start' | 'playbook.step.retry',
    runId: string,
    stepId: string,
    retry: boolean,
    metadata: ApplicationCommandMetadata,
  ): PlaybookStepClaim {
    const input = { run_id: runId, step_id: stepId };
    return this.resultAndPublish(this.commands.executeSync({
      command_kind: kind, input, schema: StepSchema, metadata,
      state_keys: ['playbook_runs'],
      execute: parsed => retry
        ? this.runs.retryStep(parsed.run_id, parsed.step_id)
        : this.runs.startStep(parsed.run_id, parsed.step_id),
      record: (_parsed, result) => ({
        entity_refs: {
          run_id: result.run.run_id,
          step_id: result.step.step_id,
          attempt_id: result.attempt.attempt_id,
        },
      }),
    }));
  }

  private stepMutation(
    kind: 'playbook.step.skip' | 'playbook.step.interrupt',
    runId: string,
    stepId: string,
    reason: string | undefined,
    metadata: ApplicationCommandMetadata,
    mutate: (input: z.infer<typeof StepReasonSchema>) => PersistedDurablePlaybookRunV1,
  ): PersistedDurablePlaybookRunV1 {
    const input = { run_id: runId, step_id: stepId, ...(reason === undefined ? {} : { reason }) };
    return this.resultAndPublish(this.commands.executeSync({
      command_kind: kind, input, schema: StepReasonSchema, metadata,
      state_keys: ['playbook_runs'],
      execute: parsed => ({ run: mutate(parsed) }),
      record: (_parsed, result) => ({
        entity_refs: { run_id: result.run.run_id, step_id: stepId },
      }),
    })).run;
  }

  private result<T>(execution: ApplicationCommandExecution<T>): T {
    if (execution.status === 'succeeded' && execution.result !== undefined) return execution.result;
    const code = execution.error?.code;
    const supported = [
      'PLAYBOOK_NOT_FOUND', 'PLAYBOOK_LEGACY_RECORD', 'PLAYBOOK_STEP_NOT_FOUND',
      'PLAYBOOK_CONFLICT', 'PLAYBOOK_BLOCKED', 'PLAYBOOK_ATTEMPT_NOT_FOUND',
    ] as const;
    const playbookCode = supported.find(candidate => candidate === code) ?? 'PLAYBOOK_CONFLICT';
    const details = execution.error?.details;
    const httpStatus = details && typeof details === 'object' && !Array.isArray(details)
      && (details as { http_status?: unknown }).http_status === 404 ? 404 : 409;
    throw new PlaybookRunError(
      execution.error?.message ?? 'The durable playbook command failed.',
      playbookCode,
      httpStatus,
    );
  }

  private resultAndPublish<T extends { run: PersistedDurablePlaybookRunV1 }>(
    execution: ApplicationCommandExecution<T>,
  ): T {
    const result = this.result(execution);
    if (!execution.replayed) this.runs.publish(result.run);
    return result;
  }
}
