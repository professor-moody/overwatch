// ============================================================
// Overwatch — transport-neutral recovery commands
// ============================================================

import { z } from 'zod';
import type {
  ResolveConfigDivergenceInput,
  ResolveConfigDivergenceResult,
} from './engagement-config-service.js';
import type { GraphEngine } from './graph-engine.js';
import {
  ApplicationCommandService,
  type ApplicationCommandExecution,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import type { PersistedApplicationCommandV1 } from './persisted-state.js';

const Sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);

const ResolveConfigInputSchema = z.object({
  mode: z.enum(['use_file', 'use_state']),
  expected_file_hash: Sha256Schema,
  expected_state_hash: Sha256Schema,
}).strict();

export class RecoveryCommandError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly http_status: number,
  ) {
    super(message);
    this.name = 'RecoveryCommandError';
  }
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function executionFromRecord<T>(
  record: PersistedApplicationCommandV1,
  replayed: boolean,
): ApplicationCommandExecution<T> {
  return {
    command_id: record.command_id,
    idempotency_key: record.idempotency_key,
    status: record.status,
    replayed,
    ...(Object.prototype.hasOwnProperty.call(record, 'result')
      ? { result: clone(record.result) as T }
      : {}),
    ...(record.error ? { error: clone(record.error) } : {}),
    record: clone(record),
  };
}

export class RecoveryCommandService {
  constructor(
    private readonly engine: GraphEngine,
    private readonly commands = new ApplicationCommandService(engine),
  ) {}

  resolveConfig(
    input: ResolveConfigDivergenceInput,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ResolveConfigDivergenceResult> {
    const parsed = ResolveConfigInputSchema.parse(input);
    const effectiveMetadata: ApplicationCommandMetadata = {
      ...metadata,
      idempotency_key: metadata.idempotency_key
        ?? [
          'config-reconcile',
          parsed.mode,
          parsed.expected_file_hash,
          parsed.expected_state_hash,
        ].join(':'),
    };
    const replay = this.commands.lookup<
      typeof parsed,
      ResolveConfigDivergenceResult
    >('recovery.config.resolve', parsed, effectiveMetadata);
    if (replay) {
      const succeeded = this.requireSucceeded(replay);
      this.engine.resumeDeferredStartupReconciliation();
      return succeeded;
    }
    const identity = this.commands.buildIdentity(
      'recovery.config.resolve',
      parsed,
      effectiveMetadata,
    );
    const committed = this.engine.resolveConfigDivergenceApplicationCommand(
      parsed,
      result => {
        const now = this.engine.now();
        return {
          ...identity,
          command_kind: 'recovery.config.resolve',
          validated_input: clone(parsed),
          status: 'succeeded',
          created_at: now,
          started_at: now,
          completed_at: now,
          result: clone(result),
          entity_refs: {
            engagement_id: result.config.id,
          },
        };
      },
    );
    return executionFromRecord<ResolveConfigDivergenceResult>(
      committed.command,
      false,
    );
  }

  private requireSucceeded<T>(
    execution: ApplicationCommandExecution<T>,
  ): ApplicationCommandExecution<T> {
    if (execution.status === 'succeeded') return execution;
    throw new RecoveryCommandError(
      execution.error?.message
        ?? `Recovery command ${execution.command_id} is ${execution.status}.`,
      execution.error?.code ?? 'RECOVERY_COMMAND_NOT_SUCCEEDED',
      execution.status === 'accepted' || execution.status === 'running'
        ? 409
        : 503,
    );
  }
}
