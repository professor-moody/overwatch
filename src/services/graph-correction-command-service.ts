// ============================================================
// Overwatch — transport-neutral graph correction commands
// ============================================================

import {
  GraphCorrectionRequestSchema,
  type GraphCorrectionOperationDto,
  type GraphCorrectionResultDto,
} from '../contracts/dashboard-v1.js';
import type { GraphCorrectionOperation } from '../types.js';
import {
  ApplicationCommandService,
  type ApplicationCommandExecution,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import type { GraphEngine } from './graph-engine.js';
import type { PersistedApplicationCommandV1 } from './persisted-state.js';

export class GraphCorrectionCommandError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly http_status: number,
  ) {
    super(message);
    this.name = 'GraphCorrectionCommandError';
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

export class GraphCorrectionCommandService {
  constructor(
    private readonly engine: GraphEngine,
    private readonly commands = new ApplicationCommandService(engine),
  ) {}

  correct(
    input: {
      reason: string;
      action_id?: string;
      operations: GraphCorrectionOperationDto[];
    },
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<GraphCorrectionResultDto> {
    const parsed = GraphCorrectionRequestSchema.parse(input);
    const replay = this.commands.lookup<
      typeof parsed,
      GraphCorrectionResultDto
    >('graph.correct', parsed, {
      ...metadata,
      action_id: metadata.action_id ?? parsed.action_id,
    });
    if (replay) return this.requireSucceeded(replay);
    const identity = this.commands.buildIdentity('graph.correct', parsed, {
      ...metadata,
      action_id: metadata.action_id ?? parsed.action_id,
    });
    let committed: ReturnType<GraphEngine['correctGraphApplicationCommand']>;
    try {
      committed = this.engine.correctGraphApplicationCommand(
        parsed.reason,
        parsed.operations as GraphCorrectionOperation[],
        identity.action_id,
        result => {
          const now = this.engine.now();
          return {
            ...identity,
            command_kind: 'graph.correct',
            validated_input: clone(parsed),
            status: 'succeeded',
            created_at: now,
            started_at: now,
            completed_at: now,
            result: clone(result),
            entity_refs: correctionEntityRefs(parsed.operations),
          };
        },
      );
    } catch (error) {
      const afterFailure = this.commands.lookup<
        typeof parsed,
        GraphCorrectionResultDto
      >('graph.correct', parsed, {
        ...metadata,
        action_id: identity.action_id,
      });
      if (afterFailure) return this.requireSucceeded(afterFailure);
      if (!this.engine.isPersistenceWritable()) throw error;
      const rawCode = typeof (error as { code?: unknown } | null)?.code === 'string'
        ? (error as { code: string }).code
        : undefined;
      const persistenceFailure = rawCode === 'PERSISTENCE_READ_ONLY'
        || rawCode === 'CONFIG_WRITE_INCOMPLETE'
        || /\b(?:persistence|durab(?:le|ly|ility)|read[- ]only|journal|WAL|fsync)\b/i.test(
          error instanceof Error ? error.message : String(error),
        );
      const durableError = error instanceof GraphCorrectionCommandError
        ? error
        : new GraphCorrectionCommandError(
            error instanceof Error ? error.message : String(error),
            persistenceFailure
              ? rawCode ?? 'PERSISTENCE_READ_ONLY'
              : 'GRAPH_CORRECTION_FAILED',
            persistenceFailure ? 503 : 400,
          );
      return this.requireSucceeded(
        this.commands.recordFailureSync({
          command_kind: 'graph.correct',
          input: parsed,
          schema: GraphCorrectionRequestSchema,
          metadata: {
            ...metadata,
            action_id: identity.action_id,
          },
          error: durableError,
        }),
      );
    }
    return executionFromRecord<GraphCorrectionResultDto>(
      committed.command,
      false,
    );
  }

  private requireSucceeded<T>(
    execution: ApplicationCommandExecution<T>,
  ): ApplicationCommandExecution<T> {
    if (execution.status === 'succeeded') return execution;
    const details = execution.error?.details;
    const httpStatus = details
      && typeof details === 'object'
      && !Array.isArray(details)
      && typeof (details as Record<string, unknown>).http_status === 'number'
      ? (details as Record<string, number>).http_status
      : undefined;
    throw new GraphCorrectionCommandError(
      execution.error?.message
        ?? `Graph correction command ${execution.command_id} is ${execution.status}.`,
      execution.error?.code ?? 'GRAPH_CORRECTION_NOT_SUCCEEDED',
      httpStatus
        ?? (execution.status === 'accepted' || execution.status === 'running'
          ? 409
          : 503),
    );
  }
}

function correctionEntityRefs(
  operations: GraphCorrectionOperationDto[],
): Record<string, string[]> {
  const nodeIds = new Set<string>();
  for (const operation of operations) {
    if (operation.kind === 'drop_node' || operation.kind === 'patch_node') {
      nodeIds.add(operation.node_id);
      continue;
    }
    nodeIds.add(operation.source_id);
    nodeIds.add(operation.target_id);
    if (operation.kind === 'replace_edge') {
      if (operation.new_source_id) nodeIds.add(operation.new_source_id);
      if (operation.new_target_id) nodeIds.add(operation.new_target_id);
    }
  }
  return { node_ids: [...nodeIds].sort() };
}
