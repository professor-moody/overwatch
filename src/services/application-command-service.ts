// ============================================================
// Overwatch — transport-neutral application command boundary
// ============================================================

import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomUUID } from 'node:crypto';
import { z, type ZodType } from 'zod';
import type { GraphEngine } from './graph-engine.js';
import { canonicalJson } from './engagement-config-service.js';
import type { DurableStateSliceKey } from './durable-state-patch.js';
import type {
  ApplicationCommandStatus,
  ApplicationCommandTransport,
  PersistedApplicationCommandV1,
} from './persisted-state.js';

export interface ApplicationCommandInvocationContext {
  transport: ApplicationCommandTransport;
  actor_task_id?: string | null;
  request_id?: string;
  session_id?: string;
  command_id?: string;
  idempotency_key?: string;
  action_id?: string;
  frontier_item_id?: string;
}

const invocationStorage = new AsyncLocalStorage<ApplicationCommandInvocationContext>();

export function withApplicationCommandInvocation<T>(
  context: ApplicationCommandInvocationContext,
  operation: () => T,
): T {
  return invocationStorage.run(context, operation);
}

export function getApplicationCommandInvocation():
  | ApplicationCommandInvocationContext
  | undefined {
  return invocationStorage.getStore();
}

export interface ApplicationCommandMetadata {
  command_id?: string;
  idempotency_key?: string;
  transport?: ApplicationCommandTransport;
  actor_task_id?: string | null;
  action_id?: string;
  frontier_item_id?: string;
  plan_id?: string;
}

export interface ApplicationCommandExecution<T> {
  command_id: string;
  idempotency_key: string;
  status: ApplicationCommandStatus;
  replayed: boolean;
  result?: T;
  error?: PersistedApplicationCommandV1['error'];
  record: PersistedApplicationCommandV1;
}

export interface ApplicationCommandReservation<T> {
  result: T;
  status?: Extract<ApplicationCommandStatus, 'accepted' | 'running'>;
  entity_refs?: Record<string, string | string[]>;
  action_id?: string;
  frontier_item_id?: string;
  plan_id?: string;
}

export interface ApplicationCommandTransition<T = unknown> {
  status: ApplicationCommandStatus;
  result?: T;
  error?: PersistedApplicationCommandV1['error'];
  entity_refs?: Record<string, string | string[]>;
  action_id?: string;
  frontier_item_id?: string;
  plan_id?: string;
}

type ApplicationCommandRecordMetadata = Pick<
  ApplicationCommandTransition,
  'entity_refs' | 'action_id' | 'frontier_item_id' | 'plan_id'
>;

export class ApplicationCommandConflictError extends Error {
  readonly code = 'IDEMPOTENCY_CONFLICT';
  constructor(
    message: string,
    readonly existing: PersistedApplicationCommandV1,
  ) {
    super(message);
    this.name = 'ApplicationCommandConflictError';
  }
}

export class ApplicationCommandInProgressError extends Error {
  readonly code = 'COMMAND_IN_PROGRESS';
  constructor(readonly record: PersistedApplicationCommandV1) {
    super(`Application command ${record.command_id} is still ${record.status}.`);
    this.name = 'ApplicationCommandInProgressError';
  }
}

export class ApplicationCommandFailedError extends Error {
  readonly code: string;
  constructor(readonly record: PersistedApplicationCommandV1) {
    super(record.error?.message ?? `Application command ${record.command_id} ${record.status}.`);
    this.name = 'ApplicationCommandFailedError';
    this.code = record.error?.code ?? 'COMMAND_FAILED';
  }
}

const commandMetadataSchema = z.object({
  command_id: z.string().trim().min(1).max(256).optional(),
  idempotency_key: z.string().trim().min(1).max(512).optional(),
  transport: z.enum([
    'mcp',
    'dashboard',
    'cli',
    'planner',
    'scripted_runner',
    'headless_runner',
    'system',
  ]).optional(),
  actor_task_id: z.string().trim().min(1).max(256).nullable().optional(),
  action_id: z.string().trim().min(1).max(256).optional(),
  frontier_item_id: z.string().trim().min(1).max(512).optional(),
  plan_id: z.string().trim().min(1).max(256).optional(),
}).strict();

const TERMINAL_STATUSES = new Set<ApplicationCommandStatus>([
  'succeeded',
  'failed',
  'interrupted',
]);

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function jsonSafe(value: unknown): unknown {
  const serialized = JSON.stringify(value);
  return serialized === undefined ? null : JSON.parse(serialized);
}

function commandError(error: unknown): NonNullable<PersistedApplicationCommandV1['error']> {
  const code = typeof (error as { code?: unknown } | null)?.code === 'string'
    ? (error as { code: string }).code
    : undefined;
  const rawDetails = (error as { details?: unknown } | null)?.details;
  const httpStatus = (error as { http_status?: unknown } | null)?.http_status;
  const details = typeof httpStatus === 'number'
    ? {
        ...(rawDetails && typeof rawDetails === 'object' && !Array.isArray(rawDetails)
          ? rawDetails as Record<string, unknown>
          : rawDetails === undefined
            ? {}
            : { cause: rawDetails }),
        http_status: httpStatus,
      }
    : rawDetails;
  return {
    ...(code ? { code } : {}),
    message: error instanceof Error ? error.message : String(error),
    ...(details !== undefined ? { details: structuredClone(details) } : {}),
  };
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
      ? { result: structuredClone(record.result) as T }
      : {}),
    ...(record.error ? { error: structuredClone(record.error) } : {}),
    record: structuredClone(record),
  };
}

/**
 * The command boundary owns validation, actor-scoped idempotency, durable
 * response storage, and synchronous transaction composition. Domain services
 * own business validation and choose the durable slices their command changes.
 */
export class ApplicationCommandService {
  private readonly inFlight = new Map<string, Promise<ApplicationCommandExecution<unknown>>>();

  constructor(private readonly engine: GraphEngine) {}

  buildIdentity<I>(
    commandKind: string,
    input: I,
    metadata: ApplicationCommandMetadata = {},
  ): {
    command_id: string;
    idempotency_key: string;
    input_sha256: string;
    transport: ApplicationCommandTransport;
    actor_task_id: string | null;
    action_id?: string;
    frontier_item_id?: string;
    plan_id?: string;
  } {
    const parsedMetadata = commandMetadataSchema.parse(metadata);
    const invocation = getApplicationCommandInvocation();
    const transport = parsedMetadata.transport ?? invocation?.transport ?? 'system';
    const actorTaskId = Object.prototype.hasOwnProperty.call(
      parsedMetadata,
      'actor_task_id',
    )
      ? parsedMetadata.actor_task_id ?? null
      : invocation?.actor_task_id ?? null;
    const commandId = parsedMetadata.command_id
      ?? invocation?.command_id
      ?? randomUUID();
    const explicitIdempotencyKey = parsedMetadata.idempotency_key
      ?? invocation?.idempotency_key;
    const requestIdentity = explicitIdempotencyKey
      ?? (invocation?.session_id ? invocation.request_id : undefined)
      ?? commandId;
    const scopedKeyMaterial = canonicalJson({
      actor_task_id: actorTaskId,
      command_kind: commandKind,
      idempotency_key: requestIdentity,
      ...(explicitIdempotencyKey
        ? {}
        : {
            transport,
            session_id: invocation?.session_id ?? null,
          }),
    });
    const identity = {
      command_id: commandId,
      idempotency_key: `idem_${sha256(scopedKeyMaterial)}`,
      input_sha256: sha256(canonicalJson(input)),
      transport,
      actor_task_id: actorTaskId,
      action_id: parsedMetadata.action_id ?? invocation?.action_id,
      frontier_item_id: parsedMetadata.frontier_item_id ?? invocation?.frontier_item_id,
      plan_id: parsedMetadata.plan_id,
    };
    const existingByCommandId = this.engine.getApplicationCommandById(commandId);
    if (
      existingByCommandId
      && existingByCommandId.idempotency_key !== identity.idempotency_key
    ) {
      throw new ApplicationCommandConflictError(
        `Command ID ${commandId} is already bound to a different application command.`,
        existingByCommandId,
      );
    }
    return identity;
  }

  lookup<I, T = unknown>(
    commandKind: string,
    input: I,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<T> | undefined {
    const identity = this.buildIdentity(commandKind, input, metadata);
    const existing = this.engine.getApplicationCommand(identity.idempotency_key);
    if (!existing) return undefined;
    this.assertCompatible(existing, commandKind, identity.input_sha256);
    return executionFromRecord<T>(existing, true);
  }

  /**
   * Bind a validated custom-command failure when the domain owns a specialized
   * atomic commit path and therefore cannot run inside `executeSync`.
   */
  recordFailureSync<I, T = never>(options: {
    command_kind: string;
    input: unknown;
    schema: ZodType<I, z.ZodTypeDef, unknown>;
    metadata?: ApplicationCommandMetadata;
    error: unknown;
    started?: boolean;
  }): ApplicationCommandExecution<T> {
    const input = options.schema.parse(options.input);
    const identity = this.buildIdentity(
      options.command_kind,
      input,
      options.metadata,
    );
    const existing = this.engine.getApplicationCommand(identity.idempotency_key);
    if (existing) {
      this.assertCompatible(
        existing,
        options.command_kind,
        identity.input_sha256,
      );
      return executionFromRecord<T>(existing, true);
    }
    return this.recordFailedExecution<T>(
      options.command_kind,
      identity,
      input,
      options.error,
      options.started ?? true,
    );
  }

  executeSync<I, T>(
    options: {
      command_kind: string;
      input: unknown;
      schema: ZodType<I, z.ZodTypeDef, unknown>;
      metadata?: ApplicationCommandMetadata;
      state_keys?: readonly DurableStateSliceKey[];
      execute: (input: I) => T;
      record?: (input: I, result: T) => ApplicationCommandRecordMetadata;
    },
  ): ApplicationCommandExecution<T> {
    const input = options.schema.parse(options.input);
    const identity = this.buildIdentity(options.command_kind, input, options.metadata);
    const existing = this.engine.getApplicationCommand(identity.idempotency_key);
    if (existing) {
      this.assertCompatible(existing, options.command_kind, identity.input_sha256);
      return executionFromRecord<T>(existing, true);
    }

    let domainError: unknown;
    try {
      return this.engine.runApplicationCommandTransaction(
        `application command ${options.command_kind}`,
        identity.action_id,
        () => {
          const concurrent = this.engine.getApplicationCommand(identity.idempotency_key);
          if (concurrent) {
            this.assertCompatible(concurrent, options.command_kind, identity.input_sha256);
            return executionFromRecord<T>(concurrent, true);
          }

          const now = this.engine.now();
          let result: T;
          try {
            result = options.execute(input);
          } catch (error) {
            domainError = error;
            throw error;
          }
          const recordMetadata = options.record?.(input, result);
          const record: PersistedApplicationCommandV1 = {
            ...identity,
            command_kind: options.command_kind,
            validated_input: jsonSafe(input),
            status: 'succeeded',
            created_at: now,
            started_at: now,
            completed_at: this.engine.now(),
            result: structuredClone(result),
            ...(recordMetadata?.entity_refs
              ? { entity_refs: structuredClone(recordMetadata.entity_refs) }
              : {}),
            action_id: recordMetadata?.action_id ?? identity.action_id,
            frontier_item_id:
              recordMetadata?.frontier_item_id ?? identity.frontier_item_id,
            plan_id: recordMetadata?.plan_id ?? identity.plan_id,
          };
          this.engine.recordApplicationCommand(record);
          return executionFromRecord<T>(record, false);
        },
        options.state_keys ?? [],
      );
    } catch (error) {
      if (error !== domainError) throw error;
      return this.recordFailedExecution<T>(
        options.command_kind,
        identity,
        input,
        error,
        true,
      );
    }
  }

  reserveSync<I, T>(
    options: {
      command_kind: string;
      input: unknown;
      schema: ZodType<I, z.ZodTypeDef, unknown>;
      metadata?: ApplicationCommandMetadata;
      state_keys?: readonly DurableStateSliceKey[];
      reserve: (input: I) => ApplicationCommandReservation<T>;
    },
  ): ApplicationCommandExecution<T> {
    const input = options.schema.parse(options.input);
    const identity = this.buildIdentity(options.command_kind, input, options.metadata);
    const existing = this.engine.getApplicationCommand(identity.idempotency_key);
    if (existing) {
      this.assertCompatible(existing, options.command_kind, identity.input_sha256);
      return executionFromRecord<T>(existing, true);
    }

    let domainError: unknown;
    try {
      return this.engine.runApplicationCommandTransaction(
        `reserve application command ${options.command_kind}`,
        identity.action_id,
        () => {
          const concurrent = this.engine.getApplicationCommand(identity.idempotency_key);
          if (concurrent) {
            this.assertCompatible(concurrent, options.command_kind, identity.input_sha256);
            return executionFromRecord<T>(concurrent, true);
          }
          const now = this.engine.now();
          let reserved: ApplicationCommandReservation<T>;
          try {
            reserved = options.reserve(input);
          } catch (error) {
            domainError = error;
            throw error;
          }
          const record: PersistedApplicationCommandV1 = {
            ...identity,
            command_kind: options.command_kind,
            validated_input: jsonSafe(input),
            status: reserved.status ?? 'accepted',
            created_at: now,
            ...(reserved.status === 'running' ? { started_at: now } : {}),
            result: structuredClone(reserved.result),
            ...(reserved.entity_refs ? { entity_refs: structuredClone(reserved.entity_refs) } : {}),
            action_id: reserved.action_id ?? identity.action_id,
            frontier_item_id: reserved.frontier_item_id ?? identity.frontier_item_id,
            plan_id: reserved.plan_id ?? identity.plan_id,
          };
          this.engine.recordApplicationCommand(record);
          return executionFromRecord<T>(record, false);
        },
        options.state_keys ?? [],
      );
    } catch (error) {
      if (error !== domainError) throw error;
      return this.recordFailedExecution<T>(
        options.command_kind,
        identity,
        input,
        error,
        false,
      );
    }
  }

  async executeAsync<I, T>(
    options: {
      command_kind: string;
      input: unknown;
      schema: ZodType<I, z.ZodTypeDef, unknown>;
      metadata?: ApplicationCommandMetadata;
      reservation_state_keys?: readonly DurableStateSliceKey[];
      reserve?: (input: I) => Omit<ApplicationCommandReservation<unknown>, 'status'>;
      execute: (input: I, command: PersistedApplicationCommandV1) => Promise<ApplicationCommandTransition<T>>;
      completion_state_keys?: readonly DurableStateSliceKey[];
      completion_effects?: (
        input: I,
        transition: ApplicationCommandTransition<T>,
      ) => void;
    },
  ): Promise<ApplicationCommandExecution<T>> {
    const input = options.schema.parse(options.input);
    const identity = this.buildIdentity(options.command_kind, input, options.metadata);
    const existing = this.engine.getApplicationCommand(identity.idempotency_key);
    if (existing) {
      this.assertCompatible(existing, options.command_kind, identity.input_sha256);
      const running = this.inFlight.get(identity.idempotency_key);
      if (running) return running as Promise<ApplicationCommandExecution<T>>;
      return executionFromRecord<T>(existing, true);
    }

    const reserved = this.reserveSync({
      command_kind: options.command_kind,
      input,
      schema: options.schema,
      metadata: {
        ...options.metadata,
        command_id: identity.command_id,
      },
      state_keys: options.reservation_state_keys,
      reserve: parsed => ({
        ...(options.reserve?.(parsed) ?? { result: null }),
        status: 'accepted',
      }),
    });
    if (reserved.status === 'failed' || reserved.replayed) {
      return reserved as ApplicationCommandExecution<T>;
    }

    const operation = (async (): Promise<ApplicationCommandExecution<T>> => {
      this.transition(identity.command_id, {
        status: 'running',
        result: reserved.result,
      });
      const runningRecord = this.engine.getApplicationCommandById(identity.command_id)!;
      let requestedTransition: ApplicationCommandTransition<T>;
      try {
        requestedTransition = await options.execute(input, runningRecord);
      } catch (error) {
        return this.transition<T>(
          identity.command_id,
          {
            status: 'failed',
            error: commandError(error),
          },
          options.completion_state_keys,
        );
      }
      // Keep the durable transition outside the domain-execution catch. If its
      // WAL/apply boundary fails, the command must remain running for recovery;
      // attempting a second "failed" transition could hide a committed effect.
      return this.transition<T>(
        identity.command_id,
        requestedTransition,
        options.completion_state_keys,
        () => options.completion_effects?.(input, requestedTransition),
      );
    })();

    this.inFlight.set(identity.idempotency_key, operation as Promise<ApplicationCommandExecution<unknown>>);
    try {
      return await operation;
    } finally {
      this.inFlight.delete(identity.idempotency_key);
    }
  }

  transition<T>(
    commandId: string,
    transition: ApplicationCommandTransition<T>,
    stateKeys: readonly DurableStateSliceKey[] = [],
    effects?: () => void,
  ): ApplicationCommandExecution<T> {
    return this.engine.runApplicationCommandTransaction(
      `transition application command ${commandId} to ${transition.status}`,
      transition.action_id,
      () => {
        const current = this.engine.getApplicationCommandById(commandId);
        if (!current) throw new Error(`Application command not found: ${commandId}`);
        if (TERMINAL_STATUSES.has(current.status)) {
          return executionFromRecord<T>(current, true);
        }
        const now = this.engine.now();
        const next: PersistedApplicationCommandV1 = {
          ...current,
          status: transition.status,
          ...(transition.status === 'running' && !current.started_at ? { started_at: now } : {}),
          ...(TERMINAL_STATUSES.has(transition.status) ? { completed_at: now } : {}),
          ...(Object.prototype.hasOwnProperty.call(transition, 'result')
            ? { result: structuredClone(transition.result) }
            : {}),
          ...(transition.error ? { error: structuredClone(transition.error) } : {}),
          ...(transition.entity_refs
            ? {
                entity_refs: {
                  ...(current.entity_refs ?? {}),
                  ...structuredClone(transition.entity_refs),
                },
              }
            : {}),
          action_id: transition.action_id ?? current.action_id,
          frontier_item_id: transition.frontier_item_id ?? current.frontier_item_id,
          plan_id: transition.plan_id ?? current.plan_id,
        };
        effects?.();
        this.engine.recordApplicationCommand(next);
        return executionFromRecord<T>(next, false);
      },
      stateKeys,
    );
  }

  recoverInterruptedCommands(reason = 'daemon restarted before command completion'): number {
    if (!this.engine.isPersistenceWritable()) return 0;
    const unfinished = this.engine.listApplicationCommands()
      .filter(command => command.status === 'accepted' || command.status === 'running');
    if (unfinished.length === 0) return 0;
    return this.engine.runApplicationCommandTransaction(
      'interrupt unfinished application commands during recovery',
      undefined,
      () => {
        for (const command of unfinished) {
          this.engine.recordApplicationCommand({
            ...command,
            status: 'interrupted',
            completed_at: this.engine.now(),
            error: { code: 'COMMAND_INTERRUPTED', message: reason },
          });
        }
        return unfinished.length;
      },
    );
  }

  unwrap<T>(execution: ApplicationCommandExecution<T>): T {
    if (execution.status === 'accepted' || execution.status === 'running') {
      throw new ApplicationCommandInProgressError(execution.record);
    }
    if (execution.status === 'failed' || execution.status === 'interrupted') {
      throw new ApplicationCommandFailedError(execution.record);
    }
    return execution.result as T;
  }

  private assertCompatible(
    existing: PersistedApplicationCommandV1,
    commandKind: string,
    inputSha256: string,
  ): void {
    if (
      existing.command_kind !== commandKind
      || existing.input_sha256 !== inputSha256
    ) {
      throw new ApplicationCommandConflictError(
        `Idempotency key is already bound to command ${existing.command_id} with different input.`,
        existing,
      );
    }
  }

  private recordFailedExecution<T>(
    commandKind: string,
    identity: ReturnType<ApplicationCommandService['buildIdentity']>,
    input: unknown,
    error: unknown,
    started: boolean,
  ): ApplicationCommandExecution<T> {
    return this.engine.runApplicationCommandTransaction(
      `record failed application command ${commandKind}`,
      identity.action_id,
      () => {
        const concurrent = this.engine.getApplicationCommand(identity.idempotency_key);
        if (concurrent) {
          this.assertCompatible(concurrent, commandKind, identity.input_sha256);
          return executionFromRecord<T>(concurrent, true);
        }
        const now = this.engine.now();
        const record: PersistedApplicationCommandV1 = {
          ...identity,
          command_kind: commandKind,
          validated_input: jsonSafe(input),
          status: 'failed',
          created_at: now,
          ...(started ? { started_at: now } : {}),
          completed_at: now,
          error: commandError(error),
        };
        this.engine.recordApplicationCommand(record);
        return executionFromRecord<T>(record, false);
      },
    );
  }
}
