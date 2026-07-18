// ============================================================
// Overwatch — transport-neutral application command boundary
// ============================================================

import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomUUID } from 'node:crypto';
import { z, type ZodType } from 'zod';
import type { GraphEngine } from './graph-engine.js';
import { canonicalJson } from './engagement-config-service.js';
import type { DurableStateSliceKey } from './durable-state-patch.js';
import {
  MAX_PERSISTED_APPLICATION_COMMAND_ERROR_DETAILS_BYTES,
  MAX_PERSISTED_APPLICATION_COMMAND_INPUT_BYTES,
  MAX_PERSISTED_APPLICATION_COMMAND_RESULT_BYTES,
  type ApplicationCommandStatus,
  type ApplicationCommandTransport,
  type PersistedApplicationCommandV1,
} from './persisted-state.js';
export const MAX_APPLICATION_COMMAND_INPUT_BYTES = MAX_PERSISTED_APPLICATION_COMMAND_INPUT_BYTES;
export const MAX_APPLICATION_COMMAND_RESULT_BYTES = MAX_PERSISTED_APPLICATION_COMMAND_RESULT_BYTES;
export const MAX_APPLICATION_COMMAND_ERROR_DETAILS_BYTES =
  MAX_PERSISTED_APPLICATION_COMMAND_ERROR_DETAILS_BYTES;

export interface ApplicationCommandInvocationContext {
  transport: ApplicationCommandTransport;
  actor_task_id?: string | null;
  request_id?: string;
  session_id?: string;
  command_id?: string;
  idempotency_key?: string;
  retry_token?: string;
  action_id?: string;
  frontier_item_id?: string;
}

const invocationStorage = new AsyncLocalStorage<ApplicationCommandInvocationContext>();
const inFlightByEngine = new WeakMap<
  GraphEngine,
  Map<string, Promise<ApplicationCommandExecution<unknown>>>
>();

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
  retry_token?: string;
  transport?: ApplicationCommandTransport;
  actor_task_id?: string | null;
  action_id?: string;
  frontier_item_id?: string;
  plan_id?: string;
}

export interface ApplicationCommandRetention {
  retention_class: string;
  retention_group: string;
  max_group_records: number;
  max_class_records: number;
  max_class_bytes?: number;
  max_age_ms?: number;
}

export const DEFAULT_APPLICATION_COMMAND_RETENTION = {
  retention_class: 'application.command',
  max_group_records: 10_000,
  max_class_records: 10_000,
  max_class_bytes: 256 * 1024 * 1024,
  max_age_ms: 30 * 24 * 60 * 60 * 1_000,
} as const;

export interface ApplicationCommandExecution<T> {
  command_id: string;
  /** Opaque token callers may send back as retry_token after response loss. */
  retry_token: string;
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

export class ApplicationCommandActorMismatchError extends Error {
  readonly code = 'COMMAND_ACTOR_MISMATCH';
  readonly http_status = 409;
  readonly details: { authenticated_actor_task_id: string; claimed_actor_task_id: string };

  constructor(authenticatedActorTaskId: string, claimedActorTaskId: string) {
    super(
      `Authenticated task ${authenticatedActorTaskId} cannot submit an application command as task ${claimedActorTaskId}.`,
    );
    this.name = 'ApplicationCommandActorMismatchError';
    this.details = {
      authenticated_actor_task_id: authenticatedActorTaskId,
      claimed_actor_task_id: claimedActorTaskId,
    };
  }
}

export class ApplicationCommandPayloadError extends Error {
  readonly code = 'COMMAND_PAYLOAD_INVALID';
  readonly http_status = 400;
  readonly details: { field: string; max_bytes: number; actual_bytes?: number };

  constructor(
    message: string,
    field: string,
    maxBytes: number,
    actualBytes?: number,
  ) {
    super(message);
    this.name = 'ApplicationCommandPayloadError';
    this.details = {
      field,
      max_bytes: maxBytes,
      ...(actualBytes === undefined ? {} : { actual_bytes: actualBytes }),
    };
  }
}

export class ApplicationCommandTransitionError extends Error {
  readonly code = 'COMMAND_TRANSITION_INVALID';
  readonly http_status = 409;
  readonly details: { command_id: string; from: ApplicationCommandStatus; to: ApplicationCommandStatus };

  constructor(
    commandId: string,
    from: ApplicationCommandStatus,
    to: ApplicationCommandStatus,
  ) {
    super(`Application command ${commandId} cannot transition from ${from} to ${to}.`);
    this.name = 'ApplicationCommandTransitionError';
    this.details = { command_id: commandId, from, to };
  }
}

export class ApplicationCommandRetryTokenError extends Error {
  readonly code = 'COMMAND_RETRY_TOKEN_UNKNOWN';
  readonly http_status = 409;

  constructor() {
    super('The supplied application-command retry token is unknown or has expired.');
    this.name = 'ApplicationCommandRetryTokenError';
  }
}

const commandMetadataSchema = z.object({
  command_id: z.string().trim().min(1).max(256).optional(),
  idempotency_key: z.string().trim().min(1).max(512).optional(),
  retry_token: z.string().regex(/^idem_[a-f0-9]{64}$/).optional(),
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

const commandRetentionSchema = z.object({
  retention_class: z.string().trim().min(1).max(256),
  retention_group: z.string().trim().min(1).max(512),
  max_group_records: z.number().int().min(1).max(100_000),
  max_class_records: z.number().int().min(1).max(1_000_000),
  max_class_bytes: z.number().int().min(1).max(4 * 1024 * 1024 * 1024).optional(),
  max_age_ms: z.number().int().min(1).max(10 * 365 * 24 * 60 * 60 * 1_000).optional(),
}).strict().refine(
  value => value.max_group_records <= value.max_class_records,
  { message: 'max_group_records cannot exceed max_class_records' },
);

function retentionRecordFields(retention: ApplicationCommandRetention): Pick<
  PersistedApplicationCommandV1,
  | 'retention_class'
  | 'retention_group'
  | 'retention_max_group_records'
  | 'retention_max_class_records'
  | 'retention_max_class_bytes'
  | 'retention_max_age_ms'
> {
  return {
    retention_class: retention.retention_class,
    retention_group: retention.retention_group,
    retention_max_group_records: retention.max_group_records,
    retention_max_class_records: retention.max_class_records,
    ...(retention.max_class_bytes !== undefined
      ? { retention_max_class_bytes: retention.max_class_bytes }
      : {}),
    ...(retention.max_age_ms !== undefined
      ? { retention_max_age_ms: retention.max_age_ms }
      : {}),
  };
}

function retentionFromRecord(
  record: PersistedApplicationCommandV1,
): ApplicationCommandRetention | undefined {
  if (
    !record.retention_class
    || !record.retention_group
    || record.retention_max_group_records === undefined
    || record.retention_max_class_records === undefined
  ) return undefined;
  return commandRetentionSchema.parse({
    retention_class: record.retention_class,
    retention_group: record.retention_group,
    max_group_records: record.retention_max_group_records,
    max_class_records: record.retention_max_class_records,
    ...(record.retention_max_class_bytes !== undefined
      ? { max_class_bytes: record.retention_max_class_bytes }
      : {}),
    ...(record.retention_max_age_ms !== undefined
      ? { max_age_ms: record.retention_max_age_ms }
      : {}),
  });
}

function defaultRetention(
  commandKind: string,
  transport: ApplicationCommandTransport,
): ApplicationCommandRetention {
  return {
    ...DEFAULT_APPLICATION_COMMAND_RETENTION,
    retention_group: `${transport}:${commandKind}`,
  };
}

const TERMINAL_STATUSES = new Set<ApplicationCommandStatus>([
  'succeeded',
  'failed',
  'interrupted',
]);
const APPLICATION_COMMAND_STATUSES = new Set<ApplicationCommandStatus>([
  'accepted',
  'running',
  ...TERMINAL_STATUSES,
]);

const MAX_APPLICATION_COMMAND_ERROR_MESSAGE_CHARS = 8 * 1024;
const MAX_APPLICATION_COMMAND_ERROR_CODE_CHARS = 256;

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function boundedJsonSafe(value: unknown, field: string, maxBytes: number): unknown {
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(value, (_key, candidate: unknown) => {
      if (typeof candidate === 'number' && !Number.isFinite(candidate)) {
        throw new TypeError(`${field} contains a non-finite number`);
      }
      if (
        typeof candidate === 'bigint'
        || typeof candidate === 'function'
        || typeof candidate === 'symbol'
      ) {
        throw new TypeError(`${field} contains unsupported ${typeof candidate} data`);
      }
      return candidate;
    });
  } catch (error) {
    throw new ApplicationCommandPayloadError(
      `${field} must be JSON-compatible: ${error instanceof Error ? error.message : String(error)}`,
      field,
      maxBytes,
    );
  }
  const normalized = serialized ?? 'null';
  const bytes = Buffer.byteLength(normalized);
  if (bytes > maxBytes) {
    throw new ApplicationCommandPayloadError(
      `${field} is ${bytes} bytes; the durable command limit is ${maxBytes} bytes. Store large content as an artifact and retain its reference instead.`,
      field,
      maxBytes,
      bytes,
    );
  }
  return JSON.parse(normalized);
}

function validatedCommandInput<I>(
  schema: ZodType<I, z.ZodTypeDef, unknown>,
  rawInput: unknown,
): I {
  const parsed = schema.parse(rawInput);
  return boundedJsonSafe(
    parsed,
    'application command input',
    MAX_APPLICATION_COMMAND_INPUT_BYTES,
  ) as I;
}

function commandResult<T>(value: T): T {
  return boundedJsonSafe(
    value,
    'application command result',
    MAX_APPLICATION_COMMAND_RESULT_BYTES,
  ) as T;
}

function commandEntityRefs(
  value: Record<string, string | string[]>,
): Record<string, string | string[]> {
  const normalized = boundedJsonSafe(
    value,
    'application command entity references',
    MAX_APPLICATION_COMMAND_ERROR_DETAILS_BYTES,
  );
  if (!normalized || typeof normalized !== 'object' || Array.isArray(normalized)) {
    throw new ApplicationCommandPayloadError(
      'application command entity references must be an object',
      'application command entity references',
      MAX_APPLICATION_COMMAND_ERROR_DETAILS_BYTES,
    );
  }
  for (const [name, reference] of Object.entries(normalized)) {
    if (!name || (
      typeof reference !== 'string'
      && !(Array.isArray(reference) && reference.every(item => typeof item === 'string'))
    )) {
      throw new ApplicationCommandPayloadError(
        `application command entity reference ${name || '<empty>'} must be a string or string array`,
        'application command entity references',
        MAX_APPLICATION_COMMAND_ERROR_DETAILS_BYTES,
      );
    }
  }
  return normalized as Record<string, string | string[]>;
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
  let safeDetails: unknown;
  if (details !== undefined) {
    try {
      safeDetails = boundedJsonSafe(
        details,
        'application command error details',
        MAX_APPLICATION_COMMAND_ERROR_DETAILS_BYTES,
      );
    } catch (detailsError) {
      safeDetails = {
        omitted: true,
        reason: detailsError instanceof Error
          ? detailsError.message.slice(0, MAX_APPLICATION_COMMAND_ERROR_MESSAGE_CHARS)
          : 'error details were not JSON-compatible',
      };
    }
  }
  const rawMessage = typeof (error as { message?: unknown } | null)?.message === 'string'
    ? (error as { message: string }).message
    : error instanceof Error
      ? error.message
      : String(error);
  const message = rawMessage
    .slice(0, MAX_APPLICATION_COMMAND_ERROR_MESSAGE_CHARS);
  return {
    ...(code ? { code: code.slice(0, MAX_APPLICATION_COMMAND_ERROR_CODE_CHARS) } : {}),
    message,
    ...(safeDetails !== undefined ? { details: safeDetails } : {}),
  };
}

function safeCommandTransition<T>(
  transition: ApplicationCommandTransition<T>,
): ApplicationCommandTransition<T> {
  return {
    ...transition,
    ...(Object.prototype.hasOwnProperty.call(transition, 'result')
      ? { result: commandResult(transition.result) }
      : {}),
    ...(transition.error ? { error: commandError(transition.error) } : {}),
    ...(transition.entity_refs
      ? {
          entity_refs: commandEntityRefs(transition.entity_refs),
        }
      : {}),
  };
}

function executionFromRecord<T>(
  record: PersistedApplicationCommandV1,
  replayed: boolean,
): ApplicationCommandExecution<T> {
  return {
    command_id: record.command_id,
    retry_token: record.idempotency_key,
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
  private readonly inFlight: Map<string, Promise<ApplicationCommandExecution<unknown>>>;

  constructor(private readonly engine: GraphEngine) {
    const shared = inFlightByEngine.get(engine)
      ?? new Map<string, Promise<ApplicationCommandExecution<unknown>>>();
    inFlightByEngine.set(engine, shared);
    this.inFlight = shared;
  }

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
    const inputSha256 = sha256(canonicalJson(input));
    const invocation = getApplicationCommandInvocation();
    const transport = parsedMetadata.transport ?? invocation?.transport ?? 'system';
    const authenticatedActorTaskId = invocation?.actor_task_id ?? null;
    const claimedActorTaskId = parsedMetadata.actor_task_id;
    if (
      authenticatedActorTaskId
      && claimedActorTaskId
      && claimedActorTaskId !== authenticatedActorTaskId
    ) {
      throw new ApplicationCommandActorMismatchError(
        authenticatedActorTaskId,
        claimedActorTaskId,
      );
    }
    // A daemon-authenticated task is connection authority. Optional body
    // aliases may agree with it, but may neither erase nor replace it. Keep the
    // legacy actorless stdio/operator behavior: without authenticated authority
    // a resolved task alias may still provide attribution.
    const actorTaskId = authenticatedActorTaskId
      || claimedActorTaskId
      || null;
    const commandId = parsedMetadata.command_id
      ?? invocation?.command_id
      ?? randomUUID();
    const explicitIdempotencyKey = parsedMetadata.idempotency_key
      ?? invocation?.idempotency_key;
    const retryToken = parsedMetadata.retry_token ?? invocation?.retry_token;
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
    let durableIdempotencyKey = `idem_${sha256(scopedKeyMaterial)}`;
    if (retryToken) {
      const retryRecord = this.engine.getApplicationCommand(retryToken);
      if (!retryRecord) {
        throw new ApplicationCommandRetryTokenError();
      }
      if (
        retryRecord.actor_task_id !== actorTaskId
        || retryRecord.command_kind !== commandKind
        || retryRecord.input_sha256 !== inputSha256
      ) {
        throw new ApplicationCommandConflictError(
          'The supplied application-command retry token belongs to a different actor, command, or input.',
          retryRecord,
        );
      }
      durableIdempotencyKey = retryToken;
    }
    const identity = {
      command_id: commandId,
      idempotency_key: durableIdempotencyKey,
      input_sha256: inputSha256,
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
    retention?: ApplicationCommandRetention;
  }): ApplicationCommandExecution<T> {
    const input = validatedCommandInput(options.schema, options.input);
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
      options.retention,
    );
  }

  /**
   * Install a successful receipt inside a domain-owned transaction draft.
   * Complex domains such as finding ingestion already own graph/counter/audit
   * composition and must not be wrapped in a second operation-capture layer.
   */
  recordSuccessInDomainTransaction<I, T>(options: {
    command_kind: string;
    input: unknown;
    schema: ZodType<I, z.ZodTypeDef, unknown>;
    metadata?: ApplicationCommandMetadata;
    result: T;
    record?: (input: I, result: T) => ApplicationCommandRecordMetadata;
    retention?: ApplicationCommandRetention;
  }): ApplicationCommandExecution<T> {
    const input = validatedCommandInput(options.schema, options.input);
    const result = commandResult(options.result);
    const identity = this.buildIdentity(options.command_kind, input, options.metadata);
    const retention = commandRetentionSchema.parse(
      options.retention ?? defaultRetention(options.command_kind, identity.transport),
    );
    const existing = this.engine.getApplicationCommand(identity.idempotency_key);
    if (existing) {
      this.assertCompatible(existing, options.command_kind, identity.input_sha256);
      return executionFromRecord<T>(existing, true);
    }
    const recordMetadata = options.record?.(input, result);
    const now = this.engine.now();
    const record: PersistedApplicationCommandV1 = {
      ...identity,
      command_kind: options.command_kind,
      validated_input: input,
      status: 'succeeded',
      created_at: now,
      started_at: now,
      completed_at: this.engine.now(),
      result,
      ...(recordMetadata?.entity_refs
        ? { entity_refs: commandEntityRefs(recordMetadata.entity_refs) }
        : {}),
      action_id: recordMetadata?.action_id ?? identity.action_id,
      frontier_item_id: recordMetadata?.frontier_item_id ?? identity.frontier_item_id,
      plan_id: recordMetadata?.plan_id ?? identity.plan_id,
      ...retentionRecordFields(retention),
    };
    const installed = this.engine.recordApplicationCommand(record);
    return executionFromRecord<T>(installed, false);
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
      retention?: ApplicationCommandRetention;
    },
  ): ApplicationCommandExecution<T> {
    const input = validatedCommandInput(options.schema, options.input);
    const identity = this.buildIdentity(options.command_kind, input, options.metadata);
    const retention = commandRetentionSchema.parse(
      options.retention ?? defaultRetention(options.command_kind, identity.transport),
    );
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
            result = commandResult(result);
          } catch (error) {
            domainError = error;
            throw error;
          }
          let recordMetadata: ApplicationCommandRecordMetadata | undefined;
          try {
            recordMetadata = options.record?.(input, result);
            if (recordMetadata?.entity_refs) {
              recordMetadata.entity_refs = commandEntityRefs(recordMetadata.entity_refs);
            }
          } catch (error) {
            domainError = error;
            throw error;
          }
          const record: PersistedApplicationCommandV1 = {
            ...identity,
            command_kind: options.command_kind,
            validated_input: input,
            status: 'succeeded',
            created_at: now,
            started_at: now,
            completed_at: this.engine.now(),
            result,
            ...(recordMetadata?.entity_refs
              ? { entity_refs: recordMetadata.entity_refs }
              : {}),
            action_id: recordMetadata?.action_id ?? identity.action_id,
            frontier_item_id:
              recordMetadata?.frontier_item_id ?? identity.frontier_item_id,
            plan_id: recordMetadata?.plan_id ?? identity.plan_id,
            ...retentionRecordFields(retention),
          };
          const installed = this.engine.recordApplicationCommand(record);
          return executionFromRecord<T>(installed, false);
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
        retention,
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
      retention?: ApplicationCommandRetention;
    },
  ): ApplicationCommandExecution<T> {
    const input = validatedCommandInput(options.schema, options.input);
    const identity = this.buildIdentity(options.command_kind, input, options.metadata);
    const retention = commandRetentionSchema.parse(
      options.retention ?? defaultRetention(options.command_kind, identity.transport),
    );
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
            reserved = {
              ...reserved,
              result: commandResult(reserved.result),
              ...(reserved.entity_refs
                ? {
                    entity_refs: commandEntityRefs(reserved.entity_refs),
                  }
                : {}),
            };
          } catch (error) {
            domainError = error;
            throw error;
          }
          const record: PersistedApplicationCommandV1 = {
            ...identity,
            command_kind: options.command_kind,
            validated_input: input,
            status: reserved.status ?? 'accepted',
            created_at: now,
            ...(reserved.status === 'running' ? { started_at: now } : {}),
            result: reserved.result,
            ...(reserved.entity_refs ? { entity_refs: reserved.entity_refs } : {}),
            action_id: reserved.action_id ?? identity.action_id,
            frontier_item_id: reserved.frontier_item_id ?? identity.frontier_item_id,
            plan_id: reserved.plan_id ?? identity.plan_id,
            ...retentionRecordFields(retention),
          };
          const installed = this.engine.recordApplicationCommand(record);
          return executionFromRecord<T>(installed, false);
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
        retention,
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
      retention?: ApplicationCommandRetention;
    },
  ): Promise<ApplicationCommandExecution<T>> {
    const input = validatedCommandInput(options.schema, options.input);
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
      retention: options.retention,
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
          undefined,
          options.retention,
        );
      }
      if (!TERMINAL_STATUSES.has(requestedTransition.status)) {
        return this.transition<T>(
          identity.command_id,
          {
            status: 'failed',
            error: commandError(new ApplicationCommandTransitionError(
              identity.command_id,
              'running',
              requestedTransition.status,
            )),
          },
          options.completion_state_keys,
          undefined,
          options.retention,
        );
      }
      try {
        requestedTransition = safeCommandTransition(requestedTransition);
      } catch (error) {
        return this.transition<T>(
          identity.command_id,
          {
            status: 'failed',
            error: commandError(error),
          },
          options.completion_state_keys,
          undefined,
          options.retention,
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
        options.retention,
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
    retention?: ApplicationCommandRetention,
  ): ApplicationCommandExecution<T> {
    if (!APPLICATION_COMMAND_STATUSES.has(transition.status)) {
      throw new ApplicationCommandPayloadError(
        `application command transition status is invalid: ${String(transition.status)}`,
        'application command transition status',
        32,
      );
    }
    return this.engine.runApplicationCommandTransaction(
      `transition application command ${commandId} to ${transition.status}`,
      transition.action_id,
      () => {
        const current = this.engine.getApplicationCommandById(commandId);
        if (!current) throw new Error(`Application command not found: ${commandId}`);
        if (TERMINAL_STATUSES.has(current.status)) {
          return executionFromRecord<T>(current, true);
        }
        if (current.status === 'running' && transition.status === 'accepted') {
          throw new ApplicationCommandTransitionError(
            commandId,
            current.status,
            transition.status,
          );
        }
        const safeTransition = safeCommandTransition(transition);
        const now = this.engine.now();
        const safeResult = Object.prototype.hasOwnProperty.call(safeTransition, 'result')
          ? safeTransition.result
          : undefined;
        const safeError = safeTransition.error;
        const safeEntityRefs = safeTransition.entity_refs;
        const parsedRetention = retention
          ? commandRetentionSchema.parse(retention)
          : retentionFromRecord(current);
        const next: PersistedApplicationCommandV1 = {
          ...current,
          status: transition.status,
          ...((transition.status === 'running' || transition.status === 'succeeded')
            && !current.started_at
            ? { started_at: now }
            : {}),
          ...(TERMINAL_STATUSES.has(transition.status) ? { completed_at: now } : {}),
          ...(Object.prototype.hasOwnProperty.call(transition, 'result')
            ? { result: safeResult }
            : {}),
          ...(safeError ? { error: safeError } : {}),
          ...(safeEntityRefs
            ? {
                entity_refs: {
                  ...(current.entity_refs ?? {}),
                  ...safeEntityRefs,
                },
              }
            : {}),
          action_id: transition.action_id ?? current.action_id,
          frontier_item_id: transition.frontier_item_id ?? current.frontier_item_id,
          plan_id: transition.plan_id ?? current.plan_id,
          ...(parsedRetention ? retentionRecordFields(parsedRetention) : {}),
        };
        effects?.();
        const installed = this.engine.recordApplicationCommand(next);
        return executionFromRecord<T>(installed, false);
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
          const next = {
            ...command,
            status: 'interrupted',
            completed_at: this.engine.now(),
            error: { code: 'COMMAND_INTERRUPTED', message: reason },
          } satisfies PersistedApplicationCommandV1;
          this.engine.recordApplicationCommand(next);
          if (command.command_kind === 'operator.plan') {
            const plannerTaskId = command.entity_refs?.planner_task_id;
            if (typeof plannerTaskId === 'string') {
              const task = this.engine.getTask(plannerTaskId);
              if (task?.status === 'running' || task?.status === 'pending') {
                this.engine.updateAgentStatus(plannerTaskId, 'interrupted', reason);
              }
            }
          }
        }
        return unfinished.length;
      },
      ['agents', 'plans_questions', 'approvals', 'activity', 'frontier'],
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
    retention?: ApplicationCommandRetention,
  ): ApplicationCommandExecution<T> {
    const parsedRetention = commandRetentionSchema.parse(
      retention ?? defaultRetention(commandKind, identity.transport),
    );
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
          validated_input: boundedJsonSafe(
            input,
            'application command input',
            MAX_APPLICATION_COMMAND_INPUT_BYTES,
          ),
          status: 'failed',
          created_at: now,
          ...(started ? { started_at: now } : {}),
          completed_at: now,
          error: commandError(error),
          ...retentionRecordFields(parsedRetention),
        };
        const installed = this.engine.recordApplicationCommand(record);
        return executionFromRecord<T>(installed, false);
      },
    );
  }
}
