// ============================================================
// Overwatch — replay-safe boundary for external mutation adapters
// ============================================================

import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { GraphEngine } from './graph-engine.js';
import {
  ApplicationCommandService,
  type ApplicationCommandExecution,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import { canonicalJson } from './engagement-config-service.js';

const MAX_REPLAY_RESPONSE_BYTES = 64 * 1024 * 1024;
const INLINE_REPLAY_RESPONSE_BYTES = 64 * 1024;

const ExternalMutationDescriptorSchema = z.object({
  operation_id: z.string().trim().min(1).max(256),
  request_fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();

const ExternalMutationResultSchema = z.object({
  storage: z.enum(['inline', 'evidence']),
  response_bytes: z.number().int().nonnegative(),
  response_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  response: z.unknown().optional(),
  response_evidence_id: z.string().min(1).optional(),
}).strict();

type PersistedExternalMutationResult =
  | {
      storage: 'inline';
      response_bytes: number;
      response_sha256: string;
      response: unknown;
    }
  | {
      storage: 'evidence';
      response_bytes: number;
      response_sha256: string;
      response_evidence_id: string;
    };

export interface ExternalMutationDescriptor {
  operation_id: string;
  request_fingerprint: string;
}

export interface ExternalMutationCommandResult<T> {
  command_id: string;
  retry_token: string;
  idempotency_key: string;
  status: ApplicationCommandExecution<unknown>['status'];
  replayed: boolean;
  response?: T;
  error?: ApplicationCommandExecution<unknown>['error'];
  delivery_error?: ApplicationCommandExecution<unknown>['error'];
}

export function buildExternalMutationFingerprint(input: unknown): string {
  return createHash('sha256').update(canonicalJson(input)).digest('hex');
}

function responseFilename(operationId: string): string {
  const safe = operationId.replace(/[^a-zA-Z0-9._-]+/g, '-').slice(0, 96);
  return `${safe || 'external-mutation'}-response.json`;
}

/**
 * Durable middleware for public mutation adapters that have not yet moved all
 * orchestration into one domain-specific command service. It reserves before
 * invoking the adapter and publishes the exact wire response as evidence
 * before the terminal command transition. A lost response or daemon restart
 * therefore cannot turn the same command identity into a second mutation.
 *
 * Domain-specific command services may execute inside this outer boundary.
 * Callers give this boundary a derived command identity, leaving the public
 * identity available to the inner service without collision.
 */
export class ExternalMutationCommandService {
  private readonly commands: ApplicationCommandService;

  constructor(private readonly engine: GraphEngine) {
    this.commands = new ApplicationCommandService(engine);
  }

  async execute<T>(options: {
    descriptor: ExternalMutationDescriptor;
    metadata?: ApplicationCommandMetadata;
    operation: () => Promise<T> | T;
  }): Promise<ExternalMutationCommandResult<T>> {
    let liveResponse: T | undefined;
    const commandKind = `external.${options.descriptor.operation_id}`;
    const identity = this.commands.buildIdentity(
      commandKind,
      options.descriptor,
      options.metadata,
    );
    let execution: ApplicationCommandExecution<unknown>;
    try {
      execution = await this.commands.executeAsync<
        z.infer<typeof ExternalMutationDescriptorSchema>,
        PersistedExternalMutationResult
      >({
        command_kind: commandKind,
        input: options.descriptor,
        schema: ExternalMutationDescriptorSchema,
        metadata: {
          ...options.metadata,
          command_id: identity.command_id,
        },
        reserve: () => ({
          result: { reserved: true },
        }),
        execute: async (_descriptor, command) => {
        liveResponse = await options.operation();
        const serialized = JSON.stringify(liveResponse);
        if (serialized === undefined) {
          return {
            status: 'failed',
            error: {
              code: 'COMMAND_RESPONSE_INVALID',
              message: 'The external mutation returned no JSON-serializable response.',
            },
          };
        }
        const responseBytes = Buffer.byteLength(serialized);
        if (responseBytes > MAX_REPLAY_RESPONSE_BYTES) {
          return {
            status: 'failed',
            error: {
              code: 'COMMAND_RESPONSE_TOO_LARGE',
              message: `The external mutation response is ${responseBytes} bytes; the replay limit is ${MAX_REPLAY_RESPONSE_BYTES} bytes.`,
            },
          };
        }
        const responseSha256 = createHash('sha256').update(serialized).digest('hex');
        if (responseBytes <= INLINE_REPLAY_RESPONSE_BYTES) {
          return {
            status: 'succeeded',
            result: {
              storage: 'inline',
              response_bytes: responseBytes,
              response_sha256: responseSha256,
              response: JSON.parse(serialized),
            },
          };
        }
        let responseEvidenceId: string;
        try {
          responseEvidenceId = this.engine.getEvidenceStore().store({
            action_id: command.action_id,
            task_id: command.actor_task_id ?? undefined,
            evidence_type: 'log',
            filename: responseFilename(options.descriptor.operation_id),
            content: serialized,
          });
        } catch (error) {
          return {
            status: 'failed',
            error: {
              code: 'COMMAND_RESPONSE_PERSIST_FAILED',
              message:
                'The external mutation completed, but its replay response could not be persisted.',
              details: {
                cause: error instanceof Error ? error.message : String(error),
              },
            },
          };
        }
        return {
          status: 'succeeded',
          result: {
            storage: 'evidence',
            response_evidence_id: responseEvidenceId,
            response_bytes: responseBytes,
            response_sha256: responseSha256,
          },
          entity_refs: { evidence_ids: [responseEvidenceId] },
        };
        },
      });
    } catch (error) {
      const record = this.engine.getApplicationCommand(identity.idempotency_key);
      if (liveResponse !== undefined && record) {
        return {
          command_id: record.command_id,
          retry_token: record.idempotency_key,
          idempotency_key: record.idempotency_key,
          status: record.status,
          replayed: false,
          response: liveResponse,
          delivery_error: {
            code: 'COMMAND_TERMINAL_PERSIST_FAILED',
            message: error instanceof Error ? error.message : String(error),
          },
        };
      }
      throw error;
    }

    if (execution.status !== 'succeeded') {
      return {
        command_id: execution.command_id,
        retry_token: execution.retry_token,
        idempotency_key: execution.idempotency_key,
        status: execution.status,
        replayed: execution.replayed,
        error: execution.error,
      };
    }
    if (liveResponse !== undefined) {
      return {
        command_id: execution.command_id,
        retry_token: execution.retry_token,
        idempotency_key: execution.idempotency_key,
        status: execution.status,
        replayed: execution.replayed,
        response: liveResponse,
      };
    }

    const persisted = ExternalMutationResultSchema.safeParse(execution.result);
    if (!persisted.success || persisted.data.response_bytes > MAX_REPLAY_RESPONSE_BYTES) {
      return {
        command_id: execution.command_id,
        retry_token: execution.retry_token,
        idempotency_key: execution.idempotency_key,
        status: execution.status,
        replayed: true,
        delivery_error: {
          code: 'COMMAND_RESPONSE_INVALID',
          message: 'The durable external mutation response reference is invalid or too large.',
        },
      };
    }
    if (persisted.data.storage === 'inline') {
      const serialized = JSON.stringify(persisted.data.response);
      if (
        Buffer.byteLength(serialized) !== persisted.data.response_bytes
        || createHash('sha256').update(serialized).digest('hex')
          !== persisted.data.response_sha256
      ) {
        return {
          command_id: execution.command_id,
          retry_token: execution.retry_token,
          idempotency_key: execution.idempotency_key,
          status: execution.status,
          replayed: true,
          delivery_error: {
            code: 'COMMAND_RESPONSE_UNAVAILABLE',
            message: 'The inline durable external mutation response failed its integrity check.',
          },
        };
      }
      return {
        command_id: execution.command_id,
        retry_token: execution.retry_token,
        idempotency_key: execution.idempotency_key,
        status: execution.status,
        replayed: true,
        response: persisted.data.response as T,
      };
    }
    if (!persisted.data.response_evidence_id) {
      return {
        command_id: execution.command_id,
        retry_token: execution.retry_token,
        idempotency_key: execution.idempotency_key,
        status: execution.status,
        replayed: true,
        delivery_error: {
          code: 'COMMAND_RESPONSE_INVALID',
          message: 'The durable external mutation response artifact reference is missing.',
        },
      };
    }
    try {
      const serialized = this.engine.getEvidenceStore().getContent(
        persisted.data.response_evidence_id,
        { max_bytes: MAX_REPLAY_RESPONSE_BYTES },
      );
      if (
        serialized === null
        || Buffer.byteLength(serialized) !== persisted.data.response_bytes
        || createHash('sha256').update(serialized).digest('hex')
          !== persisted.data.response_sha256
      ) {
        throw new Error('response artifact is missing or failed its integrity check');
      }
      return {
        command_id: execution.command_id,
        retry_token: execution.retry_token,
        idempotency_key: execution.idempotency_key,
        status: execution.status,
        replayed: true,
        response: JSON.parse(serialized) as T,
      };
    } catch (error) {
      return {
        command_id: execution.command_id,
        retry_token: execution.retry_token,
        idempotency_key: execution.idempotency_key,
        status: execution.status,
        replayed: true,
        delivery_error: {
          code: 'COMMAND_RESPONSE_UNAVAILABLE',
          message: `The original mutation completed, but its response cannot be replayed: ${error instanceof Error ? error.message : String(error)}`,
        },
      };
    }
  }
}
