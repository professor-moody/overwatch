// ============================================================
// Overwatch — transport-neutral claim-promotion commands
// ============================================================
// Routes promote_claim through the ApplicationCommandService boundary so the promotion, its
// audit event, and the durable command receipt commit as ONE atomic transaction (via
// engine.promoteClaimApplicationCommand), and a duplicate call with the same idempotency key
// replays the stored receipt instead of restamping. Mirrors GraphCorrectionCommandService.

import { z } from 'zod';
import {
  ApplicationCommandService,
  type ApplicationCommandExecution,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import type {
  GraphEngine,
  ClaimPromotionInput,
  ClaimPromotionResult,
  ClaimWithdrawalInput,
  ClaimWithdrawalResult,
} from './graph-engine.js';
import type { PersistedApplicationCommandV1 } from './persisted-state.js';

/** Validated input to a claim promotion. The node_id/edge_id XOR + non-empty reason are also
 *  enforced by the engine; kept a plain object schema so it flows to recordFailureSync. */
export const PromoteClaimRequestSchema = z.object({
  state: z.enum(['observed', 'validated', 'exploited', 'refuted', 'stale']),
  reason: z.string().trim().min(1),
  node_id: z.string().optional(),
  edge_id: z.string().optional(),
  agent_id: z.string().optional(),
  valid_until: z.string().optional(),
  action_id: z.string().optional(),
});
export type PromoteClaimRequest = z.infer<typeof PromoteClaimRequestSchema>;
export type PromoteClaimResultDto = ClaimPromotionResult;

/** Validated input to a claim withdrawal — clears the effective promotion, reverting to the
 *  derived state. Same target XOR + reason contract as a promotion, minus the promoted standing. */
export const WithdrawClaimRequestSchema = z.object({
  reason: z.string().trim().min(1),
  node_id: z.string().optional(),
  edge_id: z.string().optional(),
  agent_id: z.string().optional(),
  action_id: z.string().optional(),
});
export type WithdrawClaimRequest = z.infer<typeof WithdrawClaimRequestSchema>;
export type WithdrawClaimResultDto = ClaimWithdrawalResult;

export class PromoteClaimCommandError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly http_status: number,
  ) {
    super(message);
    this.name = 'PromoteClaimCommandError';
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
    retry_token: record.idempotency_key,
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

export class PromoteClaimCommandService {
  constructor(
    private readonly engine: GraphEngine,
    private readonly commands = new ApplicationCommandService(engine),
  ) {}

  promote(
    input: PromoteClaimRequest,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<PromoteClaimResultDto> {
    const parsed = PromoteClaimRequestSchema.parse(input);
    const meta = { ...metadata, action_id: metadata.action_id ?? parsed.action_id };
    const replay = this.commands.lookup<typeof parsed, PromoteClaimResultDto>('claim.promote', parsed, meta);
    if (replay) return this.requireSucceeded(replay);
    const identity = this.commands.buildIdentity('claim.promote', parsed, meta);
    const engineInput: ClaimPromotionInput = {
      node_id: parsed.node_id,
      edge_id: parsed.edge_id,
      state: parsed.state,
      reason: parsed.reason,
      by_kind: parsed.agent_id ? 'agent' : 'operator',
      by: parsed.agent_id,
      valid_until: parsed.valid_until,
      action_id: identity.action_id,
    };
    const entityRefs: Record<string, string[]> = parsed.node_id
      ? { node_ids: [parsed.node_id] }
      : { edge_ids: [parsed.edge_id as string] };
    let committed: ReturnType<GraphEngine['promoteClaimApplicationCommand']>;
    try {
      committed = this.engine.promoteClaimApplicationCommand(engineInput, identity.action_id, result => {
        const now = this.engine.now();
        return {
          ...identity,
          command_kind: 'claim.promote',
          validated_input: clone(parsed),
          status: 'succeeded',
          created_at: now,
          started_at: now,
          completed_at: now,
          result: clone(result),
          entity_refs: entityRefs,
        };
      });
    } catch (error) {
      const afterFailure = this.commands.lookup<typeof parsed, PromoteClaimResultDto>('claim.promote', parsed, {
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
      const durableError = error instanceof PromoteClaimCommandError
        ? error
        : new PromoteClaimCommandError(
            error instanceof Error ? error.message : String(error),
            persistenceFailure ? rawCode ?? 'PERSISTENCE_READ_ONLY' : 'CLAIM_PROMOTION_FAILED',
            persistenceFailure ? 503 : 400,
          );
      return this.requireSucceeded(
        this.commands.recordFailureSync({
          command_kind: 'claim.promote',
          input: parsed,
          schema: PromoteClaimRequestSchema,
          metadata: { ...metadata, action_id: identity.action_id },
          error: durableError,
        }),
      );
    }
    return executionFromRecord<PromoteClaimResultDto>(committed.command, false);
  }

  withdraw(
    input: WithdrawClaimRequest,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<WithdrawClaimResultDto> {
    const parsed = WithdrawClaimRequestSchema.parse(input);
    const meta = { ...metadata, action_id: metadata.action_id ?? parsed.action_id };
    const replay = this.commands.lookup<typeof parsed, WithdrawClaimResultDto>('claim.withdraw', parsed, meta);
    if (replay) return this.requireSucceeded(replay);
    const identity = this.commands.buildIdentity('claim.withdraw', parsed, meta);
    const engineInput: ClaimWithdrawalInput = {
      node_id: parsed.node_id,
      edge_id: parsed.edge_id,
      reason: parsed.reason,
      by_kind: parsed.agent_id ? 'agent' : 'operator',
      by: parsed.agent_id,
      action_id: identity.action_id,
    };
    const entityRefs: Record<string, string[]> = parsed.node_id
      ? { node_ids: [parsed.node_id] }
      : { edge_ids: [parsed.edge_id as string] };
    let committed: ReturnType<GraphEngine['withdrawClaimApplicationCommand']>;
    try {
      committed = this.engine.withdrawClaimApplicationCommand(engineInput, identity.action_id, result => {
        const now = this.engine.now();
        return {
          ...identity,
          command_kind: 'claim.withdraw',
          validated_input: clone(parsed),
          status: 'succeeded',
          created_at: now,
          started_at: now,
          completed_at: now,
          result: clone(result),
          entity_refs: entityRefs,
        };
      });
    } catch (error) {
      const afterFailure = this.commands.lookup<typeof parsed, WithdrawClaimResultDto>('claim.withdraw', parsed, {
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
      const durableError = error instanceof PromoteClaimCommandError
        ? error
        : new PromoteClaimCommandError(
            error instanceof Error ? error.message : String(error),
            persistenceFailure ? rawCode ?? 'PERSISTENCE_READ_ONLY' : 'CLAIM_WITHDRAWAL_FAILED',
            persistenceFailure ? 503 : 400,
          );
      return this.requireSucceeded(
        this.commands.recordFailureSync({
          command_kind: 'claim.withdraw',
          input: parsed,
          schema: WithdrawClaimRequestSchema,
          metadata: { ...metadata, action_id: identity.action_id },
          error: durableError,
        }),
      );
    }
    return executionFromRecord<WithdrawClaimResultDto>(committed.command, false);
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
    throw new PromoteClaimCommandError(
      execution.error?.message ?? `Claim promotion command ${execution.command_id} is ${execution.status}.`,
      execution.error?.code ?? 'CLAIM_PROMOTION_NOT_SUCCEEDED',
      httpStatus ?? (execution.status === 'accepted' || execution.status === 'running' ? 409 : 503),
    );
  }
}
