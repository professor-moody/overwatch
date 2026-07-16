// ============================================================
// Overwatch — canonical approval application command
// ============================================================

import { z } from 'zod';
import type { ActionResolution } from './pending-action-queue.js';
import type { GraphEngine } from './graph-engine.js';
import {
  ApplicationCommandService,
  type ApplicationCommandExecution,
  type ApplicationCommandMetadata,
} from './application-command-service.js';

const ApprovalResolutionInputSchema = z.object({
  action_id: z.string().trim().min(1),
  status: z.enum(['approved', 'denied']),
  note: z.string().optional(),
}).strict();

type ApprovalResolutionInput = z.infer<typeof ApprovalResolutionInputSchema>;

export interface ApprovalCommandResult {
  action_id: string;
  approved: boolean;
  denied: boolean;
  approval: ActionResolution;
}

export class ApprovalCommandError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly http_status: number,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'ApprovalCommandError';
  }
}

export class ApprovalCommandService {
  constructor(
    private readonly engine: GraphEngine,
    private readonly commands: ApplicationCommandService = new ApplicationCommandService(engine),
  ) {}

  approve(
    actionId: string,
    notes?: string,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ApprovalCommandResult> {
    return this.resolve({
      action_id: actionId,
      status: 'approved',
      note: notes,
    }, metadata);
  }

  deny(
    actionId: string,
    reason?: string,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ApprovalCommandResult> {
    return this.resolve({
      action_id: actionId,
      status: 'denied',
      note: reason,
    }, metadata);
  }

  resolve(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ApprovalCommandResult> {
    const input = ApprovalResolutionInputSchema.parse(rawInput);
    const effectiveMetadata: ApplicationCommandMetadata = {
      ...metadata,
      action_id: input.action_id,
    };
    const replay = this.commands.lookup<ApprovalResolutionInput, ApprovalCommandResult>(
      'approval.resolve',
      input,
      effectiveMetadata,
    );
    if (replay) {
      if (replay.status === 'failed' || replay.status === 'interrupted') {
        this.throwExecutionFailure(replay);
      }
      if (replay.result) {
        this.engine.getPendingActionQueue().commitPreparedResolution(replay.result.approval);
      }
      return replay;
    }

    const resolution = this.engine.getPendingActionQueue().prepareResolution(
      input.action_id,
      input.status,
      input.note,
    );
    if (!resolution) {
      const durable = this.engine.getApprovalRequest(input.action_id);
      throw new ApprovalCommandError(
        durable
          ? 'Approval record exists, but no live tool call is waiting for this action.'
          : 'No pending approval record exists for this action.',
        durable ? 'APPROVAL_NOT_LIVE' : 'APPROVAL_NOT_FOUND',
        durable ? 409 : 404,
        { action_id: input.action_id },
      );
    }

    const execution = this.commands.executeSync({
      command_kind: 'approval.resolve',
      input,
      schema: ApprovalResolutionInputSchema,
      metadata: effectiveMetadata,
      state_keys: ['approvals'],
      execute: () => {
        const durable = this.engine.resolveApprovalRequest(resolution);
        if (!durable) {
          throw new ApprovalCommandError(
            'The live approval has no matching durable approval record.',
            'APPROVAL_DURABLE_RECORD_MISSING',
            409,
            { action_id: input.action_id },
          );
        }
        return {
          action_id: input.action_id,
          approved: input.status === 'approved',
          denied: input.status === 'denied',
          approval: resolution,
        };
      },
      record: () => ({
        action_id: input.action_id,
        entity_refs: { action_id: input.action_id },
      }),
    });
    if (execution.status === 'failed' || execution.status === 'interrupted') {
      this.throwExecutionFailure(execution);
    }
    this.engine.getPendingActionQueue().commitPreparedResolution(resolution);
    return execution;
  }

  private throwExecutionFailure(execution: ApplicationCommandExecution<unknown>): never {
    const details = execution.error?.details;
    const record = details && typeof details === 'object' && !Array.isArray(details)
      ? details as Record<string, unknown>
      : {};
    throw new ApprovalCommandError(
      execution.error?.message ?? 'Approval resolution failed.',
      execution.error?.code ?? 'APPROVAL_RESOLUTION_FAILED',
      typeof record.http_status === 'number' ? record.http_status : 409,
      record,
    );
  }
}
