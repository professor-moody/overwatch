// ============================================================
// Overwatch — canonical campaign application commands
// ============================================================

import { z } from 'zod';
import {
  CampaignActionRequestSchema,
  CampaignCreateRequestSchema,
  CampaignSplitRequestSchema,
  CampaignUpdateRequestSchema,
} from '../contracts/dashboard-v1.js';
import type { Campaign } from '../types.js';
import {
  ApplicationCommandService,
  type ApplicationCommandExecution,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import type { GraphEngine } from './graph-engine.js';

const CampaignIdentityInputSchema = z.object({
  campaign_id: z.string().trim().min(1),
}).strict();

const CampaignUpdateCommandInputSchema = z.object({
  campaign_id: z.string().trim().min(1),
  patch: CampaignUpdateRequestSchema,
}).strict();

const CampaignActionCommandInputSchema = z.object({
  campaign_id: z.string().trim().min(1),
  action: CampaignActionRequestSchema.shape.action,
}).strict();

const CampaignSplitCommandInputSchema = z.object({
  campaign_id: z.string().trim().min(1),
  count: CampaignSplitRequestSchema.shape.count.optional(),
}).strict();

export class CampaignCommandError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly http_status: number,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'CampaignCommandError';
  }
}

export interface CampaignCreateResult {
  campaign: Campaign;
}

export interface CampaignUpdateResult {
  campaign: Campaign;
}

export interface CampaignActionResult {
  action: 'activate' | 'pause' | 'resume' | 'abort';
  campaign: Campaign;
}

export interface CampaignCloneResult {
  campaign: Campaign;
}

export interface CampaignDeleteResult {
  deleted: true;
  campaign_id: string;
}

export interface CampaignSplitResult {
  parent_id: string;
  children: Campaign[];
  count: number;
}

export class CampaignCommandService {
  constructor(
    private readonly engine: GraphEngine,
    private readonly commands: ApplicationCommandService = new ApplicationCommandService(engine),
  ) {}

  create(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<CampaignCreateResult> {
    const execution = this.commands.executeSync({
      command_kind: 'campaign.create',
      input: rawInput,
      schema: CampaignCreateRequestSchema,
      metadata,
      state_keys: ['campaigns'],
      execute: input => ({
        campaign: this.engine.createCampaign(input),
      }),
      record: (_input, result) => ({
        entity_refs: { campaign_id: result.campaign.id },
      }),
    });
    return this.requireSucceeded(execution);
  }

  update(
    campaignId: string,
    rawPatch: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<CampaignUpdateResult> {
    const input = CampaignUpdateCommandInputSchema.parse({
      campaign_id: campaignId,
      patch: rawPatch,
    });
    const replay = this.commands.lookup<
      typeof input,
      CampaignUpdateResult
    >('campaign.update', input, metadata);
    if (replay) return this.requireSucceeded(replay);
    this.requireCampaign(input.campaign_id);
    const execution = this.commands.executeSync({
      command_kind: 'campaign.update',
      input,
      schema: CampaignUpdateCommandInputSchema,
      metadata,
      state_keys: ['campaigns'],
      execute: parsed => {
        const campaign = this.engine.updateCampaign(
          parsed.campaign_id,
          parsed.patch,
        );
        if (!campaign) {
          throw this.notFound(parsed.campaign_id);
        }
        return { campaign };
      },
      record: () => ({
        entity_refs: { campaign_id: input.campaign_id },
      }),
    });
    return this.requireSucceeded(execution);
  }

  action(
    campaignId: string,
    rawAction: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<CampaignActionResult> {
    const parsedAction = CampaignActionRequestSchema.parse(rawAction);
    const input = CampaignActionCommandInputSchema.parse({
      campaign_id: campaignId,
      action: parsedAction.action,
    });
    const replay = this.commands.lookup<
      typeof input,
      CampaignActionResult
    >('campaign.action', input, metadata);
    if (replay) return this.requireSucceeded(replay);
    this.requireCampaign(input.campaign_id);
    const execution = this.commands.executeSync({
      command_kind: 'campaign.action',
      input,
      schema: CampaignActionCommandInputSchema,
      metadata,
      state_keys: input.action === 'abort'
        ? [
            'campaigns',
            'agents',
            'plans_questions',
            'approvals',
            'activity',
            'frontier',
          ]
        : ['campaigns'],
      execute: parsed => {
        const campaign = this.applyAction(parsed.campaign_id, parsed.action);
        if (!campaign) {
          throw new CampaignCommandError(
            `Failed to ${parsed.action} campaign`,
            'CAMPAIGN_ACTION_NOT_APPLICABLE',
            409,
            {
              campaign_id: parsed.campaign_id,
              action: parsed.action,
            },
          );
        }
        return { action: parsed.action, campaign };
      },
      record: () => ({
        entity_refs: { campaign_id: input.campaign_id },
      }),
    });
    return this.requireSucceeded(execution);
  }

  clone(
    campaignId: string,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<CampaignCloneResult> {
    const input = CampaignIdentityInputSchema.parse({ campaign_id: campaignId });
    const replay = this.commands.lookup<
      typeof input,
      CampaignCloneResult
    >('campaign.clone', input, metadata);
    if (replay) return this.requireSucceeded(replay);
    this.requireCampaign(input.campaign_id);
    const execution = this.commands.executeSync({
      command_kind: 'campaign.clone',
      input,
      schema: CampaignIdentityInputSchema,
      metadata,
      state_keys: ['campaigns'],
      execute: parsed => {
        const campaign = this.engine.cloneCampaign(parsed.campaign_id);
        if (!campaign) throw this.notFound(parsed.campaign_id);
        return { campaign };
      },
      record: (_parsed, result) => ({
        entity_refs: {
          source_campaign_id: input.campaign_id,
          campaign_id: result.campaign.id,
        },
      }),
    });
    return this.requireSucceeded(execution);
  }

  delete(
    campaignId: string,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<CampaignDeleteResult> {
    const input = CampaignIdentityInputSchema.parse({ campaign_id: campaignId });
    const replay = this.commands.lookup<
      typeof input,
      CampaignDeleteResult
    >('campaign.delete', input, metadata);
    if (replay) return this.requireSucceeded(replay);
    this.requireCampaign(input.campaign_id);
    const execution = this.commands.executeSync({
      command_kind: 'campaign.delete',
      input,
      schema: CampaignIdentityInputSchema,
      metadata,
      state_keys: ['campaigns'],
      execute: parsed => {
        if (!this.engine.deleteCampaign(parsed.campaign_id)) {
          throw this.notFound(parsed.campaign_id);
        }
        return {
          deleted: true as const,
          campaign_id: parsed.campaign_id,
        };
      },
      record: () => ({
        entity_refs: { campaign_id: input.campaign_id },
      }),
    });
    return this.requireSucceeded(execution);
  }

  split(
    campaignId: string,
    count?: number,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<CampaignSplitResult> {
    const input = CampaignSplitCommandInputSchema.parse({
      campaign_id: campaignId,
      count,
    });
    const replay = this.commands.lookup<
      typeof input,
      CampaignSplitResult
    >('campaign.split', input, metadata);
    if (replay) return this.requireSucceeded(replay);
    const parent = this.requireCampaign(input.campaign_id);
    if (input.count !== undefined && input.count > parent.items.length) {
      throw new CampaignCommandError(
        'Split count cannot exceed campaign item count',
        'CAMPAIGN_SPLIT_COUNT_EXCEEDS_ITEMS',
        400,
        {
          campaign_id: input.campaign_id,
          count: input.count,
          item_count: parent.items.length,
        },
      );
    }
    const execution = this.commands.executeSync({
      command_kind: 'campaign.split',
      input,
      schema: CampaignSplitCommandInputSchema,
      metadata,
      state_keys: ['campaigns', 'agents'],
      execute: parsed => {
        const children = this.engine.splitCampaign(
          parsed.campaign_id,
          parsed.count,
        );
        if (!children) {
          throw new CampaignCommandError(
            `Campaign ${parsed.campaign_id} cannot be split in its current state`,
            'CAMPAIGN_SPLIT_NOT_APPLICABLE',
            409,
            { campaign_id: parsed.campaign_id },
          );
        }
        return {
          parent_id: parsed.campaign_id,
          children,
          count: children.length,
        };
      },
      record: (_parsed, result) => ({
        entity_refs: {
          campaign_id: input.campaign_id,
          child_campaign_id: result.children.map(child => child.id),
        },
      }),
    });
    return this.requireSucceeded(execution);
  }

  private applyAction(
    campaignId: string,
    action: CampaignActionResult['action'],
  ): Campaign | null {
    switch (action) {
      case 'activate':
        return this.engine.activateCampaign(campaignId);
      case 'pause':
        return this.engine.pauseCampaign(campaignId);
      case 'resume':
        return this.engine.resumeCampaign(campaignId);
      case 'abort':
        return this.engine.abortCampaign(campaignId);
    }
  }

  private requireCampaign(campaignId: string): Campaign {
    const campaign = this.engine.getCampaign(campaignId);
    if (!campaign) throw this.notFound(campaignId);
    return campaign;
  }

  private notFound(campaignId: string): CampaignCommandError {
    return new CampaignCommandError(
      `Campaign not found: ${campaignId}`,
      'CAMPAIGN_NOT_FOUND',
      404,
      { campaign_id: campaignId },
    );
  }

  private requireSucceeded<T>(
    execution: ApplicationCommandExecution<T>,
  ): ApplicationCommandExecution<T> {
    if (execution.status !== 'failed' && execution.status !== 'interrupted') {
      return execution;
    }
    const details = execution.error?.details;
    const record = details && typeof details === 'object' && !Array.isArray(details)
      ? details as Record<string, unknown>
      : {};
    throw new CampaignCommandError(
      execution.error?.message ?? 'Campaign command failed.',
      execution.error?.code ?? 'CAMPAIGN_COMMAND_FAILED',
      typeof record.http_status === 'number' ? record.http_status : 409,
      record,
    );
  }
}
