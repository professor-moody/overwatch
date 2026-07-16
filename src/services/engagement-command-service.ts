// ============================================================
// Overwatch — transport-neutral engagement/config commands
// ============================================================

import { randomUUID } from 'node:crypto';
import { z, type ZodType } from 'zod';
import {
  ObjectiveCreateRequestSchema,
  ObjectiveUpdateRequestSchema,
  SettingsPatchSchema,
} from '../contracts/dashboard-v1.js';
import {
  engagementConfigSchema,
  type EngagementConfig,
} from '../types.js';
import {
  ApplicationCommandService,
  type ApplicationCommandExecution,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import { mergeConfig } from './config-manager.js';
import {
  configsSemanticallyEqual,
} from './engagement-config-service.js';
import type { GraphEngine } from './graph-engine.js';
import type { PersistedApplicationCommandV1 } from './persisted-state.js';

const ConfigPatchInputSchema = z.record(z.unknown());

const ScopeReplacementInputSchema = z.object({
  cidrs: z.array(z.string()).optional(),
  domains: z.array(z.string()).optional(),
  exclusions: z.array(z.string()).optional(),
  hosts: z.array(z.string()).optional(),
  url_patterns: z.array(z.string()).optional(),
  aws_accounts: z.array(z.string()).optional(),
  azure_subscriptions: z.array(z.string()).optional(),
  gcp_projects: z.array(z.string()).optional(),
  cross_tier_links: z.array(z.unknown()).optional(),
}).strict();

const ScopeChangeInputSchema = z.object({
  add_cidrs: z.array(z.string()).optional(),
  remove_cidrs: z.array(z.string()).optional(),
  add_domains: z.array(z.string()).optional(),
  remove_domains: z.array(z.string()).optional(),
  add_exclusions: z.array(z.string()).optional(),
  remove_exclusions: z.array(z.string()).optional(),
  reason: z.string().trim().min(1),
}).strict();

const ObjectiveUpdateCommandSchema = z.object({
  objective_id: z.string().trim().min(1),
  updates: ObjectiveUpdateRequestSchema,
}).strict();

const ObjectiveDeleteCommandSchema = z.object({
  objective_id: z.string().trim().min(1),
}).strict();

const OpsecCommandSchema = z.object({
  patch: SettingsPatchSchema,
  reason: z.string().trim().min(1),
}).strict();

export class EngagementCommandError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly http_status: number,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'EngagementCommandError';
  }
}

export interface ConfigPatchResult {
  updated: boolean;
  config: EngagementConfig;
}

export interface SettingsPatchResult {
  updated: boolean;
  opsec: EngagementConfig['opsec'];
}

export interface OpsecCommandResult {
  applied: true;
  reason: string;
  before: Partial<EngagementConfig['opsec']>;
  after: Partial<EngagementConfig['opsec']>;
  weakening_warnings?: string[];
}

export interface ScopeCommandResult {
  updated: true;
  applied: true;
  scope: EngagementConfig['scope'];
  before: EngagementConfig['scope'];
  after: EngagementConfig['scope'];
  affected_node_count: number;
}

export interface ObjectiveCreateResult {
  created: true;
  objective: EngagementConfig['objectives'][number];
}

export interface ObjectiveUpdateResult {
  updated: true;
  objective: EngagementConfig['objectives'][number];
}

export interface ObjectiveDeleteResult {
  deleted: true;
  objective_id: string;
}

function jsonClone<T>(value: T): T {
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
      ? { result: jsonClone(record.result) as T }
      : {}),
    ...(record.error ? { error: jsonClone(record.error) } : {}),
    record: jsonClone(record),
  };
}

export class EngagementCommandService {
  constructor(
    private readonly engine: GraphEngine,
    private readonly commands = new ApplicationCommandService(engine),
  ) {}

  patchConfig(
    partial: Record<string, unknown>,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ConfigPatchResult> {
    const sanitized = jsonClone(
      ConfigPatchInputSchema.parse(partial),
    ) as Record<string, unknown>;
    delete sanitized.id;
    delete sanitized.created_at;
    delete sanitized.config_revision;
    delete sanitized.config_hash;
    return this.commitConfigCommand(
      'engagement.config.patch',
      sanitized,
      ConfigPatchInputSchema,
      metadata,
      current => mergeConfig(current, sanitized),
      (current, committed) => ({
        updated: !configsSemanticallyEqual(current, committed),
        config: committed,
      }),
    );
  }

  previewScope(replacement: unknown): ReturnType<GraphEngine['previewScopeConfig']> {
    const input = ScopeReplacementInputSchema.parse(replacement);
    const current = this.engine.getConfig();
    const desired = mergeConfig(current, {
      scope: {
        ...current.scope,
        ...input,
      },
    });
    return this.engine.previewScopeConfig(desired.scope);
  }

  updateSettings(
    patch: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<SettingsPatchResult> {
    const input = SettingsPatchSchema.parse(patch);
    return this.commitConfigCommand(
      'engagement.settings.patch',
      input,
      SettingsPatchSchema,
      metadata,
      current => {
        const opsec = jsonClone(current.opsec);
        if (input.enabled !== undefined) opsec.enabled = input.enabled;
        if (input.max_noise !== undefined) opsec.max_noise = input.max_noise;
        if (input.approval_mode !== undefined) {
          opsec.approval_mode = input.approval_mode;
        }
        if (input.approval_timeout_ms !== undefined) {
          opsec.approval_timeout_ms = input.approval_timeout_ms;
        }
        if (input.blacklisted_techniques !== undefined) {
          opsec.blacklisted_techniques = input.blacklisted_techniques;
        }
        if (input.time_window !== undefined) {
          opsec.time_window = input.time_window ?? undefined;
        }
        return mergeConfig(current, {
          opsec: input.time_window === null
            ? { ...opsec, time_window: null }
            : opsec,
        });
      },
      (current, committed) => ({
        updated: !configsSemanticallyEqual(current, committed),
        opsec: committed.opsec,
      }),
    );
  }

  updateOpsec(
    patch: unknown,
    reason: string,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<OpsecCommandResult> {
    const input = OpsecCommandSchema.parse({ patch, reason });
    const currentOpsec = this.engine.getConfig().opsec;
    const before = opsecPublicFields(currentOpsec);
    const warnings = opsecWeakeningWarnings(before, input.patch);
    return this.commitConfigCommand(
      'engagement.opsec.update',
      input,
      OpsecCommandSchema,
      metadata,
      current => {
        const opsec = jsonClone(current.opsec);
        if (input.patch.enabled !== undefined) {
          opsec.enabled = input.patch.enabled;
        }
        if (input.patch.max_noise !== undefined) {
          opsec.max_noise = input.patch.max_noise;
        }
        if (input.patch.approval_mode !== undefined) {
          opsec.approval_mode = input.patch.approval_mode;
        }
        if (input.patch.approval_timeout_ms !== undefined) {
          opsec.approval_timeout_ms = input.patch.approval_timeout_ms;
        }
        if (input.patch.blacklisted_techniques !== undefined) {
          opsec.blacklisted_techniques =
            input.patch.blacklisted_techniques;
        }
        if (input.patch.time_window !== undefined) {
          opsec.time_window = input.patch.time_window ?? undefined;
        }
        return mergeConfig(current, {
          opsec: input.patch.time_window === null
            ? { ...opsec, time_window: null }
            : opsec,
        });
      },
      (_current, committed) => ({
        applied: true,
        reason: input.reason,
        before,
        after: opsecPublicFields(committed.opsec),
        ...(warnings.length > 0
          ? { weakening_warnings: warnings }
          : {}),
      }),
      {},
      `opsec.update:${input.reason}`,
    );
  }

  replaceScope(
    replacement: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ScopeCommandResult> {
    const input = ScopeReplacementInputSchema.parse(replacement);
    return this.commitConfigCommand(
      'engagement.scope.replace',
      input,
      ScopeReplacementInputSchema,
      metadata,
      current => mergeConfig(current, {
        scope: {
          ...current.scope,
          ...input,
        },
      }),
      (_current, committed, scope) => ({
        updated: true,
        applied: true,
        scope: committed.scope,
        before: scope.before,
        after: scope.after,
        affected_node_count: scope.affected_node_count,
      }),
      {},
      metadata.transport === 'dashboard'
        ? 'dashboard scope update'
        : 'engagement.scope.replace',
    );
  }

  updateScope(
    changes: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ScopeCommandResult> {
    const input = ScopeChangeInputSchema.parse(changes);
    return this.commitConfigCommand(
      'engagement.scope.update',
      input,
      ScopeChangeInputSchema,
      metadata,
      current => {
        const next = jsonClone(current.scope);
        addUnique(next.cidrs, input.add_cidrs);
        next.cidrs = removeValues(next.cidrs, input.remove_cidrs);
        addUnique(next.domains, input.add_domains);
        next.domains = removeValues(next.domains, input.remove_domains);
        addUnique(next.exclusions, input.add_exclusions);
        next.exclusions = removeValues(
          next.exclusions,
          input.remove_exclusions,
        );
        return mergeConfig(current, { scope: next });
      },
      (_current, committed, scope) => ({
        updated: true,
        applied: true,
        scope: committed.scope,
        before: scope.before,
        after: scope.after,
        affected_node_count: scope.affected_node_count,
      }),
    );
  }

  addObjective(
    objective: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ObjectiveCreateResult> {
    const input = ObjectiveCreateRequestSchema.parse(objective);
    const replay = this.commands.lookup<
      typeof input,
      ObjectiveCreateResult
    >('engagement.objective.add', input, metadata);
    if (replay) return this.requireSucceeded(replay);
    const objectiveId = randomUUID();
    return this.commitConfigCommand(
      'engagement.objective.add',
      input,
      ObjectiveCreateRequestSchema,
      metadata,
      current => mergeConfig(current, {
        objectives: [
          ...current.objectives,
          {
            id: objectiveId,
            description: input.description,
            target_node_type: input.target_node_type,
            target_criteria: input.target_criteria,
            achievement_edge_types: input.achievement_edge_types,
            achieved: false,
          },
        ],
      }),
      (_current, committed) => ({
        created: true,
        objective: committed.objectives.find(
          candidate => candidate.id === objectiveId,
        )!,
      }),
      { objective_id: objectiveId },
    );
  }

  updateObjective(
    objectiveId: string,
    updates: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ObjectiveUpdateResult> {
    const input = ObjectiveUpdateCommandSchema.parse({
      objective_id: objectiveId,
      updates,
    });
    return this.commitConfigCommand(
      'engagement.objective.update',
      input,
      ObjectiveUpdateCommandSchema,
      metadata,
      current => {
        const index = current.objectives.findIndex(
          objective => objective.id === input.objective_id,
        );
        if (index < 0) {
          throw new EngagementCommandError(
            'Objective not found.',
            'OBJECTIVE_NOT_FOUND',
            404,
          );
        }
        const objectives = jsonClone(current.objectives);
        const objective = objectives[index];
        if (input.updates.description !== undefined) {
          objective.description = input.updates.description;
        }
        if (input.updates.target_node_type !== undefined) {
          objective.target_node_type = input.updates.target_node_type;
        }
        if (input.updates.target_criteria !== undefined) {
          objective.target_criteria = input.updates.target_criteria;
        }
        if (input.updates.achievement_edge_types !== undefined) {
          objective.achievement_edge_types =
            input.updates.achievement_edge_types;
        }
        if (input.updates.achieved !== undefined) {
          objective.achieved = input.updates.achieved;
          objective.achieved_at = input.updates.achieved
            ? this.engine.now()
            : undefined;
        }
        return mergeConfig(current, { objectives });
      },
      (_current, committed) => ({
        updated: true,
        objective: committed.objectives.find(
          objective => objective.id === input.objective_id,
        )!,
      }),
      { objective_id: input.objective_id },
    );
  }

  deleteObjective(
    objectiveId: string,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ObjectiveDeleteResult> {
    const input = ObjectiveDeleteCommandSchema.parse({
      objective_id: objectiveId,
    });
    return this.commitConfigCommand(
      'engagement.objective.delete',
      input,
      ObjectiveDeleteCommandSchema,
      metadata,
      current => {
        if (!current.objectives.some(
          objective => objective.id === input.objective_id,
        )) {
          throw new EngagementCommandError(
            'Objective not found.',
            'OBJECTIVE_NOT_FOUND',
            404,
          );
        }
        return mergeConfig(current, {
          objectives: current.objectives.filter(
            objective => objective.id !== input.objective_id,
          ),
        });
      },
      () => ({
        deleted: true,
        objective_id: input.objective_id,
      }),
      { objective_id: input.objective_id },
    );
  }

  private commitConfigCommand<I, T>(
    commandKind: string,
    input: I,
    schema: ZodType<I, z.ZodTypeDef, unknown>,
    metadata: ApplicationCommandMetadata,
    buildConfig: (current: EngagementConfig) => EngagementConfig,
    buildResult: (
      current: EngagementConfig,
      committed: EngagementConfig,
      scope: {
        before: EngagementConfig['scope'];
        after: EngagementConfig['scope'];
        affected_node_count: number;
      },
    ) => T,
    entityRefs: Record<string, string | string[]> = {},
    source = commandKind,
  ): ApplicationCommandExecution<T> {
    const parsed = schema.parse(input);
    const replay = this.commands.lookup<I, T>(
      commandKind,
      parsed,
      metadata,
    );
    if (replay) return this.requireSucceeded(replay);
    const identity = this.commands.buildIdentity(
      commandKind,
      parsed,
      metadata,
    );
    let committed: ReturnType<GraphEngine['commitConfigApplicationCommand']>;
    try {
      const current = this.engine.getConfig();
      const desired = engagementConfigSchema.parse(buildConfig(current));
      committed = this.engine.commitConfigApplicationCommand(
        desired,
        source,
        identity.action_id,
        (target, scope) => {
          const result = buildResult(current, target, scope);
          return this.succeededRecord(
            identity,
            commandKind,
            parsed,
            result,
            entityRefs,
          );
        },
      );
    } catch (error) {
      const afterFailure = this.commands.lookup<I, T>(
        commandKind,
        parsed,
        metadata,
      );
      if (afterFailure) return this.requireSucceeded(afterFailure);
      const coded = typeof (error as { code?: unknown } | null)?.code === 'string'
        || typeof (error as { http_status?: unknown } | null)?.http_status === 'number';
      if (!coded || !this.engine.isPersistenceWritable()) throw error;
      return this.requireSucceeded(
        this.commands.recordFailureSync({
          command_kind: commandKind,
          input: parsed,
          schema,
          metadata,
          error,
        }),
      );
    }
    return executionFromRecord<T>(committed.command, false);
  }

  private succeededRecord<I, T>(
    identity: ReturnType<ApplicationCommandService['buildIdentity']>,
    commandKind: string,
    input: I,
    result: T,
    entityRefs: Record<string, string | string[]>,
  ): PersistedApplicationCommandV1 {
    const now = this.engine.now();
    return {
      ...identity,
      command_kind: commandKind,
      validated_input: jsonClone(input),
      status: 'succeeded',
      created_at: now,
      started_at: now,
      completed_at: now,
      result: jsonClone(result),
      ...(Object.keys(entityRefs).length > 0
        ? { entity_refs: jsonClone(entityRefs) }
        : {}),
    };
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
    const code = execution.error?.code;
    const codedStatus = code === 'CONFIG_HASH_CONFLICT'
      ? 409
      : code === 'OBJECTIVE_NOT_FOUND'
        ? 404
        : code === 'ENGAGEMENT_VALIDATION_FAILED'
          ? 400
          : undefined;
    throw new EngagementCommandError(
      execution.error?.message
        ?? `Engagement command ${execution.command_id} is ${execution.status}.`,
      code ?? 'ENGAGEMENT_COMMAND_NOT_SUCCEEDED',
      httpStatus
        ?? codedStatus
        ?? (execution.status === 'accepted' || execution.status === 'running'
          ? 409
          : 503),
    );
  }
}

function addUnique(target: string[], values: string[] | undefined): void {
  for (const value of values ?? []) {
    if (!target.includes(value)) target.push(value);
  }
}

function removeValues(target: string[], values: string[] | undefined): string[] {
  if (!values?.length) return target;
  return target.filter(value => !values.includes(value));
}

function opsecPublicFields(
  opsec: EngagementConfig['opsec'],
): Partial<EngagementConfig['opsec']> {
  return {
    enabled: opsec.enabled,
    max_noise: opsec.max_noise,
    approval_mode: opsec.approval_mode,
    approval_timeout_ms: opsec.approval_timeout_ms,
    time_window: opsec.time_window,
    blacklisted_techniques: opsec.blacklisted_techniques,
  };
}

function opsecWeakeningWarnings(
  before: Partial<EngagementConfig['opsec']>,
  patch: z.infer<typeof SettingsPatchSchema>,
): string[] {
  const warnings: string[] = [];
  if (
    patch.max_noise !== undefined
    && patch.max_noise > (before.max_noise ?? 0)
  ) {
    warnings.push(
      `max_noise raised ${before.max_noise} → ${patch.max_noise} (louder ceiling).`,
    );
  }
  if (patch.enabled === false && before.enabled !== false) {
    warnings.push(
      'OPSEC enforcement DISABLED — actions will not be noise/scope-vetoed.',
    );
  }
  if (
    patch.approval_mode === 'auto-approve'
    && before.approval_mode !== 'auto-approve'
  ) {
    warnings.push(
      'approval_mode → auto-approve — no operator gate on actions.',
    );
  }
  return warnings;
}
