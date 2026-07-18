// ============================================================
// Overwatch — operator plans and command confirmation
// ============================================================

import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { ActionResolution } from './pending-action-queue.js';
import type { GraphEngine } from './graph-engine.js';
import {
  ApplicationCommandConflictError,
  ApplicationCommandService,
  getApplicationCommandInvocation,
  type ApplicationCommandExecution,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import {
  DispatchCommandService,
  type AgentDispatchInput,
} from './dispatch-command-service.js';
import {
  buildPlannerObjective,
  type InterpreterState,
  type OperatorOp,
  type OpResult,
} from './command-interpreter.js';
import type { PersistedApplicationCommandV1 } from './persisted-state.js';
import type { ProposedPlan } from './proposed-plan-store.js';
import { OperatorOpsSchema } from './operator-op-schema.js';
import {
  getArchetype,
  isArchetypeId,
  recommendExploreArchetype,
} from './agent-archetypes.js';
import {
  mergeScopeAdds,
  previewScopeChange,
  type ScopePreview,
} from './scope-preview.js';
import type { AgentDirectiveKind } from '../types.js';

const ConfirmPlanInputSchema = z.object({
  plan_id: z.string().trim().min(1),
}).strict();

const DenyPlanInputSchema = z.object({
  plan_id: z.string().trim().min(1),
}).strict();

const GrammarPlanInputSchema = z.object({
  command: z.string().trim().min(1),
  ops: OperatorOpsSchema,
}).strict();

const PlannerRequestInputSchema = z.object({
  command: z.string().trim().min(1),
}).strict();

const PlannerProposalInputSchema = z.object({
  agent_id: z.string().trim().min(1).optional(),
  task_id: z.string().trim().min(1).optional(),
  command: z.string().optional(),
  summary: z.string().trim().min(1),
  rationale: z.string().optional(),
  ops: OperatorOpsSchema,
}).strict();

const DIRECTIVE_KINDS: readonly AgentDirectiveKind[] = [
  'pause',
  'resume',
  'stop',
  'narrow_scope',
  'skip_types',
  'prioritize',
  'instruct',
];

export class OperatorCommandError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly http_status: number,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'OperatorCommandError';
  }
}

export interface ConfirmPlanResult {
  executed: true;
  already_executed?: boolean;
  results: OpResult[];
}

export interface DenyPlanResult {
  denied: true;
  plan_id: string;
}

export interface GrammarPlanResult {
  plan_id: string;
  command: string;
  ops: OperatorOp[];
}

export interface PlannerRequestResult {
  phase: 'planning_queued' | 'planning_running' | 'plan_ready';
  command_id: string;
  planner_task_id?: string;
  plan_id?: string;
  plan?: unknown;
  queued_at?: string;
}

export interface PlannerProposalInput {
  agent_id?: string;
  task_id?: string;
  command?: string;
  summary: string;
  rationale?: string;
  ops: OperatorOp[];
}

export type PlannerProposalResult =
  | {
      ok: true;
      plan_id: string;
      ops_count: number;
      summary: string;
      scope_preview?: ScopePreview;
    }
  | {
      ok: false;
      error: string;
      rejected?: { op: OperatorOp; reason: string }[];
    };

function executionFromRecord<T>(
  record: PersistedApplicationCommandV1,
  replayed = true,
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

function normalizePlannerCommand(value: string): string {
  return value.trim().replace(/\s+/g, ' ').toLowerCase();
}

function plannerRequestKey(value: string): string {
  return `planner_${createHash('sha256')
    .update(normalizePlannerCommand(value))
    .digest('hex')}`;
}

function commandFromRecord(
  record: PersistedApplicationCommandV1 | undefined,
): string | undefined {
  const input = record?.validated_input;
  if (!input || typeof input !== 'object' || Array.isArray(input)) return undefined;
  const value = (input as Record<string, unknown>).command;
  return typeof value === 'string' ? value : undefined;
}

export class OperatorCommandService {
  private readonly dispatch: DispatchCommandService;

  constructor(
    private readonly engine: GraphEngine,
    private readonly commands: ApplicationCommandService = new ApplicationCommandService(engine),
  ) {
    this.dispatch = new DispatchCommandService(engine, commands);
  }

  createGrammarPlan(
    command: string,
    ops: OperatorOp[],
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<GrammarPlanResult> {
    const input = GrammarPlanInputSchema.parse({ command, ops });
    const execution = this.commands.executeSync({
      command_kind: 'operator.plan.preview',
      input,
      schema: GrammarPlanInputSchema,
      metadata,
      state_keys: ['command_state'],
      execute: parsed => {
        const planId = this.engine.createCommandPlan(parsed);
        return {
          plan_id: planId,
          command: parsed.command,
          ops: parsed.ops as OperatorOp[],
        };
      },
      record: (_parsed, result) => ({
        plan_id: result.plan_id,
        entity_refs: { plan_id: result.plan_id },
      }),
    });
    return execution;
  }

  requestPlanner(
    command: string,
    state: InterpreterState,
    options: { runtime_available: boolean },
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<PlannerRequestResult> {
    const input = PlannerRequestInputSchema.parse({ command });
    const replay = this.commands.lookup<
      typeof input,
      PlannerRequestResult
    >('operator.plan', input, metadata);
    if (replay) return replay;
    const identity = this.commands.buildIdentity(
      'operator.plan',
      input,
      metadata,
    );

    const wanted = normalizePlannerCommand(input.command);
    const requestKey = plannerRequestKey(input.command);
    const matchingOpenPlans = this.engine.getProposedPlanStore().getOpen()
      .filter(plan => {
        if (normalizePlannerCommand(plan.command) === wanted) return true;
        const linked = plan.command_id
          ? this.engine.getApplicationCommandById(plan.command_id)
          : undefined;
        const linkedCommand = commandFromRecord(linked);
        return Boolean(
          linkedCommand
          && normalizePlannerCommand(linkedCommand) === wanted,
        );
      });
    if (matchingOpenPlans.length > 1) {
      throw new OperatorCommandError(
        'Multiple open planner plans match this command; resolve or dismiss them before retrying.',
        'PLANNER_REQUEST_AMBIGUOUS',
        409,
        { plan_ids: matchingOpenPlans.map(plan => plan.plan_id) },
      );
    }
    const openPlan = matchingOpenPlans[0];
    if (openPlan) {
      const existingCommand = openPlan.command_id
        ? this.engine.getApplicationCommandById(openPlan.command_id)
        : undefined;
      if (existingCommand) {
        return executionFromRecord<PlannerRequestResult>(existingCommand);
      }
      const execution = this.commands.executeSync({
        command_kind: 'operator.plan',
        input,
        schema: PlannerRequestInputSchema,
        metadata: {
          ...metadata,
          command_id: identity.command_id,
        },
        execute: () => ({
          phase: 'plan_ready' as const,
          command_id: identity.command_id,
          planner_task_id:
            openPlan.owner_task_id ?? openPlan.source_task_id,
          plan_id: openPlan.plan_id,
          plan: openPlan,
        }),
        record: (_parsed, result) => ({
          plan_id: result.plan_id,
          entity_refs: {
            planner_request_key: requestKey,
            ...(result.planner_task_id
              ? { planner_task_id: result.planner_task_id }
              : {}),
            plan_id: openPlan.plan_id,
          },
        }),
      });
      return execution;
    }
    const liveCommands = this.engine.listApplicationCommands().filter(record => {
      if (
        record.command_kind !== 'operator.plan'
        || (record.status !== 'accepted' && record.status !== 'running')
      ) return false;
      if (record.entity_refs?.planner_request_key === requestKey) return true;
      const existingCommand = commandFromRecord(record);
      return Boolean(
        existingCommand
        && normalizePlannerCommand(existingCommand) === wanted,
      );
    });
    if (liveCommands.length > 1) {
      throw new OperatorCommandError(
        'Multiple active planners match this command; cancel the duplicates before retrying.',
        'PLANNER_REQUEST_AMBIGUOUS',
        409,
        { command_ids: liveCommands.map(record => record.command_id) },
      );
    }
    if (liveCommands[0]) {
      return executionFromRecord<PlannerRequestResult>(liveCommands[0]);
    }

    const execution = this.commands.reserveSync({
      command_kind: 'operator.plan',
      input,
      schema: PlannerRequestInputSchema,
      metadata: {
        ...metadata,
        command_id: identity.command_id,
      },
      state_keys: ['agents', 'activity'],
      reserve: parsed => {
        if (!options.runtime_available) {
          throw new OperatorCommandError(
            'Natural-language planning needs the headless runtime (daemon mode).',
            'PLANNER_UNAVAILABLE',
            409,
          );
        }
        const taskId = randomUUID();
        const configuredModel = this.engine.getConfig().default_agent_model;
        const allowedModels = this.engine.getConfig().available_models;
        const modelAllowed = !configuredModel
          || !(Array.isArray(allowedModels) && allowedModels.length > 0)
          || allowedModels.includes(configuredModel);
        if (configuredModel && !modelAllowed) {
          this.engine.logActionEvent({
            description: `default_agent_model "${configuredModel}" is not in available_models — planner is using the CLI default; fix the engagement config`,
            event_type: 'instrumentation_warning',
            category: 'system',
            result_classification: 'failure',
            details: {
              reason: 'default_model_not_allowed',
              model: configuredModel,
            },
          });
        }
        const label = `planner-${taskId.slice(0, 8)}`;
        const plannerArchetype = getArchetype('planner');
        const registration = this.engine.registerAgent({
          id: taskId,
          task_id: taskId,
          agent_id: label,
          agent_label: label,
          assigned_at: this.engine.now(),
          // A reserved planner has not necessarily acquired the bounded planner
          // lane yet. TaskExecutionService advances it to running only after the
          // managed target process is acknowledged.
          status: 'pending',
          subgraph_node_ids: [],
          backend: 'headless_mcp',
          role: 'planner',
          archetype: plannerArchetype.id,
          skill: plannerArchetype.defaultSkill,
          objective: buildPlannerObjective(parsed.command, state),
          application_command_id: identity.command_id,
          ...(configuredModel && modelAllowed
            ? { model: configuredModel }
            : {}),
        });
        if (!registration.ok) {
          throw new OperatorCommandError(
            'Planner task registration was refused.',
            'PLANNER_REGISTRATION_REFUSED',
            registration.cap_exceeded ? 429 : 409,
          );
        }
        return {
          status: 'accepted',
          entity_refs: {
            planner_task_id: taskId,
            planner_request_key: requestKey,
          },
          result: {
            phase: 'planning_queued' as const,
            command_id: identity.command_id,
            planner_task_id: taskId,
            queued_at: this.engine.now(),
          },
        };
      },
    });
    return execution;
  }

  submitProposal(args: PlannerProposalInput): PlannerProposalResult {
    if (!args.ops.length) {
      return { ok: false, error: 'a plan must contain at least one op' };
    }
    const parsed = PlannerProposalInputSchema.parse(args);
    const {
      agent_id,
      task_id,
      command,
      summary,
      rationale,
    } = parsed;
    const ops = structuredClone(parsed.ops) as OperatorOp[];
    const invocation = getApplicationCommandInvocation();
    if (invocation?.transport === 'mcp' && !invocation.actor_task_id) {
      return {
        ok: false,
        error: 'an authenticated planner task is required to submit an MCP proposal; task_id and agent_id body aliases cannot claim ownership',
      };
    }
    const invocationActorTaskId = invocation?.actor_task_id ?? undefined;
    const ownerReference = invocationActorTaskId ?? task_id ?? agent_id;
    const inferredOwner = ownerReference
      ? undefined
      : this.engine.getAgentTasks().filter(task => {
          if (
            task.role !== 'planner'
            || !task.application_command_id
            || (task.status !== 'running' && task.status !== 'pending')
          ) {
            return false;
          }
          if (!command) return true;
          const match = task.objective?.match(
            /^OPERATOR COMMAND \(free-form\): "([\s\S]*?)"$/m,
          );
          return Boolean(
            match
            && normalizePlannerCommand(match[1]) === normalizePlannerCommand(command),
          );
        });
    if (inferredOwner && inferredOwner.length > 1) {
      return {
        ok: false,
        error: 'planner task identity is ambiguous; pass the exact task_id',
      };
    }
    const ownerResolution = ownerReference
      ? this.engine.resolveAgentTaskReference(ownerReference)
      : inferredOwner?.length === 1
        ? { status: 'exact' as const, task: inferredOwner[0] }
        : { status: 'missing' as const };
    if (ownerResolution.status === 'ambiguous_legacy_label') {
      return {
        ok: false,
        error: `agent label "${ownerReference}" is ambiguous; pass the exact task_id`,
      };
    }
    if (ownerReference && ownerResolution.status === 'missing') {
      return { ok: false, error: `planner task not found: ${ownerReference}` };
    }
    const ownerTask = ownerResolution.status === 'exact'
      || ownerResolution.status === 'unique_legacy_label'
      ? ownerResolution.task
      : undefined;
    const ownerTaskId = ownerTask?.task_id ?? ownerTask?.id;
    const ownerAgentLabel = ownerTask?.agent_label ?? ownerTask?.agent_id;
    if (
      ownerTask
      && ownerTask.status !== 'running'
      && ownerTask.status !== 'pending'
    ) {
      return {
        ok: false,
        error: `planner task ${ownerTaskId} is already ${ownerTask.status}; no new plan can be attached`,
      };
    }
    if (task_id && ownerTask && task_id !== ownerTaskId) {
      return {
        ok: false,
        error: `task_id "${task_id}" does not match invoking planner task ${ownerTaskId}`,
      };
    }
    if (
      agent_id
      && ownerTask
      && agent_id !== ownerTaskId
      && agent_id !== ownerAgentLabel
    ) {
      return {
        ok: false,
        error: `agent_id "${agent_id}" does not match planner task ${ownerTaskId} (${ownerAgentLabel})`,
      };
    }

    const commandId = ownerTask?.application_command_id;
    let owningCommand: PersistedApplicationCommandV1 | undefined;
    let canonicalCommand = command ?? '';
    if (commandId) {
      const existingPlan = this.engine.getProposedPlanStore()
        .getByCommandId(commandId);
      if (existingPlan) {
        return proposalResult(existingPlan);
      }
      owningCommand = this.engine.getApplicationCommandById(commandId);
      if (!owningCommand) {
        return { ok: false, error: `planner command not found: ${commandId}` };
      }
      const persistedCommand = commandFromRecord(owningCommand);
      if (persistedCommand) {
        if (
          command !== undefined
          && normalizePlannerCommand(command)
            !== normalizePlannerCommand(persistedCommand)
        ) {
          return {
            ok: false,
            error: `proposal command does not match owning planner command ${commandId}`,
          };
        }
        canonicalCommand = persistedCommand;
      }
      if (
        owningCommand.status === 'failed'
        || owningCommand.status === 'interrupted'
        || owningCommand.status === 'succeeded'
      ) {
        return {
          ok: false,
          error: `planner command ${commandId} is already ${owningCommand.status}; no new plan can be attached`,
        };
      }
    }

    const rejected = validateProposedOps(this.engine, ops);
    if (rejected.length) {
      return {
        ok: false,
        error: `${rejected.length} op(s) could not be resolved against live state`,
        rejected,
      };
    }

    for (const op of ops) {
      if (op.op === 'dispatch' && op.target_node_ids.length) {
        op.archetype = recommendExploreArchetype(
          op.archetype,
          this.engine.getNode(op.target_node_ids[0])?.type,
        );
      }
    }
    const scopePreview = computeScopePreview(this.engine, ops);

    return this.engine.runApplicationCommandTransaction(
      'record planner proposal',
      undefined,
      () => {
        if (commandId) {
          const concurrent = this.engine.getProposedPlanStore()
            .getByCommandId(commandId);
          if (concurrent) return proposalResult(concurrent);
        }
        const plan = this.engine.getProposedPlanStore().add({
          command_id: commandId,
          command: canonicalCommand,
          ops,
          summary,
          rationale,
          owner_task_id: ownerTaskId,
          owner_agent_label: ownerAgentLabel,
          scope_preview: scopePreview,
        });
        this.engine.logActionEvent({
          description: `Planner proposed a ${ops.length}-op plan: ${summary}`,
          event_type: 'plan_proposed',
          category: 'agent',
          result_classification: 'neutral',
          agent_id: ownerAgentLabel,
          linked_agent_task_id: ownerTaskId,
          details: {
            reason: 'plan_proposed',
            command_id: commandId,
            plan_id: plan.plan_id,
            command: canonicalCommand,
            summary,
            ops,
          },
        });
        if (commandId) {
          const owningCommand = this.engine.getApplicationCommandById(commandId);
          if (!owningCommand) {
            throw new OperatorCommandError(
              `planner command not found: ${commandId}`,
              'PLANNER_COMMAND_NOT_FOUND',
              409,
            );
          }
          this.engine.recordApplicationCommand({
            ...owningCommand,
            status: 'succeeded',
            started_at: owningCommand.started_at ?? this.engine.now(),
            completed_at: this.engine.now(),
            plan_id: plan.plan_id,
            entity_refs: {
              ...(owningCommand.entity_refs ?? {}),
              ...(ownerTaskId ? { planner_task_id: ownerTaskId } : {}),
              plan_id: plan.plan_id,
            },
            result: {
              phase: 'plan_ready',
              command_id: commandId,
              ...(ownerTaskId ? { planner_task_id: ownerTaskId } : {}),
              plan_id: plan.plan_id,
              plan,
            },
          });
        }
        return proposalResult(plan);
      },
      ['plans_questions', 'activity'],
    );
  }

  confirmPlan(
    planId: string,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ConfirmPlanResult> {
    const input = ConfirmPlanInputSchema.parse({ plan_id: planId });
    const effectiveMetadata = {
      ...metadata,
      plan_id: planId,
      idempotency_key: metadata.idempotency_key ?? `plan-confirm:${planId}`,
    };
    const replay = this.commands.lookup<typeof input, ConfirmPlanResult>(
      'operator.plan.confirm',
      input,
      effectiveMetadata,
    );
    if (replay) {
      if (replay.status === 'failed' || replay.status === 'interrupted') {
        this.throwConfirmExecutionFailure(replay);
      }
      if (replay.result) replay.result.already_executed = true;
      return replay;
    }

    const grammarPlan = this.engine.getCommandPlan(planId);
    const proposedPlan = grammarPlan
      ? undefined
      : this.engine.getProposedPlanStore().get(planId);
    const plan = grammarPlan ?? (
      proposedPlan?.status === 'open'
        ? { ops: proposedPlan.ops, command: proposedPlan.command }
        : undefined
    );
    if (!plan) {
      const legacy = this.engine.getCommandOutcome(planId);
      if (legacy) {
        const result: ConfirmPlanResult = {
          executed: true,
          already_executed: true,
          results: legacy.results as OpResult[],
        };
        return this.commands.executeSync({
          command_kind: 'operator.plan.confirm',
          input,
          schema: ConfirmPlanInputSchema,
          metadata: effectiveMetadata,
          execute: () => result,
        });
      }
      const resolution = this.engine.getProposedPlanStore().describeResolution(planId);
      if (resolution === 'confirmed') {
        throw new OperatorCommandError(
          'plan was already confirmed — check the fleet (do not re-issue)',
          'PLAN_OUTCOME_UNAVAILABLE',
          409,
          { resolution, already_handled: true },
        );
      }
      if (resolution === 'denied') {
        throw new OperatorCommandError(
          'plan was dismissed — it will not deploy (do not re-issue)',
          'PLAN_DENIED',
          409,
          { resolution, already_handled: true },
        );
      }
      throw new OperatorCommandError(
        'plan not found or expired — re-issue the command',
        'PLAN_NOT_FOUND',
        404,
        { resolution, already_handled: false },
      );
    }

    const scopeChanges = this.mergeScopeOperations(plan.ops);
    const preparedResolutions: ActionResolution[] = [];
    const execute = (): ConfirmPlanResult => {
      const results = this.executeOperations(
        planId,
        plan.ops,
        preparedResolutions,
        Boolean(scopeChanges),
      );
      if (grammarPlan) {
        this.engine.deleteCommandPlan(planId);
      } else {
        const resolved = this.engine.getProposedPlanStore().resolve(planId, 'confirmed');
        if (!resolved) {
          throw new OperatorCommandError(
            'plan is no longer open',
            'PLAN_ALREADY_RESOLVED',
            409,
          );
        }
        this.engine.getProposedPlanStore().recordExecutionOutcome(planId, results);
      }
      this.engine.recordCommandOutcome(planId, results);
      this.engine.logActionEvent({
        description: `Operator command executed: ${plan.command || '(planner plan)'}`,
        event_type: 'operator_command',
        category: 'system',
        source_kind: 'dashboard',
        result_classification: results.every(result => result.ok)
          ? 'success'
          : results.some(result => result.ok)
            ? 'partial'
            : 'failure',
        details: {
          reason: 'operator_command',
          command: plan.command,
          plan_id: planId,
          planner: Boolean(proposedPlan),
          transport: metadata.transport ?? 'dashboard',
          results,
        },
      });
      return { executed: true, results };
    };

    let execution: ApplicationCommandExecution<ConfirmPlanResult>;
    if (scopeChanges) {
      execution = this.executeScopePlan(
        input,
        effectiveMetadata,
        scopeChanges,
        execute,
      );
    } else {
      execution = this.commands.executeSync({
        command_kind: 'operator.plan.confirm',
        input,
        schema: ConfirmPlanInputSchema,
        metadata: effectiveMetadata,
        state_keys: [
          'agents',
          'campaigns',
          'directives',
          'approvals',
          'plans_questions',
          'activity',
          'frontier',
        ],
        execute,
      });
    }

    if (execution.status === 'failed' || execution.status === 'interrupted') {
      this.throwConfirmExecutionFailure(execution);
    }
    if (!execution.replayed) {
      for (const resolution of preparedResolutions) {
        this.engine.getPendingActionQueue().commitPreparedResolution(resolution);
      }
    }
    if (execution.replayed && execution.result) {
      execution.result.already_executed = true;
    }
    return execution;
  }

  denyPlan(
    planId: string,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<DenyPlanResult> {
    const input = DenyPlanInputSchema.parse({ plan_id: planId });
    const execution = this.commands.executeSync({
      command_kind: 'operator.plan.deny',
      input,
      schema: DenyPlanInputSchema,
      metadata: {
        ...metadata,
        plan_id: planId,
        idempotency_key: metadata.idempotency_key ?? `plan-deny:${planId}`,
      },
      state_keys: ['plans_questions'],
      execute: () => {
        const denied = this.engine.getProposedPlanStore().resolve(planId, 'denied');
        if (!denied) {
          throw new OperatorCommandError(
            'plan not found or already resolved',
            'PLAN_NOT_FOUND',
            404,
          );
        }
        return { denied: true, plan_id: planId } as const;
      },
    });
    if (execution.status === 'failed' || execution.status === 'interrupted') {
      const details = execution.error?.details;
      const record = details && typeof details === 'object' && !Array.isArray(details)
        ? details as Record<string, unknown>
        : {};
      throw new OperatorCommandError(
        execution.error?.message ?? 'Plan denial failed.',
        execution.error?.code ?? 'PLAN_DENY_FAILED',
        typeof record.http_status === 'number' ? record.http_status : 404,
        record,
      );
    }
    return execution;
  }

  private executeScopePlan(
    input: z.infer<typeof ConfirmPlanInputSchema>,
    metadata: ApplicationCommandMetadata,
    scopeChanges: {
      add_cidrs?: string[];
      add_domains?: string[];
      add_exclusions?: string[];
    },
    execute: () => ConfirmPlanResult,
  ): ApplicationCommandExecution<ConfirmPlanResult> {
    const identity = this.commands.buildIdentity(
      'operator.plan.confirm',
      input,
      metadata,
    );
    const scopeExecution = this.engine.runAtomicScopeCommand(
      {
        ...scopeChanges,
        reason: `operator command plan ${input.plan_id}`,
      },
      identity.action_id,
      [
        'agents',
        'campaigns',
        'directives',
        'approvals',
        'plans_questions',
        'command_state',
        'activity',
        'frontier',
      ],
      () => {
        const concurrent = this.engine.getApplicationCommand(identity.idempotency_key);
        if (concurrent) {
          if (
            concurrent.command_kind !== 'operator.plan.confirm'
            || concurrent.input_sha256 !== identity.input_sha256
          ) {
            throw new ApplicationCommandConflictError(
              `Idempotency key is already bound to command ${concurrent.command_id} with different input.`,
              concurrent,
            );
          }
          return executionFromRecord<ConfirmPlanResult>(concurrent);
        }
        const result = execute();
        const now = this.engine.now();
        const record: PersistedApplicationCommandV1 = {
          ...identity,
          command_kind: 'operator.plan.confirm',
          validated_input: structuredClone(input),
          status: 'succeeded',
          created_at: now,
          started_at: now,
          completed_at: now,
          plan_id: input.plan_id,
          result,
        };
        return {
          command_id: record.command_id,
          retry_token: record.idempotency_key,
          idempotency_key: record.idempotency_key,
          status: record.status,
          replayed: false,
          result,
          record,
        };
      },
      execution => execution.record,
    );
    const installed = this.engine.getApplicationCommand(identity.idempotency_key);
    if (!installed) {
      throw new Error('Operator plan committed without its application-command receipt.');
    }
    return executionFromRecord<ConfirmPlanResult>(
      installed,
      scopeExecution.result.replayed,
    );
  }

  private executeOperations(
    planId: string,
    ops: OperatorOp[],
    preparedResolutions: ActionResolution[],
    scopeHandledByOuterCommand: boolean,
  ): OpResult[] {
    const results: OpResult[] = [];
    for (const [index, op] of ops.entries()) {
      try {
        if (op.op === 'scope') {
          if (scopeHandledByOuterCommand) {
            results.push({
              op,
              ok: true,
              detail: 'scope update committed with the operator command',
            });
          } else {
            const result = this.engine.updateScope({
              add_cidrs: op.add_cidrs,
              add_domains: op.add_domains,
              add_exclusions: op.add_exclusions,
              reason: 'operator command',
            });
            results.push(result.applied
              ? {
                  op,
                  ok: true,
                  detail: `scope updated (${result.affected_node_count} nodes affected)`,
                }
              : { op, ok: false, error: result.errors.join('; ') });
          }
          continue;
        }
        if (op.op === 'directive') {
          this.engine.issueAgentDirective({
            task_id: op.task_id,
            kind: op.kind,
            node_ids: op.node_ids,
            frontier_types: op.frontier_types,
            note: op.note,
            issued_by: 'operator',
          });
          const target = this.engine.getTask(op.task_id);
          const advisory = !target || target.backend !== 'headless_mcp';
          results.push({
            op,
            ok: true,
            detail: advisory
              ? `directive ${op.kind} recorded for ${op.agent_label} (advisory — no live agent)`
              : `directive ${op.kind} issued to ${op.agent_label}`,
          });
          continue;
        }
        if (op.op === 'approve' || op.op === 'deny') {
          if (preparedResolutions.some(item => item.action_id === op.action_id)) {
            results.push({
              op,
              ok: false,
              error: 'the plan resolves this action more than once',
            });
            continue;
          }
          const resolution = this.engine.getPendingActionQueue().prepareResolution(
            op.action_id,
            op.op === 'approve' ? 'approved' : 'denied',
            op.op === 'approve' ? op.notes : op.reason,
          );
          if (!resolution) {
            results.push({ op, ok: false, error: 'action not found or already resolved' });
            continue;
          }
          this.engine.resolveApprovalRequest(resolution);
          preparedResolutions.push(resolution);
          results.push({ op, ok: true, detail: `${op.op}d ${op.action_id}` });
          continue;
        }
        const dispatchInput: AgentDispatchInput = {
          target_node_ids: op.target_node_ids,
          skill: op.skill,
          archetype: op.archetype,
          objective: op.objective,
        };
        const dispatch = this.dispatch.dispatch(dispatchInput, {
          transport: 'planner',
          actor_task_id: metadataActorTaskId(this.engine, planId),
          idempotency_key: `plan:${planId}:dispatch:${index}`,
        });
        const body = dispatch.result!.body;
        if (body.dispatched === true) {
          const task = body.task as { task_id?: string; id?: string; agent_label?: string; agent_id?: string };
          const taskId = task.task_id ?? task.id;
          const agentLabel = task.agent_label ?? task.agent_id;
          if (!taskId || !agentLabel) {
            throw new OperatorCommandError(
              'Dispatch succeeded without canonical task identity.',
              'DISPATCH_IDENTITY_MISSING',
              500,
            );
          }
          results.push({
            op,
            ok: true,
            detail: `deployed ${agentLabel} as ${taskId}`,
            task: {
              task_id: taskId,
              agent_label: agentLabel,
              id: taskId,
              agent_id: agentLabel,
            },
          });
        } else {
          results.push({
            op,
            ok: false,
            error: String(body.reason ?? 'dispatch refused'),
          });
        }
      } catch (error) {
        results.push({
          op,
          ok: false,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return results;
  }

  private mergeScopeOperations(ops: OperatorOp[]): {
    add_cidrs?: string[];
    add_domains?: string[];
    add_exclusions?: string[];
  } | undefined {
    const cidrs = new Set<string>();
    const domains = new Set<string>();
    const exclusions = new Set<string>();
    for (const op of ops) {
      if (op.op !== 'scope') continue;
      for (const value of op.add_cidrs ?? []) cidrs.add(value);
      for (const value of op.add_domains ?? []) domains.add(value);
      for (const value of op.add_exclusions ?? []) exclusions.add(value);
    }
    if (cidrs.size + domains.size + exclusions.size === 0) return undefined;
    return {
      ...(cidrs.size ? { add_cidrs: [...cidrs] } : {}),
      ...(domains.size ? { add_domains: [...domains] } : {}),
      ...(exclusions.size ? { add_exclusions: [...exclusions] } : {}),
    };
  }

  private throwConfirmExecutionFailure(
    execution: ApplicationCommandExecution<unknown>,
  ): never {
    const details = execution.error?.details;
    const record = details && typeof details === 'object' && !Array.isArray(details)
      ? details as Record<string, unknown>
      : {};
    throw new OperatorCommandError(
      execution.error?.message ?? 'Plan confirmation failed.',
      execution.error?.code ?? 'PLAN_CONFIRM_FAILED',
      typeof record.http_status === 'number' ? record.http_status : 400,
      record,
    );
  }

}

function metadataActorTaskId(engine: GraphEngine, planId: string): string | null {
  const proposed = engine.getProposedPlanStore().get(planId);
  return proposed?.owner_task_id ?? proposed?.source_task_id ?? null;
}

function proposalResult(
  plan: ProposedPlan,
): Extract<PlannerProposalResult, { ok: true }> {
  return {
    ok: true,
    plan_id: plan.plan_id,
    ops_count: plan.ops.length,
    summary: plan.summary,
    ...(plan.scope_preview ? { scope_preview: plan.scope_preview } : {}),
  };
}

export function computeScopePreview(
  engine: GraphEngine,
  ops: OperatorOp[],
): ScopePreview | undefined {
  const adds = mergeScopeAdds(ops);
  if (!adds) return undefined;
  const scope = engine.getConfig().scope;
  const exported = engine.exportGraph();
  const cold = (exported.cold_nodes ?? []).map(node => ({
    id: node.id,
    properties: {
      ip: node.ip,
      hostname: node.hostname,
      label: node.label,
    },
  }));
  return previewScopeChange(
    [...exported.nodes, ...cold],
    {
      cidrs: scope.cidrs,
      domains: scope.domains,
      exclusions: scope.exclusions,
    },
    adds,
  );
}

export function validateProposedOps(
  engine: GraphEngine,
  ops: OperatorOp[],
): { op: OperatorOp; reason: string }[] {
  const rejected: { op: OperatorOp; reason: string }[] = [];
  const pendingIds = new Set(
    engine.getPendingActionQueue().getPending().map(action => action.action_id),
  );
  for (const op of ops) {
    if (op.op === 'directive') {
      if (!DIRECTIVE_KINDS.includes(op.kind)) {
        rejected.push({
          op,
          reason: `unknown directive kind "${op.kind}"`,
        });
        continue;
      }
      const task = op.task_id ? engine.getTask(op.task_id) : undefined;
      if (!task) {
        rejected.push({
          op,
          reason: `no agent task with id "${op.task_id}"`,
        });
      } else if (task.status !== 'running') {
        rejected.push({
          op,
          reason: `task "${op.task_id}" is ${task.status}, not running`,
        });
      }
      continue;
    }
    if (op.op === 'scope') {
      const adds = (op.add_cidrs?.length ?? 0)
        + (op.add_domains?.length ?? 0)
        + (op.add_exclusions?.length ?? 0);
      if (adds === 0) {
        rejected.push({
          op,
          reason: 'scope op adds nothing (no cidrs/domains/exclusions)',
        });
      }
      continue;
    }
    if (op.op === 'approve' || op.op === 'deny') {
      if (!pendingIds.has(op.action_id)) {
        rejected.push({
          op,
          reason: `no pending action with id "${op.action_id}"`,
        });
      }
      continue;
    }
    if (!op.target_node_ids?.length) {
      rejected.push({ op, reason: 'dispatch op has no target_node_ids' });
      continue;
    }
    const missing = op.target_node_ids.filter(id => !engine.getNode(id));
    if (missing.length) {
      rejected.push({
        op,
        reason: `unknown node id(s): ${missing.join(', ')}`,
      });
    } else if (op.archetype && !isArchetypeId(op.archetype)) {
      rejected.push({
        op,
        reason: `unknown agent type "${op.archetype}"`,
      });
    }
  }
  return rejected;
}
