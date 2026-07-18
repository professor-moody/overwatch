// ============================================================
// Overwatch — canonical dispatch application commands
// ============================================================

import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { FRONTIER_TYPES } from '../contracts/dashboard-v1.js';
import type { AgentTask } from '../types.js';
import { isIpInCidr } from './cidr.js';
import {
  getArchetype,
  isArchetypeId,
  recommendArchetype,
  recommendExploreArchetype,
  type AgentArchetypeId,
  type RecommendInput,
} from './agent-archetypes.js';
import {
  ApplicationCommandConflictError,
  ApplicationCommandService,
  type ApplicationCommandExecution,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import type { GraphEngine } from './graph-engine.js';
import type { PersistedApplicationCommandV1 } from './persisted-state.js';

export class DispatchCommandError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly http_status: number,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'DispatchCommandError';
  }
}

export const AgentDispatchInputSchema = z.object({
  agent_label: z.string().trim().min(1).optional(),
  frontier_item_id: z.string().trim().min(1).optional(),
  target_node_ids: z.array(z.string()).default([]),
  skill: z.string().optional(),
  campaign_id: z.string().optional(),
  archetype: z.string().optional(),
  model: z.string().optional(),
  objective: z.string().optional(),
}).strict().refine(
  input => Boolean(input.frontier_item_id) || input.target_node_ids.length > 0,
  'frontier_item_id or a non-empty target_node_ids array is required',
);

export type AgentDispatchInput = z.infer<typeof AgentDispatchInputSchema>;

export const AgentRegisterInputSchema = z.object({
  agent_label: z.string().trim().min(1),
  frontier_item_id: z.string().trim().min(1).optional(),
  target_node_ids: z.array(z.string()).default([]),
  skill: z.string().optional(),
  archetype: z.string().optional(),
  model: z.string().optional(),
  objective: z.string().optional(),
}).strict();

export type AgentRegisterInput = z.infer<typeof AgentRegisterInputSchema>;

const ExactAgentTaskSchema = z.object({
  id: z.string().trim().min(1),
  task_id: z.string().trim().min(1).optional(),
  agent_id: z.string().trim().min(1),
  agent_label: z.string().trim().min(1).optional(),
  assigned_at: z.string().min(1),
  status: z.enum(['pending', 'running', 'completed', 'failed', 'interrupted']),
  subgraph_node_ids: z.array(z.string()),
}).passthrough();

const ExactAgentRegisterInputSchema = z.object({
  task: ExactAgentTaskSchema,
}).strict();

export interface ExactAgentRegisterResponse {
  task: AgentTask;
  registration: ReturnType<GraphEngine['registerAgent']>;
}

export interface DispatchCommandResponse {
  http_status: 201 | 409 | 429;
  body: Record<string, unknown>;
}

export const AgentDispatchBatchInputSchema = z.object({
  target_node_ids: z.array(z.string()).min(1),
  mode: z.enum(['per-node', 'per-batch']).default('per-node'),
  batch_size: z.number().int().min(1).default(5),
  archetype: z.string().optional(),
  skill: z.string().optional(),
  model: z.string().optional(),
  objective: z.string().optional(),
}).strict();

export type AgentDispatchBatchInput = z.infer<typeof AgentDispatchBatchInputSchema>;

export interface DispatchBatchCommandResponse {
  dispatched: Array<{
    node_ids: string[];
    task_id: string;
    agent_label: string;
    id: string;
    agent_id: string;
    archetype?: string;
  }>;
  skipped: Array<{
    node_ids: string[];
    reason: string;
    existing_agent_id?: string;
  }>;
  deferred: Array<{ node_ids: string[]; reason: string }>;
  summary: {
    dispatched: number;
    skipped: number;
    deferred: number;
    groups: number;
  };
}

export const FrontierDispatchBatchInputSchema = z.object({
  count: z.number().int().min(1).max(20).default(3),
  strategy: z.enum(['top_priority', 'by_type']).default('top_priority'),
  types: z.array(z.enum(FRONTIER_TYPES)).optional(),
  skill: z.string().optional(),
  archetype: z.string().optional(),
  hops: z.number().int().min(1).max(5).default(2),
}).strict();

export type FrontierDispatchBatchInput = z.infer<
  typeof FrontierDispatchBatchInputSchema
>;

export interface FrontierDispatchBatchResponse {
  requested: number;
  strategy: FrontierDispatchBatchInput['strategy'];
  types: string[];
  total_candidates: number;
  dispatched: Array<{
    task_id: string;
    agent_label: string;
    id: string;
    agent_id: string;
    frontier_item_id: string;
    frontier_type: string;
    archetype: string;
    skill?: string;
  }>;
  skipped_existing: Array<{
    frontier_item_id: string;
    task_id: string;
    agent_label: string;
    id: string;
    agent_id: string;
  }>;
  skipped_unscoped: Array<{
    frontier_item_id: string;
    frontier_type: string;
  }>;
  skipped_lease_conflict: Array<{
    frontier_item_id: string;
    frontier_type: string;
    existing_task_id?: string;
    existing_agent_id?: string;
  }>;
  skipped_dispatch_cap: Array<{
    frontier_item_id: string;
    frontier_type: string;
    cap_scope: string;
    cap_key: string;
    limit: number;
    current: number;
  }>;
}

export const CampaignAgentDispatchInputSchema = z.object({
  campaign_id: z.string().trim().min(1),
  max_agents: z.number().int().min(1).max(20).default(8),
  hops: z.number().int().min(0).max(5).default(2),
  skill: z.string().optional(),
  archetype: z.string().optional(),
}).strict();

export type CampaignAgentDispatchInput = z.infer<
  typeof CampaignAgentDispatchInputSchema
>;

export interface CampaignAgentDispatchResponse {
  campaign_id: string;
  strategy: string;
  requested: number;
  total_items: number;
  dispatched: Array<{
    task_id: string;
    agent_label: string;
    id: string;
    agent_id: string;
    frontier_item_id: string;
    scope_nodes: number;
    archetype: string;
    skill?: string;
  }>;
  skipped: Array<{ frontier_item_id: string; reason: string }>;
  warning?: string;
}

export const SubnetAgentDispatchInputSchema = z.object({
  max_agents: z.number().int().min(1).max(20).default(8),
  skill: z.string().default('subnet-enumeration'),
  hops: z.number().int().min(1).max(5).default(2),
}).strict();

export type SubnetAgentDispatchInput = z.infer<
  typeof SubnetAgentDispatchInputSchema
>;

export interface SubnetAgentDispatchResponse {
  requested: number;
  total_cidrs: number;
  dispatched: Array<{
    task_id: string;
    agent_label: string;
    id: string;
    agent_id: string;
    cidr: string;
    existing_nodes: number;
    skill: string;
  }>;
  skipped: Array<{ cidr: string; reason: string }>;
}

export const QuickDeployInputSchema = z.object({
  target: z.string().trim().min(1),
  archetype: z.string().optional(),
  model: z.string().optional(),
}).strict();

export type QuickDeployInput = z.infer<typeof QuickDeployInputSchema>;

export interface QuickDeployCommandResponse {
  dispatched: true;
  task: AgentTask;
  archetype: string;
  scope: {
    added_cidrs: string[];
    added_domains: string[];
    affected_node_count: number;
  };
}

function taskResult(
  command: PersistedApplicationCommandV1,
  replayed: boolean,
): ApplicationCommandExecution<QuickDeployCommandResponse> {
  return {
    command_id: command.command_id,
    retry_token: command.idempotency_key,
    idempotency_key: command.idempotency_key,
    status: command.status,
    replayed,
    ...(Object.prototype.hasOwnProperty.call(command, 'result')
      ? { result: structuredClone(command.result) as QuickDeployCommandResponse }
      : {}),
    ...(command.error ? { error: structuredClone(command.error) } : {}),
    record: structuredClone(command),
  };
}

function domainErrorFromExecution(
  execution: ApplicationCommandExecution<unknown>,
): never {
  const details = execution.error?.details;
  const record = details && typeof details === 'object' && !Array.isArray(details)
    ? details as Record<string, unknown>
    : {};
  throw new DispatchCommandError(
    execution.error?.message ?? 'Dispatch command failed.',
    execution.error?.code ?? 'DISPATCH_FAILED',
    typeof record.http_status === 'number' ? record.http_status : 400,
    record,
  );
}

export class DispatchCommandService {
  constructor(
    private readonly engine: GraphEngine,
    private readonly commands: ApplicationCommandService = new ApplicationCommandService(engine),
  ) {}

  dispatch(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<DispatchCommandResponse> {
    const input = AgentDispatchInputSchema.parse(rawInput);
    const execution = this.commands.executeSync<AgentDispatchInput, DispatchCommandResponse>({
      command_kind: 'agent.dispatch',
      input,
      schema: AgentDispatchInputSchema,
      metadata: {
        ...metadata,
        frontier_item_id: input.frontier_item_id ?? metadata.frontier_item_id,
      },
      state_keys: ['agents', 'campaigns'],
      execute: parsed => this.executeDispatch(parsed),
      record: (parsed, result) => {
        const task = result.body.task as AgentTask | undefined;
        return {
          frontier_item_id: parsed.frontier_item_id,
          ...(task
            ? { entity_refs: { task_id: task.task_id ?? task.id } }
            : {}),
        };
      },
    });
    if (execution.status === 'failed' || execution.status === 'interrupted') {
      domainErrorFromExecution(execution);
    }
    return execution;
  }

  register(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<DispatchCommandResponse> {
    const input = AgentRegisterInputSchema.parse(rawInput);
    const execution = this.commands.executeSync<AgentRegisterInput, DispatchCommandResponse>({
      command_kind: 'agent.register',
      input,
      schema: AgentRegisterInputSchema,
      metadata: {
        ...metadata,
        frontier_item_id: input.frontier_item_id ?? metadata.frontier_item_id,
      },
      state_keys: ['agents'],
      execute: parsed => this.executeRegister(parsed),
      record: (parsed, result) => {
        const task = result.body.task as AgentTask | undefined;
        return {
          frontier_item_id: parsed.frontier_item_id,
          ...(task
            ? { entity_refs: { task_id: task.task_id ?? task.id } }
            : {}),
        };
      },
    });
    if (execution.status === 'failed' || execution.status === 'interrupted') {
      domainErrorFromExecution(execution);
    }
    return execution;
  }

  /** Internal scheduler registration with a preallocated task identity.
   * Public adapters continue to use register()/dispatch(); this path exists so
   * autonomous CVE/orchestrator scheduling is no longer a direct graph write. */
  registerExact(
    task: AgentTask,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<ExactAgentRegisterResponse> {
    const execution = this.commands.executeSync({
      command_kind: 'agent.runtime.register',
      input: { task },
      schema: ExactAgentRegisterInputSchema,
      metadata,
      state_keys: ['agents', 'campaigns', 'activity', 'frontier'],
      execute: parsed => {
        const exactTask = structuredClone(parsed.task) as AgentTask;
        return {
          task: exactTask,
          registration: this.engine.registerAgent(exactTask),
        };
      },
      record: (_input, result) => ({
        frontier_item_id: result.task.frontier_item_id,
        entity_refs: { task_id: result.task.task_id ?? result.task.id },
      }),
    });
    if (execution.status === 'failed' || execution.status === 'interrupted') {
      domainErrorFromExecution(execution);
    }
    return execution;
  }

  dispatchBatch(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<DispatchBatchCommandResponse> {
    const execution = this.commands.executeSync<AgentDispatchBatchInput, DispatchBatchCommandResponse>({
      command_kind: 'agent.dispatch_batch',
      input: rawInput,
      schema: AgentDispatchBatchInputSchema,
      metadata,
      state_keys: ['agents'],
      execute: input => this.executeDispatchBatch(input),
    });
    if (execution.status === 'failed' || execution.status === 'interrupted') {
      domainErrorFromExecution(execution);
    }
    return execution;
  }

  dispatchFrontierBatch(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<FrontierDispatchBatchResponse> {
    const execution = this.commands.executeSync<
      FrontierDispatchBatchInput,
      FrontierDispatchBatchResponse
    >({
      command_kind: 'agent.dispatch_frontier_batch',
      input: rawInput,
      schema: FrontierDispatchBatchInputSchema,
      metadata,
      state_keys: ['agents'],
      execute: input => this.executeFrontierDispatchBatch(input),
      record: (_input, result) => ({
        entity_refs: {
          task_id: result.dispatched.map(item => item.task_id),
          frontier_item_id: result.dispatched.map(item => item.frontier_item_id),
        },
      }),
    });
    if (execution.status === 'failed' || execution.status === 'interrupted') {
      domainErrorFromExecution(execution);
    }
    return execution;
  }

  dispatchCampaign(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<CampaignAgentDispatchResponse> {
    const execution = this.commands.executeSync<
      CampaignAgentDispatchInput,
      CampaignAgentDispatchResponse
    >({
      command_kind: 'agent.dispatch_campaign',
      input: rawInput,
      schema: CampaignAgentDispatchInputSchema,
      metadata,
      state_keys: ['agents', 'campaigns'],
      execute: input => this.executeCampaignDispatch(input),
      record: (input, result) => ({
        entity_refs: {
          campaign_id: input.campaign_id,
          task_id: result.dispatched.map(item => item.task_id),
          frontier_item_id: result.dispatched.map(
            item => item.frontier_item_id,
          ),
        },
      }),
    });
    if (execution.status === 'failed' || execution.status === 'interrupted') {
      domainErrorFromExecution(execution);
    }
    return execution;
  }

  dispatchSubnets(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<SubnetAgentDispatchResponse> {
    const execution = this.commands.executeSync<
      SubnetAgentDispatchInput,
      SubnetAgentDispatchResponse
    >({
      command_kind: 'agent.dispatch_subnets',
      input: rawInput,
      schema: SubnetAgentDispatchInputSchema,
      metadata,
      state_keys: ['agents'],
      execute: input => this.executeSubnetDispatch(input),
      record: (_input, result) => ({
        entity_refs: {
          task_id: result.dispatched.map(item => item.task_id),
        },
      }),
    });
    if (execution.status === 'failed' || execution.status === 'interrupted') {
      domainErrorFromExecution(execution);
    }
    return execution;
  }

  quickDeploy(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<QuickDeployCommandResponse> {
    const input = QuickDeployInputSchema.parse(rawInput);
    const identity = this.commands.buildIdentity('agent.quick_deploy', input, metadata);
    const replay = this.commands.lookup<QuickDeployInput, QuickDeployCommandResponse>(
      'agent.quick_deploy',
      input,
      metadata,
    );
    if (replay) {
      if (replay.status === 'failed' || replay.status === 'interrupted') {
        domainErrorFromExecution(replay);
      }
      return replay as ApplicationCommandExecution<QuickDeployCommandResponse>;
    }

    const { add_cidrs, add_domains } = this.classifyRawTargets(input.target);
    let scopeResult;
    try {
      scopeResult = this.engine.runAtomicScopeCommand(
        {
          add_cidrs,
          add_domains,
          reason: 'quick-deploy',
        },
        identity.action_id,
        ['agents', 'command_state'],
        plannedScope => {
          const concurrent = this.engine.getApplicationCommand(identity.idempotency_key);
          if (concurrent) {
            if (
              concurrent.command_kind !== 'agent.quick_deploy'
              || concurrent.input_sha256 !== identity.input_sha256
            ) {
              throw new ApplicationCommandConflictError(
                `Idempotency key is already bound to command ${concurrent.command_id} with different input.`,
                concurrent,
              );
            }
            return taskResult(concurrent, true);
          }
          const model = this.resolveDispatchModel(input.model);
          const archetype = getArchetype(
            input.archetype ?? recommendArchetype({ rawTarget: true }),
          );
          const taskId = randomUUID();
          const agentLabel = `quick-${taskId.slice(0, 8)}`;
          const task: AgentTask = {
            id: taskId,
            task_id: taskId,
            agent_id: agentLabel,
            agent_label: agentLabel,
            assigned_at: this.engine.now(),
            status: 'running',
            subgraph_node_ids: [],
            skill: archetype.defaultSkill,
            archetype: archetype.id,
            role: archetype.role,
            backend: archetype.backend,
            objective: (archetype.defaultObjective || 'Investigate {target}.')
              .replace('{target}', input.target),
            ...(model ? { model } : {}),
          };
          const registration = this.engine.registerAgent(task);
          if (registration.cap_exceeded) {
            throw new DispatchCommandError(
              'Dispatch cap exceeded.',
              'DISPATCH_CAP_EXCEEDED',
              429,
              {
                http_status: 429,
                cap_scope: registration.cap_exceeded.scope,
                cap_key: registration.cap_exceeded.key,
                limit: registration.cap_exceeded.limit,
                current: registration.cap_exceeded.current,
              },
            );
          }
          if (!registration.ok) {
            throw new DispatchCommandError(
              'Quick deploy was refused.',
              'DISPATCH_REFUSED',
              409,
              { http_status: 409 },
            );
          }
          const body: QuickDeployCommandResponse = {
            dispatched: true,
            task,
            archetype: archetype.id,
            scope: {
              added_cidrs: add_cidrs,
              added_domains: add_domains,
              affected_node_count: plannedScope.affected_node_count,
            },
          };
          const now = this.engine.now();
          const command: PersistedApplicationCommandV1 = {
            ...identity,
            command_kind: 'agent.quick_deploy',
            validated_input: structuredClone(input),
            status: 'succeeded',
            created_at: now,
            started_at: now,
            completed_at: now,
            entity_refs: { task_id: task.task_id ?? task.id },
            result: body,
          };
          return taskResult(command, false);
        },
        execution => execution.record,
      );
    } catch (error) {
      if (error instanceof ApplicationCommandConflictError) throw error;
      if (error instanceof DispatchCommandError) {
        const failed = this.commands.executeSync<QuickDeployInput, never>({
          command_kind: 'agent.quick_deploy',
          input,
          schema: QuickDeployInputSchema,
          metadata,
          execute: () => { throw error; },
        });
        if (failed.status === 'failed') domainErrorFromExecution(failed);
      }
      throw error;
    }
    const installed = this.engine.getApplicationCommand(identity.idempotency_key);
    if (!installed) {
      throw new Error('Quick deploy committed without its application-command receipt.');
    }
    return taskResult(installed, scopeResult.result.replayed);
  }

  private executeDispatch(input: AgentDispatchInput): DispatchCommandResponse {
    let dispatchInput = input;
    let targetNodeIds = input.target_node_ids;
    let campaignToActivate: string | undefined;

    if (input.frontier_item_id) {
      const known = this.engine.getFrontierItem(input.frontier_item_id);
      if (!known) {
        throw new DispatchCommandError(
          'Frontier item not found.',
          'FRONTIER_NOT_FOUND',
          404,
          { http_status: 404, frontier_item_id: input.frontier_item_id },
        );
      }
      const actionable = this.engine.getActionableFrontierItem(input.frontier_item_id);
      if (!actionable) {
        throw new DispatchCommandError(
          'Frontier item is no longer actionable.',
          'FRONTIER_NOT_ACTIONABLE',
          409,
          { http_status: 409, frontier_item_id: input.frontier_item_id },
        );
      }
      targetNodeIds = this.engine.computeSubgraphNodeIds(actionable.id, 2);
      if (targetNodeIds.length === 0 && actionable.type !== 'network_discovery') {
        throw new DispatchCommandError(
          'Frontier item has no live graph scope.',
          'FRONTIER_UNSCOPED',
          409,
          { http_status: 409, frontier_item_id: actionable.id },
        );
      }
      const seedType = targetNodeIds[0]
        ? this.engine.getNode(targetNodeIds[0])?.type
        : undefined;
      const archetype = recommendArchetype({
        frontierType: actionable.type,
        nodeType: seedType,
      });
      const campaign = this.engine.findCampaignForItem(actionable.id);
      const itemStatus = campaign?.item_status?.[actionable.id];
      if (itemStatus) {
        throw new DispatchCommandError(
          `Campaign item already ${itemStatus}.`,
          `ALREADY_${itemStatus.toUpperCase()}`,
          409,
          {
            http_status: 409,
            campaign_id: campaign.id,
            frontier_item_id: actionable.id,
          },
        );
      }
      if (campaign && campaign.status !== 'draft' && campaign.status !== 'active') {
        throw new DispatchCommandError(
          `Campaign is ${campaign.status} — cannot dispatch frontier work.`,
          'CAMPAIGN_NOT_DISPATCHABLE',
          409,
          {
            http_status: 409,
            campaign_id: campaign.id,
            frontier_item_id: actionable.id,
          },
        );
      }
      if (campaign?.status === 'draft') campaignToActivate = campaign.id;
      dispatchInput = {
        ...input,
        frontier_item_id: actionable.id,
        target_node_ids: targetNodeIds,
        archetype,
        objective: actionable.description,
        campaign_id: campaign?.id,
      };
    }

    const task = this.buildDispatchTask(dispatchInput, targetNodeIds);
    const registration = this.engine.registerAgent(task);
    if (registration.cap_exceeded) {
      return {
        http_status: 429,
        body: {
          dispatched: false,
          reason: 'dispatch_cap_exceeded',
          cap_scope: registration.cap_exceeded.scope,
          cap_key: registration.cap_exceeded.key,
          limit: registration.cap_exceeded.limit,
          current: registration.cap_exceeded.current,
        },
      };
    }
    if (!registration.ok) {
      return {
        http_status: 409,
        body: registration.node_conflict
          ? {
              dispatched: false,
              reason: 'node_dispatch_conflict',
              node_id: registration.node_conflict.node_id,
              existing_task_id: registration.node_conflict.existing_task_id,
              existing_agent_id: registration.node_conflict.existing_agent_id,
            }
          : {
              dispatched: false,
              reason: 'frontier_lease_conflict',
              existing_task_id: registration.lease_conflict?.existing_task_id,
              existing_agent_id: registration.lease_conflict?.existing_agent_id,
            },
      };
    }
    if (campaignToActivate) this.engine.activateCampaign(campaignToActivate);
    return {
      http_status: 201,
      body: { dispatched: true, task },
    };
  }

  private executeRegister(input: AgentRegisterInput): DispatchCommandResponse {
    if (input.frontier_item_id) {
      const existing = this.engine.getRunningTaskForFrontierItem(
        input.frontier_item_id,
      );
      if (existing) {
        return {
          http_status: 201,
          body: {
            dispatched: true,
            task: existing,
            skipped_existing: true,
          },
        };
      }
    }

    let targetNodeIds = [...new Set(input.target_node_ids)];
    const frontierItem = input.frontier_item_id
      ? this.engine.getFrontierItem(input.frontier_item_id)
      : null;
    let scopeWarning: string | undefined;
    if (
      input.frontier_item_id
      && targetNodeIds.length === 0
      && !input.frontier_item_id.startsWith('frontier-discovery-')
    ) {
      targetNodeIds = this.engine.computeSubgraphNodeIds(
        input.frontier_item_id,
        2,
      );
      if (targetNodeIds.length === 0) {
        scopeWarning = `Frontier item ${input.frontier_item_id} resolved to zero seed nodes — the agent may lack graph context`;
      }
    }
    const explicitArchetype = input.archetype && isArchetypeId(input.archetype)
      ? input.archetype
      : undefined;
    const seedType = targetNodeIds[0]
      ? this.engine.getNode(targetNodeIds[0])?.type
      : undefined;
    const archetype = explicitArchetype
      ?? recommendArchetype({
        frontierType: frontierItem?.type,
        nodeType: seedType,
      });
    const task = this.buildDispatchTask({
      agent_label: input.agent_label,
      frontier_item_id: input.frontier_item_id,
      archetype,
      skill: input.skill,
      model: input.model,
      objective: input.objective,
    }, targetNodeIds);
    const registration = this.engine.registerAgent(task);
    if (registration.cap_exceeded) {
      return {
        http_status: 429,
        body: {
          dispatched: false,
          reason: 'dispatch_cap_exceeded',
          cap_scope: registration.cap_exceeded.scope,
          cap_key: registration.cap_exceeded.key,
          limit: registration.cap_exceeded.limit,
          current: registration.cap_exceeded.current,
        },
      };
    }
    if (!registration.ok) {
      return {
        http_status: 409,
        body: registration.node_conflict
          ? {
              dispatched: false,
              reason: 'node_dispatch_conflict',
              node_id: registration.node_conflict.node_id,
              existing_task_id: registration.node_conflict.existing_task_id,
              existing_agent_id: registration.node_conflict.existing_agent_id,
            }
          : {
              dispatched: false,
              reason: 'frontier_lease_conflict',
              existing_task_id: registration.lease_conflict?.existing_task_id,
              existing_agent_id: registration.lease_conflict?.existing_agent_id,
            },
      };
    }
    return {
      http_status: 201,
      body: {
        dispatched: true,
        task,
        ...(scopeWarning ? { scope_warning: scopeWarning } : {}),
      },
    };
  }

  private executeDispatchBatch(input: AgentDispatchBatchInput): DispatchBatchCommandResponse {
    if (input.archetype && !isArchetypeId(input.archetype)) {
      throw new DispatchCommandError(
        `Unknown agent type: ${input.archetype}`,
        'UNKNOWN_ARCHETYPE',
        400,
        { http_status: 400 },
      );
    }
    this.resolveDispatchModel(input.model);
    const nodeIds = [...new Set(input.target_node_ids)];
    const dispatched: DispatchBatchCommandResponse['dispatched'] = [];
    const skipped: DispatchBatchCommandResponse['skipped'] = [];
    const deferred: DispatchBatchCommandResponse['deferred'] = [];
    const coverage = new Map<string, string>();
    for (const task of this.engine.getAgentTasks()) {
      if (task.status !== 'running' && task.status !== 'pending') continue;
      for (const nodeId of task.subgraph_node_ids ?? []) {
        if (!coverage.has(nodeId)) coverage.set(nodeId, task.agent_id);
      }
    }
    const fresh: string[] = [];
    for (const nodeId of nodeIds) {
      const owner = coverage.get(nodeId);
      if (owner) {
        skipped.push({
          node_ids: [nodeId],
          reason: 'already_being_worked',
          existing_agent_id: owner,
        });
      } else {
        fresh.push(nodeId);
      }
    }
    const batchSize = input.mode === 'per-batch' ? input.batch_size : 1;
    const groups: string[][] = [];
    for (let index = 0; index < fresh.length; index += batchSize) {
      groups.push(fresh.slice(index, index + batchSize));
    }
    for (const group of groups) {
      const task = this.buildDispatchTask(input, group);
      const registration = this.engine.registerAgent(task);
      if (registration.cap_exceeded) {
        deferred.push({ node_ids: group, reason: 'dispatch_cap_exceeded' });
        continue;
      }
      if (!registration.ok) {
        skipped.push(registration.node_conflict
          ? {
              node_ids: group,
              reason: 'already_being_worked',
              existing_agent_id: registration.node_conflict.existing_agent_id,
            }
          : {
              node_ids: group,
              reason: 'frontier_lease_conflict',
              existing_agent_id: registration.lease_conflict?.existing_agent_id,
            });
        continue;
      }
      dispatched.push({
        node_ids: group,
        task_id: task.task_id ?? task.id,
        agent_label: task.agent_label ?? task.agent_id,
        id: task.task_id ?? task.id,
        agent_id: task.agent_label ?? task.agent_id,
        archetype: task.archetype,
      });
    }
    return {
      dispatched,
      skipped,
      deferred,
      summary: {
        dispatched: dispatched.length,
        skipped: skipped.length,
        deferred: deferred.length,
        groups: groups.length,
      },
    };
  }

  private executeFrontierDispatchBatch(
    input: FrontierDispatchBatchInput,
  ): FrontierDispatchBatchResponse {
    if (input.archetype && !isArchetypeId(input.archetype)) {
      throw new DispatchCommandError(
        `Unknown agent type: ${input.archetype}`,
        'UNKNOWN_ARCHETYPE',
        400,
        { http_status: 400 },
      );
    }
    const frontier = this.engine.computeFrontier();
    const { passed } = this.engine.filterFrontier(frontier);
    const typeOrder = input.types?.length
      ? input.types
      : [...FRONTIER_TYPES];
    const allowedTypes = new Set<string>(typeOrder);
    let candidates = passed.filter(item => allowedTypes.has(item.type));
    if (input.strategy === 'by_type') {
      const queues = new Map(
        typeOrder.map(type => [
          type,
          candidates.filter(item => item.type === type),
        ]),
      );
      const ordered: typeof candidates = [];
      let madeProgress = true;
      while (madeProgress) {
        madeProgress = false;
        for (const type of typeOrder) {
          const queue = queues.get(type);
          if (queue?.length) {
            ordered.push(queue.shift()!);
            madeProgress = true;
          }
        }
      }
      candidates = ordered;
    }

    const result: FrontierDispatchBatchResponse = {
      requested: input.count,
      strategy: input.strategy,
      types: [...typeOrder],
      total_candidates: candidates.length,
      dispatched: [],
      skipped_existing: [],
      skipped_unscoped: [],
      skipped_lease_conflict: [],
      skipped_dispatch_cap: [],
    };
    for (const item of candidates) {
      if (result.dispatched.length >= input.count) break;
      const existing = this.engine.getRunningTaskForFrontierItem(item.id);
      if (existing) {
        const taskId = existing.task_id ?? existing.id;
        const label = existing.agent_label ?? existing.agent_id;
        result.skipped_existing.push({
          frontier_item_id: item.id,
          task_id: taskId,
          agent_label: label,
          id: taskId,
          agent_id: label,
        });
        continue;
      }
      const scope = this.engine.computeSubgraphNodeIds(item.id, input.hops);
      if (scope.length === 0 && item.type !== 'network_discovery') {
        result.skipped_unscoped.push({
          frontier_item_id: item.id,
          frontier_type: item.type,
        });
        continue;
      }
      const seedType = scope[0]
        ? this.engine.getNode(scope[0])?.type
        : undefined;
      const archetype = input.archetype
        ?? recommendArchetype({
          frontierType: item.type,
          nodeType: seedType,
        });
      const taskId = randomUUID();
      const label = `agent-${item.type.replace(/[^a-z]/g, '').slice(0, 6)}-${taskId.slice(0, 8)}`;
      const task = this.buildDispatchTask({
        agent_label: label,
        frontier_item_id: item.id,
        archetype,
        skill: input.skill,
        objective: item.description,
      }, scope);
      const registration = this.engine.registerAgent(task);
      if (registration.cap_exceeded) {
        result.skipped_dispatch_cap.push({
          frontier_item_id: item.id,
          frontier_type: item.type,
          cap_scope: registration.cap_exceeded.scope,
          cap_key: registration.cap_exceeded.key,
          limit: registration.cap_exceeded.limit,
          current: registration.cap_exceeded.current,
        });
        continue;
      }
      if (!registration.ok) {
        result.skipped_lease_conflict.push({
          frontier_item_id: item.id,
          frontier_type: item.type,
          existing_task_id: registration.lease_conflict?.existing_task_id
            ?? registration.node_conflict?.existing_task_id,
          existing_agent_id: registration.lease_conflict?.existing_agent_id
            ?? registration.node_conflict?.existing_agent_id,
        });
        continue;
      }
      result.dispatched.push({
        task_id: task.task_id ?? task.id,
        agent_label: task.agent_label ?? task.agent_id,
        id: task.task_id ?? task.id,
        agent_id: task.agent_label ?? task.agent_id,
        frontier_item_id: item.id,
        frontier_type: item.type,
        archetype,
        ...(input.skill ? { skill: input.skill } : {}),
      });
    }
    return result;
  }

  private executeCampaignDispatch(
    input: CampaignAgentDispatchInput,
  ): CampaignAgentDispatchResponse {
    const campaign = this.engine.getCampaign(input.campaign_id);
    if (!campaign) {
      throw new DispatchCommandError(
        `Campaign not found: ${input.campaign_id}`,
        'CAMPAIGN_NOT_FOUND',
        404,
        {
          http_status: 404,
          campaign_id: input.campaign_id,
        },
      );
    }
    if (
      campaign.status === 'paused'
      || campaign.status === 'aborted'
      || campaign.status === 'completed'
    ) {
      throw new DispatchCommandError(
        `Campaign is ${campaign.status} — cannot dispatch agents`,
        'CAMPAIGN_NOT_DISPATCHABLE',
        409,
        {
          http_status: 409,
          campaign_id: input.campaign_id,
          status: campaign.status,
        },
      );
    }
    if (this.engine.getCampaignChildren(input.campaign_id).length > 0) {
      throw new DispatchCommandError(
        'Campaign has child campaigns — dispatch a child campaign instead',
        'CAMPAIGN_HAS_CHILDREN',
        409,
        {
          http_status: 409,
          campaign_id: input.campaign_id,
        },
      );
    }

    const dispatched: CampaignAgentDispatchResponse['dispatched'] = [];
    const skipped: CampaignAgentDispatchResponse['skipped'] = [];
    const wasDraft = campaign.status === 'draft';

    for (const itemId of campaign.items) {
      if (dispatched.length >= input.max_agents) break;
      const itemStatus = campaign.item_status?.[itemId];
      if (itemStatus) {
        skipped.push({
          frontier_item_id: itemId,
          reason: `already_${itemStatus}`,
        });
        continue;
      }
      const existing = this.engine.getRunningTaskForFrontierItem(itemId);
      if (existing) {
        skipped.push({
          frontier_item_id: itemId,
          reason: `running_agent: ${existing.agent_label ?? existing.agent_id}`,
        });
        continue;
      }
      const frontierItem = this.engine.getActionableFrontierItem(itemId);
      if (!frontierItem) {
        skipped.push({
          frontier_item_id: itemId,
          reason: 'frontier_not_actionable',
        });
        continue;
      }
      const scope = this.computeCampaignScope(
        campaign.strategy,
        itemId,
        input.hops,
      );
      if (scope.length === 0 && frontierItem.type !== 'network_discovery') {
        skipped.push({
          frontier_item_id: itemId,
          reason: 'frontier_item_unscoped',
        });
        continue;
      }
      const archetype = this.resolveCampaignArchetype(
        input.archetype,
        campaign.strategy,
        frontierItem,
        scope,
      );
      const taskId = randomUUID();
      const label = `agent-campaign-${campaign.strategy.replace(/[^a-z]/g, '').slice(0, 6)}-${taskId.slice(0, 8)}`;
      const task = this.buildDispatchTask({
        agent_label: label,
        frontier_item_id: itemId,
        campaign_id: input.campaign_id,
        archetype,
        skill: input.skill,
        objective: frontierItem.description,
      }, scope);
      const registration = this.engine.registerAgent(task);
      if (registration.cap_exceeded) {
        skipped.push({
          frontier_item_id: itemId,
          reason: `dispatch_cap: ${registration.cap_exceeded.current}/${registration.cap_exceeded.limit} on ${registration.cap_exceeded.scope} ${registration.cap_exceeded.key}`,
        });
        continue;
      }
      if (!registration.ok) {
        skipped.push({
          frontier_item_id: itemId,
          reason: registration.node_conflict
            ? `node_dispatch_conflict: held by task ${registration.node_conflict.existing_task_id}`
            : `frontier_lease_conflict${registration.lease_conflict ? `: held by task ${registration.lease_conflict.existing_task_id}` : ''}`,
        });
        continue;
      }
      dispatched.push({
        task_id: task.task_id ?? task.id,
        agent_label: task.agent_label ?? task.agent_id,
        id: task.task_id ?? task.id,
        agent_id: task.agent_label ?? task.agent_id,
        frontier_item_id: itemId,
        scope_nodes: scope.length,
        archetype,
        ...(input.skill ? { skill: input.skill } : {}),
      });
    }
    if (wasDraft && dispatched.length > 0) {
      this.engine.activateCampaign(input.campaign_id);
    }
    return {
      campaign_id: input.campaign_id,
      strategy: campaign.strategy,
      requested: input.max_agents,
      total_items: campaign.items.length,
      dispatched,
      skipped,
      ...(dispatched.length === 0
        ? { warning: 'No agents dispatched — all items were skipped' }
        : {}),
    };
  }

  private executeSubnetDispatch(
    input: SubnetAgentDispatchInput,
  ): SubnetAgentDispatchResponse {
    const cidrs = this.engine.getConfig().scope.cidrs;
    if (cidrs.length === 0) {
      throw new DispatchCommandError(
        'No CIDRs in engagement scope',
        'NO_SCOPE_CIDRS',
        400,
        { http_status: 400 },
      );
    }
    const frontier = this.engine.computeFrontier();
    const filtered = this.engine.filterFrontier(frontier);
    const passedById = new Map(filtered.passed.map(item => [item.id, item]));
    const filteredById = new Set(filtered.filtered.map(item => item.item.id));
    const graph = this.engine.exportGraph();
    const dispatched: SubnetAgentDispatchResponse['dispatched'] = [];
    const skipped: SubnetAgentDispatchResponse['skipped'] = [];

    for (const cidr of cidrs) {
      if (dispatched.length >= input.max_agents) break;
      const slug = cidr.replace(/[./]/g, '-');
      const frontierItemId = `frontier-discovery-${slug}`;
      const frontierItem = passedById.get(frontierItemId);
      if (!frontierItem) {
        skipped.push({
          cidr,
          reason: filteredById.has(frontierItemId)
            ? 'filtered_by_opsec'
            : 'fully_discovered',
        });
        continue;
      }
      const existing = this.engine.getRunningTaskForFrontierItem(frontierItemId);
      if (existing) {
        skipped.push({
          cidr,
          reason: `running_agent: ${existing.agent_label ?? existing.agent_id}`,
        });
        continue;
      }
      const nodesInCidr = graph.nodes
        .filter(node =>
          node.properties.type === 'host'
          && typeof node.properties.ip === 'string'
          && isIpInCidr(node.properties.ip, cidr))
        .map(node => node.id);
      const taskId = randomUUID();
      const label = `agent-subnet-${slug}-${taskId.slice(0, 8)}`;
      const task = this.buildDispatchTask({
        agent_label: label,
        frontier_item_id: frontierItemId,
        archetype: 'recon_scanner',
        skill: input.skill,
        objective: frontierItem.description,
      }, nodesInCidr);
      const registration = this.engine.registerAgent(task);
      if (registration.cap_exceeded) {
        skipped.push({
          cidr,
          reason: `dispatch_cap: ${registration.cap_exceeded.current}/${registration.cap_exceeded.limit} on ${registration.cap_exceeded.scope} ${registration.cap_exceeded.key}`,
        });
        continue;
      }
      if (!registration.ok) {
        skipped.push({
          cidr,
          reason: registration.node_conflict
            ? `node_dispatch_conflict: held by task ${registration.node_conflict.existing_task_id}`
            : `frontier_lease_conflict${registration.lease_conflict ? `: held by task ${registration.lease_conflict.existing_task_id}` : ''}`,
        });
        continue;
      }
      dispatched.push({
        task_id: task.task_id ?? task.id,
        agent_label: task.agent_label ?? task.agent_id,
        id: task.task_id ?? task.id,
        agent_id: task.agent_label ?? task.agent_id,
        cidr,
        existing_nodes: nodesInCidr.length,
        skill: input.skill,
      });
    }
    return {
      requested: input.max_agents,
      total_cidrs: cidrs.length,
      dispatched,
      skipped,
    };
  }

  private computeCampaignScope(
    strategy: string,
    frontierItemId: string,
    hops: number,
  ): string[] {
    if (strategy === 'credential_spray') {
      return this.computeSprayScope(frontierItemId);
    }
    if (strategy === 'post_exploitation') {
      return this.engine.computeSubgraphNodeIds(frontierItemId, 1);
    }
    return this.engine.computeSubgraphNodeIds(frontierItemId, hops);
  }

  private computeSprayScope(frontierItemId: string): string[] {
    const scope = new Set(
      this.engine.computeSubgraphNodeIds(frontierItemId, 0),
    );
    const graph = this.engine.exportGraph();
    const nodeMap = new Map(graph.nodes.map(node => [node.id, node]));
    for (const seed of [...scope]) {
      for (const edge of graph.edges) {
        if (edge.source !== seed && edge.target !== seed) continue;
        const neighbor = edge.source === seed ? edge.target : edge.source;
        const neighborNode = nodeMap.get(neighbor);
        if (!neighborNode) continue;
        if (
          neighborNode.properties.type === 'credential'
          || neighborNode.properties.type === 'service'
          || neighborNode.properties.type === 'host'
          || neighborNode.properties.type === 'user'
        ) {
          scope.add(neighbor);
        }
        if (neighborNode.properties.type === 'service') {
          for (const parentEdge of graph.edges) {
            if (
              parentEdge.properties.type === 'RUNS'
              && (parentEdge.source === neighbor || parentEdge.target === neighbor)
            ) {
              scope.add(
                parentEdge.source === neighbor
                  ? parentEdge.target
                  : parentEdge.source,
              );
            }
          }
        }
      }
    }
    return [...scope];
  }

  private resolveCampaignArchetype(
    explicit: string | undefined,
    strategy: string,
    frontierItem: { type: string },
    scope: string[],
  ): AgentArchetypeId {
    if (explicit && isArchetypeId(explicit)) return explicit;
    const strategyArchetypes: Partial<Record<string, AgentArchetypeId>> = {
      credential_spray: 'credential_operator',
      post_exploitation: 'post_exploit',
      enumeration: 'recon_scanner',
      network_discovery: 'recon_scanner',
    };
    const strategyArchetype = strategyArchetypes[strategy];
    if (strategyArchetype) return strategyArchetype;
    const nodeType = scope[0]
      ? this.engine.getNode(scope[0])?.type
      : undefined;
    return recommendArchetype({
      frontierType: frontierItem.type as RecommendInput['frontierType'],
      nodeType,
    });
  }

  private buildDispatchTask(
    input: {
      agent_label?: string;
      archetype?: string;
      skill?: string;
      objective?: string;
      model?: string;
      campaign_id?: string;
      frontier_item_id?: string;
    },
    targetNodeIds: string[],
  ): AgentTask {
    if (input.archetype && !isArchetypeId(input.archetype)) {
      throw new DispatchCommandError(
        `Unknown agent type: ${input.archetype}`,
        'UNKNOWN_ARCHETYPE',
        400,
        { http_status: 400 },
      );
    }
    const explicit = input.archetype ? getArchetype(input.archetype) : undefined;
    const seedType = targetNodeIds[0]
      ? this.engine.getNode(targetNodeIds[0])?.type
      : undefined;
    const autoArchetype = recommendExploreArchetype(undefined, seedType);
    const model = this.resolveDispatchModel(input.model);
    const taskId = randomUUID();
    const agentLabel =
      input.agent_label ?? `dashboard-agent-${taskId.slice(0, 8)}`;
    const objective = input.objective
      ?? (explicit
        ? undefined
        : 'Explore and assess this node: check get_agent_context for prior actions on it first, then pursue untested attack surface.');
    return {
      id: taskId,
      task_id: taskId,
      agent_id: agentLabel,
      agent_label: agentLabel,
      assigned_at: this.engine.now(),
      status: 'running',
      subgraph_node_ids: targetNodeIds,
      skill: input.skill ?? explicit?.defaultSkill,
      campaign_id: input.campaign_id,
      frontier_item_id: input.frontier_item_id,
      ...(explicit
        ? {
            archetype: explicit.id,
            role: explicit.role,
            backend: explicit.backend,
          }
        : { archetype: autoArchetype }),
      ...(objective ? { objective } : {}),
      ...(model ? { model } : {}),
    };
  }

  private resolveDispatchModel(raw: unknown): string | undefined {
    const config = this.engine.getConfig();
    const requested = typeof raw === 'string' && raw.trim()
      ? raw.trim()
      : config.default_agent_model;
    if (
      requested
      && Array.isArray(config.available_models)
      && config.available_models.length > 0
      && !config.available_models.includes(requested)
    ) {
      throw new DispatchCommandError(
        `model "${requested}" is not allowed (available_models: ${config.available_models.join(', ')})`,
        'MODEL_NOT_ALLOWED',
        400,
        { http_status: 400 },
      );
    }
    return requested;
  }

  private classifyRawTargets(target: string): {
    add_cidrs: string[];
    add_domains: string[];
  } {
    const cidr = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    const ip = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domain = /^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/i;
    const add_cidrs: string[] = [];
    const add_domains: string[] = [];
    for (const token of target.split(/[\s,]+/).filter(Boolean)) {
      if (cidr.test(token)) add_cidrs.push(token);
      else if (ip.test(token)) add_cidrs.push(`${token}/32`);
      else if (domain.test(token)) add_domains.push(token.toLowerCase());
    }
    if (add_cidrs.length === 0 && add_domains.length === 0) {
      throw new DispatchCommandError(
        `no valid IPv4/CIDR/domain target in "${target}"`,
        'INVALID_TARGET',
        400,
        { http_status: 400 },
      );
    }
    return { add_cidrs, add_domains };
  }
}
