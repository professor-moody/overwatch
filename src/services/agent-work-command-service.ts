import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { AgentTask, Campaign, EngagementConfig } from '../types.js';
import {
  AgentHandoffRequestSchema,
  AgentMergeRequestSchema,
  AgentSplitRequestSchema,
  type AgentHandoffRequest,
  type AgentMergeRequest,
  type AgentSplitRequest,
} from '../contracts/dashboard-v1.js';
import {
  getArchetype,
  isArchetypeId,
} from './agent-archetypes.js';
import {
  ApplicationCommandService,
  getApplicationCommandInvocation,
  type ApplicationCommandExecution,
  type ApplicationCommandHost,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import type { ActivityLogEntry, ActivityLogInput } from './engine-context.js';
import {
  buildHandoffAgentWorkMetadata,
  buildMergedAgentWorkMetadata,
  buildSplitAgentWorkMetadata,
  canonicalAgentWorkSpec,
  compareAgentWorkStrings,
  groupExactDuplicateAgentWork,
  readAgentWorkMetadata,
} from './agent-work.js';
import { canonicalJson } from './engagement-config-service.js';
import { agentLabelOf, taskIdOf } from './agent-identity.js';

type WorkTask = AgentTask & { work: NonNullable<AgentTask['work']> };
const AgentTaskIdSchema = z.string().trim().min(1).max(512);

export interface AgentWorkCommandPort extends ApplicationCommandHost {
  getTask(taskId: string): AgentTask | null;
  getAgentTasks(): AgentTask[];
  getAgentWorkSuccessors(sourceTaskId: string, kind: 'handoff' | 'split'): AgentTask[];
  getFrontierItem(frontierItemId: string): unknown | null;
  getActionableFrontierItem(frontierItemId: string): unknown | null;
  getActiveFrontierLease(frontierItemId: string): { task_id: string; agent_id: string } | null;
  getCampaign(id: string): Campaign | null;
  getCampaignChildren(parentId: string): Campaign[];
  getAgentWorkTransferBlockers(taskId: string): string[];
  getConfig(): EngagementConfig;
  applyAgentCoordinationTaskChanges(
    reason: string,
    requested: ReadonlyArray<{ task_id: string; after: AgentTask }>,
  ): AgentTask[];
  logActionEvent(event: ActivityLogInput): ActivityLogEntry;
}

export class AgentWorkCommandError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly http_status: number,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'AgentWorkCommandError';
  }
}

export interface AgentHandoffResult {
  operation: 'handoff';
  source_task_id: string;
  created_tasks: WorkTask[];
  warnings: string[];
  reused_existing: boolean;
}

export interface AgentSplitResult {
  operation: 'split';
  source_task_id: string;
  created_tasks: WorkTask[];
  warnings: string[];
  reused_existing: boolean;
}

export interface AgentMergeResult {
  operation: 'merge';
  canonical_task_id: string;
  updated_tasks: WorkTask[];
  warnings: string[];
  reused_existing: boolean;
}

export interface AgentDuplicateWorkGroup {
  signature: string;
  canonical_task_id: string;
  candidate_task_ids: string[];
  tasks: WorkTask[];
}

export interface AgentDuplicatesResult {
  groups: AgentDuplicateWorkGroup[];
  total: number;
}

const TERMINAL = new Set<AgentTask['status']>([
  'completed',
  'failed',
  'interrupted',
]);

function normalizedIds(values: readonly string[] | undefined): string[] | undefined {
  if (!values?.length) return undefined;
  return [...new Set(values.map(value => value.trim()).filter(Boolean))]
    .sort();
}

function taskWithWork(task: AgentTask): WorkTask {
  return {
    ...structuredClone(task),
    work: readAgentWorkMetadata(task),
  };
}

function sameReferenceList(left: readonly string[] | undefined, right: readonly string[] | undefined): boolean {
  return canonicalJson(normalizedIds(left) ?? []) === canonicalJson(normalizedIds(right) ?? []);
}

export class AgentWorkCommandService {
  private readonly commands: ApplicationCommandService;

  constructor(
    private readonly engine: AgentWorkCommandPort,
    commands?: ApplicationCommandService,
  ) {
    this.commands = commands ?? new ApplicationCommandService(engine);
  }

  handoff(
    sourceTaskId: string,
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentHandoffResult> {
    this.assertOperatorAuthority();
    const source_task_id = sourceTaskId.trim();
    if (!source_task_id) {
      throw new AgentWorkCommandError('source task_id is required', 'AGENT_TASK_ID_REQUIRED', 400);
    }
    const body = AgentHandoffRequestSchema.parse(rawInput);
    const input = { source_task_id, ...body };
    const identity = this.commands.buildIdentity('agent.work.handoff', input, metadata);
    const boundMetadata = { ...metadata, command_id: identity.command_id };
    const execution = this.commands.executeSync({
      command_kind: 'agent.work.handoff',
      input,
      schema: AgentHandoffRequestSchema.extend({ source_task_id: AgentTaskIdSchema }),
      metadata: boundMetadata,
      // Agent, lease, activity, and receipt truth are all represented by
      // bounded operations. Capturing the historical roster/log as fallback
      // slices here would reintroduce O(total engagement) command drafting.
      state_keys: [],
      execute: parsed => this.executeHandoff(parsed.source_task_id, parsed, identity.command_id),
      record: (_parsed, result) => ({
        entity_refs: {
          source_task_id: result.source_task_id,
          task_id: result.created_tasks.map(taskIdOf),
        },
      }),
    });
    return this.requireSucceeded(execution);
  }

  split(
    parentTaskId: string,
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentSplitResult> {
    this.assertOperatorAuthority();
    const source_task_id = parentTaskId.trim();
    if (!source_task_id) {
      throw new AgentWorkCommandError('parent task_id is required', 'AGENT_TASK_ID_REQUIRED', 400);
    }
    const body = AgentSplitRequestSchema.parse(rawInput);
    const input = { source_task_id, ...body };
    const schema = AgentSplitRequestSchema.extend({ source_task_id: AgentTaskIdSchema });
    const identity = this.commands.buildIdentity('agent.work.split', input, metadata);
    const execution = this.commands.executeSync({
      command_kind: 'agent.work.split',
      input,
      schema,
      metadata: { ...metadata, command_id: identity.command_id },
      state_keys: [],
      execute: parsed => this.executeSplit(parsed.source_task_id, parsed, identity.command_id),
      record: (_parsed, result) => ({
        entity_refs: {
          source_task_id: result.source_task_id,
          task_id: result.created_tasks.map(taskIdOf),
        },
      }),
    });
    return this.requireSucceeded(execution);
  }

  merge(
    canonicalTaskId: string,
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentMergeResult> {
    this.assertOperatorAuthority();
    const canonical_task_id = canonicalTaskId.trim();
    if (!canonical_task_id) {
      throw new AgentWorkCommandError('canonical task_id is required', 'AGENT_TASK_ID_REQUIRED', 400);
    }
    const body = AgentMergeRequestSchema.parse(rawInput);
    const input = { canonical_task_id, ...body };
    const schema = AgentMergeRequestSchema.extend({ canonical_task_id: AgentTaskIdSchema });
    const execution = this.commands.executeSync({
      command_kind: 'agent.work.merge',
      input,
      schema,
      metadata,
      state_keys: [],
      execute: parsed => this.executeMerge(parsed.canonical_task_id, parsed),
      record: (_parsed, result) => ({
        entity_refs: {
          canonical_task_id: result.canonical_task_id,
          task_id: result.updated_tasks.map(taskIdOf),
        },
      }),
    });
    return this.requireSucceeded(execution);
  }

  findDuplicates(): AgentDuplicatesResult {
    this.assertOperatorAuthority();
    const tasks = this.engine.getAgentTasks();
    const byId = new Map(tasks.map(task => [taskIdOf(task), task]));
    const groups = groupExactDuplicateAgentWork(tasks).map(group => {
      const candidates = group.task_ids
        .map(taskId => byId.get(taskId))
        .filter((task): task is AgentTask => Boolean(task))
        .sort((left, right) => {
          const leftLive = left.status === 'running' || left.status === 'pending' ? 0 : 1;
          const rightLive = right.status === 'running' || right.status === 'pending' ? 0 : 1;
          return leftLive - rightLive
            || compareAgentWorkStrings(left.assigned_at, right.assigned_at)
            || compareAgentWorkStrings(taskIdOf(left), taskIdOf(right));
        });
      return {
        signature: group.signature,
        canonical_task_id: taskIdOf(candidates[0]!),
        candidate_task_ids: candidates.map(taskIdOf),
        tasks: candidates.map(taskWithWork),
      };
    });
    return { groups, total: groups.length };
  }

  private assertOperatorAuthority(): void {
    const actorTaskId = getApplicationCommandInvocation()?.actor_task_id;
    if (!actorTaskId) return;
    const actor = this.engine.getTask(actorTaskId);
    if (actor?.orchestrator === true || actor?.role === 'orchestrator') return;
    throw new AgentWorkCommandError(
      'Agent work inspection and shaping are operator/orchestrator actions; scoped workers may not inspect or reshape fleet work.',
      'AGENT_WORK_OPERATOR_REQUIRED',
      403,
      { actor_task_id: actorTaskId },
    );
  }

  private executeHandoff(
    sourceTaskId: string,
    input: AgentHandoffRequest,
    commandId: string,
  ): AgentHandoffResult {
    const source = this.requireTask(sourceTaskId);
    this.requireShapeableSource(source, 'handoff');
    const existing = this.existingSuccessors(sourceTaskId, 'handoff');
    if (existing.length > 0) {
      if (existing.length !== 1 || !this.successorMatches(existing[0]!, input, source.subgraph_node_ids)) {
        throw new AgentWorkCommandError(
          'This source already has a different durable handoff successor.',
          'AGENT_HANDOFF_ALREADY_EXISTS',
          409,
          { source_task_id: sourceTaskId, successor_task_ids: existing.map(taskIdOf) },
        );
      }
      return {
        operation: 'handoff',
        source_task_id: sourceTaskId,
        created_tasks: [taskWithWork(existing[0]!)],
        warnings: [
          ...(source.frontier_item_id && !existing[0]!.frontier_item_id
            ? ['frontier_not_reacquired']
            : []),
          ...(source.campaign_id && !existing[0]!.campaign_id
            ? ['campaign_not_reacquired']
            : []),
        ],
        reused_existing: true,
      };
    }
    this.requireQuiesced(source, 'handoff');
    const warnings: string[] = [];
    const actionableFrontierItemId = this.resolveHandoffFrontier(source, warnings);
    const binding = this.resolveHandoffCampaign(source, actionableFrontierItemId, warnings);
    const successor = this.buildSuccessorTask(input, {
      target_node_ids: source.subgraph_node_ids,
      ...binding,
      command_id: commandId,
    });
    successor.work = buildHandoffAgentWorkMetadata(source, successor, {
      created_at: this.engine.now(),
      summary: input.summary,
      key_finding_ids: input.key_finding_ids,
      key_evidence_ids: input.key_evidence_ids,
      key_event_ids: input.key_event_ids,
    });
    const sourceAfter: AgentTask = {
      ...source,
      work: readAgentWorkMetadata(source),
      no_retry: true,
    };
    const changed = this.engine.applyAgentCoordinationTaskChanges(
      `handoff agent work ${sourceTaskId}`,
      [
        { task_id: sourceTaskId, after: sourceAfter },
        { task_id: taskIdOf(successor), after: successor },
      ],
    );
    const created = changed.find(task => taskIdOf(task) === taskIdOf(successor))!;
    this.engine.logActionEvent({
      description: `Agent work handed off from ${agentLabelOf(source)} to ${agentLabelOf(created)}`,
      event_type: 'operator_command',
      category: 'agent',
      linked_agent_task_id: taskIdOf(created),
      frontier_item_id: created.frontier_item_id,
      result_classification: 'success',
      details: {
        reason: 'agent_work_handoff',
        source_task_id: sourceTaskId,
        successor_task_id: taskIdOf(created),
        warnings,
      },
    });
    return {
      operation: 'handoff',
      source_task_id: sourceTaskId,
      created_tasks: [taskWithWork(created)],
      warnings,
      reused_existing: false,
    };
  }

  /** Campaign attribution is durable operator truth, not a label to copy. A
   * successor may retain it only while the same active leaf campaign item is
   * still pending and actionable. Terminal/stale items fall back to explicit
   * node work without contaminating campaign progress. */
  private resolveHandoffCampaign(
    source: AgentTask,
    frontierItemId: string | undefined,
    warnings: string[],
  ): { campaign_id?: string; frontier_item_id?: string } {
    if (!source.campaign_id) {
      return frontierItemId ? { frontier_item_id: frontierItemId } : {};
    }
    const campaign = this.engine.getCampaign(source.campaign_id);
    if (!campaign) {
      throw new AgentWorkCommandError(
        `Campaign ${source.campaign_id} no longer exists.`,
        'AGENT_HANDOFF_CAMPAIGN_NOT_FOUND',
        409,
        { source_task_id: taskIdOf(source), campaign_id: source.campaign_id },
      );
    }
    if (campaign.status !== 'active') {
      throw new AgentWorkCommandError(
        `Campaign ${campaign.id} is ${campaign.status}; explicitly change its lifecycle before handing off work.`,
        'AGENT_HANDOFF_CAMPAIGN_INACTIVE',
        409,
        { source_task_id: taskIdOf(source), campaign_id: campaign.id, status: campaign.status },
      );
    }
    if (this.engine.getCampaignChildren(campaign.id).length > 0) {
      throw new AgentWorkCommandError(
        `Campaign ${campaign.id} has child campaigns; hand off work from the owning child instead.`,
        'AGENT_HANDOFF_CAMPAIGN_PARENT',
        409,
        { source_task_id: taskIdOf(source), campaign_id: campaign.id },
      );
    }
    const sourceFrontierItemId = source.frontier_item_id;
    if (!sourceFrontierItemId || !campaign.items.includes(sourceFrontierItemId)) {
      throw new AgentWorkCommandError(
        'The source task is not bound to a valid item in its campaign.',
        'AGENT_HANDOFF_CAMPAIGN_ITEM_INVALID',
        409,
        {
          source_task_id: taskIdOf(source),
          campaign_id: campaign.id,
          frontier_item_id: sourceFrontierItemId,
        },
      );
    }
    if (!frontierItemId || campaign.item_status?.[sourceFrontierItemId]) {
      if (!warnings.includes('frontier_not_reacquired')) {
        warnings.push('frontier_not_reacquired');
      }
      if (!warnings.includes('campaign_not_reacquired')) {
        warnings.push('campaign_not_reacquired');
      }
      return {};
    }
    return { campaign_id: campaign.id, frontier_item_id: frontierItemId };
  }

  private resolveHandoffFrontier(source: AgentTask, warnings: string[]): string | undefined {
    const frontierItemId = source.frontier_item_id;
    if (!frontierItemId) return undefined;
    const lease = this.engine.getActiveFrontierLease(frontierItemId);
    if (lease) {
      throw new AgentWorkCommandError(
        `Frontier item ${frontierItemId} is already leased by task ${lease.task_id}.`,
        'AGENT_HANDOFF_FRONTIER_LEASED',
        409,
        { source_task_id: taskIdOf(source), frontier_item_id: frontierItemId, lease },
      );
    }
    const raw = this.engine.getFrontierItem(frontierItemId);
    if (raw && !this.engine.getActionableFrontierItem(frontierItemId)) {
      throw new AgentWorkCommandError(
        `Frontier item ${frontierItemId} still exists but is not currently actionable.`,
        'AGENT_HANDOFF_FRONTIER_FILTERED',
        409,
        { source_task_id: taskIdOf(source), frontier_item_id: frontierItemId },
      );
    }
    if (raw) return frontierItemId;
    warnings.push('frontier_not_reacquired');
    if (source.subgraph_node_ids.length === 0) {
      throw new AgentWorkCommandError(
        'The source frontier no longer exists and has no node scope for a follow-up.',
        'AGENT_HANDOFF_NO_ACTIONABLE_SCOPE',
        409,
        { source_task_id: taskIdOf(source), frontier_item_id: frontierItemId },
      );
    }
    return undefined;
  }

  private executeSplit(
    sourceTaskId: string,
    input: AgentSplitRequest,
    commandId: string,
  ): AgentSplitResult {
    const source = this.requireTask(sourceTaskId);
    this.requireShapeableSource(source, 'split');
    const existing = this.existingSuccessors(sourceTaskId, 'split');
    if (existing.length > 0) {
      if (!this.splitMatches(existing, input)) {
        throw new AgentWorkCommandError(
          'This source already has a different durable split.',
          'AGENT_SPLIT_ALREADY_EXISTS',
          409,
          { source_task_id: sourceTaskId, child_task_ids: existing.map(taskIdOf) },
        );
      }
      return {
        operation: 'split',
        source_task_id: sourceTaskId,
        created_tasks: existing.map(taskWithWork),
        warnings: [],
        reused_existing: true,
      };
    }
    this.requireQuiesced(source, 'split');
    if (source.frontier_item_id || source.campaign_id) {
      throw new AgentWorkCommandError(
        'PR9 split supports ad-hoc node work only; frontier or campaign work must be handed off as one unit.',
        'AGENT_SPLIT_FRONTIER_UNSUPPORTED',
        409,
        {
          source_task_id: sourceTaskId,
          frontier_item_id: source.frontier_item_id,
          campaign_id: source.campaign_id,
        },
      );
    }
    this.validateSplitPartitions(source, input);
    const createdAt = this.engine.now();
    const children = input.children.map((child, index) => {
      const task = this.buildSuccessorTask(child, {
        target_node_ids: [...child.target_node_ids],
        command_id: commandId,
        fallback_label: `split-${sourceTaskId.slice(0, 8)}-${index + 1}`,
      });
      task.work = buildSplitAgentWorkMetadata(source, task, {
        created_at: createdAt,
        summary: input.summary,
        key_finding_ids: input.key_finding_ids,
        key_evidence_ids: input.key_evidence_ids,
        key_event_ids: input.key_event_ids,
      });
      return task;
    });
    const sourceAfter: AgentTask = {
      ...source,
      work: readAgentWorkMetadata(source),
      no_retry: true,
    };
    const changed = this.engine.applyAgentCoordinationTaskChanges(
      `split agent work ${sourceTaskId}`,
      [
        { task_id: sourceTaskId, after: sourceAfter },
        ...children.map(child => ({ task_id: taskIdOf(child), after: child })),
      ],
    );
    const childIds = new Set(children.map(taskIdOf));
    const created = changed.filter(task => childIds.has(taskIdOf(task)));
    this.engine.logActionEvent({
      description: `Agent work split from ${agentLabelOf(source)} into ${created.length} children`,
      event_type: 'operator_command',
      category: 'agent',
      linked_agent_task_id: sourceTaskId,
      result_classification: 'success',
      details: {
        reason: 'agent_work_split',
        source_task_id: sourceTaskId,
        child_task_ids: created.map(taskIdOf),
      },
    });
    return {
      operation: 'split',
      source_task_id: sourceTaskId,
      created_tasks: created.map(taskWithWork),
      warnings: [],
      reused_existing: false,
    };
  }

  private executeMerge(
    canonicalTaskId: string,
    input: AgentMergeRequest,
  ): AgentMergeResult {
    if (input.duplicate_task_ids.includes(canonicalTaskId)) {
      throw new AgentWorkCommandError(
        'canonical task cannot also be a duplicate',
        'AGENT_MERGE_SELF_REFERENCE',
        400,
      );
    }
    const canonical = this.requireTask(canonicalTaskId);
    const canonicalWork = readAgentWorkMetadata(canonical);
    if (canonicalWork.merged_into_task_id) {
      throw new AgentWorkCommandError(
        `Canonical task is already merged into ${canonicalWork.merged_into_task_id}.`,
        'AGENT_MERGE_CANONICAL_IS_SOURCE',
        409,
      );
    }
    const duplicates = input.duplicate_task_ids.map(taskId => this.requireTask(taskId));
    for (const duplicate of duplicates) {
      const duplicateWork = readAgentWorkMetadata(duplicate);
      if (duplicateWork.merged_into_task_id === canonicalTaskId) continue;
      this.requireQuiesced(duplicate, 'merge');
      if (duplicateWork.merged_into_task_id) {
        throw new AgentWorkCommandError(
          `Task ${taskIdOf(duplicate)} is already merged into ${duplicateWork.merged_into_task_id}.`,
          'AGENT_MERGE_ALREADY_MERGED',
          409,
        );
      }
      if (canonicalWork.signature !== duplicateWork.signature) {
        throw new AgentWorkCommandError(
          `Task ${taskIdOf(duplicate)} does not represent the same exact work as ${canonicalTaskId}.`,
          'AGENT_WORK_SIGNATURE_MISMATCH',
          409,
          {
            canonical_signature: canonicalWork.signature,
            duplicate_signature: duplicateWork.signature,
          },
        );
      }
    }
    const alreadyMerged = duplicates.every(duplicate =>
      readAgentWorkMetadata(duplicate).merged_into_task_id === canonicalTaskId);
    if (alreadyMerged) {
      return {
        operation: 'merge',
        canonical_task_id: canonicalTaskId,
        updated_tasks: [canonical, ...duplicates].map(taskWithWork),
        warnings: [],
        reused_existing: true,
      };
    }
    const canonicalAfter: AgentTask = {
      ...canonical,
      work: canonicalWork,
    };
    const duplicateAfters = duplicates.map(duplicate => ({
      ...duplicate,
      work: buildMergedAgentWorkMetadata(duplicate, canonical),
      no_retry: true,
    }));
    const changed = this.engine.applyAgentCoordinationTaskChanges(
      `merge exact duplicate agent work into ${canonicalTaskId}`,
      [
        { task_id: canonicalTaskId, after: canonicalAfter },
        ...duplicateAfters.map(task => ({ task_id: taskIdOf(task), after: task })),
      ],
    );
    this.engine.logActionEvent({
      description: `Merged ${duplicates.length} exact duplicate agent task(s) into ${agentLabelOf(canonical)}`,
      event_type: 'operator_command',
      category: 'agent',
      linked_agent_task_id: canonicalTaskId,
      result_classification: 'success',
      details: {
        reason: 'agent_work_merge',
        canonical_task_id: canonicalTaskId,
        duplicate_task_ids: duplicates.map(taskIdOf),
        summary: input.summary,
      },
    });
    return {
      operation: 'merge',
      canonical_task_id: canonicalTaskId,
      updated_tasks: changed.map(taskWithWork),
      warnings: [],
      reused_existing: false,
    };
  }

  private buildSuccessorTask(
    input: Pick<AgentHandoffRequest, 'agent_label' | 'archetype' | 'objective' | 'skill' | 'model'>,
    options: {
      target_node_ids: string[];
      campaign_id?: string;
      frontier_item_id?: string;
      command_id: string;
      fallback_label?: string;
    },
  ): AgentTask {
    if (!isArchetypeId(input.archetype)) {
      throw new AgentWorkCommandError(
        `Unknown agent type: ${input.archetype}`,
        'UNKNOWN_ARCHETYPE',
        400,
      );
    }
    const archetype = getArchetype(input.archetype);
    const model = this.resolveModel(input.model);
    const taskId = randomUUID();
    const agentLabel = input.agent_label
      ?? options.fallback_label
      ?? `handoff-${taskId.slice(0, 8)}`;
    return {
      id: taskId,
      task_id: taskId,
      agent_id: agentLabel,
      agent_label: agentLabel,
      assigned_at: this.engine.now(),
      // A committed successor is durable launch intent, not proof that a
      // process has started. The owning runner transitions pending -> running
      // only at its execution/target-launch acknowledgement boundary.
      status: 'pending',
      subgraph_node_ids: [...new Set(options.target_node_ids)].sort(),
      archetype: archetype.id,
      role: archetype.role,
      backend: archetype.backend,
      skill: input.skill ?? archetype.defaultSkill,
      objective: input.objective,
      campaign_id: options.campaign_id,
      frontier_item_id: options.frontier_item_id,
      application_command_id: options.command_id,
      ...(model ? { model } : {}),
    };
  }

  private resolveModel(raw: string | undefined): string | undefined {
    const config = this.engine.getConfig();
    const model = raw?.trim() || config.default_agent_model;
    if (model && config.available_models?.length && !config.available_models.includes(model)) {
      throw new AgentWorkCommandError(
        `model "${model}" is not allowed`,
        'MODEL_NOT_ALLOWED',
        400,
        { available_models: config.available_models },
      );
    }
    return model;
  }

  private requireTask(taskId: string): AgentTask {
    const task = this.engine.getTask(taskId);
    if (!task) {
      throw new AgentWorkCommandError(
        `Agent task ${taskId} was not found.`,
        'AGENT_TASK_NOT_FOUND',
        404,
        { task_id: taskId },
      );
    }
    return task;
  }

  private requireQuiesced(task: AgentTask, operation: string): void {
    if (!TERMINAL.has(task.status)) {
      throw new AgentWorkCommandError(
        `Agent task must be terminal before ${operation}; cancel it and wait for runtime termination first.`,
        `AGENT_${operation.toUpperCase()}_REQUIRES_TERMINAL`,
        409,
        { task_id: taskIdOf(task), status: task.status },
      );
    }
    const blockers = this.engine.getAgentWorkTransferBlockers(taskIdOf(task));
    if (blockers.length > 0) {
      throw new AgentWorkCommandError(
        `Agent task still owns live resources: ${blockers.join(', ')}.`,
        'AGENT_WORK_OWNERSHIP_ACTIVE',
        409,
        { task_id: taskIdOf(task), blockers },
      );
    }
  }

  private requireShapeableSource(task: AgentTask, requestedKind: 'handoff' | 'split'): void {
    const work = readAgentWorkMetadata(task);
    if (work.merged_into_task_id) {
      throw new AgentWorkCommandError(
        `Task ${taskIdOf(task)} was merged into ${work.merged_into_task_id} and cannot create successor work.`,
        'AGENT_WORK_SOURCE_MERGED',
        409,
        { task_id: taskIdOf(task), merged_into_task_id: work.merged_into_task_id },
      );
    }
    const otherKind = requestedKind === 'handoff' ? 'split' : 'handoff';
    const otherSuccessors = this.existingSuccessors(taskIdOf(task), otherKind);
    if (otherSuccessors.length > 0) {
      throw new AgentWorkCommandError(
        `Task ${taskIdOf(task)} already has durable ${otherKind} successor work.`,
        'AGENT_WORK_ALREADY_SHAPED',
        409,
        {
          task_id: taskIdOf(task),
          existing_kind: otherKind,
          successor_task_ids: otherSuccessors.map(taskIdOf),
        },
      );
    }
  }

  private existingSuccessors(
    sourceTaskId: string,
    kind: 'handoff' | 'split',
  ): AgentTask[] {
    return this.engine.getAgentWorkSuccessors(sourceTaskId, kind)
      .sort((left, right) => compareAgentWorkStrings(left.assigned_at, right.assigned_at)
        || compareAgentWorkStrings(taskIdOf(left), taskIdOf(right)));
  }

  private successorMatches(
    task: AgentTask,
    input: Pick<AgentHandoffRequest, 'agent_label' | 'archetype' | 'objective' | 'skill' | 'model' | 'summary' | 'key_finding_ids' | 'key_evidence_ids' | 'key_event_ids'>,
    expectedScope: readonly string[],
  ): boolean {
    const relation = task.work?.relation;
    const actualSpec = canonicalAgentWorkSpec(task);
    const archetype = getArchetype(input.archetype);
    const expectedSpec = {
      version: 1 as const,
      frontier_item_id: task.frontier_item_id ?? null,
      campaign_id: task.campaign_id ?? null,
      subgraph_node_ids: [...new Set(expectedScope)].sort(),
      archetype: input.archetype,
      role: archetype.role ?? null,
      skill: input.skill ?? archetype.defaultSkill ?? null,
      objective: input.objective.trim().replace(/\s+/g, ' '),
    };
    return (!input.agent_label || task.agent_label === input.agent_label)
      && canonicalJson(actualSpec) === canonicalJson(expectedSpec)
      && (task.skill ?? null) === (input.skill ?? getArchetype(input.archetype).defaultSkill ?? null)
      && (task.model ?? null) === (this.resolveModel(input.model) ?? null)
      && relation?.summary === input.summary.trim()
      && sameReferenceList(relation?.key_finding_ids, input.key_finding_ids)
      && sameReferenceList(relation?.key_evidence_ids, input.key_evidence_ids)
      && sameReferenceList(relation?.key_event_ids, input.key_event_ids);
  }

  private splitMatches(existing: AgentTask[], input: AgentSplitRequest): boolean {
    if (existing.length !== input.children.length) return false;
    const unmatched = [...existing];
    for (const child of input.children) {
      if (!isArchetypeId(child.archetype)) return false;
      const archetype = getArchetype(child.archetype);
      const expectedSpec = {
        version: 1 as const,
        frontier_item_id: null,
        campaign_id: null,
        subgraph_node_ids: [...new Set(child.target_node_ids)].sort(),
        archetype: child.archetype,
        role: archetype.role ?? null,
        skill: child.skill ?? archetype.defaultSkill ?? null,
        objective: child.objective.trim().replace(/\s+/g, ' '),
      };
      const matchIndex = unmatched.findIndex(task =>
        (!child.agent_label || task.agent_label === child.agent_label)
        && canonicalJson(canonicalAgentWorkSpec(task)) === canonicalJson(expectedSpec)
        && (task.model ?? null) === (this.resolveModel(child.model) ?? null)
        && task.work?.relation?.summary === input.summary.trim()
        && sameReferenceList(task.work?.relation?.key_finding_ids, input.key_finding_ids)
        && sameReferenceList(task.work?.relation?.key_evidence_ids, input.key_evidence_ids)
        && sameReferenceList(task.work?.relation?.key_event_ids, input.key_event_ids));
      if (matchIndex < 0) return false;
      unmatched.splice(matchIndex, 1);
    }
    return unmatched.length === 0;
  }

  private validateSplitPartitions(source: AgentTask, input: AgentSplitRequest): void {
    const sourceNodes = new Set(source.subgraph_node_ids);
    if (sourceNodes.size === 0) {
      throw new AgentWorkCommandError(
        'A split source must have non-empty node scope.',
        'AGENT_SPLIT_EMPTY_SOURCE',
        409,
      );
    }
    const covered = new Set<string>();
    for (const [index, child] of input.children.entries()) {
      const childNodes = new Set(child.target_node_ids);
      if (childNodes.size !== child.target_node_ids.length) {
        throw new AgentWorkCommandError(
          `Split child ${index + 1} contains duplicate node IDs.`,
          'AGENT_SPLIT_DUPLICATE_NODE',
          400,
        );
      }
      for (const nodeId of childNodes) {
        if (!sourceNodes.has(nodeId)) {
          throw new AgentWorkCommandError(
            `Split child ${index + 1} contains node ${nodeId} outside the source scope.`,
            'AGENT_SPLIT_SCOPE_MISMATCH',
            409,
          );
        }
        if (covered.has(nodeId)) {
          throw new AgentWorkCommandError(
            `Split partitions overlap at node ${nodeId}.`,
            'AGENT_SPLIT_SCOPE_OVERLAP',
            409,
          );
        }
        covered.add(nodeId);
      }
    }
    if (covered.size !== sourceNodes.size) {
      throw new AgentWorkCommandError(
        'Split partitions must cover the source scope exactly.',
        'AGENT_SPLIT_SCOPE_GAP',
        409,
        { uncovered_node_ids: [...sourceNodes].filter(nodeId => !covered.has(nodeId)) },
      );
    }
  }

  private requireSucceeded<T>(
    execution: ApplicationCommandExecution<T>,
  ): ApplicationCommandExecution<T> {
    if (execution.status === 'succeeded' && execution.result !== undefined) return execution;
    const details = execution.error?.details;
    const detailRecord = details && typeof details === 'object' && !Array.isArray(details)
      ? details as Record<string, unknown>
      : {};
    throw new AgentWorkCommandError(
      execution.error?.message ?? `Agent work command ${execution.status}.`,
      execution.error?.code ?? 'AGENT_WORK_COMMAND_FAILED',
      typeof detailRecord.http_status === 'number' ? detailRecord.http_status : 500,
      detailRecord,
    );
  }
}
