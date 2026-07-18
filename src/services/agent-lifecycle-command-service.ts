// ============================================================
// Overwatch — canonical agent coordination application commands
// ============================================================

import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { AgentDirective, AgentTask } from '../types.js';
import {
  ApplicationCommandService,
  getApplicationCommandInvocation,
  type ApplicationCommandExecution,
  type ApplicationCommandHost,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import type { AgentIdentityResolution } from './agent-identity.js';
import type { AgentQuery, AgentQueryStore } from './agent-query-store.js';
import type {
  ActivityLogEntry,
  ActivityLogInput,
} from './engine-context.js';
import type { EvidenceStore } from './evidence-store.js';
import type { ProposedPlanStore } from './proposed-plan-store.js';

/** Durable coordination capabilities used by agent lifecycle commands. */
export interface AgentLifecycleCommandPort extends ApplicationCommandHost {
  getTask(taskId: string): AgentTask | null;
  updateAgentStatus(
    taskId: string,
    status: AgentTask['status'],
    summary?: string,
  ): boolean;
  getProposedPlanStore(): ProposedPlanStore;
  getAgentQueryStore(): AgentQueryStore;
  getEvidenceStore(): EvidenceStore;
  getFullHistory(): ActivityLogEntry[];
  logActionEvent(event: ActivityLogInput): ActivityLogEntry;
  resolveAgentTaskReference(reference: string): AgentIdentityResolution;
  getAgentTasks(): AgentTask[];
  agentHeartbeat(
    taskId: string,
    now?: string,
    opts?: { silent?: boolean },
  ): boolean;
  getPendingAgentDirective(taskId: string): AgentDirective | null;
  issueAgentDirective(params: {
    task_id: string;
    kind: AgentDirective['kind'];
    node_ids?: string[];
    frontier_types?: string[];
    note?: string;
    issued_by?: string;
  }): AgentDirective;
  acknowledgeAgentDirective(
    taskId: string,
    directiveId: string,
  ): AgentDirective | null;
  updateAgentSchedulerFlags(
    taskId: string,
    patch: { no_retry?: boolean; reoffered?: boolean },
  ): boolean;
  abortApprovalsForTask(taskId: string, reason?: string): number;
  dismissAgent(taskId: string): boolean;
}

const AgentStatusUpdateInputSchema = z.object({
  task_id: z.string().trim().min(1),
  status: z.enum(['pending', 'running', 'completed', 'failed', 'interrupted']),
  summary: z.string().optional(),
}).strict();

const AgentTranscriptCommandInputSchema = z.object({
  task_id: z.string().trim().min(1),
  summary: z.string().trim().min(1),
  transcript_sha256: z.string().length(64).optional(),
  transcript_bytes: z.number().int().nonnegative(),
  key_thought_event_ids: z.array(z.string()).optional(),
  key_finding_ids: z.array(z.string()).optional(),
  planner_outcome: z.literal('unexpressible').optional(),
}).strict();

const AgentHeartbeatInputSchema = z.object({
  task_id: z.string().trim().min(1),
  acknowledged_query_id: z.string().trim().min(1).optional(),
}).strict();

const AgentQuestionInputSchema = z.object({
  task_id: z.string().trim().min(1),
  agent_label: z.string().trim().min(1).optional(),
  question: z.string().trim().min(1),
  options: z.array(z.string().trim().min(1)).optional(),
}).strict();

const AgentQuestionAnswerInputSchema = z.object({
  query_ids: z.array(z.string().trim().min(1)).min(1),
  answer: z.string().trim().min(1),
}).strict();

const AgentDirectiveInputSchema = z.object({
  task_id: z.string().trim().min(1),
  kind: z.enum([
    'pause',
    'resume',
    'stop',
    'narrow_scope',
    'skip_types',
    'prioritize',
    'instruct',
  ]),
  node_ids: z.array(z.string()).optional(),
  frontier_types: z.array(z.string()).optional(),
  note: z.string().optional(),
  issued_by: z.string().optional(),
}).strict();

const AgentDirectiveAckInputSchema = z.object({
  task_id: z.string().trim().min(1),
  directive_id: z.string().trim().min(1),
}).strict();

const AgentCancelInputSchema = z.object({
  task_id: z.string().trim().min(1),
  reason: z.string().trim().min(1),
}).strict();

const AgentDismissInputSchema = z.object({
  task_id: z.string().trim().min(1),
  force: z.boolean().default(false),
}).strict();

const AgentDismissBatchInputSchema = z.object({
  campaign_id: z.string().trim().min(1).optional(),
}).strict();

const AgentDirectiveBatchInputSchema = z.object({
  kind: z.enum(['pause', 'resume', 'stop', 'instruct']),
  note: z.string().optional(),
  campaign_id: z.string().trim().min(1).optional(),
}).strict();

export class AgentLifecycleCommandError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly http_status: number,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'AgentLifecycleCommandError';
  }
}

export interface AgentIdentityResult {
  task_id: string;
  agent_label: string;
  id: string;
  agent_id: string;
}

export interface AgentStatusUpdateResult extends AgentIdentityResult {
  status: AgentTask['status'];
  summary?: string;
  updated: true;
  transcript_warning?: string;
}

export interface AgentTranscriptResult extends AgentIdentityResult {
  event_id: string;
  evidence_id?: string;
  transcript_bytes: number;
  submitted: true;
  planner_outcome?: 'unexpressible';
}

export interface AgentHeartbeatResult extends AgentIdentityResult {
  ok: true;
  heartbeat_at?: string;
  heartbeat_ttl_seconds: number;
  acknowledged_query_id?: string;
  pending_directive?: AgentDirective;
  pending_answer?: {
    query_id: string;
    question: string;
    answer?: string;
  };
}

export interface AgentQuestionResult {
  ok: true;
  query: AgentQuery;
}

export interface AgentQuestionAnswerResult {
  ok: true;
  answered: number;
  queries: AgentQuery[];
}

export interface AgentDirectiveResult {
  ok: true;
  directive: AgentDirective;
}

export interface AgentCancelResult {
  cancelled: true;
  already_terminal: boolean;
  process_killed: boolean;
  task: AgentTask;
}

export interface AgentDismissResult {
  dismissed: true;
  task_id: string;
  forced: boolean;
}

export interface AgentDismissBatchResult {
  ok: true;
  dismissed: number;
  total: number;
}

export interface AgentDirectiveBatchResult {
  ok: true;
  applied: number;
  total: number;
  results: Array<{
    task_id: string;
    agent_label: string;
    kind: 'pause' | 'resume' | 'stop' | 'instruct';
    ok: true;
    directive_id: string;
  }>;
}

export interface AgentRuntimeController {
  cancelHeadless(task_id: string, reason?: string): boolean;
}

function identity(task: AgentTask): AgentIdentityResult {
  const taskId = task.task_id ?? task.id;
  const agentLabel = task.agent_label ?? task.agent_id;
  return {
    task_id: taskId,
    agent_label: agentLabel,
    id: taskId,
    agent_id: agentLabel,
  };
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function withActor(
  metadata: ApplicationCommandMetadata,
  taskId: string,
): ApplicationCommandMetadata {
  const invocation = getApplicationCommandInvocation();
  const explicit = Object.prototype.hasOwnProperty.call(metadata, 'actor_task_id');
  const actorTaskId = explicit
    ? metadata.actor_task_id ?? null
    : invocation
      ? invocation.actor_task_id
      : undefined;
  if (actorTaskId === null && (metadata.transport === 'mcp' || invocation?.transport === 'mcp')) {
    throw new AgentLifecycleCommandError(
      'An authenticated agent task is required for this MCP coordination operation.',
      'AGENT_ACTOR_REQUIRED',
      403,
      { task_id: taskId },
    );
  }
  if (typeof actorTaskId === 'string' && actorTaskId !== taskId) {
    throw new AgentLifecycleCommandError(
      `Authenticated task ${actorTaskId} cannot act as task ${taskId}.`,
      'AGENT_ACTOR_MISMATCH',
      409,
      { task_id: taskId, actor_task_id: actorTaskId },
    );
  }
  return actorTaskId === undefined
    ? { ...metadata, actor_task_id: taskId }
    : { ...metadata, actor_task_id: actorTaskId };
}

export class AgentLifecycleCommandService {
  private runtimeController: AgentRuntimeController | null = null;

  constructor(
    private readonly engine: AgentLifecycleCommandPort,
    private readonly commands: ApplicationCommandService = new ApplicationCommandService(engine),
  ) {}

  setRuntimeController(controller: AgentRuntimeController | null): void {
    this.runtimeController = controller;
  }

  updateStatus(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentStatusUpdateResult> {
    const input = AgentStatusUpdateInputSchema.parse(rawInput);
    const execution = this.commands.executeSync({
      command_kind: 'agent.lifecycle.update',
      input,
      schema: AgentStatusUpdateInputSchema,
      metadata: withActor(metadata, input.task_id),
      state_keys: [
        'agents',
        'campaigns',
        'plans_questions',
        'approvals',
        'activity',
        'frontier',
      ],
      execute: parsed => {
        const task = this.requireTask(parsed.task_id);
        const terminal = parsed.status === 'completed'
          || parsed.status === 'failed'
          || parsed.status === 'interrupted';
        if (terminal && task.role === 'planner' && task.application_command_id) {
          const owningCommand = this.engine.getApplicationCommandById(
            task.application_command_id,
          );
          const plan = this.engine.getProposedPlanStore()
            .getByCommandId(task.application_command_id);
          if (
            owningCommand
            && (owningCommand.status === 'accepted' || owningCommand.status === 'running')
            && !plan
          ) {
            if (parsed.status === 'completed') {
              throw new AgentLifecycleCommandError(
                'Planner cannot complete before proposing a plan or submitting a transcript with planner_outcome="unexpressible".',
                'PLANNER_CONCLUSION_REQUIRED',
                409,
                {
                  task_id: parsed.task_id,
                  command_id: task.application_command_id,
                },
              );
            }
            // A genuine runtime/tool failure is itself a terminal conclusion.
            // Settle the owning operator command in the same durable transaction
            // instead of forcing the process-exit fallback to misclassify it as
            // PLANNER_NO_PLAN.
            const interrupted = parsed.status === 'interrupted';
            const reason = parsed.summary
              ?? (interrupted
                ? 'Planner was interrupted before returning a plan.'
                : 'Planner failed before returning a plan.');
            this.commands.transition(task.application_command_id, {
              status: interrupted ? 'interrupted' : 'failed',
              error: {
                code: interrupted ? 'PLANNER_INTERRUPTED' : 'PLANNER_FAILED',
                message: reason,
              },
              entity_refs: { planner_task_id: parsed.task_id },
              result: {
                phase: interrupted ? 'interrupted' : 'failed',
                command_id: task.application_command_id,
                planner_task_id: parsed.task_id,
                reason,
              },
            });
          }
        }
        let transcriptWarning: string | undefined;
        if (terminal && !this.hasSubmittedTranscript(task)) {
          this.engine.logActionEvent({
            description: `Agent ${parsed.task_id} closed with status "${parsed.status}" without calling submit_agent_transcript first`,
            event_type: 'instrumentation_warning',
            category: 'system',
            provenance: 'system',
            linked_agent_task_id: parsed.task_id,
            details: {
              warning: 'missing_agent_transcript',
              task_id: parsed.task_id,
              status: parsed.status,
            },
          });
          transcriptWarning = 'Call submit_agent_transcript before update_agent on terminal status to keep the primary session in the loop.';
        }
        if (!this.engine.updateAgentStatus(parsed.task_id, parsed.status, parsed.summary)) {
          const currentStatus = this.engine.getTask(parsed.task_id)?.status;
          throw new AgentLifecycleCommandError(
            currentStatus
              ? `Task ${parsed.task_id} is already ${currentStatus}; it cannot transition to ${parsed.status}.`
              : `Task not updated: ${parsed.task_id}`,
            'AGENT_STATUS_NOT_UPDATED',
            409,
            {
              task_id: parsed.task_id,
              status: parsed.status,
              ...(currentStatus ? { current_status: currentStatus } : {}),
            },
          );
        }
        return {
          ...identity(task),
          status: parsed.status,
          summary: parsed.summary,
          updated: true as const,
          ...(transcriptWarning
            ? { transcript_warning: transcriptWarning }
            : {}),
        };
      },
      record: () => ({ entity_refs: { task_id: input.task_id } }),
    });
    return this.requireSucceeded(execution);
  }

  submitTranscript(
    rawInput: {
      task_reference: string;
      summary: string;
      transcript_jsonl?: string;
      key_thought_event_ids?: string[];
      key_finding_ids?: string[];
      planner_outcome?: 'unexpressible';
    },
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentTranscriptResult> {
    const transcript = rawInput.transcript_jsonl;
    const transcriptFields = {
      summary: rawInput.summary,
      transcript_sha256: transcript ? sha256(transcript) : undefined,
      transcript_bytes: transcript ? Buffer.byteLength(transcript, 'utf8') : 0,
      key_thought_event_ids: rawInput.key_thought_event_ids,
      key_finding_ids: rawInput.key_finding_ids,
      planner_outcome: rawInput.planner_outcome,
    };
    // A completed task may have been dismissed after the original transcript
    // landed. Canonical task-id retries must still return that durable result.
    if (!this.engine.getTask(rawInput.task_reference)) {
      const directInput = AgentTranscriptCommandInputSchema.parse({
        task_id: rawInput.task_reference,
        ...transcriptFields,
      });
      const directReplay = this.commands.lookup<
        typeof directInput,
        AgentTranscriptResult
      >(
        'agent.transcript.submit',
        directInput,
        withActor(metadata, rawInput.task_reference),
      );
      if (directReplay) return this.requireSucceeded(directReplay);
    }
    const task = this.resolveTaskReference(rawInput.task_reference);
    const taskId = task.task_id ?? task.id;
    const canonicalInput = AgentTranscriptCommandInputSchema.parse({
      task_id: taskId,
      ...transcriptFields,
    });
    const effectiveMetadata = withActor(metadata, taskId);
    const replay = this.commands.lookup<
      typeof canonicalInput,
      AgentTranscriptResult
    >('agent.transcript.submit', canonicalInput, effectiveMetadata);
    if (replay) return this.requireSucceeded(replay);

    const evidenceId = transcript
      ? this.engine.getEvidenceStore().store({
          evidence_type: 'log',
          filename: 'agent_transcript.jsonl',
          content: transcript,
        })
      : undefined;
    const execution = this.commands.executeSync({
      command_kind: 'agent.transcript.submit',
      input: canonicalInput,
      schema: AgentTranscriptCommandInputSchema,
      metadata: effectiveMetadata,
      state_keys: [
        'agents',
        'campaigns',
        'plans_questions',
        'approvals',
        'activity',
        'frontier',
      ],
      execute: parsed => {
        const details: Record<string, unknown> = {
          summary: parsed.summary,
          transcript_bytes: parsed.transcript_bytes,
        };
        if (evidenceId) details.evidence_id = evidenceId;
        if (parsed.key_thought_event_ids?.length) {
          details.key_thought_event_ids = parsed.key_thought_event_ids;
        }
        if (parsed.key_finding_ids?.length) {
          details.key_finding_ids = parsed.key_finding_ids;
        }
        if (parsed.planner_outcome) details.planner_outcome = parsed.planner_outcome;
        const event = this.engine.logActionEvent({
          description: `Agent ${task.agent_label ?? task.agent_id} submitted transcript: ${parsed.summary.slice(0, 120)}${parsed.summary.length > 120 ? '…' : ''}`,
          event_type: 'agent_transcript_submitted',
          category: 'agent',
          provenance: 'agent',
          agent_id: task.agent_label ?? task.agent_id,
          linked_agent_task_id: taskId,
          linked_finding_ids: parsed.key_finding_ids,
          details,
        });
        if (
          parsed.planner_outcome === 'unexpressible'
          && task.role === 'planner'
          && task.application_command_id
        ) {
          const owningCommand = this.engine.getApplicationCommandById(task.application_command_id);
          if (
            owningCommand
            && (owningCommand.status === 'accepted' || owningCommand.status === 'running')
          ) {
            const message = `Planner could not express this command with the available operations: ${parsed.summary}`;
            this.engine.recordApplicationCommand({
              ...owningCommand,
              status: 'failed',
              completed_at: this.engine.now(),
              error: {
                code: 'PLANNER_UNEXPRESSIBLE',
                message,
                details: { planner_summary: parsed.summary },
              },
              result: {
                phase: 'unanswerable',
                command_id: owningCommand.command_id,
                planner_task_id: taskId,
                reason: parsed.summary,
              },
              entity_refs: {
                ...(owningCommand.entity_refs ?? {}),
                planner_task_id: taskId,
              },
            });
            if (!this.engine.updateAgentStatus(taskId, 'completed', parsed.summary)) {
              throw new AgentLifecycleCommandError(
                `Planner task not completed after unexpressible conclusion: ${taskId}`,
                'PLANNER_CONCLUSION_NOT_APPLIED',
                409,
                { task_id: taskId, command_id: owningCommand.command_id },
              );
            }
          }
        }
        return {
          ...identity(task),
          event_id: event.event_id,
          evidence_id: evidenceId,
          transcript_bytes: parsed.transcript_bytes,
          ...(parsed.planner_outcome ? { planner_outcome: parsed.planner_outcome } : {}),
          submitted: true as const,
        };
      },
      record: (_parsed, result) => ({
        entity_refs: {
          task_id: taskId,
          event_id: result.event_id,
          ...(result.evidence_id ? { evidence_id: result.evidence_id } : {}),
        },
      }),
    });
    return this.requireSucceeded(execution);
  }

  heartbeat(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentHeartbeatResult> {
    const input = AgentHeartbeatInputSchema.parse(rawInput);
    const execution = this.commands.executeSync({
      command_kind: 'agent.heartbeat',
      input,
      schema: AgentHeartbeatInputSchema,
      metadata: withActor(metadata, input.task_id),
      state_keys: ['agents', 'plans_questions', 'activity', 'frontier'],
      execute: parsed => {
        if (parsed.acknowledged_query_id) {
          const query = this.engine.getAgentQueryStore().get(parsed.acknowledged_query_id);
          const ownerTaskId = query?.owner_task_id ?? query?.task_id;
          if (
            !query
            || ownerTaskId !== parsed.task_id
            || query.status !== 'answered'
          ) {
            throw new AgentLifecycleCommandError(
              `query answer not found for task ${parsed.task_id}: ${parsed.acknowledged_query_id}`,
              'AGENT_QUERY_ANSWER_NOT_FOUND',
              404,
              {
                task_id: parsed.task_id,
                query_id: parsed.acknowledged_query_id,
              },
            );
          }
        }
        if (!this.engine.agentHeartbeat(parsed.task_id)) {
          const current = this.engine.getTask(parsed.task_id);
          throw new AgentLifecycleCommandError(
            current
              ? `task is already in terminal state: ${current.status}`
              : `task not found: ${parsed.task_id}`,
            current ? 'AGENT_TERMINAL' : 'AGENT_NOT_FOUND',
            current ? 409 : 404,
            { task_id: parsed.task_id },
          );
        }
        const task = this.requireTask(parsed.task_id);
        if (
          parsed.acknowledged_query_id
          && !this.engine.getAgentQueryStore().acknowledge(
            parsed.acknowledged_query_id,
            parsed.task_id,
          )
        ) {
          throw new AgentLifecycleCommandError(
            `query answer not found for task ${parsed.task_id}: ${parsed.acknowledged_query_id}`,
            'AGENT_QUERY_ANSWER_NOT_FOUND',
            404,
          );
        }
        const pending = this.engine.getPendingAgentDirective(parsed.task_id);
        const answered = this.engine.getAgentQueryStore().getAnswerForTask(parsed.task_id);
        if (answered) {
          this.engine.getAgentQueryStore().markDelivered(
            answered.query_id,
            parsed.task_id,
          );
        }
        return {
          ...identity(task),
          ok: true as const,
          heartbeat_at: task.heartbeat_at,
          heartbeat_ttl_seconds: task.heartbeat_ttl_seconds ?? 120,
          ...(parsed.acknowledged_query_id
            ? { acknowledged_query_id: parsed.acknowledged_query_id }
            : {}),
          ...(pending ? { pending_directive: pending } : {}),
          ...(answered
            ? {
                pending_answer: {
                  query_id: answered.query_id,
                  question: answered.question,
                  answer: answered.answer,
                },
              }
            : {}),
        };
      },
      record: () => ({ entity_refs: { task_id: input.task_id } }),
    });
    return this.requireSucceeded(execution);
  }

  askQuestion(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentQuestionResult> {
    const input = AgentQuestionInputSchema.parse(rawInput);
    const execution = this.commands.executeSync({
      command_kind: 'agent.question.ask',
      input,
      schema: AgentQuestionInputSchema,
      metadata: withActor(metadata, input.task_id),
      state_keys: ['plans_questions', 'activity'],
      execute: parsed => {
        const task = this.requireTask(parsed.task_id);
        const taskLabel = task.agent_label ?? task.agent_id;
        if (parsed.agent_label && parsed.agent_label !== taskLabel) {
          throw new AgentLifecycleCommandError(
            `agent_id "${parsed.agent_label}" does not match task ${parsed.task_id} (${taskLabel})`,
            'AGENT_IDENTITY_MISMATCH',
            409,
            { task_id: parsed.task_id, agent_label: taskLabel },
          );
        }
        const query = this.engine.getAgentQueryStore().add({
          owner_task_id: parsed.task_id,
          owner_agent_label: taskLabel,
          question: parsed.question,
          options: parsed.options,
        });
        this.engine.logActionEvent({
          description: `Agent asked the operator: ${parsed.question}`,
          event_type: 'agent_query',
          category: 'agent',
          result_classification: 'neutral',
          agent_id: taskLabel,
          linked_agent_task_id: parsed.task_id,
          details: {
            reason: 'agent_query',
            query_id: query.query_id,
            question: parsed.question,
            options: parsed.options,
          },
        });
        return { ok: true as const, query };
      },
      record: (_parsed, result) => ({
        entity_refs: {
          task_id: input.task_id,
          query_id: result.query.query_id,
        },
      }),
    });
    return this.requireSucceeded(execution);
  }

  answerQuestions(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentQuestionAnswerResult> {
    const parsed = AgentQuestionAnswerInputSchema.parse(rawInput);
    const input = {
      ...parsed,
      query_ids: [...new Set(parsed.query_ids)],
    };
    const execution = this.commands.executeSync({
      command_kind: 'agent.question.answer',
      input,
      schema: AgentQuestionAnswerInputSchema,
      metadata,
      state_keys: ['plans_questions', 'activity'],
      execute: canonical => {
        if (canonical.query_ids.length === 1) {
          const existing = this.engine.getAgentQueryStore().get(
            canonical.query_ids[0],
          );
          const ownerTaskId = existing?.owner_task_id ?? existing?.task_id;
          const ownerTask = ownerTaskId
            ? this.engine.getTask(ownerTaskId)
            : undefined;
          if (existing && ownerTaskId && (!ownerTask || ownerTask.status !== 'running')) {
            throw new AgentLifecycleCommandError(
              'the asking agent is no longer running — answer would not be delivered',
              'AGENT_QUESTION_OWNER_NOT_RUNNING',
              409,
              {
                query_id: existing.query_id,
                task_id: ownerTaskId,
              },
            );
          }
        }
        const deliverable = canonical.query_ids.filter(queryId => {
          const existing = this.engine.getAgentQueryStore().get(queryId);
          if (!existing) return false;
          const ownerTaskId = existing.owner_task_id ?? existing.task_id;
          if (!ownerTaskId) return true;
          const task = this.engine.getTask(ownerTaskId);
          return Boolean(task && task.status === 'running');
        });
        const queries = this.engine.getAgentQueryStore().answerMany(
          deliverable,
          canonical.answer,
        );
        if (queries.length === 0) {
          throw new AgentLifecycleCommandError(
            'no answerable questions — all unknown, already answered, or their agents are gone',
            'AGENT_QUESTION_NOT_ANSWERABLE',
            404,
            { query_ids: canonical.query_ids },
          );
        }
        this.engine.logActionEvent({
          description: `Operator answered ${queries.length} agent question(s): ${queries[0].question}`,
          event_type: 'operator_command',
          category: 'system',
          source_kind: metadata.transport === 'dashboard' ? 'dashboard' : 'system',
          result_classification: 'neutral',
          details: {
            reason: queries.length === 1
              ? 'agent_query_answered'
              : 'agent_query_answered_batch',
            source: metadata.transport ?? 'system',
            query_ids: queries.map(query => query.query_id),
            question: queries[0].question,
            answer: canonical.answer,
            count: queries.length,
          },
        });
        return {
          ok: true as const,
          answered: queries.length,
          queries,
        };
      },
      record: (_canonical, result) => ({
        entity_refs: { query_id: result.queries.map(query => query.query_id) },
      }),
    });
    return this.requireSucceeded(execution);
  }

  issueDirective(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentDirectiveResult> {
    const input = AgentDirectiveInputSchema.parse(rawInput);
    const execution = this.commands.executeSync({
      command_kind: 'agent.directive.issue',
      input,
      schema: AgentDirectiveInputSchema,
      metadata,
      state_keys: ['directives', 'activity', 'frontier'],
      execute: parsed => {
        const task = this.requireTask(parsed.task_id);
        if (task.status !== 'running' && task.status !== 'pending') {
          throw new AgentLifecycleCommandError(
            `task is not running or pending (status: ${task.status}); directives cannot be delivered`,
            'AGENT_NOT_LIVE',
            409,
            { task_id: parsed.task_id, status: task.status },
          );
        }
        return {
          ok: true as const,
          directive: this.engine.issueAgentDirective(parsed),
        };
      },
      record: (_parsed, result) => ({
        entity_refs: {
          task_id: input.task_id,
          directive_id: result.directive.id,
        },
      }),
    });
    return this.requireSucceeded(execution);
  }

  acknowledgeDirective(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentDirectiveResult> {
    const input = AgentDirectiveAckInputSchema.parse(rawInput);
    const execution = this.commands.executeSync({
      command_kind: 'agent.directive.acknowledge',
      input,
      schema: AgentDirectiveAckInputSchema,
      metadata: withActor(metadata, input.task_id),
      state_keys: ['directives', 'activity', 'frontier'],
      execute: parsed => {
        const directive = this.engine.acknowledgeAgentDirective(
          parsed.task_id,
          parsed.directive_id,
        );
        if (!directive) {
          throw new AgentLifecycleCommandError(
            'directive not found',
            'AGENT_DIRECTIVE_NOT_FOUND',
            404,
            {
              task_id: parsed.task_id,
              directive_id: parsed.directive_id,
            },
          );
        }
        return { ok: true as const, directive };
      },
      record: () => ({
        entity_refs: {
          task_id: input.task_id,
          directive_id: input.directive_id,
        },
      }),
    });
    return this.requireSucceeded(execution);
  }

  cancel(
    taskId: string,
    reason = 'cancelled by operator',
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentCancelResult> {
    const input = AgentCancelInputSchema.parse({
      task_id: taskId,
      reason,
    });
    const replay = this.commands.lookup<
      typeof input,
      AgentCancelResult
    >('agent.cancel', input, metadata);
    if (
      replay
      && replay.status !== 'accepted'
      && replay.status !== 'running'
    ) {
      return this.requireSucceeded(replay);
    }
    const task = this.requireTask(input.task_id);
    const alreadyTerminal = task.status !== 'running' && task.status !== 'pending';
    const reservation = replay ?? this.commands.reserveSync({
      command_kind: 'agent.cancel',
      input,
      schema: AgentCancelInputSchema,
      metadata,
      state_keys: [
        'agents',
        'campaigns',
        'plans_questions',
        'approvals',
        'activity',
        'frontier',
      ],
      reserve: parsed => {
        this.engine.updateAgentSchedulerFlags(parsed.task_id, {
          no_retry: true,
        });
        const current = this.requireTask(parsed.task_id);
        if (current.status === 'running' || current.status === 'pending') {
          this.engine.updateAgentStatus(
            parsed.task_id,
            'interrupted',
            parsed.reason,
          );
        }
        this.engine.abortApprovalsForTask(parsed.task_id, parsed.reason);
        return {
          status: 'accepted',
          entity_refs: { task_id: parsed.task_id },
          result: {
            phase: 'cancel_reserved',
            task_id: parsed.task_id,
            already_terminal: alreadyTerminal,
          },
        };
      },
    });
    if (
      reservation.status !== 'accepted'
      && reservation.status !== 'running'
    ) {
      return this.requireSucceeded(
        reservation as ApplicationCommandExecution<AgentCancelResult>,
      );
    }

    let killed = false;
    try {
      killed = this.runtimeController?.cancelHeadless(
        input.task_id,
        input.reason,
      ) ?? false;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const failed = this.commands.transition<AgentCancelResult>(
        reservation.command_id,
        {
          status: 'failed',
          error: {
            code: 'AGENT_PROCESS_CANCEL_FAILED',
            message: `Agent process cancellation failed: ${message}`,
            details: { http_status: 500 },
          },
          entity_refs: { task_id: input.task_id },
          result: {
            cancelled: true,
            already_terminal: alreadyTerminal,
            process_killed: false,
            task: this.requireTask(input.task_id),
          },
        },
      );
      return this.requireSucceeded(failed);
    }
    const reservedResult = reservation.result
      && typeof reservation.result === 'object'
      ? reservation.result as Record<string, unknown>
      : undefined;
    const originallyTerminal = typeof reservedResult?.already_terminal === 'boolean'
      ? reservedResult.already_terminal
      : alreadyTerminal;
    return this.requireSucceeded(this.commands.transition<AgentCancelResult>(
      reservation.command_id,
      {
        status: 'succeeded',
        entity_refs: { task_id: input.task_id },
        result: {
          cancelled: true,
          already_terminal: originallyTerminal,
          process_killed: killed,
          task: this.requireTask(input.task_id),
        },
      },
    ));
  }

  dismiss(
    taskId: string,
    force = false,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentDismissResult> {
    const input = AgentDismissInputSchema.parse({
      task_id: taskId,
      force,
    });
    const replay = this.commands.lookup<
      typeof input,
      AgentDismissResult
    >('agent.dismiss', input, metadata);
    if (replay) return this.requireSucceeded(replay);
    const task = this.requireTask(input.task_id);
    const live = task.status === 'running' || task.status === 'pending';
    if (live && !input.force) {
      throw new AgentLifecycleCommandError(
        `Agent is ${task.status} — cancel it before dismissing (or pass force:true)`,
        'AGENT_DISMISS_REQUIRES_CANCEL',
        409,
        { task_id: input.task_id, status: task.status },
      );
    }
    if (input.force) {
      const identity = this.commands.buildIdentity(
        'agent.dismiss',
        input,
        metadata,
      );
      this.cancel(input.task_id, 'Force-removed by operator', {
        transport: identity.transport,
        actor_task_id: identity.actor_task_id,
        command_id: `${identity.command_id}:cancel`,
        idempotency_key: `${identity.idempotency_key}:cancel`,
      });
    }
    const execution = this.commands.executeSync({
      command_kind: 'agent.dismiss',
      input,
      schema: AgentDismissInputSchema,
      metadata,
      state_keys: ['agents', 'activity', 'frontier'],
      execute: parsed => {
        if (!this.engine.dismissAgent(parsed.task_id)) {
          throw new AgentLifecycleCommandError(
            'Failed to dismiss agent',
            'AGENT_DISMISS_FAILED',
            409,
            { task_id: parsed.task_id },
          );
        }
        return {
          dismissed: true as const,
          task_id: parsed.task_id,
          forced: parsed.force,
        };
      },
      record: () => ({ entity_refs: { task_id: input.task_id } }),
    });
    return this.requireSucceeded(execution);
  }

  dismissBatch(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentDismissBatchResult> {
    const input = AgentDismissBatchInputSchema.parse(rawInput);
    const execution = this.commands.executeSync({
      command_kind: 'agent.dismiss_batch',
      input,
      schema: AgentDismissBatchInputSchema,
      metadata,
      state_keys: ['agents', 'activity', 'frontier'],
      execute: parsed => {
        const terminal = new Set<AgentTask['status']>([
          'completed',
          'failed',
          'interrupted',
        ]);
        const targets = this.engine.getAgentTasks().filter(task =>
          terminal.has(task.status)
          && (!parsed.campaign_id || task.campaign_id === parsed.campaign_id));
        let dismissed = 0;
        for (const task of targets) {
          if (this.engine.dismissAgent(task.task_id ?? task.id)) dismissed++;
        }
        return {
          ok: true as const,
          dismissed,
          total: targets.length,
        };
      },
    });
    return this.requireSucceeded(execution);
  }

  issueDirectiveBatch(
    rawInput: unknown,
    metadata: ApplicationCommandMetadata = {},
  ): ApplicationCommandExecution<AgentDirectiveBatchResult> {
    const input = AgentDirectiveBatchInputSchema.parse(rawInput);
    const note = input.note?.trim();
    if (input.kind === 'instruct' && !note) {
      throw new AgentLifecycleCommandError(
        'fleet instruct requires a non-empty note',
        'AGENT_DIRECTIVE_NOTE_REQUIRED',
        400,
      );
    }
    const canonicalInput = {
      ...input,
      ...(note ? { note } : {}),
    };
    const execution = this.commands.executeSync({
      command_kind: 'agent.directive.issue_batch',
      input: canonicalInput,
      schema: AgentDirectiveBatchInputSchema,
      metadata,
      state_keys: ['directives', 'activity', 'frontier'],
      execute: parsed => {
        const targets = this.engine.getAgentTasks().filter(task =>
          task.status === 'running'
          && (!parsed.campaign_id || task.campaign_id === parsed.campaign_id));
        const results = targets.map(task => {
          const directive = this.engine.issueAgentDirective({
            task_id: task.task_id ?? task.id,
            kind: parsed.kind,
            note: parsed.note,
            issued_by: 'operator',
          });
          return {
            task_id: task.task_id ?? task.id,
            agent_label: task.agent_label ?? task.agent_id,
            kind: parsed.kind,
            ok: true as const,
            directive_id: directive.id,
          };
        });
        this.engine.logActionEvent({
          description: `Operator fleet directive: ${parsed.kind} → ${results.length}/${targets.length} running agent(s)${parsed.campaign_id ? ` in campaign ${parsed.campaign_id}` : ''}`,
          event_type: 'operator_command',
          category: 'system',
          source_kind: metadata.transport === 'dashboard'
            ? 'dashboard'
            : 'system',
          result_classification: 'success',
          details: {
            reason: 'operator_command',
            source: metadata.transport ?? 'system',
            command: `${parsed.kind} all${parsed.campaign_id ? ` (campaign ${parsed.campaign_id})` : ''}`,
            results,
          },
        });
        return {
          ok: true as const,
          applied: results.length,
          total: targets.length,
          results,
        };
      },
      record: (_parsed, result) => ({
        entity_refs: {
          task_id: result.results.map(item => item.task_id),
          directive_id: result.results.map(item => item.directive_id),
        },
      }),
    });
    return this.requireSucceeded(execution);
  }

  private requireTask(taskId: string): AgentTask {
    const task = this.engine.getTask(taskId);
    if (!task) {
      throw new AgentLifecycleCommandError(
        `Task not found: ${taskId}`,
        'AGENT_NOT_FOUND',
        404,
        { task_id: taskId },
      );
    }
    return task;
  }

  private resolveTaskReference(reference: string): AgentTask {
    const resolution = this.engine.resolveAgentTaskReference(reference);
    if (resolution.status === 'ambiguous_legacy_label') {
      throw new AgentLifecycleCommandError(
        `Agent label is ambiguous: ${reference}`,
        'AGENT_LABEL_AMBIGUOUS',
        409,
        {
          agent_label: reference,
          candidate_task_ids: resolution.candidate_task_ids,
        },
      );
    }
    if (resolution.status === 'missing') {
      throw new AgentLifecycleCommandError(
        `Agent task not found: ${reference}`,
        'AGENT_NOT_FOUND',
        404,
        { task_reference: reference },
      );
    }
    return resolution.task;
  }

  private hasSubmittedTranscript(task: AgentTask): boolean {
    const taskId = task.task_id ?? task.id;
    const agentLabel = task.agent_label ?? task.agent_id;
    const uniqueLabel = this.engine.getAgentTasks()
      .filter(candidate =>
        (candidate.agent_label ?? candidate.agent_id) === agentLabel)
      .length === 1;
    return this.engine.getFullHistory().some(entry =>
      entry.event_type === 'agent_transcript_submitted'
      && (
        entry.linked_agent_task_id === taskId
        || entry.agent_id === taskId
        || (uniqueLabel && entry.agent_id === agentLabel)
      ));
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
    throw new AgentLifecycleCommandError(
      execution.error?.message ?? 'Agent command failed.',
      execution.error?.code ?? 'AGENT_COMMAND_FAILED',
      typeof record.http_status === 'number' ? record.http_status : 409,
      record,
    );
  }
}
