import { createHash } from 'crypto';
import type { AgentTask } from '../types.js';

export type AgentIdentityResolution =
  | { status: 'exact'; task: AgentTask }
  | { status: 'unique_legacy_label'; task: AgentTask }
  | { status: 'ambiguous_legacy_label'; candidate_task_ids: string[] }
  | { status: 'missing' };

export interface CoordinationRecoveryWarning {
  warning_id: string;
  relationship: string;
  reference: string;
  message: string;
  candidate_task_ids?: string[];
  payload?: unknown;
}

export type AgentTaskInput = Omit<AgentTask, 'task_id' | 'agent_label' | 'id' | 'agent_id'> & {
  task_id?: string;
  agent_label?: string;
  /** Legacy wire alias retained for one minor release. */
  id?: string;
  /** Legacy wire alias retained for one minor release. */
  agent_id?: string;
};

function nonEmpty(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

export function taskIdOf(task: AgentTask): string {
  return nonEmpty(task.task_id) ?? task.id;
}

export function agentLabelOf(task: AgentTask): string {
  return nonEmpty(task.agent_label) ?? task.agent_id;
}

/**
 * Convert legacy or additive task input into the canonical runtime/persisted
 * shape. The compatibility aliases are always regenerated from the canonical
 * fields so they cannot drift.
 */
export function normalizeAgentTask(input: AgentTaskInput | AgentTask, mapKey?: string): AgentTask {
  const taskId = nonEmpty(input.task_id) ?? nonEmpty(input.id) ?? nonEmpty(mapKey);
  const agentLabel = nonEmpty(input.agent_label) ?? nonEmpty(input.agent_id);
  if (!taskId) throw new Error('Agent task requires task_id (or legacy id).');
  if (!agentLabel) throw new Error('Agent task requires agent_label (or legacy agent_id).');
  if (mapKey && taskId !== mapKey) {
    throw new Error(`Agent task_id ${taskId} does not match persisted map key ${mapKey}.`);
  }
  if (nonEmpty(input.task_id) && nonEmpty(input.id) && input.task_id !== input.id) {
    throw new Error(`Agent task identity aliases disagree: task_id=${input.task_id}, id=${input.id}.`);
  }
  if (nonEmpty(input.agent_label) && nonEmpty(input.agent_id) && input.agent_label !== input.agent_id) {
    throw new Error(
      `Agent label aliases disagree: agent_label=${input.agent_label}, agent_id=${input.agent_id}.`,
    );
  }
  return {
    ...input,
    task_id: taskId,
    agent_label: agentLabel,
    id: taskId,
    agent_id: agentLabel,
  } as AgentTask;
}

export function resolveAgentIdentity(
  tasks: Iterable<AgentTask>,
  reference: string | undefined,
): AgentIdentityResolution {
  if (!reference) return { status: 'missing' };
  const all = [...tasks];
  const exact = all.find(task => taskIdOf(task) === reference || task.id === reference);
  if (exact) return { status: 'exact', task: exact };
  const labelMatches = all.filter(task =>
    agentLabelOf(task) === reference || task.agent_id === reference);
  if (labelMatches.length === 1) {
    return { status: 'unique_legacy_label', task: labelMatches[0] };
  }
  if (labelMatches.length > 1) {
    return {
      status: 'ambiguous_legacy_label',
      candidate_task_ids: labelMatches.map(taskIdOf).sort(),
    };
  }
  return { status: 'missing' };
}

export function coordinationRecoveryWarning(input: {
  relationship: string;
  reference: string;
  candidate_task_ids?: string[];
  payload?: unknown;
}): CoordinationRecoveryWarning {
  const candidates = input.candidate_task_ids?.slice().sort();
  const message = candidates?.length
    ? `Legacy agent label "${input.reference}" is ambiguous for ${input.relationship}; the relationship was left unlinked.`
    : `Agent reference "${input.reference}" could not be resolved for ${input.relationship}; the relationship was left unlinked.`;
  const identity = JSON.stringify({
    relationship: input.relationship,
    reference: input.reference,
    candidate_task_ids: candidates ?? [],
  });
  return {
    warning_id: `coord_${createHash('sha256').update(identity).digest('hex').slice(0, 20)}`,
    relationship: input.relationship,
    reference: input.reference,
    message,
    ...(candidates?.length ? { candidate_task_ids: candidates } : {}),
    ...(input.payload !== undefined ? { payload: structuredClone(input.payload) } : {}),
  };
}

export function mergeCoordinationRecoveryWarnings(
  ...groups: Array<Iterable<CoordinationRecoveryWarning> | undefined>
): CoordinationRecoveryWarning[] {
  const merged = new Map<string, CoordinationRecoveryWarning>();
  for (const group of groups) {
    if (!group) continue;
    for (const warning of group) merged.set(warning.warning_id, structuredClone(warning));
  }
  return [...merged.values()].sort((a, b) => a.warning_id.localeCompare(b.warning_id));
}
