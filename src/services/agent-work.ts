import { createHash } from 'node:crypto';
import type {
  AgentTask,
  AgentWorkMetadataV1,
  AgentWorkRelationV1,
} from '../types.js';
import { canonicalJson } from './engagement-config-service.js';
import { taskIdOf } from './agent-identity.js';

export interface CanonicalAgentWorkSpecV1 {
  version: 1;
  frontier_item_id: string | null;
  campaign_id: string | null;
  subgraph_node_ids: string[];
  archetype: string | null;
  role: string | null;
  skill: string | null;
  objective: string | null;
}

export type AgentWorkRelationDetails = Omit<
  AgentWorkRelationV1,
  'kind' | 'source_task_id'
>;

export interface ExactAgentWorkDuplicateGroup {
  signature: string;
  task_ids: string[];
}

/** Locale-independent UTF-16 code-unit ordering for durable/canonical output. */
export function compareAgentWorkStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function optionalString(value: string | undefined): string | null {
  return value === undefined ? null : value;
}

function normalizeObjective(value: string | undefined): string | null {
  if (value === undefined) return null;
  const normalized = value.trim().replace(/\s+/g, ' ');
  return normalized.length > 0 ? normalized : null;
}

function sortedUnique(values: readonly string[] | undefined): string[] {
  // Default UTF-16 ordering is locale-independent. These arrays feed a durable
  // cross-machine hash, so ICU collation must never influence their bytes.
  return [...new Set(values ?? [])].sort();
}

/**
 * The semantic task fields used for exact duplicate detection. Presentation,
 * scheduling, lifecycle, backend, and model fields are intentionally excluded.
 */
export function canonicalAgentWorkSpec(task: AgentTask): CanonicalAgentWorkSpecV1 {
  return {
    version: 1,
    frontier_item_id: optionalString(task.frontier_item_id),
    campaign_id: optionalString(task.campaign_id),
    subgraph_node_ids: sortedUnique(task.subgraph_node_ids),
    archetype: optionalString(task.archetype),
    role: optionalString(task.role),
    skill: optionalString(task.skill),
    objective: normalizeObjective(task.objective),
  };
}

/** Stable SHA-256 identity for exact semantic work, independent of task order. */
export function computeAgentWorkSignature(task: AgentTask): string {
  return createHash('sha256')
    .update(canonicalJson(canonicalAgentWorkSpec(task)))
    .digest('hex');
}

/**
 * Derive the metadata absent on pre-PR9 tasks. The task is never modified; the
 * returned object can be used as a read model or attached by a later command.
 */
export function deriveLegacyAgentWorkMetadata(task: AgentTask): AgentWorkMetadataV1 {
  return {
    version: 1,
    root_task_id: taskIdOf(task),
    signature: computeAgentWorkSignature(task),
    ...(task.frontier_item_id
      ? { origin_frontier_item_id: task.frontier_item_id }
      : {}),
  };
}

/** Return a detached explicit work record, or a derived legacy record. */
export function readAgentWorkMetadata(task: AgentTask): AgentWorkMetadataV1 {
  return task.work
    ? structuredClone(task.work)
    : deriveLegacyAgentWorkMetadata(task);
}

function relationMetadata(
  kind: AgentWorkRelationV1['kind'],
  source: AgentTask,
  target: AgentTask,
  details: AgentWorkRelationDetails,
): AgentWorkMetadataV1 {
  const sourceTaskId = taskIdOf(source);
  if (sourceTaskId === taskIdOf(target)) {
    throw new Error(`Agent work ${kind} source and target must be different tasks.`);
  }
  const sourceWork = readAgentWorkMetadata(source);
  const summary = details.summary.trim();
  if (!summary) {
    throw new Error(`Agent work ${kind} summary must be non-empty.`);
  }
  const relation: AgentWorkRelationV1 = {
    kind,
    source_task_id: sourceTaskId,
    created_at: details.created_at,
    summary,
    ...(details.key_finding_ids?.length
      ? { key_finding_ids: sortedUnique(details.key_finding_ids) }
      : {}),
    ...(details.key_evidence_ids?.length
      ? { key_evidence_ids: sortedUnique(details.key_evidence_ids) }
      : {}),
    ...(details.key_event_ids?.length
      ? { key_event_ids: sortedUnique(details.key_event_ids) }
      : {}),
  };
  const originFrontierItemId = sourceWork.origin_frontier_item_id
    ?? source.frontier_item_id;
  return {
    version: 1,
    root_task_id: sourceWork.root_task_id,
    signature: computeAgentWorkSignature(target),
    ...(originFrontierItemId
      ? { origin_frontier_item_id: originFrontierItemId }
      : {}),
    relation,
  };
}

export function buildHandoffAgentWorkMetadata(
  source: AgentTask,
  successor: AgentTask,
  details: AgentWorkRelationDetails,
): AgentWorkMetadataV1 {
  return relationMetadata('handoff', source, successor, details);
}

export function buildSplitAgentWorkMetadata(
  parent: AgentTask,
  child: AgentTask,
  details: AgentWorkRelationDetails,
): AgentWorkMetadataV1 {
  return relationMetadata('split', parent, child, details);
}

/**
 * Mark an exact duplicate as merged into its canonical task. This only builds
 * detached metadata; callers remain responsible for committing it atomically.
 */
export function buildMergedAgentWorkMetadata(
  duplicate: AgentTask,
  canonical: AgentTask,
): AgentWorkMetadataV1 {
  const duplicateTaskId = taskIdOf(duplicate);
  const canonicalTaskId = taskIdOf(canonical);
  if (duplicateTaskId === canonicalTaskId) {
    throw new Error('Agent work cannot be merged into itself.');
  }
  const duplicateWork = readAgentWorkMetadata(duplicate);
  const canonicalWork = readAgentWorkMetadata(canonical);
  if (duplicateWork.signature !== canonicalWork.signature) {
    throw new Error(
      `Agent work signatures do not match: ${duplicateWork.signature} != ${canonicalWork.signature}.`,
    );
  }
  return {
    ...duplicateWork,
    root_task_id: canonicalWork.root_task_id,
    merged_into_task_id: canonicalTaskId,
  };
}

/**
 * Group only exact, unmerged duplicates. Both groups and ids are sorted so the
 * read model is stable across map iteration and recovery order.
 */
export function groupExactDuplicateAgentWork(
  tasks: Iterable<AgentTask>,
  options: { includeMerged?: boolean } = {},
): ExactAgentWorkDuplicateGroup[] {
  const bySignature = new Map<string, Set<string>>();
  for (const task of tasks) {
    const work = readAgentWorkMetadata(task);
    if (!options.includeMerged && work.merged_into_task_id) continue;
    const taskIds = bySignature.get(work.signature) ?? new Set<string>();
    taskIds.add(taskIdOf(task));
    bySignature.set(work.signature, taskIds);
  }
  return [...bySignature]
    .map(([signature, taskIds]) => ({
      signature,
      task_ids: [...taskIds].sort(compareAgentWorkStrings),
    }))
    .filter(group => group.task_ids.length > 1)
    .sort((left, right) => compareAgentWorkStrings(left.signature, right.signature));
}
