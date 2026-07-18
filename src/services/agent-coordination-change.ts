import type { AgentTask } from '../types.js';
import type { FrontierLease } from './frontier-leases.js';
import { computeAgentWorkSignature } from './agent-work.js';

export const AGENT_COORDINATION_CHANGE_PAYLOAD_VERSION = 1 as const;
export const MAX_AGENT_COORDINATION_TASK_CHANGES = 64;
export const MAX_AGENT_COORDINATION_LEASE_CHANGES = 16;
export const MAX_AGENT_COORDINATION_CHANGE_BYTES = 512 * 1024;

export interface AgentCoordinationTaskChangeV1 {
  task_id: string;
  before: AgentTask | null;
  after: AgentTask | null;
}

export interface AgentCoordinationLeaseChangeV1 {
  frontier_item_id: string;
  before: FrontierLease | null;
  after: FrontierLease | null;
}

/**
 * A bounded compare-and-swap batch for durable agent work shaping. Historical
 * task rosters can be large, so handoff/split/merge journal only the touched
 * task and lease pre/post images instead of cloning the complete `agents` slice.
 */
export interface AgentCoordinationChangePayloadV1 {
  payload_version: typeof AGENT_COORDINATION_CHANGE_PAYLOAD_VERSION;
  operation_id: string;
  occurred_at: string;
  reason: string;
  task_changes: AgentCoordinationTaskChangeV1[];
  lease_changes: AgentCoordinationLeaseChangeV1[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function validateTaskImage(
  value: unknown,
  taskId: string,
  path: string,
): string | undefined {
  if (value === null) return undefined;
  if (!isRecord(value)) return `${path} must be an object or null`;
  if (value.id !== taskId || value.task_id !== taskId) {
    return `${path} identity must match task_id ${taskId}`;
  }
  if (!isNonEmptyString(value.agent_id)) return `${path}.agent_id must be non-empty`;
  if (value.agent_label !== value.agent_id) {
    return `${path}.agent_label must match agent_id`;
  }
  if (!isNonEmptyString(value.assigned_at) || !Number.isFinite(Date.parse(value.assigned_at))) {
    return `${path}.assigned_at must be an ISO timestamp`;
  }
  if (!['pending', 'running', 'completed', 'failed', 'interrupted'].includes(String(value.status))) {
    return `${path}.status is invalid`;
  }
  if (!Array.isArray(value.subgraph_node_ids)
    || value.subgraph_node_ids.some(nodeId => !isNonEmptyString(nodeId))) {
    return `${path}.subgraph_node_ids must contain non-empty strings`;
  }
  if (value.work !== undefined) {
    if (!isRecord(value.work)) return `${path}.work must be an object`;
    const work = value.work;
    if (work.version !== 1 || !isNonEmptyString(work.root_task_id)) {
      return `${path}.work must contain version 1 and root_task_id`;
    }
    if (!isNonEmptyString(work.signature) || !/^[a-f0-9]{64}$/.test(work.signature)) {
      return `${path}.work.signature must be a lowercase SHA-256 digest`;
    }
    if (work.origin_frontier_item_id !== undefined
      && !isNonEmptyString(work.origin_frontier_item_id)) {
      return `${path}.work.origin_frontier_item_id must be non-empty`;
    }
    if (work.relation !== undefined) {
      if (!isRecord(work.relation)) return `${path}.work.relation must be an object`;
      const relation = work.relation;
      if (relation.kind !== 'handoff' && relation.kind !== 'split') {
        return `${path}.work.relation.kind is invalid`;
      }
      if (!isNonEmptyString(relation.source_task_id) || relation.source_task_id === taskId) {
        return `${path}.work.relation.source_task_id is invalid`;
      }
      if (!isNonEmptyString(relation.created_at)
        || !Number.isFinite(Date.parse(relation.created_at))) {
        return `${path}.work.relation.created_at must be an ISO timestamp`;
      }
      if (!isNonEmptyString(relation.summary)) {
        return `${path}.work.relation.summary must be non-empty`;
      }
      for (const field of [
        'key_finding_ids',
        'key_evidence_ids',
        'key_event_ids',
      ] as const) {
        const references = relation[field];
        if (references === undefined) continue;
        if (!Array.isArray(references)
          || references.some(reference => !isNonEmptyString(reference))
          || new Set(references).size !== references.length) {
          return `${path}.work.relation.${field} must contain unique non-empty ids`;
        }
      }
    }
    if (work.merged_into_task_id !== undefined
      && (!isNonEmptyString(work.merged_into_task_id) || work.merged_into_task_id === taskId)) {
      return `${path}.work.merged_into_task_id is invalid`;
    }
    if (computeAgentWorkSignature(value as unknown as AgentTask) !== work.signature) {
      return `${path}.work.signature does not match the task's canonical work fields`;
    }
  }
  return undefined;
}

function validateLeaseImage(
  value: unknown,
  frontierItemId: string,
  path: string,
): string | undefined {
  if (value === null) return undefined;
  if (!isRecord(value)) return `${path} must be an object or null`;
  if (value.frontier_item_id !== frontierItemId) {
    return `${path}.frontier_item_id must match ${frontierItemId}`;
  }
  if (!isNonEmptyString(value.task_id) || !isNonEmptyString(value.agent_id)) {
    return `${path} must contain task_id and agent_id`;
  }
  if (!isNonEmptyString(value.leased_at) || !Number.isFinite(Date.parse(value.leased_at))) {
    return `${path}.leased_at must be an ISO timestamp`;
  }
  if (!isNonEmptyString(value.expires_at) || !Number.isFinite(Date.parse(value.expires_at))) {
    return `${path}.expires_at must be an ISO timestamp`;
  }
  if (!Number.isSafeInteger(value.ttl_seconds) || (value.ttl_seconds as number) < 1) {
    return `${path}.ttl_seconds must be a positive safe integer`;
  }
  return undefined;
}

export function validateAgentCoordinationChangePayload(
  value: unknown,
): { ok: true; payload: AgentCoordinationChangePayloadV1 } | { ok: false; reason: string } {
  if (!isRecord(value)) return { ok: false, reason: 'agent_coordination_change payload must be an object' };
  if (value.payload_version !== AGENT_COORDINATION_CHANGE_PAYLOAD_VERSION) {
    return { ok: false, reason: 'agent_coordination_change payload_version must be 1' };
  }
  if (!isNonEmptyString(value.operation_id)
    || !isNonEmptyString(value.occurred_at)
    || !Number.isFinite(Date.parse(value.occurred_at))
    || !isNonEmptyString(value.reason)) {
    return {
      ok: false,
      reason: 'agent_coordination_change requires operation_id, occurred_at, and reason',
    };
  }
  if (!Array.isArray(value.task_changes)
    || value.task_changes.length < 1
    || value.task_changes.length > MAX_AGENT_COORDINATION_TASK_CHANGES) {
    return {
      ok: false,
      reason: `agent_coordination_change task_changes must contain 1 through ${MAX_AGENT_COORDINATION_TASK_CHANGES} entries`,
    };
  }
  if (!Array.isArray(value.lease_changes)
    || value.lease_changes.length > MAX_AGENT_COORDINATION_LEASE_CHANGES) {
    return {
      ok: false,
      reason: `agent_coordination_change lease_changes may contain at most ${MAX_AGENT_COORDINATION_LEASE_CHANGES} entries`,
    };
  }
  const taskIds = new Set<string>();
  for (const [index, candidate] of value.task_changes.entries()) {
    if (!isRecord(candidate) || !isNonEmptyString(candidate.task_id)) {
      return { ok: false, reason: `agent_coordination_change.task_changes[${index}] is malformed` };
    }
    if (taskIds.has(candidate.task_id)) {
      return { ok: false, reason: `agent_coordination_change contains duplicate task ${candidate.task_id}` };
    }
    taskIds.add(candidate.task_id);
    if (candidate.before === null && candidate.after === null) {
      return { ok: false, reason: `agent_coordination_change task ${candidate.task_id} has no before or after image` };
    }
    const beforeError = validateTaskImage(
      candidate.before,
      candidate.task_id,
      `agent_coordination_change.task_changes[${index}].before`,
    );
    if (beforeError) return { ok: false, reason: beforeError };
    const afterError = validateTaskImage(
      candidate.after,
      candidate.task_id,
      `agent_coordination_change.task_changes[${index}].after`,
    );
    if (afterError) return { ok: false, reason: afterError };
  }
  const frontierIds = new Set<string>();
  for (const [index, candidate] of value.lease_changes.entries()) {
    if (!isRecord(candidate) || !isNonEmptyString(candidate.frontier_item_id)) {
      return { ok: false, reason: `agent_coordination_change.lease_changes[${index}] is malformed` };
    }
    if (frontierIds.has(candidate.frontier_item_id)) {
      return {
        ok: false,
        reason: `agent_coordination_change contains duplicate frontier lease ${candidate.frontier_item_id}`,
      };
    }
    frontierIds.add(candidate.frontier_item_id);
    if (candidate.before === null && candidate.after === null) {
      return {
        ok: false,
        reason: `agent_coordination_change lease ${candidate.frontier_item_id} has no before or after image`,
      };
    }
    const beforeError = validateLeaseImage(
      candidate.before,
      candidate.frontier_item_id,
      `agent_coordination_change.lease_changes[${index}].before`,
    );
    if (beforeError) return { ok: false, reason: beforeError };
    const afterError = validateLeaseImage(
      candidate.after,
      candidate.frontier_item_id,
      `agent_coordination_change.lease_changes[${index}].after`,
    );
    if (afterError) return { ok: false, reason: afterError };
  }
  const taskChangeById = new Map(
    (value.task_changes as AgentCoordinationTaskChangeV1[])
      .map(change => [change.task_id, change] as const),
  );
  const leaseChangeByFrontier = new Map(
    (value.lease_changes as AgentCoordinationLeaseChangeV1[])
      .map(change => [change.frontier_item_id, change] as const),
  );
  for (const change of taskChangeById.values()) {
    const after = change.after;
    if (!after || (after.status !== 'running' && after.status !== 'pending')
      || !after.frontier_item_id) continue;
    const before = change.before;
    const requiresLeaseChange = before === null
      || (before.status !== 'running' && before.status !== 'pending')
      || before.frontier_item_id !== after.frontier_item_id;
    if (!requiresLeaseChange) continue;
    const leaseAfter = leaseChangeByFrontier.get(after.frontier_item_id)?.after;
    if (!leaseAfter
      || leaseAfter.task_id !== change.task_id
      || leaseAfter.agent_id !== after.agent_id) {
      return {
        ok: false,
        reason: `live frontier task ${change.task_id} requires a matching lease postimage`,
      };
    }
  }
  for (const leaseChange of leaseChangeByFrontier.values()) {
    if (!leaseChange.after) continue;
    const taskChange = taskChangeById.get(leaseChange.after.task_id);
    const taskAfter = taskChange?.after;
    if (!taskAfter
      || taskAfter.frontier_item_id !== leaseChange.frontier_item_id
      || taskAfter.agent_id !== leaseChange.after.agent_id
      || (taskAfter.status !== 'running' && taskAfter.status !== 'pending')) {
      return {
        ok: false,
        reason: `frontier lease ${leaseChange.frontier_item_id} must match a live task postimage`,
      };
    }
  }
  if (Buffer.byteLength(JSON.stringify(value)) > MAX_AGENT_COORDINATION_CHANGE_BYTES) {
    return {
      ok: false,
      reason: `agent_coordination_change exceeds ${MAX_AGENT_COORDINATION_CHANGE_BYTES} bytes`,
    };
  }
  return {
    ok: true,
    payload: value as unknown as AgentCoordinationChangePayloadV1,
  };
}
