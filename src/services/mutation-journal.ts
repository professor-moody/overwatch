// ============================================================
// Overwatch — Mutation Journal (P2.1)
//
// Write-ahead log for graph-affecting mutations. The canonical engagement
// state is `snapshot.json` + `journal.jsonl`: snapshot is a periodic full
// dump, journal is the append-only stream of mutations applied since.
//
// Crash safety contract:
//   1. Caller appends a MutationEntry to the journal (fsync).
//   2. Caller applies the mutation in memory.
//   3. Caller eventually triggers a snapshot, which truncates the journal.
//
// If the process dies between (1) and (2), startup replay reproduces (2).
// If it dies before (1), the in-memory state hasn't changed yet — nothing
// to recover.
//
// Managed active engagements enable the journal even when they pre-date
// `engagement_nonce`; deterministic-ID engagements also enable it directly.
// Existing journal bytes are always recovered, regardless of current config,
// so a legacy/no-nonce config can never make a WAL tail invisible.
//
// Design notes:
//   * Append mode: open-write-fsync-close per entry. Per-line cost ~1ms
//     locally; fine for offensive-engagement workloads where mutation
//     rate is bursty (parser ingest) not sustained.
//   * Sequence numbers: persisted in snapshot. Survive restart. Monotonic.
//   * Replay reads each line, applies to a `MutationApplier` adapter
//     supplied by the caller. The journal itself doesn't know about the
//     graph; it's a typed stream.
// ============================================================

import { existsSync, openSync, fsyncSync, closeSync, writeSync, readFileSync, renameSync, unlinkSync } from 'fs';
import { dirname, join, basename } from 'path';
import { createHash, randomUUID } from 'crypto';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';
import { decodeUtf8Fatal } from './durable-json.js';
import type {
  ConfigIntentConflict,
  EdgeProperties,
  EngagementConfig,
  GraphCorrectionOperation,
  NodeProperties,
} from '../types.js';
import type { ColdNodeRecord } from './cold-store.js';

type WriteSyncLike = (
  fd: number,
  buffer: Uint8Array,
  offset: number,
  length: number,
  position: number | null,
) => number;

const defaultWriteSync: WriteSyncLike = (fd, buffer, offset, length, position) =>
  writeSync(fd, buffer, offset, length, position);

/**
 * `fs.writeSync` is permitted to return a short byte count.  WAL writes are
 * framed and later published with rename/fsync, so treating a short write as
 * success can turn a partial frame or compacted tail into durable state.  Keep
 * writing until every byte has reached the descriptor, and fail closed if the
 * writer makes no progress or reports an impossible count.
 *
 * The writer argument is injectable only so the short-write behavior can be
 * exercised deterministically in unit tests; production callers use the Node
 * implementation above.
 */
export function writeAllSync(
  fd: number,
  data: string | Uint8Array,
  writer: WriteSyncLike = defaultWriteSync,
): void {
  const buffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);
  let offset = 0;
  while (offset < buffer.length) {
    const remaining = buffer.length - offset;
    const written = writer(fd, buffer, offset, remaining, null);
    if (!Number.isSafeInteger(written) || written <= 0 || written > remaining) {
      throw new Error(
        `WAL write made invalid progress: wrote ${String(written)} of ${remaining} remaining byte(s)`,
      );
    }
    offset += written;
  }
}

export type MutationType =
  | 'add_node'
  | 'merge_node_attrs'
  | 'replace_node_attrs'   // full-node replace (patch with unsets) — removes keys, unlike merge
  | 'drop_node'
  | 'add_edge'
  | 'merge_edge_attrs'
  | 'drop_edge'
  | 'cold_add'
  | 'cold_promote'
  | 'lease_acquire'
  | 'lease_release'
  | 'lease_renew'
  | 'log_event'
  | 'scope_updated'
  | 'identity_rewrite'
  | 'graph_corrected';

export interface ScopeUpdatedMutationPayloadV1 {
  payload_version: 1;
  operation_id: string;
  occurred_at: string;
  reason: string;
  source_config_hash: string;
  source_file_hash: string;
  target_config: EngagementConfig;
  before_scope: EngagementConfig['scope'];
  after_scope: EngagementConfig['scope'];
  promotions: Array<{
    cold_record: ColdNodeRecord;
    hot_node: NodeProperties;
  }>;
  inferred_edges: Array<{
    edge_id: string;
    before?: IdentityRewriteEdgeStateV1;
    after: IdentityRewriteEdgeStateV1;
  }>;
  inference_events: Array<{
    description: string;
    target_node_ids?: string[];
    details?: Record<string, unknown>;
  }>;
  config_resolution?: 'use_file';
  superseded_config_intent?: ConfigIntentConflict;
  affected_node_count: number;
}

export interface DropNodeMutationPayloadV1 {
  payload_version: 1;
  operation_id: string;
  occurred_at: string;
  reason: string;
  action_id?: string;
  node_id: string;
  expected_type: string;
  expected_node: {
    node_id: string;
    props: NodeProperties;
  };
  incident_edges: Array<{
    edge_id: string;
    source: string;
    target: string;
    edge_type: string;
    props: EdgeProperties;
  }>;
}

export interface IdentityRewriteNodeStateV1 {
  node_id: string;
  props: NodeProperties;
}

export interface IdentityRewriteEdgeStateV1 {
  edge_id: string;
  source: string;
  target: string;
  props: EdgeProperties;
}

export interface IdentityRewriteMutationPayloadV1 {
  payload_version: 1;
  operation_id: string;
  occurred_at: string;
  canonical_node_id: string;
  agent_id?: string;
  action_id?: string;
  node_changes: Array<{
    node_id: string;
    before?: IdentityRewriteNodeStateV1;
    after?: IdentityRewriteNodeStateV1;
  }>;
  edge_changes: Array<{
    edge_id: string;
    before?: IdentityRewriteEdgeStateV1;
    after?: IdentityRewriteEdgeStateV1;
  }>;
  audit_events: Array<{
    description: string;
    category?: 'system' | 'inference';
    event_type?: 'system' | 'inference_generated';
    result_classification?: 'success';
    target_node_ids?: string[];
    details: Record<string, unknown>;
  }>;
  result: {
    removed_nodes: string[];
    removed_edges: string[];
    new_edges: string[];
    updated_edges: string[];
    updated_canonical: boolean;
    survivor_id?: string;
    reverse_target?: string;
  };
}

export interface GraphCorrectedMutationPayloadV1 {
  payload_version: 1;
  operation_id: string;
  occurred_at: string;
  reason: string;
  action_id?: string;
  operations: GraphCorrectionOperation[];
  node_changes: IdentityRewriteMutationPayloadV1['node_changes'];
  edge_changes: IdentityRewriteMutationPayloadV1['edge_changes'];
  before_summary: { total_nodes: number; total_edges: number };
  after_summary: { total_nodes: number; total_edges: number };
  result: {
    dropped_nodes: string[];
    dropped_edges: string[];
    replaced_edges: Array<{ old_edge_id: string; new_edge_id: string }>;
    patched_nodes: string[];
  };
}

/** Records this binary can deterministically replay.  A string-shaped record
 *  from a newer writer is still unknown, even if its JSON envelope is valid;
 *  compaction must retain it rather than trusting an older snapshot checkpoint
 *  that may have advanced past an unapplied record. */
const REPLAYABLE_MUTATION_TYPES = new Set<string>([
  'add_node',
  'merge_node_attrs',
  'replace_node_attrs',
  'drop_node',
  'add_edge',
  'merge_edge_attrs',
  'drop_edge',
  'cold_add',
  'cold_promote',
  'scope_updated',
  'identity_rewrite',
  'graph_corrected',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

type MutationValidationResult =
  | { ok: true; entry: MutationEntry }
  | { ok: false; reason: string };

/** Validate the complete v1 envelope and every payload shape this binary can
 * replay. Unknown string-valued mutation types retain their envelope so replay
 * can stop with an explicit unsupported-type result; compaction rejects them. */
function validateMutationEntry(value: unknown): MutationValidationResult {
  if (!isRecord(value)) return { ok: false, reason: 'entry must be an object' };
  if (!Number.isSafeInteger(value.seq) || (value.seq as number) <= 0) {
    return { ok: false, reason: 'entry.seq must be a positive safe integer' };
  }
  if (!nonEmptyString(value.ts) || !Number.isFinite(Date.parse(value.ts))) {
    return { ok: false, reason: 'entry.ts must be a valid timestamp string' };
  }
  if (!nonEmptyString(value.type)) return { ok: false, reason: 'entry.type must be a non-empty string' };
  if (!isRecord(value.payload)) return { ok: false, reason: 'entry.payload must be an object' };
  if (value.source_action_id !== undefined && !nonEmptyString(value.source_action_id)) {
    return { ok: false, reason: 'entry.source_action_id must be a non-empty string when present' };
  }

  const payload = value.payload;
  switch (value.type) {
    case 'add_node':
    case 'merge_node_attrs':
    case 'replace_node_attrs': {
      if (!isRecord(payload.props) || !nonEmptyString(payload.props.id)) {
        return { ok: false, reason: `${value.type} payload.props.id must be a non-empty string` };
      }
      break;
    }
    case 'drop_node': {
      if (!Number.isSafeInteger(payload.payload_version) || (payload.payload_version as number) <= 0) {
        return { ok: false, reason: 'drop_node payload.payload_version must be a positive safe integer' };
      }
      if (payload.payload_version !== 1) break;
      if (
        !nonEmptyString(payload.operation_id)
        || !nonEmptyString(payload.reason)
        || !nonEmptyString(payload.node_id)
        || !nonEmptyString(payload.expected_type)
      ) {
        return { ok: false, reason: 'drop_node requires non-empty operation_id, reason, node_id, and expected_type strings' };
      }
      if (
        !isRecord(payload.expected_node)
        || payload.expected_node.node_id !== payload.node_id
        || !isRecord(payload.expected_node.props)
        || payload.expected_node.props.id !== payload.node_id
        || payload.expected_node.props.type !== payload.expected_type
      ) {
        return { ok: false, reason: 'drop_node payload.expected_node must exactly identify the expected typed node' };
      }
      if (!nonEmptyString(payload.occurred_at) || !Number.isFinite(Date.parse(payload.occurred_at))) {
        return { ok: false, reason: 'drop_node payload.occurred_at must be a valid timestamp string' };
      }
      if (payload.action_id !== undefined && !nonEmptyString(payload.action_id)) {
        return { ok: false, reason: 'drop_node payload.action_id must be a non-empty string when present' };
      }
      if (!Array.isArray(payload.incident_edges)) {
        return { ok: false, reason: 'drop_node payload.incident_edges must be an array' };
      }
      const edgeIds = new Set<string>();
      for (const edge of payload.incident_edges) {
        if (
          !isRecord(edge)
          || !nonEmptyString(edge.edge_id)
          || !nonEmptyString(edge.source)
          || !nonEmptyString(edge.target)
          || !nonEmptyString(edge.edge_type)
          || !isRecord(edge.props)
          || edge.props.type !== edge.edge_type
          || edgeIds.has(edge.edge_id)
        ) {
          return { ok: false, reason: 'drop_node incident edges require unique IDs, endpoints, and matching typed properties' };
        }
        if (edge.source !== payload.node_id && edge.target !== payload.node_id) {
          return { ok: false, reason: 'drop_node incident edge must reference payload.node_id' };
        }
        edgeIds.add(edge.edge_id);
      }
      break;
    }
    case 'identity_rewrite': {
      if (!Number.isSafeInteger(payload.payload_version) || (payload.payload_version as number) <= 0) {
        return { ok: false, reason: 'identity_rewrite payload.payload_version must be a positive safe integer' };
      }
      if (payload.payload_version !== 1) break;
      if (!nonEmptyString(payload.operation_id) || !nonEmptyString(payload.canonical_node_id)) {
        return { ok: false, reason: 'identity_rewrite requires non-empty operation_id and canonical_node_id strings' };
      }
      if (!nonEmptyString(payload.occurred_at) || !Number.isFinite(Date.parse(payload.occurred_at))) {
        return { ok: false, reason: 'identity_rewrite payload.occurred_at must be a valid timestamp string' };
      }
      for (const key of ['agent_id', 'action_id'] as const) {
        if (payload[key] !== undefined && !nonEmptyString(payload[key])) {
          return { ok: false, reason: `identity_rewrite payload.${key} must be a non-empty string when present` };
        }
      }
      if (!Array.isArray(payload.node_changes) || payload.node_changes.length === 0) {
        return { ok: false, reason: 'identity_rewrite payload.node_changes must be a non-empty array' };
      }
      const nodeIds = new Set<string>();
      for (const change of payload.node_changes) {
        if (!isRecord(change) || !nonEmptyString(change.node_id) || nodeIds.has(change.node_id)) {
          return { ok: false, reason: 'identity_rewrite node changes require unique non-empty node IDs' };
        }
        if (change.before === undefined && change.after === undefined) {
          return { ok: false, reason: 'identity_rewrite node change requires a before or after state' };
        }
        for (const phase of ['before', 'after'] as const) {
          const state = change[phase];
          if (state === undefined) continue;
          if (
            !isRecord(state)
            || state.node_id !== change.node_id
            || !isRecord(state.props)
            || state.props.id !== change.node_id
            || !nonEmptyString(state.props.type)
          ) {
            return { ok: false, reason: `identity_rewrite node change has an invalid ${phase} state` };
          }
        }
        nodeIds.add(change.node_id);
      }
      if (!Array.isArray(payload.edge_changes)) {
        return { ok: false, reason: 'identity_rewrite payload.edge_changes must be an array' };
      }
      const edgeIds = new Set<string>();
      for (const change of payload.edge_changes) {
        if (!isRecord(change) || !nonEmptyString(change.edge_id) || edgeIds.has(change.edge_id)) {
          return { ok: false, reason: 'identity_rewrite edge changes require unique non-empty edge IDs' };
        }
        if (change.before === undefined && change.after === undefined) {
          return { ok: false, reason: 'identity_rewrite edge change requires a before or after state' };
        }
        for (const phase of ['before', 'after'] as const) {
          const state = change[phase];
          if (state === undefined) continue;
          if (
            !isRecord(state)
            || state.edge_id !== change.edge_id
            || !nonEmptyString(state.source)
            || !nonEmptyString(state.target)
            || !isRecord(state.props)
            || !nonEmptyString(state.props.type)
          ) {
            return { ok: false, reason: `identity_rewrite edge change has an invalid ${phase} state` };
          }
        }
        edgeIds.add(change.edge_id);
      }
      if (!Array.isArray(payload.audit_events)) {
        return { ok: false, reason: 'identity_rewrite payload.audit_events must be an array' };
      }
      for (const event of payload.audit_events) {
        if (
          !isRecord(event)
          || !nonEmptyString(event.description)
          || !isRecord(event.details)
          || (event.category !== undefined && event.category !== 'system' && event.category !== 'inference')
          || (event.event_type !== undefined && event.event_type !== 'system' && event.event_type !== 'inference_generated')
          || (event.result_classification !== undefined && event.result_classification !== 'success')
          || (event.target_node_ids !== undefined
            && (!Array.isArray(event.target_node_ids) || event.target_node_ids.some(id => !nonEmptyString(id))))
        ) {
          return { ok: false, reason: 'identity_rewrite audit_events contain an invalid event descriptor' };
        }
      }
      if (!isRecord(payload.result)) {
        return { ok: false, reason: 'identity_rewrite payload.result must be an object' };
      }
      for (const key of ['removed_nodes', 'removed_edges', 'new_edges', 'updated_edges'] as const) {
        if (!Array.isArray(payload.result[key]) || payload.result[key].some(id => !nonEmptyString(id))) {
          return { ok: false, reason: `identity_rewrite payload.result.${key} must be a string array` };
        }
      }
      if (typeof payload.result.updated_canonical !== 'boolean') {
        return { ok: false, reason: 'identity_rewrite payload.result.updated_canonical must be boolean' };
      }
      for (const key of ['survivor_id', 'reverse_target'] as const) {
        if (payload.result[key] !== undefined && !nonEmptyString(payload.result[key])) {
          return { ok: false, reason: `identity_rewrite payload.result.${key} must be a non-empty string when present` };
        }
      }
      break;
    }
    case 'graph_corrected': {
      if (!Number.isSafeInteger(payload.payload_version) || (payload.payload_version as number) <= 0) {
        return { ok: false, reason: 'graph_corrected payload.payload_version must be a positive safe integer' };
      }
      if (payload.payload_version !== 1) break;
      if (!nonEmptyString(payload.operation_id) || !nonEmptyString(payload.reason)) {
        return { ok: false, reason: 'graph_corrected requires non-empty operation_id and reason strings' };
      }
      if (!nonEmptyString(payload.occurred_at) || !Number.isFinite(Date.parse(payload.occurred_at))) {
        return { ok: false, reason: 'graph_corrected payload.occurred_at must be a valid timestamp string' };
      }
      if (payload.action_id !== undefined && !nonEmptyString(payload.action_id)) {
        return { ok: false, reason: 'graph_corrected payload.action_id must be a non-empty string when present' };
      }
      if (!Array.isArray(payload.operations) || payload.operations.length === 0) {
        return { ok: false, reason: 'graph_corrected payload.operations must be a non-empty array' };
      }
      for (const operation of payload.operations) {
        if (!isRecord(operation) || !nonEmptyString(operation.kind)) {
          return { ok: false, reason: 'graph_corrected operations must be typed objects' };
        }
        if (operation.kind === 'drop_node') {
          if (!nonEmptyString(operation.node_id)) {
            return { ok: false, reason: 'graph_corrected drop_node requires node_id' };
          }
        } else if (operation.kind === 'drop_edge' || operation.kind === 'replace_edge') {
          if (
            !nonEmptyString(operation.source_id)
            || !nonEmptyString(operation.target_id)
            || !nonEmptyString(operation.edge_type)
          ) {
            return { ok: false, reason: `graph_corrected ${operation.kind} requires source_id, target_id, and edge_type` };
          }
        } else if (operation.kind === 'patch_node') {
          if (
            !nonEmptyString(operation.node_id)
            || (operation.set_properties !== undefined && !isRecord(operation.set_properties))
            || (operation.unset_properties !== undefined
              && (!Array.isArray(operation.unset_properties)
                || operation.unset_properties.some(key => !nonEmptyString(key))))
          ) {
            return { ok: false, reason: 'graph_corrected patch_node descriptor is invalid' };
          }
        } else {
          return { ok: false, reason: `graph_corrected operation kind is unsupported: ${operation.kind}` };
        }
      }
      if (!Array.isArray(payload.node_changes)) {
        return { ok: false, reason: 'graph_corrected payload.node_changes must be an array' };
      }
      const nodeIds = new Set<string>();
      for (const change of payload.node_changes) {
        if (!isRecord(change) || !nonEmptyString(change.node_id) || nodeIds.has(change.node_id)) {
          return { ok: false, reason: 'graph_corrected node changes require unique non-empty node IDs' };
        }
        if (change.before === undefined && change.after === undefined) {
          return { ok: false, reason: 'graph_corrected node change requires a before or after state' };
        }
        for (const phase of ['before', 'after'] as const) {
          const state = change[phase];
          if (state === undefined) continue;
          if (
            !isRecord(state)
            || state.node_id !== change.node_id
            || !isRecord(state.props)
            || state.props.id !== change.node_id
            || !nonEmptyString(state.props.type)
          ) {
            return { ok: false, reason: `graph_corrected node change has an invalid ${phase} state` };
          }
        }
        nodeIds.add(change.node_id);
      }
      if (!Array.isArray(payload.edge_changes)) {
        return { ok: false, reason: 'graph_corrected payload.edge_changes must be an array' };
      }
      const edgeIds = new Set<string>();
      for (const change of payload.edge_changes) {
        if (!isRecord(change) || !nonEmptyString(change.edge_id) || edgeIds.has(change.edge_id)) {
          return { ok: false, reason: 'graph_corrected edge changes require unique non-empty edge IDs' };
        }
        if (change.before === undefined && change.after === undefined) {
          return { ok: false, reason: 'graph_corrected edge change requires a before or after state' };
        }
        for (const phase of ['before', 'after'] as const) {
          const state = change[phase];
          if (state === undefined) continue;
          if (
            !isRecord(state)
            || state.edge_id !== change.edge_id
            || !nonEmptyString(state.source)
            || !nonEmptyString(state.target)
            || !isRecord(state.props)
            || !nonEmptyString(state.props.type)
          ) {
            return { ok: false, reason: `graph_corrected edge change has an invalid ${phase} state` };
          }
        }
        edgeIds.add(change.edge_id);
      }
      for (const key of ['before_summary', 'after_summary'] as const) {
        const summary = payload[key];
        if (
          !isRecord(summary)
          || !Number.isSafeInteger(summary.total_nodes)
          || (summary.total_nodes as number) < 0
          || !Number.isSafeInteger(summary.total_edges)
          || (summary.total_edges as number) < 0
        ) {
          return { ok: false, reason: `graph_corrected payload.${key} is invalid` };
        }
      }
      if (!isRecord(payload.result)) {
        return { ok: false, reason: 'graph_corrected payload.result must be an object' };
      }
      for (const key of ['dropped_nodes', 'dropped_edges', 'patched_nodes'] as const) {
        if (!Array.isArray(payload.result[key]) || payload.result[key].some(id => !nonEmptyString(id))) {
          return { ok: false, reason: `graph_corrected payload.result.${key} must be a string array` };
        }
      }
      if (!Array.isArray(payload.result.replaced_edges) || payload.result.replaced_edges.some(replacement =>
        !isRecord(replacement)
        || !nonEmptyString(replacement.old_edge_id)
        || !nonEmptyString(replacement.new_edge_id)
      )) {
        return { ok: false, reason: 'graph_corrected payload.result.replaced_edges is invalid' };
      }
      break;
    }
    case 'add_edge': {
      if (!nonEmptyString(payload.source) || !nonEmptyString(payload.target)) {
        return { ok: false, reason: 'add_edge payload.source and payload.target must be non-empty strings' };
      }
      if (!isRecord(payload.props) || !nonEmptyString(payload.props.type)) {
        return { ok: false, reason: 'add_edge payload.props.type must be a non-empty string' };
      }
      if (payload.edge_id !== undefined && !nonEmptyString(payload.edge_id)) {
        return { ok: false, reason: 'add_edge payload.edge_id must be a non-empty string when present' };
      }
      break;
    }
    case 'merge_edge_attrs': {
      if (!nonEmptyString(payload.edge_id) || !isRecord(payload.props)) {
        return { ok: false, reason: 'merge_edge_attrs requires a non-empty payload.edge_id and object payload.props' };
      }
      break;
    }
    case 'drop_edge': {
      if (!nonEmptyString(payload.edge_id)) {
        return { ok: false, reason: 'drop_edge payload.edge_id must be a non-empty string' };
      }
      const hasIdentityRef = payload.source !== undefined
        || payload.target !== undefined
        || payload.edge_type !== undefined;
      if (
        hasIdentityRef
        && (
          !nonEmptyString(payload.source)
          || !nonEmptyString(payload.target)
          || !nonEmptyString(payload.edge_type)
        )
      ) {
        return { ok: false, reason: 'drop_edge identity fallback requires non-empty source, target, and edge_type strings' };
      }
      break;
    }
    case 'cold_add': {
      const record = payload.record;
      if (
        !isRecord(record)
        || !nonEmptyString(record.id)
        || !nonEmptyString(record.type)
        || !nonEmptyString(record.label)
        || !nonEmptyString(record.discovered_at)
        || !nonEmptyString(record.last_seen_at)
      ) {
        return {
          ok: false,
          reason: 'cold_add payload.record requires non-empty id, type, label, discovered_at, and last_seen_at strings',
        };
      }
      break;
    }
    case 'cold_promote': {
      if (!nonEmptyString(payload.id)) {
        return { ok: false, reason: 'cold_promote payload.id must be a non-empty string' };
      }
      break;
    }
    case 'scope_updated': {
      if (!Number.isSafeInteger(payload.payload_version) || (payload.payload_version as number) <= 0) {
        return { ok: false, reason: 'scope_updated payload.payload_version must be a positive safe integer' };
      }
      // Future payload versions remain readable but unsupported. The replay
      // applier will skip them and PR1 recovery will preserve the WAL.
      if (payload.payload_version !== 1) break;
      if (!nonEmptyString(payload.operation_id) || !nonEmptyString(payload.reason)) {
        return { ok: false, reason: 'scope_updated requires non-empty operation_id and reason strings' };
      }
      if (!nonEmptyString(payload.occurred_at) || !Number.isFinite(Date.parse(payload.occurred_at))) {
        return { ok: false, reason: 'scope_updated payload.occurred_at must be a valid timestamp string' };
      }
      if (typeof payload.source_config_hash !== 'string' || !/^[0-9a-f]{64}$/.test(payload.source_config_hash)) {
        return { ok: false, reason: 'scope_updated payload.source_config_hash must be a lowercase SHA-256 hash' };
      }
      if (typeof payload.source_file_hash !== 'string' || !/^[0-9a-f]{64}$/.test(payload.source_file_hash)) {
        return { ok: false, reason: 'scope_updated payload.source_file_hash must be a lowercase SHA-256 hash' };
      }
      if (!isRecord(payload.target_config) || !nonEmptyString(payload.target_config.id)) {
        return { ok: false, reason: 'scope_updated payload.target_config must be an engagement config object' };
      }
      if (
        !Number.isSafeInteger(payload.target_config.config_revision)
        || (payload.target_config.config_revision as number) <= 0
        || typeof payload.target_config.config_hash !== 'string'
        || !/^[0-9a-f]{64}$/.test(payload.target_config.config_hash)
      ) {
        return { ok: false, reason: 'scope_updated target_config requires a positive config_revision and lowercase SHA-256 config_hash' };
      }
      for (const key of ['before_scope', 'after_scope'] as const) {
        const scope = payload[key];
        if (
          !isRecord(scope)
          || !Array.isArray(scope.cidrs)
          || !Array.isArray(scope.domains)
          || !Array.isArray(scope.exclusions)
        ) {
          return { ok: false, reason: `scope_updated payload.${key} requires cidrs, domains, and exclusions arrays` };
        }
      }
      if (!Array.isArray(payload.promotions)) {
        return { ok: false, reason: 'scope_updated payload.promotions must be an array' };
      }
      const promotionIds = new Set<string>();
      for (const promotion of payload.promotions) {
        if (!isRecord(promotion) || !isRecord(promotion.cold_record) || !isRecord(promotion.hot_node)) {
          return { ok: false, reason: 'scope_updated promotions require cold_record and hot_node objects' };
        }
        if (
          !nonEmptyString(promotion.cold_record.id)
          || promotion.hot_node.id !== promotion.cold_record.id
          || promotionIds.has(promotion.cold_record.id)
        ) {
          return { ok: false, reason: 'scope_updated promotion IDs must be non-empty, unique, and match the hot node' };
        }
        promotionIds.add(promotion.cold_record.id);
      }
      if (!Array.isArray(payload.inferred_edges)) {
        return { ok: false, reason: 'scope_updated payload.inferred_edges must be an array' };
      }
      const inferredEdgeIds = new Set<string>();
      for (const edge of payload.inferred_edges) {
        if (
          !isRecord(edge)
          || !nonEmptyString(edge.edge_id)
          || inferredEdgeIds.has(edge.edge_id)
          || !isRecord(edge.after)
          || edge.after.edge_id !== edge.edge_id
          || !nonEmptyString(edge.after.source)
          || !nonEmptyString(edge.after.target)
          || !isRecord(edge.after.props)
          || !nonEmptyString(edge.after.props.type)
        ) {
          return { ok: false, reason: 'scope_updated inferred_edges require unique IDs and exact typed after states' };
        }
        if (
          edge.before !== undefined
          && (
            !isRecord(edge.before)
            || edge.before.edge_id !== edge.edge_id
            || !nonEmptyString(edge.before.source)
            || !nonEmptyString(edge.before.target)
            || !isRecord(edge.before.props)
            || !nonEmptyString(edge.before.props.type)
          )
        ) {
          return { ok: false, reason: 'scope_updated inferred edge has an invalid before state' };
        }
        inferredEdgeIds.add(edge.edge_id);
      }
      if (!Array.isArray(payload.inference_events)) {
        return { ok: false, reason: 'scope_updated payload.inference_events must be an array' };
      }
      for (const event of payload.inference_events) {
        if (
          !isRecord(event)
          || !nonEmptyString(event.description)
          || (event.target_node_ids !== undefined && !Array.isArray(event.target_node_ids))
          || (event.details !== undefined && !isRecord(event.details))
        ) {
          return { ok: false, reason: 'scope_updated inference_events contain an invalid event descriptor' };
        }
      }
      if (payload.config_resolution !== undefined && payload.config_resolution !== 'use_file') {
        return { ok: false, reason: 'scope_updated payload.config_resolution must be use_file when present' };
      }
      if (payload.superseded_config_intent !== undefined) {
        const conflict = payload.superseded_config_intent;
        if (
          !isRecord(conflict)
          || !nonEmptyString(conflict.archive_path)
          || !nonEmptyString(conflict.reason)
          || typeof conflict.intent_sha256 !== 'string'
          || !/^[0-9a-f]{64}$/.test(conflict.intent_sha256)
          || (conflict.intent_checksum !== undefined
            && (typeof conflict.intent_checksum !== 'string' || !/^[0-9a-f]{64}$/.test(conflict.intent_checksum)))
          || typeof conflict.observed_file_hash !== 'string'
          || !/^[0-9a-f]{64}$/.test(conflict.observed_file_hash)
          || typeof conflict.observed_state_hash !== 'string'
          || !/^[0-9a-f]{64}$/.test(conflict.observed_state_hash)
        ) {
          return { ok: false, reason: 'scope_updated payload.superseded_config_intent is invalid' };
        }
      }
      if (!Number.isSafeInteger(payload.affected_node_count) || (payload.affected_node_count as number) < 0) {
        return { ok: false, reason: 'scope_updated payload.affected_node_count must be a non-negative safe integer' };
      }
      break;
    }
    default:
      // A future/unsupported mutation remains structurally readable. Replay
      // reports it as skipped and compaction preserves it byte-for-byte.
      break;
  }

  return { ok: true, entry: value as unknown as MutationEntry };
}

interface ScannedMutationRecord {
  entry: MutationEntry;
  line: number;
  byte_offset: number;
  byte_end: number;
}

interface MutationScanResult {
  raw: Buffer;
  records: ScannedMutationRecord[];
  issue?: MutationReadIssue;
}

export interface MutationEntry {
  seq: number;
  ts: string;                  // ISO timestamp the entry was journaled
  type: MutationType;
  payload: Record<string, unknown>;
  source_action_id?: string;   // optional cross-reference to the originating action
}

export type MutationApplyResult =
  | { status: 'applied' }
  | { status: 'skipped'; reason: string };

export interface MutationReplayResult {
  read: number;
  attempted: number;
  applied: number;
  skipped: number;
  failed: number;
  /** True when readSince stopped on a malformed record or sequence gap. The
   *  caller must preserve the active WAL and remain degraded; even a physical
   *  EOF fragment is not permission to checkpoint a partial replay. */
  truncated: boolean;
  complete: boolean;
  highest_on_disk_seq: number;
  highest_contiguous_applied_seq: number;
  stopped_at_seq?: number;
  read_issue?: MutationReadIssue;
  skipped_reasons: Array<{ seq: number; type: string; reason: string }>;
  failed_reasons: Array<{ seq: number; type: string; reason: string }>;
}

export interface MutationReadIssue {
  kind: 'malformed_entry' | 'sequence_gap' | 'unknown_type' | 'ambiguous_checkpoint';
  line: number;
  byte_offset: number;
  reason: string;
  expected_seq?: number;
  actual_seq?: number;
  /** True when the offending record is present in the entries returned for
   * replay. Physical scan gaps stop before the offending frame, while an
   * unknown type and a candidate-specific first-newer gap include it. */
  offending_record_included?: boolean;
  unterminated_eof_fragment?: boolean;
}

export type MutationCompactionResult =
  | { kept: number; dropped: number }
  | { kept: 0; dropped: 0; preserved: true; reason: string };

export interface MutationApplier {
  apply(entry: MutationEntry): MutationApplyResult;
}

export interface MutationReplayOptions {
  /**
   * New snapshots explicitly attest that their checkpoint is the highest
   * contiguously-applied record. Legacy snapshots have no such attestation; if
   * their WAL still contains a record at/below the claimed checkpoint, replay
   * cannot safely decide whether to re-apply or skip it and must degrade.
   */
  trustedContiguousCheckpoint?: boolean;
}

export class MutationJournal {
  private journalPath: string;
  private nextSeq: number = 0;
  private appliedThroughSeq: number = 0;
  private lastReadIssue: MutationReadIssue | undefined;
  private appendBlockedReason: string | undefined;

  constructor(stateFilePath: string) {
    const stateDir = dirname(stateFilePath);
    if (!existsSync(stateDir)) {
      mkdirDurable(stateDir);
    }
    this.journalPath = join(stateDir, basename(stateFilePath, '.json') + '.journal.jsonl');
  }

  /** Resolve the WAL path without creating directories or opening the file. */
  static pathForState(stateFilePath: string): string {
    return join(dirname(stateFilePath), basename(stateFilePath, '.json') + '.journal.jsonl');
  }

  /** Detect a physical WAL independently of engagement feature flags. Recovery
   *  must never ignore durable bytes merely because the incoming config is a
   *  legacy/no-nonce shape. */
  static hasDataForState(stateFilePath: string): boolean {
    const path = MutationJournal.pathForState(stateFilePath);
    if (!existsSync(path)) return false;
    try {
      return readFileSync(path).length > 0;
    } catch {
      // Presence plus unreadability must construct the recovery machinery so
      // startup can expose a degraded status instead of ignoring or appending
      // to an inaccessible WAL.
      return true;
    }
  }

  /**
   * Set the starting sequence number — typically restored from snapshot
   * metadata so journal entries don't collide with pre-restart sequences.
   */
  setNextSeq(
    seq: number,
    options: { preserveAllocated?: boolean; appliedThroughSeq?: number } = {},
  ): void {
    this.nextSeq = options.preserveAllocated ? Math.max(this.nextSeq, seq) : seq;
    this.appliedThroughSeq = options.appliedThroughSeq ?? seq;
  }

  /**
   * Get the next sequence number that will be assigned (without consuming it).
   * Used by snapshot writers so the snapshot's `journal_seq` field aligns
   * with where the journal currently is.
   */
  peekSeq(): number {
    return this.nextSeq;
  }

  /** Highest sequence allocated by this process, whether or not the write
   *  subsequently reached stable storage. */
  getHighestAllocatedSeq(): number {
    return this.nextSeq;
  }

  /** Highest parseable sequence physically present in the WAL. */
  getHighestPhysicalSeq(): number {
    return this.highestSeqOnDisk();
  }

  /** Highest sequence known to have been applied contiguously in memory. */
  getAppliedThroughSeq(): number {
    return this.appliedThroughSeq;
  }

  /** Mark a just-appended live mutation (or replayed entry) as applied. */
  markApplied(seq: number): void {
    if (seq <= this.appliedThroughSeq) return;
    const expected = this.appliedThroughSeq + 1;
    if (seq !== expected) {
      throw new Error(`Cannot advance applied WAL checkpoint across a gap: expected seq ${expected}, got ${seq}`);
    }
    this.appliedThroughSeq = seq;
  }

  blockAppends(reason: string): void {
    this.appendBlockedReason = reason;
  }

  getAppendBlockedReason(): string | undefined {
    return this.appendBlockedReason;
  }

  unblockAppends(): void {
    this.appendBlockedReason = undefined;
  }

  /**
   * Append a mutation entry. Synchronously fsyncs the file before
   * returning. Throws on write failure — callers MUST treat that as
   * "the mutation is not durable, do not apply it in memory."
   */
  append(entry: Omit<MutationEntry, 'seq' | 'ts'> & { ts?: string }): MutationEntry {
    if (this.appendBlockedReason) {
      throw new Error(`Mutation journal is read-only: ${this.appendBlockedReason}`);
    }
    const seq = this.nextSeq + 1;
    const full: MutationEntry = {
      seq,
      ts: entry.ts ?? new Date().toISOString(),
      type: entry.type,
      payload: entry.payload,
      ...(entry.source_action_id ? { source_action_id: entry.source_action_id } : {}),
    };
    const validation = validateMutationEntry(full);
    if (!validation.ok) {
      throw new Error(`Refusing to append malformed WAL record: ${validation.reason}`);
    }
    const line = JSON.stringify(full) + '\n';
    // Serialization and schema validation happen before allocation. Once I/O
    // begins, retain the allocated sequence even on ambiguity and block later
    // appends until restart/recovery resolves the physical bytes.
    this.nextSeq = seq;

    // Open-append-fsync-close: simple and bulletproof; the bulkier
    // engagements that justify a long-lived stream can land later.
    const existed = existsSync(this.journalPath);
    let fd: number | undefined;
    try {
      fd = openSync(this.journalPath, 'a');
      writeAllSync(fd, line);
      fsyncSync(fd);
    } catch (error) {
      // The caller cannot know whether an interrupted append left no bytes, a
      // full record, or a partial record.  Refuse later appends so we never
      // write beyond that ambiguity in the same process.
      this.blockAppends(`append of allocated seq ${seq} failed`);
      throw error;
    } finally {
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch (error) {
          this.blockAppends(`close after append of allocated seq ${seq} failed`);
          throw error;
        }
      }
    }
    if (!existed) {
      try {
        fsyncDirectory(dirname(this.journalPath));
      } catch (error) {
        this.blockAppends(`directory fsync for allocated seq ${seq} failed`);
        throw error;
      }
    }
    return full;
  }

  /**
   * Read all journal entries with `seq > fromSeq`. Used on startup to
   * replay entries the snapshot doesn't yet contain.
   *
   * Stops at the first malformed record and returns only the complete prefix
   * while recording a fatal read issue. Callers may inspect that prefix, but
   * must not checkpoint or compact it: strict recovery preserves the active
   * WAL byte-for-byte and remains degraded.
   */
  /** Set by the most recent readSince() when replay cannot safely continue. */
  wasLastReadTruncated(): boolean { return this.lastReadIssue !== undefined; }

  getLastReadIssue(): MutationReadIssue | undefined {
    return this.lastReadIssue ? { ...this.lastReadIssue } : undefined;
  }

  /** Read-only integrity preflight used before snapshot rotation. This catches
   * a malformed/unknown/gapped WAL before any recovery anchor is created,
   * pruned, or compacted. Filesystem errors intentionally propagate so the
   * persistence owner can enter inspectable degraded mode. */
  inspectIntegrity(afterCheckpoint?: number): MutationReadIssue | undefined {
    const scan = this.scanJournal();
    const issue = afterCheckpoint === undefined
      ? scan.issue
      : this.resolveReplayIssue(scan, afterCheckpoint, { trustedContiguousCheckpoint: true });
    return issue ? { ...issue } : undefined;
  }

  /** Candidate-aware read-only replay preflight. Unlike inspectIntegrity(),
   * this can preserve the ambiguity semantics of a legacy checkpoint. */
  inspectReplayIntegrity(
    fromSeq: number,
    options: MutationReplayOptions = {},
  ): MutationReadIssue | undefined {
    const issue = this.resolveReplayIssue(this.scanJournal(), fromSeq, options);
    return issue ? { ...issue } : undefined;
  }

  hasData(): boolean {
    return existsSync(this.journalPath) && readFileSync(this.journalPath).length > 0;
  }

  /** Highest parseable seq PHYSICALLY present in the journal file, including
   *  entries stranded AFTER a malformed line. After a truncated read the corrupt
   *  journal is preserved (evidence), so a fresh append must start above this to
   *  avoid reusing a seq that still lives orphaned past the corruption barrier. */
  highestSeqOnDisk(): number {
    if (!existsSync(this.journalPath)) return 0;
    const raw = readFileSync(this.journalPath);
    let max = 0;
    let byteOffset = 0;
    while (byteOffset < raw.length) {
      const newlineOffset = raw.indexOf(0x0a, byteOffset);
      const byteEnd = newlineOffset < 0 ? raw.length : newlineOffset;
      const frame = raw.subarray(byteOffset, byteEnd);
      byteOffset = newlineOffset < 0 ? raw.length : newlineOffset + 1;
      if (frame.length === 0) continue;
      try {
        const e = JSON.parse(decodeUtf8Fatal(frame)) as MutationEntry;
        if (typeof e.seq === 'number' && e.seq > max) max = e.seq;
      } catch { /* skip malformed */ }
    }
    return max;
  }

  private scanJournal(): MutationScanResult {
    if (!existsSync(this.journalPath)) return { raw: Buffer.alloc(0), records: [] };
    const raw = readFileSync(this.journalPath);
    if (raw.length === 0) return { raw, records: [] };

    const records: ScannedMutationRecord[] = [];
    let byteOffset = 0;
    let line = 1;
    let previousSeq: number | undefined;
    while (byteOffset < raw.length) {
      const newlineOffset = raw.indexOf(0x0a, byteOffset);
      if (newlineOffset < 0) {
        return {
          raw,
          records,
          issue: {
            kind: 'malformed_entry',
            line,
            byte_offset: byteOffset,
            reason: 'unterminated journal frame at physical EOF (missing newline commit marker)',
            unterminated_eof_fragment: true,
          },
        };
      }

      const frame = raw.subarray(byteOffset, newlineOffset);
      const byteEnd = newlineOffset + 1;
      if (frame.length === 0) {
        return {
          raw,
          records,
          issue: {
            kind: 'malformed_entry',
            line,
            byte_offset: byteOffset,
            reason: 'empty journal frame',
          },
        };
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(decodeUtf8Fatal(frame));
      } catch (error) {
        return {
          raw,
          records,
          issue: {
            kind: 'malformed_entry',
            line,
            byte_offset: byteOffset,
            reason: error instanceof Error ? error.message : String(error),
          },
        };
      }

      const validation = validateMutationEntry(parsed);
      if (!validation.ok) {
        return {
          raw,
          records,
          issue: {
            kind: 'malformed_entry',
            line,
            byte_offset: byteOffset,
            reason: validation.reason,
          },
        };
      }

      const entry = validation.entry;
      if (previousSeq !== undefined && entry.seq !== previousSeq + 1) {
        return {
          raw,
          records,
          issue: {
            kind: 'sequence_gap',
            line,
            byte_offset: byteOffset,
            reason: `journal sequence discontinuity: expected ${previousSeq + 1}, found ${entry.seq}`,
            expected_seq: previousSeq + 1,
            actual_seq: entry.seq,
            offending_record_included: false,
          },
        };
      }

      records.push({ entry, line, byte_offset: byteOffset, byte_end: byteEnd });
      if (!REPLAYABLE_MUTATION_TYPES.has(entry.type)) {
        return {
          raw,
          records,
          issue: {
            kind: 'unknown_type',
            line,
            byte_offset: byteOffset,
            reason: `unsupported journal mutation type: ${entry.type}`,
            actual_seq: entry.seq,
            offending_record_included: true,
          },
        };
      }
      previousSeq = entry.seq;
      byteOffset = byteEnd;
      line++;
    }
    return { raw, records };
  }

  private readForReplay(
    fromSeq: number,
    options: MutationReplayOptions = {},
  ): MutationEntry[] {
    const scan = this.scanJournal();
    const replayRecords = scan.records.filter(record => record.entry.seq > fromSeq);
    const issue = this.resolveReplayIssue(scan, fromSeq, options);
    this.lastReadIssue = issue;
    return replayRecords.map(record => record.entry);
  }

  private resolveReplayIssue(
    scan: MutationScanResult,
    fromSeq: number,
    options: MutationReplayOptions,
  ): MutationReadIssue | undefined {
    // Candidate-specific legacy ambiguity takes precedence over any later
    // physical issue. Otherwise a valid retained record at/below an untrusted
    // checkpoint could be applied or skipped based on a claim we do not know is
    // contiguous merely because an unknown/malformed tail was also present.
    const ambiguous = options.trustedContiguousCheckpoint === false && fromSeq > 0
      ? scan.records.find(record => record.entry.seq <= fromSeq)
      : undefined;
    if (ambiguous) {
      return {
        kind: 'ambiguous_checkpoint',
        line: ambiguous.line,
        byte_offset: ambiguous.byte_offset,
        reason: `legacy base checkpoint ${fromSeq} may hide retained WAL seq ${ambiguous.entry.seq}`,
        expected_seq: fromSeq + 1,
        actual_seq: ambiguous.entry.seq,
      };
    }
    const firstNewer = scan.records.find(record => record.entry.seq > fromSeq);
    if (firstNewer && firstNewer.entry.seq !== fromSeq + 1) {
      const gap: MutationReadIssue = {
        kind: 'sequence_gap',
        line: firstNewer.line,
        byte_offset: firstNewer.byte_offset,
        reason: `expected seq ${fromSeq + 1}, found ${firstNewer.entry.seq}`,
        expected_seq: fromSeq + 1,
        actual_seq: firstNewer.entry.seq,
        offending_record_included: true,
      };
      // Recovery stops at the first physical boundary it cannot justify. A
      // later unknown/malformed frame must not hide an earlier base-to-WAL
      // sequence gap and allow the post-gap prefix to reach the applier.
      if (!scan.issue || gap.byte_offset <= scan.issue.byte_offset) return gap;
    }
    return scan.issue;
  }

  readSince(fromSeq: number): MutationEntry[] {
    return this.readForReplay(fromSeq, { trustedContiguousCheckpoint: true });
  }

  /**
   * Compact the journal: drop entries with `seq <= upTo`, keep newer ones.
   * Used after a snapshot rotation — entries that are now in the snapshot
   * are redundant and can be discarded.
   *
   * Atomic on POSIX via write-tmp-then-rename.
   */
  compactUpTo(upTo: number): MutationCompactionResult {
    const scan = this.scanJournal();
    if (scan.raw.length === 0) return { kept: 0, dropped: 0 };
    if (scan.issue) {
      return {
        kept: 0,
        dropped: 0,
        preserved: true,
        reason: `journal scan failed at line ${scan.issue.line}: ${scan.issue.reason}`,
      };
    }
    for (const { entry } of scan.records) {
      if (!REPLAYABLE_MUTATION_TYPES.has(entry.type)) {
        return {
          kept: 0,
          dropped: 0,
          preserved: true,
          reason: `unsupported journal mutation type: ${entry.type}`,
        };
      }
    }

    const keptRecords = scan.records.filter(record => record.entry.seq > upTo);
    const kept = keptRecords.length;
    const dropped = scan.records.length - kept;
    if (kept === 0) {
      this.truncate();
      return { kept, dropped };
    }
    // Copy exact physical frames rather than parsing/stringifying the tail.
    // This preserves whitespace/escaping and keeps compaction byte-stable.
    const keptBytes = Buffer.concat(
      keptRecords.map(record => scan.raw.subarray(record.byte_offset, record.byte_end)),
    );
    const tmp = this.journalPath + '.compact';
    const fd = openSync(tmp, 'w');
    try {
      writeAllSync(fd, keptBytes);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.journalPath);
    fsyncDirectory(dirname(this.journalPath));
    return { kept, dropped };
  }

  /**
   * Truncate the journal — called after a fresh snapshot is durable.
   * Atomic on POSIX via rename-to-tmp-then-unlink.
   */
  truncate(): void {
    if (!existsSync(this.journalPath)) return;
    // Rename first so the durable snapshot/checkpoint and the WAL removal have
    // an atomic directory-entry boundary.  Never swallow a failure here: the
    // caller must stay read-only rather than claim compaction succeeded while
    // the on-disk result is ambiguous. A unique suffix also avoids overwriting
    // a stale artifact retained from an earlier interrupted cleanup.
    const stale = `${this.journalPath}.stale-${process.pid}-${randomUUID()}`;
    renameSync(this.journalPath, stale);
    fsyncDirectory(dirname(this.journalPath));
    unlinkSync(stale);
    fsyncDirectory(dirname(this.journalPath));
  }

  /**
   * Copy the complete journal to a content-addressed quarantine artifact.
   * The active journal is intentionally left untouched for manual recovery.
   */
  quarantine(): string | undefined {
    if (!existsSync(this.journalPath)) return undefined;
    const raw = readFileSync(this.journalPath);
    if (raw.length === 0) return undefined;
    const digest = createHash('sha256').update(raw).digest('hex').slice(0, 16);
    const quarantinePath = `${this.journalPath}.quarantine-${digest}.jsonl`;
    if (existsSync(quarantinePath)) return quarantinePath;

    const tmpPath = `${quarantinePath}.tmp-${process.pid}`;
    const fd = openSync(tmpPath, 'w');
    try {
      writeAllSync(fd, raw);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmpPath, quarantinePath);
    fsyncDirectory(dirname(quarantinePath));
    return quarantinePath;
  }

  /**
   * Replay every entry in the journal through the supplied applier.
   * Returns detailed counts so callers can decide whether to truncate —
   * truncation should be skipped when entries failed or were skipped
   * unexpectedly, so the evidence is preserved for manual inspection (P2).
   */
  replay(
    applier: MutationApplier,
    fromSeq: number,
    options: MutationReplayOptions = {},
  ): MutationReplayResult {
    const entries = this.readForReplay(fromSeq, options);
    const readIssue = this.getLastReadIssue();
    if (options.trustedContiguousCheckpoint === false && readIssue === undefined) {
      // A complete physical scan found no retained record that contradicts the
      // legacy base claim, so it is a usable replay cursor. Ambiguous claims
      // intentionally retain the caller-provided known-applied floor instead.
      this.appliedThroughSeq = fromSeq;
    }
    let applied = 0;
    let skipped = 0;
    let failed = 0;
    let attempted = 0;
    let stoppedAtSeq: number | undefined;
    const skipped_reasons: MutationReplayResult['skipped_reasons'] = [];
    const failed_reasons: MutationReplayResult['failed_reasons'] = [];
    // Every fully framed, schema-valid record before the first physical issue
    // is still a committed mutation. Apply that prefix, then stop before the
    // malformed/unknown/gapped record and preserve the complete WAL. A legacy
    // checkpoint ambiguity is different: it is candidate-specific and gives us
    // no proof that *any* retained record after the claimed checkpoint is safe
    // to apply, so its replayable prefix is deliberately empty.
    const issueSeq = readIssue?.actual_seq;
    const excludeIncludedIssue = readIssue?.kind === 'unknown_type'
      || (
        readIssue?.kind === 'sequence_gap'
        && readIssue.offending_record_included === true
      );
    const replayableEntries = readIssue?.kind === 'ambiguous_checkpoint'
      ? []
      : excludeIncludedIssue && issueSeq !== undefined
        ? entries.filter(entry => entry.seq < issueSeq)
        : entries;
    const checkpointIsProven = fromSeq === 0
      || options.trustedContiguousCheckpoint !== false
      || readIssue === undefined;
    for (const entry of replayableEntries) {
      attempted++;
      try {
        const result = applier.apply(entry);
        if (result.status === 'skipped') {
          skipped++;
          skipped_reasons.push({ seq: entry.seq, type: entry.type, reason: result.reason });
          stoppedAtSeq = entry.seq;
          break;
        } else {
          applied++;
          // A legacy base without an explicit contiguous-checkpoint marker is
          // only promoted after a complete scan. During incomplete recovery we
          // still expose every committed, ordered prefix mutation, but do not
          // claim that it closes the unknown base-to-WAL interval.
          if (checkpointIsProven) this.markApplied(entry.seq);
        }
      } catch (err) {
        failed++;
        stoppedAtSeq = entry.seq;
        const reason = err instanceof Error ? err.message : String(err);
        failed_reasons.push({ seq: entry.seq, type: entry.type, reason });
        // eslint-disable-next-line no-console
        console.warn(`[mutation-journal] apply failed for seq=${entry.seq} type=${entry.type}: ${reason}`);
        break;
      }
    }
    const highestOnDisk = this.highestSeqOnDisk();
    this.nextSeq = Math.max(this.nextSeq, highestOnDisk, fromSeq);
    const truncated = readIssue !== undefined;
    if (readIssue) {
      // The orphaned tail past the malformed line stays in the (preserved)
      // journal, so advance nextSeq above the HIGHEST seq on disk — otherwise a
      // fresh append could reuse a seq that still lives orphaned in the file.
      // eslint-disable-next-line no-console
      console.warn(`[mutation-journal] replay stopped at journal line ${readIssue.line}: ${readIssue.reason}`);
    }
    if (readIssue?.kind === 'unknown_type' && skipped === 0 && failed === 0) {
      skipped = 1;
      stoppedAtSeq = readIssue.actual_seq;
      skipped_reasons.push({
        seq: readIssue.actual_seq ?? 0,
        type: 'unknown',
        reason: readIssue.reason,
      });
    }
    const complete = !readIssue
      && skipped === 0
      && failed === 0
      && attempted === entries.length;
    return {
      read: entries.length,
      attempted,
      applied,
      skipped,
      failed,
      truncated,
      complete,
      highest_on_disk_seq: highestOnDisk,
      highest_contiguous_applied_seq: this.appliedThroughSeq,
      ...(stoppedAtSeq !== undefined ? { stopped_at_seq: stoppedAtSeq } : {}),
      ...(readIssue ? { read_issue: readIssue } : {}),
      skipped_reasons,
      failed_reasons,
    };
  }

  /** Path to the journal file. Useful for tests + diagnostics. */
  getPath(): string {
    return this.journalPath;
  }
}
