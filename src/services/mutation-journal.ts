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

import { existsSync, openSync, fsyncSync, closeSync, writeSync, readFileSync, renameSync, statSync, unlinkSync } from 'fs';
import { dirname, join, basename, resolve } from 'path';
import { createHash, randomUUID } from 'crypto';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';
import { decodeUtf8Fatal } from './durable-json.js';
import {
  acquireStateMigrationWriteGuard,
  assertStateMigrationWriteAllowed,
  getStateWriterLockDepth,
  withStateMigrationWriteGuard,
} from './state-migration-lock.js';
import {
  CURRENT_JOURNAL_VERSION,
  LEGACY_JOURNAL_VERSION,
  validatePersistedApplicationCommandV1,
} from './persisted-state.js';
import type {
  EngineOperation,
  EngineTransaction,
  EngineTransactionApplier,
  EngineTransactionDraft,
} from './engine-transaction.js';
import type {
  ConfigIntentConflict,
  EdgeProperties,
  EngagementConfig,
  GraphCorrectionOperation,
  NodeProperties,
} from '../types.js';
import type { ColdNodeRecord } from './cold-store.js';
import {
  DURABLE_STATE_SLICE_KEYS,
  type DurableStatePatchV1,
} from './durable-state-patch.js';
import type { ActivityAppendPayloadV1 } from './activity-append.js';
import type { ApplicationCommandChangePayloadV1 } from './application-command-change.js';
import {
  MAX_COMMAND_COORDINATION_VALUE_BYTES,
  type CommandCoordinationChangePayloadV1,
} from './command-coordination-change.js';

type WriteSyncLike = (
  fd: number,
  buffer: Uint8Array,
  offset: number,
  length: number,
  position: number | null,
) => number;

const defaultWriteSync: WriteSyncLike = (fd, buffer, offset, length, position) =>
  writeSync(fd, buffer, offset, length, position);

interface RetainedWriterOwner {
  token: string;
  busy: number;
  release: () => void;
}

const retainedWriterOwners = new Map<string, RetainedWriterOwner>();

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
  | 'graph_corrected'
  | 'activity_append'
  | 'application_command_change'
  | 'command_coordination_change'
  | 'state_patch';

export const JOURNAL_V2_CHUNK_BYTES = 64 * 1024;
export const JOURNAL_V2_MAX_TRANSACTION_BYTES = 64 * 1024 * 1024;
export const JOURNAL_V2_MAX_OPERATIONS = 10_000;

interface JournalV2BeginRecord {
  journal_version: typeof CURRENT_JOURNAL_VERSION;
  record_type: 'tx_begin';
  tx_version: 2;
  frame_seq: number;
  tx_seq: number;
  tx_id: string;
  ts: string;
  operation_count: number;
  payload_bytes: number;
  chunk_count: number;
  payload_sha256: string;
  source_action_id?: string;
}

interface JournalV2ChunkRecord {
  journal_version: typeof CURRENT_JOURNAL_VERSION;
  record_type: 'tx_chunk';
  frame_seq: number;
  tx_seq: number;
  tx_id: string;
  chunk_index: number;
  chunk_sha256: string;
  data: string;
}

interface JournalV2CommitRecord {
  journal_version: typeof CURRENT_JOURNAL_VERSION;
  record_type: 'tx_commit';
  frame_seq: number;
  tx_seq: number;
  tx_id: string;
  operation_count: number;
  payload_bytes: number;
  chunk_count: number;
  payload_sha256: string;
  commit_checksum: string;
}

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
  /** Optional absolute after-state for a high-level command that must commit
   * with the scope/config change (for example quick-deploy's agent task and
   * idempotent response record). Hashes prevent replay from overwriting a
   * divergent later state while remaining idempotent after partial apply. */
  state_patch?: DurableStatePatchV1;
  state_patch_before_sha256?: string;
  state_patch_after_sha256?: string;
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
  /** The enclosing v2 transaction carries the finalized graph-correction audit. */
  audit_event_externalized?: boolean;
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
  /** The enclosing v2 transaction carries finalized activity_append records. */
  audit_events_externalized?: boolean;
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
  /** New writers externalize the audit entry as an immutable
   * `activity_append` operation in the same transaction. Older payloads omit
   * this flag and retain the legacy in-applier audit behavior. */
  audit_event_externalized?: boolean;
  /** Optional command-state envelope committed with the destructive graph
   * correction so retries cannot repeat it after a lost response. */
  state_patch?: DurableStatePatchV1;
  state_patch_before_sha256?: string;
  state_patch_after_sha256?: string;
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
  'activity_append',
  'application_command_change',
  'command_coordination_change',
  'state_patch',
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
      if (
        payload.audit_event_externalized !== undefined
        && typeof payload.audit_event_externalized !== 'boolean'
      ) {
        return { ok: false, reason: 'drop_node payload.audit_event_externalized must be boolean' };
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
      if (
        payload.audit_events_externalized !== undefined
        && typeof payload.audit_events_externalized !== 'boolean'
      ) {
        return { ok: false, reason: 'identity_rewrite payload.audit_events_externalized must be boolean' };
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
      if (
        payload.audit_event_externalized !== undefined
        && typeof payload.audit_event_externalized !== 'boolean'
      ) {
        return { ok: false, reason: 'graph_corrected payload.audit_event_externalized must be boolean' };
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
    case 'state_patch': {
      const patch = payload as unknown as DurableStatePatchV1;
      if (patch.payload_version !== 1) {
        return { ok: false, reason: 'state_patch payload.payload_version must be 1' };
      }
      if (
        !nonEmptyString(patch.operation_id)
        || !nonEmptyString(patch.reason)
        || !nonEmptyString(patch.occurred_at)
        || !Number.isFinite(Date.parse(patch.occurred_at))
        || !isRecord(patch.slices)
      ) {
        return {
          ok: false,
          reason: 'state_patch requires operation_id, reason, occurred_at, and object slices',
        };
      }
      const sliceKeys = Object.keys(patch.slices);
      if (sliceKeys.length === 0) {
        return { ok: false, reason: 'state_patch payload.slices must not be empty' };
      }
      const allowed = new Set<string>(DURABLE_STATE_SLICE_KEYS);
      const unsupported = sliceKeys.find(key => !allowed.has(key));
      if (unsupported) {
        return { ok: false, reason: `state_patch contains unsupported slice: ${unsupported}` };
      }
      break;
    }
    case 'application_command_change': {
      const change = payload as unknown as ApplicationCommandChangePayloadV1;
      if (change.payload_version !== 1) {
        return {
          ok: false,
          reason: 'application_command_change payload.payload_version must be 1',
        };
      }
      if (
        !nonEmptyString(change.operation_id)
        || !nonEmptyString(change.occurred_at)
        || !Number.isFinite(Date.parse(change.occurred_at))
        || !nonEmptyString(change.idempotency_key)
        || (change.before === null && change.after === null)
      ) {
        return {
          ok: false,
          reason: 'application_command_change requires operation_id, occurred_at, idempotency_key, and a before or after record',
        };
      }
      try {
        if (change.before !== null) {
          validatePersistedApplicationCommandV1(
            change.before,
            'application_command_change.before',
            {
              expected_idempotency_key: change.idempotency_key,
              enforce_limits: false,
              enforce_lifecycle: false,
            },
          );
        }
        if (change.after !== null) {
          validatePersistedApplicationCommandV1(
            change.after,
            'application_command_change.after',
            { expected_idempotency_key: change.idempotency_key },
          );
        }
      } catch (error) {
        return {
          ok: false,
          reason: error instanceof Error ? error.message : String(error),
        };
      }
      break;
    }
    case 'command_coordination_change': {
      const change = payload as unknown as CommandCoordinationChangePayloadV1;
      if (change.payload_version !== 1) {
        return {
          ok: false,
          reason: 'command_coordination_change payload.payload_version must be 1',
        };
      }
      if (
        !nonEmptyString(change.operation_id)
        || !nonEmptyString(change.occurred_at)
        || !Number.isFinite(Date.parse(change.occurred_at))
        || !nonEmptyString(change.key)
        || (change.record_kind !== 'plan' && change.record_kind !== 'outcome')
        || (change.before === null && change.after === null)
      ) {
        return {
          ok: false,
          reason: 'command_coordination_change requires operation_id, occurred_at, record_kind, key, and a before or after record',
        };
      }
      for (const [phase, value] of [
        ['before', change.before],
        ['after', change.after],
      ] as const) {
        if (value === null) continue;
        if (!isRecord(value)) {
          return { ok: false, reason: `command_coordination_change.${phase} must be an object or null` };
        }
        const record = value as Record<string, unknown>;
        if (
          phase === 'after'
          && Buffer.byteLength(JSON.stringify(value)) > MAX_COMMAND_COORDINATION_VALUE_BYTES
        ) {
          return { ok: false, reason: 'command_coordination_change.after exceeds its size limit' };
        }
        if (change.record_kind === 'plan') {
          if (
            typeof record.command !== 'string'
            || !Array.isArray(record.ops)
            || !Number.isFinite(record.created_at)
            || !Number.isFinite(record.expires_at)
            || (record.expires_at as number) <= (record.created_at as number)
          ) {
            return { ok: false, reason: `command_coordination_change.${phase} plan is malformed` };
          }
        } else if (
          !Array.isArray(record.results)
          || !Number.isFinite(record.at)
          || !Number.isFinite(record.expires_at)
          || (record.expires_at as number) <= (record.at as number)
        ) {
          return { ok: false, reason: `command_coordination_change.${phase} outcome is malformed` };
        }
      }
      break;
    }
    case 'activity_append': {
      const append = payload as unknown as ActivityAppendPayloadV1;
      if (append.payload_version !== 1) {
        return { ok: false, reason: 'activity_append payload.payload_version must be 1' };
      }
      if (
        !Array.isArray(append.items)
        || append.items.length === 0
        || append.items.length > 16
      ) {
        return { ok: false, reason: 'activity_append payload.items must contain 1 through 16 events' };
      }
      const eventIds = new Set<string>();
      for (const item of append.items) {
        if (
          !isRecord(item)
          || !isRecord(item.entry)
          || !nonEmptyString(item.entry.event_id)
          || eventIds.has(item.entry.event_id)
          || !nonEmptyString(item.entry.timestamp)
          || !Number.isFinite(Date.parse(item.entry.timestamp))
          || !nonEmptyString(item.entry.description)
        ) {
          return { ok: false, reason: 'activity_append contains an invalid or duplicate event entry' };
        }
        eventIds.add(item.entry.event_id);
        if (item.checkpoint !== undefined) {
          const checkpoint = item.checkpoint;
          if (
            !isRecord(checkpoint)
            || checkpoint.event_id !== item.entry.event_id
            || !Number.isSafeInteger(checkpoint.event_index)
            || (checkpoint.event_index as number) < 0
            || !nonEmptyString(checkpoint.event_hash)
            || checkpoint.event_hash !== item.entry.event_hash
            || !Number.isSafeInteger(checkpoint.events_since_previous)
            || (checkpoint.events_since_previous as number) <= 0
            || !nonEmptyString(checkpoint.emitted_at)
            || !Number.isFinite(Date.parse(checkpoint.emitted_at))
          ) {
            return { ok: false, reason: 'activity_append contains an invalid checkpoint' };
          }
        }
      }
      if (!nonEmptyString(append.result_event_id) || !eventIds.has(append.result_event_id)) {
        return { ok: false, reason: 'activity_append result_event_id must reference an appended event' };
      }
      const validContinuity = (
        value: unknown,
        includeWindow: boolean,
      ): value is Record<string, unknown> => {
        if (!isRecord(value)) return false;
        if (
          !/^[0-9a-f]{64}$/i.test(String(value.last_chain_hash ?? ''))
          || !Number.isSafeInteger(value.chain_events_since_checkpoint)
          || (value.chain_events_since_checkpoint as number) < 0
          || !Number.isSafeInteger(value.deterministic_seq)
          || (value.deterministic_seq as number) < 0
        ) {
          return false;
        }
        if (!includeWindow) return true;
        return Number.isSafeInteger(value.activity_length)
          && (value.activity_length as number) >= 0
          && (value.activity_tail_event_id === null || nonEmptyString(value.activity_tail_event_id))
          && Number.isSafeInteger(value.checkpoint_count)
          && (value.checkpoint_count as number) >= 0
          && (value.checkpoint_tail_event_id === null || nonEmptyString(value.checkpoint_tail_event_id));
      };
      if (!validContinuity(append.expected, true) || !validContinuity(append.final, false)) {
        return { ok: false, reason: 'activity_append continuity metadata is invalid' };
      }
      const update = append.action_frontier_update;
      if (update !== undefined) {
        const validMapping = (value: unknown): boolean => isRecord(value)
          && nonEmptyString(value.frontier_item_id)
          && (value.agent_id === undefined || nonEmptyString(value.agent_id))
          && (value.frontier_type === undefined || nonEmptyString(value.frontier_type));
        if (
          !isRecord(update)
          || !nonEmptyString(update.action_id)
          || (update.before !== null && !validMapping(update.before))
          || !validMapping(update.after)
        ) {
          return { ok: false, reason: 'activity_append action_frontier_update is invalid' };
        }
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

function validateEngineOperation(
  operation: unknown,
  seq: number,
  ts: string,
): { ok: true; operation: EngineOperation } | { ok: false; reason: string } {
  if (!isRecord(operation) || !nonEmptyString(operation.type) || !isRecord(operation.payload)) {
    return { ok: false, reason: 'transaction operations require a non-empty type and object payload' };
  }
  const validation = validateMutationEntry({
    seq,
    ts,
    type: operation.type,
    payload: operation.payload,
  });
  if (!validation.ok) return validation;
  return {
    ok: true,
    operation: {
      type: validation.entry.type,
      payload: validation.entry.payload,
    },
  };
}

export function validateTransactionOperationRelationships(
  operations: readonly EngineOperation[],
): { ok: true } | { ok: false; reason: string } {
  const externalizedAuditIds = new Set<string>();
  for (const operation of operations) {
    if (operation.type !== 'activity_append') continue;
    const append = operation.payload as unknown as ActivityAppendPayloadV1;
    for (const item of append.items ?? []) {
      const operationId = item.entry.details?.operation_id;
      if (
        item.entry.event_type === 'graph_corrected'
        && typeof operationId === 'string'
      ) {
        externalizedAuditIds.add(operationId);
      }
    }
  }
  for (const operation of operations) {
    if (operation.type !== 'drop_node' && operation.type !== 'graph_corrected') continue;
    const payload = operation.payload as Record<string, unknown>;
    if (payload.audit_event_externalized !== true) continue;
    if (
      typeof payload.operation_id !== 'string'
      || !externalizedAuditIds.has(payload.operation_id)
    ) {
      return {
        ok: false,
        reason: `${operation.type} externalized audit requires a matching activity_append in the same transaction`,
      };
    }
  }
  return { ok: true };
}

function transactionPayload(
  draft: EngineTransactionDraft,
): Buffer {
  const payload = {
    operations: draft.operations,
    ...(draft.update_detail === undefined ? {} : { update_detail: draft.update_detail }),
  };
  return Buffer.from(JSON.stringify(payload), 'utf-8');
}

function transactionCommitChecksum(
  begin: JournalV2BeginRecord,
  chunkHashes: string[],
): string {
  return createHash('sha256').update(JSON.stringify([
    begin.journal_version,
    begin.record_type,
    begin.tx_version,
    begin.frame_seq,
    begin.tx_seq,
    begin.tx_id,
    begin.ts,
    begin.operation_count,
    begin.payload_bytes,
    begin.chunk_count,
    begin.payload_sha256,
    begin.source_action_id ?? null,
    chunkHashes,
  ])).digest('hex');
}

function encodeTransactionFrames(transaction: EngineTransaction): Buffer {
  if (!Array.isArray(transaction.operations) || transaction.operations.length === 0) {
    throw new Error('Refusing to append an empty engine transaction');
  }
  if (transaction.operations.length > JOURNAL_V2_MAX_OPERATIONS) {
    throw new Error(
      `Refusing to append engine transaction with ${transaction.operations.length} operations; maximum is ${JOURNAL_V2_MAX_OPERATIONS}`,
    );
  }
  if (!nonEmptyString(transaction.tx_id)) {
    throw new Error('Refusing to append engine transaction without tx_id');
  }
  if (!Number.isSafeInteger(transaction.seq) || transaction.seq <= 0) {
    throw new Error('Refusing to append engine transaction with invalid seq');
  }
  if (
    !Number.isSafeInteger(transaction.begin_frame_seq)
    || transaction.begin_frame_seq <= 0
    || !Number.isSafeInteger(transaction.commit_frame_seq)
    || transaction.commit_frame_seq < transaction.begin_frame_seq + 2
  ) {
    throw new Error('Refusing to append engine transaction with invalid physical frame range');
  }
  if (!nonEmptyString(transaction.ts) || !Number.isFinite(Date.parse(transaction.ts))) {
    throw new Error('Refusing to append engine transaction with invalid timestamp');
  }
  if (transaction.source_action_id !== undefined && !nonEmptyString(transaction.source_action_id)) {
    throw new Error('Refusing to append engine transaction with invalid source_action_id');
  }
  for (const [index, operation] of transaction.operations.entries()) {
    const validation = validateEngineOperation(operation, transaction.seq, transaction.ts);
    if (!validation.ok) {
      throw new Error(
        `Refusing to append malformed engine transaction operation ${index}: ${validation.reason}`,
      );
    }
  }
  const relationshipValidation = validateTransactionOperationRelationships(
    transaction.operations,
  );
  if (!relationshipValidation.ok) {
    throw new Error(
      `Refusing to append malformed engine transaction: ${relationshipValidation.reason}`,
    );
  }

  const payload = transactionPayload(transaction);
  if (payload.length > JOURNAL_V2_MAX_TRANSACTION_BYTES) {
    throw new Error(
      `Refusing to append ${payload.length}-byte engine transaction; maximum is ${JOURNAL_V2_MAX_TRANSACTION_BYTES}`,
    );
  }
  const chunks: Buffer[] = [];
  for (let offset = 0; offset < payload.length; offset += JOURNAL_V2_CHUNK_BYTES) {
    chunks.push(payload.subarray(offset, Math.min(offset + JOURNAL_V2_CHUNK_BYTES, payload.length)));
  }
  if (chunks.length === 0) chunks.push(Buffer.alloc(0));
  if (transaction.commit_frame_seq !== transaction.begin_frame_seq + chunks.length + 1) {
    throw new Error('Refusing to append engine transaction whose frame range does not match its chunk count');
  }
  const payloadSha256 = createHash('sha256').update(payload).digest('hex');
  const begin: JournalV2BeginRecord = {
    journal_version: CURRENT_JOURNAL_VERSION,
    record_type: 'tx_begin',
    tx_version: 2,
    frame_seq: transaction.begin_frame_seq,
    tx_seq: transaction.seq,
    tx_id: transaction.tx_id,
    ts: transaction.ts,
    operation_count: transaction.operations.length,
    payload_bytes: payload.length,
    chunk_count: chunks.length,
    payload_sha256: payloadSha256,
    ...(transaction.source_action_id
      ? { source_action_id: transaction.source_action_id }
      : {}),
  };
  const chunkRecords: JournalV2ChunkRecord[] = chunks.map((chunk, chunkIndex) => ({
    journal_version: CURRENT_JOURNAL_VERSION,
    record_type: 'tx_chunk',
    frame_seq: transaction.begin_frame_seq + chunkIndex + 1,
    tx_seq: transaction.seq,
    tx_id: transaction.tx_id,
    chunk_index: chunkIndex,
    chunk_sha256: createHash('sha256').update(chunk).digest('hex'),
    data: chunk.toString('base64'),
  }));
  const commit: JournalV2CommitRecord = {
    journal_version: CURRENT_JOURNAL_VERSION,
    record_type: 'tx_commit',
    frame_seq: transaction.commit_frame_seq,
    tx_seq: transaction.seq,
    tx_id: transaction.tx_id,
    operation_count: transaction.operations.length,
    payload_bytes: payload.length,
    chunk_count: chunks.length,
    payload_sha256: payloadSha256,
    commit_checksum: transactionCommitChecksum(
      begin,
      chunkRecords.map(record => record.chunk_sha256),
    ),
  };
  return Buffer.from(
    [begin, ...chunkRecords, commit].map(record => JSON.stringify(record)).join('\n') + '\n',
    'utf-8',
  );
}

interface ScannedEngineTransaction {
  transaction: EngineTransaction;
  line: number;
  byte_offset: number;
  byte_end: number;
  format_version: typeof LEGACY_JOURNAL_VERSION | typeof CURRENT_JOURNAL_VERSION;
  frame_count: number;
}

interface EngineTransactionScanResult {
  raw: Buffer;
  transactions: ScannedEngineTransaction[];
  issue?: MutationReadIssue;
  format_version?: typeof LEGACY_JOURNAL_VERSION | typeof CURRENT_JOURNAL_VERSION;
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
  highest_physical_frame_seq?: number;
  frames_read?: number;
  committed_transactions?: number;
  incomplete_transactions?: number;
  stopped_at_seq?: number;
  read_issue?: MutationReadIssue;
  skipped_reasons: Array<{ seq: number; type: string; reason: string }>;
  failed_reasons: Array<{ seq: number; type: string; reason: string }>;
}

export interface MutationReadIssue {
  kind:
    | 'malformed_entry'
    | 'sequence_gap'
    | 'unknown_type'
    | 'ambiguous_checkpoint'
    | 'incomplete_transaction'
    | 'checksum_mismatch'
    | 'unsupported_journal_version'
    | 'interleaved_transaction';
  line: number;
  byte_offset: number;
  reason: string;
  expected_seq?: number;
  actual_seq?: number;
  frame_seq?: number;
  tx_id?: string;
  /** True when the offending record is present in the entries returned for
   * replay. Physical scan gaps stop before the offending frame, while an
   * unknown type and a candidate-specific first-newer gap include it. */
  offending_record_included?: boolean;
  unterminated_eof_fragment?: boolean;
}

export type MutationCompactionResult =
  | { kept: number; dropped: number }
  | { kept: 0; dropped: 0; preserved: true; reason: string };

export type IncompleteTransactionRepairResult =
  | { repaired: false }
  | {
      repaired: true;
      quarantine_path: string;
      dropped_bytes: number;
      committed_transactions: number;
    };

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
  private stateFilePath: string;
  private journalPath: string;
  private nextSeq: number = 0;
  private nextFrameSeq: number = 0;
  private appliedThroughSeq: number = 0;
  private lastReadIssue: MutationReadIssue | undefined;
  private appendBlockedReason: string | undefined;
  private migrationOwnerToken: string | undefined;
  private observedJournalHead?: {
    fingerprint: string | null;
    logicalSeq: number;
    physicalFrameSeq: number;
  };
  private observedStateCheckpoint?: {
    fingerprint: string | null;
    checkpoint: number;
  };
  private readonly writerInstanceToken = randomUUID();
  private retainedWriterRelease?: () => void;

  constructor(stateFilePath: string) {
    this.stateFilePath = stateFilePath;
    const stateDir = dirname(stateFilePath);
    this.journalPath = join(stateDir, basename(stateFilePath, '.json') + '.journal.jsonl');
  }

  setMigrationOwnerToken(token: string | undefined): void {
    this.migrationOwnerToken = token;
  }

  private assertMigrationWriteAllowed(): void {
    assertStateMigrationWriteAllowed(this.stateFilePath, this.migrationOwnerToken);
  }

  private withMigrationWriteGuard<T>(operation: () => T): T {
    const absoluteStatePath = resolve(this.stateFilePath);
    if (this.retainedWriterRelease) {
      const retainedOwner = retainedWriterOwners.get(absoluteStatePath);
      if (retainedOwner?.token !== this.writerInstanceToken) {
        throw new Error(`state writer lock ownership was lost for ${absoluteStatePath}`);
      }
      retainedOwner.busy++;
      try {
        this.assertMigrationWriteAllowed();
        return operation();
      } finally {
        retainedOwner.busy--;
      }
    }
    this.releaseIdleCompetingWriter(absoluteStatePath);
    const retainedOwner = retainedWriterOwners.get(absoluteStatePath);
    if (retainedOwner && retainedOwner.token !== this.writerInstanceToken) {
      throw new Error(`state writer lock is already owned for ${absoluteStatePath}`);
    }
    return withStateMigrationWriteGuard(
      this.stateFilePath,
      this.migrationOwnerToken,
      operation,
    );
  }

  private retainMigrationWriteGuard(): void {
    if (this.retainedWriterRelease) return;
    const absoluteStatePath = resolve(this.stateFilePath);
    this.releaseIdleCompetingWriter(absoluteStatePath);
    const retainedOwner = retainedWriterOwners.get(absoluteStatePath);
    if (retainedOwner && retainedOwner.token !== this.writerInstanceToken) {
      throw new Error(`state writer lock is already owned for ${absoluteStatePath}`);
    }
    const release = acquireStateMigrationWriteGuard(
      this.stateFilePath,
      this.migrationOwnerToken,
    );
    const owner: RetainedWriterOwner = {
      token: this.writerInstanceToken,
      busy: 0,
      release: () => {},
    };
    const releaseRetained = () => {
      if (owner.busy > 0 || getStateWriterLockDepth(absoluteStatePath) !== 1) {
        throw new Error(`state writer lock is busy for ${absoluteStatePath}`);
      }
      release();
      if (retainedWriterOwners.get(absoluteStatePath) === owner) {
        retainedWriterOwners.delete(absoluteStatePath);
      }
      if (this.retainedWriterRelease === releaseRetained) {
        this.retainedWriterRelease = undefined;
      }
    };
    owner.release = releaseRetained;
    retainedWriterOwners.set(absoluteStatePath, owner);
    this.retainedWriterRelease = releaseRetained;
  }

  private releaseIdleCompetingWriter(absoluteStatePath: string): void {
    const retainedOwner = retainedWriterOwners.get(absoluteStatePath);
    if (!retainedOwner || retainedOwner.token === this.writerInstanceToken) return;
    if (retainedOwner.busy > 0) {
      throw new Error(`state writer lock is already owned for ${absoluteStatePath}`);
    }
    if (getStateWriterLockDepth(absoluteStatePath) !== 1) {
      throw new Error(`state writer lock is already owned for ${absoluteStatePath}`);
    }
    retainedOwner.release();
  }

  dispose(): void {
    this.retainedWriterRelease?.();
  }

  private fileFingerprint(path: string): string | null {
    if (!existsSync(path)) return null;
    const stat = statSync(path);
    return [
      stat.dev,
      stat.ino,
      stat.size,
      stat.mtimeMs,
      stat.ctimeMs,
    ].join(':');
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
    options: {
      preserveAllocated?: boolean;
      appliedThroughSeq?: number;
      physicalFrameSeq?: number;
    } = {},
  ): void {
    this.nextSeq = options.preserveAllocated ? Math.max(this.nextSeq, seq) : seq;
    const physical = options.physicalFrameSeq ?? seq;
    this.nextFrameSeq = options.preserveAllocated
      ? Math.max(this.nextFrameSeq, physical)
      : physical;
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

  /** Highest physical frame sequence allocated by this process. */
  getHighestAllocatedFrameSeq(): number {
    return this.nextFrameSeq;
  }

  /** Highest parseable sequence physically present in the WAL. */
  getHighestPhysicalSeq(): number {
    return this.highestSeqOnDisk();
  }

  /** Highest parseable physical frame sequence present in the WAL. Journal v1
   * records use their logical seq as the frame sequence. */
  getHighestPhysicalFrameSeq(): number {
    return this.highestPhysicalFrameSeqOnDisk();
  }

  /**
   * Best-effort observed on-disk journal format. This is deliberately distinct
   * from the current writer version so degraded recovery can truthfully report
   * a legacy or future WAL without implying that this binary wrote it.
   */
  getObservedFormatVersion(): number | undefined {
    if (!existsSync(this.journalPath)) return undefined;
    const raw = readFileSync(this.journalPath);
    let observed: number | undefined;
    let byteOffset = 0;
    while (byteOffset < raw.length) {
      const newlineOffset = raw.indexOf(0x0a, byteOffset);
      const byteEnd = newlineOffset < 0 ? raw.length : newlineOffset;
      const frame = raw.subarray(byteOffset, byteEnd);
      byteOffset = newlineOffset < 0 ? raw.length : newlineOffset + 1;
      if (frame.length === 0) continue;
      try {
        const record = JSON.parse(decodeUtf8Fatal(frame)) as Record<string, unknown>;
        if (
          Number.isSafeInteger(record.journal_version)
          && (record.journal_version as number) > 0
        ) {
          observed = record.journal_version as number;
        } else if (
          observed === undefined
          && Number.isSafeInteger(record.seq)
          && typeof record.type === 'string'
          && isRecord(record.payload)
        ) {
          observed = LEGACY_JOURNAL_VERSION;
        }
      } catch {
        // Format reporting is best effort. Recovery still performs strict
        // validation and surfaces malformed bytes independently.
      }
    }
    return observed;
  }

  /** Highest sequence known to have been applied contiguously in memory. */
  getAppliedThroughSeq(): number {
    return this.appliedThroughSeq;
  }

  /**
   * Verify that this process still owns the current durable transaction head
   * before it replaces the primary state file. The caller must hold the shared
   * state-writer mutex so another cooperating process cannot append or replace
   * state between this check and the atomic rename.
   */
  assertCaughtUpForStateWrite(stateCheckpoint: number): void {
    if (!Number.isSafeInteger(stateCheckpoint) || stateCheckpoint < 0) {
      throw new Error('durable state checkpoint must be a non-negative safe integer');
    }
    const scan = this.scanTransactions();
    const issue = this.resolveTransactionReplayIssue(
      scan,
      stateCheckpoint,
      { trustedContiguousCheckpoint: true },
    );
    if (issue) {
      throw new Error(
        `journal integrity check failed before state write at line ${issue.line}: ${issue.reason}`,
      );
    }
    const walHead = scan.transactions.at(-1)?.transaction.seq ?? 0;
    const durableHead = Math.max(walHead, stateCheckpoint);
    if (durableHead !== this.appliedThroughSeq) {
      throw new Error(
        `writer is stale: durable transaction head ${durableHead} does not match local applied checkpoint ${this.appliedThroughSeq}`,
      );
    }
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
   * Append one journal-v2 transaction. The complete begin/chunk/commit frame
   * set is serialized and validated before the logical sequence is allocated,
   * then written with one append descriptor and one fsync. A crash may leave an
   * incomplete physical tail, but recovery will never expose it as committed.
   */
  appendTransaction(draft: EngineTransactionDraft & { ts?: string }): EngineTransaction {
    const retainedBefore = this.retainedWriterRelease !== undefined;
    if (
      draft.operations.length === 1
      && draft.operations[0]?.type === 'activity_append'
    ) {
      this.retainMigrationWriteGuard();
    }
    try {
      return this.withMigrationWriteGuard(() => this.appendTransactionUnlocked(draft));
    } catch (error) {
      if (!retainedBefore) this.retainedWriterRelease?.();
      throw error;
    }
  }

  private appendTransactionUnlocked(
    draft: EngineTransactionDraft & { ts?: string },
  ): EngineTransaction {
    if (this.appendBlockedReason) {
      throw new Error(`Mutation journal is read-only: ${this.appendBlockedReason}`);
    }
    this.assertMigrationWriteAllowed();
    const journalFingerprint = this.fileFingerprint(this.journalPath);
    let walHead: number;
    let physicalFrameHead: number;
    let scan: EngineTransactionScanResult | undefined;
    if (
      this.observedJournalHead
      && this.observedJournalHead.fingerprint === journalFingerprint
    ) {
      walHead = this.observedJournalHead.logicalSeq;
      physicalFrameHead = this.observedJournalHead.physicalFrameSeq;
    } else {
      scan = this.scanTransactions();
      if (scan.issue) {
        this.blockAppends(
          `journal integrity check failed before append at line ${scan.issue.line}: ${scan.issue.reason}`,
        );
        throw new Error(`Mutation journal is read-only: ${this.appendBlockedReason}`);
      }
      const lastTransaction = scan.transactions.at(-1)?.transaction;
      walHead = lastTransaction?.seq ?? 0;
      physicalFrameHead = lastTransaction?.commit_frame_seq ?? 0;
      this.observedJournalHead = {
        fingerprint: journalFingerprint,
        logicalSeq: walHead,
        physicalFrameSeq: physicalFrameHead,
      };
    }
    const stateFingerprint = this.fileFingerprint(this.stateFilePath);
    let stateCheckpoint: number;
    if (
      this.observedStateCheckpoint
      && this.observedStateCheckpoint.fingerprint === stateFingerprint
    ) {
      stateCheckpoint = this.observedStateCheckpoint.checkpoint;
    } else if (stateFingerprint !== null) {
      let state: unknown;
      try {
        state = JSON.parse(decodeUtf8Fatal(readFileSync(this.stateFilePath)));
      } catch (error) {
        this.blockAppends(
          `state checkpoint could not be read before WAL append: ${error instanceof Error ? error.message : String(error)}`,
        );
        throw new Error(`Mutation journal is read-only: ${this.appendBlockedReason}`);
      }
      if (isRecord(state) && state.journalSnapshotSeq !== undefined) {
        if (
          !Number.isSafeInteger(state.journalSnapshotSeq)
          || (state.journalSnapshotSeq as number) < 0
        ) {
          this.blockAppends('state checkpoint is invalid before WAL append');
          throw new Error(`Mutation journal is read-only: ${this.appendBlockedReason}`);
        }
        stateCheckpoint = state.journalSnapshotSeq as number;
      } else {
        stateCheckpoint = 0;
      }
      this.observedStateCheckpoint = {
        fingerprint: stateFingerprint,
        checkpoint: stateCheckpoint,
      };
    } else {
      stateCheckpoint = 0;
      this.observedStateCheckpoint = {
        fingerprint: null,
        checkpoint: 0,
      };
    }
    if (scan) {
      const replayIssue = this.resolveTransactionReplayIssue(
        scan,
        stateCheckpoint,
        { trustedContiguousCheckpoint: true },
      );
      if (replayIssue) {
        this.blockAppends(
          `journal integrity check failed before append at line ${replayIssue.line}: ${replayIssue.reason}`,
        );
        throw new Error(`Mutation journal is read-only: ${this.appendBlockedReason}`);
      }
    }
    const durableHead = Math.max(walHead, stateCheckpoint);
    if (durableHead !== this.appliedThroughSeq) {
      this.blockAppends(
        `writer is stale: durable transaction head ${durableHead} does not match local applied checkpoint ${this.appliedThroughSeq}`,
      );
      throw new Error(`Mutation journal is read-only: ${this.appendBlockedReason}`);
    }
    const seq = this.nextSeq + 1;
    const payloadBytes = transactionPayload(draft).length;
    const chunkCount = Math.max(1, Math.ceil(payloadBytes / JOURNAL_V2_CHUNK_BYTES));
    const beginFrameSeq = Math.max(this.nextFrameSeq, physicalFrameHead) + 1;
    const commitFrameSeq = beginFrameSeq + chunkCount + 1;
    const transaction: EngineTransaction = {
      version: CURRENT_JOURNAL_VERSION,
      tx_id: randomUUID(),
      seq,
      begin_frame_seq: beginFrameSeq,
      commit_frame_seq: commitFrameSeq,
      ts: draft.ts ?? new Date().toISOString(),
      operations: draft.operations,
      ...(draft.source_action_id ? { source_action_id: draft.source_action_id } : {}),
      ...(draft.update_detail === undefined ? {} : { update_detail: draft.update_detail }),
    };
    const bytes = encodeTransactionFrames(transaction);

    // Once I/O begins the logical sequence is allocated even if the caller
    // cannot determine how many frames reached the file.
    this.nextSeq = seq;
    this.nextFrameSeq = commitFrameSeq;
    const stateDir = dirname(this.journalPath);
    if (!existsSync(stateDir)) mkdirDurable(stateDir);
    const existed = existsSync(this.journalPath);
    let fd: number | undefined;
    try {
      fd = openSync(this.journalPath, 'a');
      writeAllSync(fd, bytes);
      fsyncSync(fd);
    } catch (error) {
      this.blockAppends(`append of allocated transaction seq ${seq} failed`);
      throw error;
    } finally {
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch (error) {
          this.blockAppends(`close after append of allocated transaction seq ${seq} failed`);
          throw error;
        }
      }
    }
    if (!existed) {
      try {
        fsyncDirectory(stateDir);
      } catch (error) {
        this.blockAppends(`directory fsync for allocated transaction seq ${seq} failed`);
        throw error;
      }
    }
    try {
      this.observedJournalHead = {
        fingerprint: this.fileFingerprint(this.journalPath),
        logicalSeq: seq,
        physicalFrameSeq: commitFrameSeq,
      };
    } catch {
      // The append is already durable. A missing cache only makes the next
      // append rescan; it must not retroactively turn a committed write into a
      // reported failure.
      this.observedJournalHead = undefined;
    }
    return transaction;
  }

  /**
   * Append a mutation entry. Synchronously fsyncs the file before
   * returning. Throws on write failure — callers MUST treat that as
   * "the mutation is not durable, do not apply it in memory."
   *
   * This is the legacy journal-v1 writer retained for migration fixtures and
   * backward-compatibility tests. Production engine writes use
   * appendTransaction().
   */
  append(entry: Omit<MutationEntry, 'seq' | 'ts'> & { ts?: string }): MutationEntry {
    return this.withMigrationWriteGuard(() => this.appendUnlocked(entry));
  }

  private appendUnlocked(
    entry: Omit<MutationEntry, 'seq' | 'ts'> & { ts?: string },
  ): MutationEntry {
    if (this.appendBlockedReason) {
      throw new Error(`Mutation journal is read-only: ${this.appendBlockedReason}`);
    }
    this.assertMigrationWriteAllowed();
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
    this.nextFrameSeq = Math.max(this.nextFrameSeq, seq);

    // Open-append-fsync-close: simple and bulletproof; the bulkier
    // engagements that justify a long-lived stream can land later.
    const stateDir = dirname(this.journalPath);
    if (!existsSync(stateDir)) mkdirDurable(stateDir);
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
    const scan = this.scanTransactions();
    const issue = afterCheckpoint === undefined
      ? scan.issue
      : this.resolveTransactionReplayIssue(
          scan,
          afterCheckpoint,
          { trustedContiguousCheckpoint: true },
        );
    return issue ? { ...issue } : undefined;
  }

  /** Candidate-aware read-only replay preflight. Unlike inspectIntegrity(),
   * this can preserve the ambiguity semantics of a legacy checkpoint. */
  inspectReplayIntegrity(
    fromSeq: number,
    options: MutationReplayOptions = {},
  ): MutationReadIssue | undefined {
    const issue = this.resolveTransactionReplayIssue(
      this.scanTransactions(),
      fromSeq,
      options,
    );
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
        const e = JSON.parse(decodeUtf8Fatal(frame)) as {
          seq?: unknown;
          tx_seq?: unknown;
        };
        const logical = Number.isSafeInteger(e.tx_seq)
          ? e.tx_seq as number
          : Number.isSafeInteger(e.seq)
            ? e.seq as number
            : 0;
        if (logical > max) max = logical;
      } catch { /* skip malformed */ }
    }
    return max;
  }

  private highestPhysicalFrameSeqOnDisk(): number {
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
        const record = JSON.parse(decodeUtf8Fatal(frame)) as {
          seq?: unknown;
          frame_seq?: unknown;
        };
        const physical = Number.isSafeInteger(record.frame_seq)
          ? record.frame_seq as number
          : Number.isSafeInteger(record.seq)
            ? record.seq as number
            : 0;
        if (physical > max) max = physical;
      } catch { /* skip malformed */ }
    }
    return max;
  }

  /**
   * Scan legacy primitive records and journal-v2 transactions into one logical
   * transaction stream. A legacy prefix followed by v2 is supported so old
   * snapshots can continue replaying through the upgrade boundary. Once a v2
   * frame appears, a later v1 record is rejected.
   */
  private scanTransactions(): EngineTransactionScanResult {
    if (!existsSync(this.journalPath)) {
      return { raw: Buffer.alloc(0), transactions: [] };
    }
    const raw = readFileSync(this.journalPath);
    if (raw.length === 0) return { raw, transactions: [] };

    const transactions: ScannedEngineTransaction[] = [];
    let byteOffset = 0;
    let line = 1;
    let previousTxSeq: number | undefined;
    let previousFrameSeq: number | undefined;
    let formatVersion: typeof LEGACY_JOURNAL_VERSION | typeof CURRENT_JOURNAL_VERSION | undefined;

    const issue = (
      kind: MutationReadIssue['kind'],
      atLine: number,
      atOffset: number,
      reason: string,
      extra: Partial<MutationReadIssue> = {},
    ): EngineTransactionScanResult => ({
      raw,
      transactions,
      format_version: formatVersion,
      issue: {
        kind,
        line: atLine,
        byte_offset: atOffset,
        reason,
        ...extra,
      },
    });

    const parseFrame = (
      offset: number,
      frameLine: number,
    ):
      | { ok: true; value: unknown; bytes: Buffer; byte_end: number }
      | { ok: false; result: EngineTransactionScanResult } => {
      if (offset >= raw.length) {
        return {
          ok: false,
          result: issue(
            'incomplete_transaction',
            frameLine,
            offset,
            'transaction ended before every declared frame and tx_commit were present',
          ),
        };
      }
      const newlineOffset = raw.indexOf(0x0a, offset);
      if (newlineOffset < 0) {
        return {
          ok: false,
          result: issue(
            'malformed_entry',
            frameLine,
            offset,
            'unterminated journal frame at physical EOF (missing newline commit marker)',
            { unterminated_eof_fragment: true },
          ),
        };
      }
      const bytes = raw.subarray(offset, newlineOffset);
      if (bytes.length === 0) {
        return {
          ok: false,
          result: issue('malformed_entry', frameLine, offset, 'empty journal frame'),
        };
      }
      try {
        return {
          ok: true,
          value: JSON.parse(decodeUtf8Fatal(bytes)),
          bytes,
          byte_end: newlineOffset + 1,
        };
      } catch (error) {
        return {
          ok: false,
          result: issue(
            'malformed_entry',
            frameLine,
            offset,
            error instanceof Error ? error.message : String(error),
          ),
        };
      }
    };

    while (byteOffset < raw.length) {
      const firstOffset = byteOffset;
      const firstLine = line;
      const first = parseFrame(byteOffset, line);
      if (!first.ok) return first.result;
      if (!isRecord(first.value)) {
        return issue('malformed_entry', line, byteOffset, 'journal frame must be an object');
      }

      const value = first.value;
      const looksLikeV2 = value.record_type !== undefined || value.journal_version !== undefined;
      if (!looksLikeV2) {
        if (formatVersion === CURRENT_JOURNAL_VERSION) {
          return issue(
            'unsupported_journal_version',
            line,
            byteOffset,
            'legacy journal-v1 record appears after journal-v2 frames',
          );
        }
        formatVersion = LEGACY_JOURNAL_VERSION;
        const validation = validateMutationEntry(value);
        if (!validation.ok) {
          return issue('malformed_entry', line, byteOffset, validation.reason);
        }
        const entry = validation.entry;
        if (previousTxSeq !== undefined && entry.seq !== previousTxSeq + 1) {
          return issue(
            'sequence_gap',
            line,
            byteOffset,
            `journal transaction sequence discontinuity: expected ${previousTxSeq + 1}, found ${entry.seq}`,
            {
              expected_seq: previousTxSeq + 1,
              actual_seq: entry.seq,
              offending_record_included: false,
            },
          );
        }
        if (previousFrameSeq !== undefined && entry.seq !== previousFrameSeq + 1) {
          return issue(
            'sequence_gap',
            line,
            byteOffset,
            `journal physical frame sequence discontinuity: expected ${previousFrameSeq + 1}, found ${entry.seq}`,
            {
              expected_seq: previousFrameSeq + 1,
              actual_seq: entry.seq,
              frame_seq: entry.seq,
              offending_record_included: false,
            },
          );
        }
        const transaction: EngineTransaction = {
          version: CURRENT_JOURNAL_VERSION,
          tx_id: `legacy-v1-${entry.seq}`,
          seq: entry.seq,
          begin_frame_seq: entry.seq,
          commit_frame_seq: entry.seq,
          ts: entry.ts,
          operations: [{ type: entry.type, payload: entry.payload }],
          ...(entry.source_action_id ? { source_action_id: entry.source_action_id } : {}),
        };
        transactions.push({
          transaction,
          line,
          byte_offset: byteOffset,
          byte_end: first.byte_end,
          format_version: LEGACY_JOURNAL_VERSION,
          frame_count: 1,
        });
        previousTxSeq = entry.seq;
        previousFrameSeq = entry.seq;
        byteOffset = first.byte_end;
        line++;
        if (!REPLAYABLE_MUTATION_TYPES.has(entry.type)) {
          return issue(
            'unknown_type',
            firstLine,
            firstOffset,
            `unsupported journal mutation type: ${entry.type}`,
            {
              actual_seq: entry.seq,
              frame_seq: entry.seq,
              tx_id: transaction.tx_id,
              offending_record_included: true,
            },
          );
        }
        continue;
      }

      if (value.journal_version !== CURRENT_JOURNAL_VERSION) {
        return issue(
          'unsupported_journal_version',
          line,
          byteOffset,
          `unsupported journal frame version: ${String(value.journal_version)}`,
        );
      }
      if (value.record_type !== 'tx_begin') {
        return issue(
          'interleaved_transaction',
          line,
          byteOffset,
          `expected tx_begin, found ${String(value.record_type)}`,
          {
            frame_seq: Number.isSafeInteger(value.frame_seq) ? value.frame_seq as number : undefined,
            tx_id: nonEmptyString(value.tx_id) ? value.tx_id : undefined,
          },
        );
      }
      formatVersion = CURRENT_JOURNAL_VERSION;
      const begin = value as unknown as JournalV2BeginRecord;
      if (
        begin.tx_version !== 2
        || !Number.isSafeInteger(begin.frame_seq)
        || begin.frame_seq <= 0
        || !Number.isSafeInteger(begin.tx_seq)
        || begin.tx_seq <= 0
        || !nonEmptyString(begin.tx_id)
        || !nonEmptyString(begin.ts)
        || !Number.isFinite(Date.parse(begin.ts))
        || !Number.isSafeInteger(begin.operation_count)
        || begin.operation_count <= 0
        || begin.operation_count > JOURNAL_V2_MAX_OPERATIONS
        || !Number.isSafeInteger(begin.payload_bytes)
        || begin.payload_bytes < 0
        || begin.payload_bytes > JOURNAL_V2_MAX_TRANSACTION_BYTES
        || !Number.isSafeInteger(begin.chunk_count)
        || begin.chunk_count <= 0
        || begin.chunk_count !== Math.max(1, Math.ceil(begin.payload_bytes / JOURNAL_V2_CHUNK_BYTES))
        || typeof begin.payload_sha256 !== 'string'
        || !/^[a-f0-9]{64}$/.test(begin.payload_sha256)
        || (begin.source_action_id !== undefined && !nonEmptyString(begin.source_action_id))
      ) {
        return issue('malformed_entry', line, byteOffset, 'invalid tx_begin frame');
      }
      if (previousTxSeq !== undefined && begin.tx_seq !== previousTxSeq + 1) {
        return issue(
          'sequence_gap',
          line,
          byteOffset,
          `journal transaction sequence discontinuity: expected ${previousTxSeq + 1}, found ${begin.tx_seq}`,
          {
            expected_seq: previousTxSeq + 1,
            actual_seq: begin.tx_seq,
            frame_seq: begin.frame_seq,
            tx_id: begin.tx_id,
            offending_record_included: false,
          },
        );
      }
      if (previousFrameSeq !== undefined && begin.frame_seq !== previousFrameSeq + 1) {
        return issue(
          'sequence_gap',
          line,
          byteOffset,
          `journal physical frame sequence discontinuity: expected ${previousFrameSeq + 1}, found ${begin.frame_seq}`,
          {
            expected_seq: previousFrameSeq + 1,
            actual_seq: begin.frame_seq,
            frame_seq: begin.frame_seq,
            tx_id: begin.tx_id,
            offending_record_included: false,
          },
        );
      }

      byteOffset = first.byte_end;
      line++;
      const chunkBuffers: Buffer[] = [];
      const chunkHashes: string[] = [];
      let lastFrameSeq = begin.frame_seq;
      for (let chunkIndex = 0; chunkIndex < begin.chunk_count; chunkIndex++) {
        if (byteOffset >= raw.length) {
          return issue(
            'incomplete_transaction',
            firstLine,
            firstOffset,
            `transaction ${begin.tx_id} ended before chunk ${chunkIndex}`,
            {
              actual_seq: begin.tx_seq,
              frame_seq: lastFrameSeq,
              tx_id: begin.tx_id,
            },
          );
        }
        const parsed = parseFrame(byteOffset, line);
        if (!parsed.ok) {
          if (parsed.result.issue?.kind === 'incomplete_transaction') {
            return issue(
              'incomplete_transaction',
              firstLine,
              firstOffset,
              `transaction ${begin.tx_id} ended before chunk ${chunkIndex}`,
              {
                actual_seq: begin.tx_seq,
                frame_seq: lastFrameSeq,
                tx_id: begin.tx_id,
              },
            );
          }
          return parsed.result;
        }
        const chunk = parsed.value;
        if (
          !isRecord(chunk)
          || chunk.journal_version !== CURRENT_JOURNAL_VERSION
          || chunk.record_type !== 'tx_chunk'
          || chunk.tx_seq !== begin.tx_seq
          || chunk.tx_id !== begin.tx_id
          || chunk.chunk_index !== chunkIndex
          || chunk.frame_seq !== lastFrameSeq + 1
          || typeof chunk.chunk_sha256 !== 'string'
          || !/^[a-f0-9]{64}$/.test(chunk.chunk_sha256)
          || typeof chunk.data !== 'string'
        ) {
          return issue(
            'interleaved_transaction',
            line,
            byteOffset,
            `invalid or interleaved tx_chunk ${chunkIndex} for transaction ${begin.tx_id}`,
            {
              actual_seq: begin.tx_seq,
              frame_seq: isRecord(chunk) && Number.isSafeInteger(chunk.frame_seq)
                ? chunk.frame_seq as number
                : undefined,
              tx_id: begin.tx_id,
            },
          );
        }
        const decoded = Buffer.from(chunk.data, 'base64');
        if (decoded.toString('base64') !== chunk.data) {
          return issue(
            'malformed_entry',
            line,
            byteOffset,
            `transaction ${begin.tx_id} chunk ${chunkIndex} is not canonical base64`,
            { actual_seq: begin.tx_seq, frame_seq: chunk.frame_seq as number, tx_id: begin.tx_id },
          );
        }
        const chunkHash = createHash('sha256').update(decoded).digest('hex');
        if (chunkHash !== chunk.chunk_sha256) {
          return issue(
            'checksum_mismatch',
            line,
            byteOffset,
            `transaction ${begin.tx_id} chunk ${chunkIndex} checksum mismatch`,
            { actual_seq: begin.tx_seq, frame_seq: chunk.frame_seq as number, tx_id: begin.tx_id },
          );
        }
        chunkBuffers.push(decoded);
        chunkHashes.push(chunkHash);
        lastFrameSeq = chunk.frame_seq as number;
        byteOffset = parsed.byte_end;
        line++;
      }

      if (byteOffset >= raw.length) {
        return issue(
          'incomplete_transaction',
          firstLine,
          firstOffset,
          `transaction ${begin.tx_id} has no tx_commit`,
          {
            actual_seq: begin.tx_seq,
            frame_seq: lastFrameSeq,
            tx_id: begin.tx_id,
          },
        );
      }
      const parsedCommit = parseFrame(byteOffset, line);
      if (!parsedCommit.ok) return parsedCommit.result;
      const commit = parsedCommit.value;
      if (
        !isRecord(commit)
        || commit.journal_version !== CURRENT_JOURNAL_VERSION
        || commit.record_type !== 'tx_commit'
        || commit.tx_seq !== begin.tx_seq
        || commit.tx_id !== begin.tx_id
        || commit.frame_seq !== lastFrameSeq + 1
        || commit.operation_count !== begin.operation_count
        || commit.payload_bytes !== begin.payload_bytes
        || commit.chunk_count !== begin.chunk_count
        || commit.payload_sha256 !== begin.payload_sha256
        || typeof commit.commit_checksum !== 'string'
        || !/^[a-f0-9]{64}$/.test(commit.commit_checksum)
      ) {
        return issue(
          'interleaved_transaction',
          line,
          byteOffset,
          `invalid or interleaved tx_commit for transaction ${begin.tx_id}`,
          {
            actual_seq: begin.tx_seq,
            frame_seq: isRecord(commit) && Number.isSafeInteger(commit.frame_seq)
              ? commit.frame_seq as number
              : undefined,
            tx_id: begin.tx_id,
          },
        );
      }
      const expectedCommitChecksum = transactionCommitChecksum(begin, chunkHashes);
      if (commit.commit_checksum !== expectedCommitChecksum) {
        return issue(
          'checksum_mismatch',
          line,
          byteOffset,
          `transaction ${begin.tx_id} commit checksum mismatch`,
          {
            actual_seq: begin.tx_seq,
            frame_seq: commit.frame_seq as number,
            tx_id: begin.tx_id,
          },
        );
      }
      const payload = Buffer.concat(chunkBuffers);
      if (payload.length !== begin.payload_bytes) {
        return issue(
          'checksum_mismatch',
          line,
          byteOffset,
          `transaction ${begin.tx_id} payload length mismatch`,
          {
            actual_seq: begin.tx_seq,
            frame_seq: commit.frame_seq as number,
            tx_id: begin.tx_id,
          },
        );
      }
      if (createHash('sha256').update(payload).digest('hex') !== begin.payload_sha256) {
        return issue(
          'checksum_mismatch',
          line,
          byteOffset,
          `transaction ${begin.tx_id} payload checksum mismatch`,
          {
            actual_seq: begin.tx_seq,
            frame_seq: commit.frame_seq as number,
            tx_id: begin.tx_id,
          },
        );
      }

      let decodedPayload: unknown;
      try {
        decodedPayload = JSON.parse(decodeUtf8Fatal(payload));
      } catch (error) {
        return issue(
          'malformed_entry',
          firstLine,
          firstOffset,
          `transaction ${begin.tx_id} payload is invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
          {
            actual_seq: begin.tx_seq,
            frame_seq: commit.frame_seq as number,
            tx_id: begin.tx_id,
          },
        );
      }
      if (
        !isRecord(decodedPayload)
        || !Array.isArray(decodedPayload.operations)
        || decodedPayload.operations.length !== begin.operation_count
        || (decodedPayload.update_detail !== undefined && !isRecord(decodedPayload.update_detail))
      ) {
        return issue(
          'malformed_entry',
          firstLine,
          firstOffset,
          `transaction ${begin.tx_id} payload shape does not match tx_begin`,
          {
            actual_seq: begin.tx_seq,
            frame_seq: commit.frame_seq as number,
            tx_id: begin.tx_id,
          },
        );
      }
      const operations: EngineOperation[] = [];
      let unknownOperation: EngineOperation | undefined;
      for (const [index, operation] of decodedPayload.operations.entries()) {
        const validation = validateEngineOperation(operation, begin.tx_seq, begin.ts);
        if (!validation.ok) {
          return issue(
            'malformed_entry',
            firstLine,
            firstOffset,
            `transaction ${begin.tx_id} operation ${index} is invalid: ${validation.reason}`,
            {
              actual_seq: begin.tx_seq,
              frame_seq: commit.frame_seq as number,
              tx_id: begin.tx_id,
            },
          );
        }
        operations.push(validation.operation);
        if (!REPLAYABLE_MUTATION_TYPES.has(validation.operation.type)) {
          unknownOperation ??= validation.operation;
        }
      }
      const relationshipValidation = validateTransactionOperationRelationships(operations);
      if (!relationshipValidation.ok) {
        return issue(
          'malformed_entry',
          firstLine,
          firstOffset,
          `transaction ${begin.tx_id} is invalid: ${relationshipValidation.reason}`,
          {
            actual_seq: begin.tx_seq,
            frame_seq: commit.frame_seq as number,
            tx_id: begin.tx_id,
          },
        );
      }
      const transaction: EngineTransaction = {
        version: CURRENT_JOURNAL_VERSION,
        tx_id: begin.tx_id,
        seq: begin.tx_seq,
        begin_frame_seq: begin.frame_seq,
        commit_frame_seq: commit.frame_seq as number,
        ts: begin.ts,
        operations,
        ...(begin.source_action_id ? { source_action_id: begin.source_action_id } : {}),
        ...(decodedPayload.update_detail === undefined
          ? {}
          : { update_detail: decodedPayload.update_detail }),
      };
      transactions.push({
        transaction,
        line: firstLine,
        byte_offset: firstOffset,
        byte_end: parsedCommit.byte_end,
        format_version: CURRENT_JOURNAL_VERSION,
        frame_count: begin.chunk_count + 2,
      });
      previousTxSeq = begin.tx_seq;
      previousFrameSeq = commit.frame_seq as number;
      byteOffset = parsedCommit.byte_end;
      line++;
      if (unknownOperation) {
        return issue(
          'unknown_type',
          firstLine,
          firstOffset,
          `unsupported journal mutation type: ${unknownOperation.type}`,
          {
            actual_seq: begin.tx_seq,
            frame_seq: commit.frame_seq as number,
            tx_id: begin.tx_id,
            offending_record_included: true,
          },
        );
      }
    }
    return {
      raw,
      transactions,
      format_version: formatVersion,
    };
  }

  private readForReplay(
    fromSeq: number,
    options: MutationReplayOptions = {},
  ): MutationEntry[] {
    const scan = this.scanTransactions();
    const replayTransactions = scan.transactions.filter(record => record.transaction.seq > fromSeq);
    const issue = this.resolveTransactionReplayIssue(scan, fromSeq, options);
    this.lastReadIssue = issue;
    return replayTransactions.flatMap(record =>
      record.transaction.operations.map(operation => ({
        seq: record.transaction.seq,
        ts: record.transaction.ts,
        type: operation.type,
        payload: operation.payload,
        ...(record.transaction.source_action_id
          ? { source_action_id: record.transaction.source_action_id }
          : {}),
      })),
    );
  }

  private readTransactionsForReplay(
    fromSeq: number,
    options: MutationReplayOptions = {},
  ): EngineTransaction[] {
    const scan = this.scanTransactions();
    const issue = this.resolveTransactionReplayIssue(scan, fromSeq, options);
    this.lastReadIssue = issue;
    return scan.transactions
      .filter(record => record.transaction.seq > fromSeq)
      .map(record => record.transaction);
  }

  private resolveTransactionReplayIssue(
    scan: EngineTransactionScanResult,
    fromSeq: number,
    options: MutationReplayOptions,
  ): MutationReadIssue | undefined {
    const ambiguous = options.trustedContiguousCheckpoint === false && fromSeq > 0
      ? scan.transactions.find(record => record.transaction.seq <= fromSeq)
      : undefined;
    if (ambiguous) {
      return {
        kind: 'ambiguous_checkpoint',
        line: ambiguous.line,
        byte_offset: ambiguous.byte_offset,
        reason: `legacy base checkpoint ${fromSeq} may hide retained WAL transaction seq ${ambiguous.transaction.seq}`,
        expected_seq: fromSeq + 1,
        actual_seq: ambiguous.transaction.seq,
        frame_seq: ambiguous.transaction.begin_frame_seq,
        tx_id: ambiguous.transaction.tx_id,
      };
    }
    const firstNewer = scan.transactions.find(record => record.transaction.seq > fromSeq);
    if (firstNewer && firstNewer.transaction.seq !== fromSeq + 1) {
      const gap: MutationReadIssue = {
        kind: 'sequence_gap',
        line: firstNewer.line,
        byte_offset: firstNewer.byte_offset,
        reason: `expected transaction seq ${fromSeq + 1}, found ${firstNewer.transaction.seq}`,
        expected_seq: fromSeq + 1,
        actual_seq: firstNewer.transaction.seq,
        frame_seq: firstNewer.transaction.begin_frame_seq,
        tx_id: firstNewer.transaction.tx_id,
        offending_record_included: true,
      };
      if (!scan.issue || gap.byte_offset <= scan.issue.byte_offset) return gap;
    }
    return scan.issue;
  }

  readSince(fromSeq: number): MutationEntry[] {
    return this.readForReplay(fromSeq, { trustedContiguousCheckpoint: true });
  }

  readTransactionsSince(fromSeq: number): EngineTransaction[] {
    return this.readTransactionsForReplay(
      fromSeq,
      { trustedContiguousCheckpoint: true },
    );
  }

  /**
   * Compact the journal: drop entries with `seq <= upTo`, keep newer ones.
   * Used after a snapshot rotation — entries that are now in the snapshot
   * are redundant and can be discarded.
   *
   * Atomic on POSIX via write-tmp-then-rename.
   */
  compactUpTo(upTo: number): MutationCompactionResult {
    return this.withMigrationWriteGuard(() => this.compactUpToUnlocked(upTo));
  }

  private compactUpToUnlocked(upTo: number): MutationCompactionResult {
    this.assertMigrationWriteAllowed();
    const scan = this.scanTransactions();
    if (scan.raw.length === 0) return { kept: 0, dropped: 0 };
    if (scan.issue) {
      return {
        kept: 0,
        dropped: 0,
        preserved: true,
        reason: `journal scan failed at line ${scan.issue.line}: ${scan.issue.reason}`,
      };
    }
    const keptRecords = scan.transactions.filter(record => record.transaction.seq > upTo);
    const kept = keptRecords.length;
    const dropped = scan.transactions.length - kept;
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
    this.withMigrationWriteGuard(() => this.truncateUnlocked());
  }

  private truncateUnlocked(): void {
    this.assertMigrationWriteAllowed();
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
    return this.withMigrationWriteGuard(() => this.quarantineUnlocked());
  }

  private quarantineUnlocked(): string | undefined {
    this.assertMigrationWriteAllowed();
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
   * Repair only the one WAL tail shape journal v2 can prove was never
   * committed: complete newline-framed tx_begin/tx_chunk records followed by
   * physical EOF before tx_commit. The original complete WAL is quarantined
   * first; the active path is then replaced by the exact committed prefix.
   *
   * Partial frames, checksum failures, gaps, unknown operations, and
   * interleaving are deliberately not repairable here.
   */
  repairIncompleteTransactionTail(): IncompleteTransactionRepairResult {
    return this.withMigrationWriteGuard(() => {
      this.assertMigrationWriteAllowed();
      const scan = this.scanTransactions();
      if (scan.issue?.kind !== 'incomplete_transaction') return { repaired: false };
      const quarantinePath = this.quarantineUnlocked();
      if (!quarantinePath) {
        throw new Error('incomplete transaction WAL could not be quarantined');
      }
      const committedEnd = scan.transactions.at(-1)?.byte_end ?? 0;
      const committedPrefix = scan.raw.subarray(0, committedEnd);
      const droppedBytes = scan.raw.length - committedEnd;
      if (droppedBytes <= 0) {
        throw new Error('incomplete transaction repair found no uncommitted tail bytes');
      }

      if (committedPrefix.length === 0) {
        this.truncateUnlocked();
      } else {
        const tmp = `${this.journalPath}.repair-${process.pid}-${randomUUID()}`;
        const fd = openSync(tmp, 'w');
        try {
          writeAllSync(fd, committedPrefix);
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
        renameSync(tmp, this.journalPath);
        fsyncDirectory(dirname(this.journalPath));
      }

      const highestCommitted = scan.transactions.at(-1)?.transaction.seq ?? 0;
      const highestFrame = scan.transactions.at(-1)?.transaction.commit_frame_seq ?? 0;
      this.nextSeq = Math.max(this.appliedThroughSeq, highestCommitted);
      this.nextFrameSeq = highestFrame;
      this.lastReadIssue = undefined;
      return {
        repaired: true,
        quarantine_path: quarantinePath,
        dropped_bytes: droppedBytes,
        committed_transactions: scan.transactions.length,
      };
    });
  }

  replayTransactions(
    applier: EngineTransactionApplier,
    fromSeq: number,
    options: MutationReplayOptions = {},
  ): MutationReplayResult {
    const transactions = this.readTransactionsForReplay(fromSeq, options);
    const readIssue = this.getLastReadIssue();
    if (options.trustedContiguousCheckpoint === false && readIssue === undefined) {
      this.appliedThroughSeq = fromSeq;
    }
    let applied = 0;
    let skipped = 0;
    let failed = 0;
    let attempted = 0;
    let stoppedAtSeq: number | undefined;
    const skipped_reasons: MutationReplayResult['skipped_reasons'] = [];
    const failed_reasons: MutationReplayResult['failed_reasons'] = [];
    const issueSeq = readIssue?.actual_seq;
    const excludeIncludedIssue = readIssue?.kind === 'unknown_type'
      || (
        readIssue?.kind === 'sequence_gap'
        && readIssue.offending_record_included === true
      );
    const replayableTransactions = readIssue?.kind === 'ambiguous_checkpoint'
      ? []
      : excludeIncludedIssue && issueSeq !== undefined
        ? transactions.filter(transaction => transaction.seq < issueSeq)
        : transactions;
    const checkpointIsProven = fromSeq === 0
      || options.trustedContiguousCheckpoint !== false
      || readIssue === undefined;
    for (const transaction of replayableTransactions) {
      attempted++;
      const type = transaction.operations.length === 1
        ? transaction.operations[0]!.type
        : 'engine_transaction';
      try {
        const result = applier.applyTransaction(transaction);
        if (result.status === 'skipped') {
          skipped++;
          skipped_reasons.push({ seq: transaction.seq, type, reason: result.reason });
          stoppedAtSeq = transaction.seq;
          break;
        } else {
          applied++;
          if (checkpointIsProven) this.markApplied(transaction.seq);
        }
      } catch (err) {
        failed++;
        stoppedAtSeq = transaction.seq;
        const reason = err instanceof Error ? err.message : String(err);
        failed_reasons.push({ seq: transaction.seq, type, reason });
        // eslint-disable-next-line no-console
        console.warn(`[mutation-journal] apply failed for tx_seq=${transaction.seq} tx_id=${transaction.tx_id}: ${reason}`);
        break;
      }
    }
    const highestOnDisk = this.highestSeqOnDisk();
    const highestPhysicalFrameSeq = this.highestPhysicalFrameSeqOnDisk();
    this.nextSeq = Math.max(this.nextSeq, highestOnDisk, fromSeq);
    this.nextFrameSeq = Math.max(this.nextFrameSeq, highestPhysicalFrameSeq);
    const truncated = readIssue !== undefined;
    if (readIssue) {
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
      && attempted === transactions.length;
    return {
      read: transactions.length,
      attempted,
      applied,
      skipped,
      failed,
      truncated,
      complete,
      highest_on_disk_seq: highestOnDisk,
      highest_contiguous_applied_seq: this.appliedThroughSeq,
      highest_physical_frame_seq: highestPhysicalFrameSeq,
      frames_read: replayableTransactions.reduce(
        (count, transaction) =>
          count + (transaction.commit_frame_seq - transaction.begin_frame_seq + 1),
        0,
      ),
      committed_transactions: transactions.length,
      incomplete_transactions: readIssue?.kind === 'incomplete_transaction' ? 1 : 0,
      ...(stoppedAtSeq !== undefined ? { stopped_at_seq: stoppedAtSeq } : {}),
      ...(readIssue ? { read_issue: readIssue } : {}),
      skipped_reasons,
      failed_reasons,
    };
  }

  /**
   * Legacy per-operation replay adapter. Production recovery uses
   * replayTransactions(); this remains for primitive-journal compatibility and
   * focused tests.
   */
  replay(
    applier: MutationApplier,
    fromSeq: number,
    options: MutationReplayOptions = {},
  ): MutationReplayResult {
    return this.replayTransactions({
      applyTransaction(transaction) {
        for (const operation of transaction.operations) {
          const result = applier.apply({
            seq: transaction.seq,
            ts: transaction.ts,
            type: operation.type,
            payload: operation.payload,
            ...(transaction.source_action_id
              ? { source_action_id: transaction.source_action_id }
              : {}),
          });
          if (result.status === 'skipped') return result;
        }
        return { status: 'applied' };
      },
    }, fromSeq, options);
  }

  /** Path to the journal file. Useful for tests + diagnostics. */
  getPath(): string {
    return this.journalPath;
  }
}
