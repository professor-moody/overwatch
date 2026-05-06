// ============================================================
// Overwatch — Activity Chain
// Tamper-evident hash chain over the live agent/system event stream.
// Skips ingested/inferred/thought entries so retro-imports and high-volume
// reasoning events don't break the chain.
// ============================================================

import { createHash } from 'crypto';
import type { ActivityLogEntry, ActivityProvenance } from './engine-context.js';

/**
 * Decide whether an event participates in the live hash chain.
 *
 * Rule:
 *   - provenance ∈ {agent, system}
 *   - event_type ∉ {'thought', 'heartbeat'} (volume control: don't chain
 *     reasoning or liveness pings; both are high-volume, low-stakes signals)
 * Anything else (ingested, inferred, operator-imported notes, raw thoughts,
 * heartbeats) is `chain_excluded: true`.
 */
export function shouldChainEntry(entry: ActivityLogEntry): boolean {
  const prov: ActivityProvenance | undefined = entry.provenance;
  if (prov !== 'agent' && prov !== 'system') return false;
  if (entry.event_type === 'thought') return false;
  if (entry.event_type === 'heartbeat') return false;
  return true;
}

/**
 * Canonical JSON for an entry, EXCLUDING the hash-chain fields themselves
 * (so `event_hash` is a function of everything except the hashes). Keys are
 * sorted recursively for stability across runs.
 */
export function canonicalizeEntry(entry: ActivityLogEntry): string {
  const copy: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(entry)) {
    if (k === 'event_hash' || k === 'prev_hash' || k === 'chain_excluded') continue;
    if (v === undefined) continue;
    copy[k] = v;
  }
  return canonicalJson(copy);
}

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
    return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
  }
  return 'null';
}

/** SHA-256 hex of the canonical (hash-free) entry plus prev_hash. */
export function computeEventHash(entry: ActivityLogEntry, prevHash: string): string {
  const canonical = canonicalizeEntry(entry);
  return createHash('sha256')
    .update(prevHash)
    .update('|')
    .update(canonical)
    .digest('hex');
}

export const GENESIS_HASH = '0'.repeat(64);

export interface ChainBreak {
  event_id: string;
  index: number;
  reason: 'prev_hash_mismatch' | 'event_hash_mismatch' | 'missing_hash';
  expected?: string;
  actual?: string;
}

export interface ChainVerificationResult {
  valid: boolean;
  chained_count: number;
  excluded_count: number;
  breaks: ChainBreak[];
}

/**
 * Walk an activity log and verify the hash chain over the chained subset.
 * Excluded entries are counted but never break the chain.
 *
 * Optional `from` parameter starts the verification from a checkpoint instead
 * of from genesis — O(events_since_checkpoint) instead of O(n). Used by the
 * dashboard / introspection surfaces that don't need to re-walk thousands of
 * historical events on every check.
 */
export function verifyChain(
  log: ActivityLogEntry[],
  from?: { event_index: number; event_hash: string },
): ChainVerificationResult {
  const breaks: ChainBreak[] = [];
  let chained_count = 0;
  let excluded_count = 0;
  let lastHash = from?.event_hash ?? GENESIS_HASH;
  const startIndex = from?.event_index !== undefined ? from.event_index + 1 : 0;

  for (let index = startIndex; index < log.length; index++) {
    const entry = log[index];
    const eligible = shouldChainEntry(entry);
    const marked = entry.event_hash !== undefined;

    if (!eligible) {
      excluded_count += 1;
      continue;
    }

    if (!marked || !entry.event_hash || !entry.prev_hash) {
      breaks.push({ event_id: entry.event_id, index, reason: 'missing_hash' });
      // Continue from genesis-style baseline so subsequent breaks are still
      // surfaced rather than cascading silently.
      continue;
    }

    if (entry.prev_hash !== lastHash) {
      breaks.push({
        event_id: entry.event_id,
        index,
        reason: 'prev_hash_mismatch',
        expected: lastHash,
        actual: entry.prev_hash,
      });
    }

    const recomputed = computeEventHash(entry, entry.prev_hash);
    if (recomputed !== entry.event_hash) {
      breaks.push({
        event_id: entry.event_id,
        index,
        reason: 'event_hash_mismatch',
        expected: recomputed,
        actual: entry.event_hash,
      });
    }

    lastHash = entry.event_hash;
    chained_count += 1;
  }

  return {
    valid: breaks.length === 0,
    chained_count,
    excluded_count,
    breaks,
  };
}

// ============================================================
// Phase 0.2: Signed Checkpoints
// ============================================================
//
// A checkpoint is a snapshot of the chain tail at a particular event index.
// Verifiers can walk *forward* from a checkpoint instead of replaying the
// entire log from genesis — useful for dashboards and incremental audit.
//
// Signing slot is reserved (`signature` + `signing_key_id`) but actual key
// management is out of scope for this pass; the runtime emits unsigned
// checkpoints today and signed ones become a flag-flip later.

export interface ChainCheckpoint {
  event_index: number;        // index in the activity log of the checkpointed event
  event_id: string;           // event_id at that index (for cross-validation)
  event_hash: string;         // chain tail at this checkpoint
  events_since_previous: number; // chained-event count since previous checkpoint
  emitted_at: string;         // ISO timestamp when the checkpoint was emitted
  signing_key_id?: string;    // identifier of the signing key (when signed)
  signature?: string;         // base64 detached signature over canonical(checkpoint)
}

export interface CheckpointEmitOptions {
  /** Emit a new checkpoint after every N chained events. Default 500. */
  every_events?: number;
  /** Emit a new checkpoint after at most M minutes since the last one. Default 30. */
  every_minutes?: number;
}

const DEFAULT_CHECKPOINT_EVERY_EVENTS = 500;
const DEFAULT_CHECKPOINT_EVERY_MINUTES = 30;

/**
 * Decide whether a new checkpoint should be emitted given the current state
 * of the chain and the previous checkpoint (if any). Pure function so the
 * caller (engine-context) controls timing.
 */
export function shouldEmitCheckpoint(
  state: {
    chained_events_since_previous: number;
    seconds_since_previous_checkpoint: number;
    has_previous_checkpoint: boolean;
  },
  options: CheckpointEmitOptions = {},
): boolean {
  const everyEvents = options.every_events ?? DEFAULT_CHECKPOINT_EVERY_EVENTS;
  const everyMinutes = options.every_minutes ?? DEFAULT_CHECKPOINT_EVERY_MINUTES;
  // Always emit the very first checkpoint as soon as we have any chained
  // events; this gives the verifier a starting point that isn't genesis.
  if (!state.has_previous_checkpoint && state.chained_events_since_previous > 0) {
    return true;
  }
  if (state.chained_events_since_previous >= everyEvents) return true;
  if (state.seconds_since_previous_checkpoint >= everyMinutes * 60) return true;
  return false;
}

/**
 * Build a checkpoint record for the chain tail. Caller passes the index +
 * tail-state; this function just packages it (and stamps `emitted_at`).
 */
export function buildCheckpoint(args: {
  event_index: number;
  event_id: string;
  event_hash: string;
  events_since_previous: number;
  emitted_at?: string;
  signing_key_id?: string;
}): ChainCheckpoint {
  return {
    event_index: args.event_index,
    event_id: args.event_id,
    event_hash: args.event_hash,
    events_since_previous: args.events_since_previous,
    emitted_at: args.emitted_at ?? new Date().toISOString(),
    ...(args.signing_key_id ? { signing_key_id: args.signing_key_id } : {}),
  };
}

/**
 * Verify the chain against a list of checkpoints. Each checkpoint must
 * (a) reference a chained event and (b) match the recomputed chain tail at
 * that index. Returns the index of the latest valid checkpoint so callers
 * can cheaply resume verification from there.
 */
export function verifyCheckpoints(
  log: ActivityLogEntry[],
  checkpoints: ChainCheckpoint[],
): { valid: boolean; latest_valid_index: number; mismatches: ChainCheckpoint[] } {
  const mismatches: ChainCheckpoint[] = [];
  let latest_valid_index = -1;
  for (const cp of checkpoints) {
    const entry = log[cp.event_index];
    if (!entry || entry.event_id !== cp.event_id || entry.event_hash !== cp.event_hash) {
      mismatches.push(cp);
      continue;
    }
    if (cp.event_index > latest_valid_index) latest_valid_index = cp.event_index;
  }
  return { valid: mismatches.length === 0, latest_valid_index, mismatches };
}
