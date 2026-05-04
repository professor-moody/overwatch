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
 * Rule (matches the plan):
 *   - provenance ∈ {agent, system}
 *   - event_type !== 'thought' (volume control: don't chain reasoning)
 * Anything else (ingested, inferred, operator-imported notes, raw thoughts)
 * is `chain_excluded: true`.
 */
export function shouldChainEntry(entry: ActivityLogEntry): boolean {
  const prov: ActivityProvenance | undefined = entry.provenance;
  if (prov !== 'agent' && prov !== 'system') return false;
  if (entry.event_type === 'thought') return false;
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
 */
export function verifyChain(log: ActivityLogEntry[]): ChainVerificationResult {
  const breaks: ChainBreak[] = [];
  let chained_count = 0;
  let excluded_count = 0;
  let lastHash = GENESIS_HASH;

  log.forEach((entry, index) => {
    const eligible = shouldChainEntry(entry);
    const marked = entry.event_hash !== undefined;

    if (!eligible) {
      excluded_count += 1;
      return;
    }

    if (!marked || !entry.event_hash || !entry.prev_hash) {
      breaks.push({ event_id: entry.event_id, index, reason: 'missing_hash' });
      // Continue from genesis-style baseline so subsequent breaks are still
      // surfaced rather than cascading silently.
      return;
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
  });

  return {
    valid: breaks.length === 0,
    chained_count,
    excluded_count,
    breaks,
  };
}
