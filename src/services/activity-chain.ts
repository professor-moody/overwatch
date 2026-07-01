// ============================================================
// Overwatch — Activity Chain
// Tamper-evident hash chain over the live agent/system event stream.
// Skips ingested/inferred/thought entries so retro-imports and high-volume
// reasoning events don't break the chain.
// ============================================================

import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify, createPrivateKey, createPublicKey } from 'crypto';
import { existsSync, readFileSync } from 'fs';
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
// Checkpoints are Ed25519-signed when a signing key is configured (see
// loadCheckpointSigningKey / signCheckpoint below); otherwise the runtime emits
// unsigned checkpoints (hash-chain tamper-evidence still applies — the signature
// adds attribution / non-repudiation on top). Key management is operator-provided:
// generate a keypair (`npm run gen:checkpoint-key`), set the private key via
// OVERWATCH_CHECKPOINT_SIGNING_KEY to sign, and distribute the public key (verifiers
// set OVERWATCH_CHECKPOINT_PUBLIC_KEY). The key id is always DERIVED from the public key
// (checkpointKeyId), so signer + verifier agree without extra config. When a verifier key
// is configured, the verify tool requires EVERY checkpoint to be signed + verified — an
// unsigned run, or a checkpoint signed by an unknown/forged key, fails the attestation.
// Rotation/HSM are out of scope.

/** Bumped whenever the signed canonical form changes. A HARD break: a verifier
 *  rejects any checkpoint whose schema_version differs (no dual-path). v1 added
 *  engagement-nonce binding + domain separation to the signed bytes. */
export const CHECKPOINT_SCHEMA_VERSION = 1;
/** Domain-separation tag mixed into the signed bytes so a checkpoint signature
 *  can't be reused across a different protocol/context. */
const CHECKPOINT_DOMAIN = 'overwatch-checkpoint-v1';

export interface ChainCheckpoint {
  schema_version: number;     // canonical/signing schema version (hard-break on change)
  event_index: number;        // index in the activity log at emit time (informational; verify resolves by event_id)
  event_id: string;           // event_id at that index — the STABLE key verify binds on (survives truncation)
  event_hash: string;         // chain tail at this checkpoint
  events_since_previous: number; // chained-event count since previous checkpoint
  emitted_at: string;         // ISO timestamp when the checkpoint was emitted
  engagement_nonce: string | null; // binds the checkpoint to ONE engagement (anti-splice); null for legacy
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
  // Required: emitted_at is part of the SIGNED canonical bytes, so it must be the
  // deterministic event timestamp (never a wall-clock fallback that would make the
  // signed bytes non-reproducible).
  emitted_at: string;
  engagement_nonce?: string | null;
  signing_key_id?: string;
}): ChainCheckpoint {
  return {
    schema_version: CHECKPOINT_SCHEMA_VERSION,
    event_index: args.event_index,
    event_id: args.event_id,
    event_hash: args.event_hash,
    events_since_previous: args.events_since_previous,
    emitted_at: args.emitted_at,
    engagement_nonce: args.engagement_nonce ?? null,
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
): { valid: boolean; latest_valid_index: number; mismatches: ChainCheckpoint[]; aged_out: ChainCheckpoint[] } {
  // Resolve each checkpoint to its log entry BY event_id, not by event_index —
  // tieredTruncate reindexes the log so a stored event_index goes stale, and an
  // index-based lookup would silently validate the WRONG entry.
  const idxById = new Map<string, number>();
  log.forEach((e, i) => { if (e.event_id) idxById.set(e.event_id, i); });
  const mismatches: ChainCheckpoint[] = [];  // event PRESENT but recomputed hash differs → tamper
  const aged_out: ChainCheckpoint[] = [];    // event no longer in the window (rolled off / legacy orphan)
  let latest_valid_index = -1;
  for (const cp of checkpoints) {
    const idx = idxById.get(cp.event_id);
    if (idx === undefined) {
      // The checkpointed event isn't in the (bounded) log. NOT treated as a
      // tamper: legitimately-aged-out events have their checkpoints pruned, and
      // a malicious DROP+rehash is caught by the SUBSEQUENT checkpoints (whose
      // present event_hash then diverges) and/or verifyChain. Flagging it here
      // would false-positive on rolling-window / legacy state.
      aged_out.push(cp);
      continue;
    }
    if (log[idx].event_hash !== cp.event_hash) {
      mismatches.push(cp);
      continue;
    }
    if (idx > latest_valid_index) latest_valid_index = idx;
  }
  return { valid: mismatches.length === 0, latest_valid_index, mismatches, aged_out };
}

/** Seed for verifyChain that tolerates a truncated rolling window: adopt the
 *  first surviving chained entry's prev_hash when it isn't genesis, so the
 *  contiguous surviving sub-chain verifies instead of reporting a phantom break
 *  at the window boundary. Returns undefined for a full (genesis-anchored) log.
 *  Shared by verify_activity_chain and run_graph_health so both stay consistent. */
export function deriveChainSeed(log: ActivityLogEntry[]): { event_index: number; event_hash: string } | undefined {
  const first = log.find(e => e.event_hash !== undefined && e.prev_hash !== undefined);
  return first && first.prev_hash && first.prev_hash !== GENESIS_HASH
    ? { event_index: -1, event_hash: first.prev_hash }
    : undefined;
}

/** Attest that every checkpoint binds to THIS engagement + the current schema:
 *  a checkpoint minted for a different engagement (spliced in, same operator
 *  key) or under an older/newer schema version does not attest this run. */
export function checkpointsBindToEngagement(
  checkpoints: ChainCheckpoint[],
  engagementNonce: string | null,
): { ok: boolean; reason: string | null } {
  for (const cp of checkpoints) {
    if ((cp.schema_version ?? 0) !== CHECKPOINT_SCHEMA_VERSION) {
      return { ok: false, reason: `checkpoint schema_version ${cp.schema_version ?? 'missing'} != ${CHECKPOINT_SCHEMA_VERSION}` };
    }
    if ((cp.engagement_nonce ?? null) !== (engagementNonce ?? null)) {
      return { ok: false, reason: 'checkpoint engagement_nonce does not match this engagement (possible splice)' };
    }
  }
  return { ok: true, reason: null };
}

// ============================================================
// Ed25519 checkpoint signing (attribution / non-repudiation)
// ============================================================

/** Canonical signable bytes for a checkpoint — the tamper-bound fields plus the
 *  signing key id (so a signature can't be re-labelled to another key). Excludes
 *  `signature` itself. Stable JSON array (fixed field order) for deterministic signing. */
export function canonicalCheckpoint(cp: ChainCheckpoint): string {
  return JSON.stringify([
    CHECKPOINT_DOMAIN,
    cp.schema_version ?? null,
    cp.event_index, cp.event_id, cp.event_hash, cp.events_since_previous, cp.emitted_at,
    cp.engagement_nonce ?? null,
    cp.signing_key_id ?? null,
  ]);
}

/** Stable key id from a public key: `ed25519:<first 16 hex of sha256(spki der)>`.
 *  Lets a verifier match a checkpoint's `signing_key_id` to a known public key. */
export function checkpointKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' }) as Buffer;
  return 'ed25519:' + createHash('sha256').update(der).digest('hex').slice(0, 16);
}

export interface CheckpointKeypair { keyId: string; publicKeyPem: string; privateKeyPem: string; }

/** Generate a fresh Ed25519 keypair for checkpoint signing (PEM-encoded). */
export function generateCheckpointKeypair(): CheckpointKeypair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  return { keyId: checkpointKeyId(publicKeyPem), publicKeyPem, privateKeyPem };
}

/** Sign a checkpoint: stamps `signing_key_id` then attaches a detached base64
 *  Ed25519 `signature` over canonicalCheckpoint(). Returns a new object. */
export function signCheckpoint(cp: ChainCheckpoint, privateKeyPem: string, keyId: string): ChainCheckpoint {
  const signed: ChainCheckpoint = { ...cp, signing_key_id: keyId };
  const signature = edSign(null, Buffer.from(canonicalCheckpoint(signed)), createPrivateKey(privateKeyPem)).toString('base64');
  return { ...signed, signature };
}

/** Verify one checkpoint's Ed25519 signature against a public key. False if the
 *  checkpoint is unsigned, the key is malformed, or the signature doesn't match. */
export function verifyCheckpointSignature(cp: ChainCheckpoint, publicKeyPem: string): boolean {
  if (!cp.signature || !cp.signing_key_id) return false;
  try {
    return edVerify(null, Buffer.from(canonicalCheckpoint(cp)), createPublicKey(publicKeyPem), Buffer.from(cp.signature, 'base64'));
  } catch {
    return false;
  }
}

export interface CheckpointSignatureReport {
  total: number;
  signed: number;
  verified: number;
  failed: number[];        // event_index of checkpoints whose signature failed verification
  unverifiable: number[];  // event_index of signed checkpoints whose key id we don't have
}

/** Batch-verify checkpoint signatures against a keyring (keyId → publicKeyPem).
 *  Unsigned checkpoints are ignored; signed ones with an unknown key id are
 *  reported as `unverifiable` (not a hard failure — the hash chain still stands). */
export function verifyCheckpointSignatures(
  checkpoints: ChainCheckpoint[],
  keyring: Record<string, string>,
): CheckpointSignatureReport {
  const report: CheckpointSignatureReport = { total: checkpoints.length, signed: 0, verified: 0, failed: [], unverifiable: [] };
  for (const cp of checkpoints) {
    if (!cp.signature) continue;
    report.signed += 1;
    const pub = cp.signing_key_id ? keyring[cp.signing_key_id] : undefined;
    if (!pub) { report.unverifiable.push(cp.event_index); continue; }
    if (verifyCheckpointSignature(cp, pub)) report.verified += 1;
    else report.failed.push(cp.event_index);
  }
  return report;
}

/** STRICT attestation decision over a signature report: with a verifier key configured,
 *  EVERY checkpoint must be signed AND verified. Unsigned (signed < total), failed, or
 *  unverifiable (signed by an unknown/forged key) all fail — none may pass silently. */
export function attestCheckpointSignatures(report: CheckpointSignatureReport): { ok: boolean; reason: string | null } {
  if (report.signed !== report.total) {
    return { ok: false, reason: `${report.total - report.signed}/${report.total} checkpoint(s) unsigned` };
  }
  if (report.verified !== report.signed) {
    return { ok: false, reason: `${report.failed.length} signature(s) failed, ${report.unverifiable.length} signed by an unknown key` };
  }
  return { ok: true, reason: null };
}

/** Resolve a PEM key from a raw value: an inline PEM, a file path, or base64-encoded
 *  PEM. Returns null if it can't be resolved. */
function resolvePem(raw: string): string | null {
  try {
    if (raw.includes('-----BEGIN')) return raw;
    // base64 BEFORE file path: a base64-encoded key that happens to collide with a
    // filename in CWD must decode, not be read as a file.
    const decoded = Buffer.from(raw, 'base64').toString('utf8');
    if (decoded.includes('-----BEGIN')) return decoded;
    if (existsSync(raw)) return readFileSync(raw, 'utf8');
    return null;
  } catch {
    return null;
  }
}

/** Load the checkpoint signing key from the environment. Returns null (→ emit
 *  unsigned, never crash) when unset or malformed. Fail-open for SIGNING: a missing
 *  key means unsigned checkpoints, not a halted engine. */
export function loadCheckpointSigningKey(
  env: NodeJS.ProcessEnv = process.env,
): { privateKeyPem: string; keyId: string } | null {
  const raw = env.OVERWATCH_CHECKPOINT_SIGNING_KEY;
  if (!raw) return null;
  const pem = resolvePem(raw);
  if (!pem) return null;
  try {
    const priv = createPrivateKey(pem);
    const pub = createPublicKey(priv).export({ type: 'spki', format: 'pem' }).toString();
    // Always DERIVE the key id from the public key — so the signer and an independent
    // verifier (loadCheckpointKeyring) compute the SAME id from the same key. A
    // configurable id would let the two sides diverge and silently mis-match every
    // signature.
    return { privateKeyPem: pem, keyId: checkpointKeyId(pub) };
  } catch {
    return null;
  }
}

/** Load the verifier keyring (keyId → publicKeyPem) from the environment, deriving
 *  the key id from each public key (same derivation as the signer). Supports
 *  OVERWATCH_CHECKPOINT_PUBLIC_KEY (one key). */
export function loadCheckpointKeyring(env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const raw = env.OVERWATCH_CHECKPOINT_PUBLIC_KEY;
  if (!raw) return {};
  const pem = resolvePem(raw);
  if (!pem) return {};
  try {
    const normalized = createPublicKey(pem).export({ type: 'spki', format: 'pem' }).toString();
    return { [checkpointKeyId(normalized)]: normalized };
  } catch {
    return {};
  }
}
