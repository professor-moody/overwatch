// ============================================================
// Overwatch — Deterministic IDs (P1.2)
//
// When an engagement has `engagement_nonce` populated, action IDs and
// event IDs are derived from sha256(nonce | agent_id | timestamp |
// command_signature | sequence) instead of uuidv4(). The same inputs
// always produce the same ID, which makes engagements byte-reproducible
// from a recorded JSON-RPC tape — the foundation for golden-master tests
// and audit reproducibility.
//
// Backward compat: callers pass an optional `engagement_nonce`. If absent,
// the dispatcher returns null and the caller falls back to uuidv4. This
// keeps legacy engagements (no nonce) running on UUIDs forever; strict
// migration per the approved plan.
//
// Design notes:
//   * Output is prefixed `act_` / `evt_` so it's visually distinct from
//     uuidv4 in logs and telemetry.
//   * Length is 16 hex chars after prefix — collision probability per
//     engagement is ~2^-64 even at billions of actions, plenty for our
//     purposes. We don't ship full 64-char digests because action_ids end
//     up in URLs, log files, and human-facing surfaces.
//   * Sequence numbers are caller-managed (engine-context owns the
//     monotonic counter). The dispatcher itself is pure.
// ============================================================

import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';

export interface DeterministicIdInputs {
  engagement_nonce: string;
  /** Agent that originated the action. Required so two agents in the same
   * engagement can act at the same instant without colliding. */
  agent_id?: string;
  /** ISO timestamp of the action's recording moment. Caller-provided so
   * two replays of the same wire-frame produce identical IDs. */
  timestamp: string;
  /** A stable signature of the command being recorded — for run_bash this
   * is `command_string`; for parse_output it's the parser name + first
   * 256 bytes of input; for register_agent it's `agent_id|frontier_item_id`. */
  command_signature: string;
  /** Per-engagement monotonic counter. Caller is responsible for
   * incrementing on each call. */
  sequence: number;
}

const ID_HEX_LEN = 16;

function digest(prefix: string, inputs: DeterministicIdInputs): string {
  const h = createHash('sha256')
    .update(inputs.engagement_nonce)
    .update('|')
    .update(inputs.agent_id ?? '')
    .update('|')
    .update(inputs.timestamp)
    .update('|')
    .update(inputs.command_signature)
    .update('|')
    .update(String(inputs.sequence))
    .digest('hex');
  return `${prefix}_${h.slice(0, ID_HEX_LEN)}`;
}

/**
 * Compute a deterministic action_id. Returns the `act_…` form when a
 * nonce is provided, otherwise null — caller should fall back to uuidv4.
 */
export function deterministicActionId(
  inputs: DeterministicIdInputs | null | undefined,
): string | null {
  if (!inputs?.engagement_nonce) return null;
  return digest('act', inputs);
}

/**
 * Compute a deterministic event_id. Same dispatcher pattern; pass through
 * to a different prefix so action_id and event_id can't collide on a
 * shared sequence number.
 */
export function deterministicEventId(
  inputs: DeterministicIdInputs | null | undefined,
): string | null {
  if (!inputs?.engagement_nonce) return null;
  return digest('evt', inputs);
}

/**
 * Convenience: pick deterministic when nonce is present, fall back to
 * uuidv4 otherwise. The callers that already check `if (action_id) keep`
 * can stay shape-compatible.
 */
export function actionIdOrUuid(inputs: DeterministicIdInputs | null | undefined): string {
  return deterministicActionId(inputs) ?? uuidv4();
}

export function eventIdOrUuid(inputs: DeterministicIdInputs | null | undefined): string {
  return deterministicEventId(inputs) ?? uuidv4();
}
