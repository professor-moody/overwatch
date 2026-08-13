// ============================================================
// Source-trust: epistemic provenance of a graph element
// ============================================================
// Distinguishes what we OBSERVED (directly confirmed) from what we ASSERTED
// (recorded but not yet verified) from what we INFERRED (a rule's hypothesis).
// This is report honesty — a client-grade finding should say which links are
// confirmed vs. hypothesized, not present them all as equal fact.
//
// DERIVED, not stored: computed on read from existing signals (inferred_by_rule,
// confidence / confirmed, tested / test_result). No schema field, no migration,
// no backfill — and the default is the conservative one (`asserted` = "we have it
// but haven't confirmed it"), so an unclassifiable element never over-claims.

import type { ClaimState, SourceTrust } from '../types.js';

// The minimal shape we classify from — satisfied by both NodeProperties and
// EdgeProperties (extra fields are simply ignored).
export interface SourceTrustInput {
  confidence?: number;
  inferred_by_rule?: string;
  tested?: boolean;
  test_result?: 'success' | 'failure' | 'partial' | 'error';
  confirmed_at?: string;
}

const CONFIRMED = 1;

/** Classify a node/edge's epistemic provenance. Order matters:
 *  inferred (rule hypothesis) → observed (confirmed / tool-tested success) → asserted. */
export function sourceTrust(p: SourceTrustInput): SourceTrust {
  if (p.inferred_by_rule) return 'inferred';
  if ((typeof p.confidence === 'number' && p.confidence >= CONFIRMED)
    || !!p.confirmed_at
    || (p.tested === true && p.test_result === 'success')) {
    return 'observed';
  }
  return 'asserted';
}

// ============================================================
// Claim state: how well-established the claim is (its lifecycle)
// ============================================================
// Phase 1 of the claim lifecycle. Where source_trust answers "where did this come from"
// (provenance), claim_state answers "how well established is it" (candidate → … →
// validated / exploited, plus terminal refuted / stale). Both are DERIVED on read from
// signals the graph already carries — no schema field, no migration. Durable operator/
// agent promotions (validate / refute) come in a later phase; this floor is derivable.

/** Superset of SourceTrustInput adding the signals that separate the extra states. */
export interface ClaimStateInput extends SourceTrustInput {
  /** The node/edge type. An EXPLOITS edge is the graph's "we exploited it" relationship —
   *  when confirmed, it is the signal for `exploited` (not the loose `exploitable` flag). */
  type?: string;
  /** A finding was *flagged* as potentially exploitable — parsers set this loosely from
   *  severity (high/critical → true), so it means "a candidate opportunity", NOT proof of
   *  exploitation. It never promotes a claim past `candidate`. */
  exploitable?: boolean;
  /** An explicit exploitation event actually occurred (a real signal, set by a successful
   *  exploitation, not derived from severity). */
  exploited_at?: string;
  exploitation_confirmed?: boolean;
  identity_status?: 'canonical' | 'unresolved' | 'superseded';
  credential_status?: 'active' | 'stale' | 'expired' | 'rotated';
}

/**
 * Classify how well-established a claim is. Precedence, highest first:
 *   refuted (disproven) → stale (decayed) → exploited → validated (actively tested)
 *   → observed (passively confirmed) → candidate (hypothesis / untested / flagged
 *   exploitable) → asserted.
 *
 * `exploited` requires a REAL exploitation signal — an explicit exploitation event
 * (`exploited_at` / `exploitation_confirmed`) or a *confirmed* `EXPLOITS` relationship —
 * never the `exploitable` flag, which parsers derive loosely from severity and which
 * therefore only ever makes a claim a `candidate`. (Conflating the two silently inflated
 * the engagement scorecard's verified share with every high/critical severity flag.)
 *
 * A confirmed rule-inferred claim is `observed`/`validated`, not `candidate` — origin
 * (source_trust: inferred) and current standing (claim_state) are deliberately distinct.
 */
export function claimState(p: ClaimStateInput): ClaimState {
  if (p.tested === true && p.test_result === 'failure') return 'refuted';
  if (p.identity_status === 'superseded'
    || p.credential_status === 'stale'
    || p.credential_status === 'expired'
    || p.credential_status === 'rotated') {
    return 'stale';
  }
  const confirmed = (typeof p.confidence === 'number' && p.confidence >= CONFIRMED)
    || !!p.confirmed_at
    || (p.tested === true && p.test_result === 'success');
  if (!!p.exploited_at || p.exploitation_confirmed === true || (p.type === 'EXPLOITS' && confirmed)) {
    return 'exploited';
  }
  if (p.tested === true && p.test_result === 'success') return 'validated';
  if (confirmed) return 'observed';
  if (p.inferred_by_rule || p.tested === false || p.exploitable === true) return 'candidate';
  return 'asserted';
}

/** The historical "confident enough" floor for a directly-recorded observation. */
const MATURE_CONFIDENCE_FLOOR = 0.9;

/**
 * A claim is "mature" — established enough to complete an objective or to route a real
 * attack path — unless it is an unverified hypothesis or has been undermined:
 *
 *   - observed / validated / exploited → mature (confirmed or actively verified).
 *   - refuted (tested and disproven) or stale (superseded identity / rotated-expired
 *     credential) → NEVER mature. A bare `confidence >= 0.9` gate would happily complete an
 *     objective on a DISPROVEN edge or a ROTATED credential; this closes that.
 *   - a rule inference (`inferred_by_rule`) → NEVER mature, at ANY confidence. That is the
 *     core fix: an objective must not be marked achieved on something a rule merely guessed.
 *   - otherwise (a directly-recorded, non-inferred claim) → mature once it clears the
 *     historical confidence floor, so legitimately-confirmed access recorded at 0.9-0.99 is
 *     unaffected (no regression against the previous behavior).
 *
 * Replaces the bare `confidence >= 0.9` gates in objective + path evaluation, which treated
 * a rule's hypothesis — and a refuted or stale claim — the same as a validated observation.
 */
export function isMatureClaim(p: ClaimStateInput): boolean {
  const s = claimState(p);
  if (s === 'observed' || s === 'validated' || s === 'exploited') return true;
  if (s === 'refuted' || s === 'stale') return false;
  if (p.inferred_by_rule) return false; // a hypothesis is never mature, whatever its confidence
  return typeof p.confidence === 'number' && p.confidence >= MATURE_CONFIDENCE_FLOOR;
}
