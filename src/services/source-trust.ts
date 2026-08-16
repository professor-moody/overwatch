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

import type { ClaimState, ClaimPromotion, SourceTrust } from '../types.js';

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
// Where source_trust answers "where did this come from" (provenance), claim_state answers
// "how well established is it" (candidate → … → validated / exploited, plus terminal refuted /
// stale). It is DERIVED on read from signals the graph carries — no stored claim_state field.
// Phase 2b adds ONE durably-stored input: an explicit operator/agent `claim_promotion` that
// claimState honors above the derived signals (see below).

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
  /** A durable operator/agent promotion of this claim's standing (Phase 2b). When present it
   *  overrides the derived signals below — negative/terminal promotions authoritatively, and
   *  positive promotions as a floor a stronger real signal can still raise. */
  claim_promotion?: ClaimPromotion;
}

/**
 * Classify how well-established a claim is. Precedence, highest first:
 *   refuted (disproven) → stale (decayed) → exploited → validated (actively tested)
 *   → observed (passively confirmed) → candidate (hypothesis / untested / flagged
 *   exploitable) → asserted.
 *
 * A durable operator/agent PROMOTION (`claim_promotion`, Phase 2b) overrides the derived
 * signals: refuted / stale promotions are authoritative (an operator disproving or retiring a
 * claim wins over any derived positive), while observed / validated / exploited promotions set
 * a floor — only a *stronger* real signal (an actual exploitation) can raise past a positive
 * promotion.
 *
 * `exploited` requires a REAL exploitation signal — an explicit exploitation event
 * (`exploited_at` / `exploitation_confirmed`), an explicit exploited promotion, or a *confirmed*
 * `EXPLOITS` relationship — never the `exploitable` flag, which parsers derive loosely from
 * severity and which therefore only ever makes a claim a `candidate`. (Conflating the two
 * silently inflated the engagement scorecard's verified share with every high/critical flag.)
 *
 * A confirmed rule-inferred claim is `observed`/`validated`, not `candidate` — origin
 * (source_trust: inferred) and current standing (claim_state) are deliberately distinct.
 */
export function claimState(p: ClaimStateInput, now?: string): ClaimState {
  const promo = p.claim_promotion;
  const promoted = promo?.state;
  // A promotion whose validity window has elapsed has DECAYED: its positive standing is no
  // longer current, so the claim reads `stale` until re-validated. (A `refuted` verdict is
  // terminal — it does not expire back into "maybe true".) Only evaluated when the caller
  // supplies `now`; callers without a clock treat the promotion as non-expiring.
  const expired = !!promo?.valid_until && !!now && now >= promo.valid_until;

  // Negative / terminal — authoritative: an operator/agent saying "refuted" or "stale" wins.
  if (promoted === 'refuted' || (p.tested === true && p.test_result === 'failure')) return 'refuted';
  if (promoted === 'stale'
    || (expired && promoted !== undefined) // a positive promotion whose window elapsed has decayed
    || p.identity_status === 'superseded'
    || p.credential_status === 'stale'
    || p.credential_status === 'expired'
    || p.credential_status === 'rotated') {
    return 'stale';
  }
  // An expired promotion no longer sets a positive floor (handled as stale above; guarded here
  // so the derived signals alone decide).
  const activePromo = expired ? undefined : promoted;
  const confirmed = (typeof p.confidence === 'number' && p.confidence >= CONFIRMED)
    || !!p.confirmed_at
    || (p.tested === true && p.test_result === 'success');
  // Exploited — a real exploitation signal (or an explicit exploited promotion) beats a
  // positive validated/observed promotion.
  if (activePromo === 'exploited' || !!p.exploited_at || p.exploitation_confirmed === true
    || (p.type === 'EXPLOITS' && confirmed)) {
    return 'exploited';
  }
  // Positive promotions set a floor alongside the equivalent derived signals.
  if (activePromo === 'validated' || (p.tested === true && p.test_result === 'success')) return 'validated';
  if (activePromo === 'observed' || confirmed) return 'observed';
  if (p.inferred_by_rule || p.tested === false || p.exploitable === true) return 'candidate';
  return 'asserted';
}

/** A durable promotion conflicting with the claim's own evidence — worth an operator's
 *  attention (the promotion may be out of date or wrong). */
export type ClaimContradiction =
  /** Promoted `refuted`, yet the claim's evidence positively confirms it. */
  | 'refuted_but_evidence_positive'
  /** Promoted `observed`/`validated`/`exploited`, yet a test of it FAILED. */
  | 'promoted_positive_but_tested_failed';

/** Detect a promotion-vs-evidence contradiction. Pure, computed on read; null when the
 *  promotion and the evidence agree (or there is no promotion). */
export function claimContradiction(p: ClaimStateInput): ClaimContradiction | null {
  const promoted = p.claim_promotion?.state;
  if (!promoted) return null;
  const evidencePositive = (typeof p.confidence === 'number' && p.confidence >= CONFIRMED)
    || !!p.confirmed_at
    || (p.tested === true && p.test_result === 'success')
    || !!p.exploited_at
    || p.exploitation_confirmed === true;
  const testedFailed = p.tested === true && p.test_result === 'failure';
  if (promoted === 'refuted' && evidencePositive) return 'refuted_but_evidence_positive';
  if ((promoted === 'observed' || promoted === 'validated' || promoted === 'exploited') && testedFailed) {
    return 'promoted_positive_but_tested_failed';
  }
  return null;
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
export function isMatureClaim(p: ClaimStateInput, now?: string): boolean {
  const s = claimState(p, now);
  if (s === 'observed' || s === 'validated' || s === 'exploited') return true;
  if (s === 'refuted' || s === 'stale') return false;
  if (p.inferred_by_rule) return false; // a hypothesis is never mature, whatever its confidence
  return typeof p.confidence === 'number' && p.confidence >= MATURE_CONFIDENCE_FLOOR;
}
