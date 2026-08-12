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
  exploitable?: boolean;
  identity_status?: 'canonical' | 'unresolved' | 'superseded';
  credential_status?: 'active' | 'stale' | 'expired' | 'rotated';
}

/**
 * Classify how well-established a claim is. Precedence, highest first:
 *   refuted (disproven) → stale (decayed) → exploited → validated (actively tested)
 *   → observed (passively confirmed) → candidate (hypothesis / untested) → asserted.
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
  if (p.exploitable === true) return 'exploited';
  if (p.tested === true && p.test_result === 'success') return 'validated';
  if ((typeof p.confidence === 'number' && p.confidence >= CONFIRMED) || !!p.confirmed_at) return 'observed';
  if (p.inferred_by_rule || p.tested === false) return 'candidate';
  return 'asserted';
}
