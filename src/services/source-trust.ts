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

import type { SourceTrust } from '../types.js';

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
