import { describe, it, expect } from 'vitest';
import { claimState, sourceTrust, isMatureClaim, claimContradiction, attachDerivedTrust } from '../source-trust.js';
import type { ExportedGraph } from '../../types.js';

describe('sourceTrust', () => {
  it('inferred: created by an inference rule (a hypothesis), regardless of confidence', () => {
    expect(sourceTrust({ inferred_by_rule: 'smb_signing_relay', confidence: 0.5 })).toBe('inferred');
    // inferred wins even if later confirmed-looking — the rule origin is the truth here
    expect(sourceTrust({ inferred_by_rule: 'r1', confidence: 1 })).toBe('inferred');
  });

  it('observed: confirmed by confidence 1.0, a confirmed_at stamp, or a tested success', () => {
    expect(sourceTrust({ confidence: 1 })).toBe('observed');
    expect(sourceTrust({ confidence: 0.4, confirmed_at: '2026-06-30T00:00:00Z' })).toBe('observed');
    expect(sourceTrust({ confidence: 0.6, tested: true, test_result: 'success' })).toBe('observed');
  });

  it('asserted: recorded but not yet confirmed (the conservative default)', () => {
    expect(sourceTrust({ confidence: 0.5 })).toBe('asserted');                 // discovered, unconfirmed
    expect(sourceTrust({ confidence: 0.6, tested: true, test_result: 'failure' })).toBe('asserted'); // tested but failed
    expect(sourceTrust({ confidence: 0.9, tested: true, test_result: 'partial' })).toBe('asserted'); // partial ≠ confirmed
    expect(sourceTrust({})).toBe('asserted');                                  // nothing to go on → don't over-claim
  });
});

describe('claimState — how well-established a claim is (its lifecycle)', () => {
  it('refuted: tested and disproven — overrides any former standing', () => {
    expect(claimState({ tested: true, test_result: 'failure' })).toBe('refuted');
    expect(claimState({ tested: true, test_result: 'failure', confidence: 1, exploitable: true })).toBe('refuted');
  });

  it('stale: decayed — superseded identity or an expired/rotated credential', () => {
    expect(claimState({ identity_status: 'superseded', confidence: 1 })).toBe('stale');
    expect(claimState({ credential_status: 'expired' })).toBe('stale');
    expect(claimState({ credential_status: 'rotated' })).toBe('stale');
    expect(claimState({ credential_status: 'stale' })).toBe('stale');
  });

  it('exploited: a REAL exploitation signal — a confirmed EXPLOITS relationship or an explicit event', () => {
    expect(claimState({ type: 'EXPLOITS', confidence: 1 })).toBe('exploited');
    expect(claimState({ type: 'EXPLOITS', tested: true, test_result: 'success' })).toBe('exploited');
    expect(claimState({ exploited_at: '2026-01-01T00:00:00Z' })).toBe('exploited');
    expect(claimState({ exploitation_confirmed: true })).toBe('exploited');
  });

  it('the loose `exploitable` severity flag is only a candidate, never exploited', () => {
    // Parsers set `exploitable` from severity (high/critical → true); it marks a potential
    // opportunity, not proof. Conflating it with `exploited` inflated the scorecard.
    expect(claimState({ exploitable: true })).toBe('candidate');
    // An unconfirmed / inferred EXPLOITS hypothesis is likewise a candidate, not exploited.
    expect(claimState({ type: 'EXPLOITS', inferred_by_rule: 'r1', confidence: 0.7 })).toBe('candidate');
  });

  it('validated: an active tool test succeeded', () => {
    expect(claimState({ tested: true, test_result: 'success' })).toBe('validated');
  });

  it('observed: passively confirmed (confidence 1.0 or a confirmed_at stamp)', () => {
    expect(claimState({ confidence: 1 })).toBe('observed');
    expect(claimState({ confirmed_at: '2026-01-01T00:00:00Z' })).toBe('observed');
  });

  it('candidate: a rule hypothesis or an explicitly untested lead (not yet confirmed)', () => {
    expect(claimState({ inferred_by_rule: 'smb_relay', confidence: 0.5 })).toBe('candidate');
    expect(claimState({ tested: false })).toBe('candidate');
  });

  it('asserted: recorded but unconfirmed — the conservative default', () => {
    expect(claimState({})).toBe('asserted');
    expect(claimState({ confidence: 0.6 })).toBe('asserted');
  });

  it('a confirmed rule-inferred claim is observed by state, even though its origin is inferred', () => {
    // claim_state (current standing) and source_trust (origin) are deliberately distinct.
    const input = { inferred_by_rule: 'r1', confidence: 1 } as const;
    expect(claimState(input)).toBe('observed');
    expect(sourceTrust(input)).toBe('inferred');
  });
});

describe('claimState — durable operator/agent promotions (Phase 2b)', () => {
  const promo = (state: 'observed' | 'validated' | 'exploited' | 'refuted' | 'stale') =>
    ({ state, by_kind: 'operator' as const, at: '2026-01-01T00:00:00Z', reason: 'r' });

  it('a refuted promotion is authoritative — overrides a derived positive', () => {
    // confidence 1 would otherwise be observed; the operator disproved it.
    expect(claimState({ confidence: 1, claim_promotion: promo('refuted') })).toBe('refuted');
  });

  it('a stale promotion overrides a derived positive', () => {
    expect(claimState({ confidence: 1, claim_promotion: promo('stale') })).toBe('stale');
  });

  it('positive promotions set the standing when no stronger signal exists', () => {
    expect(claimState({ claim_promotion: promo('validated') })).toBe('validated');
    expect(claimState({ claim_promotion: promo('observed') })).toBe('observed');
    expect(claimState({ claim_promotion: promo('exploited') })).toBe('exploited');
  });

  it('a real exploitation signal still beats a positive validated promotion', () => {
    expect(claimState({ exploited_at: '2026-01-02T00:00:00Z', claim_promotion: promo('validated') })).toBe('exploited');
  });

  it('a refuted promotion makes the claim immature (un-satisfies objectives/paths)', () => {
    expect(isMatureClaim({ confidence: 1, claim_promotion: promo('refuted') })).toBe(false);
    expect(isMatureClaim({ claim_promotion: promo('validated') })).toBe(true);
  });

  it('a positive promotion decays to stale once its validity window has elapsed (needs `now`)', () => {
    const p = { ...promo('validated'), valid_until: '2026-06-01T00:00:00Z' };
    expect(claimState({ claim_promotion: p }, '2026-07-01T00:00:00Z')).toBe('stale');       // now > valid_until
    expect(claimState({ claim_promotion: p }, '2026-05-01T00:00:00Z')).toBe('validated');    // still within window
    expect(claimState({ claim_promotion: p })).toBe('validated');                            // no clock → no expiry
    expect(isMatureClaim({ claim_promotion: p }, '2026-07-01T00:00:00Z')).toBe(false);       // decayed → immature
  });

  it('a refuted promotion is terminal — it does not expire back to maybe-true', () => {
    const p = { ...promo('refuted'), valid_until: '2026-06-01T00:00:00Z' };
    expect(claimState({ confidence: 1, claim_promotion: p }, '2026-07-01T00:00:00Z')).toBe('refuted');
  });

  it('expiry PARSES datetimes (not string compare) and never decays on an unparseable window', () => {
    const withUntil = (valid_until: string) => ({ ...promo('validated'), valid_until });
    // valid_until at +06:00 is 2026-05-31T23:00Z — earlier than the Z `now`, so it IS expired.
    // A lexical string compare ("...05:00:00+06:00" >= "...00:00:00Z") would wrongly say no.
    expect(claimState({ claim_promotion: withUntil('2026-06-01T05:00:00+06:00') }, '2026-06-01T00:00:00Z')).toBe('stale');
    // an unparseable window never decays the claim (conservative).
    expect(claimState({ claim_promotion: withUntil('not-a-date') }, '2026-06-01T00:00:00Z')).toBe('validated');
  });
});

describe('claimContradiction — a promotion at odds with its own evidence', () => {
  const promo = (state: 'observed' | 'validated' | 'exploited' | 'refuted' | 'stale') =>
    ({ state, by_kind: 'operator' as const, at: '2026-01-01T00:00:00Z', reason: 'r' });

  it('flags a refuted promotion that the evidence positively confirms', () => {
    expect(claimContradiction({ confidence: 1, claim_promotion: promo('refuted') })).toBe('refuted_but_evidence_positive');
    expect(claimContradiction({ tested: true, test_result: 'success', claim_promotion: promo('refuted') })).toBe('refuted_but_evidence_positive');
  });

  it('flags a positive promotion that a test disproved', () => {
    expect(claimContradiction({ tested: true, test_result: 'failure', claim_promotion: promo('validated') })).toBe('promoted_positive_but_tested_failed');
  });

  it('returns null when the promotion and evidence agree, or there is no promotion', () => {
    expect(claimContradiction({ confidence: 1, claim_promotion: promo('validated') })).toBeNull();
    expect(claimContradiction({ confidence: 1 })).toBeNull();
    expect(claimContradiction({})).toBeNull();
  });
});

describe('isMatureClaim — established enough to complete an objective / route a path', () => {
  it('confirmed / verified / exploited claims are mature', () => {
    expect(isMatureClaim({ confidence: 1 })).toBe(true);                        // observed
    expect(isMatureClaim({ confirmed_at: '2026-01-01T00:00:00Z' })).toBe(true); // observed
    expect(isMatureClaim({ tested: true, test_result: 'success' })).toBe(true); // validated
    expect(isMatureClaim({ type: 'EXPLOITS', confidence: 1 })).toBe(true);      // exploited
  });

  it('a directly-recorded, non-inferred claim is mature at the confidence floor (no regression)', () => {
    expect(isMatureClaim({ confidence: 0.9 })).toBe(true);
    expect(isMatureClaim({ confidence: 0.95 })).toBe(true);
    expect(isMatureClaim({ confidence: 0.89 })).toBe(false);
  });

  it('a rule inference is NEVER mature, at any confidence below confirmation', () => {
    expect(isMatureClaim({ inferred_by_rule: 'r1', confidence: 0.95 })).toBe(false);
    expect(isMatureClaim({ inferred_by_rule: 'r1', confidence: 0.7 })).toBe(false);
    // ...but a rule-inferred claim later CONFIRMED (confidence 1) IS mature — origin doesn't taint a confirmed claim.
    expect(isMatureClaim({ inferred_by_rule: 'r1', confidence: 1 })).toBe(true);
  });

  it('a refuted or stale claim is never mature, even at high confidence (a bare 0.9 gate missed this)', () => {
    expect(isMatureClaim({ tested: true, test_result: 'failure', confidence: 1 })).toBe(false); // refuted
    expect(isMatureClaim({ credential_status: 'rotated', confidence: 1 })).toBe(false);          // stale
    expect(isMatureClaim({ identity_status: 'superseded', confidence: 1 })).toBe(false);         // stale
  });
});

describe('attachDerivedTrust', () => {
  it('re-derives claim_state / source_trust against `now`, so an elapsed validity window reads stale', () => {
    const graph = {
      nodes: [{ id: 'n1', properties: { type: 'host', confidence: 1.0, claim_promotion: { state: 'validated', by_kind: 'operator', at: '2026-07-16T00:00:00.000Z', reason: 'x', valid_until: '2026-07-16T01:00:00.000Z' } } }],
      edges: [{ id: 'e1', source: 'n1', target: 'n1', properties: { type: 'ADMIN_TO', confidence: 1.0 } }],
    } as unknown as ExportedGraph;

    const within = attachDerivedTrust(graph, '2026-07-16T00:30:00.000Z');
    expect(within.nodes[0].properties.claim_state).toBe('validated');
    expect(within.edges[0].properties.claim_state).toBe('observed'); // confidence 1.0, no promotion

    const after = attachDerivedTrust(graph, '2026-07-16T09:00:00.000Z');
    expect(after.nodes[0].properties.claim_state).toBe('stale'); // window elapsed → decayed
    expect(after.edges[0].properties.claim_state).toBe('observed');

    // The input graph is never mutated (a revision-cached base can be re-labelled repeatedly).
    expect((graph.nodes[0].properties as { claim_state?: string }).claim_state).toBeUndefined();
  });
});
