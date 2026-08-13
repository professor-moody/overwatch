import { describe, it, expect } from 'vitest';
import { claimState, sourceTrust, isMatureClaim } from '../source-trust.js';

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
