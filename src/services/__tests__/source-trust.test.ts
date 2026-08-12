import { describe, it, expect } from 'vitest';
import { claimState, sourceTrust } from '../source-trust.js';

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

  it('exploited: exploitation confirmed', () => {
    expect(claimState({ exploitable: true })).toBe('exploited');
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
