import { describe, it, expect } from 'vitest';
import { sourceTrust } from '../source-trust.js';

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
