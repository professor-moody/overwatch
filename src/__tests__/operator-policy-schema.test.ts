import { describe, it, expect } from 'vitest';
import { operatorPolicySchema } from '../types.js';

// T3 (compiled policies) — the OperatorPolicy schema is the contract the dashboard
// PATCHes and the engine reads. Strict parsing catches client drift (an unknown
// key, a typo'd require mode) with a 400 instead of silently storing junk.
describe('operatorPolicySchema', () => {
  it('accepts a well-formed policy', () => {
    const policy = {
      version: 1,
      approval_rules: [
        { match: { network: '10.0.0.0/8' }, require: 'approve-all' },
        { match: { host_class: 'unverified', technique: 'rdp_lateral_movement' }, require: 'approve-critical' },
      ],
      dispatch_limits: { max_per_subnet: 1, max_per_target: 2, target_facing_archetypes: ['recon_scanner'] },
    };
    expect(operatorPolicySchema.safeParse(policy).success).toBe(true);
  });

  it('accepts a minimal policy (version only)', () => {
    expect(operatorPolicySchema.safeParse({ version: 1 }).success).toBe(true);
  });

  it('requires version === 1', () => {
    expect(operatorPolicySchema.safeParse({ approval_rules: [] }).success).toBe(false);
    expect(operatorPolicySchema.safeParse({ version: 2 }).success).toBe(false);
  });

  it('rejects unknown top-level keys (strict)', () => {
    expect(operatorPolicySchema.safeParse({ version: 1, bogus: true }).success).toBe(false);
  });

  it('rejects an unknown approval-rule match key (strict)', () => {
    expect(operatorPolicySchema.safeParse({
      version: 1,
      approval_rules: [{ match: { hostclass: 'in_scope' }, require: 'approve-all' }],
    }).success).toBe(false);
  });

  it('rejects an invalid require mode and an invalid host_class', () => {
    expect(operatorPolicySchema.safeParse({ version: 1, approval_rules: [{ match: {}, require: 'maybe' }] }).success).toBe(false);
    expect(operatorPolicySchema.safeParse({ version: 1, approval_rules: [{ match: { host_class: 'sometimes' }, require: 'approve-all' }] }).success).toBe(false);
  });

  it('rejects an unknown dispatch_limits key (strict)', () => {
    expect(operatorPolicySchema.safeParse({ version: 1, dispatch_limits: { max_per_rack: 1 } }).success).toBe(false);
  });
});
