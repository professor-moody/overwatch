import { describe, it, expect } from 'vitest';
import { validateEdgeEndpoints, EDGE_CONSTRAINTS } from '../graph-schema.js';
import { EDGE_TYPES } from '../../types.js';

describe('edge constraints', () => {
  it('covers all edge types except RELATED', () => {
    const constrained = new Set(Object.keys(EDGE_CONSTRAINTS));
    const unconstrained = EDGE_TYPES.filter(t => !constrained.has(t));
    // Only RELATED should be unconstrained
    expect(unconstrained).toEqual(['RELATED']);
  });

  // --- Valid combos ---
  const validCases: Array<[string, string, string]> = [
    ['REACHABLE', 'host', 'host'],
    ['RUNS', 'host', 'service'],
    ['MEMBER_OF', 'user', 'group'],
    ['MEMBER_OF_DOMAIN', 'host', 'domain'],
    ['ADMIN_TO', 'credential', 'host'],
    ['HAS_SESSION', 'user', 'host'],
    ['CAN_RDPINTO', 'user', 'host'],
    ['CAN_PSREMOTE', 'group', 'host'],
    ['VALID_ON', 'credential', 'host'],
    ['OWNS_CRED', 'user', 'credential'],
    ['CAN_DCSYNC', 'user', 'domain'],
    ['DELEGATES_TO', 'host', 'service'],
    ['WRITEABLE_BY', 'user', 'gpo'],
    ['GENERIC_ALL', 'group', 'domain'],
    ['GENERIC_WRITE', 'user', 'cert_template'],
    ['WRITE_OWNER', 'group', 'ca'],
    ['WRITE_DACL', 'user', 'domain'],
    ['ADD_MEMBER', 'user', 'group'],
    ['FORCE_CHANGE_PASSWORD', 'group', 'user'],
    ['ALLOWED_TO_ACT', 'host', 'host'],
    ['CAN_ENROLL', 'user', 'cert_template'],
    ['ESC1', 'user', 'cert_template'],
    ['ESC6', 'group', 'ca'],
    ['ESC8', 'user', 'ca'],
    ['TRUSTS', 'domain', 'domain'],
    ['SAME_DOMAIN', 'host', 'user'],
    ['AS_REP_ROASTABLE', 'user', 'domain'],
    ['KERBEROASTABLE', 'user', 'domain'],
    ['CAN_DELEGATE_TO', 'host', 'service'],
    ['CAN_READ_LAPS', 'user', 'host'],
    ['CAN_READ_LAPS', 'group', 'host'],
    ['CAN_READ_GMSA', 'user', 'user'],
    ['CAN_READ_GMSA', 'group', 'user'],
    ['RBCD_TARGET', 'host', 'host'],
    ['RBCD_TARGET', 'user', 'host'],
    ['DERIVED_FROM', 'credential', 'credential'],
    ['RELAY_TARGET', 'credential', 'host'],
    ['NULL_SESSION', 'host', 'host'],
    ['POTENTIAL_AUTH', 'credential', 'service'],
    ['PATH_TO_OBJECTIVE', 'user', 'objective'],
    ['RELATED', 'host', 'share'],
  ];

  for (const [edgeType, sourceType, targetType] of validCases) {
    it(`allows ${edgeType}: ${sourceType} → ${targetType}`, () => {
      const result = validateEdgeEndpoints(edgeType as any, sourceType as any, targetType as any, {
        source_id: 'src', target_id: 'tgt',
      });
      expect(result.valid).toBe(true);
    });
  }

  // --- Invalid combos ---
  const invalidCases: Array<[string, string, string]> = [
    ['RUNS', 'service', 'host'],
    ['MEMBER_OF', 'host', 'group'],
    ['OWNS_CRED', 'host', 'credential'],
    ['CAN_DCSYNC', 'host', 'domain'],
    ['TRUSTS', 'host', 'domain'],
    ['AS_REP_ROASTABLE', 'host', 'domain'],
    ['KERBEROASTABLE', 'group', 'domain'],
    ['NULL_SESSION', 'user', 'host'],
    ['ESC1', 'host', 'cert_template'],
    ['ALLOWED_TO_ACT', 'group', 'host'],
    ['CAN_READ_LAPS', 'host', 'host'],
    ['CAN_READ_LAPS', 'credential', 'host'],
    ['CAN_READ_GMSA', 'host', 'user'],
    ['RBCD_TARGET', 'group', 'host'],
    ['DERIVED_FROM', 'user', 'credential'],
    ['DERIVED_FROM', 'credential', 'user'],
  ];

  for (const [edgeType, sourceType, targetType] of invalidCases) {
    it(`rejects ${edgeType}: ${sourceType} → ${targetType}`, () => {
      const result = validateEdgeEndpoints(edgeType as any, sourceType as any, targetType as any, {
        source_id: 'src', target_id: 'tgt',
      });
      expect(result.valid).toBe(false);
    });
  }
});
