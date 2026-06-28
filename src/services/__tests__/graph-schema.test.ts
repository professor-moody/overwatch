import { describe, it, expect } from 'vitest';
import { validateEdgeEndpoints, EDGE_CONSTRAINTS } from '../graph-schema.js';
import { EDGE_TYPES, NODE_TYPES } from '../../types.js';
import { BUILTIN_RULES } from '../builtin-inference-rules.js';
import { subdomainId, asnId, organizationId, emailId } from '../parser-utils.js';

describe('edge constraints', () => {
  it('covers all edge types except RELATED', () => {
    const constrained = new Set(Object.keys(EDGE_CONSTRAINTS));
    const unconstrained = EDGE_TYPES.filter(t => !constrained.has(t));
    expect(unconstrained).toEqual(['RELATED']);
  });

  it('every rule-produced edge type exists in EDGE_CONSTRAINTS', () => {
    const constrained = new Set(Object.keys(EDGE_CONSTRAINTS));
    const missing: string[] = [];
    for (const rule of BUILTIN_RULES) {
      for (const prod of rule.produces) {
        if (!constrained.has(prod.edge_type) && prod.edge_type !== 'RELATED') {
          missing.push(`${rule.id} produces ${prod.edge_type}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });

  it('every rule trigger node_type exists in NODE_TYPES', () => {
    const validTypes = new Set(NODE_TYPES as readonly string[]);
    const invalid: string[] = [];
    for (const rule of BUILTIN_RULES) {
      if (rule.trigger.node_type && !validTypes.has(rule.trigger.node_type)) {
        invalid.push(`${rule.id} triggers on ${rule.trigger.node_type}`);
      }
    }
    expect(invalid).toEqual([]);
  });

  it('every rule requires_edge type exists in EDGE_TYPES', () => {
    const validEdges = new Set(EDGE_TYPES as readonly string[]);
    const invalid: string[] = [];
    for (const rule of BUILTIN_RULES) {
      if (!rule.trigger.requires_edge) continue;
      const types = Array.isArray(rule.trigger.requires_edge.type)
        ? rule.trigger.requires_edge.type
        : [rule.trigger.requires_edge.type];
      for (const t of types) {
        if (!validEdges.has(t)) {
          invalid.push(`${rule.id} requires_edge ${t}`);
        }
      }
    }
    expect(invalid).toEqual([]);
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
    ['VALID_ON', 'credential', 'service'],
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
    ['ALLOWED_TO_ACT', 'group', 'host'],
    ['CAN_ENROLL', 'user', 'cert_template'],
    ['ESC1', 'user', 'cert_template'],
    ['ESC6', 'group', 'ca'],
    ['ESC8', 'user', 'ca'],
    ['ESC12', 'user', 'ca'],
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
    ['DUMPED_FROM', 'credential', 'host'],
    ['RELAY_TARGET', 'credential', 'host'],
    ['NULL_SESSION', 'host', 'host'],
    ['POTENTIAL_AUTH', 'credential', 'service'],
    ['POTENTIAL_AUTH', 'cloud_resource', 'cloud_identity'],
    ['REACHABLE', 'cloud_identity', 'cloud_resource'],
    ['ASSUMES_ROLE', 'cloud_resource', 'cloud_identity'],
    ['PATH_TO_OBJECTIVE', 'user', 'objective'],
    ['RELATED', 'host', 'share'],
    // OSINT / external recon (Phase 2A)
    ['SUBDOMAIN_OF', 'subdomain', 'domain'],
    ['SUBDOMAIN_OF', 'subdomain', 'subdomain'],
    ['RESOLVES_TO', 'subdomain', 'host'],
    ['IN_NETBLOCK', 'host', 'asn'],
    ['OWNS_ASSET', 'organization', 'domain'],
    ['OWNS_ASSET', 'organization', 'asn'],
    ['AFFILIATED_WITH', 'email', 'organization'],
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
    ['CAN_READ_LAPS', 'host', 'host'],
    ['CAN_READ_LAPS', 'credential', 'host'],
    ['CAN_READ_GMSA', 'host', 'user'],
    ['RBCD_TARGET', 'group', 'host'],
    ['DERIVED_FROM', 'user', 'credential'],
    ['DERIVED_FROM', 'credential', 'user'],
    ['DUMPED_FROM', 'user', 'host'],
    ['DUMPED_FROM', 'credential', 'service'],
    // OSINT: OWNS_ASSET (organization-owned internet asset) must NOT accept the
    // AD `OWNS` source/target shapes — proves the two edges stay distinct.
    ['OWNS_ASSET', 'user', 'domain'],
    ['IN_NETBLOCK', 'asn', 'host'],
    ['AFFILIATED_WITH', 'organization', 'email'],
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

describe('OSINT node types + canonical ids (Phase 2A)', () => {
  it('registers the four OSINT node types', () => {
    for (const t of ['subdomain', 'asn', 'organization', 'email']) {
      expect(NODE_TYPES as readonly string[]).toContain(t);
    }
  });

  it('derives stable canonical ids (ASN reduced to digits; org normalized)', () => {
    expect(asnId('AS13335')).toBe('asn-13335');
    expect(asnId(13335)).toBe('asn-13335');
    expect(organizationId('Acme Corp')).toBe('organization-acme-corp');
  });

  it('subdomainId preserves the dot separator so hyphen vs sub-level do not collide', () => {
    expect(subdomainId('API.Example.COM')).toBe('subdomain-api.example.com');
    // The whole point: a hyphenated label and a deeper name must differ.
    expect(subdomainId('api-gw.example.com')).not.toBe(subdomainId('api.gw.example.com'));
  });

  it('emailId splits on @ so distinct mailboxes do not merge', () => {
    expect(emailId('Jane.Doe@Example.com')).toBe('email-jane-doe-at-example-com');
    // Cross-domain mailboxes that normalizeKeyPart alone would have merged:
    expect(emailId('jane.doe@example.com')).not.toBe(emailId('jane@doe.example.com'));
    // Degenerate input (no @) still yields a stable id, not a crash.
    expect(emailId('not-an-email')).toBe('email-not-an-email');
  });
});
