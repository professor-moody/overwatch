// ============================================================
// Phase 3 (enterprise readiness) — cross-tier correlator + inference.
//
// Pins the cross-tier behavior:
//   - explicit cross_tier_links → BACKED_BY / AUTHENTICATES_VIA
//   - SSRF_REACHES_IMDS rule emits CAN_REACH for non-IMDSv2 backends
//   - OIDC_FEDERATION_PIVOT rule emits ASSUMES_ROLE when an
//     idp_application has ISSUES_TOKENS_FOR a cloud_identity AND a
//     captured token's audience matches the app
//   - HYBRID_IDENTITY_PIVOT rule emits VALID_FOR_IDP_PRINCIPAL when
//     an idp federates with an on-prem domain and a domain credential
//     matches a federated principal's UPN
//   - inferFindingTier classifies cross-tier findings correctly
// ============================================================

import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { EdgeProperties, NodeProperties } from '../types.js';
import type { OverwatchGraph } from '../services/engine-context.js';
import { EngineContext } from '../services/engine-context.js';
import { runCrossTierCorrelator } from '../services/cross-tier-correlator.js';
import { runCrossTierInference } from '../services/cross-tier-inference.js';
import { inferFindingTier } from '../services/finding-classifier.js';

const now = new Date().toISOString();

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, allowSelfLoops: true, type: 'directed' }) as OverwatchGraph;
}
function addNode(graph: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  graph.addNode(id, { id, label: id, discovered_at: now, confidence: 1.0, ...props } as NodeProperties);
}
function addEdge(graph: OverwatchGraph, src: string, tgt: string, type: string, extra: Record<string, unknown> = {}): string {
  return graph.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: now, ...extra } as EdgeProperties);
}
function makeConfig(crossTierLinks?: any) {
  return {
    id: 'test-cross-tier',
    name: 'cross-tier test',
    created_at: '2026-05-07T00:00:00Z',
    scope: { cidrs: [], domains: [], exclusions: [], cross_tier_links: crossTierLinks },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  } as any;
}

function buildHost(graph: OverwatchGraph, config: any) {
  const ctx = new EngineContext(graph, config, './test-state-cross-tier.json');
  return {
    ctx,
    addEdge: (src: string, tgt: string, props: EdgeProperties) => {
      // Dedup by (src, tgt, type) like the real engine does.
      const existing = graph.edges(src, tgt).find(eid => graph.getEdgeAttributes(eid).type === props.type);
      if (existing) return { id: existing, isNew: false };
      const id = graph.addEdge(src, tgt, props);
      return { id, isNew: true };
    },
    log: () => {},
  };
}

// =============================================
// CrossTierCorrelator (explicit linkage)
// =============================================

describe('CrossTierCorrelator', () => {
  it('emits BACKED_BY when a webapp matches url_pattern + cloud_resource matches account', () => {
    const graph = makeGraph();
    addNode(graph, 'webapp-app', { type: 'webapp', url: 'https://app.client.com/api' });
    addNode(graph, 'res-lambda', { type: 'cloud_resource', cloud_account: '123456789012', resource_type: 'Lambda' });
    addNode(graph, 'res-other', { type: 'cloud_resource', cloud_account: '999999999999', resource_type: 'EC2' });
    const config = makeConfig([{ url_pattern: '*.client.com/*', aws_account: '123456789012' }]);
    const host = buildHost(graph, config);
    const r = runCrossTierCorrelator(host);
    expect(r.backed_by_added).toBe(1);
    const backed = graph.edges('webapp-app', 'res-lambda').filter(e => graph.getEdgeAttributes(e).type === 'BACKED_BY');
    expect(backed.length).toBe(1);
  });

  it('emits AUTHENTICATES_VIA when a webapp matches url_pattern + idp_application matches idp_kind+tenant', () => {
    const graph = makeGraph();
    addNode(graph, 'webapp-app', { type: 'webapp', url: 'https://auth.client.com/login' });
    addNode(graph, 'idp-okta', { type: 'idp', idp_kind: 'okta', tenant_id: 'client-prod' });
    addNode(graph, 'idp-app-1', { type: 'idp_application', client_id: 'app-okta-1', idp_id: 'idp-okta' });
    const config = makeConfig([{ url_pattern: 'auth.client.com/*', idp_kind: 'okta', tenant_id: 'client-prod' }]);
    const host = buildHost(graph, config);
    const r = runCrossTierCorrelator(host);
    expect(r.authenticates_via_added).toBe(1);
  });

  it('is idempotent — second run adds no new edges', () => {
    const graph = makeGraph();
    addNode(graph, 'webapp-app', { type: 'webapp', url: 'https://app.client.com/api' });
    addNode(graph, 'res-lambda', { type: 'cloud_resource', cloud_account: '123456789012' });
    const config = makeConfig([{ url_pattern: '*.client.com/*', aws_account: '123456789012' }]);
    const host = buildHost(graph, config);
    const r1 = runCrossTierCorrelator(host);
    const r2 = runCrossTierCorrelator(host);
    expect(r1.backed_by_added).toBe(1);
    expect(r2.backed_by_added).toBe(0);
  });
});

// =============================================
// SSRF_REACHES_IMDS
// =============================================

describe('SSRF_REACHES_IMDS', () => {
  it('emits CAN_REACH from webapp with SSRF vuln to non-IMDSv2 backing EC2', () => {
    const graph = makeGraph();
    addNode(graph, 'webapp-1', { type: 'webapp', url: 'https://app/' });
    addNode(graph, 'vuln-ssrf', { type: 'vulnerability', vuln_type: 'ssrf', label: 'SSRF in /api/fetch' });
    addNode(graph, 'res-ec2', { type: 'cloud_resource', resource_type: 'EC2', imdsv2_required: false });
    addEdge(graph, 'webapp-1', 'vuln-ssrf', 'VULNERABLE_TO');
    addEdge(graph, 'webapp-1', 'res-ec2', 'BACKED_BY');
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.ssrf_reaches_imds).toBe(1);
  });

  it('does NOT fire when IMDSv2 is required', () => {
    const graph = makeGraph();
    addNode(graph, 'webapp-1', { type: 'webapp', url: 'https://app/' });
    addNode(graph, 'vuln-ssrf', { type: 'vulnerability', vuln_type: 'ssrf' });
    addNode(graph, 'res-ec2', { type: 'cloud_resource', resource_type: 'EC2', imdsv2_required: true });
    addEdge(graph, 'webapp-1', 'vuln-ssrf', 'VULNERABLE_TO');
    addEdge(graph, 'webapp-1', 'res-ec2', 'BACKED_BY');
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.ssrf_reaches_imds).toBe(0);
  });

  it('does NOT fire when the backing resource type does not have IMDS (S3)', () => {
    const graph = makeGraph();
    addNode(graph, 'webapp-1', { type: 'webapp', url: 'https://app/' });
    addNode(graph, 'vuln-ssrf', { type: 'vulnerability', vuln_type: 'ssrf' });
    addNode(graph, 'res-s3', { type: 'cloud_resource', resource_type: 'S3' });
    addEdge(graph, 'webapp-1', 'vuln-ssrf', 'VULNERABLE_TO');
    addEdge(graph, 'webapp-1', 'res-s3', 'BACKED_BY');
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.ssrf_reaches_imds).toBe(0);
  });
});

// =============================================
// OIDC_FEDERATION_PIVOT
// =============================================

describe('OIDC_FEDERATION_PIVOT', () => {
  it('emits ASSUMES_ROLE when a captured token matches an idp_application audience', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-app', { type: 'idp_application', client_id: 'app-1', audience: 'arn:aws:iam::123:role/PowerUser' });
    addNode(graph, 'cloud-id', { type: 'cloud_identity', principal_type: 'role', arn: 'arn:aws:iam::123:role/PowerUser' });
    addEdge(graph, 'idp-app', 'cloud-id', 'ISSUES_TOKENS_FOR');
    addNode(graph, 'cred-token', {
      type: 'credential',
      cred_material_kind: 'oidc_access_token',
      cred_audience: 'arn:aws:iam::123:role/PowerUser',
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.oidc_federation_pivot).toBe(1);
    const edges = graph.edges('cred-token', 'cloud-id').filter(e => graph.getEdgeAttributes(e).type === 'ASSUMES_ROLE');
    expect(edges.length).toBe(1);
  });

  it('does NOT fire when audience mismatches', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-app', { type: 'idp_application', client_id: 'app-1', audience: 'arn:aws:iam::123:role/PowerUser' });
    addNode(graph, 'cloud-id', { type: 'cloud_identity', principal_type: 'role' });
    addEdge(graph, 'idp-app', 'cloud-id', 'ISSUES_TOKENS_FOR');
    addNode(graph, 'cred-token', {
      type: 'credential',
      cred_material_kind: 'oidc_access_token',
      cred_audience: 'arn:aws:iam::999:role/Other',
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.oidc_federation_pivot).toBe(0);
  });

  // S4-A2: subject-pattern validation
  const seedSubjectFixture = (subPattern: string | undefined, credSubject: string | undefined) => {
    const graph = makeGraph();
    addNode(graph, 'idp-app', {
      type: 'idp_application',
      client_id: 'app-1',
      audience: 'arn:aws:iam::123:role/PowerUser',
      ...(subPattern !== undefined ? { sub_claim_pattern: subPattern } : {}),
    });
    addNode(graph, 'cloud-id', { type: 'cloud_identity', principal_type: 'role', arn: 'arn:aws:iam::123:role/PowerUser' });
    addEdge(graph, 'idp-app', 'cloud-id', 'ISSUES_TOKENS_FOR');
    addNode(graph, 'cred-token', {
      type: 'credential',
      cred_material_kind: 'oidc_access_token',
      cred_audience: 'arn:aws:iam::123:role/PowerUser',
      ...(credSubject !== undefined ? { cred_subject: credSubject } : {}),
    });
    return graph;
  };

  it('S4-A2 fires when token subject matches the exact sub_claim_pattern', () => {
    const graph = seedSubjectFixture('repo:acme/webapp:ref:refs/heads/main', 'repo:acme/webapp:ref:refs/heads/main');
    const host = buildHost(graph, makeConfig());
    expect(runCrossTierInference(host).oidc_federation_pivot).toBe(1);
  });

  it('S4-A2 fires when token subject matches a `repo:owner/*` wildcard pattern', () => {
    const graph = seedSubjectFixture('repo:acme/*', 'repo:acme/webapp:ref:refs/heads/main');
    const host = buildHost(graph, makeConfig());
    expect(runCrossTierInference(host).oidc_federation_pivot).toBe(1);
  });

  it('S4-A2 fires when token subject matches a `repo:owner/repo:*` per-repo wildcard pattern', () => {
    const graph = seedSubjectFixture('repo:acme/webapp:*', 'repo:acme/webapp:ref:refs/heads/main');
    const host = buildHost(graph, makeConfig());
    expect(runCrossTierInference(host).oidc_federation_pivot).toBe(1);
  });

  it('S4-A2 does NOT fire when token subject mismatches the pattern', () => {
    const graph = seedSubjectFixture('repo:acme/api:*', 'repo:acme/webapp:ref:refs/heads/main');
    const host = buildHost(graph, makeConfig());
    expect(runCrossTierInference(host).oidc_federation_pivot).toBe(0);
  });

  it('S4-A2 still fires when no sub_claim_pattern is stamped (GitLab/CircleCI case)', () => {
    const graph = seedSubjectFixture(undefined, 'project_path:acme/webapp:ref_type:branch:ref:main');
    const host = buildHost(graph, makeConfig());
    expect(runCrossTierInference(host).oidc_federation_pivot).toBe(1);
  });

  it('S4-A2 fires for any non-empty subject under `repo:*` (intentional; ci_trust_wildcard separately flags the over-broad trust)', () => {
    const graph = seedSubjectFixture('repo:*', 'repo:random/repo:ref:refs/heads/main');
    const host = buildHost(graph, makeConfig());
    expect(runCrossTierInference(host).oidc_federation_pivot).toBe(1);
  });

  it('S4-A2 does NOT fire when pattern is stamped but token has no cred_subject', () => {
    const graph = seedSubjectFixture('repo:acme/webapp:*', undefined);
    const host = buildHost(graph, makeConfig());
    expect(runCrossTierInference(host).oidc_federation_pivot).toBe(0);
  });
});

describe('matchesSubjectPattern (S4-A2 helper unit test)', () => {
  // Exported helper unit-tested directly so the regex semantics stay pinned.
  it('treats undefined pattern as no constraint', async () => {
    const { matchesSubjectPattern } = await import('../services/cross-tier-inference.js');
    expect(matchesSubjectPattern('anything', undefined)).toBe(true);
    expect(matchesSubjectPattern(undefined, undefined)).toBe(true);
  });
  it('returns false when pattern is set and subject is missing', async () => {
    const { matchesSubjectPattern } = await import('../services/cross-tier-inference.js');
    expect(matchesSubjectPattern(undefined, 'repo:acme/webapp:*')).toBe(false);
  });
  it('escapes regex metacharacters in the pattern body', async () => {
    const { matchesSubjectPattern } = await import('../services/cross-tier-inference.js');
    // `.` is a regex metachar — must be escaped so it does not match arbitrary chars.
    expect(matchesSubjectPattern('repoXacme/webapp:ref:x', 'repo.acme/webapp:*')).toBe(false);
    expect(matchesSubjectPattern('repo.acme/webapp:ref:x', 'repo.acme/webapp:*')).toBe(true);
  });
});

// =============================================
// HYBRID_IDENTITY_PIVOT
// =============================================

describe('HYBRID_IDENTITY_PIVOT', () => {
  it('emits VALID_FOR_IDP_PRINCIPAL when a domain cred matches a federated UPN', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-entra', { type: 'idp', idp_kind: 'entra', tenant_id: 't-1' });
    addNode(graph, 'domain-acme', { type: 'domain', domain_name: 'acme.local' });
    addEdge(graph, 'idp-entra', 'domain-acme', 'FEDERATES_WITH');
    addNode(graph, 'principal-alice', { type: 'idp_principal', upn: 'alice@acme.local' });
    addNode(graph, 'cred-alice', {
      type: 'credential',
      cred_type: 'plaintext',
      cred_material_kind: 'plaintext_password',
      cred_user: 'alice',
      cred_domain: 'acme.local',
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.hybrid_identity_pivot).toBe(1);
    const edges = graph.edges('cred-alice', 'principal-alice').filter(e => graph.getEdgeAttributes(e).type === 'VALID_FOR_IDP_PRINCIPAL');
    expect(edges.length).toBe(1);
  });

  it('does NOT fire when domains differ', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-entra', { type: 'idp', idp_kind: 'entra', tenant_id: 't-1' });
    addNode(graph, 'domain-acme', { type: 'domain', domain_name: 'acme.local' });
    addEdge(graph, 'idp-entra', 'domain-acme', 'FEDERATES_WITH');
    addNode(graph, 'principal-alice', { type: 'idp_principal', upn: 'alice@acme.local' });
    addNode(graph, 'cred-alice', {
      type: 'credential',
      cred_type: 'plaintext',
      cred_material_kind: 'plaintext_password',
      cred_user: 'alice',
      cred_domain: 'other.local', // different domain
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.hybrid_identity_pivot).toBe(0);
  });
});

// =============================================
// SAML_ROUND_TRIP
// =============================================

describe('SAML_ROUND_TRIP', () => {
  it('emits VALID_FOR_APP when a SAML assertion audience matches an idp_application', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-app', { type: 'idp_application', client_id: 'sp-1', audience: 'https://sp.acme.com' });
    addNode(graph, 'cred-saml', {
      type: 'credential',
      cred_type: 'token',
      cred_material_kind: 'saml_assertion',
      cred_audience: 'https://sp.acme.com',
      cred_token_expires_at: '2099-01-01T00:00:00Z',
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.saml_round_trip).toBe(1);
    const edges = graph.edges('cred-saml', 'idp-app').filter(e => graph.getEdgeAttributes(e).type === 'VALID_FOR_APP');
    expect(edges.length).toBe(1);
  });

  it('does NOT fire when audience mismatches', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-app', { type: 'idp_application', client_id: 'sp-1', audience: 'https://sp.acme.com' });
    addNode(graph, 'cred-saml', {
      type: 'credential',
      cred_type: 'token',
      cred_material_kind: 'saml_assertion',
      cred_audience: 'https://other.example.com',
      cred_token_expires_at: '2099-01-01T00:00:00Z',
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.saml_round_trip).toBe(0);
  });

  it('does NOT fire when the assertion is expired', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-app', { type: 'idp_application', audience: 'https://sp.acme.com' });
    addNode(graph, 'cred-saml', {
      type: 'credential',
      cred_type: 'token',
      cred_material_kind: 'saml_assertion',
      cred_audience: 'https://sp.acme.com',
      cred_token_expires_at: '2020-01-01T00:00:00Z',
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.saml_round_trip).toBe(0);
  });
});

// =============================================
// MFA_BYPASS_VIA_AITM
// =============================================

describe('MFA_BYPASS_VIA_AITM', () => {
  it('flags a session_cookie with cred_mfa_satisfied=true and lists apps at risk', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-okta', { type: 'idp', idp_kind: 'okta' });
    addNode(graph, 'idp-app-1', { type: 'idp_application', client_id: 'app-1', idp_id: 'idp-okta', audience: 'idp-okta' });
    addNode(graph, 'idp-app-2', { type: 'idp_application', client_id: 'app-2', idp_id: 'idp-okta', audience: 'idp-okta' });
    addNode(graph, 'cred-cookie', {
      type: 'credential',
      cred_type: 'token',
      cred_material_kind: 'session_cookie',
      cred_mfa_required: true,
      cred_mfa_satisfied: true,
      cred_issuer: 'idp-okta',
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.mfa_bypass_via_aitm).toBe(1);
    const cred = graph.getNodeAttributes('cred-cookie');
    expect(cred.aitm_bypass).toBe(true);
    expect((cred.aitm_apps_at_risk as string[]).sort()).toEqual(['idp-app-1', 'idp-app-2']);
    expect(cred.finding_severity).toBe('high');
  });

  it('does NOT fire on a non-cookie credential', () => {
    const graph = makeGraph();
    addNode(graph, 'cred-token', {
      type: 'credential',
      cred_type: 'token',
      cred_material_kind: 'oidc_access_token',
      cred_mfa_satisfied: true,
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.mfa_bypass_via_aitm).toBe(0);
  });

  it('is idempotent — re-runs do not re-flag', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-okta', { type: 'idp', idp_kind: 'okta' });
    addNode(graph, 'idp-app-1', { type: 'idp_application', client_id: 'app-1', idp_id: 'idp-okta', audience: 'idp-okta' });
    addNode(graph, 'cred-cookie', {
      type: 'credential',
      cred_type: 'token',
      cred_material_kind: 'session_cookie',
      cred_mfa_satisfied: true,
      cred_issuer: 'idp-okta',
    });
    const host = buildHost(graph, makeConfig());
    const r1 = runCrossTierInference(host);
    const r2 = runCrossTierInference(host);
    expect(r1.mfa_bypass_via_aitm).toBe(1);
    expect(r2.mfa_bypass_via_aitm).toBe(0);
  });
});

// =============================================
// CONSENT_ABUSE
// =============================================

describe('CONSENT_ABUSE', () => {
  it('flags an idp_application with high-priv scopes + many assignments', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-app', {
      type: 'idp_application',
      app_scopes: ['Mail.ReadWrite', 'User.Read'],
      assigned_user_count: 42,
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.consent_abuse).toBe(1);
    const app = graph.getNodeAttributes('idp-app');
    expect(app.consent_phishing_target).toBe(true);
    expect(app.consent_abuse_high_priv_scopes).toContain('Mail.ReadWrite');
    expect(app.consent_abuse_assignment_count).toBe(42);
    expect(app.finding_severity).toBe('medium');
  });

  it('does NOT fire when scopes are low-privilege only', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-app', {
      type: 'idp_application',
      app_scopes: ['User.Read', 'profile', 'openid', 'email'],
      assigned_user_count: 100,
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.consent_abuse).toBe(0);
  });

  it('does NOT fire when assignment count is below threshold', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-app', {
      type: 'idp_application',
      app_scopes: ['Mail.ReadWrite'],
      assigned_user_count: 3,
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.consent_abuse).toBe(0);
  });

  it('preserves prior `high` severity rather than downgrading to medium', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-app', {
      type: 'idp_application',
      app_scopes: ['Files.ReadWrite.All'],
      assigned_user_count: 50,
      finding_severity: 'high',
    });
    const host = buildHost(graph, makeConfig());
    runCrossTierInference(host);
    expect(graph.getNodeAttributes('idp-app').finding_severity).toBe('high');
  });

  it('matches Okta admin scopes', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-app', {
      type: 'idp_application',
      app_scopes: ['okta.users.manage'],
      assigned_user_count: 25,
    });
    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.consent_abuse).toBe(1);
  });
});

// =============================================
// inferFindingTier
// =============================================

describe('inferFindingTier', () => {
  it('classifies a webapp finding as `app`', () => {
    const graph = { nodes: [{ id: 'webapp-1', properties: { type: 'webapp' as const, id: 'webapp-1', label: 'a', discovered_at: now, confidence: 1 } }], edges: [] };
    const finding: any = { id: 'f', title: 'XSS', severity: 'high', category: 'webapp', description: 'd', affected_assets: ['webapp-1'], evidence: [], remediation: '', risk_score: 7 };
    expect(inferFindingTier(finding, graph as any)).toBe('app');
  });

  it('classifies a finding spanning webapp + cloud_resource as `cross_tier`', () => {
    const graph = {
      nodes: [
        { id: 'webapp-1', properties: { type: 'webapp' as const, id: 'webapp-1', label: 'a', discovered_at: now, confidence: 1 } },
        { id: 'res-1', properties: { type: 'cloud_resource' as const, id: 'res-1', label: 'r', discovered_at: now, confidence: 1 } },
      ],
      edges: [],
    };
    const finding: any = { id: 'f', title: 'SSRF→IMDS', severity: 'critical', category: 'webapp', description: 'd', affected_assets: ['webapp-1', 'res-1'], evidence: [], remediation: '', risk_score: 9 };
    expect(inferFindingTier(finding, graph as any)).toBe('cross_tier');
  });

  it('classifies an idp finding as `identity`', () => {
    const graph = { nodes: [{ id: 'idp-1', properties: { type: 'idp' as const, id: 'idp-1', label: 'i', discovered_at: now, confidence: 1 } }], edges: [] };
    const finding: any = { id: 'f', title: 'Open enrollment', severity: 'medium', category: 'webapp', description: 'd', affected_assets: ['idp-1'], evidence: [], remediation: '', risk_score: 5 };
    expect(inferFindingTier(finding, graph as any)).toBe('identity');
  });
});
