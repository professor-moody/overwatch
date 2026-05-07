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
