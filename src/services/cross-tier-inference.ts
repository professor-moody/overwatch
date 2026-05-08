// ============================================================
// Cross-tier inference rules (Phase 3 enterprise readiness).
//
// Three rules fire imperatively over the current graph state. Each is
// declarative in spirit (selector + condition → emitted edge) but uses
// full graph traversal because the patterns span node types (webapp →
// cloud_resource → cloud_identity, idp_application → cloud_identity →
// iam_role, idp → domain → credential → idp_principal).
//
// Rules implemented in this pass:
//
//   1. SSRF_REACHES_IMDS — when a webapp finding has a vulnerability
//      classified as SSRF AND the webapp has BACKED_BY edges to one or
//      more cloud_resource nodes (EC2/Lambda/ECS), emit
//      `webapp → CAN_REACH → cloud_resource` for each backing
//      resource. Confidence 0.7 — this is a "you should check IMDS"
//      signal, not a confirmed exploit.
//
//   2. OIDC_FEDERATION_PIVOT — when an idp_application has
//      ISSUES_TOKENS_FOR a cloud_identity, AND there's a captured
//      credential with cred_audience matching the idp_application's
//      audience, emit `credential → ASSUMES_ROLE → cloud_identity`.
//
//   3. HYBRID_IDENTITY_PIVOT — when an idp FEDERATES_WITH an on-prem
//      domain AND a usable credential has cred_domain matching that
//      domain, AND an idp_principal exists with upn matching the
//      credential's username, emit
//      `credential → VALID_FOR_IDP_PRINCIPAL → idp_principal`.
//
// The remaining three rules in the plan (SAML_ROUND_TRIP,
// MFA_BYPASS_VIA_AITM, CONSENT_ABUSE) are intentionally deferred to a
// follow-up — the parsers (jwt-tool, evilginx, roadrecon) already shape
// their output to make those rules straightforward additions when
// operators see the need.
// ============================================================

import type { EngineContext, ActivityLogEntry } from './engine-context.js';
import type { EdgeProperties, EdgeType, NodeProperties } from '../types.js';
import { isCredentialMfaBlocked, isCredentialStaleOrExpired, isCredentialUsableForAuth, isTokenCredential } from './credential-utils.js';

export interface CrossTierInferenceHost {
  ctx: EngineContext;
  addEdge(source: string, target: string, props: EdgeProperties): { id: string; isNew: boolean };
  log(message: string, agentId?: string, extra?: Partial<ActivityLogEntry>): void;
}

function nodesByType(ctx: EngineContext, type: string): Array<{ id: string; attrs: NodeProperties }> {
  const out: Array<{ id: string; attrs: NodeProperties }> = [];
  ctx.graph.forEachNode((id: string, attrs) => {
    if (attrs.type === type) out.push({ id, attrs });
  });
  return out;
}

function outgoing(ctx: EngineContext, source: string): Array<{ edge: string; target: string; attrs: EdgeProperties }> {
  const out: Array<{ edge: string; target: string; attrs: EdgeProperties }> = [];
  for (const e of ctx.graph.outEdges(source) as string[]) {
    out.push({ edge: e, target: ctx.graph.target(e), attrs: ctx.graph.getEdgeAttributes(e) });
  }
  return out;
}

function inbound(ctx: EngineContext, target: string): Array<{ edge: string; source: string; attrs: EdgeProperties }> {
  const out: Array<{ edge: string; source: string; attrs: EdgeProperties }> = [];
  for (const e of ctx.graph.inEdges(target) as string[]) {
    out.push({ edge: e, source: ctx.graph.source(e), attrs: ctx.graph.getEdgeAttributes(e) });
  }
  return out;
}

// =============================================
// SSRF_REACHES_IMDS
// =============================================

function ssrfReachesImds(host: CrossTierInferenceHost, agentId: string): number {
  const now = new Date().toISOString();
  let added = 0;
  // Find webapp → VULNERABLE_TO → vulnerability where vuln_type indicates SSRF.
  for (const w of nodesByType(host.ctx, 'webapp')) {
    const vulns = outgoing(host.ctx, w.id)
      .filter(e => e.attrs.type === 'VULNERABLE_TO')
      .map(e => host.ctx.graph.getNodeAttributes(e.target));
    const hasSsrf = vulns.some(v => {
      const cls = (v.vuln_type as string | undefined) ?? '';
      const cve = (v.cve as string | undefined) ?? '';
      const label = ((v.label as string | undefined) ?? '').toLowerCase();
      const affected = ((v.affected_component as string | undefined) ?? '').toLowerCase();
      return /ssrf/i.test(cls) || /ssrf/i.test(cve) || /ssrf/i.test(label) || /ssrf/i.test(affected);
    });
    if (!hasSsrf) continue;
    // Find BACKED_BY edges from this webapp.
    const backings = outgoing(host.ctx, w.id).filter(e => e.attrs.type === 'BACKED_BY');
    for (const b of backings) {
      const r = host.ctx.graph.getNodeAttributes(b.target);
      if (r.type !== 'cloud_resource') continue;
      // Only emit for resources that actually have IMDS exposure.
      const resourceType = ((r.resource_type as string | undefined) ?? '').toLowerCase();
      const imdsBearing = /(ec2|lambda|ecs|eks|nodegroup|gce|compute|virtualmachine)/i.test(resourceType);
      if (!imdsBearing) continue;
      // Skip if IMDSv2 is required (the SSRF attack typically only works against v1).
      if (r.imdsv2_required === true) continue;
      const result = host.addEdge(w.id, b.target, {
        type: 'CAN_REACH' as EdgeType,
        confidence: 0.7,
        discovered_at: now,
        discovered_by: agentId,
        rule: 'ssrf_reaches_imds',
        notes: 'SSRF vulnerability + non-IMDSv2 backing — IMDS reachable via SSRF',
      });
      if (result.isNew) added++;
    }
  }
  return added;
}

// =============================================
// OIDC_FEDERATION_PIVOT
// =============================================

function oidcFederationPivot(host: CrossTierInferenceHost, agentId: string): number {
  const now = new Date().toISOString();
  let added = 0;
  for (const app of nodesByType(host.ctx, 'idp_application')) {
    // Find ISSUES_TOKENS_FOR → cloud_identity edges from this app.
    const tokenTargets = outgoing(host.ctx, app.id)
      .filter(e => e.attrs.type === 'ISSUES_TOKENS_FOR')
      .map(e => ({ id: e.target, attrs: host.ctx.graph.getNodeAttributes(e.target) }))
      .filter(t => t.attrs.type === 'cloud_identity');
    if (tokenTargets.length === 0) continue;
    // Find captured credentials with cred_audience matching this app's audience.
    const aud = app.attrs.audience as string | undefined;
    const clientId = app.attrs.client_id as string | undefined;
    if (!aud && !clientId) continue;
    for (const cred of nodesByType(host.ctx, 'credential')) {
      const credAud = cred.attrs.cred_audience as string | undefined;
      if (!credAud) continue;
      if (credAud !== aud && credAud !== clientId) continue;
      // F3: gate the pivot on the credential actually being usable. An
      // ID token, an expired access token, an MFA-blocked token, or a
      // non-token credential all fail to authenticate against the
      // federated cloud identity, so emitting ASSUMES_ROLE for them
      // points the operator at a dead pivot.
      if (!isTokenCredential(cred.attrs)) continue;
      const kind = cred.attrs.cred_material_kind as string | undefined;
      // Only access tokens / refresh-exchanged tokens / SAML / session
      // cookies can authenticate to a cloud identity. ID tokens are
      // identity assertions, not bearer credentials, and refresh tokens
      // must be exchanged before use.
      if (kind === 'oidc_id_token' || kind === 'oidc_refresh_token') continue;
      if (isCredentialStaleOrExpired(cred.attrs)) continue;
      if (isCredentialMfaBlocked(cred.attrs)) continue;
      if (!isCredentialUsableForAuth(cred.attrs)) continue;
      // Emit credential → ASSUMES_ROLE → cloud_identity for each token target.
      for (const t of tokenTargets) {
        const result = host.addEdge(cred.id, t.id, {
          type: 'ASSUMES_ROLE' as EdgeType,
          confidence: 0.75,
          discovered_at: now,
          discovered_by: agentId,
          rule: 'oidc_federation_pivot',
          notes: `Captured token for ${aud ?? clientId} → cloud identity via OIDC federation`,
        });
        if (result.isNew) added++;
      }
    }
  }
  return added;
}

// =============================================
// HYBRID_IDENTITY_PIVOT
// =============================================

function hybridIdentityPivot(host: CrossTierInferenceHost, agentId: string): number {
  const now = new Date().toISOString();
  let added = 0;
  // Find idp ↔ domain via FEDERATES_WITH (either direction).
  const federations: Array<{ idp_id: string; domain_name: string; tenant_id?: string; idp_kind?: string }> = [];
  for (const idp of nodesByType(host.ctx, 'idp')) {
    const out = outgoing(host.ctx, idp.id).filter(e => e.attrs.type === 'FEDERATES_WITH');
    const inb = inbound(host.ctx, idp.id).filter(e => e.attrs.type === 'FEDERATES_WITH');
    const peerIds = [...out.map(e => e.target), ...inb.map(e => e.source)];
    for (const peerId of peerIds) {
      const peer = host.ctx.graph.getNodeAttributes(peerId);
      if (peer.type !== 'domain') continue;
      const dn = (peer.domain_name as string | undefined) ?? peer.label;
      if (!dn) continue;
      federations.push({
        idp_id: idp.id,
        domain_name: String(dn).toLowerCase(),
        tenant_id: idp.attrs.tenant_id as string | undefined,
        idp_kind: idp.attrs.idp_kind as string | undefined,
      });
    }
  }
  if (federations.length === 0) return 0;

  // For each federation, find creds with matching cred_domain and an
  // idp_principal whose UPN starts with the cred's username.
  for (const fed of federations) {
    for (const cred of nodesByType(host.ctx, 'credential')) {
      const credDomain = ((cred.attrs.cred_domain as string | undefined) ?? '').toLowerCase();
      const credUser = (cred.attrs.cred_user as string | undefined) ?? '';
      if (!credDomain || !credUser) continue;
      if (credDomain !== fed.domain_name) continue;
      // Find idp_principal whose upn starts with the credential's username.
      const expectedUpn = `${credUser.toLowerCase()}@`;
      for (const principal of nodesByType(host.ctx, 'idp_principal')) {
        const upn = ((principal.attrs.upn as string | undefined) ?? '').toLowerCase();
        if (!upn.startsWith(expectedUpn)) continue;
        const result = host.addEdge(cred.id, principal.id, {
          type: 'VALID_FOR_IDP_PRINCIPAL' as EdgeType,
          confidence: 0.7,
          discovered_at: now,
          discovered_by: agentId,
          rule: 'hybrid_identity_pivot',
          notes: `Domain credential ${credDomain}\\${credUser} → federated idp_principal via ${fed.idp_kind ?? 'idp'} federation`,
        });
        if (result.isNew) added++;
      }
    }
  }
  return added;
}

// =============================================
// CI_TRUST_WILDCARD
// =============================================

/**
 * Detect overly-broad CI/OIDC trust patterns. A pattern is "broad"
 * when a wildcard appears outside a domain-bounded position — for
 * GitHub Actions that's `repo:*` (any repo on the planet), not
 * `repo:acme/*` (the org-bounded variant).
 *
 * Returns the count of new findings emitted. Each finding lives on
 * the idp_application node itself (annotated as `partial: false`,
 * `wildcard_trust: true`, plus a `wildcard_trust_reason` describing
 * the bad position) so downstream consumers can surface it without
 * a separate finding store.
 */
function ciTrustWildcard(host: CrossTierInferenceHost, agentId: string): number {
  let added = 0;
  for (const app of nodesByType(host.ctx, 'idp_application')) {
    const idpId = app.attrs.idp_id as string | undefined;
    if (!idpId) continue;
    const idp = host.ctx.graph.hasNode(idpId) ? host.ctx.graph.getNodeAttributes(idpId) : null;
    const idpKind = (idp?.idp_kind ?? '') as string;
    if (!/^ci_/.test(idpKind)) continue; // only CI providers
    const pattern = app.attrs.sub_claim_pattern as string | undefined;
    if (!pattern) continue;

    // GHA: pattern shape is `repo:<owner>/<repo>:ref:<...>` or
    // `repo:<owner>/<repo>:environment:<...>` or `repo:<owner>/*` (broad
    // but bounded by org) or `repo:*` (genuinely wide open).
    //
    // Bad position: any `*` that comes BEFORE the first `/` in the repo
    // segment. We extract the repo segment via the prefix `repo:` and
    // check whether a wildcard appears before the slash.
    const m = pattern.match(/^repo:([^:]*)/i);
    let reason: string | undefined;
    if (m) {
      const repoSegment = m[1];
      if (repoSegment === '*' || /^\*/.test(repoSegment)) {
        reason = 'unbounded wildcard at owner position (e.g. `repo:*`)';
      } else if (!repoSegment.includes('/')) {
        reason = 'no repo path component — claim only bounds the owner segment';
      } else {
        const ownerPart = repoSegment.split('/')[0];
        if (ownerPart.includes('*')) {
          reason = 'wildcard inside the owner segment (e.g. `repo:acme*/...`)';
        }
      }
    } else if (pattern.includes('*')) {
      // Non-`repo:` patterns (Circle / GitLab) — flag any naked wildcard.
      reason = 'wildcard outside a domain-bounded segment';
    }
    if (!reason) continue;

    if (app.attrs.wildcard_trust === true) continue; // already flagged
    host.ctx.graph.mergeNodeAttributes(app.id, {
      wildcard_trust: true,
      wildcard_trust_reason: reason,
      finding_severity: 'high',
    });
    host.log(
      `CI trust wildcard on ${app.attrs.label ?? app.id}: ${reason} (pattern: ${pattern})`,
      agentId,
      { category: 'inference', outcome: 'failure' },
    );
    added++;
  }
  return added;
}

/**
 * Run all cross-tier inference rules over the current graph. Idempotent.
 * Intended to be called after major ingests (parser output, ingest_*
 * tools) and during retrospective passes.
 */
export function runCrossTierInference(host: CrossTierInferenceHost, agentId: string = 'cross-tier-inference'): {
  ssrf_reaches_imds: number;
  oidc_federation_pivot: number;
  hybrid_identity_pivot: number;
  ci_trust_wildcard: number;
} {
  const ssrf = ssrfReachesImds(host, agentId);
  const oidc = oidcFederationPivot(host, agentId);
  const hybrid = hybridIdentityPivot(host, agentId);
  const ciWild = ciTrustWildcard(host, agentId);
  const total = ssrf + oidc + hybrid + ciWild;
  if (total > 0) {
    host.log(
      `Cross-tier inference: +${ssrf} CAN_REACH (SSRF→IMDS), +${oidc} ASSUMES_ROLE (OIDC fed), +${hybrid} VALID_FOR_IDP_PRINCIPAL (hybrid), +${ciWild} CI_TRUST_WILDCARD`,
      agentId,
      { category: 'inference' },
    );
  }
  return {
    ssrf_reaches_imds: ssrf,
    oidc_federation_pivot: oidc,
    hybrid_identity_pivot: hybrid,
    ci_trust_wildcard: ciWild,
  };
}
