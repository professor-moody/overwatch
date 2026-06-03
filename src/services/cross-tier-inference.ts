// ============================================================
// Cross-tier inference rules (Phase 3 enterprise readiness).
//
// Three rules fire imperatively over the current graph state. Each is
// declarative in spirit (selector + condition → emitted edge) but uses
// full graph traversal because the patterns span node types (webapp →
// cloud_resource → cloud_identity, idp_application → cloud_identity →
// iam_role, idp → domain → credential → idp_principal).
//
// Rules implemented:
//
//   1. SSRF_REACHES_IMDS — webapp + SSRF vuln + BACKED_BY (non-IMDSv2
//      cloud_resource) → emit `webapp → CAN_REACH → cloud_resource`
//      (confidence 0.7).
//
//   2. OIDC_FEDERATION_PIVOT — idp_application ISSUES_TOKENS_FOR a
//      cloud_identity AND a captured token's audience matches the app
//      → emit `credential → ASSUMES_ROLE → cloud_identity`. Gated on
//      isCredentialUsableForAuth (Phase 3 fix F3).
//
//   3. HYBRID_IDENTITY_PIVOT — idp FEDERATES_WITH on-prem domain AND a
//      usable domain credential's username matches a federated
//      idp_principal's UPN → emit
//      `credential → VALID_FOR_IDP_PRINCIPAL → idp_principal`.
//
//   4. CI_TRUST_WILDCARD — CI/OIDC idp_application with overly broad
//      sub_claim_pattern (e.g. `repo:*`) → stamp wildcard_trust on
//      the node as a finding signal. (Phase 5 / Track B.)
//
//   5. SAML_ROUND_TRIP — captured saml_assertion credential whose
//      audience matches an idp_application → emit
//      `credential → VALID_FOR_APP → idp_application`. Confidence 0.7.
//      Symmetric counterpart to OIDC_FEDERATION_PIVOT for SAML flows.
//
//   6. MFA_BYPASS_VIA_AITM — session_cookie credential captured with
//      cred_mfa_satisfied: true (typical evilginx output) is, by
//      design, a post-MFA token. Stamp `aitm_bypass: true` on the
//      credential and link it to every idp_application it can hit
//      (matched by audience or shared idp), so reports/dashboards
//      can flag the AiTM circumstance distinctly from a normal sign-in.
//
//   7. CONSENT_ABUSE — idp_application with overly permissive scopes
//      (Mail.ReadWrite, User.ReadWrite.All, Files.ReadWrite.All, etc.)
//      AND assigned_user_count >= 10 → stamp consent_phishing_target
//      on the app with severity medium. The scope/assignment combo is
//      the recognized consent-phishing surface.
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

/**
 * S4-A2: match a captured token's `sub` claim against an idp_application's
 * `sub_claim_pattern`. Pattern semantics:
 *   - Literal `*` matches one or more characters (greedy `.+`).
 *   - All other regex metacharacters in the pattern are escaped.
 *   - Anchored at both ends.
 *
 * Examples:
 *   pattern `repo:acme/webapp:ref:refs/heads/main` + subject same → true
 *   pattern `repo:acme/*` + subject `repo:acme/api`              → true
 *   pattern `repo:acme/*` + subject `repo:other/api`             → false
 *   pattern `repo:*`      + any non-empty subject                → true
 *                          (ci_trust_wildcard flags this app separately)
 *
 * Callers should treat an undefined pattern as "no constraint" and skip
 * the check entirely (GitLab and CircleCI idp_application nodes lack a
 * stored sub_claim_pattern because those providers do not expose it in
 * the trust policy the way GitHub Actions does).
 *
 * Exported for unit testing.
 */
export function matchesSubjectPattern(credSubject: string | undefined, pattern: string | undefined): boolean {
  if (!pattern) return true;
  if (!credSubject) return false;
  const escaped = pattern
    .replace(/([.+?^${}()|[\]\\])/g, '\\$1')
    .replace(/\*/g, '.+');
  try {
    return new RegExp(`^${escaped}$`).test(credSubject);
  } catch {
    return false;
  }
}

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
    // S4-A2: subject pattern stamped on the idp_application by parsers
    // that read it from the cloud trust policy (today: github-actions-oidc).
    // Undefined means the rule does not enforce a subject constraint —
    // matches the case where the provider does not expose a pattern.
    const subPattern = app.attrs.sub_claim_pattern as string | undefined;
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
      // S4-A2: subject-claim validation. Previously the rule fired for any
      // audience-matching captured token, so a GHA OIDC app with
      // sub_claim_pattern: "repo:*" emitted ASSUMES_ROLE for tokens from
      // ANY repo. Now we require the captured sub claim to match the
      // pattern (when the app has one stamped).
      const credSubject = cred.attrs.cred_subject as string | undefined;
      if (subPattern && !matchesSubjectPattern(credSubject, subPattern)) continue;
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

// =============================================
// SAML_ROUND_TRIP
// =============================================

/**
 * For each captured SAML assertion credential whose `cred_audience`
 * matches an idp_application's audience, emit
 * `credential → VALID_FOR_APP → idp_application`. Symmetric counterpart
 * to OIDC_FEDERATION_PIVOT — SAML doesn't typically assume cloud roles
 * (that's web SSO territory), so the edge type differs.
 *
 * Gated on isCredentialUsableForAuth (assertion expiry / MFA).
 */
function samlRoundTrip(host: CrossTierInferenceHost, agentId: string): number {
  const now = new Date().toISOString();
  let added = 0;
  for (const cred of nodesByType(host.ctx, 'credential')) {
    const kind = cred.attrs.cred_material_kind as string | undefined;
    if (kind !== 'saml_assertion') continue;
    if (!isCredentialUsableForAuth(cred.attrs)) continue;
    if (isCredentialStaleOrExpired(cred.attrs)) continue;
    if (isCredentialMfaBlocked(cred.attrs)) continue;
    const credAud = cred.attrs.cred_audience as string | undefined;
    if (!credAud) continue;

    for (const app of nodesByType(host.ctx, 'idp_application')) {
      const aud = app.attrs.audience as string | undefined;
      const cid = app.attrs.client_id as string | undefined;
      if (credAud !== aud && credAud !== cid) continue;
      const result = host.addEdge(cred.id, app.id, {
        type: 'VALID_FOR_APP' as EdgeType,
        confidence: 0.7,
        discovered_at: now,
        discovered_by: agentId,
        rule: 'saml_round_trip',
        notes: `Captured SAML assertion audience matches idp_application ${aud ?? cid}`,
      });
      if (result.isNew) added++;
    }
  }
  return added;
}

// =============================================
// MFA_BYPASS_VIA_AITM
// =============================================

/**
 * A `session_cookie` credential captured with `cred_mfa_satisfied: true`
 * is, by design, a post-MFA token — operators ran an AiTM phishlet
 * (evilginx) precisely to bypass the IdP's MFA gate. The credential
 * model already lets such a cookie pass `isCredentialUsableForAuth`
 * even when `cred_mfa_required` is true, so OIDC_FEDERATION_PIVOT and
 * SAML_ROUND_TRIP fire correctly. What's missing is OPERATOR-FACING
 * SIGNAL: the report and dashboard should distinguish "this cred works
 * via AiTM bypass" from "this cred works because MFA wasn't required."
 *
 * This rule walks AiTM-captured session_cookie credentials and:
 *   - stamps `aitm_bypass: true` on the credential.
 *   - records `aitm_apps_at_risk: [...]` — every idp_application the
 *     cookie can reach (sharing the parent IdP), so reports can list
 *     the apps the bypass enables.
 *   - records the credential's `finding_severity: 'high'` so
 *     visibility tooling surfaces it.
 *
 * Idempotent — re-runs detect already-flagged credentials and skip.
 */
function mfaBypassViaAitm(host: CrossTierInferenceHost, agentId: string): number {
  let added = 0;
  for (const cred of nodesByType(host.ctx, 'credential')) {
    if (cred.attrs.aitm_bypass === true) continue;
    const kind = cred.attrs.cred_material_kind as string | undefined;
    if (kind !== 'session_cookie') continue;
    if (cred.attrs.cred_mfa_satisfied !== true) continue;

    // Find the IdP this cookie belongs to (via cred_issuer back-ref or
    // the OWNS_CRED principal's idp).
    const issuer = cred.attrs.cred_issuer as string | undefined;
    const ownerPrincipals = inbound(host.ctx, cred.id)
      .filter(e => e.attrs.type === 'OWNS_CRED')
      .map(e => host.ctx.graph.getNodeAttributes(e.source))
      .filter(p => p.type === 'idp_principal');

    // Apps at risk: idp_applications that share an idp_id with the
    // principal (or audience with the cookie). Use a set so multiple
    // owner paths don't double-count.
    const appsAtRisk = new Set<string>();
    for (const app of nodesByType(host.ctx, 'idp_application')) {
      const appIdpId = app.attrs.idp_id as string | undefined;
      const appAud = app.attrs.audience as string | undefined;
      let matches = false;
      if (issuer && (appIdpId === issuer || appAud === issuer)) matches = true;
      if (!matches) {
        for (const p of ownerPrincipals) {
          // No direct idp_id on idp_principal nodes; correlate via
          // assigned_apps when present, else fall back to issuer match
          // performed above. The id-prefix heuristic mirrors the
          // dashboard IdentityPanel's principal grouping.
          const assigned = (p.assigned_apps ?? []) as string[];
          if (assigned.includes(app.id) || assigned.includes(app.attrs.client_id as string)) {
            matches = true;
            break;
          }
        }
      }
      if (matches) appsAtRisk.add(app.id);
    }

    host.ctx.graph.mergeNodeAttributes(cred.id, {
      aitm_bypass: true,
      aitm_apps_at_risk: [...appsAtRisk],
      finding_severity: 'high',
    });
    host.log(
      `MFA bypass via AiTM: cookie ${cred.attrs.label ?? cred.id} satisfies MFA on ${appsAtRisk.size} app(s)`,
      agentId,
      { category: 'inference' },
    );
    added++;
  }
  return added;
}

// =============================================
// CONSENT_ABUSE
// =============================================

/**
 * Recognized high-privilege scope patterns across Microsoft Graph,
 * Okta, Auth0, and Google Workspace. The list is conservative — these
 * are scopes that, if granted to a malicious app via consent phishing,
 * give the attacker mailbox/file/directory write access. Dashboard /
 * report consumers can use `consent_phishing_target` to surface them.
 */
const HIGH_PRIVILEGE_SCOPE_PATTERNS = [
  // Microsoft Graph
  /^Mail\.(Send|ReadWrite)/i,
  /^Mail\.(Read|Send)\.Shared/i,
  /^Files\.(ReadWrite|FullControl)/i,
  /^User\.(ReadWrite|Manage)/i,
  /^Directory\.(ReadWrite|AccessAsUser)/i,
  /^Sites\.(FullControl|Manage)/i,
  /^Application\.ReadWrite/i,
  /^AppRoleAssignment\.ReadWrite/i,
  /^MailboxSettings\.ReadWrite/i,
  // Okta
  /^okta\.(users|apps|groups|policies|sessions)\.manage$/i,
  /^okta\.(users|apps)\.delete$/i,
  // Auth0
  /^(create|update|delete):users$/i,
  /^(create|update|delete):clients$/i,
  /^(read|update):client_grants$/i,
  // Google Workspace
  /^https:\/\/www\.googleapis\.com\/auth\/(admin|drive|gmail\.modify|gmail\.send)/i,
];

const DEFAULT_CONSENT_ASSIGNMENT_THRESHOLD = 10;

function consentAbuse(host: CrossTierInferenceHost, agentId: string, threshold = DEFAULT_CONSENT_ASSIGNMENT_THRESHOLD): number {
  let added = 0;
  for (const app of nodesByType(host.ctx, 'idp_application')) {
    if (app.attrs.consent_phishing_target === true) continue;
    const scopes = (app.attrs.app_scopes as string[] | undefined) ?? [];
    const assigned = (app.attrs.assigned_user_count as number | undefined) ?? 0;
    if (scopes.length === 0) continue;

    const matchedScopes = scopes.filter(s => HIGH_PRIVILEGE_SCOPE_PATTERNS.some(re => re.test(s)));
    if (matchedScopes.length === 0) continue;
    if (assigned < threshold) continue;

    host.ctx.graph.mergeNodeAttributes(app.id, {
      consent_phishing_target: true,
      consent_abuse_high_priv_scopes: matchedScopes,
      consent_abuse_assignment_count: assigned,
      finding_severity: app.attrs.finding_severity === 'high' ? 'high' : 'medium',
    });
    host.log(
      `Consent abuse target: ${app.attrs.label ?? app.id} grants ${matchedScopes.length} high-priv scope(s) to ${assigned} principals`,
      agentId,
      { category: 'inference' },
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
  saml_round_trip: number;
  mfa_bypass_via_aitm: number;
  consent_abuse: number;
} {
  const ssrf = ssrfReachesImds(host, agentId);
  const oidc = oidcFederationPivot(host, agentId);
  const hybrid = hybridIdentityPivot(host, agentId);
  const ciWild = ciTrustWildcard(host, agentId);
  const saml = samlRoundTrip(host, agentId);
  const aitm = mfaBypassViaAitm(host, agentId);
  const consent = consentAbuse(host, agentId);
  const total = ssrf + oidc + hybrid + ciWild + saml + aitm + consent;
  if (total > 0) {
    host.log(
      `Cross-tier inference: +${ssrf} CAN_REACH (SSRF→IMDS), +${oidc} ASSUMES_ROLE (OIDC fed), +${hybrid} VALID_FOR_IDP_PRINCIPAL (hybrid), +${ciWild} CI_TRUST_WILDCARD, +${saml} VALID_FOR_APP (SAML), +${aitm} AITM_BYPASS, +${consent} CONSENT_ABUSE`,
      agentId,
      { category: 'inference' },
    );
  }
  return {
    ssrf_reaches_imds: ssrf,
    oidc_federation_pivot: oidc,
    hybrid_identity_pivot: hybrid,
    ci_trust_wildcard: ciWild,
    saml_round_trip: saml,
    mfa_bypass_via_aitm: aitm,
    consent_abuse: consent,
  };
}
