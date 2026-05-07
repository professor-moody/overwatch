// ============================================================
// Cross-Tier Correlator (Phase 3 enterprise readiness).
//
// Walks the graph and emits BACKED_BY / AUTHENTICATES_VIA edges where
// the engagement scope's `cross_tier_links` block declares an explicit
// connection between a webapp URL pattern and a cloud account / IdP.
// Without operator-supplied linkage we stay silent — the correlator
// never invents cross-tier edges that weren't declared. This keeps
// inferred reachability a faithful representation of operator intent.
// ============================================================

import type { EngineContext, ActivityLogEntry } from './engine-context.js';
import type { EdgeProperties, EdgeType, NodeProperties } from '../types.js';

interface CrossTierLink {
  url_pattern?: string;
  aws_account?: string;
  azure_subscription?: string;
  gcp_project?: string;
  cloud_resource_prefix?: string;
  idp_kind?: 'okta' | 'entra' | 'auth0' | 'ping' | 'generic_oidc' | 'generic_saml';
  tenant_id?: string;
  notes?: string;
}

export interface CrossTierCorrelatorHost {
  ctx: EngineContext;
  addEdge(source: string, target: string, props: EdgeProperties): { id: string; isNew: boolean };
  log(message: string, agentId?: string, extra?: Partial<ActivityLogEntry>): void;
}

function urlMatches(pattern: string, url: string): boolean {
  // Glob matching — same shape as scope.url_patterns. Supports * and **.
  // Strip the protocol from both sides so `*.client.com/*` matches
  // `https://app.client.com/api`. The pattern itself rarely includes the
  // scheme; if it does, we leave the scheme matching to the regex.
  const stripScheme = (s: string) => s.replace(/^[a-z]+:\/\//i, '');
  const normalizedUrl = stripScheme(url);
  const normalizedPattern = stripScheme(pattern);
  const escaped = normalizedPattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '.*')
    .replace(/\*/g, '[^/]*');
  const re = new RegExp(`^${escaped}$`, 'i');
  return re.test(normalizedUrl);
}

function arnMatchesPrefix(prefix: string, arn: string): boolean {
  const escaped = prefix
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '[^:]*');
  const re = new RegExp(`^${escaped}`, 'i');
  return re.test(arn);
}

function findWebappsMatching(ctx: EngineContext, pattern: string): Array<{ id: string; attrs: NodeProperties }> {
  const out: Array<{ id: string; attrs: NodeProperties }> = [];
  ctx.graph.forEachNode((id: string, attrs) => {
    if (attrs.type !== 'webapp') return;
    const url = (attrs.url as string | undefined) ?? attrs.label;
    if (!url) return;
    if (urlMatches(pattern, url)) out.push({ id, attrs });
  });
  return out;
}

function findCloudResourcesUnderAccount(ctx: EngineContext, link: CrossTierLink): Array<{ id: string; attrs: NodeProperties }> {
  const out: Array<{ id: string; attrs: NodeProperties }> = [];
  ctx.graph.forEachNode((id: string, attrs) => {
    if (attrs.type !== 'cloud_resource') return;
    const account = attrs.cloud_account as string | undefined;
    const arn = attrs.arn as string | undefined;
    let matchesAccount = false;
    if (link.aws_account && account === link.aws_account) matchesAccount = true;
    if (link.azure_subscription && account === link.azure_subscription) matchesAccount = true;
    if (link.gcp_project && account === link.gcp_project) matchesAccount = true;
    if (!matchesAccount && !link.cloud_resource_prefix) return;
    // F6: when the operator declared a `cloud_resource_prefix` filter,
    // refuse to match resources that don't even carry the comparable
    // identifier. Previously a cloud_resource without an ARN would
    // match anyway (the prefix check silently passed), creating false
    // BACKED_BY edges for resources that couldn't be the backend.
    if (link.cloud_resource_prefix) {
      if (!arn) return;
      if (!arnMatchesPrefix(link.cloud_resource_prefix, arn)) return;
    }
    out.push({ id, attrs });
  });
  return out;
}

function findIdpAppsForLink(ctx: EngineContext, link: CrossTierLink): Array<{ id: string; attrs: NodeProperties }> {
  if (!link.idp_kind) return [];
  const out: Array<{ id: string; attrs: NodeProperties }> = [];
  ctx.graph.forEachNode((id: string, attrs) => {
    if (attrs.type !== 'idp_application') return;
    // Find the parent idp via the TRUSTS edge or idp_id back-reference.
    const idpId = attrs.idp_id as string | undefined;
    if (!idpId || !ctx.graph.hasNode(idpId)) return;
    const idp = ctx.graph.getNodeAttributes(idpId);
    if (idp.idp_kind !== link.idp_kind) return;
    if (link.tenant_id && idp.tenant_id !== link.tenant_id) return;
    out.push({ id, attrs });
  });
  return out;
}

/**
 * Run the cross-tier correlator over the current graph. Idempotent —
 * `addEdge` dedups on (source, target, type), so repeat calls don't
 * pile up duplicates. Returns the count of edges actually created.
 */
export function runCrossTierCorrelator(host: CrossTierCorrelatorHost, agentId: string = 'cross-tier-correlator'): { backed_by_added: number; authenticates_via_added: number } {
  const links = host.ctx.config.scope.cross_tier_links ?? [];
  if (links.length === 0) return { backed_by_added: 0, authenticates_via_added: 0 };
  const now = new Date().toISOString();
  let backedBy = 0;
  let authVia = 0;

  for (const link of links) {
    if (!link.url_pattern) continue;
    const webapps = findWebappsMatching(host.ctx, link.url_pattern);
    if (webapps.length === 0) continue;

    // BACKED_BY: webapp → cloud_resource matched by cloud_resource_prefix
    // and / or the cloud account.
    if (link.aws_account || link.azure_subscription || link.gcp_project || link.cloud_resource_prefix) {
      const resources = findCloudResourcesUnderAccount(host.ctx, link);
      for (const w of webapps) {
        for (const r of resources) {
          const result = host.addEdge(w.id, r.id, {
            type: 'BACKED_BY' as EdgeType,
            confidence: 1.0,
            discovered_at: now,
            discovered_by: agentId,
            cross_tier_link_notes: link.notes,
          });
          if (result.isNew) backedBy++;
        }
      }
    }

    // AUTHENTICATES_VIA: webapp → idp_application matched by idp_kind+tenant_id.
    if (link.idp_kind) {
      const apps = findIdpAppsForLink(host.ctx, link);
      for (const w of webapps) {
        for (const a of apps) {
          const result = host.addEdge(w.id, a.id, {
            type: 'AUTHENTICATES_VIA' as EdgeType,
            confidence: 1.0,
            discovered_at: now,
            discovered_by: agentId,
            cross_tier_link_notes: link.notes,
          });
          if (result.isNew) authVia++;
        }
      }
    }
  }

  if (backedBy + authVia > 0) {
    host.log(`Cross-tier correlator: +${backedBy} BACKED_BY, +${authVia} AUTHENTICATES_VIA edges`, agentId, { category: 'inference' });
  }
  return { backed_by_added: backedBy, authenticates_via_added: authVia };
}
