// ============================================================
// okta-cli / Okta admin API JSON parser.
//
// Accepts JSON output from `okta apps list`, `okta users list`, or a
// wrapping object { apps: [...], users: [...], groups: [...] }. Each
// resource maps to identity-tier nodes:
//   - apps → idp_application
//   - users → idp_principal
//   - groups → idp_principal (with idp_principal_kind: 'group')
// The `idp` node is synthesized from the org subdomain (the part of the
// `_links` URL or the explicit `org` field).
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { idpApplicationId, idpId, idpPrincipalId } from '../parser-utils.js';

interface OktaBundle {
  org?: string;
  apps?: Array<Record<string, unknown>>;
  users?: Array<Record<string, unknown>>;
  groups?: Array<Record<string, unknown>>;
}

function deriveOktaOrg(input: Record<string, unknown> | unknown[]): string | undefined {
  // If the bundle is an array of resources, pull org from the first item's
  // `_links.self.href` if present.
  const probe = Array.isArray(input) ? input[0] : input;
  if (probe && typeof probe === 'object') {
    const links = (probe as { _links?: { self?: { href?: string } } })._links;
    const href = links?.self?.href;
    if (typeof href === 'string') {
      const m = href.match(/^https?:\/\/([^.]+)\.okta(?:preview)?\.com/i);
      if (m) return m[1];
    }
  }
  return undefined;
}

function tryParse(output: string): OktaBundle | null {
  try {
    const obj = JSON.parse(output);
    if (Array.isArray(obj) && obj.length > 0) {
      const first = obj[0] as Record<string, unknown>;
      const org = deriveOktaOrg(obj);
      if (typeof first.signOnMode === 'string' || typeof first.label === 'string') {
        return { org, apps: obj as Array<Record<string, unknown>> };
      }
      if (typeof first.profile === 'object' && first.profile && 'login' in (first.profile as object)) {
        return { org, users: obj as Array<Record<string, unknown>> };
      }
      if (typeof first.type === 'string' && first.type === 'OKTA_GROUP') {
        return { org, groups: obj as Array<Record<string, unknown>> };
      }
    }
    if (obj && typeof obj === 'object' && (Array.isArray(obj.apps) || Array.isArray(obj.users) || Array.isArray(obj.groups))) {
      return obj as OktaBundle;
    }
    return null;
  } catch {
    return null;
  }
}

export function parseOkta(output: string, agentId: string = 'okta-parser', _context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const bundle = tryParse(output);
  if (!bundle) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const org = bundle.org ?? 'unknown';
  const idpNodeId = idpId('okta', org);
  if (!seenNodes.has(idpNodeId)) {
    nodes.push({
      id: idpNodeId,
      type: 'idp',
      label: `okta:${org}`,
      idp_kind: 'okta',
      tenant_id: org,
      issuer_url: org !== 'unknown' ? `https://${org}.okta.com` : undefined,
      discovered_via: agentId,
      discovered_at: now,
      confidence: 1.0,
    });
    seenNodes.add(idpNodeId);
  }

  // --- Apps → idp_application ---
  for (const app of bundle.apps ?? []) {
    const appId = String(app.id ?? app.name ?? '');
    const displayName = String(app.label ?? app.name ?? appId);
    if (!appId) continue;
    const nodeId = idpApplicationId('okta', org, appId);
    if (seenNodes.has(nodeId)) continue;
    const settings = app.settings as { signOn?: { ssoAcsUrl?: string; audience?: string } } | undefined;
    const audience = settings?.signOn?.audience;
    const signOnMode = String(app.signOnMode ?? '');
    const grantTypes = signOnMode ? [signOnMode] : undefined;
    nodes.push({
      id: nodeId,
      type: 'idp_application',
      label: displayName,
      client_id: appId,
      app_name: displayName,
      audience,
      grant_types: grantTypes,
      idp_id: idpNodeId,
      discovered_at: now,
      confidence: 1.0,
    });
    seenNodes.add(nodeId);
    edges.push({
      source: nodeId,
      target: idpNodeId,
      properties: { type: 'TRUSTS' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });
  }

  // --- Users → idp_principal ---
  for (const user of bundle.users ?? []) {
    const profile = (user.profile ?? {}) as Record<string, unknown>;
    const upn = String(profile.login ?? profile.email ?? '');
    const oid = String(user.id ?? upn);
    if (!upn && !oid) continue;
    const nodeId = idpPrincipalId('okta', org, oid || upn);
    if (seenNodes.has(nodeId)) continue;
    const factors = user.factors as Array<{ factorType?: string }> | undefined;
    const mfaMethods = Array.isArray(factors)
      ? factors.map(f => String(f.factorType ?? '')).filter(Boolean)
      : [];
    nodes.push({
      id: nodeId,
      type: 'idp_principal',
      label: upn || oid,
      idp_user_id: oid,
      idp_principal_kind: 'user',
      upn,
      mfa_methods: mfaMethods.length > 0 ? mfaMethods : undefined,
      mfa_required: mfaMethods.length > 0 ? true : undefined,
      enabled: user.status === 'ACTIVE' ? true : user.status === 'SUSPENDED' || user.status === 'DEPROVISIONED' ? false : undefined,
      discovered_at: now,
      confidence: 1.0,
    });
    seenNodes.add(nodeId);
  }

  // --- Groups → idp_principal (kind=group) ---
  for (const group of bundle.groups ?? []) {
    const oid = String(group.id ?? group.name ?? '');
    if (!oid) continue;
    const profile = (group.profile ?? {}) as Record<string, unknown>;
    const name = String(profile.name ?? group.name ?? oid);
    const nodeId = idpPrincipalId('okta', org, oid);
    if (seenNodes.has(nodeId)) continue;
    nodes.push({
      id: nodeId,
      type: 'idp_principal',
      label: name,
      idp_user_id: oid,
      idp_principal_kind: 'group',
      discovered_at: now,
      confidence: 1.0,
    });
    seenNodes.add(nodeId);
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
