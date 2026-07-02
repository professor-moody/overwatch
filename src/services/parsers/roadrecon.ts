// ============================================================
// roadrecon parser — Entra ID / Azure AD enumeration.
//
// roadrecon writes a SQLite or JSON dump of tenant artifacts. Operators
// commonly export to JSON via `roadrecon dump --format json` and feed
// the resulting `users.json`, `applications.json`, `tenant.json`,
// `serviceprincipals.json`, `conditionalaccess.json` here.
//
// We accept either a single JSON file or a wrapping object whose keys
// name the resource type ({ users: [...], applications: [...], ... }).
//
// Emits:
//   - `idp` (Entra) from tenant info.
//   - `idp_application[]` from `applications` and `serviceprincipals`.
//   - `idp_principal[]` from `users`.
//   - ASSIGNED_TO_APP edges from app role assignments.
//   - MFA_REQUIRED_FOR edges from conditional access policies that
//     enforce MFA on specific apps/users.
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { idpId, idpApplicationId, idpPrincipalId } from '../parser-utils.js';

interface RoadreconBundle {
  tenant?: { tenantId?: string; displayName?: string; verifiedDomains?: Array<{ name?: string }> };
  users?: Array<Record<string, unknown>>;
  applications?: Array<Record<string, unknown>>;
  serviceprincipals?: Array<Record<string, unknown>>;
  conditionalaccess?: Array<Record<string, unknown>>;
  groups?: Array<Record<string, unknown>>;
}

function tryParseBundle(output: string): RoadreconBundle | null {
  try {
    const obj = JSON.parse(output);
    if (!obj || typeof obj !== 'object') return null;
    // Wrapping object form
    if (Array.isArray(obj.users) || Array.isArray(obj.applications) || Array.isArray(obj.serviceprincipals) || obj.tenant) {
      return obj as RoadreconBundle;
    }
    // Single-resource form: heuristic key check on first element.
    if (Array.isArray(obj) && obj.length > 0) {
      const first = obj[0] as Record<string, unknown>;
      if (typeof first.userPrincipalName === 'string') return { users: obj as Array<Record<string, unknown>> };
      if (typeof first.appId === 'string' && typeof first.displayName === 'string') return { applications: obj as Array<Record<string, unknown>> };
      if (typeof first.servicePrincipalType === 'string') return { serviceprincipals: obj as Array<Record<string, unknown>> };
    }
    return null;
  } catch {
    return null;
  }
}

export function parseRoadrecon(output: string, agentId: string = 'roadrecon-parser', _context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const bundle = tryParseBundle(output);
  if (!bundle) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // --- Tenant → idp node ---
  const tenantId = bundle.tenant?.tenantId ?? '';
  const tenantName = bundle.tenant?.displayName ?? tenantId;
  const verifiedDomain = bundle.tenant?.verifiedDomains?.find(d => typeof d.name === 'string')?.name;
  const idpNodeId = idpId('entra', tenantId || tenantName || 'unknown');
  if (!seenNodes.has(idpNodeId) && (tenantId || tenantName)) {
    nodes.push({
      id: idpNodeId,
      type: 'idp',
      label: `entra:${tenantName || tenantId}`,
      idp_kind: 'entra',
      tenant_id: tenantId,
      issuer_url: tenantId ? `https://login.microsoftonline.com/${tenantId}/v2.0` : undefined,
      discovered_via: agentId,
      discovered_at: now,
      confidence: 1.0,
      ...(verifiedDomain ? { domain_name: verifiedDomain } : {}),
    });
    seenNodes.add(idpNodeId);
  }

  // --- Applications → idp_application ---
  for (const app of bundle.applications ?? []) {
    const appId = String(app.appId ?? app.id ?? '');
    const displayName = String(app.displayName ?? appId);
    if (!appId) continue;
    const nodeId = idpApplicationId('entra', tenantId || 'unknown', appId);
    if (seenNodes.has(nodeId)) continue;
    const grantTypes: string[] = Array.isArray(app.grantTypes)
      ? (app.grantTypes as unknown[]).map(String)
      : [];
    const audience = String(app.audience ?? app.signInAudience ?? '');
    nodes.push({
      id: nodeId,
      type: 'idp_application',
      label: displayName,
      client_id: appId,
      app_name: displayName,
      grant_types: grantTypes.length > 0 ? grantTypes : undefined,
      audience: audience || undefined,
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

  // --- Service principals → idp_application (separate kind, but same node type
  // with idp_principal_kind === 'service_principal') ---
  for (const sp of bundle.serviceprincipals ?? []) {
    const appId = String(sp.appId ?? sp.servicePrincipalId ?? sp.id ?? '');
    const displayName = String(sp.displayName ?? appId);
    if (!appId) continue;
    const nodeId = idpApplicationId('entra', tenantId || 'unknown', appId);
    if (seenNodes.has(nodeId)) continue;
    nodes.push({
      id: nodeId,
      type: 'idp_application',
      label: displayName,
      client_id: appId,
      app_name: displayName,
      idp_id: idpNodeId,
      discovered_at: now,
      confidence: 1.0,
    });
    seenNodes.add(nodeId);
  }

  // --- Users → idp_principal ---
  for (const user of bundle.users ?? []) {
    const upn = String(user.userPrincipalName ?? user.mail ?? '');
    const oid = String(user.objectId ?? user.id ?? upn);
    if (!upn && !oid) continue;
    const nodeId = idpPrincipalId('entra', tenantId || 'unknown', oid || upn);
    if (seenNodes.has(nodeId)) continue;
    const mfaMethods: string[] = Array.isArray(user.strongAuthenticationMethods)
      ? (user.strongAuthenticationMethods as Array<{ methodType?: string }>).map(m => String(m.methodType ?? '')).filter(Boolean)
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
      enabled: typeof user.accountEnabled === 'boolean' ? Boolean(user.accountEnabled) : undefined,
      discovered_at: now,
      confidence: 1.0,
    });
    seenNodes.add(nodeId);
  }

  // --- Conditional access → MFA_REQUIRED_FOR edges (best-effort) ---
  // F7: handle `includeApplications: ['All']` as tenant-wide MFA. Previously
  // the loop skipped 'All' as a sentinel, leaving every app appearing
  // MFA-free even though the tenant policy required MFA for every app.
  // We expand 'All' to the set of idp_applications we know about in this
  // bundle and emit a self-loop MFA_REQUIRED_FOR per app, plus stamp
  // app_mfa_required: true on each app node so dashboards / inference
  // see the gate.
  for (const ca of bundle.conditionalaccess ?? []) {
    const grantControls = ca.grantControls as { builtInControls?: unknown[] } | undefined;
    const requiresMfa =
      Array.isArray(grantControls?.builtInControls) &&
      grantControls!.builtInControls.some(v => String(v).toLowerCase() === 'mfa');
    if (!requiresMfa) continue;
    const conditions = ca.conditions as { applications?: { includeApplications?: unknown[]; excludeApplications?: unknown[] } } | undefined;
    const rawAppIds = (conditions?.applications?.includeApplications ?? []) as unknown[];
    const appIds = rawAppIds.map(v => String(v));
    const policyLabel = String(ca.displayName ?? ca.id ?? '');
    const isOrgWide = appIds.some(aid => aid === 'All');

    // Apps the policy explicitly carves out must NOT be stamped MFA-required,
    // even under an `All` include — otherwise an excluded app looks gated when
    // the policy deliberately exempts it.
    const excludeAppIds = (conditions?.applications?.excludeApplications ?? []) as unknown[];
    const excludedNodeIds = new Set(
      excludeAppIds
        .map(v => String(v))
        .filter(aid => aid !== 'All' && aid !== 'None')
        .map(aid => idpApplicationId('entra', tenantId || 'unknown', aid)),
    );

    // Resolve the target set:
    //  - `All` → every idp_application emitted earlier in this bundle
    //  - otherwise → each named app id, looked up in seenNodes.
    // Then subtract any excluded apps.
    const targetAppNodeIds: string[] = (isOrgWide
      ? nodes.filter(n => n.type === 'idp_application').map(n => n.id)
      : appIds
          .filter(aid => aid !== 'All' && aid !== 'None')
          .map(aid => idpApplicationId('entra', tenantId || 'unknown', aid))
          .filter(id => seenNodes.has(id))
    ).filter(id => !excludedNodeIds.has(id));

    for (const appNodeId of targetAppNodeIds) {
      // Stamp the gate on the application node itself so OIDC pivot
      // and frontier scoring can short-circuit without scanning edges.
      const appNode = nodes.find(n => n.id === appNodeId);
      if (appNode) appNode.app_mfa_required = true;
      // Self-loop: app → app with type MFA_REQUIRED_FOR. Schema permits
      // idp_application as a source for org-wide CA policies.
      edges.push({
        source: appNodeId,
        target: appNodeId,
        properties: {
          type: 'MFA_REQUIRED_FOR' as EdgeType,
          confidence: 1.0,
          discovered_at: now,
          discovered_by: agentId,
          ca_policy: policyLabel,
          ca_scope: isOrgWide ? 'all_applications' : 'named_applications',
        },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
