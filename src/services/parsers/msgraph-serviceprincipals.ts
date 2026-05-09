// ============================================================
// Parser: GET https://graph.microsoft.com/v1.0/servicePrincipals
//
// Response: { value: [{ id, appId, displayName, oauth2PermissionScopes,
//   appRoles, servicePrincipalType, ... }] }
//
// Service principals are the "instance" of an app within a tenant.
// We emit them as idp_application with app_kind: 'entra_service_principal'.
// oauth2PermissionScopes' .value strings (e.g. "User.Read.All") populate
// app_scopes so CONSENT_ABUSE can pattern-match on the human-readable
// scope names that the bare /applications endpoint doesn't expose.
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { idpId, idpApplicationId } from '../parser-utils.js';

interface OAuth2Scope {
  id?: string;
  value?: string;
  adminConsentDisplayName?: string;
  type?: 'User' | 'Admin';
}

interface MsGraphServicePrincipal {
  id?: string;
  appId?: string;
  displayName?: string;
  servicePrincipalType?: string;
  oauth2PermissionScopes?: OAuth2Scope[];
  appRoles?: Array<{ value?: string }>;
  homepage?: string | null;
  appOwnerOrganizationId?: string;
  signInAudience?: string;
}

interface PlaybookContext extends ParseContext {
  tenant_id?: string;
}

export function parseMsGraphServicePrincipals(
  output: string,
  agentId: string = 'msgraph-sp-parser',
  context?: ParseContext,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as PlaybookContext;

  let payload: { value?: MsGraphServicePrincipal[] };
  try {
    payload = JSON.parse(output);
  } catch {
    return { id: `msgraph-sp-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const sps = payload.value;
  if (!Array.isArray(sps)) {
    return { id: `msgraph-sp-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const tenant = ctx.tenant_id ?? 'unknown';
  const tenantIdpId = idpId('entra', tenant);
  nodes.push({
    id: tenantIdpId,
    type: 'idp',
    label: `entra:${tenant}`,
    idp_kind: 'entra',
    tenant_id: tenant,
    discovered_at: now,
    confidence: 1.0,
  });

  for (const sp of sps) {
    if (!sp.appId || !sp.displayName) continue;

    const scopeNames: string[] = [];
    for (const s of sp.oauth2PermissionScopes ?? []) {
      if (s.value) scopeNames.push(s.value);
    }
    for (const r of sp.appRoles ?? []) {
      if (r.value) scopeNames.push(r.value);
    }

    const id = idpApplicationId('entra', `${tenant}-sp`, sp.appId);
    nodes.push({
      id,
      type: 'idp_application',
      label: sp.displayName,
      idp_id: tenantIdpId,
      idp_kind: 'entra',
      tenant_id: tenant,
      app_kind: 'entra_service_principal',
      client_id: sp.appId,
      object_id: sp.id,
      service_principal_type: sp.servicePrincipalType,
      app_owner_tenant: sp.appOwnerOrganizationId,
      external_app: sp.appOwnerOrganizationId !== undefined && sp.appOwnerOrganizationId !== tenant,
      app_scopes: scopeNames,
      sign_in_audience: sp.signInAudience,
      discovered_at: now,
      confidence: 1.0,
    });
  }

  return { id: `msgraph-sp-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
