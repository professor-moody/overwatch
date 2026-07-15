// ============================================================
// Parser: GET https://graph.microsoft.com/v1.0/servicePrincipals
//
// Response: { value: [{ id, appId, displayName, oauth2PermissionScopes,
//   appRoles, servicePrincipalType, ... }] }
//
// Service principals are the "instance" of an app within a tenant.
// We emit them as idp_application with app_kind: 'entra_service_principal'.
// oauth2PermissionScopes/appRoles describe permissions this service
// principal exposes, not permissions granted to it. Keep them in explicit
// `exposed_*` fields so consent analysis cannot mistake them for grants.
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

  let payload: { value?: MsGraphServicePrincipal[]; '@odata.nextLink'?: string };
  try {
    payload = JSON.parse(output);
  } catch {
    return { id: `msgraph-sp-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const sps = payload.value;
  if (!Array.isArray(sps)) {
    return { id: `msgraph-sp-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
  const validSps = sps.filter((sp): sp is MsGraphServicePrincipal & { appId: string; displayName: string } =>
    typeof sp.appId === 'string' && sp.appId.length > 0
    && typeof sp.displayName === 'string' && sp.displayName.length > 0);
  if (validSps.length === 0) {
    const partial = typeof payload['@odata.nextLink'] === 'string' && payload['@odata.nextLink'].length > 0;
    return {
      id: `msgraph-sp-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges,
      partial: partial || undefined,
      partial_reason: partial ? 'msgraph_pagination_incomplete' : undefined,
    };
  }

  const tenant = typeof ctx.tenant_id === 'string' && !/^(common|organizations|consumers|unknown)$/i.test(ctx.tenant_id)
    ? ctx.tenant_id : undefined;
  if (!tenant) {
    return { id: `msgraph-sp-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
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

  for (const sp of validSps) {
    const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const comparableOwner = typeof sp.appOwnerOrganizationId === 'string'
      && guid.test(sp.appOwnerOrganizationId) && guid.test(tenant);

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
      external_app: comparableOwner ? sp.appOwnerOrganizationId !== tenant : undefined,
      exposed_oauth_scopes: (sp.oauth2PermissionScopes ?? []).map(scope => scope.value).filter((value): value is string => !!value),
      exposed_app_roles: (sp.appRoles ?? []).map(role => role.value).filter((value): value is string => !!value),
      sign_in_audience: sp.signInAudience,
      discovered_at: now,
      confidence: 1.0,
    });
  }

  const partial = typeof payload['@odata.nextLink'] === 'string' && payload['@odata.nextLink'].length > 0;
  return {
    id: `msgraph-sp-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges,
    partial: partial || undefined,
    partial_reason: partial ? 'msgraph_pagination_incomplete' : undefined,
  };
}
