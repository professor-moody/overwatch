// ============================================================
// Parser: GET https://graph.microsoft.com/v1.0/applications
//
// Response: { value: [{ id, appId, displayName, requiredResourceAccess,
//   web, signInAudience, ... }] }
//
// Emits idp_application per registration. signInAudience tells us if
// the app accepts external (multi-tenant) tokens — high-priv consent
// abuse candidate. requiredResourceAccess contains permission GUIDs; retain
// those explicitly without pretending they are granted scope names.
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { idpId, idpApplicationId } from '../parser-utils.js';

interface ResourceAccess {
  resourceAppId?: string;
  resourceAccess?: Array<{ id?: string; type?: string }>;
}

interface MsGraphApp {
  id?: string;
  appId?: string;
  displayName?: string;
  signInAudience?: string;
  publisherDomain?: string;
  requiredResourceAccess?: ResourceAccess[];
  web?: { redirectUris?: string[] };
}

interface PlaybookContext extends ParseContext {
  tenant_id?: string;
}

export function parseMsGraphApplications(
  output: string,
  agentId: string = 'msgraph-apps-parser',
  context?: ParseContext,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as PlaybookContext;

  let payload: { value?: MsGraphApp[]; '@odata.nextLink'?: string };
  try {
    payload = JSON.parse(output);
  } catch {
    return { id: `msgraph-apps-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const apps = payload.value;
  if (!Array.isArray(apps)) {
    return { id: `msgraph-apps-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
  const validApps = apps.filter((app): app is MsGraphApp & { appId: string; displayName: string } =>
    typeof app.appId === 'string' && app.appId.length > 0
    && typeof app.displayName === 'string' && app.displayName.length > 0);
  if (validApps.length === 0) {
    const partial = typeof payload['@odata.nextLink'] === 'string' && payload['@odata.nextLink'].length > 0;
    return {
      id: `msgraph-apps-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges,
      partial: partial || undefined,
      partial_reason: partial ? 'msgraph_pagination_incomplete' : undefined,
    };
  }

  const tenant = typeof ctx.tenant_id === 'string' && !/^(common|organizations|consumers|unknown)$/i.test(ctx.tenant_id)
    ? ctx.tenant_id : undefined;
  if (!tenant) {
    return { id: `msgraph-apps-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
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

  for (const a of validApps) {
    // These are permission GUIDs, not human-readable scope names. A later
    // grants/assignments query is required before consent-abuse reasoning.
    const scopeIds: string[] = [];
    for (const r of a.requiredResourceAccess ?? []) {
      for (const acc of r.resourceAccess ?? []) {
        if (acc.id) scopeIds.push(acc.id);
      }
    }

    const appNodeId = idpApplicationId('entra', tenant, a.appId);
    nodes.push({
      id: appNodeId,
      type: 'idp_application',
      label: a.displayName,
      idp_id: tenantIdpId,
      idp_kind: 'entra',
      tenant_id: tenant,
      app_kind: 'entra_application',
      client_id: a.appId,
      object_id: a.id,
      sign_in_audience: a.signInAudience,
      multi_tenant: a.signInAudience !== 'AzureADMyOrg' && a.signInAudience !== undefined,
      publisher_domain: a.publisherDomain,
      requested_permission_ids: scopeIds,
      redirect_uris: a.web?.redirectUris,
      discovered_at: now,
      confidence: 1.0,
    });
  }

  const partial = typeof payload['@odata.nextLink'] === 'string' && payload['@odata.nextLink'].length > 0;
  return {
    id: `msgraph-apps-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges,
    partial: partial || undefined,
    partial_reason: partial ? 'msgraph_pagination_incomplete' : undefined,
  };
}
