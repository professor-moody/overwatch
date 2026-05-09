// ============================================================
// Parser: GET https://graph.microsoft.com/v1.0/applications
//
// Response: { value: [{ id, appId, displayName, requiredResourceAccess,
//   web, signInAudience, ... }] }
//
// Emits idp_application per registration. signInAudience tells us if
// the app accepts external (multi-tenant) tokens — high-priv consent
// abuse candidate. requiredResourceAccess.scopes is collected onto
// app_scopes so the CONSENT_ABUSE inference rule (cross-tier-inference)
// can flag overly permissive apps without re-querying.
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

  let payload: { value?: MsGraphApp[] };
  try {
    payload = JSON.parse(output);
  } catch {
    return { id: `msgraph-apps-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const apps = payload.value;
  if (!Array.isArray(apps)) {
    return { id: `msgraph-apps-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
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

  for (const a of apps) {
    if (!a.appId || !a.displayName) continue;
    // Aggregate requested permission scope IDs into app_scopes. Real
    // scope names require a follow-up serviceprincipal lookup; the IDs
    // are still useful for the consent-abuse rule (which matches scope
    // patterns) when the app already declares plain Mail.* / Files.*
    // names in extensionAttributes. For now, we capture both.
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
      app_scopes: scopeIds,
      redirect_uris: a.web?.redirectUris,
      discovered_at: now,
      confidence: 1.0,
    });
  }

  return { id: `msgraph-apps-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
