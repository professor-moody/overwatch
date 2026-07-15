// ============================================================
// Parser: GET https://graph.microsoft.com/v1.0/users
//
// Response: { value: [{ id, userPrincipalName, displayName, mail, ... }] }
// Emits one idp_principal per user. Tenant id is captured from the
// ParseContext (passed by the playbook).
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { idpId, idpPrincipalId } from '../parser-utils.js';

interface MsGraphUser {
  id?: string;
  userPrincipalName?: string;
  displayName?: string;
  mail?: string | null;
  accountEnabled?: boolean;
  jobTitle?: string | null;
  department?: string | null;
}

interface PlaybookContext extends ParseContext {
  tenant_id?: string;
  source_credential_id?: string;
}

export function parseMsGraphUsers(
  output: string,
  agentId: string = 'msgraph-users-parser',
  context?: ParseContext,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as PlaybookContext;

  let payload: { value?: MsGraphUser[]; '@odata.nextLink'?: string };
  try {
    payload = JSON.parse(output);
  } catch {
    return { id: `msgraph-users-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const users = payload.value;
  if (!Array.isArray(users)) {
    return { id: `msgraph-users-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
  const validUsers = users.filter((user): user is MsGraphUser & { id: string; userPrincipalName: string } =>
    typeof user.id === 'string' && user.id.length > 0
    && typeof user.userPrincipalName === 'string' && user.userPrincipalName.length > 0);
  if (validUsers.length === 0) {
    const partial = typeof payload['@odata.nextLink'] === 'string' && payload['@odata.nextLink'].length > 0;
    return {
      id: `msgraph-users-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges,
      partial: partial || undefined,
      partial_reason: partial ? 'msgraph_pagination_incomplete' : undefined,
    };
  }

  const tenant = typeof ctx.tenant_id === 'string' && !/^(common|organizations|consumers|unknown)$/i.test(ctx.tenant_id)
    ? ctx.tenant_id : undefined;
  if (!tenant) {
    return { id: `msgraph-users-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
  const tenantIdpId = idpId('entra', tenant);
  // Idempotent IdP stamp.
  nodes.push({
    id: tenantIdpId,
    type: 'idp',
    label: `entra:${tenant}`,
    idp_kind: 'entra',
    tenant_id: tenant,
    discovered_at: now,
    confidence: 1.0,
  });

  for (const u of validUsers) {
    const principalId = idpPrincipalId('entra', tenant, u.id);
    nodes.push({
      id: principalId,
      type: 'idp_principal',
      label: u.userPrincipalName,
      idp_id: tenantIdpId,
      idp_kind: 'entra',
      tenant_id: tenant,
      upn: u.userPrincipalName,
      object_id: u.id,
      display_name: u.displayName,
      mail: u.mail ?? undefined,
      account_enabled: u.accountEnabled !== false,
      job_title: u.jobTitle ?? undefined,
      department: u.department ?? undefined,
      discovered_at: now,
      confidence: 1.0,
    });
  }

  const partial = typeof payload['@odata.nextLink'] === 'string' && payload['@odata.nextLink'].length > 0;
  return {
    id: `msgraph-users-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges,
    partial: partial || undefined,
    partial_reason: partial ? 'msgraph_pagination_incomplete' : undefined,
  };
}
