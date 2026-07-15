// ============================================================
// Parser: GET https://graph.microsoft.com/v1.0/groups
//
// Response: { value: [{ id, displayName, description, securityEnabled,
//   mailEnabled, groupTypes, ... }] }
//
// Emits a `group` node per security group. Mail-enabled distribution
// groups are skipped (not relevant for access control). Membership
// requires a follow-up /groups/{id}/members call which we don't
// auto-walk here — operators chain that manually after seeing the
// initial inventory.
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { groupId } from '../parser-utils.js';

interface MsGraphGroup {
  id?: string;
  displayName?: string;
  description?: string | null;
  securityEnabled?: boolean;
  mailEnabled?: boolean;
  groupTypes?: string[];
}

interface PlaybookContext extends ParseContext {
  tenant_id?: string;
}

export function parseMsGraphGroups(
  output: string,
  agentId: string = 'msgraph-groups-parser',
  context?: ParseContext,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as PlaybookContext;

  let payload: { value?: MsGraphGroup[]; '@odata.nextLink'?: string };
  try {
    payload = JSON.parse(output);
  } catch {
    return { id: `msgraph-groups-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const groups = payload.value;
  if (!Array.isArray(groups)) {
    return { id: `msgraph-groups-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const tenant = typeof ctx.tenant_id === 'string' && !/^(common|organizations|consumers|unknown)$/i.test(ctx.tenant_id)
    ? ctx.tenant_id : undefined;
  if (!tenant) {
    return { id: `msgraph-groups-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  for (const g of groups) {
    if (!g.id || !g.displayName) continue;
    // Skip distribution-only groups — pure mailing lists, not access
    // controls.
    if (g.mailEnabled === true && g.securityEnabled !== true) continue;

    // Entra display names are not unique. Key by the immutable Graph object id
    // while retaining the operator-friendly display name as the label.
    const id = groupId(g.id, `entra:${tenant}`);
    nodes.push({
      id,
      type: 'group',
      label: g.displayName,
      domain: tenant,
      tenant_id: tenant,
      object_id: g.id,
      description: g.description ?? undefined,
      security_enabled: g.securityEnabled !== false,
      group_kind: g.groupTypes?.includes('Unified') ? 'unified' : 'security',
      idp_kind: 'entra',
      discovered_at: now,
      confidence: 1.0,
    });
  }

  const partial = typeof payload['@odata.nextLink'] === 'string' && payload['@odata.nextLink'].length > 0;
  return {
    id: `msgraph-groups-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges,
    partial: partial || undefined,
    partial_reason: partial ? 'msgraph_pagination_incomplete' : undefined,
  };
}
