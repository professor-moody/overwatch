// ============================================================
// Parser: gh api /user/orgs (--paginate optional)
//
// Response: JSON array of GitHub organization objects.
// Emits one `idp` node per org (idp_kind: 'github_org') and stamps the
// list on the source credential as cred_orgs[] for fast lookups.
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { idpId } from '../parser-utils.js';

interface GhOrg {
  login?: string;
  id?: number;
  url?: string;
  description?: string | null;
}

interface PlaybookContext extends ParseContext {
  source_credential_id?: string;
}

export function parseGhApiOrgs(
  output: string,
  agentId: string = 'gh-api-orgs-parser',
  context?: ParseContext,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as PlaybookContext;

  let orgs: GhOrg[];
  try {
    const parsed = JSON.parse(output);
    orgs = Array.isArray(parsed)
      ? parsed.flatMap((page: unknown) => Array.isArray(page) ? page : [page]) as GhOrg[]
      : [];
  } catch {
    return { id: `gh-orgs-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const orgLogins: string[] = [];
  for (const o of orgs) {
    if (!o.login) continue;
    orgLogins.push(o.login);
    const id = idpId('github_org', o.login);
    nodes.push({
      id,
      type: 'idp',
      label: `github:${o.login}`,
      idp_kind: 'github_org',
      tenant_id: o.login,
      discovered_at: now,
      confidence: 1.0,
    });
  }

  if (ctx.source_credential_id && orgLogins.length > 0) {
    nodes.push({
      id: ctx.source_credential_id,
      type: 'credential',
      label: 'gh-orgs-update',
      preserve_existing_label: true,
      discovered_at: now,
      confidence: 1.0,
      cred_orgs: orgLogins,
    });
  }

  return { id: `gh-orgs-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
