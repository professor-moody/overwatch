// ============================================================
// Parser: gh api /user/repos --paginate (or per-org /orgs/{org}/repos)
//
// Response: JSON array of repo objects. Emits an `idp_application`
// per repo (idp_kind: 'github_repo'); the dashboard's IdentityPanel
// already groups apps under their parent IdP, so they roll up under
// the github_org idp emitted by gh-api-orgs.
//
// Captured fields: full_name (owner/repo), private, default_branch,
// language, archived, fork. Defaults to public visibility when the
// API response is partial (e.g. /repos/{owner}/{repo} single-object).
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { idpApplicationId, idpId } from '../parser-utils.js';

interface GhRepo {
  id?: number;
  full_name?: string;
  name?: string;
  owner?: { login?: string };
  private?: boolean;
  default_branch?: string;
  language?: string | null;
  archived?: boolean;
  fork?: boolean;
  description?: string | null;
}

interface PlaybookContext extends ParseContext {
  source_credential_id?: string;
}

export function parseGhApiRepos(
  output: string,
  agentId: string = 'gh-api-repos-parser',
  context?: ParseContext,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as PlaybookContext;

  let repos: GhRepo[];
  try {
    const parsed = JSON.parse(output);
    repos = Array.isArray(parsed)
      ? parsed.flatMap((page: unknown) => Array.isArray(page) ? page : [page]) as GhRepo[]
      : [parsed as GhRepo];
  } catch {
    return { id: `gh-repos-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  for (const r of repos) {
    if (!r.full_name && !(r.name && r.owner?.login)) continue;
    const fullName = r.full_name ?? `${r.owner!.login}/${r.name}`;
    const owner = r.owner?.login ?? fullName.split('/')[0];

    const orgIdpId = idpId('github_org', owner);
    // Idempotent: stamp the org idp (in case orgs parser hasn't run yet).
    nodes.push({
      id: orgIdpId,
      type: 'idp',
      label: `github:${owner}`,
      idp_kind: 'github_org',
      tenant_id: owner,
      discovered_at: now,
      confidence: 1.0,
    });

    const appId = idpApplicationId('github_org', owner, fullName);
    nodes.push({
      id: appId,
      type: 'idp_application',
      label: fullName,
      idp_id: orgIdpId,
      idp_kind: 'github_org',
      tenant_id: owner,
      app_kind: 'github_repo',
      repo_full_name: fullName,
      private: r.private === true,
      default_branch: r.default_branch,
      language: r.language ?? undefined,
      archived: r.archived === true,
      fork: r.fork === true,
      discovered_at: now,
      confidence: 1.0,
    });

    if (ctx.source_credential_id) {
      edges.push({
        source: ctx.source_credential_id,
        target: appId,
        properties: {
          type: 'VALID_FOR_APP',
          confidence: 0.9,
          discovered_at: now,
          discovered_by: agentId,
          notes: 'Credential lists this repo via gh api /user/repos',
        },
      });
    }
  }

  return { id: `gh-repos-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
