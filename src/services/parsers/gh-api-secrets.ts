// ============================================================
// Parser: gh api /repos/{owner}/{repo}/actions/secrets
//
// Response: { total_count, secrets: [{ name, created_at, updated_at }] }
// GitHub's API does NOT return secret values — only metadata. We emit
// one `credential` node per secret with `cred_value` set to a
// fingerprint-only placeholder so downstream coverage / chain logic
// recognizes them as token-shaped without disclosing anything.
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { credentialId, idpApplicationId, idpId } from '../parser-utils.js';

interface GhActionsSecretsResponse {
  total_count?: number;
  secrets?: Array<{
    name?: string;
    created_at?: string;
    updated_at?: string;
  }>;
}

interface PlaybookContext extends ParseContext {
  source_credential_id?: string;
  /** owner/repo, e.g. "acme/webapp". Required to anchor secrets to a repo node. */
  repo_full_name?: string;
}

export function parseGhApiSecrets(
  output: string,
  agentId: string = 'gh-api-secrets-parser',
  context?: ParseContext,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as PlaybookContext;

  let pages: GhActionsSecretsResponse[];
  try {
    const parsed = JSON.parse(output) as GhActionsSecretsResponse | GhActionsSecretsResponse[];
    pages = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return { id: `gh-secrets-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const secrets = pages.flatMap(page => Array.isArray(page?.secrets) ? page.secrets : []);
  const validSecrets = secrets.filter((secret): secret is NonNullable<GhActionsSecretsResponse['secrets']>[number] & { name: string } =>
    typeof secret.name === 'string' && secret.name.length > 0) ?? [];
  if (validSecrets.length === 0) {
    return { id: `gh-secrets-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const repo = ctx.repo_full_name;
  const owner = repo?.split('/')[0];
  const repoAppId = repo && owner ? idpApplicationId('github_org', owner, repo) : undefined;
  if (!repo || !owner || !repoAppId) {
    return { id: `gh-secrets-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
  {
    const orgId = idpId('github_org', owner);
    nodes.push({
      id: orgId, type: 'idp', label: `github:${owner}`,
      idp_kind: 'github_org', tenant_id: owner,
      discovered_at: now, confidence: 1.0,
    });
    nodes.push({
      id: repoAppId, type: 'idp_application', label: repo,
      idp_id: orgId, idp_kind: 'github_org', tenant_id: owner,
      app_kind: 'github_repo', repo_full_name: repo,
      discovered_at: now, confidence: 1.0,
    });
  }

  for (const s of validSecrets) {
    const credId = credentialId('app_password', `gh-actions-secret-${repo}-${s.name}`, s.name, undefined);
    nodes.push({
      id: credId,
      type: 'credential',
      label: `${repo}::${s.name}`,
      cred_type: 'token',
      cred_material_kind: 'app_password',
      cred_user: s.name,
      cred_evidence_kind: 'capture',
      cred_value: `<gh-actions-secret name=${s.name} repo=${repo}>`,
      cred_audience: repo,
      // Secret values aren't readable via API; status is "exists" not
      // "active" since we can't auth with it. Operators who need the
      // value go through workflow exfiltration, not this enum step.
      credential_status: 'active',
      cred_usable_for_auth: false,
      discovered_at: now,
      confidence: 1.0,
      created_at: s.created_at,
      updated_at: s.updated_at,
    });
    if (repoAppId) {
      edges.push({
        source: repoAppId,
        target: credId,
        properties: {
          type: 'OWNS_CRED',
          confidence: 1.0,
          discovered_at: now,
          discovered_by: agentId,
          notes: 'GitHub Actions repo secret (value not exposed by API)',
        },
      });
    }
  }

  const advertisedTotal = Math.max(0, ...pages.map(page => typeof page.total_count === 'number' ? page.total_count : 0));
  const partial = advertisedTotal > validSecrets.length;
  return {
    id: `gh-secrets-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges,
    partial: partial || undefined,
    partial_reason: partial ? 'github_pagination_incomplete' : undefined,
  };
}
