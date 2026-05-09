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
import { credentialId, idpApplicationId } from '../parser-utils.js';

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

  let payload: GhActionsSecretsResponse;
  try {
    payload = JSON.parse(output) as GhActionsSecretsResponse;
  } catch {
    return { id: `gh-secrets-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  if (!payload.secrets || payload.secrets.length === 0) {
    return { id: `gh-secrets-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const repo = ctx.repo_full_name;
  const owner = repo?.split('/')[0];
  const repoAppId = repo && owner ? idpApplicationId('github_org', owner, repo) : undefined;

  for (const s of payload.secrets) {
    if (!s.name) continue;
    const credId = credentialId('app_password', `gh-actions-secret-${repo ?? 'unknown'}-${s.name}`, s.name, undefined);
    nodes.push({
      id: credId,
      type: 'credential',
      label: `${repo ? `${repo}::` : ''}${s.name}`,
      cred_type: 'token',
      cred_material_kind: 'app_password',
      cred_user: s.name,
      cred_evidence_kind: 'capture',
      cred_value: `<gh-actions-secret name=${s.name} repo=${repo ?? '?'}>`,
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

  return { id: `gh-secrets-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
