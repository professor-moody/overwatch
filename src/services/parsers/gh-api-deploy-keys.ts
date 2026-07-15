// ============================================================
// Parser: gh api /repos/{owner}/{repo}/keys
//
// Response: JSON array of deploy-key objects.
// Each key gets a `credential` node (`cred_material_kind: 'ssh_key'`).
// `read_only: false` keys are flagged as high-priv since they can
// push to the repo. The public key itself is captured as evidence;
// the private half is never present in the API response (operator
// would need to find it on a developer/CI box separately).
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { credentialId, idpApplicationId, idpId } from '../parser-utils.js';

interface GhDeployKey {
  id?: number;
  key?: string;
  title?: string;
  read_only?: boolean;
  created_at?: string;
  verified?: boolean;
  url?: string;
}

interface PlaybookContext extends ParseContext {
  source_credential_id?: string;
  repo_full_name?: string;
}

export function parseGhApiDeployKeys(
  output: string,
  agentId: string = 'gh-api-deploy-keys-parser',
  context?: ParseContext,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as PlaybookContext;

  let keys: GhDeployKey[];
  try {
    const parsed = JSON.parse(output);
    keys = Array.isArray(parsed)
      ? parsed.flatMap((page: unknown) => Array.isArray(page) ? page : [page]) as GhDeployKey[]
      : [];
  } catch {
    return { id: `gh-deploy-keys-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
  const validKeys = keys.filter((key): key is GhDeployKey & { key: string; title: string } =>
    typeof key.key === 'string' && key.key.length > 0
    && typeof key.title === 'string' && key.title.length > 0);
  if (validKeys.length === 0) {
    return { id: `gh-deploy-keys-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const repo = ctx.repo_full_name;
  const owner = repo?.split('/')[0];
  const repoAppId = repo && owner ? idpApplicationId('github_org', owner, repo) : undefined;
  if (!repo || !owner || !repoAppId) {
    return { id: `gh-deploy-keys-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
  if (repo && owner && repoAppId) {
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

  for (const k of validKeys) {
    // Fingerprint the public key so the credential id is stable across runs.
    const credId = credentialId('ssh_key', `gh-deploy-${repo ?? '?'}-${k.title}-${k.key.slice(0, 32)}`, k.title, undefined);
    const writeAccess = k.read_only !== true;
    nodes.push({
      id: credId,
      type: 'credential',
      label: `${repo ? `${repo}::` : ''}deploy-key:${k.title}`,
      cred_type: 'ssh_key',
      cred_material_kind: 'ssh_key',
      cred_user: k.title,
      cred_audience: repo,
      cred_evidence_kind: 'capture',
      cred_value: k.key,
      credential_status: 'active',
      // GitHub exposes only the public half. Write access describes what the
      // corresponding private key could do; this record itself cannot auth.
      cred_usable_for_auth: false,
      finding_severity: writeAccess ? 'high' : 'low',
      deploy_key_write_access: writeAccess,
      discovered_at: now,
      confidence: 1.0,
      created_at: k.created_at,
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
          notes: writeAccess
            ? 'GitHub deploy key with write access — escalation surface if private half is captured'
            : 'GitHub deploy key (read-only)',
        },
      });
    }
  }

  return { id: `gh-deploy-keys-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
