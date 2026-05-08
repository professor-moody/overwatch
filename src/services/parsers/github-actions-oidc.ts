// ============================================================
// GitHub Actions OIDC parser.
//
// Two complementary input shapes:
//
//  (A) Cloud-side trust policy — `aws iam get-role` JSON for any role
//      whose AssumeRolePolicyDocument federates with
//      `token.actions.githubusercontent.com`. The trust policy carries
//      the StringLike / StringEquals condition that bounds which
//      workflows can assume the role; that condition becomes the
//      `sub_claim_pattern` on the emitted idp_application.
//
//  (B) Repo-side OIDC subject customization — output of
//      `gh api /repos/{owner}/{repo}/actions/oidc-customization/sub`
//      describing how the repo customizes its OIDC subject claim.
//
// Either input alone is informative; together they let the cross-tier
// correlator pair the cloud role to the repo workflow that can assume it.
//
// Emits:
//   - `idp` node (idp_kind: 'ci_github_actions', tenant_id: 'public',
//     issuer_url: 'https://token.actions.githubusercontent.com').
//   - `idp_application` node per repo with sub_claim_pattern.
//   - `cloud_identity` node for the IAM role (when input is the trust
//     policy).
//   - ISSUES_TOKENS_FOR edge from idp_application → cloud_identity.
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { cloudIdentityId, idpApplicationId, idpId } from '../parser-utils.js';

const GHA_ISSUER = 'https://token.actions.githubusercontent.com';
const GHA_FEDERATED_PRINCIPAL = /token\.actions\.githubusercontent\.com$/i;

interface IamStatement {
  Effect?: string;
  Principal?: { Federated?: string | string[] };
  Action?: string | string[];
  Condition?: Record<string, Record<string, string | string[]>>;
}

interface IamTrustPolicy {
  RoleName?: string;
  RoleId?: string;
  Arn?: string;
  AssumeRolePolicyDocument?: { Statement?: IamStatement[] } | string;
}

interface RepoOidcCustom {
  use_default?: boolean;
  include_claim_keys?: string[];
  /** When the repo configures a custom claim template, GitHub returns
   *  the resolved sub claim format here. */
  sub_claim_pattern?: string;
}

function tryParseTrustPolicy(output: string): IamTrustPolicy | null {
  try {
    const obj = JSON.parse(output);
    if (obj?.Role?.AssumeRolePolicyDocument) return obj.Role; // `aws iam get-role` shape
    if (obj?.AssumeRolePolicyDocument) return obj as IamTrustPolicy;
    return null;
  } catch {
    return null;
  }
}

function tryParseRepoCustomization(output: string, _context?: ParseContext): { repo: string; pattern?: string } | null {
  try {
    const obj = JSON.parse(output) as RepoOidcCustom & { repo?: string; full_name?: string };
    // Repo identifier comes either from the parser context or from a
    // `repo`/`full_name` field operators sometimes inject before piping.
    const repo = (obj as { repo?: string; full_name?: string }).repo ?? obj.full_name;
    if (!repo) return null;
    const pattern = obj.sub_claim_pattern;
    return { repo, pattern };
  } catch {
    return null;
  }
}

function pickCondition(stmt: IamStatement): string | undefined {
  const cond = stmt.Condition ?? {};
  for (const op of Object.keys(cond)) {
    const fields = cond[op];
    for (const k of Object.keys(fields)) {
      if (k.toLowerCase() !== 'token.actions.githubusercontent.com:sub') continue;
      const v = fields[k];
      return Array.isArray(v) ? v[0] : v;
    }
  }
  return undefined;
}

function extractRepo(subPattern: string | undefined): string | undefined {
  if (!subPattern) return undefined;
  // Patterns: repo:acme/webapp:ref:refs/heads/main
  //           repo:acme/* (overly broad)
  //           repo:*
  const m = subPattern.match(/^repo:([^:]+)/i);
  return m ? m[1] : undefined;
}

export function parseGitHubActionsOidc(output: string, agentId: string = 'github-actions-oidc-parser', context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const idpNodeId = idpId('ci_github_actions', 'public');
  const ensureIdp = () => {
    if (seenNodes.has(idpNodeId)) return;
    nodes.push({
      id: idpNodeId,
      type: 'idp',
      label: 'GitHub Actions OIDC',
      idp_kind: 'ci_github_actions',
      tenant_id: 'public',
      issuer_url: GHA_ISSUER,
      discovered_via: agentId,
      discovered_at: now,
      confidence: 1.0,
    });
    seenNodes.add(idpNodeId);
  };

  // (A) Trust policy path.
  const trust = tryParseTrustPolicy(output);
  if (trust) {
    let doc: { Statement?: IamStatement[] } | null = null;
    const raw = trust.AssumeRolePolicyDocument;
    if (typeof raw === 'string') { try { doc = JSON.parse(raw); } catch { /* ignore */ } }
    else if (raw) doc = raw;

    const stmts = doc?.Statement ?? [];
    for (const stmt of stmts) {
      const fed = stmt.Principal?.Federated;
      const federated = Array.isArray(fed) ? fed.find(f => GHA_FEDERATED_PRINCIPAL.test(f)) : (typeof fed === 'string' && GHA_FEDERATED_PRINCIPAL.test(fed) ? fed : undefined);
      if (!federated) continue;
      ensureIdp();
      const subPattern = pickCondition(stmt);
      const repo = extractRepo(subPattern) ?? trust.RoleName ?? 'unknown';
      const appNodeId = idpApplicationId('ci_github_actions', 'public', repo);
      if (!seenNodes.has(appNodeId)) {
        nodes.push({
          id: appNodeId,
          type: 'idp_application',
          label: `gha:${repo}`,
          client_id: repo,
          app_name: repo,
          audience: GHA_ISSUER,
          idp_id: idpNodeId,
          sub_claim_pattern: subPattern,
          discovered_at: now,
          confidence: 1.0,
        });
        seenNodes.add(appNodeId);
        edges.push({
          source: appNodeId,
          target: idpNodeId,
          properties: { type: 'TRUSTS' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
        });
      }
      // cloud_identity (the role) + ISSUES_TOKENS_FOR edge.
      const arn = trust.Arn;
      if (arn) {
        const cloudId = cloudIdentityId(arn);
        if (!seenNodes.has(cloudId)) {
          nodes.push({
            id: cloudId,
            type: 'cloud_identity',
            label: trust.RoleName ?? arn,
            arn,
            principal_type: 'role',
            principal_kind: 'aws',
            provider: 'aws',
            discovered_at: now,
            confidence: 1.0,
          });
          seenNodes.add(cloudId);
        }
        edges.push({
          source: appNodeId,
          target: cloudId,
          properties: { type: 'ISSUES_TOKENS_FOR' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId, sub_claim_pattern: subPattern },
        });
      }
    }
  }

  // (B) Repo OIDC subject customization.
  const repoCust = tryParseRepoCustomization(output, context);
  if (repoCust) {
    ensureIdp();
    const appNodeId = idpApplicationId('ci_github_actions', 'public', repoCust.repo);
    if (!seenNodes.has(appNodeId)) {
      nodes.push({
        id: appNodeId,
        type: 'idp_application',
        label: `gha:${repoCust.repo}`,
        client_id: repoCust.repo,
        app_name: repoCust.repo,
        audience: GHA_ISSUER,
        idp_id: idpNodeId,
        sub_claim_pattern: repoCust.pattern,
        discovered_at: now,
        confidence: 0.9,
      });
      seenNodes.add(appNodeId);
      edges.push({
        source: appNodeId,
        target: idpNodeId,
        properties: { type: 'TRUSTS' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    } else {
      // Update existing node with the customized pattern.
      const existing = nodes.find(n => n.id === appNodeId);
      if (existing && repoCust.pattern) existing.sub_claim_pattern = repoCust.pattern;
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
