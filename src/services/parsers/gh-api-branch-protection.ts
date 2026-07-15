// ============================================================
// Parser: gh api /repos/{owner}/{repo}/branches/{branch}/protection
//
// Response shape varies — when protection is enabled, returns an
// object with keys like `required_status_checks`, `enforce_admins`,
// `required_pull_request_reviews`, `restrictions`. When disabled,
// the API returns 404 (the response we get is `{ "message": "Branch
// not protected" }`).
//
// We stamp `branch_protection` and `branch_protection_gaps` on the
// repo idp_application so reports can flag missing controls without a
// separate vulnerability node.
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { idpApplicationId, idpId } from '../parser-utils.js';

interface BranchProtection {
  required_status_checks?: { strict?: boolean; contexts?: string[] };
  enforce_admins?: { enabled?: boolean };
  required_pull_request_reviews?: {
    required_approving_review_count?: number;
    require_code_owner_reviews?: boolean;
    dismiss_stale_reviews?: boolean;
  };
  restrictions?: { users?: unknown[]; teams?: unknown[]; apps?: unknown[] } | null;
  required_signatures?: { enabled?: boolean };
  required_linear_history?: { enabled?: boolean };
  message?: string;
}

interface PlaybookContext extends ParseContext {
  repo_full_name?: string;
  branch_name?: string;
}

export function parseGhApiBranchProtection(
  output: string,
  agentId: string = 'gh-api-branch-protection-parser',
  context?: ParseContext,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as PlaybookContext;

  if (!ctx.repo_full_name) {
    return { id: `gh-branch-protection-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  let payload: BranchProtection;
  try {
    payload = JSON.parse(output) as BranchProtection;
  } catch {
    return { id: `gh-branch-protection-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { id: `gh-branch-protection-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const unprotected = typeof payload.message === 'string' && /branch not protected/i.test(payload.message);
  const knownProtectionShape = [
    'required_status_checks', 'enforce_admins', 'required_pull_request_reviews',
    'restrictions', 'required_signatures', 'required_linear_history',
  ].some(key => Object.prototype.hasOwnProperty.call(payload, key));
  // 403/rate-limit/not-found bodies are API errors, not evidence of weak or
  // absent protection. Only the canonical unprotected message is actionable.
  if (!unprotected && (payload.message || !knownProtectionShape)) {
    return { id: `gh-branch-protection-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const owner = ctx.repo_full_name.split('/')[0];
  const appId = idpApplicationId('github_org', owner, ctx.repo_full_name);
  const orgId = idpId('github_org', owner);
  const branch = ctx.branch_name ?? 'main';
  nodes.push({
    id: orgId, type: 'idp', label: `github:${owner}`,
    idp_kind: 'github_org', tenant_id: owner,
    discovered_at: now, confidence: 1.0,
  });

  // 404-shaped response → fully unprotected.
  if (unprotected) {
    nodes.push({
      id: appId,
      type: 'idp_application',
      label: ctx.repo_full_name,
      idp_id: orgId,
      idp_kind: 'github_org',
      app_kind: 'github_repo',
      tenant_id: owner,
      repo_full_name: ctx.repo_full_name,
      branch_protection: { branch, status: 'unprotected' },
      branch_protection_gaps: [
        'no required_status_checks',
        'no required_pull_request_reviews',
        'admins not enforced',
      ],
      finding_severity: 'high',
      discovered_at: now,
      confidence: 1.0,
    });
    return { id: `gh-branch-protection-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const gaps: string[] = [];
  if (!payload.required_status_checks) gaps.push('no required_status_checks');
  if (!payload.required_pull_request_reviews?.required_approving_review_count) gaps.push('no required reviews');
  if (payload.required_pull_request_reviews && !payload.required_pull_request_reviews.require_code_owner_reviews) {
    gaps.push('code-owner review not required');
  }
  if (!payload.enforce_admins?.enabled) gaps.push('admins can bypass protection');
  if (!payload.required_signatures?.enabled) gaps.push('commit signatures not required');

  nodes.push({
    id: appId,
    type: 'idp_application',
    label: ctx.repo_full_name,
    idp_id: orgId,
    idp_kind: 'github_org',
    app_kind: 'github_repo',
    tenant_id: owner,
    repo_full_name: ctx.repo_full_name,
    branch_protection: {
      branch,
      status: gaps.length === 0 ? 'strong' : 'weak',
      required_reviewers: payload.required_pull_request_reviews?.required_approving_review_count ?? 0,
      enforce_admins: payload.enforce_admins?.enabled === true,
      require_signatures: payload.required_signatures?.enabled === true,
    },
    branch_protection_gaps: gaps,
    finding_severity: gaps.length >= 3 ? 'high' : gaps.length > 0 ? 'medium' : undefined,
    discovered_at: now,
    confidence: 1.0,
  });

  return { id: `gh-branch-protection-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
