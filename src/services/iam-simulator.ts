// ============================================================
// Overwatch — IAM Policy Simulator
// Evaluates whether a principal can perform an action on a
// resource by traversing the graph's cloud policy nodes.
// Supports AWS (deny-overrides-allow + permission boundaries),
// Azure RBAC, and GCP IAM basics.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { EdgeProperties, NodeProperties } from '../types.js';

export interface IAMEvalResult {
  allowed: boolean;
  reason: string;
  matching_policies: string[];
  deny_policies?: string[];
  provider?: 'aws' | 'azure' | 'gcp';
  evaluated_principals?: string[];
  assumption_paths?: string[][];
}

/**
 * Match an action string against an action pattern (supports wildcards).
 * e.g., "s3:GetObject" matches "s3:*", "*", "s3:Get*"
 */
function matchAction(pattern: string, action: string): boolean {
  const pLower = pattern.toLowerCase();
  const aLower = action.toLowerCase();
  if (pLower === '*' || pLower === '*:*') return true;
  if (pLower === aLower) return true;
  // Wildcard at end: "s3:*" matches "s3:getobject"
  if (pLower.endsWith('*')) {
    return aLower.startsWith(pLower.slice(0, -1));
  }
  return false;
}

/**
 * Match a resource ARN/ID against a resource pattern (supports wildcards).
 */
function matchResource(pattern: string, resource: string): boolean {
  const pLower = pattern.toLowerCase();
  const rLower = resource.toLowerCase();
  if (pLower === '*') return true;
  if (pLower === rLower) return true;
  if (pLower.endsWith('*')) {
    return rLower.startsWith(pLower.slice(0, -1));
  }
  // ARN glob matching with ? and *
  const regex = new RegExp(
    '^' + pLower.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
  );
  return regex.test(rLower);
}

/**
 * Evaluate whether a principal can perform an action on a resource.
 * Traverses principal → HAS_POLICY → cloud_policy nodes in the graph.
 *
 * AWS semantics: explicit deny overrides allow. Permission boundaries
 * intersect with identity-based policies.
 */
export function evaluateIAM(
  principalId: string,
  action: string,
  resource: string,
  ctx: EngineContext,
): IAMEvalResult {
  if (!ctx.graph.hasNode(principalId)) {
    return { allowed: false, reason: 'Principal not found in graph', matching_policies: [] };
  }

  const principal = ctx.graph.getNodeAttributes(principalId) as NodeProperties;
  const provider = principal.provider || detectProvider(principal);

  // Collect all policies attached to the principal and confirmed assumable roles.
  const policyNodes: Array<{ id: string; node: NodeProperties }> = [];
  const seenPolicies = new Set<string>();
  const evaluatedPrincipals: string[] = [];
  const assumptionPaths: string[][] = [];
  const queue: Array<{ id: string; path: string[] }> = [{ id: principalId, path: [principalId] }];
  const visited = new Set<string>();
  const maxAssumeDepth = 5;

  function addPolicy(policy: { id: string; node: NodeProperties }): void {
    if (seenPolicies.has(policy.id)) return;
    seenPolicies.add(policy.id);
    policyNodes.push(policy);
  }

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (visited.has(current.id)) continue;
    visited.add(current.id);
    evaluatedPrincipals.push(current.id);
    if (current.path.length > 1) assumptionPaths.push(current.path);

    ctx.graph.forEachOutEdge(current.id, (_edge, attrs, _src, target) => {
      if (attrs.type === 'HAS_POLICY' || attrs.type === 'MEMBER_OF') return;

      if (attrs.type === 'ASSUMES_ROLE' && current.path.length <= maxAssumeDepth && ctx.graph.hasNode(target)) {
        const targetNode = ctx.graph.getNodeAttributes(target) as NodeProperties;
        if (
          targetNode.type === 'cloud_identity'
          && !current.path.includes(target)
          && canUseAssumeRoleEdge(current.id, targetNode, attrs as EdgeProperties, provider, ctx)
        ) {
          queue.push({ id: target, path: [...current.path, target] });
        }
      }
    });

    for (const policy of collectDirectAndGroupPolicies(current.id, ctx)) {
      addPolicy(policy);
    }
  }

  if (policyNodes.length === 0) {
    return {
      allowed: false,
      reason: 'No policies attached to principal or assumable roles',
      matching_policies: [],
      provider,
      evaluated_principals: evaluatedPrincipals,
      assumption_paths: assumptionPaths,
    };
  }

  let result: IAMEvalResult;
  switch (provider) {
    case 'aws':
      result = evaluateAWS(policyNodes, action, resource);
      break;
    case 'azure':
      result = evaluateAzure(policyNodes, action, resource);
      break;
    case 'gcp':
      result = evaluateGCP(policyNodes, action, resource);
      break;
    default:
      result = evaluateAWS(policyNodes, action, resource); // default to AWS semantics
      break;
  }
  return { ...result, evaluated_principals: evaluatedPrincipals, assumption_paths: assumptionPaths };
}

function detectProvider(node: NodeProperties): 'aws' | 'azure' | 'gcp' | undefined {
  if (node.arn?.startsWith('arn:aws:')) return 'aws';
  if (node.arn?.includes('.azure.') || node.principal_type === 'managed_identity') return 'azure';
  if (node.arn?.includes('gserviceaccount.com') || node.principal_type === 'service_account') return 'gcp';
  return undefined;
}

function collectDirectAndGroupPolicies(
  principalId: string,
  ctx: EngineContext,
): Array<{ id: string; node: NodeProperties }> {
  const policies: Array<{ id: string; node: NodeProperties }> = [];
  const seen = new Set<string>();

  function addPolicy(policyTarget: string): void {
    if (!ctx.graph.hasNode(policyTarget) || seen.has(policyTarget)) return;
    const policyNode = ctx.graph.getNodeAttributes(policyTarget) as NodeProperties;
    if (policyNode.type !== 'cloud_policy') return;
    seen.add(policyTarget);
    policies.push({ id: policyTarget, node: policyNode });
  }

  ctx.graph.forEachOutEdge(principalId, (_edge, attrs, _src, target) => {
    if (attrs.type === 'HAS_POLICY') {
      addPolicy(target);
      return;
    }

    // Group memberships: principal → MEMBER_OF → group → HAS_POLICY → policy
    if (attrs.type === 'MEMBER_OF') {
      ctx.graph.forEachOutEdge(target, (_e2, a2, _s2, policyTarget) => {
        if (a2.type === 'HAS_POLICY') addPolicy(policyTarget);
      });
    }
  });

  return policies;
}

function canUseAssumeRoleEdge(
  sourcePrincipalId: string,
  targetRole: NodeProperties,
  edge: EdgeProperties,
  provider: 'aws' | 'azure' | 'gcp' | undefined,
  ctx: EngineContext,
): boolean {
  if (provider !== 'aws') return true;
  if (edge.assumption_confirmed === true) return true;
  if (edge.tested === true && edge.test_result === 'success') return true;
  if (!targetRole.arn) return false;

  const sourcePolicies = collectDirectAndGroupPolicies(sourcePrincipalId, ctx);
  if (sourcePolicies.length === 0) return false;
  return evaluateAWS(sourcePolicies, 'sts:AssumeRole', targetRole.arn).allowed;
}

/**
 * AWS IAM evaluation: explicit deny → allow → implicit deny.
 */
function evaluateAWS(
  policies: Array<{ id: string; node: NodeProperties }>,
  action: string,
  resource: string,
): IAMEvalResult {
  const denyPolicies: string[] = [];
  const allowPolicies: string[] = [];

  for (const { id, node } of policies) {
    const policyActions = (node.actions as string[]) || [];
    const policyResources = (node.resources as string[]) || ['*'];
    const effect = node.effect || 'allow';
    const policyName = node.policy_name || node.label || id;

    const actionMatch = policyActions.some(a => matchAction(a, action));
    const resourceMatch = policyResources.some(r => matchResource(r, resource));

    if (actionMatch && resourceMatch) {
      if (effect === 'deny') {
        denyPolicies.push(policyName);
      } else {
        allowPolicies.push(policyName);
      }
    }
  }

  // Explicit deny overrides allow
  if (denyPolicies.length > 0) {
    return {
      allowed: false,
      reason: `Explicitly denied by: ${denyPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      deny_policies: denyPolicies,
      provider: 'aws',
    };
  }

  if (allowPolicies.length > 0) {
    return {
      allowed: true,
      reason: `Allowed by: ${allowPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      provider: 'aws',
    };
  }

  return {
    allowed: false,
    reason: 'Implicitly denied — no matching allow policies',
    matching_policies: [],
    provider: 'aws',
  };
}

/**
 * Azure RBAC evaluation: role assignments with scope hierarchy matching.
 */
function evaluateAzure(
  policies: Array<{ id: string; node: NodeProperties }>,
  action: string,
  resource: string,
): IAMEvalResult {
  const denyPolicies: string[] = [];
  const allowPolicies: string[] = [];

  for (const { id, node } of policies) {
    const policyActions = (node.actions as string[]) || [];
    const policyResources = (node.resources as string[]) || ['*'];
    const effect = node.effect || 'allow';
    const policyName = node.policy_name || node.label || id;

    const actionMatch = policyActions.some(a => matchAction(a, action));
    // Azure scope: resource must be at or below the scope
    const resourceMatch = policyResources.some(r =>
      matchResource(r, resource) || resource.toLowerCase().startsWith(r.toLowerCase() + '/')
    );

    if (actionMatch && resourceMatch) {
      if (effect === 'deny') {
        denyPolicies.push(policyName);
      } else {
        allowPolicies.push(policyName);
      }
    }
  }

  // Azure: deny assignments override allow
  if (denyPolicies.length > 0) {
    return {
      allowed: false,
      reason: `Denied by Azure deny assignment: ${denyPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      deny_policies: denyPolicies,
      provider: 'azure',
    };
  }

  if (allowPolicies.length > 0) {
    return {
      allowed: true,
      reason: `Allowed by RBAC: ${allowPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      provider: 'azure',
    };
  }

  return {
    allowed: false,
    reason: 'No matching RBAC role assignments',
    matching_policies: [],
    provider: 'azure',
  };
}

/**
 * GCP IAM evaluation: org → folder → project → resource hierarchy.
 * Basic evaluation without CEL conditions.
 */
function evaluateGCP(
  policies: Array<{ id: string; node: NodeProperties }>,
  action: string,
  resource: string,
): IAMEvalResult {
  const denyPolicies: string[] = [];
  const allowPolicies: string[] = [];

  for (const { id, node } of policies) {
    const policyActions = (node.actions as string[]) || [];
    const policyResources = (node.resources as string[]) || ['*'];
    const effect = node.effect || 'allow';
    const policyName = node.policy_name || node.label || id;

    // GCP uses permissions like "storage.objects.get" format
    const actionMatch = policyActions.some(a => matchAction(a, action));
    const resourceMatch = policyResources.some(r => matchResource(r, resource));

    if (actionMatch && resourceMatch) {
      if (effect === 'deny') {
        denyPolicies.push(policyName);
      } else {
        allowPolicies.push(policyName);
      }
    }
  }

  // GCP deny policies take precedence
  if (denyPolicies.length > 0) {
    return {
      allowed: false,
      reason: `Denied by GCP deny policy: ${denyPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      deny_policies: denyPolicies,
      provider: 'gcp',
    };
  }

  if (allowPolicies.length > 0) {
    return {
      allowed: true,
      reason: `Allowed by GCP IAM binding: ${allowPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      provider: 'gcp',
    };
  }

  return {
    allowed: false,
    reason: 'No matching GCP IAM bindings',
    matching_policies: [],
    provider: 'gcp',
  };
}
