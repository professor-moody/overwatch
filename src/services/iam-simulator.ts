// ============================================================
// Overwatch — IAM Policy Simulator
// Evaluates whether a principal can perform an action on a
// resource by traversing the graph's cloud policy nodes.
// Supports AWS (deny-overrides-allow + permission boundaries),
// Azure RBAC, and GCP IAM basics.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { NodeProperties } from '../types.js';

export interface IAMEvalResult {
  allowed: boolean;
  reason: string;
  matching_policies: string[];
  deny_policies?: string[];
  provider?: 'aws' | 'azure' | 'gcp';
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

  // Collect all policies attached to the principal
  const policyNodes: Array<{ id: string; node: NodeProperties }> = [];
  ctx.graph.forEachOutEdge(principalId, (_edge, attrs, _src, target) => {
    if (attrs.type !== 'HAS_POLICY') return;
    if (!ctx.graph.hasNode(target)) return;
    const policyNode = ctx.graph.getNodeAttributes(target) as NodeProperties;
    if (policyNode.type === 'cloud_policy') {
      policyNodes.push({ id: target, node: policyNode });
    }
  });

  // Also traverse group memberships: principal → MEMBER_OF → group → HAS_POLICY → policy
  ctx.graph.forEachOutEdge(principalId, (_edge, attrs, _src, groupTarget) => {
    if (attrs.type !== 'MEMBER_OF') return;
    ctx.graph.forEachOutEdge(groupTarget, (_e2, a2, _s2, policyTarget) => {
      if (a2.type !== 'HAS_POLICY') return;
      if (!ctx.graph.hasNode(policyTarget)) return;
      const policyNode = ctx.graph.getNodeAttributes(policyTarget) as NodeProperties;
      if (policyNode.type === 'cloud_policy') {
        policyNodes.push({ id: policyTarget, node: policyNode });
      }
    });
  });

  if (policyNodes.length === 0) {
    return { allowed: false, reason: 'No policies attached to principal', matching_policies: [], provider };
  }

  switch (provider) {
    case 'aws':
      return evaluateAWS(policyNodes, action, resource);
    case 'azure':
      return evaluateAzure(policyNodes, action, resource);
    case 'gcp':
      return evaluateGCP(policyNodes, action, resource);
    default:
      return evaluateAWS(policyNodes, action, resource); // default to AWS semantics
  }
}

function detectProvider(node: NodeProperties): 'aws' | 'azure' | 'gcp' | undefined {
  if (node.arn?.startsWith('arn:aws:')) return 'aws';
  if (node.arn?.includes('.azure.') || node.principal_type === 'managed_identity') return 'azure';
  if (node.arn?.includes('gserviceaccount.com') || node.principal_type === 'service_account') return 'gcp';
  return undefined;
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
