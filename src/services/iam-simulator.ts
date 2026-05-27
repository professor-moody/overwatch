// ============================================================
// Overwatch — IAM Policy Simulator
// Evaluates whether a principal can perform an action on a
// resource by traversing the graph's cloud policy nodes.
// Supports AWS (deny-overrides-allow + permission boundaries),
// Azure RBAC, and GCP IAM basics.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { EdgeProperties, NodeProperties } from '../types.js';
import { expandAzureRole } from './azure-roles.js';

/**
 * A policy attached to a principal (directly or via group), enriched
 * with the edge attrs that attached it. For Azure the edge carries
 * the assignment `scope` and `role_definition_name` — without those
 * the simulator cannot answer scoped questions correctly.
 */
type AttachedPolicy = {
  id: string;
  node: NodeProperties;
  assignment_scope?: string;
  role_definition_name?: string;
};

export interface IAMEvalResult {
  allowed: boolean;
  decision: 'allowed' | 'denied' | 'indeterminate';
  reason: string;
  matching_policies: string[];
  deny_policies?: string[];
  provider?: 'aws' | 'azure' | 'gcp';
  evaluated_principals?: string[];
  assumption_paths?: string[][];
  /** Policies that were enumerated but not permission-expanded (e.g.
   * Azure built-in roles not yet in our mapping table). Caller should
   * treat these as "unknown — could be allow OR deny". */
  enumerated_only_policies?: string[];
  depth_capped?: boolean;
  warnings?: string[];
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
    return { allowed: false, decision: 'denied', reason: 'Principal not found in graph', matching_policies: [] };
  }

  const principal = ctx.graph.getNodeAttributes(principalId) as NodeProperties;
  const provider = principal.provider || detectProvider(principal);

  // Collect all policies attached to the principal and confirmed assumable roles.
  const policyNodes: AttachedPolicy[] = [];
  const seenPolicies = new Set<string>();
  const evaluatedPrincipals: string[] = [];
  const assumptionPaths: string[][] = [];
  const queue: Array<{ id: string; path: string[] }> = [{ id: principalId, path: [principalId] }];
  const visited = new Set<string>();
  const maxAssumeDepth = ctx.config.iam_assume_depth ?? 5;
  let depthCapped = false;

  function addPolicy(policy: AttachedPolicy): void {
    // Same policy node may be attached at multiple scopes / via group +
    // direct: keep distinct by id+scope so Azure scope analysis sees both.
    const key = `${policy.id}::${policy.assignment_scope ?? ''}`;
    if (seenPolicies.has(key)) return;
    seenPolicies.add(key);
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

      if (attrs.type === 'ASSUMES_ROLE' && ctx.graph.hasNode(target)) {
        if (current.path.length - 1 >= maxAssumeDepth) {
          depthCapped = true;
          return;
        }
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
      decision: depthCapped ? 'indeterminate' : 'denied',
      reason: 'No policies attached to principal or assumable roles',
      matching_policies: [],
      provider,
      evaluated_principals: evaluatedPrincipals,
      assumption_paths: assumptionPaths,
      depth_capped: depthCapped || undefined,
      warnings: depthCapped ? [`IAM assume-role traversal hit configured depth cap (${maxAssumeDepth})`] : undefined,
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
  if (depthCapped && result.decision === 'denied' && result.matching_policies.length === 0 && !result.deny_policies?.length) {
    result = {
      ...result,
      decision: 'indeterminate',
      reason: `${result.reason}; IAM assume-role traversal hit configured depth cap (${maxAssumeDepth})`,
    };
  }
  return {
    ...result,
    evaluated_principals: evaluatedPrincipals,
    assumption_paths: assumptionPaths,
    depth_capped: depthCapped || undefined,
    warnings: depthCapped
      ? [...(result.warnings ?? []), `IAM assume-role traversal hit configured depth cap (${maxAssumeDepth})`]
      : result.warnings,
  };
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
): AttachedPolicy[] {
  const policies: AttachedPolicy[] = [];
  const seen = new Set<string>();

  function addPolicy(policyTarget: string, edgeAttrs: EdgeProperties): void {
    if (!ctx.graph.hasNode(policyTarget)) return;
    const policyNode = ctx.graph.getNodeAttributes(policyTarget) as NodeProperties;
    if (policyNode.type !== 'cloud_policy') return;
    // Allow same policy with different scope to register twice — the
    // simulator's outer dedupe handles id+scope uniqueness.
    const e = edgeAttrs as unknown as { scope?: string; role_definition_name?: string };
    const key = `${policyTarget}::${e.scope ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    policies.push({
      id: policyTarget,
      node: policyNode,
      assignment_scope: e.scope,
      role_definition_name: e.role_definition_name,
    });
  }

  ctx.graph.forEachOutEdge(principalId, (_edge, attrs, _src, target) => {
    if (attrs.type === 'HAS_POLICY') {
      addPolicy(target, attrs as EdgeProperties);
      return;
    }

    // Group memberships: principal → MEMBER_OF → group → HAS_POLICY → policy
    if (attrs.type === 'MEMBER_OF') {
      ctx.graph.forEachOutEdge(target, (_e2, a2, _s2, policyTarget) => {
        if (a2.type === 'HAS_POLICY') addPolicy(policyTarget, a2 as EdgeProperties);
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
  policies: AttachedPolicy[],
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
      decision: 'denied',
      reason: `Explicitly denied by: ${denyPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      deny_policies: denyPolicies,
      provider: 'aws',
    };
  }

  if (allowPolicies.length > 0) {
    return {
      allowed: true,
      decision: 'allowed',
      reason: `Allowed by: ${allowPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      provider: 'aws',
    };
  }

  return {
    allowed: false,
    decision: 'denied',
    reason: 'Implicitly denied — no matching allow policies',
    matching_policies: [],
    provider: 'aws',
  };
}

/**
 * Azure RBAC evaluation: role assignments with scope hierarchy matching.
 *
 * For each attached policy we use:
 *  - `actions` from the policy node if present (set during ingest from the
 *    azure-roles built-in mapping table);
 *  - if missing, expand on the fly from `role_definition_name` carried on
 *    the edge — and if still unknown, record the policy as `enumerated_only`
 *    so the caller does not silently get an "implicit deny".
 *  - the assignment `scope` from the edge constrains resource matching:
 *    a Reader@RG/foo assignment must NOT match resources outside RG/foo.
 */
function evaluateAzure(
  policies: AttachedPolicy[],
  action: string,
  resource: string,
): IAMEvalResult {
  const denyPolicies: string[] = [];
  const allowPolicies: string[] = [];
  const enumeratedOnly: string[] = [];

  for (const { id, node, assignment_scope, role_definition_name } of policies) {
    const policyName = node.policy_name || node.label || id;
    const effect = node.effect || 'allow';

    // Resolve effective actions: prefer node-stored, then expand role on demand.
    let policyActions = (node.actions as string[]) || [];
    let notActions: string[] = (node.not_actions as string[]) || [];
    let expanded = policyActions.length > 0 || (node.permission_expansion as string) === 'expanded';
    if (!expanded) {
      const roleName = role_definition_name || (node.role_definition_name as string) || policyName;
      const exp = expandAzureRole(roleName);
      if (exp.expanded) {
        policyActions = exp.actions;
        notActions = exp.not_actions;
        expanded = true;
      }
    }

    // Effective scope: prefer the edge scope (per-assignment), then the
    // node's recorded scope, then policy.resources, then '*'.
    const scopeFromNode = (node.assignment_scope as string) || undefined;
    const scopes: string[] = assignment_scope
      ? [assignment_scope]
      : scopeFromNode
        ? [scopeFromNode]
        : (node.resources as string[]) || ['*'];

    if (!expanded) {
      // We know the role exists and is assigned at this scope, but cannot
      // tell if it grants `action`. Surface as enumerated_only.
      enumeratedOnly.push(policyName);
      continue;
    }

    const actionMatch = policyActions.some(a => matchAction(a, action));
    const notActionMatch = notActions.some(a => matchAction(a, action));
    const resourceMatch = scopes.some(r =>
      r === '*' ||
      matchResource(r, resource) ||
      resource.toLowerCase().startsWith(r.toLowerCase() + '/')
    );

    if (actionMatch && !notActionMatch && resourceMatch) {
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
      decision: 'denied',
      reason: `Denied by Azure deny assignment: ${denyPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      deny_policies: denyPolicies,
      provider: 'azure',
      enumerated_only_policies: enumeratedOnly.length ? enumeratedOnly : undefined,
    };
  }

  if (allowPolicies.length > 0) {
    return {
      allowed: true,
      decision: 'allowed',
      reason: `Allowed by RBAC: ${allowPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      provider: 'azure',
      enumerated_only_policies: enumeratedOnly.length ? enumeratedOnly : undefined,
    };
  }

  if (enumeratedOnly.length > 0) {
    // We saw role assignments but cannot expand them — caller MUST treat
    // this as “unknown” rather than “denied”.
    return {
      allowed: false,
      decision: 'indeterminate',
      reason: `Indeterminate — ${enumeratedOnly.length} role assignment(s) enumerated but not permission-expanded: ${enumeratedOnly.join(', ')}`,
      matching_policies: [],
      provider: 'azure',
      enumerated_only_policies: enumeratedOnly,
    };
  }

  return {
    allowed: false,
    decision: 'denied',
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
  policies: AttachedPolicy[],
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
      decision: 'denied',
      reason: `Denied by GCP deny policy: ${denyPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      deny_policies: denyPolicies,
      provider: 'gcp',
    };
  }

  if (allowPolicies.length > 0) {
    return {
      allowed: true,
      decision: 'allowed',
      reason: `Allowed by GCP IAM binding: ${allowPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      provider: 'gcp',
    };
  }

  return {
    allowed: false,
    decision: 'denied',
    reason: 'No matching GCP IAM bindings',
    matching_policies: [],
    provider: 'gcp',
  };
}
