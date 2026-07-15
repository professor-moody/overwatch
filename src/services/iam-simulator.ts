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
 * Linear wildcard matcher supporting `*` (any run) and `?` (one char).
 * Iterative with backtrack-to-last-star — O(n·m) worst case and, crucially,
 * NO exponential blowup. The previous approach built a regex by turning each
 * `*` into a dot-star, which catastrophically backtracked on a many-`*` ARN
 * pattern (e.g. `arn:*:*:*:*:*:*`) tested against a long non-matching
 * resource (ReDoS). This two-pointer scan has no such failure mode.
 */
function globMatch(pat: string, text: string): boolean {
  let p = 0, t = 0, star = -1, mark = 0;
  while (t < text.length) {
    if (p < pat.length && (pat[p] === '?' || pat[p] === text[t])) { p++; t++; }
    else if (p < pat.length && pat[p] === '*') { star = p++; mark = t; }
    else if (star !== -1) { p = star + 1; t = ++mark; }
    else return false;
  }
  while (p < pat.length && pat[p] === '*') p++;
  return p === pat.length;
}

/**
 * Match a string against an IAM pattern with star/question wildcards ANYWHERE,
 * not just as a trailing star — AWS allows mid-string wildcards like
 * `s3:*Object`, `iam:Get*Policy`, or a bucket key glob with a star in the
 * middle of the path.
 */
function matchGlob(pattern: string, value: string): boolean {
  const p = pattern.toLowerCase();
  const v = value.toLowerCase();
  if (p === '*') return true;
  if (p === v) return true;
  const hasStar = p.includes('*');
  const hasQuestion = p.includes('?');
  if (!hasStar && !hasQuestion) return false;
  // Fast path: a single trailing `*` with no other wildcard is a prefix test.
  if (hasStar && !hasQuestion && p.indexOf('*') === p.length - 1) {
    return v.startsWith(p.slice(0, -1));
  }
  return globMatch(p, v);
}

/**
 * Match an action string against an action pattern (wildcards anywhere).
 * e.g. "s3:GetObject" matches "s3:*", "*", "s3:Get*", "s3:*Object".
 */
function matchAction(pattern: string, action: string): boolean {
  // `*:*` is the AWS "all services, all actions" form — an ACTION-only idiom
  // (not a resource pattern; resources use plain `*` / ARNs).
  if (pattern.toLowerCase() === '*:*') return true;
  return matchGlob(pattern, action);
}

/**
 * Match a resource ARN/ID against a resource pattern (wildcards anywhere).
 */
function matchResource(pattern: string, resource: string): boolean {
  return matchGlob(pattern, resource);
}

/**
 * Evaluate a statement's Action/NotAction (or Resource/NotResource) list pair
 * against a query value. AWS uses Action XOR NotAction, but if both are present
 * (invalid, but be safe) BOTH must be satisfied. A NotAction/NotResource means
 * "everything EXCEPT these", so a match-all query (`*` / empty — the "can P do A
 * anywhere?" placeholder) can NOT be affirmatively covered by an exclusion
 * statement (it always excludes a subset). Treat it as non-matching — the same
 * way a scoped positive list fails a `*` query — so a NotResource statement no
 * longer answers a blanket "yes" (or, for a deny, a blanket "no").
 */
function matchWithNot(
  positive: string[],
  negative: string[],
  value: string,
  valueIsAll: boolean,
  matcher: (pattern: string, value: string) => boolean,
): boolean {
  const hasPos = positive.length > 0;
  const hasNeg = negative.length > 0;
  if (!hasPos && !hasNeg) return false;
  // For a match-all ("anywhere") query, a positive statement satisfies it only
  // if it is genuinely blanket (`*` / `*:*`) — a scoped pattern that merely
  // glob-matches the literal one-char string `*` (e.g. `?`) must not answer
  // "anywhere? yes". Keeps the positive and negative branches consistent about
  // what "all" means.
  const posOk = hasPos
    ? (valueIsAll ? positive.some(isMatchAllPattern) : positive.some(p => matcher(p, value)))
    : true;
  const negOk = hasNeg ? (!valueIsAll && !negative.some(p => matcher(p, value))) : true;
  return posOk && negOk;
}

/** True for the genuinely "everything" IAM patterns (`*` and the AWS `*:*`). */
function isMatchAllPattern(pattern: string): boolean {
  const p = pattern.trim().toLowerCase();
  return p === '*' || p === '*:*';
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
  const conditionalDenyPolicies: string[] = [];
  const conditionalAllowPolicies: string[] = [];
  const enumeratedOnlyPolicies: string[] = [];

  for (const { id, node } of policies) {
    const policyName = node.policy_name || node.label || id;
    if (node.permission_expansion === 'unevaluable') {
      enumeratedOnlyPolicies.push(policyName);
      continue;
    }
    const policyActions = (node.actions as string[]) || [];
    // `|| ['*']` only fills in when `resources` is UNDEFINED (a source that
    // omits it → match-all, preserving prior behavior). A present-but-empty `[]`
    // (a NotResource statement, or the unparsed-policy fallback node) stays empty
    // so the NotResource branch / implicit-deny path below handles it.
    const policyResources = (node.resources as string[]) || ['*'];
    const policyNotActions = (node.not_actions as string[]) || [];
    const policyNotResources = (node.not_resources as string[]) || [];
    const effect = node.effect || 'allow';

    // AWS uses Action XOR NotAction (and Resource XOR NotResource). NotAction
    // means "every action EXCEPT these"; ignoring it turned a broad "Allow
    // NotAction: iam:*" into an empty allow, and a "Deny NotAction: …" into a
    // no-op deny (over-permissive). matchWithNot applies the correct semantics,
    // including treating a `*`/empty "anywhere" query as non-matching against an
    // exclusion statement (so it can't answer a blanket allow/deny).
    const actionIsAll = action === '*' || action === '*:*' || action === '';
    const resourceIsAll = resource === '*' || resource === '';
    const actionMatch = matchWithNot(policyActions, policyNotActions, action, actionIsAll, matchAction);
    const resourceMatch = matchWithNot(policyResources, policyNotResources, resource, resourceIsAll, matchResource);

    if (actionMatch && resourceMatch) {
      if (node.condition_present === true && effect === 'deny') {
        conditionalDenyPolicies.push(policyName);
      } else if (node.condition_present === true) {
        conditionalAllowPolicies.push(policyName);
      } else if (effect === 'deny') {
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

  if (enumeratedOnlyPolicies.length > 0) {
    return {
      allowed: false,
      decision: 'indeterminate',
      reason: `Attached AWS policies were enumerated but their statements were not expanded: ${enumeratedOnlyPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      deny_policies: conditionalDenyPolicies.length > 0 ? conditionalDenyPolicies : undefined,
      enumerated_only_policies: enumeratedOnlyPolicies,
      provider: 'aws',
      warnings: ['Fetch or parse the attached policy documents before treating this result as an allow or deny.'],
    };
  }

  if (allowPolicies.length > 0) {
    if (conditionalDenyPolicies.length > 0) {
      return {
        allowed: false,
        decision: 'indeterminate',
        reason: `An unconditional allow matches, but conditional deny policy applicability is unknown: ${conditionalDenyPolicies.join(', ')}`,
        matching_policies: allowPolicies,
        deny_policies: conditionalDenyPolicies,
        provider: 'aws',
        warnings: ['AWS Condition blocks were not evaluated because no request context was provided.'],
      };
    }
    return {
      allowed: true,
      decision: 'allowed',
      reason: `Allowed by: ${allowPolicies.join(', ')}`,
      matching_policies: allowPolicies,
      provider: 'aws',
    };
  }

  if (conditionalAllowPolicies.length > 0) {
    return {
      allowed: false,
      decision: 'indeterminate',
      reason: `Only conditional allow policies match, and their conditions could not be evaluated: ${conditionalAllowPolicies.join(', ')}`,
      matching_policies: conditionalAllowPolicies,
      deny_policies: conditionalDenyPolicies.length > 0 ? conditionalDenyPolicies : undefined,
      provider: 'aws',
      warnings: ['AWS Condition blocks were not evaluated because no request context was provided.'],
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
