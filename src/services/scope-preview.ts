// ============================================================
// Scope-impact preview — "see the impact before you confirm"
// ============================================================
// A proposed scope change (add cidrs/domains/exclusions) doesn't ingest anything,
// but it DOES reshape what's in play: existing graph nodes transition in/out of
// scope, which is what determines the frontier. This computes that transition as a
// pure dry-run — no mutation — so the operator can see "this brings these 3 hosts
// into scope" on the confirm screen, before applying the plan.

import { isIpInScope, isHostnameInScope } from './cidr.js';

export interface ScopeSet {
  cidrs: string[];
  domains: string[];
  exclusions: string[];
}

export interface ScopeAdds {
  add_cidrs?: string[];
  add_domains?: string[];
  add_exclusions?: string[];
}

interface PreviewNode { id: string; properties: { ip?: string; hostname?: string; label?: string } }

export interface ScopePreview {
  newly_in_scope_count: number;
  newly_excluded_count: number;
  /** Sample of affected nodes (capped); counts above are exact. */
  newly_in_scope: { id: string; label: string }[];
  newly_excluded: { id: string; label: string }[];
}

const SAMPLE_CAP = 50;

function inScope(p: PreviewNode['properties'], scope: ScopeSet): boolean {
  if (p.ip && isIpInScope(p.ip, scope.cidrs, scope.exclusions)) return true;
  if (p.hostname && isHostnameInScope(p.hostname, scope.domains, scope.exclusions)) return true;
  return false;
}

/** Compute which existing nodes transition in/out of scope under a proposed change.
 *  Pure + deterministic; nodes without an ip or hostname are ignored (no scope identity). */
export function previewScopeChange(nodes: PreviewNode[], current: ScopeSet, adds: ScopeAdds): ScopePreview {
  const after: ScopeSet = {
    cidrs: [...current.cidrs, ...(adds.add_cidrs ?? [])],
    domains: [...current.domains, ...(adds.add_domains ?? [])],
    exclusions: [...current.exclusions, ...(adds.add_exclusions ?? [])],
  };
  const newly_in_scope: { id: string; label: string }[] = [];
  const newly_excluded: { id: string; label: string }[] = [];
  let inCount = 0;
  let exCount = 0;
  for (const n of nodes) {
    const p = n.properties;
    if (!p.ip && !p.hostname) continue;
    const before = inScope(p, current);
    const now = inScope(p, after);
    if (!before && now) { inCount += 1; if (newly_in_scope.length < SAMPLE_CAP) newly_in_scope.push({ id: n.id, label: p.label ?? n.id }); }
    else if (before && !now) { exCount += 1; if (newly_excluded.length < SAMPLE_CAP) newly_excluded.push({ id: n.id, label: p.label ?? n.id }); }
  }
  return { newly_in_scope_count: inCount, newly_excluded_count: exCount, newly_in_scope, newly_excluded };
}

/** Merge all scope ops in a plan into a single ScopeAdds (so the preview reflects the
 *  whole plan's net scope change). Returns null if the plan has no scope ops. */
export function mergeScopeAdds(ops: Array<{ op: string; add_cidrs?: string[]; add_domains?: string[]; add_exclusions?: string[] }>): ScopeAdds | null {
  const scopeOps = ops.filter(o => o.op === 'scope');
  if (scopeOps.length === 0) return null;
  return {
    add_cidrs: scopeOps.flatMap(o => o.add_cidrs ?? []),
    add_domains: scopeOps.flatMap(o => o.add_domains ?? []),
    add_exclusions: scopeOps.flatMap(o => o.add_exclusions ?? []),
  };
}
