import { parseTargetBlob, hasParsedTargets } from './target-input';

// Phase 5c (dashboard side) — classify what the operator typed into the Deploy
// box (a raw IP/CIDR/domain → ad-hoc quick-deploy, vs. existing graph node ids →
// dispatch) and mirror the server recommender for instant UI pre-selection. The
// server (agent-archetypes.ts) is authoritative on the actual deploy; this is
// just to pre-pick the dropdown.

export type DeployInput =
  | { kind: 'raw'; target: string; cidrs: string[]; domains: string[]; invalid: string[] }
  | { kind: 'nodes'; nodeIds: string[] }
  | { kind: 'empty' };

/**
 * Decide whether the Deploy input is raw targets (any valid IP/CIDR/domain →
 * quick-deploy) or graph node ids (→ dispatch). Reuses parseTargetBlob so the
 * raw classification matches the `scan`/Add-Targets rules exactly.
 */
export function classifyDeployInput(text: string): DeployInput {
  const t = text.trim();
  if (!t) return { kind: 'empty' };
  const parsed = parseTargetBlob(t);
  if (hasParsedTargets(parsed)) {
    return { kind: 'raw', target: t, cidrs: parsed.cidrs, domains: parsed.domains, invalid: parsed.invalid };
  }
  const nodeIds = t.split(/[\s,]+/).filter(Boolean);
  return nodeIds.length ? { kind: 'nodes', nodeIds } : { kind: 'empty' };
}

/** Client mirror of the server recommendArchetype (instant UI default). */
export function recommendArchetypeFor(input: { rawTarget?: boolean; nodeType?: string }): string {
  if (input.rawTarget) return 'recon_scanner';
  switch (input.nodeType) {
    case 'credential': return 'credential_operator';
    case 'webapp':
    case 'url': return 'web_tester';
    case 'host':
    case 'service': return 'recon_scanner';
    default: return 'default';
  }
}
