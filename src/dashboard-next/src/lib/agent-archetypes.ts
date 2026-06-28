import { parseTargetBlob, hasParsedTargets } from './target-input';

// Phase 5c (dashboard side) — classify what the operator typed into the Deploy
// box (a raw IP/CIDR/domain → ad-hoc quick-deploy, vs. existing graph node ids →
// dispatch) and mirror the server recommender for instant UI pre-selection. The
// server (agent-archetypes.ts) is authoritative on the actual deploy; this is
// just to pre-pick the dropdown.

export type DeployInput =
  | { kind: 'raw'; target: string; cidrs: string[]; domains: string[]; invalid: string[] }
  | { kind: 'nodes'; nodeIds: string[] }
  // Both valid targets AND unrecognized tokens — ambiguous (raw targets and node
  // ids can't be deployed together), so the UI blocks rather than silently
  // dropping the extras.
  | { kind: 'mixed'; cidrs: string[]; domains: string[]; invalid: string[] }
  | { kind: 'empty' };

/**
 * Decide whether the Deploy input is raw targets (all valid IP/CIDR/domain →
 * quick-deploy) or graph node ids (→ dispatch). Reuses parseTargetBlob so the
 * raw classification matches the `scan`/Add-Targets rules exactly. Input that
 * mixes valid targets with unrecognized tokens is flagged `mixed` (blocking) so
 * an intended node id isn't silently discarded by the raw path.
 */
export function classifyDeployInput(text: string): DeployInput {
  const t = text.trim();
  if (!t) return { kind: 'empty' };
  const parsed = parseTargetBlob(t);
  if (hasParsedTargets(parsed)) {
    if (parsed.invalid.length > 0) {
      return { kind: 'mixed', cidrs: parsed.cidrs, domains: parsed.domains, invalid: parsed.invalid };
    }
    return { kind: 'raw', target: t, cidrs: parsed.cidrs, domains: parsed.domains, invalid: [] };
  }
  const nodeIds = t.split(/[\s,]+/).filter(Boolean);
  return nodeIds.length ? { kind: 'nodes', nodeIds } : { kind: 'empty' };
}

// Deploy-at-findings (Analysis workspace): from a tool run's targets, decide how
// a one-click follow-up deploy should route — at the discovered graph nodes
// (dispatch) or at the raw IPs/CIDRs the run hit (quick-deploy).
export type RunDeployPlan =
  | { mode: 'nodes'; nodeIds: string[] }
  | { mode: 'raw'; target: string }
  | { mode: 'none' };

export function deployTargetsFromRun(targetNodeIds: string[], targetIps: string[]): RunDeployPlan {
  if (targetNodeIds.length > 0) return { mode: 'nodes', nodeIds: targetNodeIds };
  if (targetIps.length > 0) return { mode: 'raw', target: targetIps.join(' ') };
  return { mode: 'none' };
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
    case 'domain':
    case 'subdomain':
    case 'organization':
    case 'asn':
    case 'email': return 'osint_recon';
    default: return 'default';
  }
}
