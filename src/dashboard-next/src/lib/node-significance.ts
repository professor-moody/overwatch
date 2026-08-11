import type { ExportedNode, SourceTrust } from './types';
import type { Tier } from './tier';
import { tierForNode } from './tier';
import { getFriendlyNodeTypeLabel } from './node-display';
import { formatRelativeTime } from './utils';

/** Why an operator should care about a node: is it an objective, a high-value target,
 *  or a routine asset — and which trust tier it sits in. Node significance and node
 *  provenance are computed from fields the backend already stamps on exported nodes
 *  (`objective_*`, `hvt*`, `source_trust`, `confidence`, `discovered_*`), so the drawer
 *  can lead with "why this matters" instead of a flat property dump. */
export type NodeRole = 'objective' | 'hvt' | 'standard';

export interface NodeSignificance {
  role: NodeRole;
  /** Chip label: "Objective" | "High-value target" | the friendly node-type name. */
  roleLabel: string;
  /** One-line reason from the backend, when it recorded one (objective_description /
   *  hvt_reason). */
  roleDetail?: string;
  /** Only meaningful for an objective: whether it has actually been reached. */
  achieved: boolean;
  tier: Tier;
}

export interface NodeProvenance {
  /** observed | asserted | inferred — how the node came to be known. */
  sourceTrust?: SourceTrust;
  /** 0-100, rounded; null when the backend sent no confidence. */
  confidencePct: number | null;
  /** Relative "2h ago", when discovered_at is present. */
  discoveredAgo?: string;
  /** Agent id that first observed it. */
  discoveredBy?: string;
  /** True when an action id is recorded — the node can be traced to its run/evidence
   *  (explain_action). */
  traceable: boolean;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function isSourceTrust(value: unknown): value is SourceTrust {
  return value === 'observed' || value === 'asserted' || value === 'inferred';
}

export function nodeSignificance(props: Record<string, unknown>, nodeType: string): NodeSignificance {
  const tier = tierForNode({ type: nodeType } as ExportedNode);
  const achieved = props.objective_achieved === true;
  // Most objectives are ordinary nodes (a host, a cloud identity) flagged as the goal,
  // so detect the flag/description — not just the rare type === 'objective'.
  const isObjective = nodeType === 'objective' || achieved || !!str(props.objective_description);
  const isHvt = props.hvt === true;

  if (isObjective) {
    return { role: 'objective', roleLabel: 'Objective', roleDetail: str(props.objective_description), achieved, tier };
  }
  if (isHvt) {
    return { role: 'hvt', roleLabel: 'High-value target', roleDetail: str(props.hvt_reason), achieved: false, tier };
  }
  return {
    role: 'standard',
    roleLabel: getFriendlyNodeTypeLabel(nodeType).replace(/s$/, ''),
    achieved: false,
    tier,
  };
}

export function nodeProvenance(props: Record<string, unknown>): NodeProvenance {
  const confidence = typeof props.confidence === 'number' && Number.isFinite(props.confidence) ? props.confidence : null;
  return {
    sourceTrust: isSourceTrust(props.source_trust) ? props.source_trust : undefined,
    confidencePct: confidence === null ? null : Math.round(confidence * 100),
    discoveredAgo: str(props.discovered_at) ? formatRelativeTime(String(props.discovered_at)) : undefined,
    discoveredBy: str(props.discovered_by),
    traceable: !!str(props.discovered_by_action_id),
  };
}
