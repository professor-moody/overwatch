// ============================================================
// Tier classification for dashboard graph nodes.
//
// Mirrors `src/services/finding-classifier.ts:inferFindingTier` (which
// runs server-side) but operates on dashboard-shape nodes (flat
// properties, not nested under .properties). Pure function — no I/O.
// ============================================================

import type { ExportedNode } from './types';

export type Tier = 'network' | 'app' | 'cloud' | 'identity' | 'unknown';

/** Classify a single graph node by its declared `type`. */
export function tierForNode(node: ExportedNode | undefined): Tier {
  if (!node) return 'unknown';
  switch (node.type) {
    case 'host':
    case 'service':
    case 'subnet':
    case 'domain':
    case 'user':
    case 'group':
    case 'credential':
    case 'share':
    case 'certificate':
    case 'ca':
    case 'cert_template':
    case 'pki_store':
    case 'gpo':
    case 'ou':
    case 'mock_service':
      return 'network';
    case 'webapp':
    case 'api_endpoint':
    case 'vulnerability':
      return 'app';
    case 'cloud_resource':
    case 'cloud_identity':
    case 'cloud_policy':
    case 'cloud_network':
      return 'cloud';
    case 'idp':
    case 'idp_application':
    case 'idp_principal':
      return 'identity';
    default:
      return 'unknown';
  }
}

/**
 * Set of tiers a path traverses. Used to classify a path as cross-tier
 * (multiple tiers visited) vs single-tier.
 */
export function tiersForPath(nodeIds: string[], byId: Map<string, ExportedNode>): Set<Tier> {
  const out = new Set<Tier>();
  for (const id of nodeIds) {
    const t = tierForNode(byId.get(id));
    if (t !== 'unknown') out.add(t);
  }
  return out;
}

export function isCrossTierPath(nodeIds: string[], byId: Map<string, ExportedNode>): boolean {
  return tiersForPath(nodeIds, byId).size >= 2;
}
