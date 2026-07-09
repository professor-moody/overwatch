// ============================================================
// Node color encodings for the graph.
//
// The graph can color nodes by three things: their TYPE (default, one hue per
// node type — NODE_COLORS), their Louvain COMMUNITY (cluster membership — the
// biggest "de-jumble" signal), or their TIER (network/app/cloud/identity surface).
// GraphPage rewrites each node's stored `color` attr when the mode changes, so
// everything that reads `data.color` (minimap, reducer dimming) stays consistent.
// ============================================================

import { NODE_COLORS } from './graph-constants';
import { tierForNode, type Tier } from './tier';
import type { ExportedNode } from './types';

export type ColorMode = 'type' | 'community' | 'tier';

const FALLBACK_COLOR = '#8892a6';

// Colorblind-safe-ish categorical palette for communities. Deliberately distinct
// from the semantic edge palette so a community color isn't mistaken for an edge
// category. Communities are unnamed integers, so we hash the id into this palette.
export const COMMUNITY_PALETTE: string[] = [
  '#4e79a7', '#f28e2b', '#59a14f', '#e15759', '#b07aa1', '#76b7b2',
  '#edc948', '#ff9da7', '#9c755f', '#bab0ac', '#86bcb6', '#d37295',
  '#8cd17d', '#b6992d', '#499894', '#fabfd2',
];

export const TIER_COLORS: Record<Tier, string> = {
  network: '#6e9eff',
  app: '#4ecdc4',
  cloud: '#e6a459',
  identity: '#b89af2',
  unknown: FALLBACK_COLOR,
};

export const TIER_ORDER: Tier[] = ['network', 'app', 'cloud', 'identity', 'unknown'];

/** Stable color for a community id (undefined → neutral fallback). */
export function communityColor(id: number | undefined): string {
  if (typeof id !== 'number' || !Number.isFinite(id)) return FALLBACK_COLOR;
  // id can be negative in theory; make the index non-negative and in-range.
  const idx = ((id % COMMUNITY_PALETTE.length) + COMMUNITY_PALETTE.length) % COMMUNITY_PALETTE.length;
  return COMMUNITY_PALETTE[idx];
}

/**
 * Resolve a node's color under the given mode from its stored graphology attrs.
 * `attrs` carries `nodeType`, `community` (the Louvain id), and `_props` (the raw
 * ExportedNode) as written in useGraph.loadGraphData.
 */
export function colorForNode(
  attrs: { nodeType?: string; community?: number; _props?: unknown },
  mode: ColorMode,
): string {
  if (mode === 'community') return communityColor(attrs.community);
  if (mode === 'tier') return TIER_COLORS[tierForNode(attrs._props as ExportedNode | undefined)];
  return NODE_COLORS[attrs.nodeType || ''] || FALLBACK_COLOR;
}
