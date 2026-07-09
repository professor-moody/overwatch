// ============================================================
// Deterministic, structured graph layouts — the fix for "force-directed is always
// a hairball for this heterogeneous graph." These write x/y directly onto the
// graphology nodes (skipping pinned/`fixed` ones); GraphPage treats them as transient
// views (they don't touch the saved-position store). The camera + normalizeAutoLayout
// handle final scaling, so the geometry here only needs to be internally consistent.
// ============================================================

import dagre from '@dagrejs/dagre';
import type Graph from 'graphology';
import { tierForNode, type Tier } from './tier';
import type { ExportedNode } from './types';

export type LayoutType = 'force' | 'hierarchical' | 'tiered';

// Edge types that don't express attack STRUCTURE — the reachability mesh and generic
// links. Excluded from the hierarchical ranking so the flow reflects real movement
// (matches the path-tracer, which also ignores reachability/OSINT noise).
const NON_STRUCTURAL_EDGE_TYPES = new Set(['REACHABLE', 'RELATED']);

/**
 * Hierarchical "attack-flow" layout via dagre: ranks nodes top-to-bottom following
 * edge direction (source → target), so you read what leads to what. Parallel/cyclic
 * edges are handled by dagre; reachability/generic edges are excluded from ranking
 * to keep the hierarchy clean.
 */
export function computeHierarchical(graph: Graph): void {
  const g = new dagre.graphlib.Graph({ multigraph: true, directed: true });
  // Generous separation so ranks/rows don't collide (normalizeAutoLayout rescales the
  // whole thing afterward, so these are relative spacings, kept large vs node size).
  g.setGraph({ rankdir: 'TB', nodesep: 80, ranksep: 140, marginx: 30, marginy: 30 });
  g.setDefaultEdgeLabel(() => ({}));

  graph.forEachNode((id, attrs) => {
    const size = (attrs.size as number) || 6;
    g.setNode(id, { width: Math.max(30, size * 4), height: Math.max(30, size * 4) });
  });

  let i = 0;
  graph.forEachEdge((_edgeId, attrs, source, target) => {
    if (NON_STRUCTURAL_EDGE_TYPES.has((attrs.edgeType as string) || '')) return;
    g.setEdge(source, target, {}, `e${i++}`);
  });

  dagre.layout(g);

  graph.forEachNode((id, attrs) => {
    if (attrs.fixed) return;
    const n = g.node(id);
    if (n && Number.isFinite(n.x) && Number.isFinite(n.y)) {
      graph.setNodeAttribute(id, 'x', n.x);
      graph.setNodeAttribute(id, 'y', n.y);
    }
  });
}

// Vertical band order for the tiered layout (top → bottom).
const TIER_BAND: Record<Tier, number> = { identity: 0, cloud: 1, app: 2, network: 3, unknown: 4 };

/**
 * Tiered layout: horizontal bands by role (identity / cloud / app / network), each
 * band wrapped into a grid so a populous tier (e.g. hundreds of hosts) doesn't become
 * one endless row. Fully deterministic — you always know where a class of node lives.
 */
export function computeTiered(graph: Graph): void {
  const bands = new Map<number, string[]>();
  graph.forEachNode((id, attrs) => {
    if (attrs.fixed) return;
    const band = TIER_BAND[tierForNode(attrs._props as ExportedNode | undefined)] ?? 4;
    const arr = bands.get(band);
    if (arr) arr.push(id); else bands.set(band, [id]);
  });

  const colGap = 48;
  const rowGap = 44;
  const bandGap = 140; // vertical gap between the start of one tier's block and the next
  let bandTop = 0;

  for (const band of [...bands.keys()].sort((a, b) => a - b)) {
    const ids = bands.get(band)!.sort();
    // Wrap into a roughly-square grid so wide tiers stay compact and readable.
    const cols = Math.max(1, Math.ceil(Math.sqrt(ids.length * 1.8)));
    const gridWidth = (cols - 1) * colGap;
    ids.forEach((id, idx) => {
      const col = idx % cols;
      const row = Math.floor(idx / cols);
      graph.setNodeAttribute(id, 'x', col * colGap - gridWidth / 2);
      graph.setNodeAttribute(id, 'y', bandTop + row * rowGap);
    });
    const rowsUsed = Math.ceil(ids.length / cols);
    bandTop += rowsUsed * rowGap + bandGap;
  }
}
