// ============================================================
// Hub-explode layout pass.
//
// Force-directed layout is bad at STAR structures — a domain with 30 subdomains,
// or a host with many ports/services, all get pulled to the same edge-length from
// the hub and pile into a tight, unreadable ring on top of it. This post-pass takes
// each hub's LEAF children (nodes whose only connection is that hub) and fans them
// out into concentric rings around the hub, so subdomains/ports/etc. spread instead
// of stacking. Deterministic; leaves non-leaf nodes and pinned nodes where they are.
// ============================================================

import type Graph from 'graphology';

export interface ExplodeHubsOptions {
  /** Only explode a hub with at least this many leaf children (small stars lay out
   *  fine under force + noverlap). */
  minLeaves?: number;
  /** Gap between adjacent leaves on a ring, as a FRACTION of the graph's current
   *  coordinate span. Fraction (not absolute units) so the fan stays proportional
   *  regardless of the layout's scale (positions are normalized to an arbitrary
   *  span, so absolute units would make one big hub blanket the whole graph). */
  spacingRatio?: number;
  /** Radius added per ring outward from the hub, as a fraction of the graph span. */
  ringStepRatio?: number;
}

const DEFAULTS: Required<ExplodeHubsOptions> = { minLeaves: 6, spacingRatio: 0.03, ringStepRatio: 0.045 };

/**
 * Fan each hub's leaf children into rings around it. A "leaf" is a node with
 * exactly one distinct neighbour (so moving it can't distort any other
 * relationship) — this is exactly the subdomain-on-domain / port-on-host case.
 * Ring geometry is sized relative to the graph's current coordinate span, so the
 * fan is proportional whatever scale the layout settled at. Returns the number of
 * hubs it exploded (for logging/tests).
 */
export function explodeHubs(graph: Graph, options: ExplodeHubsOptions = {}): number {
  const { minLeaves, spacingRatio, ringStepRatio } = { ...DEFAULTS, ...options };

  // Measure the current coordinate span to size the fan proportionally.
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  graph.forEachNode((_id, a) => {
    const x = a.x as number, y = a.y as number;
    if (!Number.isFinite(x) || !Number.isFinite(y)) return;
    minX = Math.min(minX, x); maxX = Math.max(maxX, x);
    minY = Math.min(minY, y); maxY = Math.max(maxY, y);
  });
  const span = Number.isFinite(minX) ? Math.max(maxX - minX, maxY - minY) || 100 : 100;
  const spacing = span * spacingRatio;
  const ringStep = span * ringStepRatio;
  let exploded = 0;

  graph.forEachNode((hubId, hubAttrs) => {
    const hx = hubAttrs.x as number;
    const hy = hubAttrs.y as number;
    if (!Number.isFinite(hx) || !Number.isFinite(hy)) return;

    // Collect this hub's true leaf children: exactly one distinct neighbour (the
    // hub) and not pinned. `neighbors` is distinct, so parallel multigraph edges
    // don't inflate the count.
    const leaves: string[] = [];
    graph.forEachNeighbor(hubId, (leafId, leafAttrs) => {
      if (leafAttrs.fixed) return;
      if (graph.neighbors(leafId).length === 1) leaves.push(leafId);
    });
    if (leaves.length < minLeaves) return;

    // Stable order so the fan is deterministic across reloads.
    leaves.sort();

    let placed = 0;
    let ring = 1;
    while (placed < leaves.length) {
      const radius = ring * ringStep;
      const capacity = Math.max(1, Math.floor((2 * Math.PI * radius) / spacing));
      const count = Math.min(capacity, leaves.length - placed);
      for (let i = 0; i < count; i++) {
        // Offset each ring's start angle so successive rings interleave.
        const angle = (i / count) * 2 * Math.PI + ring * 0.6;
        const id = leaves[placed + i];
        graph.setNodeAttribute(id, 'x', hx + radius * Math.cos(angle));
        graph.setNodeAttribute(id, 'y', hy + radius * Math.sin(angle));
      }
      placed += count;
      ring++;
    }
    exploded++;
  });

  return exploded;
}
