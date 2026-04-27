// ============================================================
// useCommunityHulls — draw convex hulls around graph communities
// ============================================================

import { useEffect, useRef, useCallback } from 'react';
import type Sigma from 'sigma';
import type Graph from 'graphology';
import { convexHull, type Point } from '../lib/graph-utils';
import { NODE_COLORS } from '../lib/graph-constants';

const HULL_ALPHA = 0.08;
const HULL_BORDER_ALPHA = 0.25;
const HULL_PADDING = 18;
const MIN_COMMUNITY_SIZE = 2;

function communityColor(index: number): string {
  const palette = Object.values(NODE_COLORS);
  return palette[index % palette.length] || '#888';
}

function hexToRgb(hex: string): [number, number, number] {
  const h = hex.replace('#', '');
  return [
    parseInt(h.substring(0, 2), 16),
    parseInt(h.substring(2, 4), 16),
    parseInt(h.substring(4, 6), 16),
  ];
}

export function useCommunityHulls(
  rendererRef: React.MutableRefObject<Sigma | null>,
  graph: Graph,
  active: boolean,
) {
  const cleanupRef = useRef<(() => void) | null>(null);

  const draw = useCallback(() => {
    const renderer = rendererRef.current;
    if (!renderer || !active) return;

    // Group nodes by community
    const communities = new Map<string, { nodeIds: string[]; index: number }>();
    let communityIndex = 0;
    graph.forEachNode((id, attrs) => {
      const cid = String(attrs.community ?? '');
      if (!cid) return;
      if (!communities.has(cid)) {
        communities.set(cid, { nodeIds: [], index: communityIndex++ });
      }
      communities.get(cid)!.nodeIds.push(id);
    });

    // Get the canvas layers
    const canvasLayers = (renderer as unknown as { getCanvases: () => Record<string, HTMLCanvasElement> }).getCanvases?.();
    if (!canvasLayers) return;

    // Use the "hovers" canvas which draws above edges but below labels, or fall back to first canvas
    const canvas = canvasLayers['hovers'] || canvasLayers['edges'] || Object.values(canvasLayers)[0];
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    for (const [, community] of communities) {
      if (community.nodeIds.length < MIN_COMMUNITY_SIZE) continue;

      // Get viewport positions for all nodes in this community
      const points: Point[] = [];
      for (const nodeId of community.nodeIds) {
        try {
          const pos = renderer.graphToViewport(graph.getNodeAttributes(nodeId) as { x: number; y: number });
          points.push(pos);
        } catch { /* node may not be visible */ }
      }
      if (points.length < MIN_COMMUNITY_SIZE) continue;

      const hull = convexHull(points);
      if (hull.length < 3) continue;

      // Expand hull outward by padding
      const cx = hull.reduce((s, p) => s + p.x, 0) / hull.length;
      const cy = hull.reduce((s, p) => s + p.y, 0) / hull.length;
      const expanded = hull.map(p => {
        const dx = p.x - cx;
        const dy = p.y - cy;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        return { x: p.x + (dx / dist) * HULL_PADDING, y: p.y + (dy / dist) * HULL_PADDING };
      });

      const color = communityColor(community.index);
      const [r, g, b] = hexToRgb(color);

      // Draw filled hull
      ctx.beginPath();
      ctx.moveTo(expanded[0].x, expanded[0].y);
      for (let i = 1; i < expanded.length; i++) {
        ctx.lineTo(expanded[i].x, expanded[i].y);
      }
      ctx.closePath();
      ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${HULL_ALPHA})`;
      ctx.fill();

      // Draw border
      ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${HULL_BORDER_ALPHA})`;
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }
  }, [rendererRef, graph, active]);

  useEffect(() => {
    const renderer = rendererRef.current;
    if (!renderer || !active) {
      if (cleanupRef.current) { cleanupRef.current(); cleanupRef.current = null; }
      return;
    }

    const handler = () => draw();
    renderer.on('afterRender', handler);
    cleanupRef.current = () => renderer.off('afterRender', handler);

    return () => {
      if (cleanupRef.current) { cleanupRef.current(); cleanupRef.current = null; }
    };
  }, [rendererRef, active, draw]);
}
