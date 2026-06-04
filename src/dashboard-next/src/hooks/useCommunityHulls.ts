// ============================================================
// useCommunityHulls — draw conservative regions around graph communities
// ============================================================

import { useEffect, useRef, useCallback } from 'react';
import type Sigma from 'sigma';
import type Graph from 'graphology';
import { convexHull, type Point } from '../lib/graph-utils';
import { NODE_COLORS } from '../lib/graph-constants';

const HULL_LAYER_ID = 'communityHulls';
const HULL_ALPHA = 0.035;
const HULL_BORDER_ALPHA = 0.14;
const HULL_PADDING = 12;
const MIN_COMMUNITY_SIZE = 4;
const MAX_VIEWPORT_AREA_SHARE = 0.18;
const MAX_VIEWPORT_WIDTH_SHARE = 0.56;
const MAX_VIEWPORT_HEIGHT_SHARE = 0.56;
const MAX_ASPECT_RATIO = 4.5;

type NodeReducer = (node: string, data: Record<string, unknown>) => Record<string, unknown>;

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

function getHullLayer(renderer: Sigma): HTMLCanvasElement | null {
  let canvas = renderer.getCanvases()[HULL_LAYER_ID];
  if (!canvas) {
    renderer.createCanvasContext(HULL_LAYER_ID);
    const canvases = renderer.getCanvases();
    canvas = canvases[HULL_LAYER_ID];
    const edges = canvases.edges;
    if (canvas && edges) edges.before(canvas);
    if (canvas) canvas.style.pointerEvents = 'none';
    renderer.resize(true);
  }
  return canvas || null;
}

function polygonArea(points: Point[]): number {
  let area = 0;
  for (let i = 0; i < points.length; i++) {
    const current = points[i];
    const next = points[(i + 1) % points.length];
    area += current.x * next.y - next.x * current.y;
  }
  return Math.abs(area) / 2;
}

function hullBounds(points: Point[]) {
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const point of points) {
    minX = Math.min(minX, point.x);
    maxX = Math.max(maxX, point.x);
    minY = Math.min(minY, point.y);
    maxY = Math.max(maxY, point.y);
  }
  return { width: maxX - minX, height: maxY - minY };
}

function isUsefulHull(hull: Point[], viewportWidth: number, viewportHeight: number): boolean {
  const { width, height } = hullBounds(hull);
  if (width <= 0 || height <= 0) return false;
  if (width > viewportWidth * MAX_VIEWPORT_WIDTH_SHARE) return false;
  if (height > viewportHeight * MAX_VIEWPORT_HEIGHT_SHARE) return false;

  const aspect = Math.max(width, height) / Math.max(1, Math.min(width, height));
  if (aspect > MAX_ASPECT_RATIO) return false;

  const viewportArea = viewportWidth * viewportHeight;
  const area = polygonArea(hull);
  return area > 0 && area <= viewportArea * MAX_VIEWPORT_AREA_SHARE;
}

function drawSoftPolygon(ctx: CanvasRenderingContext2D, points: Point[]) {
  if (points.length < 3) return;

  ctx.beginPath();
  for (let i = 0; i < points.length; i++) {
    const current = points[i];
    const next = points[(i + 1) % points.length];
    const mid = {
      x: (current.x + next.x) / 2,
      y: (current.y + next.y) / 2,
    };
    if (i === 0) ctx.moveTo(mid.x, mid.y);
    else ctx.quadraticCurveTo(current.x, current.y, mid.x, mid.y);
  }
  const first = points[0];
  const second = points[1];
  ctx.quadraticCurveTo(first.x, first.y, (first.x + second.x) / 2, (first.y + second.y) / 2);
  ctx.closePath();
}

export function useCommunityHulls(
  rendererRef: React.MutableRefObject<Sigma | null>,
  graph: Graph,
  active: boolean,
  nodeReducer?: NodeReducer,
) {
  const cleanupRef = useRef<(() => void) | null>(null);

  const draw = useCallback(() => {
    const renderer = rendererRef.current;
    if (!renderer || !active) return;

    // Group nodes by community
    const communities = new Map<string, { nodeIds: string[]; index: number }>();
    let communityIndex = 0;
    graph.forEachNode((id, attrs) => {
      if (nodeReducer?.(id, attrs as Record<string, unknown>).hidden) return;
      const cid = String(attrs.community ?? '');
      if (!cid) return;
      if (!communities.has(cid)) {
        communities.set(cid, { nodeIds: [], index: communityIndex++ });
      }
      communities.get(cid)!.nodeIds.push(id);
    });

    const canvas = getHullLayer(renderer);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const viewportWidth = canvas.clientWidth || canvas.width;
    const viewportHeight = canvas.clientHeight || canvas.height;
    ctx.clearRect(0, 0, viewportWidth, viewportHeight);

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
      if (!isUsefulHull(hull, viewportWidth, viewportHeight)) continue;

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
      drawSoftPolygon(ctx, expanded);
      ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${HULL_ALPHA})`;
      ctx.fill();

      // Draw border
      ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${HULL_BORDER_ALPHA})`;
      ctx.lineWidth = 1;
      ctx.stroke();
    }
  }, [rendererRef, graph, active, nodeReducer]);

  useEffect(() => {
    const renderer = rendererRef.current;
    if (!renderer || !active) {
      if (cleanupRef.current) { cleanupRef.current(); cleanupRef.current = null; }
      return;
    }

    const handler = () => draw();
    renderer.on('afterRender', handler);
    cleanupRef.current = () => renderer.off('afterRender', handler);
    draw();

    return () => {
      if (cleanupRef.current) { cleanupRef.current(); cleanupRef.current = null; }
    };
  }, [rendererRef, active, draw]);

  useEffect(() => {
    const renderer = rendererRef.current;
    if (active || !renderer) return;
    if (renderer.getCanvases()[HULL_LAYER_ID]) {
      renderer.killLayer(HULL_LAYER_ID);
      renderer.refresh();
    }
  }, [rendererRef, active]);
}
