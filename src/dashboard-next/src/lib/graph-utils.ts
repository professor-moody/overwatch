// ============================================================
// Graph Utilities — ported from legacy graph.js helpers
// ============================================================

import type Graph from 'graphology';
import { DRAG_THRESHOLD_PX } from './graph-constants';

/** Convert hex color to rgba with given alpha */
export function dimColor(hex: string | undefined, alpha: number): string {
  if (!hex || hex.startsWith('rgba')) return hex || '';
  const r = parseInt(hex.slice(1, 3), 16) || 0;
  const g = parseInt(hex.slice(3, 5), 16) || 0;
  const b = parseInt(hex.slice(5, 7), 16) || 0;
  return `rgba(${r},${g},${b},${alpha})`;
}

/** BFS neighborhood — returns all nodes within `hops` edges of `node` */
export function getNeighborhood(graph: Graph, node: string, hops = 1): Set<string> {
  if (!graph || !node || !graph.hasNode(node)) return new Set();

  const visited = new Set([node]);
  let frontier = [node];
  for (let depth = 0; depth < hops; depth++) {
    const next: string[] = [];
    for (const current of frontier) {
      for (const neighbor of graph.neighbors(current)) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          next.push(neighbor);
        }
      }
    }
    frontier = next;
    if (frontier.length === 0) break;
  }
  return visited;
}

/** BFS shortest path — returns the set of nodes and edges on the shortest path */
export function findShortestPath(
  graph: Graph,
  source: string,
  target: string,
): { nodes: Set<string>; edges: Set<string> } {
  const resultNodes = new Set([source, target]);
  const resultEdges = new Set<string>();

  if (!graph || !source || !target || !graph.hasNode(source) || !graph.hasNode(target)) {
    return { nodes: resultNodes, edges: resultEdges };
  }

  const visited = new Map<string, string | null>();
  const edgeUsed = new Map<string, string>();
  const queue = [source];
  visited.set(source, null);

  let found = false;
  while (queue.length > 0 && !found) {
    const current = queue.shift()!;
    const edges = graph.edges(current);
    for (const edge of edges) {
      const neighbor = graph.opposite(current, edge);
      if (!visited.has(neighbor)) {
        visited.set(neighbor, current);
        edgeUsed.set(neighbor, edge);
        queue.push(neighbor);
        if (neighbor === target) {
          found = true;
          break;
        }
      }
    }
  }

  if (found) {
    let current: string | null = target;
    while (current !== null && current !== source) {
      resultNodes.add(current);
      const edge = edgeUsed.get(current);
      if (edge) resultEdges.add(edge);
      current = visited.get(current) ?? null;
    }
  }

  return { nodes: resultNodes, edges: resultEdges };
}

/** Check if drag exceeds threshold */
export function exceededDragThreshold(
  startX: number, startY: number,
  currentX: number, currentY: number,
): boolean {
  if ([startX, startY, currentX, currentY].some(v => typeof v !== 'number' || Number.isNaN(v))) {
    return false;
  }
  const dx = currentX - startX;
  const dy = currentY - startY;
  return Math.hypot(dx, dy) >= DRAG_THRESHOLD_PX;
}

export interface Point { x: number; y: number }

/** Convex hull (Andrew's monotone chain) for community hull rendering */
export function convexHull(points: Point[]): Point[] {
  if (points.length <= 1) return [...points];

  const sorted = [...points].sort((a, b) => a.x - b.x || a.y - b.y);

  const cross = (o: Point, a: Point, b: Point) =>
    (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);

  // Build lower hull
  const lower: Point[] = [];
  for (const p of sorted) {
    while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], p) <= 0) {
      lower.pop();
    }
    lower.push(p);
  }

  // Build upper hull
  const upper: Point[] = [];
  for (let i = sorted.length - 1; i >= 0; i--) {
    const p = sorted[i];
    while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], p) <= 0) {
      upper.pop();
    }
    upper.push(p);
  }

  // Remove last point of each half because it's repeated
  lower.pop();
  upper.pop();
  return lower.concat(upper);
}

/** Escape HTML for safe insertion */
export function escapeHtml(str: string): string {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
