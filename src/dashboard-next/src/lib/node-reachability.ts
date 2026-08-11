import type { ExportedEdge, ExportedNode } from './types';
import { tierForNode, type Tier } from './tier';
import { buildAdjacency, dijkstra, isObjectiveTarget, reconstructPath } from './attack-graph';

/** A single objective/high-value target the inspected node can reach, with the hop count
 *  of its highest-confidence route. */
export interface ReachableObjective {
  id: string;
  label: string;
  tier: Tier;
  /** Number of edges on the best route from the inspected node to this target. */
  hops: number;
}

export interface Reachability {
  /** The closest reachable objective/target (fewest hops), or null when the node reaches
   *  none. */
  nearest: ReachableObjective | null;
  /** How many objectives/targets the node can reach in total. */
  count: number;
}

/**
 * Single-source reachability: from the inspected node, which objectives / high-value
 * targets can it reach, and how far is the nearest? Runs one Dijkstra (confidence-
 * weighted, same edge model as the attack-path panel) from the node, then measures the
 * highest-confidence route to each objective. "Nearest" is fewest hops; the node itself
 * is excluded so the drawer reports what it leads *to*, not itself.
 */
export function reachableObjectives(
  nodeId: string,
  nodes: ExportedNode[],
  edges: ExportedEdge[],
): Reachability {
  const adj = buildAdjacency(nodes, edges, 'confidence');
  if (!adj.has(nodeId)) return { nearest: null, count: 0 };

  const result = dijkstra(adj, nodeId);
  const reached: ReachableObjective[] = [];
  for (const n of nodes) {
    if (n.id === nodeId || !isObjectiveTarget(n)) continue;
    const recon = reconstructPath(n.id, result);
    if (!recon) continue;
    reached.push({
      id: n.id,
      label: n.label || n.id,
      tier: tierForNode(n),
      hops: Math.max(recon.nodes.length - 1, 1),
    });
  }
  if (reached.length === 0) return { nearest: null, count: 0 };

  // Nearest by hop count; break ties by label for a stable pick.
  reached.sort((a, b) => a.hops - b.hops || a.label.localeCompare(b.label));
  return { nearest: reached[0], count: reached.length };
}
