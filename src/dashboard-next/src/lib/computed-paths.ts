import type { ExportedEdge, ExportedNode } from './types';
import { tiersForPath, type Tier } from './tier';
import { BIDIRECTIONAL, buildAdjacency, dijkstra, isObjectiveTarget, reconstructPath, type Optimize } from './attack-graph';

export interface ComputedPath {
  nodes: string[];
  edge_types: string[];
  edge_ids: string[];
  weight: number;
  total_confidence: number;
  total_opsec_noise: number;
  tiers: Set<Tier>;
}

/** Native Investigate path inventory over the same client graph model used by
 * the server path analyzer: current access is a live session, compromised host,
 * or high-confidence admin edge; objectives and high-value cloud/identity nodes
 * are targets. */
export function computeWorkspacePaths(
  nodes: ExportedNode[],
  edges: ExportedEdge[],
  optimize: Optimize,
  maxHops: number,
  byId: Map<string, ExportedNode>,
): ComputedPath[] {
  const sources = nodes.filter(node => {
    if (node.type !== 'host') return false;
    if (node.compromised === true) return true;
    return edges.some(edge => {
      if (edge.target !== node.id) return false;
      if (edge.type === 'HAS_SESSION') return edge.session_live !== false && (edge.confidence ?? 1) >= 0.7;
      return edge.type === 'ADMIN_TO' && (edge.confidence ?? 1) >= 0.9;
    });
  }).map(node => node.id);
  const targets = nodes.filter(isObjectiveTarget).map(node => node.id);
  if (sources.length === 0 || targets.length === 0) return [];

  const adjacency = buildAdjacency(nodes, edges, optimize);
  const paths: ComputedPath[] = [];
  const seen = new Set<string>();
  for (const source of sources) {
    const result = dijkstra(adjacency, source);
    for (const target of targets) {
      if (source === target) continue;
      const reconstructed = reconstructPath(target, result);
      if (!reconstructed || reconstructed.nodes.length - 1 > maxHops) continue;
      const signature = `${reconstructed.nodes.join('>')}|${reconstructed.edge_types.join(',')}`;
      if (seen.has(signature)) continue;
      seen.add(signature);
      let totalConfidence = 1;
      let totalNoise = 0;
      for (let index = 0; index < reconstructed.nodes.length - 1; index++) {
        const from = reconstructed.nodes[index];
        const to = reconstructed.nodes[index + 1];
        const edge = edges.find(candidate =>
          (candidate.source === from && candidate.target === to)
          || (BIDIRECTIONAL.has(candidate.type) && candidate.source === to && candidate.target === from));
        if (!edge) continue;
        totalConfidence *= typeof edge.confidence === 'number' ? edge.confidence : 1;
        totalNoise += typeof edge.opsec_noise === 'number' ? edge.opsec_noise : 0.3;
      }
      paths.push({
        nodes: reconstructed.nodes,
        edge_types: reconstructed.edge_types,
        edge_ids: reconstructed.edge_ids,
        weight: result.get(target)?.dist ?? Number.POSITIVE_INFINITY,
        total_confidence: totalConfidence,
        total_opsec_noise: totalNoise,
        tiers: tiersForPath(reconstructed.nodes, byId),
      });
    }
  }
  return paths.sort((left, right) => {
    const leftCrossTier = left.tiers.size >= 2 ? 0 : 1;
    const rightCrossTier = right.tiers.size >= 2 ? 0 : 1;
    return leftCrossTier - rightCrossTier || left.weight - right.weight;
  });
}
