import { createUndirectedSimpleGraph, assignLouvainCommunities } from './graphology-types.js';
import type { OverwatchGraph } from './engine-context.js';

/**
 * Build an undirected simple projection of the engagement graph and run
 * Louvain community detection.  Returns a Map<nodeId, communityId>.
 *
 * The projection collapses parallel/directed edges into a single undirected
 * edge per node pair, keeping the maximum confidence as the weight.
 */
export function detectCommunities(graph: OverwatchGraph): Map<string, number> {
  if (graph.order === 0) return new Map();

  // Build undirected simple projection
  const ug = createUndirectedSimpleGraph();

  graph.forEachNode((id: string) => {
    ug.addNode(id);
  });

  graph.forEachEdge((_edgeId: string, attrs: Record<string, unknown>, source: string, target: string) => {
    if (source === target) return;
    const confidence = (typeof attrs.confidence === 'number' ? attrs.confidence : 1.0);

    if (ug.hasEdge(source, target)) {
      // Keep max confidence as weight
      const existing = ug.getEdgeAttribute(source, target, 'weight') as number;
      if (confidence > existing) {
        ug.setEdgeAttribute(source, target, 'weight', confidence);
      }
    } else {
      try {
        ug.addEdge(source, target, { weight: confidence });
      } catch {
        // duplicate edge race — ignore
      }
    }
  });

  // Need at least one edge for Louvain to be meaningful
  if (ug.size === 0) {
    const result = new Map<string, number>();
    let i = 0;
    graph.forEachNode((id: string) => {
      result.set(id, i++);
    });
    return result;
  }

  const mapping = assignLouvainCommunities(ug, {
    getEdgeWeight: 'weight',
    resolution: 1.0,
  });

  return new Map(Object.entries(mapping).map(([k, v]) => [k, v]));
}

/**
 * Compute community summary statistics from a community mapping.
 */
export function communityStats(communities: Map<string, number>): {
  community_count: number;
  largest_community_size: number;
  sizes: Map<number, number>;
} {
  const sizes = new Map<number, number>();
  for (const cid of communities.values()) {
    sizes.set(cid, (sizes.get(cid) || 0) + 1);
  }
  let largest = 0;
  for (const size of sizes.values()) {
    if (size > largest) largest = size;
  }
  return {
    community_count: sizes.size,
    largest_community_size: largest,
    sizes,
  };
}
