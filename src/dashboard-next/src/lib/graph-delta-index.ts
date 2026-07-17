import { flattenEdge, flattenNode } from './graph-flatten';
import type { ExportedEdge, ExportedGraph, ExportedNode, GraphUpdateData } from './types';

function edgeKey(edge: ExportedEdge): string {
  return edge.id || `${edge.source}-${edge.type}-${edge.target}`;
}

/** Mutable entity index behind the immutable top-level graph view. It keeps
 * ten-item dashboard merges proportional to the delta instead of rebuilding
 * maps and arrays for every node and edge in the engagement. */
export class GraphDeltaIndex {
  private nodesRef: ExportedNode[] | undefined;
  private edgesRef: ExportedEdge[] | undefined;
  private readonly nodePositions = new Map<string, number>();
  private readonly edgePositions = new Map<string, number>();

  apply(graph: ExportedGraph, data: GraphUpdateData): ExportedGraph {
    this.ensure(graph);
    for (const id of data.delta.removed_nodes || []) {
      this.remove(graph.nodes, this.nodePositions, id, node => node.id);
    }
    for (const raw of data.delta.nodes) {
      const node = flattenNode(raw);
      this.upsert(
        graph.nodes,
        this.nodePositions,
        node.id,
        node,
        (previous, next) => ({
          ...previous,
          ...next,
          ...(next.community_id === undefined && previous.community_id !== undefined
            ? { community_id: previous.community_id }
            : {}),
        }),
      );
    }
    for (const id of data.delta.removed_edges || []) {
      this.remove(graph.edges, this.edgePositions, id, edgeKey);
    }
    for (const raw of data.delta.edges) {
      const edge = flattenEdge(raw);
      this.upsert(graph.edges, this.edgePositions, edgeKey(edge), edge);
    }
    return {
      nodes: graph.nodes,
      edges: graph.edges,
      coldInventory: data.delta.cold_nodes
        ? [...data.delta.cold_nodes]
        : graph.coldInventory,
    };
  }

  reset(graph: ExportedGraph): void {
    this.nodesRef = graph.nodes;
    this.edgesRef = graph.edges;
    this.nodePositions.clear();
    this.edgePositions.clear();
    graph.nodes.forEach((node, index) => this.nodePositions.set(node.id, index));
    graph.edges.forEach((edge, index) => this.edgePositions.set(edgeKey(edge), index));
  }

  /** Replace topology-derived community labels after the coalesced state
   * projection completes. The graph arrays remain stable for fast consumers;
   * callers use graphVersion to invalidate memoized derived views. */
  applyCommunityIds(graph: ExportedGraph, communityIds: Record<string, number>): boolean {
    this.ensure(graph);
    let changed = false;
    for (let index = 0; index < graph.nodes.length; index++) {
      const previous = graph.nodes[index];
      const communityId = communityIds[previous.id];
      if (previous.community_id === communityId) continue;
      if (communityId === undefined) {
        const { community_id: _communityId, ...withoutCommunity } = previous;
        graph.nodes[index] = withoutCommunity as ExportedNode;
      } else {
        graph.nodes[index] = { ...previous, community_id: communityId };
      }
      changed = true;
    }
    return changed;
  }

  private ensure(graph: ExportedGraph): void {
    if (this.nodesRef !== graph.nodes || this.edgesRef !== graph.edges) this.reset(graph);
  }

  private upsert<T>(
    items: T[],
    positions: Map<string, number>,
    key: string,
    value: T,
    merge?: (previous: T, next: T) => T,
  ): void {
    const index = positions.get(key);
    if (index === undefined) {
      positions.set(key, items.length);
      items.push(value);
      return;
    }
    items[index] = merge ? merge(items[index], value) : value;
  }

  private remove<T>(
    items: T[],
    positions: Map<string, number>,
    key: string,
    keyOf: (item: T) => string,
  ): void {
    const index = positions.get(key);
    if (index === undefined) return;
    const lastIndex = items.length - 1;
    const last = items[lastIndex];
    if (index !== lastIndex) {
      items[index] = last;
      positions.set(keyOf(last), index);
    }
    items.pop();
    positions.delete(key);
  }
}
