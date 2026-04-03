import type { OverwatchGraph } from './engine-context.js';
import type { NodeProperties, GraphQuery, GraphQueryResult } from '../types.js';

export interface GraphQueryHost {
  graph: OverwatchGraph;
  getNode(id: string): NodeProperties | null;
}

export function matchesFilter(obj: Record<string, unknown>, filter?: Record<string, unknown>): boolean {
  if (!filter) return true;
  return Object.entries(filter).every(([key, val]) => {
    if (val === undefined || val === null) return true;
    return obj[key] === val;
  });
}

export function queryGraphImpl(host: GraphQueryHost, query: GraphQuery): GraphQueryResult {
  const result: GraphQueryResult = { nodes: [], edges: [] };
  const limit = query.limit || 100;

  // Node queries
  if (query.node_type || query.node_filter || query.from_node) {
    if (query.from_node && host.graph.hasNode(query.from_node)) {
      // Traverse from node
      const visited = new Set<string>();
      const queue: Array<{ id: string; depth: number }> = [{ id: query.from_node, depth: 0 }];
      const maxDepth = query.max_depth || 2;

      while (queue.length > 0 && result.nodes.length < limit) {
        const current = queue.shift()!;
        if (visited.has(current.id)) continue;
        visited.add(current.id);

        const node = host.getNode(current.id);
        if (node && node.identity_status !== 'superseded') {
          if (!query.node_type || node.type === query.node_type) {
            if (matchesFilter(node, query.node_filter)) {
              result.nodes.push({ id: current.id, properties: node });
            }
          }
        }

        if (current.depth < maxDepth) {
          const neighbors = query.direction === 'inbound'
            ? host.graph.inNeighbors(current.id)
            : query.direction === 'outbound'
              ? host.graph.outNeighbors(current.id)
              : host.graph.neighbors(current.id);

          for (const neighbor of neighbors) {
            if (!visited.has(neighbor)) {
              queue.push({ id: neighbor, depth: current.depth + 1 });
            }
          }
        }
      }

      // Also include edges between found nodes
      const nodeIds = new Set(result.nodes.map(n => n.id));
      host.graph.forEachEdge((_edgeId, attrs, source, target) => {
        if (nodeIds.has(source) && nodeIds.has(target)) {
          if (!query.edge_type || attrs.type === query.edge_type) {
            result.edges.push({ source, target, properties: attrs });
          }
        }
      });
    } else {
      // Filter all nodes
      host.graph.forEachNode((id, attrs) => {
        if (result.nodes.length >= limit) return;
        if (attrs.identity_status === 'superseded') return;
        if (query.node_type && attrs.type !== query.node_type) return;
        if (!matchesFilter(attrs, query.node_filter)) return;
        result.nodes.push({ id, properties: attrs });
      });
    }
  }

  // Edge queries
  if (query.edge_type || query.edge_filter) {
    host.graph.forEachEdge((_edgeId, attrs, source, target) => {
      if (result.edges.length >= limit) return;
      if (query.edge_type && attrs.type !== query.edge_type) return;
      if (!matchesFilter(attrs, query.edge_filter)) return;
      // Suppress edges attached to superseded identity nodes
      const srcAttrs = host.graph.getNodeAttributes(source);
      const tgtAttrs = host.graph.getNodeAttributes(target);
      if (srcAttrs?.identity_status === 'superseded' || tgtAttrs?.identity_status === 'superseded') return;
      result.edges.push({ source, target, properties: attrs });
    });
  }

  return result;
}
