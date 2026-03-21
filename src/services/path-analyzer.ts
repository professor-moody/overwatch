// ============================================================
// Overwatch — Path Analyzer
// Shortest-path analysis, objective resolution, path confidence.
// All state access goes through the shared EngineContext.
// ============================================================

import GraphConstructor from 'graphology';
import { dijkstra } from 'graphology-shortest-path';
import type { EngineContext } from './engine-context.js';
import type { NodeProperties, EdgeProperties, EdgeType, GraphQuery, GraphQueryResult } from '../types.js';

// Handle CJS/ESM interop for graphology
const Graph = (GraphConstructor as any).default || GraphConstructor;

export type QueryGraphFn = (query: GraphQuery) => GraphQueryResult;

export class PathAnalyzer {
  private ctx: EngineContext;
  private bidirectionalEdgeTypes: Set<EdgeType>;
  private queryGraph: QueryGraphFn;

  constructor(ctx: EngineContext, bidirectionalEdgeTypes: Set<EdgeType>, queryGraph: QueryGraphFn) {
    this.ctx = ctx;
    this.bidirectionalEdgeTypes = bidirectionalEdgeTypes;
    this.queryGraph = queryGraph;
  }

  /**
   * Build an undirected projection of the graph for pathfinding.
   * Edges in bidirectionalEdgeTypes are added as undirected (both directions).
   * All other edges keep their original direction only.
   * Cached and invalidated when the graph changes.
   */
  private buildPathGraph(): any {
    if (this.ctx.pathGraphCache) return this.ctx.pathGraphCache;

    const pg = new Graph({ type: 'directed', multi: false, allowSelfLoops: false });

    // Copy all nodes (IDs only)
    this.ctx.graph.forEachNode((id: string) => {
      pg.addNode(id);
    });

    // Copy edges with directionality semantics
    this.ctx.graph.forEachEdge((edgeId: string, attrs: any, source: string, target: string) => {
      const ep = attrs as EdgeProperties;
      const weight = 1.0 - Math.min(ep.confidence, 0.99);

      const fwdKey = `${source}--${ep.type}--${target}`;
      if (!pg.hasEdge(fwdKey)) {
        try { pg.addEdgeWithKey(fwdKey, source, target, { weight }); } catch {}
      }

      if (this.bidirectionalEdgeTypes.has(ep.type)) {
        const revKey = `${target}--${ep.type}--${source}-rev`;
        if (!pg.hasEdge(revKey)) {
          try { pg.addEdgeWithKey(revKey, target, source, { weight }); } catch {}
        }
      }
    });

    this.ctx.pathGraphCache = pg;
    return pg;
  }

  findShortestPath(fromNode: string, toNode: string): string[] | null {
    const pg = this.buildPathGraph();
    if (!pg.hasNode(fromNode) || !pg.hasNode(toNode)) return null;
    try {
      return dijkstra.bidirectional(pg, fromNode, toNode, 'weight');
    } catch {
      return null;
    }
  }

  hopsToNearestObjective(fromNodeId: string): number | null {
    if (!this.ctx.graph.hasNode(fromNodeId)) return null;

    const targetNodeIds = this.resolveObjectiveTargets();
    if (targetNodeIds.length === 0) return null;

    let minHops: number | null = null;

    for (const targetId of targetNodeIds) {
      if (targetId === fromNodeId) return 0;
      try {
        const path = this.findShortestPath(fromNodeId, targetId);
        if (path && (minHops === null || path.length - 1 < minHops)) {
          minHops = path.length - 1;
        }
      } catch (err) {
        this.ctx.log(`Path analysis error (${fromNodeId} → ${targetId}): ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    return minHops;
  }

  findPathsToObjective(objectiveId: string, maxPaths: number = 5): Array<{ nodes: string[]; total_confidence: number }> {
    const paths: Array<{ nodes: string[]; total_confidence: number }> = [];

    const obj = this.ctx.config.objectives.find(o => o.id === objectiveId);
    const targetNodeIds = obj?.target_criteria
      ? this.queryGraph({ node_type: obj.target_node_type, node_filter: obj.target_criteria }).nodes.map(n => n.id)
      : [];

    if (targetNodeIds.length === 0) return paths;

    const startNodes: string[] = [];
    this.ctx.graph.forEachNode((id: string, attrs: any) => {
      const node = attrs as NodeProperties;
      if (node.type === 'host') {
        const hasAccess = this.ctx.graph.edges(id).some((e: string) => {
          const ep = this.ctx.graph.getEdgeAttributes(e) as EdgeProperties;
          return (ep.type === 'HAS_SESSION' || ep.type === 'ADMIN_TO') && ep.confidence >= 0.9;
        });
        if (hasAccess) startNodes.push(id);
      }
    });

    for (const start of startNodes) {
      for (const targetId of targetNodeIds) {
        try {
          const path = this.findShortestPath(start, targetId);
          if (path) {
            paths.push({ nodes: path, total_confidence: this.computePathConfidence(path) });
          }
        } catch (err) {
          this.ctx.log(`Path analysis error (${start} → ${targetId}): ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }

    return paths
      .sort((a, b) => b.total_confidence - a.total_confidence)
      .slice(0, maxPaths);
  }

  findPaths(fromNode: string, toNode: string, maxPaths: number = 5): Array<{ nodes: string[]; total_confidence: number }> {
    if (!this.ctx.graph.hasNode(fromNode) || !this.ctx.graph.hasNode(toNode)) return [];

    const paths: Array<{ nodes: string[]; total_confidence: number }> = [];
    try {
      const path = this.findShortestPath(fromNode, toNode);
      if (path) {
        paths.push({ nodes: path, total_confidence: this.computePathConfidence(path) });
      }
    } catch (err) {
      this.ctx.log(`Path analysis error (${fromNode} → ${toNode}): ${err instanceof Error ? err.message : String(err)}`);
    }

    return paths.slice(0, maxPaths);
  }

  private resolveObjectiveTargets(): string[] {
    const targetIds = new Set<string>();
    for (const obj of this.ctx.config.objectives) {
      if (obj.achieved) continue;
      if (obj.target_criteria) {
        const matching = this.queryGraph({
          node_type: obj.target_node_type,
          node_filter: obj.target_criteria,
        });
        for (const n of matching.nodes) targetIds.add(n.id);
      }
    }
    return Array.from(targetIds);
  }

  private computePathConfidence(path: string[]): number {
    let totalConfidence = 1.0;
    for (let i = 0; i < path.length - 1; i++) {
      const edges = this.ctx.graph.edges(path[i], path[i + 1]);
      if (edges.length === 0) {
        const reverseEdges = this.ctx.graph.edges(path[i + 1], path[i]);
        if (reverseEdges.length === 0) { totalConfidence *= 0.1; continue; }
        const bestConfidence = Math.max(
          ...reverseEdges.map((e: string) => (this.ctx.graph.getEdgeAttributes(e) as EdgeProperties).confidence)
        );
        totalConfidence *= bestConfidence;
      } else {
        const bestConfidence = Math.max(
          ...edges.map((e: string) => (this.ctx.graph.getEdgeAttributes(e) as EdgeProperties).confidence)
        );
        totalConfidence *= bestConfidence;
      }
    }
    return totalConfidence;
  }
}
