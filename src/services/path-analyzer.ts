// ============================================================
// Overwatch — Path Analyzer
// Shortest-path analysis, objective resolution, path confidence.
// All state access goes through the shared EngineContext.
// ============================================================

import { dijkstra } from 'graphology-shortest-path';
import { createDirectedSimpleGraph } from './graphology-types.js';
import type { EngineContext, OverwatchGraph } from './engine-context.js';
import type { EdgeProperties, EdgeType, GraphQuery, GraphQueryResult } from '../types.js';

type PathEdgeAttrs = { weight: number };

export type PathOptimize = 'confidence' | 'stealth' | 'balanced';
export type PathResult = { nodes: string[]; total_confidence: number; total_opsec_noise: number };

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
   * Cached per optimize mode and invalidated when the graph changes.
   */
  private buildPathGraph(optimize: PathOptimize = 'confidence'): OverwatchGraph {
    const cached = this.ctx.pathGraphCache.get(optimize);
    if (cached) return cached;

    const pg = createDirectedSimpleGraph();

    // Copy all nodes (IDs only)
    this.ctx.graph.forEachNode((id: string) => {
      pg.addNode(id);
    });

    // Copy edges with directionality semantics
    this.ctx.graph.forEachEdge((_edgeId: string, attrs, source: string, target: string) => {
      const weight = this.computeEdgeWeight(attrs, optimize);

      const fwdKey = `${source}--${attrs.type}--${target}`;
      if (!pg.hasEdge(fwdKey)) {
        try { pg.addEdgeWithKey(fwdKey, source, target, { weight } as PathEdgeAttrs as unknown as EdgeProperties); } catch {}
      }

      if (this.bidirectionalEdgeTypes.has(attrs.type)) {
        const revKey = `${target}--${attrs.type}--${source}-rev`;
        if (!pg.hasEdge(revKey)) {
          try { pg.addEdgeWithKey(revKey, target, source, { weight } as PathEdgeAttrs as unknown as EdgeProperties); } catch {}
        }
      }
    });

    this.ctx.pathGraphCache.set(optimize, pg);
    return pg;
  }

  private computeEdgeWeight(attrs: EdgeProperties, optimize: PathOptimize): number {
    switch (optimize) {
      case 'stealth':
        return attrs.opsec_noise ?? 0.3;
      case 'balanced':
        return (1.0 - Math.min(attrs.confidence, 0.99)) * 0.5 + (attrs.opsec_noise ?? 0.3) * 0.5;
      case 'confidence':
      default:
        return 1.0 - Math.min(attrs.confidence, 0.99);
    }
  }

  findShortestPath(fromNode: string, toNode: string, optimize: PathOptimize = 'confidence'): string[] | null {
    const pg = this.buildPathGraph(optimize);
    if (!pg.hasNode(fromNode) || !pg.hasNode(toNode)) return null;
    try {
      return dijkstra.bidirectional(pg, fromNode, toNode, 'weight');
    } catch {
      return null;
    }
  }

  hopsToNearestObjective(fromNodeId: string, optimize: PathOptimize = 'confidence'): number | null {
    if (!this.ctx.graph.hasNode(fromNodeId)) return null;

    const targetNodeIds = this.resolveObjectiveTargets();
    if (targetNodeIds.length === 0) return null;

    let minHops: number | null = null;

    for (const targetId of targetNodeIds) {
      if (targetId === fromNodeId) return 0;
      try {
        const path = this.findShortestPath(fromNodeId, targetId, optimize);
        if (path && (minHops === null || path.length - 1 < minHops)) {
          minHops = path.length - 1;
        }
      } catch (err) {
        this.ctx.log(`Path analysis error (${fromNodeId} → ${targetId}): ${err instanceof Error ? err.message : String(err)}`, undefined, { category: 'system', outcome: 'failure' });
      }
    }

    return minHops;
  }

  findPathsToObjective(objectiveId: string, maxPaths: number = 5, optimize: PathOptimize = 'confidence'): Array<PathResult> {
    const paths: Array<PathResult> = [];

    const obj = this.ctx.config.objectives.find(o => o.id === objectiveId);
    const targetNodeIds = obj?.target_criteria
      ? this.queryGraph({ node_type: obj.target_node_type, node_filter: obj.target_criteria }).nodes.map(n => n.id)
      : [];

    if (targetNodeIds.length === 0) return paths;

    const startNodes: string[] = [];
    this.ctx.graph.forEachNode((id: string, attrs) => {
      if (attrs.type === 'host') {
        const hasAccess = this.ctx.graph.edges(id).some((e: string) => {
          const ep = this.ctx.graph.getEdgeAttributes(e);
          return (ep.type === 'HAS_SESSION' || ep.type === 'ADMIN_TO') && ep.confidence >= 0.9;
        });
        if (hasAccess) startNodes.push(id);
      }
    });

    for (const start of startNodes) {
      for (const targetId of targetNodeIds) {
        try {
          const path = this.findShortestPath(start, targetId, optimize);
          if (path) {
            const { total_confidence, total_opsec_noise } = this.computePathConfidence(path);
            paths.push({ nodes: path, total_confidence, total_opsec_noise });
          }
        } catch (err) {
          this.ctx.log(`Path analysis error (${start} → ${targetId}): ${err instanceof Error ? err.message : String(err)}`, undefined, { category: 'system', outcome: 'failure' });
        }
      }
    }

    return paths
      .sort((a, b) => {
        if (optimize === 'stealth') return a.total_opsec_noise - b.total_opsec_noise;
        if (optimize === 'balanced') return (b.total_confidence - b.total_opsec_noise) - (a.total_confidence - a.total_opsec_noise);
        return b.total_confidence - a.total_confidence;
      })
      .slice(0, maxPaths);
  }

  findPaths(fromNode: string, toNode: string, maxPaths: number = 5, optimize: PathOptimize = 'confidence'): Array<PathResult> {
    if (!this.ctx.graph.hasNode(fromNode) || !this.ctx.graph.hasNode(toNode)) return [];

    const paths: Array<PathResult> = [];
    try {
      const path = this.findShortestPath(fromNode, toNode, optimize);
      if (path) {
        const { total_confidence, total_opsec_noise } = this.computePathConfidence(path);
        paths.push({ nodes: path, total_confidence, total_opsec_noise });
      }
    } catch (err) {
      this.ctx.log(`Path analysis error (${fromNode} → ${toNode}): ${err instanceof Error ? err.message : String(err)}`, undefined, { category: 'system', outcome: 'failure' });
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

  private computePathConfidence(path: string[]): { total_confidence: number; total_opsec_noise: number } {
    let totalConfidence = 1.0;
    let totalOpsecNoise = 0;
    for (let i = 0; i < path.length - 1; i++) {
      let edgeList = this.ctx.graph.edges(path[i], path[i + 1]);
      if (edgeList.length === 0) {
        edgeList = this.ctx.graph.edges(path[i + 1], path[i]);
      }
      if (edgeList.length === 0) {
        totalConfidence *= 0.1;
        totalOpsecNoise += 0.3; // default noise for missing edges
        continue;
      }
      // Pick the best (highest confidence) edge
      let bestConfidence = 0;
      let bestNoise = 0.3;
      for (const e of edgeList) {
        const attrs = this.ctx.graph.getEdgeAttributes(e);
        if (attrs.confidence > bestConfidence) {
          bestConfidence = attrs.confidence;
          bestNoise = attrs.opsec_noise ?? 0.3;
        }
      }
      totalConfidence *= bestConfidence;
      totalOpsecNoise += bestNoise;
    }
    return { total_confidence: totalConfidence, total_opsec_noise: totalOpsecNoise };
  }
}
