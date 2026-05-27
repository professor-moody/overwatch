// ============================================================
// Overwatch — Path Analyzer
// Shortest-path analysis, objective resolution, path confidence.
// All state access goes through the shared EngineContext.
// ============================================================

import { dijkstra } from 'graphology-shortest-path';
import { createDirectedSimpleGraph } from './graphology-types.js';
import type { EngineContext, OverwatchGraph } from './engine-context.js';
import type { EdgeProperties, EdgeType, GraphQuery, GraphQueryResult } from '../types.js';
import { isLiveSessionEdge } from './session-edge-utils.js';

type PathEdgeAttrs = { weight: number };

export type PathOptimize = 'confidence' | 'stealth' | 'balanced';
export type PathResult = { nodes: string[]; total_confidence: number; total_opsec_noise: number };
export type PathAnalysisStatus = 'found' | 'no_path' | 'missing_endpoint' | 'analysis_failed';
export type PathAnalysisResult = {
  status: PathAnalysisStatus;
  path: string[] | null;
  missing_nodes?: string[];
  error?: string;
};

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
      // F1: HAS_SESSION edges marked dead by session-tracker (closed shell,
      // restart, watchdog timeout) MUST NOT contribute to path
      // reachability — the shell isn't there anymore. Dead edges remain
      // in the graph for reporting/retrospectives but the path graph is
      // a "live reachability" view.
      if (attrs.type === 'HAS_SESSION' && !isLiveSessionEdge(attrs)) return;

      const weight = this.computeEdgeWeight(attrs, optimize);

      const fwdKey = `${source}--${attrs.type}--${target}`;
      if (!pg.hasEdge(fwdKey)) {
        try {
          pg.addEdgeWithKey(fwdKey, source, target, { weight } as PathEdgeAttrs as unknown as EdgeProperties);
        } catch (err) {
          this.logProjectionFailure(fwdKey, source, target, err);
        }
      }

      if (this.bidirectionalEdgeTypes.has(attrs.type)) {
        const revKey = `${target}--${attrs.type}--${source}-rev`;
        if (!pg.hasEdge(revKey)) {
          try {
            pg.addEdgeWithKey(revKey, target, source, { weight } as PathEdgeAttrs as unknown as EdgeProperties);
          } catch (err) {
            this.logProjectionFailure(revKey, target, source, err);
          }
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
        return Math.max((1.0 - attrs.confidence) * 0.5 + (attrs.opsec_noise ?? 0.3) * 0.5, 0.001);
      case 'confidence':
      default:
        return Math.max(1.0 - attrs.confidence, 0.001);
    }
  }

  private logProjectionFailure(edgeKey: string, source: string, target: string, err: unknown): void {
    this.ctx.logEvent({
      description: `Path graph projection failed for edge ${edgeKey}`,
      category: 'system',
      event_type: 'instrumentation_warning',
      result_classification: 'failure',
      details: {
        analysis_status: 'analysis_failed',
        edge_key: edgeKey,
        source,
        target,
        error: err instanceof Error ? err.message : String(err),
      },
    });
  }

  findShortestPath(fromNode: string, toNode: string, optimize: PathOptimize = 'confidence'): string[] | null {
    const result = this.findShortestPathDetailed(fromNode, toNode, optimize);
    return result.status === 'found' ? result.path : null;
  }

  findShortestPathDetailed(fromNode: string, toNode: string, optimize: PathOptimize = 'confidence'): PathAnalysisResult {
    const pg = this.buildPathGraph(optimize);
    const missing = [fromNode, toNode].filter(nodeId => !pg.hasNode(nodeId));
    if (missing.length > 0) return { status: 'missing_endpoint', path: null, missing_nodes: missing };
    try {
      const path = dijkstra.bidirectional(pg, fromNode, toNode, 'weight');
      return path ? { status: 'found', path } : { status: 'no_path', path: null };
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      this.ctx.logEvent({
        description: `Path analysis failed (${fromNode} → ${toNode})`,
        category: 'system',
        event_type: 'instrumentation_warning',
        result_classification: 'failure',
        details: { analysis_status: 'analysis_failed', from_node: fromNode, to_node: toNode, optimize, error },
      });
      return { status: 'analysis_failed', path: null, error };
    }
  }

  findPathsDetailed(fromNode: string, toNode: string, maxPaths: number = 5, optimize: PathOptimize = 'confidence'): { paths: Array<PathResult>; analysis_status: PathAnalysisStatus; warnings?: string[] } {
    const result = this.findShortestPathDetailed(fromNode, toNode, optimize);
    if (result.status !== 'found' || !result.path) {
      const warnings = result.status === 'missing_endpoint'
        ? [`Missing graph endpoint(s): ${(result.missing_nodes || []).join(', ')}`]
        : result.status === 'analysis_failed'
          ? [`Path analysis failed: ${result.error || 'unknown error'}`]
          : undefined;
      return { paths: [], analysis_status: result.status, warnings };
    }

    const { total_confidence, total_opsec_noise } = this.computePathConfidence(result.path);
    return {
      paths: [{ nodes: result.path, total_confidence, total_opsec_noise }].slice(0, maxPaths),
      analysis_status: 'found',
    };
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
        // F1: only LIVE sessions (or ADMIN_TO) qualify a host as a path
        // start. A closed shell isn't a current beachhead.
        const hasAccess = this.ctx.graph.edges(id).some((e: string) => {
          const ep = this.ctx.graph.getEdgeAttributes(e);
          if (ep.type === 'HAS_SESSION') return isLiveSessionEdge(ep) && ep.confidence >= 0.9;
          return ep.type === 'ADMIN_TO' && ep.confidence >= 0.9;
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
    return this.findPathsDetailed(fromNode, toNode, maxPaths, optimize).paths;
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
