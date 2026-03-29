import { describe, it, expect, beforeEach } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties, EdgeProperties, EdgeType } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { PathAnalyzer } from '../path-analyzer.js';
import type { PathOptimize } from '../path-analyzer.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

function makeConfig(overrides: Record<string, unknown> = {}) {
  return {
    id: 'test-eng',
    name: 'Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local'], exclusions: [] },
    objectives: [{ id: 'obj-da', description: 'Get DA', target_node_type: 'credential', target_criteria: { privileged: true }, achieved: false }],
    opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
    ...overrides,
  } as any;
}

const now = new Date().toISOString();

const BIDIR: Set<EdgeType> = new Set([
  'HAS_SESSION', 'ADMIN_TO', 'CAN_RDPINTO', 'CAN_PSREMOTE',
  'OWNS_CRED', 'VALID_ON', 'MEMBER_OF', 'MEMBER_OF_DOMAIN',
  'RELATED', 'SAME_DOMAIN', 'TRUSTS', 'ASSUMES_ROLE', 'MANAGED_BY',
] as EdgeType[]);

function addNode(graph: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  graph.addNode(id, { id, label: id, discovered_at: now, confidence: 1.0, ...props } as NodeProperties);
}

function addEdge(graph: OverwatchGraph, src: string, tgt: string, type: string, extra: Record<string, unknown> = {}) {
  return graph.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: now, ...extra } as EdgeProperties);
}

function buildAnalyzer(graph: OverwatchGraph, config?: any) {
  const ctx = new EngineContext(graph, config || makeConfig(), './test-state.json');
  const queryGraph = (query: any) => {
    const nodes: any[] = [];
    graph.forEachNode((id: string, attrs) => {
      if (query.node_type && attrs.type !== query.node_type) return;
      if (query.node_filter) {
        for (const [k, v] of Object.entries(query.node_filter)) {
          if ((attrs as any)[k] !== v) return;
        }
      }
      nodes.push({ id, properties: attrs });
    });
    return { nodes, edges: [] };
  };
  return new PathAnalyzer(ctx, BIDIR, queryGraph);
}

describe('PathAnalyzer', () => {
  // =============================================
  // findShortestPath
  // =============================================
  describe('findShortestPath', () => {
    it('finds a direct path between connected nodes', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'host-b', { type: 'host' });
      addEdge(graph, 'host-a', 'host-b', 'REACHABLE');

      const analyzer = buildAnalyzer(graph);
      const path = analyzer.findShortestPath('host-a', 'host-b');

      expect(path).toEqual(['host-a', 'host-b']);
    });

    it('finds a multi-hop path', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'user-1', { type: 'user' });
      addNode(graph, 'host-b', { type: 'host' });
      addEdge(graph, 'user-1', 'host-a', 'HAS_SESSION');
      addEdge(graph, 'user-1', 'host-b', 'ADMIN_TO');

      const analyzer = buildAnalyzer(graph);
      // Through bidirectional HAS_SESSION, host-a can reach user-1, then user-1 -> host-b
      const path = analyzer.findShortestPath('host-a', 'host-b');

      expect(path).not.toBeNull();
      expect(path!.length).toBeGreaterThanOrEqual(2);
      expect(path![0]).toBe('host-a');
      expect(path![path!.length - 1]).toBe('host-b');
    });

    it('returns null for disconnected nodes', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'host-b', { type: 'host' });

      const analyzer = buildAnalyzer(graph);
      const path = analyzer.findShortestPath('host-a', 'host-b');

      expect(path).toBeNull();
    });

    it('returns null for nonexistent nodes', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });

      const analyzer = buildAnalyzer(graph);
      expect(analyzer.findShortestPath('host-a', 'nonexistent')).toBeNull();
      expect(analyzer.findShortestPath('nonexistent', 'host-a')).toBeNull();
    });

    it('traverses bidirectional edges in reverse', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user' });
      addNode(graph, 'host-a', { type: 'host' });
      // Edge is user → host, but HAS_SESSION is bidirectional
      addEdge(graph, 'user-1', 'host-a', 'HAS_SESSION');

      const analyzer = buildAnalyzer(graph);
      const path = analyzer.findShortestPath('host-a', 'user-1');

      expect(path).not.toBeNull();
      expect(path).toEqual(['host-a', 'user-1']);
    });

    it('does NOT traverse non-bidirectional edges in reverse', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'host-b', { type: 'host' });
      // REACHABLE is NOT bidirectional
      addEdge(graph, 'host-a', 'host-b', 'REACHABLE');

      const analyzer = buildAnalyzer(graph);
      const path = analyzer.findShortestPath('host-b', 'host-a');

      expect(path).toBeNull();
    });
  });

  // =============================================
  // Path optimization modes
  // =============================================
  describe('optimization modes', () => {
    it('stealth mode prefers low-noise edges', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'host-b', { type: 'host' });
      addNode(graph, 'host-c', { type: 'host' });
      // Loud path: A → B (high noise)
      addEdge(graph, 'host-a', 'host-b', 'REACHABLE', { opsec_noise: 0.9 });
      addEdge(graph, 'host-b', 'host-c', 'REACHABLE', { opsec_noise: 0.9 });
      // Quiet path: A → C (low noise, longer but quieter)
      addEdge(graph, 'host-a', 'host-c', 'REACHABLE', { opsec_noise: 0.1 });

      const analyzer = buildAnalyzer(graph);
      const stealthPath = analyzer.findShortestPath('host-a', 'host-c', 'stealth');

      // Should take the direct quiet path
      expect(stealthPath).toEqual(['host-a', 'host-c']);
    });

    it('confidence mode prefers high-confidence edges', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'host-b', { type: 'host' });
      addNode(graph, 'host-c', { type: 'host' });
      // Low confidence path: A → B → C
      addEdge(graph, 'host-a', 'host-b', 'REACHABLE', { confidence: 0.3 });
      addEdge(graph, 'host-b', 'host-c', 'REACHABLE', { confidence: 0.3 });
      // High confidence direct: A → C
      addEdge(graph, 'host-a', 'host-c', 'REACHABLE', { confidence: 0.95 });

      const analyzer = buildAnalyzer(graph);
      const confPath = analyzer.findShortestPath('host-a', 'host-c', 'confidence');

      expect(confPath).toEqual(['host-a', 'host-c']);
    });
  });

  // =============================================
  // findPaths
  // =============================================
  describe('findPaths', () => {
    it('returns path with confidence and noise metrics', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'host-b', { type: 'host' });
      addEdge(graph, 'host-a', 'host-b', 'REACHABLE', { confidence: 0.8, opsec_noise: 0.4 });

      const analyzer = buildAnalyzer(graph);
      const paths = analyzer.findPaths('host-a', 'host-b');

      expect(paths.length).toBe(1);
      expect(paths[0].nodes).toEqual(['host-a', 'host-b']);
      expect(paths[0].total_confidence).toBeCloseTo(0.8);
      expect(paths[0].total_opsec_noise).toBeCloseTo(0.4);
    });

    it('returns empty for disconnected nodes', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'host-b', { type: 'host' });

      const analyzer = buildAnalyzer(graph);
      expect(analyzer.findPaths('host-a', 'host-b').length).toBe(0);
    });
  });

  // =============================================
  // hopsToNearestObjective
  // =============================================
  describe('hopsToNearestObjective', () => {
    it('returns hop count to matching objective node', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'user-1', { type: 'user' });
      addNode(graph, 'cred-priv', { type: 'credential', privileged: true });
      addEdge(graph, 'user-1', 'host-a', 'HAS_SESSION');
      addEdge(graph, 'user-1', 'cred-priv', 'OWNS_CRED');

      const analyzer = buildAnalyzer(graph);
      const hops = analyzer.hopsToNearestObjective('host-a');

      expect(hops).not.toBeNull();
      expect(hops).toBeGreaterThan(0);
    });

    it('returns null for node with no path to objectives', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });
      // No objective nodes in graph

      const analyzer = buildAnalyzer(graph);
      const hops = analyzer.hopsToNearestObjective('host-a');

      expect(hops).toBeNull();
    });

    it('returns null for nonexistent node', () => {
      const graph = makeGraph();

      const analyzer = buildAnalyzer(graph);
      expect(analyzer.hopsToNearestObjective('nonexistent')).toBeNull();
    });
  });

  // =============================================
  // Cache invalidation
  // =============================================
  describe('cache invalidation', () => {
    it('path graph cache is per-optimize mode', () => {
      const graph = makeGraph();
      addNode(graph, 'host-a', { type: 'host' });
      addNode(graph, 'host-b', { type: 'host' });
      addEdge(graph, 'host-a', 'host-b', 'REACHABLE');

      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const analyzer = new PathAnalyzer(ctx, BIDIR, () => ({ nodes: [], edges: [] }));

      // Query with two different modes
      analyzer.findShortestPath('host-a', 'host-b', 'confidence');
      analyzer.findShortestPath('host-a', 'host-b', 'stealth');

      // Both should be cached separately
      expect(ctx.pathGraphCache.size).toBe(2);

      // Invalidation clears both
      ctx.invalidatePathGraph();
      expect(ctx.pathGraphCache.size).toBe(0);
    });
  });
});
