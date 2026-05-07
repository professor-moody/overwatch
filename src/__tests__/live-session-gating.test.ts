// ============================================================
// F1 — closed sessions must not drive active reasoning.
//
// session-tracker marks HAS_SESSION edges with `session_live: false`
// when a shell closes / the server restarts / the watchdog reaps the
// agent. Several consumers used to gate only on type+confidence and
// continued to treat dead shells as live access. The new isLiveSessionEdge
// helper centralizes the predicate; this suite pins the behavior at:
//   - path graph (no dead-shell reachability)
//   - findPathsToObjective (no dead-shell start nodes)
//   - objective achievement (no dead-shell as path to objective)
// ============================================================

import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { EdgeType, NodeProperties, EdgeProperties } from '../types.js';
import type { OverwatchGraph } from '../services/engine-context.js';
import { EngineContext } from '../services/engine-context.js';
import { PathAnalyzer } from '../services/path-analyzer.js';
import { evaluateObjectives } from '../services/objective-manager.js';
import { isLiveSessionEdge, isHasSessionEdge } from '../services/session-edge-utils.js';

const now = new Date().toISOString();
const BIDIR: Set<EdgeType> = new Set([
  'HAS_SESSION', 'ADMIN_TO', 'CAN_RDPINTO', 'CAN_PSREMOTE',
  'OWNS_CRED', 'VALID_ON', 'MEMBER_OF', 'MEMBER_OF_DOMAIN',
  'RELATED', 'SAME_DOMAIN', 'TRUSTS', 'ASSUMES_ROLE', 'MANAGED_BY',
] as EdgeType[]);

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, allowSelfLoops: true, type: 'directed' }) as OverwatchGraph;
}
function addNode(graph: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  graph.addNode(id, { id, label: id, discovered_at: now, confidence: 1.0, ...props } as NodeProperties);
}
function addEdge(graph: OverwatchGraph, src: string, tgt: string, type: string, extra: Record<string, unknown> = {}) {
  return graph.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: now, ...extra } as EdgeProperties);
}
function makeConfig(overrides: Record<string, unknown> = {}) {
  return {
    id: 'test-live-session',
    name: 'live-session test',
    created_at: '2026-05-07T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  } as any;
}

describe('isLiveSessionEdge', () => {
  it('treats undefined edges as not live', () => {
    expect(isLiveSessionEdge(undefined)).toBe(false);
    expect(isLiveSessionEdge(null)).toBe(false);
  });
  it('returns false for non-HAS_SESSION edges', () => {
    expect(isLiveSessionEdge({ type: 'ADMIN_TO', confidence: 1 })).toBe(false);
  });
  it('returns true when session_live is undefined (legacy edges)', () => {
    expect(isLiveSessionEdge({ type: 'HAS_SESSION', confidence: 1 })).toBe(true);
  });
  it('returns true when session_live === true', () => {
    expect(isLiveSessionEdge({ type: 'HAS_SESSION', confidence: 1, session_live: true })).toBe(true);
  });
  it('returns false when session_live === false', () => {
    expect(isLiveSessionEdge({ type: 'HAS_SESSION', confidence: 1, session_live: false })).toBe(false);
  });
  it('isHasSessionEdge ignores liveness for reporting paths', () => {
    expect(isHasSessionEdge({ type: 'HAS_SESSION', session_live: false })).toBe(true);
    expect(isHasSessionEdge({ type: 'ADMIN_TO' })).toBe(false);
  });
});

describe('PathAnalyzer with closed sessions (F1)', () => {
  it('does not include dead HAS_SESSION edges in the path graph', () => {
    const graph = makeGraph();
    addNode(graph, 'user-1', { type: 'user' });
    addNode(graph, 'host-a', { type: 'host', ip: '10.10.10.5', alive: true });
    addNode(graph, 'host-b', { type: 'host', ip: '10.10.10.6', alive: true });
    // Dead session into host-a (closed shell). Pure-path reachability
    // from user-1 should NOT consider this edge.
    addEdge(graph, 'user-1', 'host-a', 'HAS_SESSION', { session_live: false, confidence: 1.0 });
    // host-a is otherwise unreachable from user-1.
    const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
    const analyzer = new PathAnalyzer(ctx, BIDIR, () => ({ nodes: [], edges: [] }));
    const path = analyzer.findShortestPath('user-1', 'host-a');
    expect(path).toBeNull();
  });

  it('honors live HAS_SESSION edges as a reachable path', () => {
    const graph = makeGraph();
    addNode(graph, 'user-1', { type: 'user' });
    addNode(graph, 'host-a', { type: 'host', ip: '10.10.10.5', alive: true });
    addEdge(graph, 'user-1', 'host-a', 'HAS_SESSION', { session_live: true, confidence: 1.0 });
    const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
    const analyzer = new PathAnalyzer(ctx, BIDIR, () => ({ nodes: [], edges: [] }));
    const path = analyzer.findShortestPath('user-1', 'host-a');
    expect(path).toEqual(['user-1', 'host-a']);
  });
});

describe('Objective achievement with closed sessions (F1)', () => {
  it('does not mark a host objective achieved via a dead HAS_SESSION edge', () => {
    const graph = makeGraph();
    addNode(graph, 'host-target', { type: 'host', ip: '10.10.10.50', alive: true, label: 'CROWN-JEWEL' });
    addNode(graph, 'user-attacker', { type: 'user' });
    // Dead session — must NOT count as achievement.
    addEdge(graph, 'user-attacker', 'host-target', 'HAS_SESSION', { session_live: false, confidence: 1.0 });

    const config = makeConfig({
      objectives: [{
        id: 'obj-target',
        description: 'Compromise CROWN-JEWEL',
        target_node_type: 'host',
        target_criteria: { ip: '10.10.10.50' },
        achieved: false,
      }],
    });
    const ctx = new EngineContext(graph, config, './test-state.json');
    const queryGraph = (q: any) => {
      const nodes: any[] = [];
      graph.forEachNode((id: string, attrs) => {
        if (q.node_type && attrs.type !== q.node_type) return;
        if (q.node_filter) {
          for (const [k, v] of Object.entries(q.node_filter)) {
            if ((attrs as any)[k] !== v) return;
          }
        }
        nodes.push({ id, properties: attrs });
      });
      return { nodes, edges: [] };
    };
    evaluateObjectives({
      ctx,
      queryGraph,
      getNode: (id: string) => graph.hasNode(id) ? graph.getNodeAttributes(id) as NodeProperties : null,
      getNodesByType: () => [],
      persist: () => {},
      log: () => {},
    } as any);

    expect(ctx.config.objectives[0].achieved).toBe(false);
  });

  it('marks the objective achieved with a live HAS_SESSION edge', () => {
    const graph = makeGraph();
    addNode(graph, 'host-target', { type: 'host', ip: '10.10.10.50', alive: true, label: 'CROWN-JEWEL' });
    addNode(graph, 'user-attacker', { type: 'user' });
    addEdge(graph, 'user-attacker', 'host-target', 'HAS_SESSION', { session_live: true, confidence: 1.0 });

    const config = makeConfig({
      objectives: [{
        id: 'obj-target',
        description: 'Compromise CROWN-JEWEL',
        target_node_type: 'host',
        target_criteria: { ip: '10.10.10.50' },
        achieved: false,
      }],
    });
    const ctx = new EngineContext(graph, config, './test-state.json');
    const queryGraph = (q: any) => {
      const nodes: any[] = [];
      graph.forEachNode((id: string, attrs) => {
        if (q.node_type && attrs.type !== q.node_type) return;
        if (q.node_filter) {
          for (const [k, v] of Object.entries(q.node_filter)) {
            if ((attrs as any)[k] !== v) return;
          }
        }
        nodes.push({ id, properties: attrs });
      });
      return { nodes, edges: [] };
    };
    evaluateObjectives({
      ctx,
      queryGraph,
      getNode: (id: string) => graph.hasNode(id) ? graph.getNodeAttributes(id) as NodeProperties : null,
      getNodesByType: () => [],
      persist: () => {},
      log: () => {},
    } as any);

    expect(ctx.config.objectives[0].achieved).toBe(true);
  });
});
