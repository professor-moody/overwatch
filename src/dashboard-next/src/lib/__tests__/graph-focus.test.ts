import { describe, expect, it } from 'vitest';
import Graph from 'graphology';
import { buildGraphFocusApplication, hasFiniteNodePosition } from '../graph-focus';
import type { ResolvedGraphTarget } from '../graph-target';

function sampleGraph() {
  const graph = new Graph({ type: 'directed', multi: true });
  graph.addNode('cred', { x: 0, y: 0 });
  graph.addNode('svc', { x: 1, y: 1 });
  graph.addNode('host', { x: 2, y: 1 });
  graph.addNode('missing-pos');
  graph.addEdgeWithKey('e-cred-svc', 'cred', 'svc', { edgeType: 'TESTED_CRED' });
  graph.addEdgeWithKey('e-host-svc', 'host', 'svc', { edgeType: 'RUNS' });
  return graph;
}

function resolved(overrides: Partial<ResolvedGraphTarget>): ResolvedGraphTarget {
  return {
    kind: 'node',
    label: 'Focus',
    nodes: new Set(['cred']),
    edges: new Set(),
    primaryNode: 'cred',
    hops: 2,
    ...overrides,
  };
}

describe('graph focus application', () => {
  it('expands node focus by requested hops and inspects adjacent edges', () => {
    const focus = buildGraphFocusApplication(sampleGraph(), resolved({ kind: 'node', hops: 1 }));

    expect(focus?.primaryNode).toBe('cred');
    expect(focus?.focusNodes).toEqual(new Set(['cred', 'svc']));
    expect(focus?.inspectedEdges.has('e-cred-svc')).toBe(true);
    expect(focus?.noRenderableReason).toBeUndefined();
  });

  it('expands single contextual evidence/finding/frontier targets to one hop', () => {
    const focus = buildGraphFocusApplication(sampleGraph(), resolved({
      kind: 'frontier',
      label: 'Frontier item',
      nodes: new Set(['cred']),
      hops: 0,
    }));

    expect(focus?.focusNodes).toEqual(new Set(['cred', 'svc']));
  });

  it('keeps path edges and path nodes when provided by the resolved target', () => {
    const focus = buildGraphFocusApplication(sampleGraph(), resolved({
      kind: 'path',
      nodes: new Set(['cred', 'svc']),
      edges: new Set(['e-cred-svc']),
      hops: 0,
    }));

    expect(focus?.pathEdges).toEqual(new Set(['e-cred-svc']));
    expect(focus?.pathNodes).toEqual(new Set(['cred', 'svc']));
  });

  it('reports no-renderable targets without inventing a camera fallback', () => {
    const graph = sampleGraph();
    const focus = buildGraphFocusApplication(graph, resolved({
      kind: 'evidence',
      label: 'Evidence for missing-pos',
      nodes: new Set(['missing-pos']),
      primaryNode: 'missing-pos',
      hops: 0,
    }));

    expect(hasFiniteNodePosition(graph, 'missing-pos')).toBe(false);
    expect(focus?.noRenderableReason).toContain('Evidence for missing-pos');
  });
});
