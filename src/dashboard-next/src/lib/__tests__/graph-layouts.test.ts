import { describe, expect, it } from 'vitest';
import Graph from 'graphology';
import { computeHierarchical, computeTiered } from '../graph-layouts';

function addNode(g: Graph, id: string, type: string, extra: Record<string, unknown> = {}) {
  g.addNode(id, { x: 0, y: 0, size: 6, nodeType: type, _props: { id, type, label: id, confidence: 1, discovered_at: '' }, ...extra });
}
const y = (g: Graph, id: string) => g.getNodeAttribute(id, 'y') as number;
const xy = (g: Graph, id: string) => `${g.getNodeAttribute(id, 'x')},${y(g, id)}`;

describe('computeTiered', () => {
  it('orders bands top→bottom by role (identity above network) and is deterministic', () => {
    const build = () => {
      const g = new Graph({ type: 'directed', multi: true });
      addNode(g, 'idp1', 'idp'); addNode(g, 'idp2', 'idp');
      addNode(g, 'host1', 'host'); addNode(g, 'host2', 'host');
      return g;
    };
    const g = build();
    computeTiered(g);
    expect(y(g, 'idp1')).toBeLessThan(y(g, 'host1')); // identity band sits above network band

    const g2 = build();
    computeTiered(g2);
    for (const id of ['idp1', 'idp2', 'host1', 'host2']) expect(xy(g, id)).toBe(xy(g2, id));
  });

  it('never moves a pinned (fixed) node', () => {
    const g = new Graph({ type: 'directed', multi: true });
    addNode(g, 'a', 'host'); addNode(g, 'b', 'idp');
    addNode(g, 'pinned', 'host', { x: 999, y: 999, fixed: true });
    computeTiered(g);
    expect(g.getNodeAttribute('pinned', 'x')).toBe(999);
    expect(g.getNodeAttribute('pinned', 'y')).toBe(999);
  });
});

describe('computeHierarchical', () => {
  it('ranks along edge direction top→bottom (source above target)', () => {
    const g = new Graph({ type: 'directed', multi: true });
    addNode(g, 'a', 'domain'); addNode(g, 'b', 'host'); addNode(g, 'c', 'service');
    g.addEdge('a', 'b', { edgeType: 'RUNS' });
    g.addEdge('b', 'c', { edgeType: 'RUNS' });
    computeHierarchical(g);
    expect(y(g, 'a')).toBeLessThan(y(g, 'b'));
    expect(y(g, 'b')).toBeLessThan(y(g, 'c'));
  });

  it('gives every non-fixed node finite coordinates and skips fixed nodes', () => {
    const g = new Graph({ type: 'directed', multi: true });
    addNode(g, 'a', 'host'); addNode(g, 'b', 'service');
    addNode(g, 'pinned', 'host', { x: 42, y: 42, fixed: true });
    g.addEdge('a', 'b', { edgeType: 'RUNS' });
    computeHierarchical(g);
    for (const id of ['a', 'b']) {
      expect(Number.isFinite(g.getNodeAttribute(id, 'x'))).toBe(true);
      expect(Number.isFinite(g.getNodeAttribute(id, 'y'))).toBe(true);
    }
    expect(g.getNodeAttribute('pinned', 'y')).toBe(42);
  });

  it('ignores non-structural (REACHABLE) edges for ranking', () => {
    const g = new Graph({ type: 'directed', multi: true });
    addNode(g, 'a', 'host'); addNode(g, 'b', 'host');
    g.addEdge('a', 'b', { edgeType: 'REACHABLE' }); // excluded from the hierarchy
    computeHierarchical(g);
    // No structural edge → both stay on the same rank (no top/bottom flow separation).
    expect(y(g, 'a')).toBe(y(g, 'b'));
  });
});
