import { describe, expect, it } from 'vitest';
import Graph from 'graphology';
import { explodeHubs } from '../graph-hub-layout';

// A hub at the origin with `n` degree-1 leaf children.
function starGraph(n: number) {
  const g = new Graph({ type: 'directed', multi: true });
  g.addNode('hub', { x: 0, y: 0 });
  for (let i = 0; i < n; i++) {
    // Seed every leaf stacked ON the hub — the exact failure mode.
    g.addNode(`leaf${i}`, { x: 0, y: 0 });
    g.addEdgeWithKey(`e${i}`, 'hub', `leaf${i}`, {});
  }
  return g;
}

const dist = (g: Graph, id: string) =>
  Math.hypot(g.getNodeAttribute(id, 'x') as number, g.getNodeAttribute(id, 'y') as number);

describe('explodeHubs', () => {
  it('fans a large hub\'s leaves out into rings (no longer stacked on the hub)', () => {
    const g = starGraph(30);
    const exploded = explodeHubs(g);
    expect(exploded).toBe(1);
    // Every leaf moved off the hub…
    for (let i = 0; i < 30; i++) expect(dist(g, `leaf${i}`)).toBeGreaterThan(0);
    // …and no two leaves share the same position.
    const seen = new Set<string>();
    for (let i = 0; i < 30; i++) {
      const key = `${g.getNodeAttribute(`leaf${i}`, 'x')},${g.getNodeAttribute(`leaf${i}`, 'y')}`;
      expect(seen.has(key)).toBe(false);
      seen.add(key);
    }
    // The hub itself stays put.
    expect(dist(g, 'hub')).toBe(0);
  });

  it('leaves small stars alone (below the minLeaves threshold)', () => {
    const g = starGraph(3);
    expect(explodeHubs(g)).toBe(0);
    for (let i = 0; i < 3; i++) expect(dist(g, `leaf${i}`)).toBe(0);
  });

  it('does not move a node that has more than one neighbour (not a leaf)', () => {
    const g = new Graph({ type: 'directed', multi: true });
    g.addNode('hub', { x: 0, y: 0 });
    g.addNode('other', { x: 100, y: 100 });
    for (let i = 0; i < 10; i++) {
      g.addNode(`leaf${i}`, { x: 0, y: 0 });
      g.addEdgeWithKey(`e${i}`, 'hub', `leaf${i}`, {});
    }
    // `shared` connects to BOTH hub and other → not a leaf, must not be fanned.
    g.addNode('shared', { x: 5, y: 5 });
    g.addEdgeWithKey('e-hub-shared', 'hub', 'shared', {});
    g.addEdgeWithKey('e-other-shared', 'other', 'shared', {});
    explodeHubs(g);
    expect(g.getNodeAttribute('shared', 'x')).toBe(5);
    expect(g.getNodeAttribute('shared', 'y')).toBe(5);
  });

  it('never moves a pinned (fixed) leaf', () => {
    const g = starGraph(10);
    g.setNodeAttribute('leaf0', 'fixed', true);
    explodeHubs(g);
    expect(dist(g, 'leaf0')).toBe(0);
  });

  it('sizes the fan relative to the graph span (scale-invariant, not absolute units)', () => {
    // A far node sets the coordinate span; the same leaf should sit ~10x farther
    // from the hub in a 10x-larger graph, so the fan never dwarfs (or vanishes in)
    // the surrounding layout regardless of its normalized scale.
    const star = (spanNode: number) => {
      const g = new Graph({ type: 'directed', multi: true });
      g.addNode('hub', { x: 0, y: 0 });
      g.addNode('far', { x: spanNode, y: 0 }); // degree 0 → just sets the span
      for (let i = 0; i < 20; i++) { g.addNode(`leaf${i}`, { x: 0, y: 0 }); g.addEdgeWithKey(`e${i}`, 'hub', `leaf${i}`, {}); }
      return g;
    };
    const small = star(100); explodeHubs(small);
    const big = star(1000); explodeHubs(big);
    expect(dist(big, 'leaf5')).toBeGreaterThan(dist(small, 'leaf5') * 5);
  });

  it('is deterministic', () => {
    const a = starGraph(20); explodeHubs(a);
    const b = starGraph(20); explodeHubs(b);
    for (let i = 0; i < 20; i++) {
      expect(a.getNodeAttribute(`leaf${i}`, 'x')).toBe(b.getNodeAttribute(`leaf${i}`, 'x'));
      expect(a.getNodeAttribute(`leaf${i}`, 'y')).toBe(b.getNodeAttribute(`leaf${i}`, 'y'));
    }
  });
});
