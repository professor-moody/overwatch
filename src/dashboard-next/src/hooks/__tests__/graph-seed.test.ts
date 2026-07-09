import { describe, expect, it } from 'vitest';
import { seedByCommunity } from '../useGraph';
import type { ExportedNode } from '../../lib/types';

function node(id: string, community_id?: number): ExportedNode {
  return { id, type: 'host', label: id, confidence: 1, discovered_at: '', community_id };
}

function centroid(pos: Record<string, { x: number; y: number }>, ids: string[]) {
  const n = ids.length;
  return {
    x: ids.reduce((s, id) => s + pos[id].x, 0) / n,
    y: ids.reduce((s, id) => s + pos[id].y, 0) / n,
  };
}
const dist = (a: { x: number; y: number }, b: { x: number; y: number }) => Math.hypot(a.x - b.x, a.y - b.y);

describe('seedByCommunity', () => {
  it('returns null when there are fewer than 2 communities', () => {
    expect(seedByCommunity([node('a', 0), node('b', 0), node('c')])).toBeNull();
    expect(seedByCommunity([node('a'), node('b')])).toBeNull();
  });

  it('positions every node with FINITE coords — incl. ids whose hash exceeds 2^31', () => {
    // These real-world ids hash to >= 2^31; a signed `>> 3` on the unsigned hash
    // would make the disc radius sqrt(negative) → NaN. Guards that regression.
    const nodes = [
      node('a', 0), node('b', 0),
      node('dc01.corp.local', 1), node('https://api.example.com', 1),
      node('service:445/tcp', 2), node('c', 2),
    ];
    const pos = seedByCommunity(nodes)!;
    expect(pos).not.toBeNull();
    for (const n of nodes) {
      expect(Number.isFinite(pos[n.id].x)).toBe(true);
      expect(Number.isFinite(pos[n.id].y)).toBe(true);
    }
  });

  it('separates communities: intra-community spread is much smaller than inter-community centroid distance', () => {
    const nodes = [
      node('a0', 0), node('a1', 0), node('a2', 0),
      node('b0', 1), node('b1', 1), node('b2', 1),
    ];
    const pos = seedByCommunity(nodes)!;
    const cA = centroid(pos, ['a0', 'a1', 'a2']);
    const cB = centroid(pos, ['b0', 'b1', 'b2']);
    const between = dist(cA, cB);
    // Each member sits within its own cluster disc, so it's far closer to its own
    // centroid than the two centroids are to each other.
    for (const id of ['a0', 'a1', 'a2']) expect(dist(pos[id], cA)).toBeLessThan(between);
    for (const id of ['b0', 'b1', 'b2']) expect(dist(pos[id], cB)).toBeLessThan(between);
  });

  it('is deterministic for the same input (stable seed across reloads)', () => {
    const nodes = [node('a', 0), node('b', 1), node('c', 1), node('d', 2)];
    expect(seedByCommunity(nodes)).toEqual(seedByCommunity(nodes));
  });

  it('still seeds a node that is missing a community_id', () => {
    const pos = seedByCommunity([node('a', 0), node('b', 1), node('orphan')])!;
    expect(Number.isFinite(pos['orphan'].x)).toBe(true);
    expect(Number.isFinite(pos['orphan'].y)).toBe(true);
  });
});
