import { performance } from 'node:perf_hooks';
import Graph from 'graphology';
import { describe, expect, it } from 'vitest';
import { applyGraphCommunityPatch } from '../useGraph';
import type { ExportedNode } from '../../lib/types';

function node(id: string, communityId: number): ExportedNode {
  return {
    id,
    type: 'host',
    label: id,
    confidence: 1,
    discovered_at: '2026-07-16T00:00:00.000Z',
    community_id: communityId,
  };
}

describe('rendered graph community patches', () => {
  it('updates Graphology community attributes and raw properties by changed ID', () => {
    const graph = new Graph({ type: 'directed', multi: true });
    graph.addNode('host-1', {
      x: 0,
      y: 0,
      community: 1,
      _props: node('host-1', 1),
    });

    applyGraphCommunityPatch(graph, [node('host-1', 7)]);

    expect(graph.getNodeAttribute('host-1', 'community')).toBe(7);
    expect((graph.getNodeAttribute('host-1', '_props') as ExportedNode).community_id).toBe(7);
  });

  it('patches ten rendered nodes in a 50k graph below the delta budget', () => {
    const graph = new Graph({ type: 'directed', multi: true });
    for (let index = 0; index < 50_000; index++) {
      graph.addNode(`host-${index}`, {
        x: 0,
        y: 0,
        community: 0,
        _props: node(`host-${index}`, 0),
      });
    }
    const patch = Array.from({ length: 10 }, (_, index) => node(`host-${index * 2}`, index + 1));
    const started = performance.now();
    applyGraphCommunityPatch(graph, patch);

    expect(performance.now() - started).toBeLessThan(100);
    expect(graph.getNodeAttribute('host-18', 'community')).toBe(10);
    expect(graph.getNodeAttribute('host-19', 'community')).toBe(0);
  });
});
