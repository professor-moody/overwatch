import { performance } from 'node:perf_hooks';
import { describe, expect, it } from 'vitest';
import { GraphDeltaIndex } from '../graph-delta-index';
import type { ExportedGraph, GraphUpdateData } from '../types';

function graphFixture(size: number): ExportedGraph {
  return {
    nodes: Array.from({ length: size }, (_, index) => ({
      id: `node-${index}`,
      type: 'host' as const,
      label: `Node ${index}`,
      confidence: 1,
      discovered_at: '2026-07-16T00:00:00.000Z',
    })),
    edges: Array.from({ length: size }, (_, index) => ({
      id: `edge-${index}`,
      source: `node-${index}`,
      target: `node-${(index + 1) % size}`,
      type: 'REACHABLE',
      confidence: 1,
    })),
    coldInventory: [],
  };
}

function tenItemDelta(): GraphUpdateData {
  return {
    state: {}, history_count: 0, detail: {},
    delta: {
      nodes: Array.from({ length: 5 }, (_, index) => ({
        id: `node-${index * 2}`,
        properties: {
          type: 'host', label: `Updated ${index}`, confidence: 1,
          discovered_at: '2026-07-16T00:00:00.000Z',
        },
      })),
      edges: Array.from({ length: 5 }, (_, index) => ({
        id: `edge-${index * 2}`,
        source: `node-${index * 2}`,
        target: `node-${index * 2 + 1}`,
        properties: { type: 'REACHABLE', confidence: 1 },
      })),
      removed_nodes: [],
      removed_edges: [],
    },
  } as GraphUpdateData;
}

describe('GraphDeltaIndex', () => {
  it('updates and removes entities without replacing the complete arrays', () => {
    const graph = graphFixture(4);
    const nodes = graph.nodes;
    const edges = graph.edges;
    const index = new GraphDeltaIndex();
    index.reset(graph);
    const next = index.apply(graph, {
      ...tenItemDelta(),
      delta: {
        nodes: [{ id: 'node-1', properties: { type: 'host', label: 'Changed', confidence: 1, discovered_at: '2026-07-16T00:00:00.000Z' } }],
        edges: [],
        removed_nodes: ['node-3'],
        removed_edges: ['edge-3'],
      },
    } as GraphUpdateData);

    expect(next.nodes).toBe(nodes);
    expect(next.edges).toBe(edges);
    expect(next.nodes.find(node => node.id === 'node-1')?.label).toBe('Changed');
    expect(next.nodes.some(node => node.id === 'node-3')).toBe(false);
    expect(next.edges.some(edge => edge.id === 'edge-3')).toBe(false);
  });

  it('merges a ten-item 50k graph delta below the operator budget', () => {
    const graph = graphFixture(50_000);
    const index = new GraphDeltaIndex();
    index.reset(graph);
    const delta = tenItemDelta();
    const samples: number[] = [];
    for (let iteration = 0; iteration < 9; iteration++) {
      const started = performance.now();
      index.apply(graph, delta);
      if (iteration >= 2) samples.push(performance.now() - started);
    }
    samples.sort((left, right) => left - right);
    expect(samples[Math.floor(samples.length / 2)]).toBeLessThan(100);
  });

  it('patches changed community assignments without scanning or replacing graph arrays', () => {
    const graph = graphFixture(50_000);
    const nodes = graph.nodes;
    const index = new GraphDeltaIndex();
    index.reset(graph);
    const changedIds = Object.fromEntries(
      Array.from({ length: 10 }, (_, offset) => [`node-${offset * 2}`, offset + 1]),
    );
    const started = performance.now();
    const changed = index.applyCommunityIds(graph, changedIds);

    expect(performance.now() - started).toBeLessThan(100);
    expect(graph.nodes).toBe(nodes);
    expect(changed).toHaveLength(10);
    expect(graph.nodes[0].community_id).toBe(1);
    expect(graph.nodes[1].community_id).toBeUndefined();
  });
});
