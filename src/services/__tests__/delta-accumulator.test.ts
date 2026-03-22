import { describe, expect, it } from 'vitest';
import { DeltaAccumulator } from '../delta-accumulator.js';

describe('DeltaAccumulator', () => {
  it('merges repeated pushes without losing ids', () => {
    const accumulator = new DeltaAccumulator();

    accumulator.push({ new_nodes: ['node-a'], new_edges: ['edge-a'] });
    accumulator.push({ updated_nodes: ['node-b'], inferred_edges: ['edge-b'] });

    expect(accumulator.drain()).toEqual({
      new_nodes: ['node-a'],
      new_edges: ['edge-a'],
      updated_nodes: ['node-b'],
      inferred_edges: ['edge-b'],
    });
  });

  it('dedupes repeated ids across pushes', () => {
    const accumulator = new DeltaAccumulator();

    accumulator.push({ new_nodes: ['node-a', 'node-a'], new_edges: ['edge-a'] });
    accumulator.push({ new_nodes: ['node-a'], new_edges: ['edge-a', 'edge-b'] });

    expect(accumulator.drain()).toEqual({
      new_nodes: ['node-a'],
      new_edges: ['edge-a', 'edge-b'],
    });
  });

  it('returns null after drain when empty', () => {
    const accumulator = new DeltaAccumulator();

    accumulator.push({ new_nodes: ['node-a'] });
    expect(accumulator.drain()).toEqual({ new_nodes: ['node-a'] });
    expect(accumulator.drain()).toBeNull();
  });
});
