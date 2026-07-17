import { describe, expect, it } from 'vitest';
import type { EdgeProperties, NodeProperties } from '../../types.js';
import type { ColdNodeRecord } from '../cold-store.js';
import {
  TransactionFootprintAccumulator,
  type GraphEdgeSnapshot,
  type GraphNodeSnapshot,
} from '../transaction-footprint.js';

const at = '2026-07-17T00:00:00.000Z';

function node(id: string, label = id): GraphNodeSnapshot {
  return {
    node_id: id,
    props: {
      id,
      type: 'host',
      label,
      discovered_at: at,
      confidence: 1,
    } satisfies NodeProperties,
  };
}

function edge(id: string, notes?: string): GraphEdgeSnapshot {
  return {
    edge_id: id,
    source: 'node-a',
    target: 'node-b',
    props: {
      type: 'REACHABLE',
      confidence: 1,
      discovered_at: at,
      ...(notes ? { notes } : {}),
    } satisfies EdgeProperties,
  };
}

function cold(id: string, label = id): ColdNodeRecord {
  return {
    id,
    type: 'host',
    label,
    discovered_at: at,
    last_seen_at: at,
  };
}

describe('TransactionFootprintAccumulator', () => {
  it('normalizes repeated touches to deterministic final node effects', () => {
    const footprint = new TransactionFootprintAccumulator();
    footprint.recordNode('node-new', null, node('node-new'));
    footprint.recordNode('node-new', node('node-new'), node('node-new', 'updated'));
    footprint.recordNode('node-removed', node('node-removed'), null);
    footprint.recordNode('node-updated', node('node-updated'), node('node-updated', 'updated'));
    footprint.recordNode('node-transient', null, node('node-transient'));
    footprint.recordNode('node-transient', node('node-transient'), null);

    const result = footprint.finalize();
    expect(result.node_changes.map(change => change.node_id)).toEqual([
      'node-new',
      'node-removed',
      'node-updated',
    ]);
    expect(result.update_detail).toMatchObject({
      new_nodes: ['node-new'],
      removed_nodes: ['node-removed'],
      updated_nodes: ['node-updated'],
    });
    expect(result.update_detail).not.toHaveProperty('new_edges');
  });

  it('treats remove and recreate as no-op or update from the first preimage', () => {
    const footprint = new TransactionFootprintAccumulator();
    footprint.recordNode('same', node('same'), null);
    footprint.recordNode('same', null, node('same'));
    footprint.recordNode('changed', node('changed'), null);
    footprint.recordNode('changed', null, node('changed', 'replacement'));

    const result = footprint.finalize();
    expect(result.node_changes).toEqual([{
      node_id: 'changed',
      before: node('changed'),
      after: node('changed', 'replacement'),
    }]);
    expect(result.update_detail).toEqual({ updated_nodes: ['changed'] });
  });

  it('sorts edge effects, retains only final inferred edges, and permits overlap', () => {
    const footprint = new TransactionFootprintAccumulator();
    footprint.recordEdge('edge-z', null, edge('edge-z'));
    footprint.recordEdge('edge-a', edge('edge-a'), edge('edge-a', 'updated'));
    footprint.recordEdge('edge-removed', edge('edge-removed'), null);
    footprint.recordEdge('edge-transient', null, edge('edge-transient'));
    footprint.recordEdge('edge-transient', edge('edge-transient'), null);
    footprint.markInferredEdge('edge-z');
    footprint.markInferredEdge('edge-removed');

    const result = footprint.finalize();
    expect(result.edge_changes.map(change => change.edge_id)).toEqual([
      'edge-a',
      'edge-removed',
      'edge-z',
    ]);
    expect(result.update_detail).toEqual({
      new_edges: ['edge-z'],
      updated_edges: ['edge-a'],
      inferred_edges: ['edge-z'],
      removed_edges: ['edge-removed'],
    });
  });

  it('flags cold replacement only when the final inventory differs', () => {
    const footprint = new TransactionFootprintAccumulator();
    footprint.recordCold('cold-b', null, cold('cold-b'));
    footprint.recordCold('cold-a', cold('cold-a'), null);
    footprint.recordCold('cold-noop', cold('cold-noop'), cold('cold-noop'));

    const result = footprint.finalize();
    expect(result.cold_changes.map(change => change.id)).toEqual(['cold-a', 'cold-b']);
    expect(result.update_detail).toEqual({ cold_nodes_changed: true });
  });

  it('detaches retained preimages and returned results from caller mutation', () => {
    const footprint = new TransactionFootprintAccumulator();
    const before = node('node-a');
    const after = node('node-a', 'after');
    footprint.recordNode('node-a', before, after);
    before.props.label = 'mutated-before';
    after.props.label = 'mutated-after';

    const first = footprint.finalize();
    expect(first.node_changes[0].before?.props.label).toBe('node-a');
    expect(first.node_changes[0].after?.props.label).toBe('after');
    first.node_changes[0].after!.props.label = 'mutated-result';
    expect(footprint.finalize().node_changes[0].after?.props.label).toBe('after');
  });
});
