import { describe, expect, it } from 'vitest';
import type { RawGraphDto } from '@overwatch/dashboard-contracts';
import { flattenNode, projectRawGraph } from '../graph-flatten';

describe('raw graph projection', () => {
  it('flattens wrapped properties while preserving wrapper identity and removing the wrapper', () => {
    const node = flattenNode({
      id: 'canonical-id',
      properties: {
        id: 'untrusted-property-id', type: 'host', label: 'dc01', confidence: 0.9,
        discovered_at: '2026-07-15T00:00:00Z', properties: { nested: true }, ip: '10.0.0.10',
      },
    } as never);
    expect(node).toMatchObject({ id: 'canonical-id', type: 'host', label: 'dc01', ip: '10.0.0.10' });
    expect(node).not.toHaveProperty('properties');
  });

  it('rejects a raw node whose type is absent or outside the canonical vocabulary', () => {
    expect(() => flattenNode({ id: 'bad', properties: { label: 'bad' } } as never)).toThrow();
    expect(() => flattenNode({ id: 'bad', properties: { type: 'invented', label: 'bad' } } as never)).toThrow();
  });

  it('keeps cold inventory explicitly separate from the hot graph', () => {
    const raw: RawGraphDto = {
      nodes: [{ id: 'hot', properties: { type: 'host', label: 'hot' } }],
      edges: [],
      cold_nodes: [{
        id: 'cold', type: 'host', label: 'cold', discovered_at: '2026-07-15T00:00:00Z',
        last_seen_at: '2026-07-15T00:00:00Z',
      }],
    };
    const projected = projectRawGraph(raw);
    expect(projected.nodes.map(node => node.id)).toEqual(['hot']);
    expect(projected.coldInventory.map(node => node.id)).toEqual(['cold']);
  });
});
