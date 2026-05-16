import { describe, expect, it } from 'vitest';
import {
  buildFrontierSections,
  filterFrontierItems,
  frontierReferencesNode,
  getFrontierNodeIds,
  getFrontierPrimaryNodeId,
  sortFrontierItems,
} from '../frontier-workspace';
import type { FrontierItem } from '../types';

function item(partial: Partial<FrontierItem>): FrontierItem {
  return {
    id: partial.id || 'f1',
    type: partial.type || 'incomplete_node',
    priority: partial.priority ?? 1,
    description: partial.description || 'frontier item',
    ...partial,
  };
}

describe('frontier workspace helpers', () => {
  it('selects and matches node ids in operator priority order', () => {
    const frontier = item({
      target_node: 'target',
      node_id: 'node',
      edge_target: 'dst',
      edge_source: 'src',
      source_node: 'source',
    });

    expect(getFrontierNodeIds(frontier)).toEqual(['target', 'node', 'src', 'dst', 'source']);
    expect(getFrontierPrimaryNodeId(frontier)).toBe('target');
    expect(frontierReferencesNode(frontier, 'dst')).toBe(true);
    expect(frontierReferencesNode(frontier, 'missing')).toBe(false);
  });

  it('sorts by priority then stable frontier id', () => {
    const sorted = sortFrontierItems([
      item({ id: 'b', priority: 3 }),
      item({ id: 'a', priority: 3 }),
      item({ id: 'c', priority: 9 }),
    ]);

    expect(sorted.map(getFrontierPrimaryNodeId)).toEqual([null, null, null]);
    expect(sorted.map(x => x.id)).toEqual(['c', 'a', 'b']);
  });

  it('filters by type and node before building sections', () => {
    const items = [
      item({ id: 'n1', type: 'network_discovery', priority: 1, edge_source: 'host-1' }),
      item({ id: 'c1', type: 'credential_test', priority: 4, target_node: 'cred-1' }),
      item({ id: 'c2', type: 'credential_test', priority: 2, edge_target: 'host-1' }),
    ];

    expect(filterFrontierItems(items, 'credential_test').map(x => x.id)).toEqual(['c1', 'c2']);
    expect(buildFrontierSections(items, { nodeFilter: 'host-1' })).toEqual([
      {
        key: 'matching',
        title: 'Matching Items',
        items: [items[2], items[0]],
        total: 2,
      },
    ]);
  });
});
