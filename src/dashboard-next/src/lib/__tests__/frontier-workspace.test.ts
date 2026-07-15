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

function item(partial: Record<string, unknown> = {}): FrontierItem {
  return {
    id: partial.id || 'f1',
    type: partial.type || 'incomplete_node',
    node_id: 'node-1',
    description: partial.description || 'frontier item',
    graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 1 },
    opsec_noise: 0.2,
    staleness_seconds: 0,
    ...partial,
  } as FrontierItem;
}

describe('frontier workspace helpers', () => {
  it('selects and matches node ids in operator priority order', () => {
    const frontier = item({
      type: 'network_pivot',
      node_id: 'target',
      edge_target: 'dst',
      edge_source: 'src',
      pivot_host_id: 'pivot',
      via_pivot: 'principal',
    });

    expect(getFrontierNodeIds(frontier)).toEqual(['target', 'src', 'dst', 'pivot', 'principal']);
    expect(getFrontierPrimaryNodeId(frontier)).toBe('target');
    expect(frontierReferencesNode(frontier, 'dst')).toBe(true);
    expect(frontierReferencesNode(frontier, 'missing')).toBe(false);
  });

  it('preserves server order regardless of score or frontier id', () => {
    const sorted = sortFrontierItems([
      item({ id: 'b', graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 3 } }),
      item({ id: 'a', graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 3 } }),
      item({ id: 'c', graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 9 } }),
    ]);

    expect(sorted.map(x => x.id)).toEqual(['b', 'a', 'c']);
  });

  it('filters by type and node before building sections', () => {
    const items = [
      item({ id: 'n1', type: 'network_discovery', target_cidr: '10.0.0.0/24' }),
      item({ id: 'c1', type: 'credential_test', node_id: 'host-2', credential_id: 'cred-1' }),
      item({ id: 'c2', type: 'credential_test', node_id: 'host-1', credential_id: 'cred-2' }),
    ];

    expect(filterFrontierItems(items, 'credential_test').map(x => x.id)).toEqual(['c1', 'c2']);
    expect(buildFrontierSections(items, { nodeFilter: 'host-1' })).toEqual([
      {
        key: 'matching',
        title: 'Matching Candidates',
        items: [items[2]],
        total: 1,
      },
    ]);
  });
});
