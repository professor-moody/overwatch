import { describe, expect, it } from 'vitest';
import { reachableObjectives } from '../node-reachability';
import type { ExportedEdge, ExportedNode } from '../types';

const now = '2026-05-15T00:00:00Z';

function node(id: string, type: ExportedNode['type'], extra: Partial<ExportedNode> = {}): ExportedNode {
  return { id, type, label: id, confidence: 1, discovered_at: now, ...extra };
}

function edge(source: string, target: string, type: string): ExportedEdge {
  return { id: `${source}->${target}`, source, target, type, confidence: 0.9 } as ExportedEdge;
}

// ws01 --CAN_REACH--> dc01 (an objective) --ADMIN_TO--> role (a cloud identity target)
const nodes: ExportedNode[] = [
  node('ws01', 'host'),
  node('dc01', 'host', { objective_achieved: false, label: 'DC01' }),
  node('role', 'cloud_identity', { label: 'PowerUser' }),
  node('island', 'host', { label: 'Island' }),
];
const edges: ExportedEdge[] = [
  edge('ws01', 'dc01', 'CAN_REACH'),
  edge('dc01', 'role', 'ADMIN_TO'),
];

describe('reachableObjectives', () => {
  it('finds the nearest objective by hop count and counts all reachable targets', () => {
    const reach = reachableObjectives('ws01', nodes, edges);
    expect(reach.count).toBe(2);              // dc01 + role
    expect(reach.nearest?.label).toBe('DC01'); // 1 hop, closer than role (2 hops)
    expect(reach.nearest?.hops).toBe(1);
    expect(reach.nearest?.tier).toBe('network');
  });

  it('excludes the node itself so it reports what it leads to, not itself', () => {
    // dc01 is itself an objective; from it the only OTHER target is `role` (1 hop).
    const reach = reachableObjectives('dc01', nodes, edges);
    expect(reach.count).toBe(1);
    expect(reach.nearest?.label).toBe('PowerUser');
  });

  it('returns no objective when the node reaches none', () => {
    const reach = reachableObjectives('island', nodes, edges);
    expect(reach.nearest).toBeNull();
    expect(reach.count).toBe(0);
  });

  it('returns no objective for a node absent from the graph', () => {
    expect(reachableObjectives('ghost', nodes, edges)).toEqual({ nearest: null, count: 0 });
  });
});
