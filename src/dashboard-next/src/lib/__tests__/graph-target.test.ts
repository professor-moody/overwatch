import { describe, expect, it } from 'vitest';
import Graph from 'graphology';
import {
  buildGraphTargetPath,
  parseGraphTargetParams,
  resolveGraphTarget,
  type GraphNavigationTarget,
} from '../graph-target';
import type { FrontierItem } from '../types';

function paramsFromPath(path: string): URLSearchParams {
  return new URLSearchParams(path.split('?')[1] || '');
}

function sampleGraph(): Graph {
  const graph = new Graph({ type: 'directed', multi: true });
  graph.addNode('cred-jdoe-ntlm');
  graph.addNode('host-ws01');
  graph.addNode('svc-rdp-ws01');
  graph.addEdgeWithKey('edge-tested', 'cred-jdoe-ntlm', 'svc-rdp-ws01', { edgeType: 'TESTED_CRED' });
  graph.addEdgeWithKey('edge-hosts', 'host-ws01', 'svc-rdp-ws01', { edgeType: 'RUNS' });
  return graph;
}

describe('graph target navigation', () => {
  it('preserves legacy node graph URLs', () => {
    const path = buildGraphTargetPath({ kind: 'node', nodeId: 'cred-jdoe-ntlm', hops: 2 });
    expect(path).toBe('/graph?node=cred-jdoe-ntlm&hops=2');
    expect(parseGraphTargetParams(paramsFromPath(path))).toEqual({
      kind: 'node',
      nodeId: 'cred-jdoe-ntlm',
      hops: 2,
    });
  });

  it('builds and parses contextual graph target URLs', () => {
    const target: GraphNavigationTarget = {
      kind: 'finding',
      findingId: 'finding-1',
      nodeIds: ['cred-jdoe-ntlm', 'svc-rdp-ws01'],
      label: 'Finding Domain Admin path',
    };
    const parsed = parseGraphTargetParams(paramsFromPath(buildGraphTargetPath(target)));
    expect(parsed).toMatchObject({
      kind: 'finding',
      findingId: 'finding-1',
      nodeIds: ['cred-jdoe-ntlm', 'svc-rdp-ws01'],
      label: 'Finding Domain Admin path',
    });
  });

  it('resolves node, edge, frontier, evidence, and path targets', () => {
    const graph = sampleGraph();
    const frontier: FrontierItem[] = [{
      id: 'frontier-1',
      type: 'inferred_edge',
      priority: 1,
      description: 'Test TESTED_CRED',
      edge_source: 'cred-jdoe-ntlm',
      edge_target: 'svc-rdp-ws01',
      edge_type: 'TESTED_CRED',
    }];

    expect(resolveGraphTarget(graph, { kind: 'node', nodeId: 'cred-jdoe-ntlm' }).primaryNode)
      .toBe('cred-jdoe-ntlm');
    expect(resolveGraphTarget(graph, {
      kind: 'edge',
      source: 'cred-jdoe-ntlm',
      target: 'svc-rdp-ws01',
      edgeType: 'TESTED_CRED',
    }).edges.has('edge-tested')).toBe(true);
    expect(resolveGraphTarget(graph, {
      kind: 'frontier',
      frontierItemId: 'frontier-1',
    }, { frontier }).nodes).toEqual(new Set(['cred-jdoe-ntlm', 'svc-rdp-ws01']));
    expect(resolveGraphTarget(graph, { kind: 'evidence', nodeId: 'host-ws01' }).label)
      .toBe('Evidence for host-ws01');
    expect(resolveGraphTarget(graph, {
      kind: 'path',
      nodeIds: ['cred-jdoe-ntlm', 'svc-rdp-ws01'],
    }).nodes).toEqual(new Set(['cred-jdoe-ntlm', 'svc-rdp-ws01']));
  });

  it('returns a missing reason instead of silently falling back', () => {
    const resolved = resolveGraphTarget(sampleGraph(), { kind: 'node', nodeId: 'missing-node' });
    expect(resolved.missingReason).toBe('node not found: missing-node');
    expect(resolved.nodes.size).toBe(0);
  });
});
