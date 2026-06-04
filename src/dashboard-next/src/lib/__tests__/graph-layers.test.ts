import Graph from 'graphology';
import { describe, expect, it } from 'vitest';
import {
  buildGraphLayerStates,
  edgeMatchesSemanticType,
  isCredentialFlowEdge,
  isReachableOnlyEdge,
} from '../graph-layers';

describe('graph layer helpers', () => {
  it('includes confirmed auth and cloud credential-flow edge types', () => {
    expect(isCredentialFlowEdge('OWNS_CRED')).toBe(true);
    expect(isCredentialFlowEdge('VALID_ON')).toBe(true);
    expect(isCredentialFlowEdge('VALID_FOR_APP')).toBe(true);
    expect(isCredentialFlowEdge('ASSUMES_ROLE')).toBe(true);
    expect(isCredentialFlowEdge('AUTHENTICATES_TO')).toBe(true);
    expect(isCredentialFlowEdge('DERIVED_FROM')).toBe(true);
    expect(isCredentialFlowEdge('DUMPED_FROM')).toBe(true);
    expect(isCredentialFlowEdge('SHARED_CREDENTIAL')).toBe(true);
    expect(isCredentialFlowEdge('TESTED_CRED')).toBe(true);
    expect(isCredentialFlowEdge('POTENTIAL_AUTH')).toBe(false);
  });

  it('checks reachable-only filtering against semantic edgeType', () => {
    expect(isReachableOnlyEdge({ edgeType: 'REACHABLE', type: 'arrow' })).toBe(true);
    expect(isReachableOnlyEdge({ edgeType: 'RUNS', type: 'REACHABLE' })).toBe(false);
  });

  it('matches focus presets against semantic edgeType, not Sigma render type', () => {
    const highlighted = new Set(['ADMIN_TO']);

    expect(edgeMatchesSemanticType({ edgeType: 'ADMIN_TO', type: 'arrow' }, highlighted)).toBe(true);
    expect(edgeMatchesSemanticType({ edgeType: 'RUNS', type: 'ADMIN_TO' }, highlighted)).toBe(false);
  });

  it('does not expose community regions as a graph layer', () => {
    const graph = new Graph();
    graph.addNode('a', { nodeType: 'host' });
    graph.addNode('b', { nodeType: 'host' });

    const layers = buildGraphLayerStates({
      graph,
      edgeLabels: true,
      credentialFlow: false,
      attackPath: false,
      hideOrphans: false,
      hideReachableOnly: false,
      pathEdgeCount: 0,
    });

    expect(layers.some(l => l.label === 'Community regions')).toBe(false);
  });

  it('enables attack path only when a path exists or the layer is already active', () => {
    const graph = new Graph();
    const withoutPath = buildGraphLayerStates({
      graph,
      edgeLabels: true,
      credentialFlow: false,
      attackPath: false,
      hideOrphans: false,
      hideReachableOnly: false,
      pathEdgeCount: 0,
    });
    const withPath = buildGraphLayerStates({
      graph,
      edgeLabels: true,
      credentialFlow: false,
      attackPath: false,
      hideOrphans: false,
      hideReachableOnly: false,
      pathEdgeCount: 2,
    });

    expect(withoutPath.find(l => l.id === 'attackPath')?.available).toBe(false);
    expect(withPath.find(l => l.id === 'attackPath')?.available).toBe(true);
  });
});
