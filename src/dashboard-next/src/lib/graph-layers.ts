import type Graph from 'graphology';

export const CREDENTIAL_FLOW_EDGE_TYPES = new Set([
  'OWNS_CRED',
  'VALID_ON',
  'VALID_FOR_APP',
  'ASSUMES_ROLE',
  'AUTHENTICATES_TO',
  'DERIVED_FROM',
  'DUMPED_FROM',
  'SHARED_CREDENTIAL',
  'TESTED_CRED',
]);

export type GraphLayerId =
  | 'edgeLabels'
  | 'communityHulls'
  | 'credentialFlow'
  | 'attackPath'
  | 'hideOrphans'
  | 'hideReachableOnly';

export interface GraphLayerState {
  id: GraphLayerId;
  label: string;
  enabled: boolean;
  available: boolean;
  description: string;
  disabledReason?: string;
}

export function isCredentialFlowEdge(edgeType: unknown): boolean {
  return typeof edgeType === 'string' && CREDENTIAL_FLOW_EDGE_TYPES.has(edgeType);
}

export function isReachableOnlyEdge(attrs: { edgeType?: unknown; type?: unknown }): boolean {
  return attrs.edgeType === 'REACHABLE';
}

export function hasCredentialFlowEdges(graph: Graph): boolean {
  let found = false;
  graph.forEachEdge((_edge, attrs) => {
    if (!found && isCredentialFlowEdge(attrs.edgeType)) found = true;
  });
  return found;
}

export function hasCommunityHulls(graph: Graph): boolean {
  const counts = new Map<string, number>();
  graph.forEachNode((_node, attrs) => {
    const cid = attrs.community ?? attrs.community_id;
    if (cid == null || cid === '') return;
    const key = String(cid);
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return [...counts.values()].some(count => count >= 2);
}

export function buildGraphLayerStates({
  graph,
  edgeLabels,
  communityHulls,
  credentialFlow,
  attackPath,
  hideOrphans,
  hideReachableOnly,
  pathEdgeCount,
}: {
  graph: Graph;
  edgeLabels: boolean;
  communityHulls: boolean;
  credentialFlow: boolean;
  attackPath: boolean;
  hideOrphans: boolean;
  hideReachableOnly: boolean;
  pathEdgeCount: number;
}): GraphLayerState[] {
  const communityAvailable = hasCommunityHulls(graph);
  const credentialAvailable = hasCredentialFlowEdges(graph);
  const attackPathAvailable = attackPath || pathEdgeCount > 0;

  return [
    {
      id: 'edgeLabels',
      label: 'Edge labels',
      enabled: edgeLabels,
      available: true,
      description: 'Show relationship names on visible edges.',
    },
    {
      id: 'communityHulls',
      label: 'Community hulls',
      enabled: communityHulls && communityAvailable,
      available: communityAvailable,
      description: 'Draw soft regions around graph communities.',
      disabledReason: 'No community groups are present.',
    },
    {
      id: 'credentialFlow',
      label: 'Credential flow',
      enabled: credentialFlow,
      available: credentialAvailable,
      description: 'Emphasize credential ownership, reuse, auth, and cloud role edges.',
      disabledReason: 'No credential-flow edges are present.',
    },
    {
      id: 'attackPath',
      label: 'Attack path',
      enabled: attackPath,
      available: attackPathAvailable,
      description: 'Keep the current shift-click path highlighted as an attack-path layer.',
      disabledReason: 'Create a path first with Shift-click on two nodes.',
    },
    {
      id: 'hideOrphans',
      label: 'Hide orphans',
      enabled: hideOrphans,
      available: true,
      description: 'Hide nodes without any edges.',
    },
    {
      id: 'hideReachableOnly',
      label: 'Hide reachable-only',
      enabled: hideReachableOnly,
      available: true,
      description: 'Hide nodes connected only by REACHABLE edges.',
    },
  ];
}
