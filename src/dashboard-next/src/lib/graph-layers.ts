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

const MIN_COMMUNITY_REGION_SIZE = 4;

export function isCredentialFlowEdge(edgeType: unknown): boolean {
  return typeof edgeType === 'string' && CREDENTIAL_FLOW_EDGE_TYPES.has(edgeType);
}

export function isReachableOnlyEdge(attrs: { edgeType?: unknown; type?: unknown }): boolean {
  return attrs.edgeType === 'REACHABLE';
}

export function edgeMatchesSemanticType(
  attrs: { edgeType?: unknown; type?: unknown },
  edgeTypes: Set<string>,
): boolean {
  return typeof attrs.edgeType === 'string' && edgeTypes.has(attrs.edgeType);
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
  return [...counts.values()].some(count => count >= MIN_COMMUNITY_REGION_SIZE);
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
  graphMode,
}: {
  graph: Graph;
  edgeLabels: boolean;
  communityHulls: boolean;
  credentialFlow: boolean;
  attackPath: boolean;
  hideOrphans: boolean;
  hideReachableOnly: boolean;
  pathEdgeCount: number;
  graphMode?: 'overview' | 'focused' | 'raw' | string;
}): GraphLayerState[] {
  const communityPresent = hasCommunityHulls(graph);
  const communityModeAvailable = !graphMode || graphMode === 'overview';
  const communityAvailable = communityPresent && communityModeAvailable;
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
      label: 'Community regions',
      enabled: communityHulls && communityAvailable,
      available: communityAvailable,
      description: 'Opt-in compact regions for dense overview clusters.',
      disabledReason: communityPresent
        ? 'Community regions are hidden while the graph is focused.'
        : `No community groups with ${MIN_COMMUNITY_REGION_SIZE}+ nodes are present.`,
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
