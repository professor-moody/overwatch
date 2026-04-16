import { createUndirectedSimpleGraph, assignLouvainCommunities } from './graphology-types.js';
import type { OverwatchGraph } from './engine-context.js';

/**
 * Edge-type weight multipliers for community detection.
 * Higher weight = stronger affinity (nodes cluster together).
 * Access edges weight most: they represent direct compromise relationships.
 */
export const EDGE_TYPE_WEIGHTS: Record<string, number> = {
  // Access (direct compromise)
  ADMIN_TO: 3.0, HAS_SESSION: 3.0, CAN_RDPINTO: 3.0, CAN_PSREMOTE: 3.0,
  // Credential relationships
  VALID_ON: 2.5, OWNS_CRED: 2.5, DERIVED_FROM: 2.5, DUMPED_FROM: 2.5,
  SHARED_CREDENTIAL: 2.5, TESTED_CRED: 1.5,
  // AD attack paths
  CAN_DCSYNC: 2.0, WRITEABLE_BY: 2.0, GENERIC_ALL: 2.0, GENERIC_WRITE: 2.0,
  WRITE_OWNER: 2.0, WRITE_DACL: 2.0, ADD_MEMBER: 2.0, FORCE_CHANGE_PASSWORD: 2.0,
  ALLOWED_TO_ACT: 2.0,
  // ADCS
  CAN_ENROLL: 2.0, ISSUED_BY: 2.0, OPERATES_CA: 2.0,
  ESC1: 2.0, ESC2: 2.0, ESC3: 2.0, ESC4: 2.0, ESC5: 2.0,
  ESC6: 2.0, ESC7: 2.0, ESC8: 2.0, ESC9: 2.0, ESC10: 2.0, ESC11: 2.0, ESC12: 2.0, ESC13: 2.0,
  // ACL-derived
  CAN_READ_LAPS: 2.0, CAN_READ_GMSA: 2.0, RBCD_TARGET: 2.0,
  // Delegation
  DELEGATES_TO: 2.0, CAN_DELEGATE_TO: 2.0,
  // Roasting
  AS_REP_ROASTABLE: 1.5, KERBEROASTABLE: 1.5,
  // Domain membership
  MEMBER_OF: 1.5, MEMBER_OF_DOMAIN: 1.5, SAME_DOMAIN: 1.5, TRUSTS: 1.0,
  // Lateral movement
  RELAY_TARGET: 1.5, NULL_SESSION: 1.0, POTENTIAL_AUTH: 1.0,
  // Web surface
  HOSTS: 1.0, AUTHENTICATED_AS: 1.5, VULNERABLE_TO: 1.5, EXPLOITS: 2.0,
  AUTH_BYPASS: 2.0, HAS_ENDPOINT: 1.0,
  // Cloud
  ASSUMES_ROLE: 2.0, HAS_POLICY: 1.5, POLICY_ALLOWS: 1.5,
  EXPOSED_TO: 1.0, RUNS_ON: 1.0, MANAGED_BY: 1.0,
  // Objective
  PATH_TO_OBJECTIVE: 1.5,
  // Network (low — reachability alone is weak affinity)
  REACHABLE: 0.5, RUNS: 0.5,
  // Generic
  RELATED: 0.2,
};

export interface CommunityDetectionOptions {
  resolution?: number;     // Louvain resolution parameter (default: 1.0)
}

/**
 * Build an undirected simple projection of the engagement graph and run
 * Louvain community detection.  Returns a Map<nodeId, communityId>.
 *
 * The projection collapses parallel/directed edges into a single undirected
 * edge per node pair, keeping the maximum (typeWeight * confidence) as weight.
 */
export function detectCommunities(graph: OverwatchGraph, options?: CommunityDetectionOptions): Map<string, number> {
  if (graph.order === 0) return new Map();

  const resolution = options?.resolution ?? 1.0;

  // Build undirected simple projection
  const ug = createUndirectedSimpleGraph();

  graph.forEachNode((id: string) => {
    ug.addNode(id);
  });

  graph.forEachEdge((_edgeId: string, attrs: Record<string, unknown>, source: string, target: string) => {
    if (source === target) return;
    const confidence = (typeof attrs.confidence === 'number' ? attrs.confidence : 1.0);
    const edgeType = (attrs.type as string) || '';
    const typeWeight = EDGE_TYPE_WEIGHTS[edgeType] ?? 1.0;
    const weight = typeWeight * confidence;

    if (ug.hasEdge(source, target)) {
      // Keep max weight
      const existing = ug.getEdgeAttribute(source, target, 'weight') as number;
      if (weight > existing) {
        ug.setEdgeAttribute(source, target, 'weight', weight);
      }
    } else {
      try {
        ug.addEdge(source, target, { weight });
      } catch {
        // duplicate edge race — ignore
      }
    }
  });

  // Need at least one edge for Louvain to be meaningful
  if (ug.size === 0) {
    const result = new Map<string, number>();
    let i = 0;
    graph.forEachNode((id: string) => {
      result.set(id, i++);
    });
    return result;
  }

  const mapping = assignLouvainCommunities(ug, {
    getEdgeWeight: 'weight',
    resolution,
  });

  return new Map(Object.entries(mapping).map(([k, v]) => [k, v]));
}

/**
 * Compute community summary statistics from a community mapping.
 */
export function communityStats(communities: Map<string, number>): {
  community_count: number;
  largest_community_size: number;
  sizes: Map<number, number>;
} {
  const sizes = new Map<number, number>();
  for (const cid of communities.values()) {
    sizes.set(cid, (sizes.get(cid) || 0) + 1);
  }
  let largest = 0;
  for (const size of sizes.values()) {
    if (size > largest) largest = size;
  }
  return {
    community_count: sizes.size,
    largest_community_size: largest,
    sizes,
  };
}
