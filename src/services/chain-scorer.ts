// ============================================================
// Overwatch — Credential Chain Scorer
// Groups POTENTIAL_AUTH frontier edges into attack chains and
// scores them by depth-to-objective, chain completion, and
// credential quality. Annotates FrontierItem objects in-place.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { FrontierItem, EdgeType } from '../types.js';
import { isCredentialUsableForAuth, isCredentialStaleOrExpired, timeToExpiry } from './credential-utils.js';

// Edge types that form credential-to-access chains
const AUTH_EDGE_TYPES: ReadonlySet<EdgeType> = new Set([
  'POTENTIAL_AUTH', 'VALID_ON', 'TESTED_CRED',
] as EdgeType[]);

// Edge types that represent confirmed access (chain completion signals)
const ACCESS_EDGE_TYPES: ReadonlySet<EdgeType> = new Set([
  'ADMIN_TO', 'HAS_SESSION', 'CAN_RDPINTO', 'CAN_PSREMOTE',
] as EdgeType[]);

export type HopsToObjectiveFn = (fromNodeId: string) => number | null;

export interface ChainGroup {
  chain_id: string;
  credential_id: string;
  credential_usable: boolean;
  credential_stale: boolean;
  target_service_ids: string[];
  target_host_ids: string[];
  confirmed_count: number;          // edges already tested=true with success
  total_count: number;              // total edges in this chain (tested + untested)
  min_hops_to_objective: number | null;
  has_objective_adjacent: boolean;   // any target is ≤1 hop from objective
  chain_score: number;
}

export class ChainScorer {
  private ctx: EngineContext;
  private hopsToObjective: HopsToObjectiveFn;

  constructor(ctx: EngineContext, hopsToObjective: HopsToObjectiveFn) {
    this.ctx = ctx;
    this.hopsToObjective = hopsToObjective;
  }

  /**
   * Annotate frontier items with chain scoring data.
   * Mutates items in-place and returns the chain groups for inspection.
   */
  scoreChains(frontier: FrontierItem[]): ChainGroup[] {
    // 1. Collect all credential → service edges (frontier + already-tested)
    const chainMap = new Map<string, {
      credId: string;
      edges: Array<{
        frontierItem?: FrontierItem;      // undefined for already-tested edges
        edgeSource: string;
        edgeTarget: string;
        edgeType: EdgeType;
        tested: boolean;
        testResult?: string;
      }>;
    }>();

    // Scan frontier items for untested auth edges
    for (const item of frontier) {
      if (item.type !== 'inferred_edge' || !item.edge_source || !item.edge_target) continue;
      if (!AUTH_EDGE_TYPES.has(item.edge_type!)) continue;

      const credId = item.edge_source;
      let group = chainMap.get(credId);
      if (!group) {
        group = { credId, edges: [] };
        chainMap.set(credId, group);
      }
      group.edges.push({
        frontierItem: item,
        edgeSource: item.edge_source,
        edgeTarget: item.edge_target,
        edgeType: item.edge_type!,
        tested: false,
      });
    }

    // Scan graph for already-tested auth edges from the same credentials
    // to compute chain completion percentage
    for (const credId of chainMap.keys()) {
      if (!this.ctx.graph.hasNode(credId)) continue;
      for (const edgeId of this.ctx.graph.outEdges(credId) as string[]) {
        const attrs = this.ctx.graph.getEdgeAttributes(edgeId);
        if (!AUTH_EDGE_TYPES.has(attrs.type) && attrs.type !== 'VALID_ON') continue;
        if (!attrs.tested) continue;

        const target = this.ctx.graph.target(edgeId);
        const group = chainMap.get(credId)!;
        // Avoid duplicates (frontier item already covers this edge)
        if (group.edges.some(e => e.edgeTarget === target && e.edgeType === attrs.type)) continue;

        group.edges.push({
          edgeSource: credId,
          edgeTarget: target,
          edgeType: attrs.type,
          tested: true,
          testResult: attrs.test_result as string | undefined,
        });
      }
    }

    // 2. Score each chain group
    const groups: ChainGroup[] = [];

    for (const [credId, group] of chainMap) {
      if (group.edges.length === 0) continue;

      const credNode = this.ctx.graph.hasNode(credId)
        ? this.ctx.graph.getNodeAttributes(credId)
        : null;

      const credUsable = credNode ? isCredentialUsableForAuth(credNode) : false;
      const credStale = credNode ? isCredentialStaleOrExpired(credNode) : false;

      const confirmed = group.edges.filter(e => e.tested && e.testResult === 'success').length;
      const total = group.edges.length;

      // Resolve target hosts from target services
      const targetHostIds: string[] = [];
      const targetServiceIds: string[] = [];
      for (const edge of group.edges) {
        targetServiceIds.push(edge.edgeTarget);
        const hostId = this.resolveParentHost(edge.edgeTarget);
        if (hostId) targetHostIds.push(hostId);
      }

      // Compute hops to objective for each target
      let minHops: number | null = null;
      let hasObjectiveAdjacent = false;
      const uniqueTargets = new Set([...targetServiceIds, ...targetHostIds]);
      for (const targetId of uniqueTargets) {
        const hops = this.hopsToObjective(targetId);
        if (hops !== null) {
          if (minHops === null || hops < minHops) minHops = hops;
          if (hops <= 1) hasObjectiveAdjacent = true;
        }
      }

      // Also check if any target host already has confirmed access edges
      // (completing a chain to an already-accessed host is lower value)
      const targetsWithAccess = new Set<string>();
      for (const hostId of targetHostIds) {
        if (!this.ctx.graph.hasNode(hostId)) continue;
        for (const edgeId of this.ctx.graph.inEdges(hostId) as string[]) {
          const edgeAttrs = this.ctx.graph.getEdgeAttributes(edgeId);
          if (ACCESS_EDGE_TYPES.has(edgeAttrs.type) && edgeAttrs.confidence >= 0.9) {
            targetsWithAccess.add(hostId);
            break;
          }
        }
      }

      // 3. Compute composite chain score
      const completionPct = total > 0 ? confirmed / total : 0;
      const chainScore = this.computeChainScore({
        credUsable,
        credStale,
        credNode: credNode || undefined,
        completionPct,
        totalEdges: total,
        minHops,
        hasObjectiveAdjacent,
        targetsWithAccessCount: targetsWithAccess.size,
        totalTargets: targetHostIds.length,
      });

      const chainId = `chain-${credId}`;

      const chainGroup: ChainGroup = {
        chain_id: chainId,
        credential_id: credId,
        credential_usable: credUsable,
        credential_stale: credStale,
        target_service_ids: targetServiceIds,
        target_host_ids: [...new Set(targetHostIds)],
        confirmed_count: confirmed,
        total_count: total,
        min_hops_to_objective: minHops,
        has_objective_adjacent: hasObjectiveAdjacent,
        chain_score: chainScore,
      };

      groups.push(chainGroup);

      // 4. Annotate frontier items
      for (const edge of group.edges) {
        if (!edge.frontierItem) continue;
        edge.frontierItem.chain_id = chainId;
        edge.frontierItem.chain_depth = 0; // credential → service is always depth 0
        edge.frontierItem.chain_length = total;
        edge.frontierItem.chain_completion_pct = completionPct;
        edge.frontierItem.chain_score = chainScore;
        edge.frontierItem.chain_target_objective = hasObjectiveAdjacent;
      }
    }

    // 5. Score multi-hop chains: traverse from confirmed access hosts
    //    outward through untested edges to find deeper attack paths
    this.scoreMultiHopChains(frontier, groups);

    return groups;
  }

  /**
   * For frontier items that aren't direct credential-to-service edges,
   * check if they extend an existing chain (e.g., host → lateral movement → next host).
   */
  private scoreMultiHopChains(frontier: FrontierItem[], existingGroups: ChainGroup[]): void {
    // Build set of hosts reachable via confirmed chains
    const chainableHosts = new Set<string>();
    for (const group of existingGroups) {
      if (group.confirmed_count === 0) continue;
      for (const hostId of group.target_host_ids) {
        chainableHosts.add(hostId);
      }
    }

    // Also include hosts with confirmed access
    this.ctx.graph.forEachNode((id: string, attrs) => {
      if (attrs.type !== 'host') return;
      for (const edgeId of this.ctx.graph.inEdges(id) as string[]) {
        const edgeAttrs = this.ctx.graph.getEdgeAttributes(edgeId);
        if (ACCESS_EDGE_TYPES.has(edgeAttrs.type) && edgeAttrs.confidence >= 0.9) {
          chainableHosts.add(id);
          break;
        }
      }
    });

    if (chainableHosts.size === 0) return;

    // Find frontier items whose source is reachable from a chainable host
    for (const item of frontier) {
      if (item.chain_id) continue; // already scored
      if (item.type !== 'inferred_edge' || !item.edge_source || !item.edge_target) continue;

      // Check if source node is on or adjacent to a chainable host
      const sourceHostId = this.resolveParentHost(item.edge_source) || item.edge_source;
      if (!chainableHosts.has(sourceHostId)) continue;

      // This item extends an existing access chain
      const hops = this.hopsToObjective(item.edge_target);
      const objectiveAdjacent = hops !== null && hops <= 1;

      const chainId = `chain-lateral-${sourceHostId}`;
      item.chain_id = chainId;
      item.chain_depth = 1; // one hop beyond confirmed access
      item.chain_length = 2; // access + this edge
      item.chain_completion_pct = 0.5; // access is confirmed, this hop is not
      item.chain_target_objective = objectiveAdjacent;
      item.chain_score = this.computeChainScore({
        credUsable: true,
        credStale: false,
        completionPct: 0.5,
        totalEdges: 2,
        minHops: hops,
        hasObjectiveAdjacent: objectiveAdjacent,
        targetsWithAccessCount: 0,
        totalTargets: 1,
      });
    }
  }

  private computeChainScore(params: {
    credUsable: boolean;
    credStale: boolean;
    credNode?: { type?: string; [key: string]: unknown };
    completionPct: number;
    totalEdges: number;
    minHops: number | null;
    hasObjectiveAdjacent: boolean;
    targetsWithAccessCount: number;
    totalTargets: number;
  }): number {
    let score = 0;

    // Base: credential quality (0-3) with graduated expiry
    if (params.credUsable) {
      if (params.credNode && params.credNode.type === 'credential') {
        const ttl = timeToExpiry(params.credNode as import('../types.js').NodeProperties);
        if (ttl < 30 * 60 * 1000) score += 1;           // expiring < 30m
        else if (ttl < 2 * 60 * 60 * 1000) score += 2;  // expiring < 2h
        else score += 3;                                  // healthy
      } else {
        score += 3;
      }
    } else if (!params.credStale) {
      score += 1;
    }
    // Stale creds get 0

    // Completion bonus (0-2): partial chains are more valuable to complete
    // Peak value at ~50% completion — finishing a half-done chain is highest priority
    if (params.completionPct > 0 && params.completionPct < 1) {
      score += 2 * Math.sin(params.completionPct * Math.PI);
    }

    // Objective proximity bonus (0-3)
    if (params.hasObjectiveAdjacent) {
      score += 3;
    } else if (params.minHops !== null) {
      score += Math.max(0, 2 - params.minHops * 0.3);
    }

    // Fan-out bonus: more targets = more efficient campaign (0-1)
    score += Math.min(1, Math.log2(params.totalEdges + 1) / 5);

    // Penalty: targets already accessed (-1 per already-accessed target, scaled)
    if (params.totalTargets > 0) {
      score -= (params.targetsWithAccessCount / params.totalTargets) * 2;
    }

    return Math.max(0, Math.round(score * 100) / 100);
  }

  private resolveParentHost(nodeId: string): string | null {
    if (!this.ctx.graph.hasNode(nodeId)) return null;
    const node = this.ctx.graph.getNodeAttributes(nodeId);
    if (node.type === 'host') return nodeId;

    // Walk inbound RUNS edges to find parent host
    for (const edgeId of this.ctx.graph.inEdges(nodeId) as string[]) {
      const edgeAttrs = this.ctx.graph.getEdgeAttributes(edgeId);
      if (edgeAttrs.type === 'RUNS') {
        const source = this.ctx.graph.source(edgeId);
        const sourceNode = this.ctx.graph.getNodeAttributes(source);
        if (sourceNode.type === 'host') return source;
      }
    }
    return null;
  }
}
