// ============================================================
// Overwatch — Identity Reconciliation
// Merges alias nodes into canonical identities and retargets edges.
// Extracted from GraphEngine to keep reconciliation logic isolated.
// ============================================================

import type { OverwatchGraph } from './engine-context.js';
import type { ActivityLogEntry } from './engine-context.js';
import type { NodeProperties, EdgeProperties } from '../types.js';
import { getIdentityMarkers, isIdentityType, isUnresolvedIdentityNode } from './identity-resolution.js';
import { getNodeSources, normalizeNodeProvenance } from './provenance-utils.js';

export type ReconciliationResult = {
  removed_nodes: string[];
  removed_edges: string[];
  new_edges: string[];
  updated_canonical: boolean;
  reverse_target?: string;
};

export type ReconcilerCallbacks = {
  getNode: (id: string) => NodeProperties | null;
  addEdge: (source: string, target: string, props: EdgeProperties) => { id: string; isNew: boolean };
  logActionEvent: (event: Omit<Partial<ActivityLogEntry>, 'event_id' | 'timestamp'> & { description: string }) => void;
  invalidatePathGraph: () => void;
};

export class IdentityReconciler {
  constructor(
    private graph: OverwatchGraph,
    private callbacks: ReconcilerCallbacks,
  ) {}

  reconcileCanonicalNode(
    canonicalNodeId: string,
    agentId?: string,
    actionId?: string,
  ): ReconciliationResult {
    // Two resolved same-type nodes with shared identity markers are intentionally
    // NOT auto-merged. Graph health checks flag these overlaps for operator review
    // instead of risking incorrect automatic merges.
    const canonicalNode = this.callbacks.getNode(canonicalNodeId);
    if (!canonicalNode || !isIdentityType(canonicalNode.type) || isUnresolvedIdentityNode(canonicalNode)) {
      return { removed_nodes: [], removed_edges: [], new_edges: [], updated_canonical: false };
    }

    const canonicalMarkers = new Set(this.getEffectiveIdentityMarkers(canonicalNode));
    if (canonicalMarkers.size === 0) {
      return { removed_nodes: [], removed_edges: [], new_edges: [], updated_canonical: false };
    }

    const aliases: string[] = [];
    let reverseTarget: string | undefined;
    this.graph.forEachNode((nodeId, attrs) => {
      if (nodeId === canonicalNodeId) return;
      if (attrs.type !== canonicalNode.type) return;
      const aliasMarkers = this.getEffectiveIdentityMarkers(attrs);
      if (!aliasMarkers.some((marker) => canonicalMarkers.has(marker))) return;
      if (this.shouldMergeIntoCanonical(canonicalNode, attrs)) {
        aliases.push(nodeId);
      } else if (this.shouldMergeIntoCanonical(attrs, canonicalNode)) {
        // Reverse merge: the newly ingested node is weaker and should merge
        // INTO the existing stronger node (e.g. hostname-only → IP-based host)
        reverseTarget = nodeId;
      }
    });

    const removedNodes: string[] = [];
    const removedEdges: string[] = [];
    const newEdges: string[] = [];
    let updatedCanonical = false;

    // Reverse merge: merge the newly ingested canonical into the stronger existing node
    if (reverseTarget && aliases.length === 0) {
      const merged = this.mergeAliasIntoCanonical(canonicalNodeId, reverseTarget);
      if (merged) {
        removedNodes.push(canonicalNodeId);
        removedEdges.push(...merged.removed_edges);
        newEdges.push(...merged.new_edges);
        updatedCanonical = true;
        this.callbacks.logActionEvent({
          description: `Identity converged (reverse): ${canonicalNodeId} -> ${reverseTarget}`,
          agent_id: agentId,
          action_id: actionId,
          category: 'system',
          event_type: 'system',
          result_classification: 'success',
          target_node_ids: [reverseTarget],
          details: {
            alias_node_id: canonicalNodeId,
            canonical_node_id: reverseTarget,
            identity_markers: [...canonicalMarkers],
          },
        });
      }
      return { removed_nodes: removedNodes, removed_edges: removedEdges, new_edges: newEdges, updated_canonical: updatedCanonical, reverse_target: reverseTarget };
    }

    for (const aliasId of aliases) {
      const merged = this.mergeAliasIntoCanonical(aliasId, canonicalNodeId);
      if (!merged) continue;
      removedNodes.push(aliasId);
      removedEdges.push(...merged.removed_edges);
      newEdges.push(...merged.new_edges);
      updatedCanonical = true;
      this.callbacks.logActionEvent({
        description: `Identity converged: ${aliasId} -> ${canonicalNodeId}`,
        agent_id: agentId,
        action_id: actionId,
        category: 'system',
        event_type: 'system',
        result_classification: 'success',
        target_node_ids: [canonicalNodeId],
        details: {
          alias_node_id: aliasId,
          canonical_node_id: canonicalNodeId,
          identity_markers: [...canonicalMarkers],
        },
      });
    }

    return {
      removed_nodes: removedNodes,
      removed_edges: removedEdges,
      new_edges: newEdges,
      updated_canonical: updatedCanonical,
      reverse_target: reverseTarget,
    };
  }

  private mergeAliasIntoCanonical(
    aliasNodeId: string,
    canonicalNodeId: string,
  ): { removed_edges: string[]; new_edges: string[] } | null {
    if (!this.graph.hasNode(aliasNodeId) || !this.graph.hasNode(canonicalNodeId)) {
      return null;
    }

    const aliasNode = this.graph.getNodeAttributes(aliasNodeId);
    const canonicalNode = this.graph.getNodeAttributes(canonicalNodeId);
    const mergedNode = this.mergeNodeProperties(canonicalNode, aliasNode, canonicalNodeId);
    this.graph.replaceNodeAttributes(canonicalNodeId, mergedNode as NodeProperties);

    const removedEdges: string[] = [];
    const newEdges: string[] = [];
    const connectedEdges = [...this.graph.inEdges(aliasNodeId), ...this.graph.outEdges(aliasNodeId)];
    for (const edgeId of connectedEdges) {
      if (!this.graph.hasEdge(edgeId)) continue;
      const source = this.graph.source(edgeId);
      const target = this.graph.target(edgeId);
      const attrs = this.graph.getEdgeAttributes(edgeId);
      const nextSource = source === aliasNodeId ? canonicalNodeId : source;
      const nextTarget = target === aliasNodeId ? canonicalNodeId : target;
      this.graph.dropEdge(edgeId);
      removedEdges.push(edgeId);
      if (nextSource === nextTarget) continue;
      const { id: nextEdgeId, isNew } = this.callbacks.addEdge(nextSource, nextTarget, attrs);
      if (isNew) {
        newEdges.push(nextEdgeId);
      }
    }

    this.graph.dropNode(aliasNodeId);
    this.callbacks.invalidatePathGraph();
    return { removed_edges: removedEdges, new_edges: newEdges };
  }

  private mergeNodeProperties(
    canonicalNode: NodeProperties,
    aliasNode: NodeProperties,
    canonicalNodeId: string,
  ): NodeProperties {
    const merged: NodeProperties = {
      ...aliasNode,
      ...canonicalNode,
      id: canonicalNodeId,
      type: canonicalNode.type,
      label: choosePreferredLabel(canonicalNode.label, aliasNode.label, canonicalNodeId),
      discovered_at: earliestTimestamp(canonicalNode.discovered_at, aliasNode.discovered_at) || canonicalNode.discovered_at || aliasNode.discovered_at,
      first_seen_at: earliestTimestamp(canonicalNode.first_seen_at, aliasNode.first_seen_at, canonicalNode.discovered_at, aliasNode.discovered_at),
      last_seen_at: latestTimestamp(canonicalNode.last_seen_at, aliasNode.last_seen_at, canonicalNode.discovered_at, aliasNode.discovered_at),
      confirmed_at: earliestTimestamp(canonicalNode.confirmed_at, aliasNode.confirmed_at),
      confidence: Math.max(canonicalNode.confidence ?? 0, aliasNode.confidence ?? 0),
      discovered_by: canonicalNode.discovered_by || aliasNode.discovered_by,
      sources: mergeUniqueArrays(getNodeSources(canonicalNode), getNodeSources(aliasNode)),
      identity_status: 'canonical',
      identity_family: canonicalNode.identity_family || aliasNode.identity_family,
      canonical_id: canonicalNodeId,
      identity_markers: mergeUniqueArrays(this.getEffectiveIdentityMarkers(canonicalNode), this.getEffectiveIdentityMarkers(aliasNode)),
    };

    for (const [key, value] of Object.entries(aliasNode)) {
      if (merged[key] === undefined || merged[key] === null || merged[key] === '') {
        merged[key] = value;
      }
    }

    return { ...merged, ...normalizeNodeProvenance(merged) } as NodeProperties;
  }

  getEffectiveIdentityMarkers(node: NodeProperties): string[] {
    // Always recompute fresh markers from current node properties so stale
    // persisted entries (e.g. old credential:material:*) don't pollute matching.
    const fresh = getIdentityMarkers(node);
    // Union with stored markers to preserve accumulated merge history.
    if (Array.isArray(node.identity_markers) && node.identity_markers.length > 0) {
      const set = new Set(fresh);
      for (const marker of node.identity_markers) {
        if (typeof marker === 'string') set.add(marker);
      }
      return [...set];
    }
    return fresh;
  }

  private shouldMergeIntoCanonical(canonicalNode: NodeProperties, candidateAlias: NodeProperties): boolean {
    if (isUnresolvedIdentityNode(candidateAlias)) {
      return true;
    }

    if (canonicalNode.type === 'host' && candidateAlias.type === 'host') {
      const canonicalHasIp = typeof canonicalNode.ip === 'string' && canonicalNode.ip.length > 0;
      const aliasHasIp = typeof candidateAlias.ip === 'string' && candidateAlias.ip.length > 0;
      return canonicalHasIp && !aliasHasIp;
    }

    return false;
  }
}

// Pure utility functions (no class dependency)

function mergeUniqueArrays(left: unknown[] = [], right: unknown[] = []): string[] | undefined {
  const merged = [...new Set([...left, ...right].filter((value): value is string => typeof value === 'string' && value.length > 0))];
  return merged.length > 0 ? merged : undefined;
}

function earliestTimestamp(...values: Array<string | undefined>): string | undefined {
  const timestamps = values.filter((value): value is string => typeof value === 'string' && value.length > 0);
  if (timestamps.length === 0) return undefined;
  return timestamps.sort()[0];
}

function latestTimestamp(...values: Array<string | undefined>): string | undefined {
  const timestamps = values.filter((value): value is string => typeof value === 'string' && value.length > 0);
  if (timestamps.length === 0) return undefined;
  return timestamps.sort()[timestamps.length - 1];
}

function choosePreferredLabel(primary: string | undefined, fallback: string | undefined, nodeId: string): string {
  if (primary && primary !== nodeId) return primary;
  if (fallback && fallback !== nodeId) return fallback;
  return primary || fallback || nodeId;
}
