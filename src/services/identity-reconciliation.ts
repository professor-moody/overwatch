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
import { createOverwatchGraph } from './graphology-types.js';
import {
  deterministicCollisionEdgeKey,
  edgeIdentityMatches,
  preferredEdgeKey,
} from './edge-identity.js';
import type {
  IdentityRewriteEdgeStateV1,
  IdentityRewriteMutationPayloadV1,
  IdentityRewriteNodeStateV1,
} from './mutation-journal.js';
import { isDeepStrictEqual } from 'node:util';

export type ReconciliationResult = {
  removed_nodes: string[];
  removed_edges: string[];
  new_edges: string[];
  updated_edges: string[];
  updated_canonical: boolean;
  survivor_id?: string;
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
      return { removed_nodes: [], removed_edges: [], new_edges: [], updated_edges: [], updated_canonical: false };
    }

    const canonicalMarkers = new Set(this.getEffectiveIdentityMarkers(canonicalNode));
    if (canonicalMarkers.size === 0) {
      return { removed_nodes: [], removed_edges: [], new_edges: [], updated_edges: [], updated_canonical: false };
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
    const updatedEdges: string[] = [];
    let updatedCanonical = false;

    // Reverse merge: merge the newly ingested canonical into the stronger existing node
    if (reverseTarget && aliases.length === 0) {
      const merged = this.mergeAliasIntoCanonical(canonicalNodeId, reverseTarget);
      if (merged) {
        removedNodes.push(canonicalNodeId);
        removedEdges.push(...merged.removed_edges);
        newEdges.push(...merged.new_edges);
        updatedEdges.push(...merged.updated_edges);
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
      return {
        removed_nodes: removedNodes,
        removed_edges: removedEdges,
        new_edges: newEdges,
        updated_edges: updatedEdges,
        updated_canonical: updatedCanonical,
        survivor_id: reverseTarget,
        reverse_target: reverseTarget,
      };
    }

    for (const aliasId of aliases) {
      const merged = this.mergeAliasIntoCanonical(aliasId, canonicalNodeId);
      if (!merged) continue;
      removedNodes.push(aliasId);
      removedEdges.push(...merged.removed_edges);
      newEdges.push(...merged.new_edges);
      updatedEdges.push(...merged.updated_edges);
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
      updated_edges: updatedEdges,
      updated_canonical: updatedCanonical,
      ...(updatedCanonical ? { survivor_id: canonicalNodeId } : {}),
      reverse_target: reverseTarget,
    };
  }

  private mergeAliasIntoCanonical(
    aliasNodeId: string,
    canonicalNodeId: string,
  ): { removed_edges: string[]; new_edges: string[]; updated_edges: string[] } | null {
    if (!this.graph.hasNode(aliasNodeId) || !this.graph.hasNode(canonicalNodeId)) {
      return null;
    }

    const aliasNode = this.graph.getNodeAttributes(aliasNodeId);
    const canonicalNode = this.graph.getNodeAttributes(canonicalNodeId);
    const mergedNode = this.mergeNodeProperties(canonicalNode, aliasNode, canonicalNodeId);
    this.graph.replaceNodeAttributes(canonicalNodeId, mergedNode as NodeProperties);

    const removedEdges: string[] = [];
    const newEdges: string[] = [];
    const updatedEdges: string[] = [];
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
      } else {
        updatedEdges.push(nextEdgeId);
      }
    }

    this.graph.dropNode(aliasNodeId);
    this.callbacks.invalidatePathGraph();
    return { removed_edges: removedEdges, new_edges: newEdges, updated_edges: updatedEdges };
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

export type IdentityRewritePlan = {
  payload: IdentityRewriteMutationPayloadV1 | null;
  result: ReconciliationResult;
};

/**
 * Build the complete identity rewrite against an isolated graph. The live
 * graph is not touched until the immutable before/after delta has reached the
 * WAL, and replay consumes this same delta instead of rerunning identity rules
 * that may have changed in a newer binary.
 */
export function planIdentityRewrite(
  graph: OverwatchGraph,
  canonicalNodeId: string,
  options: {
    operation_id: string;
    occurred_at: string;
    agent_id?: string;
    action_id?: string;
  },
): IdentityRewritePlan {
  const beforeNodes = collectNodeStates(graph);
  const beforeEdges = collectEdgeStates(graph);
  const scratch = createOverwatchGraph();
  scratch.import(structuredClone(graph.export()));
  const auditEvents: IdentityRewriteMutationPayloadV1['audit_events'] = [];
  const reconciler = new IdentityReconciler(scratch, {
    getNode: id => scratch.hasNode(id)
      ? structuredClone(scratch.getNodeAttributes(id) as NodeProperties)
      : null,
    addEdge: (source, target, props) => addEdgeToPlanningGraph(
      scratch,
      source,
      target,
      props,
      options.occurred_at,
      (ruleId, edgeType) => {
        auditEvents.push({
          description: `Confirmed inferred edge [${ruleId}]: ${source} --[${edgeType}]--> ${target}`,
          category: 'inference',
          event_type: 'inference_generated',
          result_classification: 'success',
          target_node_ids: [source, target],
          details: {
            inferred_by_rule: ruleId,
            source,
            target,
            edge_type: edgeType,
          },
        });
      },
    ),
    logActionEvent: event => {
      auditEvents.push({
        description: event.description,
        ...(event.target_node_ids ? { target_node_ids: [...event.target_node_ids] } : {}),
        details: structuredClone(event.details ?? {}),
      });
    },
    invalidatePathGraph: () => undefined,
  });
  const rawResult = reconciler.reconcileCanonicalNode(
    canonicalNodeId,
    options.agent_id,
    options.action_id,
  );
  const result: ReconciliationResult = {
    ...rawResult,
    removed_nodes: sortedUnique(rawResult.removed_nodes),
    removed_edges: sortedUnique(rawResult.removed_edges),
    new_edges: sortedUnique(rawResult.new_edges),
    updated_edges: sortedUnique(rawResult.updated_edges),
  };
  if (!result.updated_canonical) return { payload: null, result };

  const afterNodes = collectNodeStates(scratch);
  const afterEdges = collectEdgeStates(scratch);
  const nodeChanges: IdentityRewriteMutationPayloadV1['node_changes'] = [];
  for (const nodeId of sortedUnique([...beforeNodes.keys(), ...afterNodes.keys()])) {
    const before = beforeNodes.get(nodeId);
    const after = afterNodes.get(nodeId);
    if (isDeepStrictEqual(before, after)) continue;
    nodeChanges.push({
      node_id: nodeId,
      ...(before ? { before } : {}),
      ...(after ? { after } : {}),
    });
  }
  const edgeChanges: IdentityRewriteMutationPayloadV1['edge_changes'] = [];
  for (const edgeId of sortedUnique([...beforeEdges.keys(), ...afterEdges.keys()])) {
    const before = beforeEdges.get(edgeId);
    const after = afterEdges.get(edgeId);
    if (isDeepStrictEqual(before, after)) continue;
    edgeChanges.push({
      edge_id: edgeId,
      ...(before ? { before } : {}),
      ...(after ? { after } : {}),
    });
  }

  const payload = jsonRoundTrip<IdentityRewriteMutationPayloadV1>({
      payload_version: 1,
      operation_id: options.operation_id,
      occurred_at: options.occurred_at,
      canonical_node_id: canonicalNodeId,
      ...(options.agent_id ? { agent_id: options.agent_id } : {}),
      ...(options.action_id ? { action_id: options.action_id } : {}),
      node_changes: nodeChanges,
      edge_changes: edgeChanges,
      audit_events: auditEvents,
      result,
  });
  return {
    payload,
    result: payload.result,
  };
}

function collectNodeStates(graph: OverwatchGraph): Map<string, IdentityRewriteNodeStateV1> {
  const states = new Map<string, IdentityRewriteNodeStateV1>();
  graph.forEachNode((nodeId, props) => {
    states.set(nodeId, { node_id: nodeId, props: structuredClone(props as NodeProperties) });
  });
  return states;
}

function collectEdgeStates(graph: OverwatchGraph): Map<string, IdentityRewriteEdgeStateV1> {
  const states = new Map<string, IdentityRewriteEdgeStateV1>();
  for (const edgeId of graph.edges()) {
    states.set(edgeId, {
      edge_id: edgeId,
      source: graph.source(edgeId),
      target: graph.target(edgeId),
      props: structuredClone(graph.getEdgeAttributes(edgeId) as EdgeProperties),
    });
  }
  return states;
}

function addEdgeToPlanningGraph(
  graph: OverwatchGraph,
  source: string,
  target: string,
  props: EdgeProperties,
  occurredAt: string,
  onConfirmed: (ruleId: string, edgeType: string) => void,
): { id: string; isNew: boolean } {
  if (!graph.hasNode(source) || !graph.hasNode(target)) {
    throw new Error(`Cannot plan identity edge with missing endpoint(s): ${source} -> ${target}`);
  }
  for (const edgeId of graph.edges(source, target)) {
    const existing = graph.getEdgeAttributes(edgeId) as EdgeProperties;
    if (!edgeIdentityMatches(existing, props)) continue;
    const effectiveProps = existing.inferred_by_rule
      && !existing.confirmed_at
      && props.confidence >= 1
      ? { ...props, confirmed_at: occurredAt }
      : props;
    if (existing.inferred_by_rule && !existing.confirmed_at && props.confidence >= 1) {
      onConfirmed(existing.inferred_by_rule, existing.type);
    }
    graph.mergeEdgeAttributes(edgeId, structuredClone(effectiveProps));
    return { id: edgeId, isNew: false };
  }
  const preferred = preferredEdgeKey(source, target, props);
  const edgeId = graph.hasEdge(preferred)
    ? deterministicCollisionEdgeKey(source, target, props)
    : preferred;
  if (graph.hasEdge(edgeId)) {
    throw new Error(`Deterministic identity edge collision: ${edgeId}`);
  }
  graph.addEdgeWithKey(edgeId, source, target, structuredClone(props));
  return { id: edgeId, isNew: true };
}

function sortedUnique(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function jsonRoundTrip<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
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
