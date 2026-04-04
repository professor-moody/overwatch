// ============================================================
// Overwatch — Finding Ingestion
// Extracted from GraphEngine to keep the class focused
// ============================================================

import type { EngineContext, ActivityLogEntry, GraphUpdateDetail } from './engine-context.js';
import type { NodeProperties, EdgeProperties, NodeType, EdgeType, Finding } from '../types.js';
import { resolveNodeIdentity } from './identity-resolution.js';
import { getNodeFirstSeenAt, getNodeSources, normalizeNodeProvenance } from './provenance-utils.js';
import { classifyNodeTemperature, isInterestingEdgeType, toColdRecord } from './cold-store.js';
import { inferCredentialDomain } from './credential-utils.js';

export interface FindingIngestionHost {
  ctx: EngineContext;
  addNode(props: NodeProperties): string;
  addEdge(source: string, target: string, props: EdgeProperties): { id: string; isNew: boolean };
  getNode(id: string): NodeProperties | null;
  log(message: string, agentId?: string, extra?: Partial<ActivityLogEntry>): void;
  logActionEvent(event: Omit<Partial<ActivityLogEntry>, 'event_id' | 'timestamp'> & { description: string }): ActivityLogEntry;
  findSubnetCidr(ip?: string): string | undefined;
  reconcileCanonicalNode(canonicalNodeId: string, agentId?: string, actionId?: string): {
    updated_canonical: boolean;
    removed_nodes: string[];
    removed_edges: string[];
    new_edges: string[];
    reverse_target?: string;
  };
  runInferenceRules(nodeId: string): string[];
  inferPivotReachability(nodeId: string): string[];
  inferDefaultCredentials(nodeIds: Set<string>): string[];
  inferImdsv1Ssrf(nodeIds: Set<string>): string[];
  inferManagedIdentityPivot(nodeIds: Set<string>): string[];
  degradeExpiredCredentialEdges(nodeId: string): string[];
  evaluateObjectives(): void;
  persist(detail?: GraphUpdateDetail): void;
  propertiesChanged(oldProps: NodeProperties, newProps: NodeProperties): boolean;
  invalidateFrontierCache(): void;
}

export function ingestFindingImpl(
  host: FindingIngestionHost,
  finding: Finding,
): { new_nodes: string[]; new_edges: string[]; updated_nodes: string[]; updated_edges: string[]; inferred_edges: string[] } {
  const newNodes: string[] = [];
  const newEdges: string[] = [];
  const updatedNodes: string[] = [];
  const updatedEdges: string[] = [];
  const inferredEdges: string[] = [];
  const removedNodes: string[] = [];
  const removedEdges: string[] = [];
  const idRemap = new Map<string, string>();
  const reconciliationCandidates = new Set<string>();

  const normalizedNodes = finding.nodes.map((node) => {
    const identity = resolveNodeIdentity(node);
    const resolvedId = identity.id || node.id;
    idRemap.set(node.id, resolvedId);
    return {
      ...node,
      id: resolvedId,
      identity_status: identity.status,
      identity_family: identity.family,
      canonical_id: identity.status === 'canonical' ? resolvedId : undefined,
      identity_markers: identity.markers,
    };
  });

  for (const node of normalizedNodes) {
    const isNew = !host.ctx.graph.hasNode(node.id);
    const existingNode = isNew ? null : host.getNode(node.id);
    const oldProps = existingNode ? { ...existingNode } : null;
    const baseProps: NodeProperties = {
      discovered_at: finding.timestamp,
      confidence: 1.0,
      label: node.id,
      ...node,
      discovered_by: finding.agent_id
    };

    const existingSources = existingNode ? getNodeSources(existingNode) : [];
    const sources = finding.agent_id && !existingSources.includes(finding.agent_id)
      ? [...existingSources, finding.agent_id]
      : existingSources;
    const firstSeenAt = existingNode ? getNodeFirstSeenAt(existingNode) || finding.timestamp : finding.timestamp;
    const fullProps: NodeProperties = {
      ...baseProps,
      ...normalizeNodeProvenance(baseProps),
      first_seen_at: firstSeenAt,
      last_seen_at: finding.timestamp,
      sources: sources.length > 0 ? sources : undefined,
      discovered_at: existingNode?.discovered_at || finding.timestamp,
      discovered_by: existingNode?.discovered_by || finding.agent_id,
    };
    if (baseProps.confidence >= 1.0) {
      if (isNew) {
        fullProps.confirmed_at = finding.timestamp;
      } else if (!existingNode?.confirmed_at) {
        fullProps.confirmed_at = finding.timestamp;
      } else if (existingNode?.confirmed_at) {
        fullProps.confirmed_at = existingNode.confirmed_at;
      }
    } else if (existingNode?.confirmed_at) {
      fullProps.confirmed_at = existingNode.confirmed_at;
    }

    // --- Graph compaction: classify new nodes as hot or cold ---
    // Cold = alive host with no services and no interesting edges (yet).
    // Already-hot nodes (in graphology) are never demoted.
    const alreadyHot = !isNew; // existing graph node stays hot
    const wasCold = !alreadyHot && host.ctx.coldStore.has(node.id);
    const temperature = alreadyHot ? 'hot' : classifyNodeTemperature(fullProps, false);

    if (temperature === 'cold' && !wasCold) {
      const subnetCidr = host.findSubnetCidr(fullProps.ip);
      host.ctx.coldStore.add(toColdRecord(fullProps, subnetCidr));
      continue;
    } else if (wasCold) {
      const coldRecord = host.ctx.coldStore.promote(node.id);
      if (coldRecord) {
        if (coldRecord.discovered_at < fullProps.discovered_at) {
          fullProps.discovered_at = coldRecord.discovered_at;
        }
        fullProps.first_seen_at = coldRecord.discovered_at < (fullProps.first_seen_at || fullProps.discovered_at)
          ? coldRecord.discovered_at
          : (fullProps.first_seen_at || fullProps.discovered_at);
        if (coldRecord.provenance && coldRecord.provenance !== finding.agent_id) {
          const existingSources = fullProps.sources || [];
          if (!existingSources.includes(coldRecord.provenance)) {
            fullProps.sources = [coldRecord.provenance, ...existingSources];
          }
        }
      }
    }

    host.addNode(fullProps);
    if (isNew || wasCold) {
      newNodes.push(node.id);
      host.log(`New ${node.type} discovered: ${fullProps.label}`, finding.agent_id, { category: 'finding', outcome: 'success' });
    } else if (oldProps && host.propertiesChanged(oldProps, fullProps)) {
      updatedNodes.push(node.id);
      host.log(`Updated ${node.type}: ${fullProps.label}`, finding.agent_id, { category: 'finding', outcome: 'success' });
    }
    if (fullProps.identity_status === 'canonical' && (fullProps.identity_markers?.length || 0) > 0) {
      reconciliationCandidates.add(fullProps.id);
    }
  }

  for (const canonicalNodeId of reconciliationCandidates) {
    const reconciliation = host.reconcileCanonicalNode(canonicalNodeId, finding.agent_id, finding.action_id);
    if (reconciliation.updated_canonical) {
      updatedNodes.push(canonicalNodeId);
    }
    removedNodes.push(...reconciliation.removed_nodes);
    removedEdges.push(...reconciliation.removed_edges);
    newEdges.push(...reconciliation.new_edges);
    for (const removedId of reconciliation.removed_nodes) {
      const survivorId = reconciliation.removed_nodes.includes(canonicalNodeId)
        ? reconciliation.reverse_target || canonicalNodeId
        : canonicalNodeId;
      idRemap.set(removedId, survivorId);
    }
  }

  // Add/update edges
  for (const edge of finding.edges) {
    const sourceId = idRemap.get(edge.source) || edge.source;
    const targetId = idRemap.get(edge.target) || edge.target;

    const edgeType = edge.properties?.type as EdgeType | undefined;
    const shouldPromoteCold = edgeType ? isInterestingEdgeType(edgeType) : false;

    if (shouldPromoteCold) {
      for (const endpointId of [sourceId, targetId]) {
        if (!host.ctx.graph.hasNode(endpointId) && host.ctx.coldStore.has(endpointId)) {
          const coldRecord = host.ctx.coldStore.promote(endpointId);
          if (coldRecord) {
            host.addNode({
              id: coldRecord.id,
              type: coldRecord.type as NodeType,
              label: coldRecord.label,
              ip: coldRecord.ip,
              hostname: coldRecord.hostname,
              discovered_at: coldRecord.discovered_at,
              last_seen_at: coldRecord.last_seen_at,
              alive: coldRecord.alive,
              discovered_by: coldRecord.provenance,
              confidence: 1.0,
            });
            newNodes.push(endpointId);
            host.log(`Promoted cold host to hot graph (${edgeType} edge requires it): ${coldRecord.label}`, finding.agent_id, { category: 'finding', outcome: 'success' });
          }
        }
      }
    }

    if (!host.ctx.graph.hasNode(sourceId) || !host.ctx.graph.hasNode(targetId)) continue;
    const fullProps: EdgeProperties = {
      discovered_at: finding.timestamp,
      confidence: 1.0,
      ...edge.properties,
      discovered_by: finding.agent_id
    };
    const { id: edgeId, isNew } = host.addEdge(sourceId, targetId, fullProps);
    if (isNew) {
      newEdges.push(edgeId);
      host.log(`New edge: ${sourceId} --[${edge.properties.type}]--> ${targetId}`, finding.agent_id, { category: 'finding', outcome: 'success' });
    } else {
      updatedEdges.push(edgeId);
      host.log(`Updated edge: ${sourceId} --[${edge.properties.type}]--> ${targetId}`, finding.agent_id, { category: 'finding', outcome: 'neutral' });
    }
  }

  // Collect edge endpoint nodes so cross-node rules re-evaluate when edges arrive
  const edgeEndpoints = new Set<string>();
  for (const edgeId of newEdges) {
    if (host.ctx.graph.hasEdge(edgeId)) {
      edgeEndpoints.add(host.ctx.graph.source(edgeId));
      edgeEndpoints.add(host.ctx.graph.target(edgeId));
    }
  }

  // Run inference rules against new nodes, updated nodes, and edge endpoints
  const inferenceTargets = new Set([...newNodes, ...updatedNodes, ...edgeEndpoints]);
  for (const nodeId of inferenceTargets) {
    const inferred = host.runInferenceRules(nodeId);
    inferredEdges.push(...inferred);
  }

  // Pivot reachability — imperative handler for subnet-based pivot inference
  for (const nodeId of inferenceTargets) {
    if (!host.ctx.graph.hasNode(nodeId)) continue;
    const attrs = host.ctx.graph.getNodeAttributes(nodeId);
    if (attrs.type === 'host') {
      inferredEdges.push(...host.inferPivotReachability(nodeId));
    }
  }

  // Default credentials for known CMS webapps — imperative handler
  const webappTargets = new Set<string>();
  for (const nodeId of inferenceTargets) {
    if (!host.ctx.graph.hasNode(nodeId)) continue;
    if (host.ctx.graph.getNodeAttributes(nodeId).type === 'webapp') {
      webappTargets.add(nodeId);
    }
  }
  if (webappTargets.size > 0) {
    inferredEdges.push(...host.inferDefaultCredentials(webappTargets));
    inferredEdges.push(...host.inferImdsv1Ssrf(webappTargets));
  }

  // Cloud managed identity pivot — imperative handler for host→RUNS_ON→cloud_resource→MANAGED_BY→cloud_identity
  const hostTargets = new Set<string>();
  for (const nodeId of inferenceTargets) {
    if (!host.ctx.graph.hasNode(nodeId)) continue;
    if (host.ctx.graph.getNodeAttributes(nodeId).type === 'host') {
      hostTargets.add(nodeId);
    }
  }
  if (hostTargets.size > 0) {
    inferredEdges.push(...host.inferManagedIdentityPivot(hostTargets));
  }

  // Backfill cred_domain from graph ownership paths for credentials missing domain qualification.
  const backfillCandidates = new Set([...newNodes, ...updatedNodes]);
  for (const nodeId of edgeEndpoints) {
    if (!host.ctx.graph.hasNode(nodeId)) continue;
    const attrs = host.ctx.graph.getNodeAttributes(nodeId);
    if (attrs.type !== 'user') continue;
    for (const edge of host.ctx.graph.outEdges(nodeId)) {
      if (host.ctx.graph.getEdgeAttributes(edge).type === 'OWNS_CRED') {
        backfillCandidates.add(host.ctx.graph.target(edge));
      }
    }
  }
  for (const nodeId of backfillCandidates) {
    if (!host.ctx.graph.hasNode(nodeId)) continue;
    const attrs = host.ctx.graph.getNodeAttributes(nodeId);
    if (attrs.type !== 'credential') continue;
    if (typeof attrs.cred_domain === 'string' && attrs.cred_domain.length > 0) continue;
    const inferred = inferCredentialDomain(nodeId, host.ctx.graph);
    if (inferred) {
      host.ctx.graph.mergeNodeAttributes(nodeId, {
        cred_domain: inferred.domain,
        cred_domain_inferred: true,
        cred_domain_source: 'graph_inference',
      });
    }
  }

  // Degrade POTENTIAL_AUTH edges from expired/stale credentials
  for (const nodeId of [...new Set([...newNodes, ...updatedNodes])]) {
    host.degradeExpiredCredentialEdges(nodeId);
  }

  // Check objectives
  host.evaluateObjectives();

  const allIngestedNodeIds = [...new Set([
    ...(finding.target_node_ids || []),
    ...newNodes,
    ...updatedNodes,
  ])];

  host.logActionEvent({
    description: `Finding ingested: ${newNodes.length} new nodes, ${newEdges.length} new edges, ${inferredEdges.length} inferred edges`,
    agent_id: finding.agent_id,
    action_id: finding.action_id,
    event_type: 'finding_ingested',
    category: 'finding',
    tool_name: finding.tool_name,
    target_node_ids: allIngestedNodeIds,
    frontier_item_id: finding.frontier_item_id,
    linked_finding_ids: [finding.id],
    result_classification: newNodes.length > 0 || newEdges.length > 0 || inferredEdges.length > 0 ? 'success' : 'neutral',
    details: {
      finding_id: finding.id,
      new_nodes: newNodes.length,
      new_edges: newEdges.length,
      updated_nodes: updatedNodes.length,
      updated_edges: updatedEdges.length,
      inferred_edges: inferredEdges.length,
      ingested_node_ids: allIngestedNodeIds,
    },
  });

  // Persist with real delta detail for dashboard callbacks
  const result = { new_nodes: newNodes, new_edges: newEdges, updated_nodes: updatedNodes, updated_edges: updatedEdges, inferred_edges: inferredEdges };
  host.persist({ ...result, removed_nodes: removedNodes, removed_edges: removedEdges });

  return result;
}
