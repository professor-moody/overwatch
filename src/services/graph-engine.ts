// ============================================================
// Overwatch — Graph Engine
// Engagement state as a directed property graph
// ============================================================

import GraphConstructor from 'graphology';
import { v4 as uuidv4 } from 'uuid';
import { existsSync } from 'fs';
import { isIpInScope, isHostnameInScope, isValidCidr, inferCidrFromIps } from './cidr.js';
import { EngineContext } from './engine-context.js';
import type { ActivityLogEntry, GraphUpdateCallback, GraphUpdateDetail, OverwatchGraph } from './engine-context.js';
import { StatePersistence } from './state-persistence.js';
import { AgentManager } from './agent-manager.js';
import { InferenceEngine } from './inference-engine.js';
import { PathAnalyzer } from './path-analyzer.js';
import { FrontierComputer } from './frontier.js';
import { getCredentialDisplayKind, isCredentialUsableForAuth, isCredentialStaleOrExpired, inferCredentialDomain } from './credential-utils.js';
import { runHealthChecks, summarizeHealthReport, hasADContext, contextualFilterHealthReport } from './graph-health.js';
import { summarizeInlineLabReadiness } from './lab-preflight.js';
import { normalizeFindingNode, validateFindingNode } from './finding-validation.js';
import { validateEdgeEndpoints } from './graph-schema.js';
import { getNodeFirstSeenAt, getNodeSources, normalizeNodeProvenance } from './provenance-utils.js';
import { getIdentityMarkers, isIdentityType, isUnresolvedIdentityNode, resolveNodeIdentity } from './identity-resolution.js';
import { IdentityReconciler } from './identity-reconciliation.js';
import { inferProfile } from '../types.js';
import type {
  NodeProperties, EdgeProperties, NodeType, EdgeType,
  EngagementConfig, EngagementState, FrontierItem,
  Finding, InferenceRule, GraphQuery, GraphQueryResult,
  AgentTask, ExportedGraph, HealthReport, GraphCorrectionOperation,
  ScopeSuggestion
} from '../types.js';

// Handle CJS/ESM interop for graphology — graphology publishes CJS with a
// default export that doesn't unwrap cleanly under Node16 module resolution.
// This pattern safely handles both CJS (.default) and native ESM imports.
const Graph = (GraphConstructor as any).default || GraphConstructor;
if (typeof Graph !== 'function') {
  throw new Error('Failed to import graphology Graph constructor — check CJS/ESM interop');
}
function createGraph(): OverwatchGraph {
  return new Graph({ type: 'directed', multi: true, allowSelfLoops: false }) as OverwatchGraph;
}

// --- Built-in inference rules ---
const BUILTIN_RULES: InferenceRule[] = [
  {
    id: 'rule-kerberos-domain',
    name: 'Kerberos implies domain membership',
    description: 'Host running Kerberos (port 88) is likely a domain controller — matched by hostname suffix',
    trigger: { node_type: 'service', property_match: { service_name: 'kerberos' } },
    produces: [{
      edge_type: 'MEMBER_OF_DOMAIN',
      source_selector: 'parent_host',
      target_selector: 'matching_domain',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-smb-signing-relay',
    name: 'SMB signing disabled implies relay target',
    description: 'Hosts with SMB signing disabled are relay targets',
    trigger: { node_type: 'service', property_match: { service_name: 'smb', smb_signing: false } },
    produces: [{
      edge_type: 'RELAY_TARGET',
      source_selector: 'all_compromised',
      target_selector: 'parent_host',
      confidence: 0.8
    }]
  },
  {
    id: 'rule-mssql-domain-auth',
    name: 'Domain-joined MSSQL accepts domain creds',
    description: 'MSSQL on domain-joined host likely accepts domain authentication',
    trigger: { node_type: 'service', property_match: { service_name: 'mssql' } },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'domain_credentials',
      target_selector: 'trigger_service',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-cred-fanout',
    name: 'New credential tests against compatible services',
    description: 'When a new credential is found, create POTENTIAL_AUTH edges to compatible services in the same domain',
    trigger: { node_type: 'credential' },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'trigger_node',
      target_selector: 'compatible_services_same_domain',
      confidence: 0.4
    }]
  },
  {
    id: 'rule-adcs-esc1',
    name: 'ADCS enrollment + subject supply = ESC1 candidate',
    description: 'Certificate template allowing enrollee-supplied subject name',
    trigger: { node_type: 'cert_template', property_match: { enrollee_supplies_subject: true } },
    produces: [{
      edge_type: 'ESC1',
      source_selector: 'enrollable_users',
      target_selector: 'trigger_node',
      confidence: 0.75
    }]
  },
  {
    id: 'rule-unconstrained-delegation',
    name: 'Unconstrained delegation target',
    description: 'Hosts with unconstrained delegation can capture TGTs',
    trigger: { node_type: 'host', property_match: { unconstrained_delegation: true } },
    produces: [{
      edge_type: 'DELEGATES_TO',
      source_selector: 'domain_users',
      target_selector: 'trigger_node',
      confidence: 0.85
    }]
  },
  {
    id: 'rule-asrep-roastable',
    name: 'AS-REP Roastable user',
    description: 'User with Kerberos pre-auth disabled is AS-REP roastable',
    trigger: { node_type: 'user', property_match: { asrep_roastable: true } },
    produces: [{
      edge_type: 'AS_REP_ROASTABLE',
      source_selector: 'trigger_node',
      target_selector: 'domain_nodes',
      confidence: 0.85
    }]
  },
  {
    id: 'rule-kerberoastable',
    name: 'Kerberoastable user',
    description: 'User with SPN set is kerberoastable',
    trigger: { node_type: 'user', property_match: { has_spn: true } },
    produces: [{
      edge_type: 'KERBEROASTABLE',
      source_selector: 'trigger_node',
      target_selector: 'domain_nodes',
      confidence: 0.85
    }]
  },
  {
    id: 'rule-constrained-delegation',
    name: 'Constrained delegation target',
    description: 'Host with constrained delegation can impersonate users to target services',
    trigger: { node_type: 'host', property_match: { constrained_delegation: true } },
    produces: [{
      edge_type: 'CAN_DELEGATE_TO',
      source_selector: 'trigger_node',
      target_selector: 'domain_nodes',
      confidence: 0.8
    }]
  },
  {
    id: 'rule-web-login-form',
    name: 'Web login form discovered',
    description: 'HTTP service with login form is a candidate for credential testing',
    trigger: { node_type: 'service', property_match: { has_login_form: true } },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'domain_credentials',
      target_selector: 'trigger_service',
      confidence: 0.5
    }]
  },
  {
    id: 'rule-laps-readable',
    name: 'LAPS password readable via ACL',
    description: 'Host with LAPS enabled and inbound GENERIC_ALL from a principal allows LAPS password read',
    trigger: {
      node_type: 'host',
      property_match: { laps: true },
      requires_edge: { type: 'GENERIC_ALL', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'CAN_READ_LAPS',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.75
    }]
  },
  {
    id: 'rule-gmsa-readable',
    name: 'gMSA password readable via ACL',
    description: 'gMSA service account with inbound GENERIC_ALL from a principal allows gMSA password read',
    trigger: {
      node_type: 'user',
      property_match: { gmsa: true },
      requires_edge: { type: 'GENERIC_ALL', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'CAN_READ_GMSA',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.75
    }]
  },
  {
    id: 'rule-rbcd-target',
    name: 'RBCD eligible target',
    description: 'Host writable by a principal is an RBCD target when MachineAccountQuota > 0',
    trigger: {
      node_type: 'host',
      property_match: { maq_gt_zero: true },
      requires_edge: { type: 'WRITEABLE_BY', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'RBCD_TARGET',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  }
];

// --- Edge types traversable in both directions for attack-path planning ---
// These represent relationships where the attacker can logically move in either
// direction (e.g., HAS_SESSION means user has access to host, traversable from
// either end). All other edge types remain strictly directional.
const BIDIRECTIONAL_EDGE_TYPES: Set<EdgeType> = new Set([
  'HAS_SESSION', 'ADMIN_TO', 'CAN_RDPINTO', 'CAN_PSREMOTE',
  'OWNS_CRED', 'VALID_ON',
  'MEMBER_OF', 'MEMBER_OF_DOMAIN',
  'RELATED', 'SAME_DOMAIN', 'TRUSTS',
]);

export { GraphUpdateCallback };

export class GraphEngine {
  private ctx: EngineContext;
  private persistence: StatePersistence;
  private agentMgr: AgentManager;
  private inference: InferenceEngine;
  private paths: PathAnalyzer;
  private frontierComputer: FrontierComputer;
  private reconciler: IdentityReconciler;
  private healthReportCache: HealthReport | null = null;
  private frontierCache: { passed: FrontierItem[]; all: FrontierItem[] } | null = null;

  constructor(config: EngagementConfig, stateFilePath?: string) {
    const graph = createGraph();
    const filePath = stateFilePath || `./state-${config.id}.json`;
    this.ctx = new EngineContext(graph, config, filePath);
    this.ctx.inferenceRules = [...BUILTIN_RULES];
    this.persistence = new StatePersistence(
      this.ctx, BUILTIN_RULES,
      createGraph,
    );
    this.agentMgr = new AgentManager(this.ctx);
    this.inference = new InferenceEngine(
      this.ctx,
      this.addEdge.bind(this),
      this.getNode.bind(this),
      this.getNodesByType.bind(this),
    );
    this.paths = new PathAnalyzer(
      this.ctx, BIDIRECTIONAL_EDGE_TYPES,
      this.queryGraph.bind(this),
    );
    this.frontierComputer = new FrontierComputer(
      this.ctx,
      this.hopsToNearestObjective.bind(this),
    );
    this.reconciler = new IdentityReconciler(this.ctx.graph, {
      getNode: this.getNode.bind(this),
      addEdge: this.addEdge.bind(this),
      logActionEvent: this.logActionEvent.bind(this),
      invalidatePathGraph: this.invalidatePathGraph.bind(this),
    });

    // Attempt to load existing state
    if (existsSync(this.ctx.stateFilePath)) {
      try {
        this.persistence.loadState();
        this.log('Resumed engagement from persisted state', undefined, { category: 'system', event_type: 'system' });
      } catch (err) {
        console.error(`Failed to load state file: ${err instanceof Error ? err.message : String(err)}`);
        // Attempt recovery from most recent snapshot
        const recovered = this.persistence.recoverFromSnapshot(BUILTIN_RULES);
        if (recovered) {
          this.log('Recovered engagement from snapshot after corrupted state file', undefined, { category: 'system', event_type: 'system' });
        } else {
          console.error('No valid snapshot found, re-seeding from config');
          this.seedFromConfig();
          this.log('Engagement re-initialized from config after corrupted state', undefined, { category: 'system', event_type: 'system' });
        }
      }
    } else {
      this.seedFromConfig();
      this.log('Engagement initialized from config', undefined, { category: 'system', event_type: 'system' });
    }

    this.syncObjectiveNodes();
  }

  // =============================================
  // Initialization
  // =============================================

  private seedFromConfig(): void {
    const now = new Date().toISOString();

    // CIDRs are used for scope validation only — hosts are created when tools discover them

    // Create host nodes from explicit hosts
    if (this.ctx.config.scope.hosts) {
      for (const host of this.ctx.config.scope.hosts) {
        const id = `host-${host.replace(/[.\s]/g, '-')}`;
        if (!this.ctx.graph.hasNode(id)) {
          this.addNode({
            id,
            type: 'host',
            label: host,
            hostname: host,
            discovered_at: now,
            first_seen_at: now,
            last_seen_at: now,
            confidence: 1.0
          });
        }
      }
    }

    // Create domain nodes
    for (const domain of this.ctx.config.scope.domains) {
      this.addNode({
        id: `domain-${domain.replace(/\./g, '-')}`,
        type: 'domain',
        label: domain,
        domain_name: domain,
        discovered_at: now,
        first_seen_at: now,
        last_seen_at: now,
        confidence: 1.0
      });
    }

    // Create objective nodes
    for (const obj of this.ctx.config.objectives) {
      this.addNode({
        id: `obj-${obj.id}`,
        type: 'objective',
        label: obj.description,
        objective_description: obj.description,
        objective_achieved: obj.achieved,
        objective_achieved_at: obj.achieved_at,
        discovered_at: now,
        first_seen_at: now,
        last_seen_at: now,
        confidence: 1.0
      });
    }

    this.persist();
  }

  // =============================================
  // Node / Edge Operations
  // =============================================

  addNode(props: NodeProperties): string {
    if (this.ctx.graph.hasNode(props.id)) {
      // Merge properties
      this.ctx.graph.mergeNodeAttributes(props.id, props as any);
    } else {
      this.ctx.graph.addNode(props.id, props);
      this.invalidatePathGraph();
    }
    this.invalidateHealthReport();
    return props.id;
  }

  addEdge(source: string, target: string, props: EdgeProperties): { id: string; isNew: boolean } {
    // Check for duplicate edge of same type
    const existingEdges = this.ctx.graph.edges(source, target);
    for (const edgeId of existingEdges) {
      const attrs = this.ctx.graph.getEdgeAttributes(edgeId);
      if (attrs.type === props.type) {
        // Detect confirmation of inferred edge
        if (attrs.inferred_by_rule && !attrs.confirmed_at && props.confidence >= 1.0) {
          props = { ...props, confirmed_at: new Date().toISOString() };
          this.log(`Confirmed inferred edge [${attrs.inferred_by_rule}]: ${source} --[${attrs.type}]--> ${target}`, undefined, { category: 'inference', outcome: 'success', event_type: 'inference_generated' });
        }
        // Update existing edge
        this.ctx.graph.mergeEdgeAttributes(edgeId, props as any);
        this.invalidateHealthReport();
        return { id: edgeId, isNew: false };
      }
    }
    // New edge
    this.invalidatePathGraph();
    this.invalidateHealthReport();
    const edgeId = `${source}--${props.type}--${target}`;
    try {
      return { id: this.ctx.graph.addEdgeWithKey(edgeId, source, target, props), isNew: true };
    } catch {
      // Edge key might already exist for a different source/target pair
      const fallbackId = `${edgeId}-${uuidv4().slice(0, 8)}`;
      return { id: this.ctx.graph.addEdgeWithKey(fallbackId, source, target, props), isNew: true };
    }
  }

  findEdgeId(source: string, target: string, type: EdgeType): string | null {
    if (!this.ctx.graph.hasNode(source) || !this.ctx.graph.hasNode(target)) {
      return null;
    }
    const existingEdges = this.ctx.graph.edges(source, target);
    for (const edgeId of existingEdges) {
      const attrs = this.ctx.graph.getEdgeAttributes(edgeId);
      if (attrs.type === type) return edgeId;
    }
    return null;
  }

  dropEdgeByRef(source: string, target: string, type: EdgeType): string | null {
    const edgeId = this.findEdgeId(source, target, type);
    if (!edgeId) return null;
    this.ctx.graph.dropEdge(edgeId);
    this.invalidatePathGraph();
    this.invalidateHealthReport();
    return edgeId;
  }

  patchNodeProperties(nodeId: string, setProperties: Record<string, unknown> = {}, unsetProperties: string[] = []): NodeProperties {
    const existing = this.getNode(nodeId);
    if (!existing) {
      throw new Error(`Node does not exist in graph: ${nodeId}`);
    }
    if ((typeof setProperties.id === 'string' && setProperties.id !== nodeId) || (typeof setProperties.type === 'string' && setProperties.type !== existing.type)) {
      throw new Error('patch_node cannot change a node id or type.');
    }

    const normalizedPatch = existing.type === 'credential'
      ? normalizeFindingNode({
          ...existing,
          ...setProperties,
          id: nodeId,
          type: existing.type,
          label: typeof setProperties.label === 'string' ? setProperties.label : existing.label,
        } as Partial<NodeProperties> & { id: string; type: string })
      : ({ ...existing, ...setProperties } as NodeProperties);

    for (const key of unsetProperties) {
      delete (normalizedPatch as Record<string, unknown>)[key];
    }

    const validationErrors = validateFindingNode(normalizedPatch as Partial<NodeProperties> & { id: string; type: string });
    if (validationErrors.length > 0) {
      throw new Error(validationErrors.map(error => error.message).join('; '));
    }

    const nextNode = {
      ...existing,
      ...normalizedPatch,
      id: nodeId,
      type: existing.type,
    } as NodeProperties;
    const nextAttrs = {
      ...nextNode,
      ...normalizeNodeProvenance(nextNode),
    };
    this.ctx.graph.replaceNodeAttributes(nodeId, nextAttrs as any);
    this.invalidateHealthReport();
    return this.ctx.graph.getNodeAttributes(nodeId);
  }

  getNode(id: string): NodeProperties | null {
    if (!this.ctx.graph.hasNode(id)) return null;
    return this.ctx.graph.getNodeAttributes(id);
  }

  getNodesByType(type: NodeType): NodeProperties[] {
    const results: NodeProperties[] = [];
    this.ctx.graph.forEachNode((id, attrs) => {
      if (attrs.type === type && attrs.identity_status !== 'superseded') {
        results.push(attrs);
      }
    });
    return results;
  }

  // =============================================
  // Finding Ingestion
  // =============================================

  ingestFinding(finding: Finding): { new_nodes: string[]; new_edges: string[]; updated_nodes: string[]; updated_edges: string[]; inferred_edges: string[] } {
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
      const isNew = !this.ctx.graph.hasNode(node.id);
      const existingNode = isNew ? null : this.getNode(node.id);
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

      this.addNode(fullProps);
      if (isNew) {
        newNodes.push(node.id);
        this.log(`New ${node.type} discovered: ${fullProps.label}`, finding.agent_id, { category: 'finding', outcome: 'success' });
      } else if (oldProps && this.propertiesChanged(oldProps, fullProps)) {
        updatedNodes.push(node.id);
        this.log(`Updated ${node.type}: ${fullProps.label}`, finding.agent_id, { category: 'finding', outcome: 'success' });
      }
      if (fullProps.identity_status === 'canonical' && (fullProps.identity_markers?.length || 0) > 0) {
        reconciliationCandidates.add(fullProps.id);
      }
    }

    for (const canonicalNodeId of reconciliationCandidates) {
      const reconciliation = this.reconciler.reconcileCanonicalNode(canonicalNodeId, finding.agent_id, finding.action_id);
      if (reconciliation.updated_canonical) {
        updatedNodes.push(canonicalNodeId);
      }
      removedNodes.push(...reconciliation.removed_nodes);
      removedEdges.push(...reconciliation.removed_edges);
      newEdges.push(...reconciliation.new_edges);
      // Update idRemap so later edge processing uses the surviving node ID
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
      if (!this.ctx.graph.hasNode(sourceId) || !this.ctx.graph.hasNode(targetId)) continue;
      const fullProps: EdgeProperties = {
        discovered_at: finding.timestamp,
        confidence: 1.0,
        ...edge.properties,
        discovered_by: finding.agent_id
      };
      const { id: edgeId, isNew } = this.addEdge(sourceId, targetId, fullProps);
      if (isNew) {
        newEdges.push(edgeId);
        this.log(`New edge: ${sourceId} --[${edge.properties.type}]--> ${targetId}`, finding.agent_id, { category: 'finding', outcome: 'success' });
      } else {
        updatedEdges.push(edgeId);
        this.log(`Updated edge: ${sourceId} --[${edge.properties.type}]--> ${targetId}`, finding.agent_id, { category: 'finding', outcome: 'neutral' });
      }
    }

    // Collect edge endpoint nodes so cross-node rules re-evaluate when edges arrive
    const edgeEndpoints = new Set<string>();
    for (const edgeId of newEdges) {
      if (this.ctx.graph.hasEdge(edgeId)) {
        edgeEndpoints.add(this.ctx.graph.source(edgeId));
        edgeEndpoints.add(this.ctx.graph.target(edgeId));
      }
    }

    // Run inference rules against new nodes, updated nodes, and edge endpoints
    const inferenceTargets = new Set([...newNodes, ...updatedNodes, ...edgeEndpoints]);
    for (const nodeId of inferenceTargets) {
      const inferred = this.runInferenceRules(nodeId);
      inferredEdges.push(...inferred);
    }

    // Backfill cred_domain from graph ownership paths for credentials missing domain qualification.
    // Include credentials owned by users in edgeEndpoints — handles incremental ingestion where
    // a MEMBER_OF_DOMAIN edge arrives after the credential was already created.
    const backfillCandidates = new Set([...newNodes, ...updatedNodes]);
    for (const nodeId of edgeEndpoints) {
      if (!this.ctx.graph.hasNode(nodeId)) continue;
      const attrs = this.ctx.graph.getNodeAttributes(nodeId);
      if (attrs.type !== 'user') continue;
      for (const edge of this.ctx.graph.outEdges(nodeId)) {
        if (this.ctx.graph.getEdgeAttributes(edge).type === 'OWNS_CRED') {
          backfillCandidates.add(this.ctx.graph.target(edge));
        }
      }
    }
    for (const nodeId of backfillCandidates) {
      if (!this.ctx.graph.hasNode(nodeId)) continue;
      const attrs = this.ctx.graph.getNodeAttributes(nodeId);
      if (attrs.type !== 'credential') continue;
      if (typeof attrs.cred_domain === 'string' && attrs.cred_domain.length > 0) continue;
      const inferred = inferCredentialDomain(nodeId, this.ctx.graph);
      if (inferred) {
        this.ctx.graph.mergeNodeAttributes(nodeId, {
          cred_domain: inferred.domain,
          cred_domain_inferred: true,
          cred_domain_source: 'graph_inference',
        });
      }
    }

    // Degrade POTENTIAL_AUTH edges from expired/stale credentials
    for (const nodeId of [...new Set([...newNodes, ...updatedNodes])]) {
      this.degradeExpiredCredentialEdges(nodeId);
    }

    // Check objectives
    this.evaluateObjectives();

    this.logActionEvent({
      description: `Finding ingested: ${newNodes.length} new nodes, ${newEdges.length} new edges, ${inferredEdges.length} inferred edges`,
      agent_id: finding.agent_id,
      action_id: finding.action_id,
      event_type: 'finding_ingested',
      category: 'finding',
      tool_name: finding.tool_name,
      target_node_ids: finding.target_node_ids,
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
      },
    });

    // Persist with real delta detail for dashboard callbacks
    const result = { new_nodes: newNodes, new_edges: newEdges, updated_nodes: updatedNodes, updated_edges: updatedEdges, inferred_edges: inferredEdges };
    this.persist({ ...result, removed_nodes: removedNodes, removed_edges: removedEdges });

    return result;
  }

  // =============================================
  // Inference Engine (delegated to InferenceEngine)
  // =============================================

  addInferenceRule(rule: InferenceRule): void {
    this.inference.addRule(rule);
    this.persist();
  }

  backfillRule(rule: InferenceRule): string[] {
    const inferred = this.inference.backfillRule(rule);
    if (inferred.length > 0) this.persist();
    return inferred;
  }

  private runInferenceRules(triggerNodeId: string): string[] {
    return this.inference.runRules(triggerNodeId);
  }

  degradeExpiredCredentialEdges(credNodeId: string): string[] {
    const node = this.getNode(credNodeId);
    if (!node || node.type !== 'credential' || !isCredentialStaleOrExpired(node)) return [];

    const degraded: string[] = [];
    for (const edgeId of this.ctx.graph.outEdges(credNodeId) as string[]) {
      const attrs = this.ctx.graph.getEdgeAttributes(edgeId);
      if (attrs.type !== 'POTENTIAL_AUTH') continue;
      const newConfidence = Math.max(0.1, attrs.confidence * 0.5);
      if (newConfidence >= attrs.confidence) continue;
      this.ctx.graph.mergeEdgeAttributes(edgeId, { confidence: newConfidence } as any);
      degraded.push(edgeId);
    }

    if (degraded.length > 0) {
      this.log(`Degraded ${degraded.length} POTENTIAL_AUTH edge(s) from expired/stale credential ${credNodeId}`, undefined, {
        category: 'inference',
        event_type: 'credential_degradation',
        details: { credential_node: credNodeId, degraded_edges: degraded.length, credential_status: node.credential_status },
      });
      this.invalidateHealthReport();
    }

    return degraded;
  }

  // =============================================
  // Frontier Computation (delegated to FrontierComputer)
  // =============================================

  computeFrontier(): FrontierItem[] {
    if (!this.frontierCache) {
      const all = this.frontierComputer.compute();
      const { passed } = this.filterFrontier(all);
      this.frontierCache = { all, passed };
    }
    return this.frontierCache.all;
  }

  private getCachedFilteredFrontier(): FrontierItem[] {
    if (!this.frontierCache) {
      this.computeFrontier();
    }
    return this.frontierCache!.passed;
  }

  // =============================================
  // Path Analysis (delegated to PathAnalyzer)
  // =============================================

  private invalidatePathGraph(): void {
    this.ctx.invalidatePathGraph();
  }

  hopsToNearestObjective(fromNodeId: string): number | null {
    return this.paths.hopsToNearestObjective(fromNodeId);
  }

  findPathsToObjective(objectiveId: string, maxPaths: number = 5): Array<{ nodes: string[]; total_confidence: number }> {
    return this.paths.findPathsToObjective(objectiveId, maxPaths);
  }

  findPaths(fromNode: string, toNode: string, maxPaths: number = 5): Array<{ nodes: string[]; total_confidence: number }> {
    return this.paths.findPaths(fromNode, toNode, maxPaths);
  }

  // =============================================
  // Graph Queries (full access for LLM)
  // =============================================

  queryGraph(query: GraphQuery): GraphQueryResult {
    const result: GraphQueryResult = { nodes: [], edges: [] };
    const limit = query.limit || 100;

    // Node queries
    if (query.node_type || query.node_filter || query.from_node) {
      if (query.from_node && this.ctx.graph.hasNode(query.from_node)) {
        // Traverse from node
        const visited = new Set<string>();
        const queue: Array<{ id: string; depth: number }> = [{ id: query.from_node, depth: 0 }];
        const maxDepth = query.max_depth || 2;

        while (queue.length > 0 && result.nodes.length < limit) {
          const current = queue.shift()!;
          if (visited.has(current.id)) continue;
          visited.add(current.id);

          const node = this.getNode(current.id);
          if (node && node.identity_status !== 'superseded') {
            if (!query.node_type || node.type === query.node_type) {
              if (this.matchesFilter(node, query.node_filter)) {
                result.nodes.push({ id: current.id, properties: node });
              }
            }
          }

          if (current.depth < maxDepth) {
            const neighbors = query.direction === 'inbound'
              ? this.ctx.graph.inNeighbors(current.id)
              : query.direction === 'outbound'
                ? this.ctx.graph.outNeighbors(current.id)
                : this.ctx.graph.neighbors(current.id);

            for (const neighbor of neighbors) {
              if (!visited.has(neighbor)) {
                queue.push({ id: neighbor, depth: current.depth + 1 });
              }
            }
          }
        }

        // Also include edges between found nodes
        const nodeIds = new Set(result.nodes.map(n => n.id));
        this.ctx.graph.forEachEdge((edgeId, attrs, source, target) => {
          if (nodeIds.has(source) && nodeIds.has(target)) {
            if (!query.edge_type || attrs.type === query.edge_type) {
              result.edges.push({ source, target, properties: attrs });
            }
          }
        });
      } else {
        // Filter all nodes
        this.ctx.graph.forEachNode((id, attrs) => {
          if (result.nodes.length >= limit) return;
          if (attrs.identity_status === 'superseded') return;
          if (query.node_type && attrs.type !== query.node_type) return;
          if (!this.matchesFilter(attrs, query.node_filter)) return;
          result.nodes.push({ id, properties: attrs });
        });
      }
    }

    // Edge queries
    if (query.edge_type || query.edge_filter) {
      this.ctx.graph.forEachEdge((edgeId, attrs, source, target) => {
        if (result.edges.length >= limit) return;
        if (query.edge_type && attrs.type !== query.edge_type) return;
        if (!this.matchesFilter(attrs, query.edge_filter)) return;
        result.edges.push({ source, target, properties: attrs });
      });
    }

    return result;
  }

  private matchesFilter(obj: Record<string, unknown>, filter?: Record<string, unknown>): boolean {
    if (!filter) return true;
    return Object.entries(filter).every(([key, val]) => {
      if (val === undefined || val === null) return true;
      return obj[key] === val;
    });
  }

  // =============================================
  // Deterministic Filter (Layer 1)
  // =============================================

  filterFrontier(frontier: FrontierItem[]): { passed: FrontierItem[]; filtered: Array<{ item: FrontierItem; reason: string }> } {
    const passed: FrontierItem[] = [];
    const filtered: Array<{ item: FrontierItem; reason: string }> = [];

    for (const item of frontier) {
      // 1. Scope check — node_id, edge_source, and edge_target
      //    Resolves child nodes (services, shares) to their parent host IP.
      if (item.node_id) {
        const excludedIp = this.isNodeExcluded(item.node_id);
        if (excludedIp) {
          filtered.push({ item, reason: `Out of scope: ${excludedIp} is excluded` });
          continue;
        }
      }
      if (item.edge_source) {
        const excludedIp = this.isNodeExcluded(item.edge_source);
        if (excludedIp) {
          filtered.push({ item, reason: `Out of scope: edge source ${excludedIp} is excluded` });
          continue;
        }
      }
      if (item.edge_target) {
        const excludedIp = this.isNodeExcluded(item.edge_target);
        if (excludedIp) {
          filtered.push({ item, reason: `Out of scope: edge target ${excludedIp} is excluded` });
          continue;
        }
      }

      // 2. OPSEC hard veto
      if (item.opsec_noise > this.ctx.config.opsec.max_noise) {
        filtered.push({ item, reason: `OPSEC veto: noise ${item.opsec_noise} exceeds max ${this.ctx.config.opsec.max_noise}` });
        continue;
      }

      // 3. Dead host skip
      if (item.node_id) {
        const node = this.getNode(item.node_id);
        if (node?.type === 'host' && node.alive === false) {
          filtered.push({ item, reason: `Dead host: ${node.label}` });
          continue;
        }
      }

      // Everything else passes through to LLM
      passed.push(item);
    }

    return { passed, filtered };
  }

  private isExcluded(ip: string): boolean {
    return !isIpInScope(ip, this.ctx.config.scope.cidrs, this.ctx.config.scope.exclusions);
  }

  private resolveHostIp(nodeId: string): string | null {
    const node = this.getNode(nodeId);
    if (!node) return null;
    if (node.ip) return node.ip;
    // Walk inbound edges to find the parent host (e.g. host --RUNS--> service)
    for (const edge of this.ctx.graph.inEdges(nodeId) as string[]) {
      const source = this.ctx.graph.source(edge);
      const sourceNode = this.getNode(source);
      if (sourceNode?.type === 'host' && sourceNode.ip) return sourceNode.ip;
    }
    return null;
  }

  private resolveHostname(nodeId: string): string | null {
    const node = this.getNode(nodeId);
    if (!node) return null;
    if (node.hostname) return node.hostname;
    // Walk inbound edges to find the parent host
    for (const edge of this.ctx.graph.inEdges(nodeId) as string[]) {
      const source = this.ctx.graph.source(edge);
      const sourceNode = this.getNode(source);
      if (sourceNode?.type === 'host' && sourceNode.hostname) return sourceNode.hostname;
    }
    return null;
  }

  private isNodeExcluded(nodeId: string): string | null {
    const ip = this.resolveHostIp(nodeId);
    if (ip && this.isExcluded(ip)) return ip;
    // Fall back to hostname-based scope check for nodes without IPs
    if (!ip) {
      const hostname = this.resolveHostname(nodeId);
      if (hostname && !isHostnameInScope(hostname, this.ctx.config.scope.domains, this.ctx.config.scope.exclusions)) {
        return hostname;
      }
    }
    return null;
  }

  // =============================================
  // Validation (Layer 3 — post-LLM sanity check)
  // =============================================

  validateAction(action: { target_node?: string; target_ip?: string; edge_source?: string; edge_target?: string; technique?: string }): {
    valid: boolean;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check referenced nodes exist
    if (action.target_node && !this.ctx.graph.hasNode(action.target_node)) {
      errors.push(`Node does not exist in graph: ${action.target_node}`);
    }
    if (action.edge_source && !this.ctx.graph.hasNode(action.edge_source)) {
      errors.push(`Source node does not exist: ${action.edge_source}`);
    }
    if (action.edge_target && !this.ctx.graph.hasNode(action.edge_target)) {
      errors.push(`Target node does not exist: ${action.edge_target}`);
    }

    // Scope check for raw target_ip (pre-discovery validation)
    if (action.target_ip) {
      if (!isIpInScope(action.target_ip, this.ctx.config.scope.cidrs, this.ctx.config.scope.exclusions)) {
        errors.push(`Target IP is out of scope: ${action.target_ip}`);
      }
    }

    // Check scope — target_node, edge_source, and edge_target
    //    Resolves child nodes (services, shares) to their parent host IP.
    if (action.target_node) {
      const excludedIp = this.isNodeExcluded(action.target_node);
      if (excludedIp) {
        errors.push(`Target is out of scope: ${excludedIp}`);
      }
    }
    if (action.edge_source) {
      const excludedIp = this.isNodeExcluded(action.edge_source);
      if (excludedIp) {
        errors.push(`Edge source is out of scope: ${excludedIp}`);
      }
    }
    if (action.edge_target) {
      const excludedIp = this.isNodeExcluded(action.edge_target);
      if (excludedIp) {
        errors.push(`Edge target is out of scope: ${excludedIp}`);
      }
    }

    // Check OPSEC blacklist
    if (action.technique && this.ctx.config.opsec.blacklisted_techniques?.includes(action.technique)) {
      errors.push(`Technique blacklisted by OPSEC profile: ${action.technique}`);
    }

    // Time window check (handles wrap-around, e.g. 22:00–06:00)
    if (this.ctx.config.opsec.time_window) {
      const hour = new Date().getHours();
      const { start_hour, end_hour } = this.ctx.config.opsec.time_window;
      const inWindow = start_hour <= end_hour
        ? hour >= start_hour && hour < end_hour
        : hour >= start_hour || hour < end_hour;
      if (!inWindow) {
        warnings.push(`Outside approved time window (${start_hour}:00-${end_hour}:00), current hour: ${hour}`);
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  // =============================================
  // Objective Tracking
  // =============================================

  private evaluateObjectives(): void {
    const DEFAULT_ACCESS_EDGE_TYPES = new Set(['HAS_SESSION', 'ADMIN_TO', 'OWNS_CRED']);

    for (const obj of this.ctx.config.objectives) {
      if (obj.achieved) continue;
      // Check if objective criteria are met in the graph
      if (obj.target_criteria) {
        const matching = this.queryGraph({
          node_type: obj.target_node_type,
          node_filter: obj.target_criteria
        });
        const accessEdgeTypes = obj.achievement_edge_types
          ? new Set(obj.achievement_edge_types)
          : DEFAULT_ACCESS_EDGE_TYPES;
        // A matching node must also be obtained — via an access edge, an explicit
        // obtained flag, or (for shares) readable/writable properties.
        const obtained = matching.nodes.some(n => {
          const nodeProps = n.properties;
          if (nodeProps.type === 'credential' && !isCredentialUsableForAuth(nodeProps)) {
            return false;
          }
          if (n.properties.obtained === true) return true;
          // Shares with readable/writable access count as obtained
          if (nodeProps.type === 'share' && (nodeProps.readable === true || nodeProps.writable === true)) {
            return true;
          }
          return this.ctx.graph.inEdges(n.id).some((e: string) => {
            const ep = this.ctx.graph.getEdgeAttributes(e);
            if (ep.type !== 'OWNS_CRED') {
              return accessEdgeTypes.has(ep.type) && ep.confidence >= 0.9;
            }
            return nodeProps.type === 'credential' && isCredentialUsableForAuth(nodeProps) && ep.confidence >= 0.9;
          });
        });
        if (obtained) {
          obj.achieved = true;
          obj.achieved_at = new Date().toISOString();
          this.log(`OBJECTIVE ACHIEVED: ${obj.description}`, undefined, { category: 'objective', outcome: 'success', event_type: 'objective_achieved' });
        }
      }
    }

    this.syncObjectiveNodes();
  }

  recomputeObjectives(): { before: Array<{ id: string; achieved: boolean; achieved_at?: string }>; after: Array<{ id: string; achieved: boolean; achieved_at?: string }> } {
    const before = this.ctx.config.objectives.map(obj => ({
      id: obj.id,
      achieved: obj.achieved,
      achieved_at: obj.achieved_at,
    }));

    for (const obj of this.ctx.config.objectives) {
      obj.achieved = false;
      delete obj.achieved_at;
    }

    this.evaluateObjectives();
    const after = this.ctx.config.objectives.map(obj => ({
      id: obj.id,
      achieved: obj.achieved,
      achieved_at: obj.achieved_at,
    }));

    this.persist();
    return { before, after };
  }

  correctGraph(
    reason: string,
    operations: GraphCorrectionOperation[],
    actionId?: string,
  ): {
    dropped_edges: string[];
    replaced_edges: Array<{ old_edge_id: string; new_edge_id: string }>;
    patched_nodes: string[];
  } {
    const droppedEdges: string[] = [];
    const replacedEdges: Array<{ old_edge_id: string; new_edge_id: string }> = [];
    const patchedNodes: string[] = [];
    const removedEdges: string[] = [];
    const newEdges: string[] = [];
    const updatedNodes: string[] = [];
    const beforeSummary = {
      total_nodes: this.ctx.graph.order,
      total_edges: this.ctx.graph.size,
    };

    for (const operation of operations) {
      if (operation.kind === 'drop_edge' || operation.kind === 'replace_edge') {
        const sourceId = operation.source_id;
        const targetId = operation.target_id;
        const existingEdgeId = this.findEdgeId(sourceId, targetId, operation.edge_type);
        if (!existingEdgeId) {
          throw new Error(`Edge does not exist in graph: ${sourceId} --[${operation.edge_type}]--> ${targetId}`);
        }

        if (operation.kind === 'replace_edge') {
          const newSource = operation.new_source_id || sourceId;
          const newTarget = operation.new_target_id || targetId;
          const newType = operation.new_edge_type || operation.edge_type;
          const sourceNode = this.getNode(newSource);
          const targetNode = this.getNode(newTarget);
          if (!sourceNode || !targetNode) {
            throw new Error(`Replacement edge references missing nodes: ${newSource} --[${newType}]--> ${newTarget}`);
          }

          const validation = validateEdgeEndpoints(newType, sourceNode.type, targetNode.type, {
            source_id: newSource,
            target_id: newTarget,
            edge_id: existingEdgeId,
          });
          if (!validation.valid) {
            throw new Error(`Replacement edge ${newType} cannot connect ${sourceNode.type} to ${targetNode.type}.`);
          }
        }
      }

      if (operation.kind === 'patch_node') {
        const existingNode = this.getNode(operation.node_id);
        if (!existingNode) {
          throw new Error(`Node does not exist in graph: ${operation.node_id}`);
        }
      }
    }

    for (const operation of operations) {
      if (operation.kind === 'drop_edge') {
        const dropped = this.dropEdgeByRef(operation.source_id, operation.target_id, operation.edge_type);
        if (!dropped) {
          throw new Error(`Edge disappeared before correction: ${operation.source_id} --[${operation.edge_type}]--> ${operation.target_id}`);
        }
        droppedEdges.push(dropped);
        removedEdges.push(dropped);
        continue;
      }

      if (operation.kind === 'replace_edge') {
        const existingEdgeId = this.findEdgeId(operation.source_id, operation.target_id, operation.edge_type);
        const previousAttrs = existingEdgeId ? this.ctx.graph.getEdgeAttributes(existingEdgeId) : null;
        const oldEdgeId = this.dropEdgeByRef(operation.source_id, operation.target_id, operation.edge_type);
        if (!oldEdgeId) {
          throw new Error(`Edge disappeared before replacement: ${operation.source_id} --[${operation.edge_type}]--> ${operation.target_id}`);
        }
        removedEdges.push(oldEdgeId);
        droppedEdges.push(oldEdgeId);
        const sourceId = operation.new_source_id || operation.source_id;
        const targetId = operation.new_target_id || operation.target_id;
        const edgeType = operation.new_edge_type || operation.edge_type;
        const nextProps: EdgeProperties = {
          ...(previousAttrs || {}),
          ...(operation.properties || {}),
          type: edgeType,
          confidence: operation.confidence ?? previousAttrs?.confidence ?? 1.0,
          discovered_at: previousAttrs?.discovered_at || new Date().toISOString(),
          discovered_by: previousAttrs?.discovered_by,
        };
        const { id: newEdgeId } = this.addEdge(sourceId, targetId, nextProps);
        replacedEdges.push({ old_edge_id: oldEdgeId, new_edge_id: newEdgeId });
        newEdges.push(newEdgeId);
        continue;
      }

      if (operation.kind === 'patch_node') {
        this.patchNodeProperties(operation.node_id, operation.set_properties, operation.unset_properties);
        patchedNodes.push(operation.node_id);
        updatedNodes.push(operation.node_id);
      }
    }

    this.evaluateObjectives();
    this.logActionEvent({
      description: `Graph corrected: ${operations.length} operation(s) applied`,
      action_id: actionId,
      event_type: 'graph_corrected',
      category: 'system',
      result_classification: 'success',
      details: {
        reason,
        operations,
        before_summary: beforeSummary,
        after_summary: {
          total_nodes: this.ctx.graph.order,
          total_edges: this.ctx.graph.size,
        },
        dropped_edges: droppedEdges,
        replaced_edges: replacedEdges,
        patched_nodes: patchedNodes,
      },
    });
    this.persist({ removed_edges: removedEdges, new_edges: newEdges, updated_nodes: updatedNodes });

    return {
      dropped_edges: droppedEdges,
      replaced_edges: replacedEdges,
      patched_nodes: patchedNodes,
    };
  }

  // =============================================
  // Agent Management (delegated to AgentManager)
  // =============================================

  registerAgent(task: AgentTask): void {
    this.agentMgr.register(task);
    this.persist();
  }

  getRunningTaskForFrontierItem(frontierItemId: string): AgentTask | null {
    return this.agentMgr.getRunningTaskForFrontierItem(frontierItemId);
  }

  getTask(taskId: string): AgentTask | null {
    return this.agentMgr.getTask(taskId);
  }

  updateAgentStatus(taskId: string, status: AgentTask['status'], summary?: string): boolean {
    const ok = this.agentMgr.updateStatus(taskId, status, summary);
    if (ok) this.persist();
    return ok;
  }

  getSubgraphForAgent(nodeIds: string[], options?: { hops?: number; includeCredentials?: boolean; includeServices?: boolean }): GraphQueryResult {
    const hops = options?.hops ?? 2;
    const includeCredentials = options?.includeCredentials ?? true;
    const includeServices = options?.includeServices ?? true;

    const result: GraphQueryResult = { nodes: [], edges: [] };
    const nodeSet = new Set<string>();

    // N-hop BFS from seed nodes
    let frontier = new Set(nodeIds.filter(id => this.ctx.graph.hasNode(id)));
    for (const id of frontier) nodeSet.add(id);

    for (let depth = 0; depth < hops; depth++) {
      const nextFrontier = new Set<string>();
      for (const id of frontier) {
        for (const neighbor of this.ctx.graph.neighbors(id)) {
          if (!nodeSet.has(neighbor)) {
            nodeSet.add(neighbor);
            nextFrontier.add(neighbor);
          }
        }
      }
      frontier = nextFrontier;
      if (frontier.size === 0) break;
    }

    // Enrich: include all credentials and services connected to hosts in the subgraph
    if (includeCredentials || includeServices) {
      const hostIds = [...nodeSet].filter(id => {
        const n = this.getNode(id);
        return n && n.type === 'host';
      });
      for (const hostId of hostIds) {
        for (const neighbor of this.ctx.graph.neighbors(hostId)) {
          if (nodeSet.has(neighbor)) continue;
          const n = this.getNode(neighbor);
          if (!n) continue;
          if ((includeCredentials && n.type === 'credential') ||
              (includeServices && n.type === 'service')) {
            nodeSet.add(neighbor);
          }
        }
      }
    }

    // Collect nodes
    for (const id of nodeSet) {
      const node = this.getNode(id);
      if (node) result.nodes.push({ id, properties: node });
    }

    // Collect all edges between collected nodes
    this.ctx.graph.forEachEdge((_, attrs, source, target) => {
      if (nodeSet.has(source) && nodeSet.has(target)) {
        result.edges.push({ source, target, properties: attrs });
      }
    });

    return result;
  }

  /**
   * Auto-compute subgraph from a frontier item's target node(s).
   * Returns node IDs for the N-hop neighborhood.
   */
  computeSubgraphNodeIds(frontierItemId: string, hops: number = 2): string[] {
    const seeds = this.resolveFrontierSeeds(frontierItemId);

    if (seeds.length === 0) return [];

    // BFS N-hop
    const visited = new Set(seeds);
    let current = new Set(seeds);
    for (let d = 0; d < hops; d++) {
      const next = new Set<string>();
      for (const id of current) {
        for (const neighbor of this.ctx.graph.neighbors(id)) {
          if (!visited.has(neighbor)) {
            visited.add(neighbor);
            next.add(neighbor);
          }
        }
      }
      current = next;
      if (current.size === 0) break;
    }

    return [...visited];
  }

  // =============================================
  // State Summary
  // =============================================

  getState(options?: { activityCount?: number }): EngagementState {
    const activityCount = options?.activityCount ?? 20;
    const nodesByType: Record<string, number> = {};
    const edgesByType: Record<string, number> = {};
    let confirmedEdges = 0;
    let inferredEdges = 0;

    this.ctx.graph.forEachNode((_, attrs) => {
      if (attrs.identity_status === 'superseded') return;
      nodesByType[attrs.type] = (nodesByType[attrs.type] || 0) + 1;
    });

    this.ctx.graph.forEachEdge((_, attrs) => {
      edgesByType[attrs.type] = (edgesByType[attrs.type] || 0) + 1;
      if (attrs.confidence >= 1.0) confirmedEdges++;
      else inferredEdges++;
    });

    // Compute access summary
    const compromised: string[] = [];
    const validCreds: string[] = [];

    this.ctx.graph.forEachNode((id, attrs) => {
      if (attrs.identity_status === 'superseded') return;
      if (attrs.type === 'host') {
        const hasAccess = this.ctx.graph.edges(id).some(e => {
          const ep = this.ctx.graph.getEdgeAttributes(e);
          return (ep.type === 'HAS_SESSION' || ep.type === 'ADMIN_TO') && ep.confidence >= 0.9;
        });
        if (hasAccess) compromised.push(attrs.label);
      }
      if (attrs.type === 'credential' && attrs.confidence >= 0.9 && isCredentialUsableForAuth(attrs)) {
        validCreds.push(`${getCredentialDisplayKind(attrs)}: ${attrs.cred_user || attrs.label}`);
      }
    });

    const rawHealthReport = this.runHealthChecks();
    const profile = inferProfile(this.ctx.config);
    const adContext = hasADContext(this.ctx.graph);
    const healthReport = contextualFilterHealthReport(rawHealthReport, profile, adContext);
    const labReadiness = summarizeInlineLabReadiness(this);

    return {
      config: this.ctx.config,
      graph_summary: {
        total_nodes: this.ctx.graph.order,
        nodes_by_type: nodesByType,
        total_edges: this.ctx.graph.size,
        edges_by_type: edgesByType,
        confirmed_edges: confirmedEdges,
        inferred_edges: inferredEdges
      },
      objectives: this.ctx.config.objectives,
      frontier: this.getCachedFilteredFrontier(),
      active_agents: Array.from(this.ctx.agents.values()).filter(a => a.status === 'running'),
      recent_activity: this.ctx.activityLog.slice(-activityCount),
      access_summary: {
        compromised_hosts: compromised,
        valid_credentials: validCreds,
        current_access_level: this.computeAccessLevel(compromised)
      },
      warnings: summarizeHealthReport(healthReport),
      lab_readiness: labReadiness,
      scope_suggestions: this.collectScopeSuggestions(),
    };
  }

  private computeAccessLevel(compromised: string[]): string {
    if (compromised.length === 0) return 'none';
    const scopeDomains = this.ctx.config.scope.domains.map(d => d.toLowerCase());
    // Check for DA — credential must be actually obtained, not just discovered,
    // AND must be a domain credential matching a scope domain.
    const hasDa = this.getNodesByType('credential').some(c => {
      if (c.privileged !== true || c.confidence < 0.9 || !isCredentialUsableForAuth(c)) return false;
      // Must be a domain credential matching a scope domain
      if (!c.cred_domain || !scopeDomains.includes(c.cred_domain.toLowerCase())) return false;
      // Must have an OWNS_CRED inbound edge or explicit obtained flag
      if (c.obtained === true) return true;
      return this.ctx.graph.inEdges(c.id).some((e: string) => {
        const ep = this.ctx.graph.getEdgeAttributes(e);
        return ep.type === 'OWNS_CRED' && ep.confidence >= 0.9;
      });
    });
    if (hasDa) return 'domain_admin';
    // Check for local admin
    const hasAdmin = !!this.ctx.graph.findEdge((_, attrs) =>
      attrs.type === 'ADMIN_TO' && attrs.confidence >= 0.9
    );
    if (hasAdmin) return 'local_admin';
    return 'user';
  }

  // =============================================
  // Scope Management
  // =============================================

  updateScope(changes: {
    add_cidrs?: string[];
    remove_cidrs?: string[];
    add_domains?: string[];
    remove_domains?: string[];
    add_exclusions?: string[];
    remove_exclusions?: string[];
    reason: string;
  }): { applied: boolean; errors: string[]; before: EngagementConfig['scope']; after: EngagementConfig['scope']; affected_node_count: number } {
    const errors: string[] = [];

    // Validate CIDRs
    for (const cidr of changes.add_cidrs || []) {
      if (!isValidCidr(cidr)) errors.push(`Invalid CIDR: ${cidr}`);
    }
    for (const cidr of changes.remove_cidrs || []) {
      if (!isValidCidr(cidr)) errors.push(`Invalid CIDR to remove: ${cidr}`);
    }
    for (const cidr of changes.add_exclusions || []) {
      if (!isValidCidr(cidr)) errors.push(`Invalid exclusion: ${cidr}`);
    }
    for (const cidr of changes.remove_exclusions || []) {
      if (!isValidCidr(cidr)) errors.push(`Invalid exclusion to remove: ${cidr}`);
    }

    if (errors.length > 0) {
      return { applied: false, errors, before: { ...this.ctx.config.scope }, after: { ...this.ctx.config.scope }, affected_node_count: 0 };
    }

    const before = {
      cidrs: [...this.ctx.config.scope.cidrs],
      domains: [...this.ctx.config.scope.domains],
      exclusions: [...this.ctx.config.scope.exclusions],
    };

    // Apply mutations
    if (changes.add_cidrs) {
      for (const cidr of changes.add_cidrs) {
        if (!this.ctx.config.scope.cidrs.includes(cidr)) {
          this.ctx.config.scope.cidrs.push(cidr);
        }
      }
    }
    if (changes.remove_cidrs) {
      this.ctx.config.scope.cidrs = this.ctx.config.scope.cidrs.filter(c => !changes.remove_cidrs!.includes(c));
    }
    if (changes.add_domains) {
      for (const domain of changes.add_domains) {
        if (!this.ctx.config.scope.domains.includes(domain)) {
          this.ctx.config.scope.domains.push(domain);
        }
      }
    }
    if (changes.remove_domains) {
      this.ctx.config.scope.domains = this.ctx.config.scope.domains.filter(d => !changes.remove_domains!.includes(d));
    }
    if (changes.add_exclusions) {
      for (const excl of changes.add_exclusions) {
        if (!this.ctx.config.scope.exclusions.includes(excl)) {
          this.ctx.config.scope.exclusions.push(excl);
        }
      }
    }
    if (changes.remove_exclusions) {
      this.ctx.config.scope.exclusions = this.ctx.config.scope.exclusions.filter(e => !changes.remove_exclusions!.includes(e));
    }

    const after = {
      cidrs: [...this.ctx.config.scope.cidrs],
      domains: [...this.ctx.config.scope.domains],
      exclusions: [...this.ctx.config.scope.exclusions],
    };

    // Count nodes now in scope that were previously out of scope
    let affectedNodeCount = 0;
    this.ctx.graph.forEachNode((id, attrs) => {
      if (attrs.type !== 'host') return;
      const ip = attrs.ip;
      if (!ip) return;
      const wasInScope = isIpInScope(ip, before.cidrs, before.exclusions);
      const nowInScope = isIpInScope(ip, after.cidrs, after.exclusions);
      if (!wasInScope && nowInScope) affectedNodeCount++;
    });

    // Invalidate caches
    this.invalidateFrontierCache();
    this.invalidateHealthReport();

    // Log the scope change
    this.logActionEvent({
      description: `Scope updated: ${changes.reason}`,
      event_type: 'scope_updated',
      category: 'system',
      result_classification: 'success',
      details: {
        reason: changes.reason,
        before,
        after,
        affected_node_count: affectedNodeCount,
      },
    });

    this.persist();

    return { applied: true, errors: [], before, after, affected_node_count: affectedNodeCount };
  }

  collectScopeSuggestions(): ScopeSuggestion[] {
    const outOfScopeIps = new Map<string, { ips: Set<string>; nodeIds: Set<string>; firstSeen: string; sources: Set<string> }>();

    this.ctx.graph.forEachNode((id, attrs) => {
      if (attrs.type !== 'host' || !attrs.ip) return;
      if (isIpInScope(attrs.ip, this.ctx.config.scope.cidrs, this.ctx.config.scope.exclusions)) return;

      const parts = attrs.ip.split('.');
      if (parts.length !== 4) return;
      const prefix = `${parts[0]}.${parts[1]}.${parts[2]}`;
      const suggestedCidr = `${prefix}.0/24`;

      if (!outOfScopeIps.has(suggestedCidr)) {
        outOfScopeIps.set(suggestedCidr, { ips: new Set(), nodeIds: new Set(), firstSeen: attrs.discovered_at, sources: new Set() });
      }
      const entry = outOfScopeIps.get(suggestedCidr)!;
      entry.ips.add(attrs.ip);
      entry.nodeIds.add(id);
      if (attrs.discovered_at < entry.firstSeen) entry.firstSeen = attrs.discovered_at;
      if (attrs.discovered_by) entry.sources.add(attrs.discovered_by);
    });

    return Array.from(outOfScopeIps.entries()).map(([cidr, data]) => ({
      suggested_cidr: cidr,
      out_of_scope_ips: Array.from(data.ips).sort(),
      node_ids: Array.from(data.nodeIds),
      first_seen_at: data.firstSeen,
      source_descriptions: Array.from(data.sources),
    }));
  }

  previewScopeChange(changes: {
    add_cidrs?: string[];
    remove_cidrs?: string[];
    add_domains?: string[];
    remove_domains?: string[];
    add_exclusions?: string[];
    remove_exclusions?: string[];
  }): { before: EngagementConfig['scope']; after: EngagementConfig['scope']; nodes_entering_scope: number; nodes_leaving_scope: number; pending_suggestions_resolved: string[] } {
    const before = {
      cidrs: [...this.ctx.config.scope.cidrs],
      domains: [...this.ctx.config.scope.domains],
      exclusions: [...this.ctx.config.scope.exclusions],
    };

    // Compute hypothetical after state
    const afterCidrs = [...before.cidrs];
    for (const cidr of changes.add_cidrs || []) {
      if (!afterCidrs.includes(cidr)) afterCidrs.push(cidr);
    }
    for (const cidr of changes.remove_cidrs || []) {
      const idx = afterCidrs.indexOf(cidr);
      if (idx >= 0) afterCidrs.splice(idx, 1);
    }
    const afterDomains = [...before.domains];
    for (const d of changes.add_domains || []) {
      if (!afterDomains.includes(d)) afterDomains.push(d);
    }
    for (const d of changes.remove_domains || []) {
      const idx = afterDomains.indexOf(d);
      if (idx >= 0) afterDomains.splice(idx, 1);
    }
    const afterExclusions = [...before.exclusions];
    for (const e of changes.add_exclusions || []) {
      if (!afterExclusions.includes(e)) afterExclusions.push(e);
    }
    for (const e of changes.remove_exclusions || []) {
      const idx = afterExclusions.indexOf(e);
      if (idx >= 0) afterExclusions.splice(idx, 1);
    }

    const after = { cidrs: afterCidrs, domains: afterDomains, exclusions: afterExclusions };

    let entering = 0;
    let leaving = 0;
    this.ctx.graph.forEachNode((_id, attrs) => {
      if (attrs.type !== 'host' || !attrs.ip) return;
      const wasIn = isIpInScope(attrs.ip, before.cidrs, before.exclusions);
      const nowIn = isIpInScope(attrs.ip, after.cidrs, after.exclusions);
      if (!wasIn && nowIn) entering++;
      if (wasIn && !nowIn) leaving++;
    });

    // Check which pending suggestions would be resolved
    const suggestions = this.collectScopeSuggestions();
    const resolved: string[] = [];
    for (const s of suggestions) {
      for (const ip of s.out_of_scope_ips) {
        if (isIpInScope(ip, after.cidrs, after.exclusions)) {
          resolved.push(s.suggested_cidr);
          break;
        }
      }
    }

    return { before, after, nodes_entering_scope: entering, nodes_leaving_scope: leaving, pending_suggestions_resolved: [...new Set(resolved)] };
  }

  // =============================================
  // Persistence (delegated to StatePersistence)
  // =============================================

  persist(detail: GraphUpdateDetail = {}): void {
    this.invalidateHealthReport();
    this.persistence.persist(detail);
  }

  listSnapshots(): string[] {
    return this.persistence.listSnapshots();
  }

  rollbackToSnapshot(snapshotName: string): boolean {
    const ok = this.persistence.rollbackToSnapshot(snapshotName, BUILTIN_RULES);
    if (ok) this.invalidateHealthReport();
    return ok;
  }

  // =============================================
  // Evidence
  // =============================================

  getFullHistory(): ActivityLogEntry[] {
    return [...this.ctx.activityLog];
  }

  getInferenceRules(): InferenceRule[] {
    return [...this.ctx.inferenceRules];
  }

  getConfig(): EngagementConfig {
    return this.ctx.config;
  }

  getAllAgents(): AgentTask[] {
    return Array.from(this.ctx.agents.values());
  }

  getTrackedProcesses(): import('./process-tracker.js').TrackedProcess[] {
    return this.ctx.trackedProcesses;
  }

  getHealthReport(): HealthReport {
    return this.runHealthChecks();
  }

  checkADContext(): boolean {
    return hasADContext(this.ctx.graph);
  }

  getFrontierItem(frontierItemId: string): FrontierItem | null {
    return this.computeFrontier().find(item => item.id === frontierItemId) || null;
  }

  logActionEvent(event: Omit<Partial<ActivityLogEntry>, 'event_id' | 'timestamp'> & { description: string }): ActivityLogEntry {
    return this.ctx.logEvent(event);
  }

  getStateFilePath(): string {
    return this.ctx.stateFilePath;
  }

  setTrackedProcesses(processes: import('./process-tracker.js').TrackedProcess[]): void {
    this.ctx.trackedProcesses = processes;
  }

  exportGraph(): ExportedGraph {
    const nodes: ExportedGraph['nodes'] = [];
    const edges: ExportedGraph['edges'] = [];

    this.ctx.graph.forEachNode((id, attrs) => {
      nodes.push({ id, properties: attrs });
    });

    this.ctx.graph.forEachEdge((edgeId, attrs, source, target) => {
      edges.push({ id: edgeId, source, target, properties: attrs });
    });

    return { nodes, edges };
  }

  private runHealthChecks(): HealthReport {
    if (!this.healthReportCache) {
      this.healthReportCache = runHealthChecks(this.ctx.graph);
    }
    return this.healthReportCache;
  }

  private invalidateHealthReport(): void {
    this.healthReportCache = null;
    this.frontierCache = null;
  }

  private invalidateFrontierCache(): void {
    this.frontierCache = null;
  }

  // =============================================
  // Helpers
  // =============================================

  private syncObjectiveNodes(): void {
    const now = new Date().toISOString();
    for (const objective of this.ctx.config.objectives) {
      const nodeId = `obj-${objective.id}`;
      const existing = this.getNode(nodeId);
      if (!existing) continue;
      this.ctx.graph.mergeNodeAttributes(nodeId, {
        objective_description: objective.description,
        objective_achieved: objective.achieved,
        objective_achieved_at: objective.achieved_at,
        last_seen_at: now,
      } as any);
    }
  }

  private propertiesChanged(oldProps: NodeProperties, newProps: NodeProperties): boolean {
    const ignoreKeys = new Set(['discovered_at', 'discovered_by', 'last_seen_at', 'first_seen_at', 'sources']);
    for (const [key, val] of Object.entries(newProps)) {
      if (ignoreKeys.has(key)) continue;
      if (val !== undefined && val !== null && !this.valuesEqual(oldProps[key], val)) return true;
    }
    return false;
  }

  onUpdate(callback: GraphUpdateCallback): void {
    this.ctx.updateCallbacks.push(callback);
  }

  private resolveFrontierSeeds(frontierItemId: string): string[] {
    if (frontierItemId.startsWith('frontier-discovery-')) {
      return []; // network_discovery items have no backing graph nodes
    }

    if (frontierItemId.startsWith('frontier-node-')) {
      const nodeId = frontierItemId.slice('frontier-node-'.length);
      return this.ctx.graph.hasNode(nodeId) ? [nodeId] : [];
    }

    if (frontierItemId.startsWith('frontier-edge-')) {
      const edgeId = frontierItemId.slice('frontier-edge-'.length);
      if (this.ctx.graph.hasEdge(edgeId)) {
        const seeds = [this.ctx.graph.source(edgeId), this.ctx.graph.target(edgeId)];
        return seeds.filter((id, index) => seeds.indexOf(id) === index);
      }
      return [];
    }

    const frontier = this.computeFrontier();
    const item = frontier.find(f => f.id === frontierItemId);
    if (!item) return [];

    const seeds: string[] = [];
    if (item.node_id && this.ctx.graph.hasNode(item.node_id)) seeds.push(item.node_id);
    if (item.edge_source && this.ctx.graph.hasNode(item.edge_source)) seeds.push(item.edge_source);
    if (item.edge_target && this.ctx.graph.hasNode(item.edge_target)) seeds.push(item.edge_target);
    return seeds;
  }

  private valuesEqual(left: unknown, right: unknown): boolean {
    if (Array.isArray(left) && Array.isArray(right)) {
      if (left.length !== right.length) return false;
      return left.every((value, index) => this.valuesEqual(value, right[index]));
    }

    if (this.isPlainObject(left) && this.isPlainObject(right)) {
      const leftKeys = Object.keys(left);
      const rightKeys = Object.keys(right);
      if (leftKeys.length !== rightKeys.length) return false;
      return leftKeys.every((key) => this.valuesEqual(left[key], right[key]));
    }

    return Object.is(left, right);
  }

  private isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }

  private log(message: string, agentId?: string, extra?: Partial<ActivityLogEntry>): void {
    this.ctx.logEvent({
      description: message,
      agent_id: agentId,
      ...extra,
    });
  }
}
