// ============================================================
// Overwatch — Graph Engine
// Engagement state as a directed property graph
// ============================================================

import GraphConstructor from 'graphology';
import { existsSync } from 'fs';
import { expandCidr, isIpInScope } from './cidr.js';
import { EngineContext } from './engine-context.js';
import type { ActivityLogEntry, GraphUpdateCallback, GraphUpdateDetail, OverwatchGraph } from './engine-context.js';
import { StatePersistence } from './state-persistence.js';
import { AgentManager } from './agent-manager.js';
import { InferenceEngine } from './inference-engine.js';
import { PathAnalyzer } from './path-analyzer.js';
import { FrontierComputer } from './frontier.js';
import { getCredentialDisplayKind, isCredentialUsableForAuth } from './credential-utils.js';
import { runHealthChecks, summarizeHealthReport } from './graph-health.js';
import { summarizeInlineLabReadiness } from './lab-preflight.js';
import { getNodeFirstSeenAt, getNodeSources, normalizeNodeProvenance } from './provenance-utils.js';
import type {
  NodeProperties, EdgeProperties, NodeType, EdgeType,
  EngagementConfig, EngagementState, FrontierItem,
  Finding, InferenceRule, GraphQuery, GraphQueryResult,
  AgentTask, ExportedGraph, HealthReport
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
    description: 'Host running Kerberos (port 88) is likely a domain controller',
    trigger: { node_type: 'service', property_match: { service_name: 'kerberos' } },
    produces: [{
      edge_type: 'MEMBER_OF_DOMAIN',
      source_selector: 'parent_host',
      target_selector: 'domain_nodes',
      confidence: 0.9
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
    description: 'When a new credential is found, create POTENTIAL_AUTH edges to all services accepting that cred type',
    trigger: { node_type: 'credential' },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'trigger_node',
      target_selector: 'compatible_services',
      confidence: 0.6
    }]
  },
  {
    id: 'rule-adcs-esc1',
    name: 'ADCS enrollment + subject supply = ESC1 candidate',
    description: 'Certificate template allowing enrollee-supplied subject name',
    trigger: { node_type: 'certificate', property_match: { enrollee_supplies_subject: true } },
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
  }

  // =============================================
  // Initialization
  // =============================================

  private seedFromConfig(): void {
    const now = new Date().toISOString();

    // Create host nodes from CIDRs
    for (const cidr of this.ctx.config.scope.cidrs) {
      const ips = expandCidr(cidr);
      for (const ip of ips) {
        this.addNode({
          id: `host-${ip.replace(/\./g, '-')}`,
          type: 'host',
          label: ip,
          ip,
          discovered_at: now,
          first_seen_at: now,
          last_seen_at: now,
          confidence: 1.0
        });
      }
    }

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
        objective_achieved: false,
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
        return { id: edgeId, isNew: false };
      }
    }
    // New edge
    this.invalidatePathGraph();
    const edgeId = `${source}--${props.type}--${target}`;
    try {
      return { id: this.ctx.graph.addEdgeWithKey(edgeId, source, target, props), isNew: true };
    } catch {
      // Edge key might already exist for a different source/target pair
      const fallbackId = `${edgeId}-${Date.now()}`;
      return { id: this.ctx.graph.addEdgeWithKey(fallbackId, source, target, props), isNew: true };
    }
  }

  getNode(id: string): NodeProperties | null {
    if (!this.ctx.graph.hasNode(id)) return null;
    return this.ctx.graph.getNodeAttributes(id);
  }

  getNodesByType(type: NodeType): NodeProperties[] {
    const results: NodeProperties[] = [];
    this.ctx.graph.forEachNode((id, attrs) => {
      if (attrs.type === type) {
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
    for (const node of finding.nodes) {
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
        } else if (!existingNode?.confirmed_at && (existingNode?.confidence ?? 0) < 1.0) {
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
    }

    // Add/update edges
    for (const edge of finding.edges) {
      if (!this.ctx.graph.hasNode(edge.source) || !this.ctx.graph.hasNode(edge.target)) continue;
      const fullProps: EdgeProperties = {
        discovered_at: finding.timestamp,
        confidence: 1.0,
        ...edge.properties,
        discovered_by: finding.agent_id
      };
      const { id: edgeId, isNew } = this.addEdge(edge.source, edge.target, fullProps);
      if (isNew) {
        newEdges.push(edgeId);
        this.log(`New edge: ${edge.source} --[${edge.properties.type}]--> ${edge.target}`, finding.agent_id, { category: 'finding', outcome: 'success' });
      } else {
        updatedEdges.push(edgeId);
        this.log(`Updated edge: ${edge.source} --[${edge.properties.type}]--> ${edge.target}`, finding.agent_id, { category: 'finding', outcome: 'neutral' });
      }
    }

    // Run inference rules against new and updated nodes
    for (const nodeId of [...newNodes, ...updatedNodes]) {
      const inferred = this.runInferenceRules(nodeId);
      inferredEdges.push(...inferred);
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
    this.persist(result);

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

  // =============================================
  // Frontier Computation (delegated to FrontierComputer)
  // =============================================

  computeFrontier(): FrontierItem[] {
    return this.frontierComputer.compute();
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
          if (node) {
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

  private isNodeExcluded(nodeId: string): string | null {
    const ip = this.resolveHostIp(nodeId);
    if (ip && this.isExcluded(ip)) return ip;
    return null;
  }

  // =============================================
  // Validation (Layer 3 — post-LLM sanity check)
  // =============================================

  validateAction(action: { target_node?: string; edge_source?: string; edge_target?: string; technique?: string }): {
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

    // Time window check
    if (this.ctx.config.opsec.time_window) {
      const hour = new Date().getHours();
      const { start_hour, end_hour } = this.ctx.config.opsec.time_window;
      if (hour < start_hour || hour > end_hour) {
        warnings.push(`Outside approved time window (${start_hour}:00-${end_hour}:00), current hour: ${hour}`);
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  // =============================================
  // Objective Tracking
  // =============================================

  private evaluateObjectives(): void {
    const ACCESS_EDGE_TYPES = new Set(['HAS_SESSION', 'ADMIN_TO', 'OWNS_CRED']);

    for (const obj of this.ctx.config.objectives) {
      if (obj.achieved) continue;
      // Check if objective criteria are met in the graph
      if (obj.target_criteria) {
        const matching = this.queryGraph({
          node_type: obj.target_node_type,
          node_filter: obj.target_criteria
        });
        // A matching node must also be obtained — either via an access edge
        // (HAS_SESSION, ADMIN_TO, OWNS_CRED) or an explicit obtained flag.
        const obtained = matching.nodes.some(n => {
          const nodeProps = n.properties;
          if (nodeProps.type === 'credential' && !isCredentialUsableForAuth(nodeProps)) {
            return false;
          }
          if (n.properties.obtained === true) return true;
          return this.ctx.graph.inEdges(n.id).some((e: string) => {
            const ep = this.ctx.graph.getEdgeAttributes(e);
            if (ep.type !== 'OWNS_CRED') {
              return ACCESS_EDGE_TYPES.has(ep.type) && ep.confidence >= 0.9;
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
  }

  // =============================================
  // Agent Management (delegated to AgentManager)
  // =============================================

  registerAgent(task: AgentTask): void {
    this.agentMgr.register(task);
    this.persist();
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

  getState(): EngagementState {
    const nodesByType: Record<string, number> = {};
    const edgesByType: Record<string, number> = {};
    let confirmedEdges = 0;
    let inferredEdges = 0;

    this.ctx.graph.forEachNode((_, attrs) => {
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

    const frontier = this.computeFrontier();
    const { passed } = this.filterFrontier(frontier);
    const healthReport = this.runHealthChecks();
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
      frontier: passed,
      active_agents: Array.from(this.ctx.agents.values()).filter(a => a.status === 'running'),
      recent_activity: this.ctx.activityLog.slice(-20),
      access_summary: {
        compromised_hosts: compromised,
        valid_credentials: validCreds,
        current_access_level: this.computeAccessLevel(compromised)
      },
      warnings: summarizeHealthReport(healthReport),
      lab_readiness: labReadiness,
    };
  }

  private computeAccessLevel(compromised: string[]): string {
    if (compromised.length === 0) return 'none';
    // Check for DA — credential must be actually obtained, not just discovered
    const hasDa = this.getNodesByType('credential').some(c => {
      if (c.privileged !== true || c.confidence < 0.9 || !isCredentialUsableForAuth(c)) return false;
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
  // Persistence (delegated to StatePersistence)
  // =============================================

  persist(detail: GraphUpdateDetail = {}): void {
    this.persistence.persist(detail);
  }

  listSnapshots(): string[] {
    return this.persistence.listSnapshots();
  }

  rollbackToSnapshot(snapshotName: string): boolean {
    return this.persistence.rollbackToSnapshot(snapshotName, BUILTIN_RULES);
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
    return runHealthChecks(this.ctx.graph);
  }

  // =============================================
  // Helpers
  // =============================================

  private propertiesChanged(oldProps: NodeProperties, newProps: NodeProperties): boolean {
    const ignoreKeys = new Set(['discovered_at', 'discovered_by']);
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
