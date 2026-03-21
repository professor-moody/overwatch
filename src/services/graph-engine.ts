// ============================================================
// Overwatch — Graph Engine
// Engagement state as a directed property graph
// ============================================================

import GraphConstructor from 'graphology';
import { dijkstra } from 'graphology-shortest-path';
import { v4 as uuidv4 } from 'uuid';
import { readFileSync, writeFileSync, existsSync, renameSync, unlinkSync, readdirSync } from 'fs';
import { dirname, basename, join } from 'path';
import { expandCidr, isIpInScope } from './cidr.js';
import type {
  NodeProperties, EdgeProperties, NodeType, EdgeType,
  EngagementConfig, EngagementState, FrontierItem,
  Finding, InferenceRule, GraphQuery, GraphQueryResult,
  AgentTask, EngagementObjective
} from '../types.js';

// Handle CJS/ESM interop for graphology — graphology publishes CJS with a
// default export that doesn't unwrap cleanly under Node16 module resolution.
// This pattern safely handles both CJS (.default) and native ESM imports.
const Graph = (GraphConstructor as any).default || GraphConstructor;
if (typeof Graph !== 'function') {
  throw new Error('Failed to import graphology Graph constructor — check CJS/ESM interop');
}

// --- Fan-out estimates by service type ---
const FAN_OUT_ESTIMATES: Record<string, number> = {
  kerberos: 50,
  ldap: 40,
  smb: 15,
  http: 10,
  https: 10,
  mssql: 8,
  rdp: 3,
  ssh: 3,
  snmp: 5,
  winrm: 4,
  default: 5
};

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

export class GraphEngine {
  private graph: any;  // graphology Graph instance
  private config: EngagementConfig;
  private inferenceRules: InferenceRule[];
  private activityLog: Array<{ timestamp: string; description: string; agent_id?: string }>;
  private agents: Map<string, AgentTask>;
  private stateFilePath: string;

  constructor(config: EngagementConfig, stateFilePath?: string) {
    this.graph = new Graph({ type: 'directed', multi: true, allowSelfLoops: false });
    this.config = config;
    this.inferenceRules = [...BUILTIN_RULES];
    this.activityLog = [];
    this.agents = new Map();
    this.stateFilePath = stateFilePath || `./state-${config.id}.json`;

    // Attempt to load existing state
    if (existsSync(this.stateFilePath)) {
      this.loadState();
      this.log('Resumed engagement from persisted state');
    } else {
      this.seedFromConfig();
      this.log('Engagement initialized from config');
    }
  }

  // =============================================
  // Initialization
  // =============================================

  private seedFromConfig(): void {
    const now = new Date().toISOString();

    // Create host nodes from CIDRs
    for (const cidr of this.config.scope.cidrs) {
      const ips = expandCidr(cidr);
      for (const ip of ips) {
        this.addNode({
          id: `host-${ip.replace(/\./g, '-')}`,
          type: 'host',
          label: ip,
          ip,
          discovered_at: now,
          confidence: 1.0
        });
      }
    }

    // Create host nodes from explicit hosts
    if (this.config.scope.hosts) {
      for (const host of this.config.scope.hosts) {
        const id = `host-${host.replace(/[.\s]/g, '-')}`;
        if (!this.graph.hasNode(id)) {
          this.addNode({
            id,
            type: 'host',
            label: host,
            hostname: host,
            discovered_at: now,
            confidence: 1.0
          });
        }
      }
    }

    // Create domain nodes
    for (const domain of this.config.scope.domains) {
      this.addNode({
        id: `domain-${domain.replace(/\./g, '-')}`,
        type: 'domain',
        label: domain,
        domain_name: domain,
        discovered_at: now,
        confidence: 1.0
      });
    }

    // Create objective nodes
    for (const obj of this.config.objectives) {
      this.addNode({
        id: `obj-${obj.id}`,
        type: 'objective',
        label: obj.description,
        objective_description: obj.description,
        objective_achieved: false,
        discovered_at: now,
        confidence: 1.0
      });
    }

    this.persist();
  }

  // =============================================
  // Node / Edge Operations
  // =============================================

  addNode(props: NodeProperties): string {
    if (this.graph.hasNode(props.id)) {
      // Merge properties
      this.graph.mergeNodeAttributes(props.id, props);
    } else {
      this.graph.addNode(props.id, props);
    }
    return props.id;
  }

  addEdge(source: string, target: string, props: EdgeProperties): string {
    // Check for duplicate edge of same type
    const existingEdges = this.graph.edges(source, target);
    for (const edgeId of existingEdges) {
      const attrs = this.graph.getEdgeAttributes(edgeId) as EdgeProperties;
      if (attrs.type === props.type) {
        // Update existing edge
        this.graph.mergeEdgeAttributes(edgeId, props);
        return edgeId;
      }
    }
    // New edge
    const edgeId = `${source}--${props.type}--${target}`;
    try {
      return this.graph.addEdgeWithKey(edgeId, source, target, props);
    } catch {
      // Edge key might already exist for a different source/target pair
      const fallbackId = `${edgeId}-${Date.now()}`;
      return this.graph.addEdgeWithKey(fallbackId, source, target, props);
    }
  }

  getNode(id: string): NodeProperties | null {
    if (!this.graph.hasNode(id)) return null;
    return this.graph.getNodeAttributes(id) as NodeProperties;
  }

  getNodesByType(type: NodeType): NodeProperties[] {
    const results: NodeProperties[] = [];
    this.graph.forEachNode((id, attrs) => {
      if ((attrs as NodeProperties).type === type) {
        results.push(attrs as NodeProperties);
      }
    });
    return results;
  }

  // =============================================
  // Finding Ingestion
  // =============================================

  ingestFinding(finding: Finding): { new_nodes: string[]; new_edges: string[]; inferred_edges: string[] } {
    const newNodes: string[] = [];
    const newEdges: string[] = [];
    const inferredEdges: string[] = [];

    // Add/update nodes — track both new and updated for inference
    const updatedNodes: string[] = [];
    for (const node of finding.nodes) {
      const isNew = !this.graph.hasNode(node.id);
      const existingNode = isNew ? null : this.getNode(node.id);
      const oldProps = existingNode ? { ...existingNode } : null;
      const fullProps: NodeProperties = {
        discovered_at: finding.timestamp,
        confidence: 1.0,
        label: node.id,
        ...node,
        discovered_by: finding.agent_id
      };
      this.addNode(fullProps);
      if (isNew) {
        newNodes.push(node.id);
        this.log(`New ${node.type} discovered: ${fullProps.label}`, finding.agent_id);
      } else if (oldProps && this.propertiesChanged(oldProps, fullProps)) {
        updatedNodes.push(node.id);
        this.log(`Updated ${node.type}: ${fullProps.label}`, finding.agent_id);
      }
    }

    // Add/update edges
    for (const edge of finding.edges) {
      if (!this.graph.hasNode(edge.source) || !this.graph.hasNode(edge.target)) continue;
      const fullProps: EdgeProperties = {
        discovered_at: finding.timestamp,
        confidence: 1.0,
        ...edge.properties,
        discovered_by: finding.agent_id
      };
      const edgeId = this.addEdge(edge.source, edge.target, fullProps);
      newEdges.push(edgeId);
      this.log(`New edge: ${edge.source} --[${edge.properties.type}]--> ${edge.target}`, finding.agent_id);
    }

    // Run inference rules against new and updated nodes
    for (const nodeId of [...newNodes, ...updatedNodes]) {
      const inferred = this.runInferenceRules(nodeId);
      inferredEdges.push(...inferred);
    }

    // Check objectives
    this.evaluateObjectives();

    // Persist
    this.persist();

    return { new_nodes: newNodes, new_edges: newEdges, inferred_edges: inferredEdges };
  }

  // =============================================
  // Inference Engine
  // =============================================

  addInferenceRule(rule: InferenceRule): void {
    // Don't add duplicates
    if (this.inferenceRules.some(r => r.id === rule.id)) return;
    this.inferenceRules.push(rule);
    this.log(`Custom inference rule added: ${rule.name}`);
    this.persist();
  }

  backfillRule(rule: InferenceRule): string[] {
    const inferred: string[] = [];
    this.graph.forEachNode((nodeId: string, attrs: any) => {
      const node = attrs as NodeProperties;
      // Check trigger match
      if (rule.trigger.node_type && node.type !== rule.trigger.node_type) return;
      if (rule.trigger.property_match) {
        const matches = Object.entries(rule.trigger.property_match).every(
          ([key, val]) => node[key] === val
        );
        if (!matches) return;
      }
      inferred.push(...this.runInferenceRulesForRule(rule, nodeId));
    });
    if (inferred.length > 0) this.persist();
    return inferred;
  }

  private runInferenceRulesForRule(rule: InferenceRule, triggerNodeId: string): string[] {
    const inferred: string[] = [];
    const now = new Date().toISOString();
    for (const production of rule.produces) {
      const sources = this.resolveSelector(production.source_selector, triggerNodeId);
      const targets = this.resolveSelector(production.target_selector, triggerNodeId);
      for (const src of sources) {
        for (const tgt of targets) {
          if (src === tgt) continue;
          if (!this.graph.hasNode(src) || !this.graph.hasNode(tgt)) continue;
          const existing = this.graph.edges(src, tgt);
          const alreadyExists = existing.some((e: string) => {
            const attrs = this.graph.getEdgeAttributes(e) as EdgeProperties;
            return attrs.type === production.edge_type;
          });
          if (alreadyExists) continue;
          const edgeId = this.addEdge(src, tgt, {
            type: production.edge_type,
            confidence: production.confidence,
            discovered_at: now,
            discovered_by: `inference:${rule.id}`,
            tested: false,
            ...production.properties as Record<string, unknown>
          });
          inferred.push(edgeId);
          this.log(`Inferred edge [${rule.name}]: ${src} --[${production.edge_type}]--> ${tgt}`);
        }
      }
    }
    return inferred;
  }

  private runInferenceRules(triggerNodeId: string): string[] {
    const node = this.getNode(triggerNodeId);
    if (!node) return [];

    const inferred: string[] = [];
    const now = new Date().toISOString();

    for (const rule of this.inferenceRules) {
      // Check if trigger matches
      if (rule.trigger.node_type && node.type !== rule.trigger.node_type) continue;

      if (rule.trigger.property_match) {
        const matches = Object.entries(rule.trigger.property_match).every(
          ([key, val]) => node[key] === val
        );
        if (!matches) continue;
      }

      // Rule matched — produce edges
      for (const production of rule.produces) {
        const sources = this.resolveSelector(production.source_selector, triggerNodeId);
        const targets = this.resolveSelector(production.target_selector, triggerNodeId);

        for (const src of sources) {
          for (const tgt of targets) {
            if (src === tgt) continue;
            if (!this.graph.hasNode(src) || !this.graph.hasNode(tgt)) continue;

            // Don't create duplicate inferred edges
            const existing = this.graph.edges(src, tgt);
            const alreadyExists = existing.some(e => {
              const attrs = this.graph.getEdgeAttributes(e) as EdgeProperties;
              return attrs.type === production.edge_type;
            });
            if (alreadyExists) continue;

            const edgeId = this.addEdge(src, tgt, {
              type: production.edge_type,
              confidence: production.confidence,
              discovered_at: now,
              discovered_by: `inference:${rule.id}`,
              tested: false,
              ...production.properties as Record<string, unknown>
            });

            inferred.push(edgeId);
            this.log(`Inferred edge [${rule.name}]: ${src} --[${production.edge_type}]--> ${tgt}`);
          }
        }
      }
    }

    return inferred;
  }

  private resolveSelector(selector: string, triggerNodeId: string): string[] {
    const node = this.getNode(triggerNodeId);
    if (!node) return [];

    switch (selector) {
      case 'trigger_node':
      case 'trigger_service':
        return [triggerNodeId];

      case 'parent_host': {
        // Find host that runs this service
        const hosts: string[] = [];
        this.graph.forEachInEdge(triggerNodeId, (edge, attrs, src) => {
          if ((attrs as EdgeProperties).type === 'RUNS') hosts.push(src);
        });
        // Also check if trigger IS a host
        if (node.type === 'host') hosts.push(triggerNodeId);
        return hosts.length > 0 ? hosts : [triggerNodeId];
      }

      case 'domain_nodes':
        return this.getNodesByType('domain').map(n => n.id);

      case 'domain_users':
        return this.getNodesByType('user').filter(u => u.domain_joined !== false).map(n => n.id);

      case 'domain_credentials':
        return this.getNodesByType('credential')
          .filter(c => c.cred_type === 'ntlm' || c.cred_type === 'kerberos_tgt' || c.cred_type === 'aes256')
          .map(n => n.id);

      case 'all_compromised': {
        // Hosts where we have a session or admin access
        const compromised: Set<string> = new Set();
        this.graph.forEachEdge((edge, attrs) => {
          const ep = attrs as EdgeProperties;
          if ((ep.type === 'HAS_SESSION' || ep.type === 'ADMIN_TO') && ep.confidence >= 0.9) {
            compromised.add(this.graph.target(edge));
          }
        });
        return Array.from(compromised);
      }

      case 'compatible_services': {
        // All services that might accept this credential type
        return this.getNodesByType('service')
          .filter(s => {
            if (!node.cred_type) return false;
            if (node.cred_type === 'ntlm' || node.cred_type === 'kerberos_tgt' || node.cred_type === 'aes256') {
              return ['smb', 'ldap', 'mssql', 'winrm', 'rdp', 'http', 'https'].includes(s.service_name || '');
            }
            if (node.cred_type === 'plaintext') return true;
            if (node.cred_type === 'ssh_key') return s.service_name === 'ssh';
            return false;
          })
          .map(n => n.id);
      }

      case 'enrollable_users':
        return this.getNodesByType('user').map(n => n.id);

      default:
        return [];
    }
  }

  // =============================================
  // Frontier Computation
  // =============================================

  computeFrontier(): FrontierItem[] {
    const frontier: FrontierItem[] = [];
    const now = Date.now();

    // 1. Incomplete nodes (missing key properties)
    this.graph.forEachNode((id, attrs) => {
      const node = attrs as NodeProperties;
      const missing = this.getMissingProperties(node);
      if (missing.length === 0) return;

      frontier.push({
        id: `frontier-node-${id}`,
        type: 'incomplete_node',
        node_id: id,
        missing_properties: missing,
        description: `${node.type} "${node.label}" missing: ${missing.join(', ')}`,
        graph_metrics: {
          hops_to_objective: this.hopsToNearestObjective(id),
          fan_out_estimate: this.estimateFanOut(node),
          node_degree: this.graph.degree(id),
          confidence: node.confidence
        },
        opsec_noise: this.estimateNoiseForNode(node, missing),
        staleness_seconds: (now - new Date(node.discovered_at).getTime()) / 1000
      });
    });

    // 2. Untested inferred edges
    this.graph.forEachEdge((edgeId, attrs, source, target) => {
      const edge = attrs as EdgeProperties;
      if (edge.tested) return;
      if (edge.confidence >= 1.0) return; // confirmed edges aren't frontier

      frontier.push({
        id: `frontier-edge-${edgeId}`,
        type: 'inferred_edge',
        edge_source: source,
        edge_target: target,
        edge_type: edge.type,
        description: `Test ${edge.type}: ${source} → ${target} (confidence: ${edge.confidence})`,
        graph_metrics: {
          hops_to_objective: this.hopsToNearestObjective(target),
          fan_out_estimate: 2,
          node_degree: this.graph.degree(target),
          confidence: edge.confidence
        },
        opsec_noise: edge.opsec_noise || 0.3,
        staleness_seconds: (now - new Date(edge.discovered_at).getTime()) / 1000
      });
    });

    return frontier;
  }

  private getMissingProperties(node: NodeProperties): string[] {
    const missing: string[] = [];
    switch (node.type) {
      case 'host':
        if (node.alive === undefined) missing.push('alive');
        else if (node.alive) {
          if (!node.os) missing.push('os');
          // Services missing is captured by lack of RUNS edges
          const hasServices = this.graph.outEdges(node.id).some(e =>
            (this.graph.getEdgeAttributes(e) as EdgeProperties).type === 'RUNS'
          );
          if (!hasServices) missing.push('services');
        }
        break;
      case 'service':
        if (!node.version) missing.push('version');
        break;
      case 'user':
        if (node.privileged === undefined) missing.push('privilege_level');
        break;
      case 'domain':
        if (!node.functional_level) missing.push('functional_level');
        break;
    }
    return missing;
  }

  private estimateFanOut(node: NodeProperties): number {
    if (node.type === 'host') {
      // DC-like hosts have high fan-out
      const services = this.graph.outEdges(node.id)
        .map(e => this.graph.getEdgeAttributes(e) as EdgeProperties)
        .filter(e => e.type === 'RUNS');
      if (services.length === 0) return 10; // unknown, moderate estimate
      return services.length * 5;
    }
    if (node.type === 'service') {
      return FAN_OUT_ESTIMATES[node.service_name || 'default'] || FAN_OUT_ESTIMATES['default'];
    }
    if (node.type === 'credential') return 15; // creds fan out to many services
    return FAN_OUT_ESTIMATES['default'];
  }

  private estimateNoiseForNode(node: NodeProperties, missing: string[]): number {
    if (missing.includes('alive')) return 0.2;  // ping sweep is quiet
    if (missing.includes('services')) return 0.5; // port scan is moderate
    if (missing.includes('version')) return 0.3;  // banner grab is moderate
    return 0.3;
  }

  // =============================================
  // Path Analysis
  // =============================================

  hopsToNearestObjective(fromNodeId: string): number | null {
    if (!this.graph.hasNode(fromNodeId)) return null;

    // Resolve unachieved objectives to real graph nodes via their criteria
    const targetNodeIds = this.resolveObjectiveTargets();
    if (targetNodeIds.length === 0) return null;

    let minHops: number | null = null;

    for (const targetId of targetNodeIds) {
      if (targetId === fromNodeId) return 0;
      try {
        const path = dijkstra.bidirectional(this.graph, fromNodeId, targetId);
        if (path && (minHops === null || path.length - 1 < minHops)) {
          minHops = path.length - 1;
        }
      } catch (err) {
        this.log(`Path analysis error (${fromNodeId} → ${targetId}): ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    return minHops;
  }

  findPathsToObjective(objectiveId: string, maxPaths: number = 5): Array<{ nodes: string[]; total_confidence: number }> {
    const paths: Array<{ nodes: string[]; total_confidence: number }> = [];

    // Resolve objective criteria to real graph nodes
    const obj = this.config.objectives.find(o => o.id === objectiveId);
    const targetNodeIds = obj?.target_criteria
      ? this.queryGraph({ node_type: obj.target_node_type, node_filter: obj.target_criteria }).nodes.map(n => n.id)
      : [];

    if (targetNodeIds.length === 0) return paths;

    // Find all compromised hosts as potential starting points
    const startNodes: string[] = [];
    this.graph.forEachNode((id, attrs) => {
      const node = attrs as NodeProperties;
      if (node.type === 'host') {
        const hasAccess = this.graph.edges(id).some(e => {
          const ep = this.graph.getEdgeAttributes(e) as EdgeProperties;
          return (ep.type === 'HAS_SESSION' || ep.type === 'ADMIN_TO') && ep.confidence >= 0.9;
        });
        if (hasAccess) startNodes.push(id);
      }
    });

    for (const start of startNodes) {
      for (const targetId of targetNodeIds) {
        try {
          const path = dijkstra.bidirectional(this.graph, start, targetId);
          if (path) {
            paths.push({ nodes: path, total_confidence: this.computePathConfidence(path) });
          }
        } catch (err) {
          this.log(`Path analysis error (${start} → ${targetId}): ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }

    return paths
      .sort((a, b) => b.total_confidence - a.total_confidence)
      .slice(0, maxPaths);
  }

  private resolveObjectiveTargets(): string[] {
    const targetIds = new Set<string>();
    for (const obj of this.config.objectives) {
      if (obj.achieved) continue;
      if (obj.target_criteria) {
        const matching = this.queryGraph({
          node_type: obj.target_node_type,
          node_filter: obj.target_criteria,
        });
        for (const n of matching.nodes) targetIds.add(n.id);
      }
    }
    return Array.from(targetIds);
  }

  findPaths(fromNode: string, toNode: string, maxPaths: number = 5): Array<{ nodes: string[]; total_confidence: number }> {
    if (!this.graph.hasNode(fromNode) || !this.graph.hasNode(toNode)) return [];

    const paths: Array<{ nodes: string[]; total_confidence: number }> = [];
    try {
      const path = dijkstra.bidirectional(this.graph, fromNode, toNode);
      if (path) {
        paths.push({ nodes: path, total_confidence: this.computePathConfidence(path) });
      }
    } catch (err) {
      this.log(`Path analysis error (${fromNode} → ${toNode}): ${err instanceof Error ? err.message : String(err)}`);
    }

    return paths.slice(0, maxPaths);
  }

  private computePathConfidence(path: string[]): number {
    let totalConfidence = 1.0;
    for (let i = 0; i < path.length - 1; i++) {
      const edges = this.graph.edges(path[i], path[i + 1]);
      if (edges.length === 0) {
        // Check reverse direction for undirected traversal
        const reverseEdges = this.graph.edges(path[i + 1], path[i]);
        if (reverseEdges.length === 0) { totalConfidence *= 0.1; continue; }
        const bestConfidence = Math.max(
          ...reverseEdges.map(e => (this.graph.getEdgeAttributes(e) as EdgeProperties).confidence)
        );
        totalConfidence *= bestConfidence;
      } else {
        const bestConfidence = Math.max(
          ...edges.map(e => (this.graph.getEdgeAttributes(e) as EdgeProperties).confidence)
        );
        totalConfidence *= bestConfidence;
      }
    }
    return totalConfidence;
  }

  // =============================================
  // Graph Queries (full access for LLM)
  // =============================================

  queryGraph(query: GraphQuery): GraphQueryResult {
    const result: GraphQueryResult = { nodes: [], edges: [] };
    const limit = query.limit || 100;

    // Node queries
    if (query.node_type || query.node_filter || query.from_node) {
      if (query.from_node && this.graph.hasNode(query.from_node)) {
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
              ? this.graph.inNeighbors(current.id)
              : query.direction === 'outbound'
                ? this.graph.outNeighbors(current.id)
                : this.graph.neighbors(current.id);

            for (const neighbor of neighbors) {
              if (!visited.has(neighbor)) {
                queue.push({ id: neighbor, depth: current.depth + 1 });
              }
            }
          }
        }

        // Also include edges between found nodes
        const nodeIds = new Set(result.nodes.map(n => n.id));
        this.graph.forEachEdge((edgeId, attrs, source, target) => {
          if (nodeIds.has(source) && nodeIds.has(target)) {
            const ep = attrs as EdgeProperties;
            if (!query.edge_type || ep.type === query.edge_type) {
              result.edges.push({ source, target, properties: ep });
            }
          }
        });
      } else {
        // Filter all nodes
        this.graph.forEachNode((id, attrs) => {
          if (result.nodes.length >= limit) return;
          const node = attrs as NodeProperties;
          if (query.node_type && node.type !== query.node_type) return;
          if (!this.matchesFilter(node, query.node_filter)) return;
          result.nodes.push({ id, properties: node });
        });
      }
    }

    // Edge queries
    if (query.edge_type || query.edge_filter) {
      this.graph.forEachEdge((edgeId, attrs, source, target) => {
        if (result.edges.length >= limit) return;
        const edge = attrs as EdgeProperties;
        if (query.edge_type && edge.type !== query.edge_type) return;
        if (!this.matchesFilter(edge, query.edge_filter)) return;
        result.edges.push({ source, target, properties: edge });
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
      if (item.node_id) {
        const node = this.getNode(item.node_id);
        if (node?.ip && this.isExcluded(node.ip)) {
          filtered.push({ item, reason: `Out of scope: ${node.ip} is excluded` });
          continue;
        }
      }
      if (item.edge_source) {
        const node = this.getNode(item.edge_source);
        if (node?.ip && this.isExcluded(node.ip)) {
          filtered.push({ item, reason: `Out of scope: edge source ${node.ip} is excluded` });
          continue;
        }
      }
      if (item.edge_target) {
        const node = this.getNode(item.edge_target);
        if (node?.ip && this.isExcluded(node.ip)) {
          filtered.push({ item, reason: `Out of scope: edge target ${node.ip} is excluded` });
          continue;
        }
      }

      // 2. OPSEC hard veto
      if (item.opsec_noise > this.config.opsec.max_noise) {
        filtered.push({ item, reason: `OPSEC veto: noise ${item.opsec_noise} exceeds max ${this.config.opsec.max_noise}` });
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
    return !isIpInScope(ip, this.config.scope.cidrs, this.config.scope.exclusions);
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
    if (action.target_node && !this.graph.hasNode(action.target_node)) {
      errors.push(`Node does not exist in graph: ${action.target_node}`);
    }
    if (action.edge_source && !this.graph.hasNode(action.edge_source)) {
      errors.push(`Source node does not exist: ${action.edge_source}`);
    }
    if (action.edge_target && !this.graph.hasNode(action.edge_target)) {
      errors.push(`Target node does not exist: ${action.edge_target}`);
    }

    // Check scope — target_node, edge_source, and edge_target
    if (action.target_node) {
      const node = this.getNode(action.target_node);
      if (node?.ip && this.isExcluded(node.ip)) {
        errors.push(`Target is out of scope: ${node.ip}`);
      }
    }
    if (action.edge_source) {
      const node = this.getNode(action.edge_source);
      if (node?.ip && this.isExcluded(node.ip)) {
        errors.push(`Edge source is out of scope: ${node.ip}`);
      }
    }
    if (action.edge_target) {
      const node = this.getNode(action.edge_target);
      if (node?.ip && this.isExcluded(node.ip)) {
        errors.push(`Edge target is out of scope: ${node.ip}`);
      }
    }

    // Check OPSEC blacklist
    if (action.technique && this.config.opsec.blacklisted_techniques?.includes(action.technique)) {
      errors.push(`Technique blacklisted by OPSEC profile: ${action.technique}`);
    }

    // Time window check
    if (this.config.opsec.time_window) {
      const hour = new Date().getHours();
      const { start_hour, end_hour } = this.config.opsec.time_window;
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
    for (const obj of this.config.objectives) {
      if (obj.achieved) continue;
      // Check if objective criteria are met in the graph
      if (obj.target_criteria) {
        const matching = this.queryGraph({
          node_type: obj.target_node_type,
          node_filter: obj.target_criteria
        });
        if (matching.nodes.length > 0) {
          obj.achieved = true;
          obj.achieved_at = new Date().toISOString();
          this.log(`OBJECTIVE ACHIEVED: ${obj.description}`);
        }
      }
    }
  }

  // =============================================
  // Agent Management
  // =============================================

  registerAgent(task: AgentTask): void {
    this.agents.set(task.id, task);
    this.log(`Agent dispatched: ${task.agent_id} for ${task.frontier_item_id}`, task.agent_id);
    this.persist();
  }

  getTask(taskId: string): AgentTask | null {
    return this.agents.get(taskId) || null;
  }

  updateAgentStatus(taskId: string, status: AgentTask['status'], summary?: string): boolean {
    const task = this.agents.get(taskId);
    if (!task) return false;
    task.status = status;
    if (summary) task.result_summary = summary;
    if (status === 'completed' || status === 'failed') {
      task.completed_at = new Date().toISOString();
    }
    this.persist();
    return true;
  }

  getSubgraphForAgent(nodeIds: string[], options?: { hops?: number; includeCredentials?: boolean; includeServices?: boolean }): GraphQueryResult {
    const hops = options?.hops ?? 2;
    const includeCredentials = options?.includeCredentials ?? true;
    const includeServices = options?.includeServices ?? true;

    const result: GraphQueryResult = { nodes: [], edges: [] };
    const nodeSet = new Set<string>();

    // N-hop BFS from seed nodes
    let frontier = new Set(nodeIds.filter(id => this.graph.hasNode(id)));
    for (const id of frontier) nodeSet.add(id);

    for (let depth = 0; depth < hops; depth++) {
      const nextFrontier = new Set<string>();
      for (const id of frontier) {
        for (const neighbor of this.graph.neighbors(id)) {
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
        for (const neighbor of this.graph.neighbors(hostId)) {
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
    this.graph.forEachEdge((_, attrs, source, target) => {
      if (nodeSet.has(source) && nodeSet.has(target)) {
        result.edges.push({ source, target, properties: attrs as EdgeProperties });
      }
    });

    return result;
  }

  /**
   * Auto-compute subgraph from a frontier item's target node(s).
   * Returns node IDs for the N-hop neighborhood.
   */
  computeSubgraphNodeIds(frontierItemId: string, hops: number = 2): string[] {
    // Find frontier item to get target nodes
    const frontier = this.computeFrontier();
    const item = frontier.find(f => f.id === frontierItemId);
    if (!item) return [];

    const seeds: string[] = [];
    if (item.node_id && this.graph.hasNode(item.node_id)) seeds.push(item.node_id);
    if (item.edge_source && this.graph.hasNode(item.edge_source)) seeds.push(item.edge_source);
    if (item.edge_target && this.graph.hasNode(item.edge_target)) seeds.push(item.edge_target);

    if (seeds.length === 0) return [];

    // BFS N-hop
    const visited = new Set(seeds);
    let current = new Set(seeds);
    for (let d = 0; d < hops; d++) {
      const next = new Set<string>();
      for (const id of current) {
        for (const neighbor of this.graph.neighbors(id)) {
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

    this.graph.forEachNode((_, attrs) => {
      const type = (attrs as NodeProperties).type;
      nodesByType[type] = (nodesByType[type] || 0) + 1;
    });

    this.graph.forEachEdge((_, attrs) => {
      const ep = attrs as EdgeProperties;
      edgesByType[ep.type] = (edgesByType[ep.type] || 0) + 1;
      if (ep.confidence >= 1.0) confirmedEdges++;
      else inferredEdges++;
    });

    // Compute access summary
    const compromised: string[] = [];
    const validCreds: string[] = [];

    this.graph.forEachNode((id, attrs) => {
      const node = attrs as NodeProperties;
      if (node.type === 'host') {
        const hasAccess = this.graph.edges(id).some(e => {
          const ep = this.graph.getEdgeAttributes(e) as EdgeProperties;
          return (ep.type === 'HAS_SESSION' || ep.type === 'ADMIN_TO') && ep.confidence >= 0.9;
        });
        if (hasAccess) compromised.push(node.label);
      }
      if (node.type === 'credential' && node.confidence >= 0.9) {
        validCreds.push(`${node.cred_type}: ${node.cred_user || node.label}`);
      }
    });

    const frontier = this.computeFrontier();
    const { passed } = this.filterFrontier(frontier);

    return {
      config: this.config,
      graph_summary: {
        total_nodes: this.graph.order,
        nodes_by_type: nodesByType,
        total_edges: this.graph.size,
        edges_by_type: edgesByType,
        confirmed_edges: confirmedEdges,
        inferred_edges: inferredEdges
      },
      objectives: this.config.objectives,
      frontier: passed,
      active_agents: Array.from(this.agents.values()).filter(a => a.status === 'running'),
      recent_activity: this.activityLog.slice(-20),
      access_summary: {
        compromised_hosts: compromised,
        valid_credentials: validCreds,
        current_access_level: this.computeAccessLevel(compromised)
      }
    };
  }

  private computeAccessLevel(compromised: string[]): string {
    if (compromised.length === 0) return 'none';
    // Check for DA
    const hasDa = this.getNodesByType('credential').some(c =>
      c.privileged === true && c.confidence >= 0.9
    );
    if (hasDa) return 'domain_admin';
    // Check for local admin
    const hasAdmin = !!this.graph.findEdge((_, attrs) =>
      (attrs as EdgeProperties).type === 'ADMIN_TO' && (attrs as EdgeProperties).confidence >= 0.9
    );
    if (hasAdmin) return 'local_admin';
    return 'user';
  }

  // =============================================
  // Persistence
  // =============================================

  private static readonly MAX_SNAPSHOTS = 5;

  persist(): void {
    const data = {
      config: this.config,
      graph: this.graph.export(),
      activityLog: this.activityLog,
      agents: Array.from(this.agents.entries()),
      inferenceRules: this.inferenceRules.filter(r => !BUILTIN_RULES.some(b => b.id === r.id))
    };
    const json = JSON.stringify(data, null, 2);

    // Atomic write: write to temp, then rename (atomic on POSIX)
    const tmpPath = this.stateFilePath + '.tmp';
    writeFileSync(tmpPath, json);

    // Rotate snapshot before overwriting
    if (existsSync(this.stateFilePath)) {
      this.rotateSnapshot();
    }

    renameSync(tmpPath, this.stateFilePath);
  }

  private rotateSnapshot(): void {
    try {
      const dir = dirname(this.stateFilePath);
      const base = basename(this.stateFilePath, '.json');
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const snapPath = join(dir, `${base}.snap-${ts}.json`);
      // Copy current state to snapshot
      writeFileSync(snapPath, readFileSync(this.stateFilePath));
      // Prune old snapshots beyond MAX_SNAPSHOTS
      const snaps = readdirSync(dir)
        .filter(f => f.startsWith(`${base}.snap-`) && f.endsWith('.json'))
        .sort();
      while (snaps.length > GraphEngine.MAX_SNAPSHOTS) {
        const oldest = snaps.shift()!;
        try { unlinkSync(join(dir, oldest)); } catch { /* best effort */ }
      }
    } catch (err) {
      this.log(`Snapshot rotation error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  listSnapshots(): string[] {
    try {
      const dir = dirname(this.stateFilePath);
      const base = basename(this.stateFilePath, '.json');
      return readdirSync(dir)
        .filter(f => f.startsWith(`${base}.snap-`) && f.endsWith('.json'))
        .sort();
    } catch {
      return [];
    }
  }

  rollbackToSnapshot(snapshotName: string): boolean {
    const dir = dirname(this.stateFilePath);
    const snapPath = join(dir, snapshotName);
    if (!existsSync(snapPath)) return false;

    // Load snapshot data into current engine state
    const raw = readFileSync(snapPath, 'utf-8');
    const data = JSON.parse(raw);
    this.graph.clear();
    this.config = data.config;
    this.graph.import(data.graph);
    this.activityLog = data.activityLog || [];
    this.agents = new Map(data.agents || []);
    // Restore inference rules: builtins + any custom rules from the snapshot
    this.inferenceRules = [...BUILTIN_RULES];
    if (data.inferenceRules) {
      for (const rule of data.inferenceRules) {
        this.inferenceRules.push(rule);
      }
    }
    this.log('Rolled back to snapshot: ' + snapshotName);
    this.persist();
    return true;
  }

  private loadState(): void {
    const raw = readFileSync(this.stateFilePath, 'utf-8');
    const data = JSON.parse(raw);
    this.config = data.config;
    this.graph.import(data.graph);
    this.activityLog = data.activityLog || [];
    this.agents = new Map(data.agents || []);
    if (data.inferenceRules) {
      for (const rule of data.inferenceRules) {
        this.inferenceRules.push(rule);
      }
    }
  }

  // =============================================
  // Evidence
  // =============================================

  getFullHistory(): Array<{ timestamp: string; description: string; agent_id?: string }> {
    return [...this.activityLog];
  }

  exportGraph(): { nodes: Array<{ id: string; properties: NodeProperties }>; edges: Array<{ source: string; target: string; properties: EdgeProperties }> } {
    const nodes: Array<{ id: string; properties: NodeProperties }> = [];
    const edges: Array<{ source: string; target: string; properties: EdgeProperties }> = [];

    this.graph.forEachNode((id, attrs) => {
      nodes.push({ id, properties: attrs as NodeProperties });
    });

    this.graph.forEachEdge((_, attrs, source, target) => {
      edges.push({ source, target, properties: attrs as EdgeProperties });
    });

    return { nodes, edges };
  }

  // =============================================
  // Helpers
  // =============================================

  private propertiesChanged(oldProps: NodeProperties, newProps: NodeProperties): boolean {
    const ignoreKeys = new Set(['discovered_at', 'discovered_by']);
    for (const [key, val] of Object.entries(newProps)) {
      if (ignoreKeys.has(key)) continue;
      if (val !== undefined && val !== null && oldProps[key] !== val) return true;
    }
    return false;
  }

  private log(message: string, agentId?: string): void {
    this.activityLog.push({
      timestamp: new Date().toISOString(),
      description: message,
      agent_id: agentId
    });
  }
}
