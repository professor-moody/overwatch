// ============================================================
// Overwatch — Frontier Computation
// Identifies incomplete nodes and untested inferred edges.
// All state access goes through the shared EngineContext.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { NodeProperties, EdgeProperties, FrontierItem, NodeType } from '../types.js';
import { getNodeLastSeenAt } from './provenance-utils.js';
import { isCredentialStaleOrExpired } from './credential-utils.js';
import { isIpInCidr } from './cidr.js';

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

// --- Declarative required-properties map ---
// Each entry returns the list of missing properties for a given node.
// New node types added in later sprints automatically participate in
// frontier computation by adding an entry here — no switch needed.
type MissingPropertyChecker = (node: NodeProperties, ctx: EngineContext) => string[];

const REQUIRED_PROPERTIES: Partial<Record<NodeType, MissingPropertyChecker>> = {
  host: (node, ctx) => {
    const m: string[] = [];
    if (node.alive === undefined) m.push('alive');
    else if (node.alive) {
      if (!node.os) m.push('os');
      const hasServices = ctx.graph.outEdges(node.id).some((e: string) =>
        ctx.graph.getEdgeAttributes(e).type === 'RUNS'
      );
      if (!hasServices) m.push('services');
    }
    return m;
  },
  service: (node) => node.version ? [] : ['version'],
  user: (node) => node.privileged === undefined ? ['privilege_level'] : [],
  domain: (node) => node.functional_level ? [] : ['functional_level'],
};

// --- Noise estimates by missing property ---
const NOISE_ESTIMATES: Record<string, number> = {
  alive: 0.2,
  services: 0.5,
  version: 0.3,
  default: 0.3,
};

export type HopsToObjectiveFn = (fromNodeId: string) => number | null;

export class FrontierComputer {
  private ctx: EngineContext;
  private hopsToObjective: HopsToObjectiveFn;

  constructor(ctx: EngineContext, hopsToObjective: HopsToObjectiveFn) {
    this.ctx = ctx;
    this.hopsToObjective = hopsToObjective;
  }

  compute(): FrontierItem[] {
    const frontier: FrontierItem[] = [];
    const now = Date.now();

    // 1. Incomplete nodes (missing key properties)
    this.ctx.graph.forEachNode((id: string, attrs) => {
      const missing = this.getMissingProperties(attrs);
      if (missing.length === 0) return;

      frontier.push({
        id: `frontier-node-${id}`,
        type: 'incomplete_node',
        node_id: id,
        missing_properties: missing,
        description: `${attrs.type} "${attrs.label}" missing: ${missing.join(', ')}`,
        graph_metrics: {
          hops_to_objective: this.hopsToObjective(id),
          fan_out_estimate: this.estimateFanOut(attrs),
          node_degree: this.ctx.graph.degree(id),
          confidence: attrs.confidence
        },
        opsec_noise: this.estimateNoiseForNode(attrs, missing),
        staleness_seconds: (now - new Date(getNodeLastSeenAt(attrs) || attrs.discovered_at).getTime()) / 1000
      });
    });

    // 2. Untested inferred edges
    this.ctx.graph.forEachEdge((edgeId: string, attrs, source: string, target: string) => {
      if (attrs.tested) return;
      if (attrs.confidence >= 1.0) return; // confirmed edges aren't frontier

      // Check if edge source is a stale/expired credential
      const sourceNode = this.ctx.graph.getNodeAttributes(source);
      const isStale = sourceNode.type === 'credential' && isCredentialStaleOrExpired(sourceNode);

      frontier.push({
        id: `frontier-edge-${edgeId}`,
        type: 'inferred_edge',
        edge_source: source,
        edge_target: target,
        edge_type: attrs.type,
        description: `Test ${attrs.type}: ${source} → ${target} (confidence: ${attrs.confidence})${isStale ? ' [stale credential]' : ''}`,
        graph_metrics: {
          hops_to_objective: this.hopsToObjective(target),
          fan_out_estimate: 2,
          node_degree: this.ctx.graph.degree(target),
          confidence: isStale ? attrs.confidence * 0.1 : attrs.confidence
        },
        opsec_noise: attrs.opsec_noise || 0.3,
        staleness_seconds: (now - new Date(attrs.discovered_at).getTime()) / 1000,
        stale_credential: isStale || undefined,
      });
    });

    // 3. Network discovery items from scope CIDRs
    //    Suppress fully-explored CIDRs; reduce fan_out for partially-explored ones.
    const discoveredIps = this.collectDiscoveredIps();
    for (const cidr of this.ctx.config.scope.cidrs) {
      const slug = cidr.replace(/[./]/g, '-');
      const maskStr = cidr.split('/')[1];
      const mask = maskStr ? parseInt(maskStr) : 32;
      const hostBits = 32 - mask;
      const totalEstimate = mask >= 31 ? 1 : (1 << hostBits) - 2;
      const cappedEstimate = Math.min(totalEstimate, 254);

      const discoveredInCidr = discoveredIps.filter(ip => isIpInCidr(ip, cidr)).length;
      const remaining = cappedEstimate - discoveredInCidr;

      // Suppress when all estimated hosts have been discovered
      if (remaining <= 0) continue;

      frontier.push({
        id: `frontier-discovery-${slug}`,
        type: 'network_discovery',
        target_cidr: cidr,
        description: discoveredInCidr === 0
          ? `Discover hosts in ${cidr}`
          : `Continue discovery in ${cidr} (${discoveredInCidr} found, ~${remaining} remaining)`,
        graph_metrics: {
          hops_to_objective: null,
          fan_out_estimate: remaining,
          node_degree: 0,
          confidence: 1.0,
        },
        opsec_noise: 0.2,
        staleness_seconds: 0,
      });
    }

    return frontier;
  }

  private getMissingProperties(node: NodeProperties): string[] {
    const checker = REQUIRED_PROPERTIES[node.type];
    return checker ? checker(node, this.ctx) : [];
  }

  private estimateFanOut(node: NodeProperties): number {
    if (node.type === 'host') {
      const services = this.ctx.graph.outEdges(node.id)
        .map((e: string) => this.ctx.graph.getEdgeAttributes(e))
        .filter(e => e.type === 'RUNS');
      if (services.length === 0) return 10;
      return services.length * 5;
    }
    if (node.type === 'service') {
      return FAN_OUT_ESTIMATES[node.service_name || 'default'] || FAN_OUT_ESTIMATES['default'];
    }
    if (node.type === 'credential') return 15;
    return FAN_OUT_ESTIMATES['default'];
  }

  private collectDiscoveredIps(): string[] {
    const ips: string[] = [];
    this.ctx.graph.forEachNode((_id: string, attrs) => {
      if (attrs.type === 'host' && attrs.ip) ips.push(attrs.ip);
    });
    return ips;
  }

  private estimateNoiseForNode(_node: NodeProperties, missing: string[]): number {
    for (const prop of missing) {
      if (prop in NOISE_ESTIMATES) return NOISE_ESTIMATES[prop];
    }
    return NOISE_ESTIMATES['default'];
  }
}
