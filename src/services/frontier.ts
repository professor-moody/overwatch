// ============================================================
// Overwatch — Frontier Computation
// Identifies incomplete nodes and untested inferred edges.
// All state access goes through the shared EngineContext.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { NodeProperties, FrontierItem, NodeType } from '../types.js';
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
      // Linux-specific enrichment
      if (node.os && node.os.toLowerCase().includes('linux')) {
        if (node.suid_checked === undefined) m.push('suid_checked');
        if (node.cron_checked === undefined) m.push('cron_checked');
        if (node.capabilities_checked === undefined) m.push('capabilities_checked');
      }
    }
    return m;
  },
  service: (node) => node.version ? [] : ['version'],
  user: (node) => node.privileged === undefined ? ['privilege_level'] : [],
  domain: (node) => node.functional_level ? [] : ['functional_level'],
  webapp: (node) => {
    const m: string[] = [];
    if (!node.technology) m.push('technology');
    if (!node.auth_type) m.push('auth_type');
    return m;
  },
  cloud_identity: (node) => {
    const m: string[] = [];
    if (!node.policies_enumerated) m.push('policies_enumerated');
    if (node.mfa_enabled === undefined) m.push('mfa_enabled');
    return m;
  },
  cloud_resource: (node) => {
    const m: string[] = [];
    if (node.public === undefined) m.push('public_access_checked');
    if (node.encrypted === undefined) m.push('encryption_checked');
    return m;
  },
};

// --- Noise estimates by missing property ---
const NOISE_ESTIMATES: Record<string, number> = {
  alive: 0.2,
  services: 0.5,
  version: 0.3,
  suid_checked: 0.3,
  cron_checked: 0.2,
  capabilities_checked: 0.3,
  technology: 0.3,
  auth_type: 0.2,
  policies_enumerated: 0.6,
  mfa_enabled: 0.2,
  public_access_checked: 0.3,
  encryption_checked: 0.2,
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
      if (attrs.identity_status === 'superseded') return;
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

    // 4. Network pivot items: hosts reachable via pivot in same subnet
    this.ctx.graph.forEachNode((_subnetId: string, subnetAttrs) => {
      if (subnetAttrs.type !== 'subnet' || !subnetAttrs.subnet_cidr) return;
      const cidr = subnetAttrs.subnet_cidr as string;

      const hostsInSubnet: Array<{ id: string; attrs: NodeProperties }> = [];
      this.ctx.graph.forEachNode((hId: string, hAttrs) => {
        if (hAttrs.type === 'host' && hAttrs.ip && isIpInCidr(hAttrs.ip, cidr)) {
          hostsInSubnet.push({ id: hId, attrs: hAttrs });
        }
      });

      for (const host of hostsInSubnet) {
        let pivotPrincipal: string | undefined;
        for (const edge of this.ctx.graph.inEdges(host.id) as string[]) {
          const eAttrs = this.ctx.graph.getEdgeAttributes(edge);
          if (eAttrs.type === 'HAS_SESSION' && eAttrs.confidence >= 0.9) {
            pivotPrincipal = this.ctx.graph.source(edge);
            break;
          }
        }
        if (!pivotPrincipal) continue;

        for (const peer of hostsInSubnet) {
          if (peer.id === host.id) continue;
          const peerHasSession = this.ctx.graph.inEdges(peer.id).some((e: string) => {
            const ea = this.ctx.graph.getEdgeAttributes(e);
            return ea.type === 'HAS_SESSION' && ea.confidence >= 0.9;
          });
          if (peerHasSession) continue;

          const pivotItemId = `frontier-pivot-${host.id}-${peer.id}`;
          if (frontier.some(f => f.id === pivotItemId)) continue;

          // Skip if an inferred_edge item already targets this peer via REACHABLE
          if (frontier.some(f => f.type === 'inferred_edge' && f.edge_target === peer.id && f.edge_type === 'REACHABLE')) continue;

          frontier.push({
            id: pivotItemId,
            type: 'network_pivot',
            node_id: peer.id,
            pivot_host_id: host.id,
            via_pivot: pivotPrincipal,
            description: `Host "${peer.attrs.label}" in ${cidr} reachable via pivot on "${host.attrs.label}"`,
            graph_metrics: {
              hops_to_objective: this.hopsToObjective(peer.id),
              fan_out_estimate: 5,
              node_degree: this.ctx.graph.degree(peer.id),
              confidence: 0.6,
            },
            opsec_noise: 0.4,
            staleness_seconds: (now - new Date(peer.attrs.discovered_at).getTime()) / 1000,
          });
        }
      }
    });

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
    if (node.type === 'webapp') return 8;
    return FAN_OUT_ESTIMATES['default'];
  }

  private collectDiscoveredIps(): string[] {
    const ips: string[] = [];
    this.ctx.graph.forEachNode((_id: string, attrs) => {
      if (attrs.type === 'host' && attrs.ip) ips.push(attrs.ip);
    });
    // Include cold store hosts — they were discovered but demoted from the hot graph
    this.ctx.coldStore.forEach((record) => {
      if (record.ip) ips.push(record.ip);
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
