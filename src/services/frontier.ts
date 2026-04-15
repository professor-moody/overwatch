// ============================================================
// Overwatch — Frontier Computation
// Identifies incomplete nodes and untested inferred edges.
// All state access goes through the shared EngineContext.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { NodeProperties, FrontierItem, NodeType } from '../types.js';
import { getNodeLastSeenAt } from './provenance-utils.js';
import { isCredentialStaleOrExpired, timeToExpiry } from './credential-utils.js';
import { isIpInCidr } from './cidr.js';
import type { KnowledgeBase } from './knowledge-base.js';
import { EDGE_TO_ATTACK } from './finding-classifier.js';

// --- Fan-out estimates by service type ---
export const FAN_OUT_DEFAULTS: Record<string, number> = {
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
export const NOISE_ESTIMATE_DEFAULTS: Record<string, number> = {
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
  private kb: KnowledgeBase | null;
  private fanOutEstimates: Record<string, number>;
  private noiseEstimates: Record<string, number>;

  constructor(ctx: EngineContext, hopsToObjective: HopsToObjectiveFn, kb?: KnowledgeBase | null) {
    this.ctx = ctx;
    this.hopsToObjective = hopsToObjective;
    this.kb = kb || null;
    this.fanOutEstimates = { ...FAN_OUT_DEFAULTS };
    this.noiseEstimates = { ...NOISE_ESTIMATE_DEFAULTS };
  }

  setKB(kb: KnowledgeBase | null): void {
    this.kb = kb;
  }

  getFanOutEstimates(): Record<string, number> {
    return { ...this.fanOutEstimates };
  }

  getNoiseEstimates(): Record<string, number> {
    return { ...this.noiseEstimates };
  }

  setFanOutEstimates(overrides: Record<string, number>): void {
    for (const [k, v] of Object.entries(overrides)) {
      if (typeof v === 'number' && v >= 0) this.fanOutEstimates[k] = v;
    }
  }

  setNoiseEstimates(overrides: Record<string, number>): void {
    for (const [k, v] of Object.entries(overrides)) {
      if (typeof v === 'number' && v >= 0 && v <= 1) this.noiseEstimates[k] = v;
    }
  }

  resetWeightsToDefaults(): void {
    this.fanOutEstimates = { ...FAN_OUT_DEFAULTS };
    this.noiseEstimates = { ...NOISE_ESTIMATE_DEFAULTS };
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

      // Check if edge source is a stale/expired credential
      const sourceNode = this.ctx.graph.getNodeAttributes(source);
      const isStale = sourceNode.type === 'credential' && isCredentialStaleOrExpired(sourceNode);

      // Graduated credential expiry scoring
      let credMultiplier = 1;
      let credLabel = '';
      if (isStale) {
        credMultiplier = 0.1;
        credLabel = ' [stale credential]';
      } else if (sourceNode.type === 'credential') {
        const ttl = timeToExpiry(sourceNode);
        if (ttl < 30 * 60 * 1000) { // < 30 minutes
          credMultiplier = 0.3;
          credLabel = ' [expiring soon]';
        } else if (ttl < 2 * 60 * 60 * 1000) { // < 2 hours
          credMultiplier = 0.7;
          const hoursLeft = Math.ceil(ttl / (60 * 60 * 1000));
          credLabel = ` [expires in ${hoursLeft}h]`;
        }
      }

      // KB-informed confidence and noise adjustments
      let kbConfidenceBoost = 1;
      let kbNoise: number | undefined;
      let kbLabel = '';
      if (this.kb) {
        const tech = EDGE_TO_ATTACK[attrs.type];
        if (tech) {
          const stats = this.kb.getTechniqueStats(tech.id);
          if (stats && stats.attempts >= 2) {
            // Blend KB success rate into confidence (weighted 20%)
            kbConfidenceBoost = 1 + (stats.success_rate - 0.5) * 0.4;
            kbNoise = stats.avg_noise;
            kbLabel = ` [KB: ${Math.round(stats.success_rate * 100)}% success]`;
          }
        }
      }

      frontier.push({
        id: `frontier-edge-${edgeId}`,
        type: 'inferred_edge',
        edge_source: source,
        edge_target: target,
        edge_type: attrs.type,
        description: `Test ${attrs.type}: ${source} → ${target} (confidence: ${attrs.confidence})${credLabel}${kbLabel}`,
        graph_metrics: {
          hops_to_objective: this.hopsToObjective(target),
          fan_out_estimate: 2,
          node_degree: this.ctx.graph.degree(target),
          confidence: attrs.confidence * credMultiplier * kbConfidenceBoost
        },
        opsec_noise: kbNoise ?? attrs.opsec_noise ?? 0.3,
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
      const totalEstimate = mask >= 31 ? 1 : Math.max(2 ** hostBits - 2, 1);
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
    // Build dedup indexes for O(1) lookups instead of O(n) frontier.some()
    const frontierIds = new Set(frontier.map(f => f.id));
    const reachableTargets = new Set(
      frontier.filter(f => f.type === 'inferred_edge' && f.edge_type === 'REACHABLE').map(f => f.edge_target)
    );

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
          if (eAttrs.type === 'HAS_SESSION' && eAttrs.confidence >= 0.7) {
            pivotPrincipal = this.ctx.graph.source(edge);
            break;
          }
        }
        if (!pivotPrincipal) continue;

        for (const peer of hostsInSubnet) {
          if (peer.id === host.id) continue;
          const peerHasSession = this.ctx.graph.inEdges(peer.id).some((e: string) => {
            const ea = this.ctx.graph.getEdgeAttributes(e);
            return ea.type === 'HAS_SESSION' && ea.confidence >= 0.7;
          });
          if (peerHasSession) continue;

          const pivotItemId = `frontier-pivot-${host.id}-${peer.id}`;
          if (frontierIds.has(pivotItemId)) continue;
          if (reachableTargets.has(peer.id)) continue;

          frontierIds.add(pivotItemId);
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
      return this.fanOutEstimates[node.service_name || 'default'] || this.fanOutEstimates['default'];
    }
    if (node.type === 'credential') return 15;
    if (node.type === 'webapp') return 8;
    return this.fanOutEstimates['default'];
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
      if (prop in this.noiseEstimates) return this.noiseEstimates[prop];
    }
    return this.noiseEstimates['default'];
  }
}
