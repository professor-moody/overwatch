// ============================================================
// Overwatch — Frontier Computation
// Identifies incomplete nodes and untested inferred edges.
// All state access goes through the shared EngineContext.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { NodeProperties, EdgeProperties, FrontierItem } from '../types.js';
import { getNodeLastSeenAt } from './provenance-utils.js';

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

      frontier.push({
        id: `frontier-edge-${edgeId}`,
        type: 'inferred_edge',
        edge_source: source,
        edge_target: target,
        edge_type: attrs.type,
        description: `Test ${attrs.type}: ${source} → ${target} (confidence: ${attrs.confidence})`,
        graph_metrics: {
          hops_to_objective: this.hopsToObjective(target),
          fan_out_estimate: 2,
          node_degree: this.ctx.graph.degree(target),
          confidence: attrs.confidence
        },
        opsec_noise: attrs.opsec_noise || 0.3,
        staleness_seconds: (now - new Date(attrs.discovered_at).getTime()) / 1000
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
          const hasServices = this.ctx.graph.outEdges(node.id).some((e: string) =>
            this.ctx.graph.getEdgeAttributes(e).type === 'RUNS'
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

  private estimateNoiseForNode(node: NodeProperties, missing: string[]): number {
    if (missing.includes('alive')) return 0.2;
    if (missing.includes('services')) return 0.5;
    if (missing.includes('version')) return 0.3;
    return 0.3;
  }
}
