// ============================================================
// Overwatch — Inference Engine
// Rule matching, edge production, selector resolution, backfill.
// All state access goes through the shared EngineContext.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { NodeProperties, EdgeProperties, NodeType, InferenceRule } from '../types.js';

export type AddEdgeFn = (source: string, target: string, props: EdgeProperties) => { id: string; isNew: boolean };
export type GetNodeFn = (id: string) => NodeProperties | null;
export type GetNodesByTypeFn = (type: NodeType) => NodeProperties[];

export class InferenceEngine {
  private ctx: EngineContext;
  private addEdge: AddEdgeFn;
  private getNode: GetNodeFn;
  private getNodesByType: GetNodesByTypeFn;

  constructor(
    ctx: EngineContext,
    addEdge: AddEdgeFn,
    getNode: GetNodeFn,
    getNodesByType: GetNodesByTypeFn,
  ) {
    this.ctx = ctx;
    this.addEdge = addEdge;
    this.getNode = getNode;
    this.getNodesByType = getNodesByType;
  }

  addRule(rule: InferenceRule): void {
    if (this.ctx.inferenceRules.some(r => r.id === rule.id)) return;
    this.ctx.inferenceRules.push(rule);
    this.ctx.log(`Custom inference rule added: ${rule.name}`);
  }

  backfillRule(rule: InferenceRule): string[] {
    const inferred: string[] = [];
    this.ctx.graph.forEachNode((nodeId: string, attrs: any) => {
      const node = attrs as NodeProperties;
      if (rule.trigger.node_type && node.type !== rule.trigger.node_type) return;
      if (rule.trigger.property_match) {
        const matches = Object.entries(rule.trigger.property_match).every(
          ([key, val]) => node[key] === val
        );
        if (!matches) return;
      }
      inferred.push(...this.runRulesForRule(rule, nodeId));
    });
    return inferred;
  }

  runRules(triggerNodeId: string): string[] {
    const node = this.getNode(triggerNodeId);
    if (!node) return [];

    const inferred: string[] = [];
    const now = new Date().toISOString();

    for (const rule of this.ctx.inferenceRules) {
      if (rule.trigger.node_type && node.type !== rule.trigger.node_type) continue;

      if (rule.trigger.property_match) {
        const matches = Object.entries(rule.trigger.property_match).every(
          ([key, val]) => node[key] === val
        );
        if (!matches) continue;
      }

      for (const production of rule.produces) {
        const sources = this.resolveSelector(production.source_selector, triggerNodeId);
        const targets = this.resolveSelector(production.target_selector, triggerNodeId);

        for (const src of sources) {
          for (const tgt of targets) {
            if (src === tgt) continue;
            if (!this.ctx.graph.hasNode(src) || !this.ctx.graph.hasNode(tgt)) continue;

            const existing = this.ctx.graph.edges(src, tgt);
            const alreadyExists = existing.some((e: string) => {
              const attrs = this.ctx.graph.getEdgeAttributes(e) as EdgeProperties;
              return attrs.type === production.edge_type;
            });
            if (alreadyExists) continue;

            const { id: edgeId } = this.addEdge(src, tgt, {
              type: production.edge_type,
              confidence: production.confidence,
              discovered_at: now,
              discovered_by: `inference:${rule.id}`,
              tested: false,
              inferred_by_rule: rule.id,
              inferred_at: now,
              ...production.properties as Record<string, unknown>
            });

            inferred.push(edgeId);
            this.ctx.log(`Inferred edge [${rule.name}]: ${src} --[${production.edge_type}]--> ${tgt}`);
          }
        }
      }
    }

    return inferred;
  }

  private runRulesForRule(rule: InferenceRule, triggerNodeId: string): string[] {
    const inferred: string[] = [];
    const now = new Date().toISOString();
    for (const production of rule.produces) {
      const sources = this.resolveSelector(production.source_selector, triggerNodeId);
      const targets = this.resolveSelector(production.target_selector, triggerNodeId);
      for (const src of sources) {
        for (const tgt of targets) {
          if (src === tgt) continue;
          if (!this.ctx.graph.hasNode(src) || !this.ctx.graph.hasNode(tgt)) continue;
          const existing = this.ctx.graph.edges(src, tgt);
          const alreadyExists = existing.some((e: string) => {
            const attrs = this.ctx.graph.getEdgeAttributes(e) as EdgeProperties;
            return attrs.type === production.edge_type;
          });
          if (alreadyExists) continue;
          const { id: edgeId } = this.addEdge(src, tgt, {
            type: production.edge_type,
            confidence: production.confidence,
            discovered_at: now,
            discovered_by: `inference:${rule.id}`,
            tested: false,
            inferred_by_rule: rule.id,
            inferred_at: now,
            ...production.properties as Record<string, unknown>
          });
          inferred.push(edgeId);
          this.ctx.log(`Inferred edge [${rule.name}]: ${src} --[${production.edge_type}]--> ${tgt}`);
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
        const hosts: string[] = [];
        this.ctx.graph.forEachInEdge(triggerNodeId, (edge: string, attrs: any, src: string) => {
          if ((attrs as EdgeProperties).type === 'RUNS') hosts.push(src);
        });
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
        const compromised: Set<string> = new Set();
        this.ctx.graph.forEachEdge((edge: string, attrs: any) => {
          const ep = attrs as EdgeProperties;
          if ((ep.type === 'HAS_SESSION' || ep.type === 'ADMIN_TO') && ep.confidence >= 0.9) {
            compromised.add(this.ctx.graph.target(edge));
          }
        });
        return Array.from(compromised);
      }

      case 'compatible_services': {
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
}
