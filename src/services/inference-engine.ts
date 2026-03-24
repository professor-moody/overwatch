// ============================================================
// Overwatch — Inference Engine
// Rule matching, edge production, selector resolution, backfill.
// All state access goes through the shared EngineContext.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { NodeProperties, EdgeProperties, NodeType, InferenceRule } from '../types.js';
import { getCredentialMaterialKind, isCredentialUsableForAuth, isReusableDomainCredential } from './credential-utils.js';

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
    // Deduplicate by name — prevent retries from creating duplicate rules
    const existingByName = this.ctx.inferenceRules.findIndex(r => r.name === rule.name);
    if (existingByName !== -1) {
      this.ctx.inferenceRules[existingByName] = rule;
      this.ctx.logEvent({ description: `Custom inference rule updated (dedup by name): ${rule.name}`, category: 'inference', event_type: 'inference_generated', result_classification: 'neutral' });
      return;
    }
    this.ctx.inferenceRules.push(rule);
    this.ctx.logEvent({ description: `Custom inference rule added: ${rule.name}`, category: 'inference', event_type: 'inference_generated', result_classification: 'neutral' });
  }

  backfillRule(rule: InferenceRule): string[] {
    const inferred: string[] = [];
    this.ctx.graph.forEachNode((nodeId: string, attrs) => {
      if (rule.trigger.node_type && attrs.type !== rule.trigger.node_type) return;
      if (rule.trigger.property_match) {
        const matches = Object.entries(rule.trigger.property_match).every(
          ([key, val]) => (attrs as Record<string, unknown>)[key] === val
        );
        if (!matches) return;
      }
      if (rule.trigger.requires_edge && !this.hasMatchingEdge(nodeId, rule.trigger.requires_edge)) return;
      inferred.push(...this.runRulesForRule(rule, nodeId));
    });
    return inferred;
  }

  runRules(triggerNodeId: string): string[] {
    const node = this.getNode(triggerNodeId);
    if (!node) return [];

    const inferred: string[] = [];
    for (const rule of this.ctx.inferenceRules) {
      if (rule.trigger.node_type && node.type !== rule.trigger.node_type) continue;

      if (rule.trigger.property_match) {
        const matches = Object.entries(rule.trigger.property_match).every(
          ([key, val]) => node[key] === val
        );
        if (!matches) continue;
      }

      if (rule.trigger.requires_edge && !this.hasMatchingEdge(triggerNodeId, rule.trigger.requires_edge)) continue;

      inferred.push(...this.applyRuleProductions(rule, triggerNodeId));
    }

    return inferred;
  }

  private runRulesForRule(rule: InferenceRule, triggerNodeId: string): string[] {
    return this.applyRuleProductions(rule, triggerNodeId);
  }

  private hasMatchingEdge(nodeId: string, req: NonNullable<InferenceRule['trigger']['requires_edge']>): boolean {
    const edges = req.direction === 'inbound'
      ? this.ctx.graph.inEdges(nodeId) as string[]
      : this.ctx.graph.outEdges(nodeId) as string[];
    for (const e of edges) {
      const attrs = this.ctx.graph.getEdgeAttributes(e);
      if (attrs.type !== req.type) continue;
      if (req.peer_match) {
        const peerId = req.direction === 'inbound'
          ? this.ctx.graph.source(e)
          : this.ctx.graph.target(e);
        const peer = this.getNode(peerId);
        if (!peer) continue;
        const matches = Object.entries(req.peer_match).every(
          ([k, v]) => (peer as Record<string, unknown>)[k] === v
        );
        if (!matches) continue;
      }
      return true;
    }
    return false;
  }

  private resolveEdgePeers(nodeId: string, req: NonNullable<InferenceRule['trigger']['requires_edge']>): string[] {
    const edges = req.direction === 'inbound'
      ? this.ctx.graph.inEdges(nodeId) as string[]
      : this.ctx.graph.outEdges(nodeId) as string[];
    const peers: string[] = [];
    for (const e of edges) {
      const attrs = this.ctx.graph.getEdgeAttributes(e);
      if (attrs.type !== req.type) continue;
      const peerId = req.direction === 'inbound'
        ? this.ctx.graph.source(e)
        : this.ctx.graph.target(e);
      if (req.peer_match) {
        const peer = this.getNode(peerId);
        if (!peer) continue;
        const matches = Object.entries(req.peer_match).every(
          ([k, v]) => (peer as Record<string, unknown>)[k] === v
        );
        if (!matches) continue;
      }
      peers.push(peerId);
    }
    return peers;
  }

  private applyRuleProductions(rule: InferenceRule, triggerNodeId: string): string[] {
    const inferred: string[] = [];
    const now = new Date().toISOString();
    for (const production of rule.produces) {
      const sources = this.resolveSelector(production.source_selector, triggerNodeId, rule);
      const targets = this.resolveSelector(production.target_selector, triggerNodeId, rule);
      for (const src of sources) {
        for (const tgt of targets) {
          if (src === tgt) continue;
          if (!this.ctx.graph.hasNode(src) || !this.ctx.graph.hasNode(tgt)) continue;
          const existing = this.ctx.graph.edges(src, tgt);
          const alreadyExists = existing.some((e: string) => {
            return this.ctx.graph.getEdgeAttributes(e).type === production.edge_type;
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
          this.ctx.logEvent({
            description: `Inferred edge [${rule.name}]: ${src} --[${production.edge_type}]--> ${tgt}`,
            category: 'inference',
            event_type: 'inference_generated',
            result_classification: 'success',
            target_node_ids: [src, tgt],
            details: { rule_id: rule.id, edge_type: production.edge_type },
          });
        }
      }
    }
    return inferred;
  }

  private resolveSelector(selector: string, triggerNodeId: string, rule?: InferenceRule): string[] {
    const node = this.getNode(triggerNodeId);
    if (!node) return [];

    switch (selector) {
      case 'trigger_node':
      case 'trigger_service':
        return [triggerNodeId];

      case 'parent_host': {
        const hosts: string[] = [];
        this.ctx.graph.forEachInEdge(triggerNodeId, (edge: string, attrs, src: string) => {
          if (attrs.type === 'RUNS') hosts.push(src);
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
          .filter(c => isReusableDomainCredential(c))
          .map(n => n.id);

      case 'all_compromised': {
        const compromised: Set<string> = new Set();
        this.ctx.graph.forEachEdge((edge: string, attrs) => {
          if ((attrs.type === 'HAS_SESSION' || attrs.type === 'ADMIN_TO') && attrs.confidence >= 0.9) {
            compromised.add(this.ctx.graph.target(edge));
          }
        });
        return Array.from(compromised);
      }

      case 'compatible_services': {
        return this.getNodesByType('service')
          .filter(s => {
            if (!isCredentialUsableForAuth(node)) return false;

            const materialKind = getCredentialMaterialKind(node);
            if (materialKind === 'ntlm_hash' || materialKind === 'kerberos_tgt' || materialKind === 'aes256_key') {
              return ['smb', 'ldap', 'mssql', 'winrm', 'rdp', 'http', 'https'].includes(s.service_name || '');
            }
            if (materialKind === 'plaintext_password') return true;
            if (materialKind === 'ssh_key') return s.service_name === 'ssh';
            if (materialKind === 'certificate') return ['http', 'https'].includes(s.service_name || '');
            return false;
          })
          .map(n => n.id);
      }

      case 'enrollable_users':
        return this.getNodesByType('user').map(n => n.id);

      case 'edge_peers': {
        if (!rule?.trigger.requires_edge) return [];
        return this.resolveEdgePeers(triggerNodeId, rule.trigger.requires_edge);
      }

      default:
        console.error(`[InferenceEngine] Unknown selector: '${selector}' — check inference rule configuration`);
        return [];
    }
  }
}
