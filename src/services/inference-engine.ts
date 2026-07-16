// ============================================================
// Overwatch — Inference Engine
// Rule matching, edge production, selector resolution, backfill.
// All state access goes through the shared EngineContext.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { NodeProperties, EdgeProperties, NodeType, InferenceRule } from '../types.js';
import { getCredentialMaterialKind, isCredentialUsableForAuth, isReusableDomainCredential } from './credential-utils.js';

export type AddEdgeFn = (source: string, target: string, props: EdgeProperties) => { id: string; isNew: boolean };
export type AddNodeFn = (props: NodeProperties) => string;
export type GetNodeFn = (id: string) => NodeProperties | null;
export type GetNodesByTypeFn = (type: NodeType) => NodeProperties[];

export class InferenceEngine {
  private ctx: EngineContext;
  private addEdge: AddEdgeFn;
  private getNode: GetNodeFn;
  private getNodesByType: GetNodesByTypeFn;
  private addNode: AddNodeFn;

  constructor(
    ctx: EngineContext,
    addEdge: AddEdgeFn,
    getNode: GetNodeFn,
    getNodesByType: GetNodesByTypeFn,
    addNode: AddNodeFn,
  ) {
    this.ctx = ctx;
    this.addEdge = addEdge;
    this.getNode = getNode;
    this.getNodesByType = getNodesByType;
    this.addNode = addNode;
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
    let candidateNodes = 0;
    let filteredByRequiresEdge = 0;
    this.ctx.graph.forEachNode((nodeId: string, attrs) => {
      if (rule.trigger.node_type && attrs.type !== rule.trigger.node_type) return;
      if (rule.trigger.property_match) {
        const matches = Object.entries(rule.trigger.property_match).every(
          ([key, val]) => (attrs as Record<string, unknown>)[key] === val
        );
        if (!matches) return;
      }
      candidateNodes++;
      if (rule.trigger.requires_edge && !this.hasMatchingEdge(nodeId, rule.trigger.requires_edge)) {
        filteredByRequiresEdge++;
        return;
      }
      inferred.push(...this.runRulesForRule(rule, nodeId));
    });
    if (inferred.length === 0 && (candidateNodes > 0 || filteredByRequiresEdge > 0)) {
      this.ctx.logEvent({
        description: `Inference backfill produced no edges for rule ${rule.name}`,
        category: 'inference',
        event_type: 'inference_generated',
        result_classification: 'neutral',
        details: {
          rule_id: rule.id,
          inference_status: 'no_edges',
          candidate_nodes: candidateNodes,
          filtered_by_requires_edge: filteredByRequiresEdge,
        },
      });
    }
    return inferred;
  }

  runRules(triggerNodeId: string): string[] {
    const node = this.getNode(triggerNodeId);
    if (!node) return [];

    // OS enrichment: infer OS from child service signatures when host lacks os property
    if (node.type === 'host' && !node.os) {
      this.inferOsFromServices(triggerNodeId);
    }

    // Dynamic rule ordering: sort by confirmation rate (desc), deprioritize
    // rules with 0 confirmations and ≥5 attempts
    const sortedRules = this.getSortedRules();

    const inferred: string[] = [];
    for (const rule of sortedRules) {
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

  /**
   * Sort rules by effectiveness: high confirmation rate first,
   * deprioritize rules with 0 confirmations and ≥5 attempts.
   * Caches for 60s to avoid per-trigger graph scans.
   */
  private ruleOrderCache: { rules: InferenceRule[]; ts: number } | null = null;
  private static readonly RULE_ORDER_CACHE_MS = 60_000;

  invalidateCaches(): void {
    this.ruleOrderCache = null;
  }

  private getSortedRules(): InferenceRule[] {
    const now = Date.now(); // clock-ok: rule-order cache TTL (perf only; never persisted/hashed)
    if (this.ruleOrderCache && now - this.ruleOrderCache.ts < InferenceEngine.RULE_ORDER_CACHE_MS) {
      // Return cached order but use current rule set (rules may have been added)
      if (this.ruleOrderCache.rules.length === this.ctx.inferenceRules.length) {
        return this.ruleOrderCache.rules;
      }
    }

    // Compute per-rule stats from graph edges
    const ruleStats = new Map<string, { total: number; confirmed: number }>();
    this.ctx.graph.forEachEdge((_edgeId, attrs) => {
      if (!attrs.inferred_by_rule) return;
      const ruleId = attrs.inferred_by_rule as string;
      const stats = ruleStats.get(ruleId) || { total: 0, confirmed: 0 };
      stats.total++;
      if (attrs.confirmed_at) stats.confirmed++;
      ruleStats.set(ruleId, stats);
    });

    const sorted = [...this.ctx.inferenceRules].sort((a, b) => {
      const sa = ruleStats.get(a.id);
      const sb = ruleStats.get(b.id);
      const rateA = sa && sa.total > 0 ? sa.confirmed / sa.total : 0.5; // no data = neutral
      const rateB = sb && sb.total > 0 ? sb.confirmed / sb.total : 0.5;
      // Deprioritize rules with 0 confirmations and ≥5 attempts
      const penaltyA = (sa && sa.total >= 5 && sa.confirmed === 0) ? -1 : 0;
      const penaltyB = (sb && sb.total >= 5 && sb.confirmed === 0) ? -1 : 0;
      return (rateB + penaltyB) - (rateA + penaltyA);
    });

    this.ruleOrderCache = { rules: sorted, ts: now };
    return sorted;
  }

  private runRulesForRule(rule: InferenceRule, triggerNodeId: string): string[] {
    return this.applyRuleProductions(rule, triggerNodeId);
  }

  private hasMatchingEdge(nodeId: string, req: NonNullable<InferenceRule['trigger']['requires_edge']>): boolean {
    const edges = req.direction === 'inbound'
      ? this.ctx.graph.inEdges(nodeId) as string[]
      : this.ctx.graph.outEdges(nodeId) as string[];
    const allowedTypes = Array.isArray(req.type) ? new Set<string>(req.type) : null;
    for (const e of edges) {
      const attrs = this.ctx.graph.getEdgeAttributes(e);
      if (allowedTypes ? !allowedTypes.has(attrs.type) : attrs.type !== req.type) continue;
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
    const allowedTypes = Array.isArray(req.type) ? new Set<string>(req.type) : null;
    const peers: string[] = [];
    for (const e of edges) {
      const attrs = this.ctx.graph.getEdgeAttributes(e);
      if (allowedTypes ? !allowedTypes.has(attrs.type) : attrs.type !== req.type) continue;
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
    const now = this.ctx.nowIso(); // injected-clock: inferred-edge timestamps land in the golden hash
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
            ...production.properties as Record<string, unknown>,
            type: production.edge_type,
            confidence: production.confidence,
            discovered_at: now,
            discovered_by: `inference:${rule.id}`,
            tested: false,
            inferred_by_rule: rule.id,
            inferred_at: now,
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

  private resolveCredentialDomains(credNodeId: string): { domains: Set<string>; hasNonAuthoritativeDomain: boolean } {
    const domains = new Set<string>();
    let hasNonAuthoritativeDomain = false;

    // Seed from credential's own cred_domain property, but only when the source
    // is authoritative (explicit DOMAIN\user prefix or graph inference).
    // parser_context is a soft display hint and must NOT scope or trigger global fanout.
    const credNode = this.getNode(credNodeId);
    if (credNode?.cred_domain) {
      if (credNode.cred_domain_source === 'parser_context') {
        hasNonAuthoritativeDomain = true;
      } else {
        domains.add(String(credNode.cred_domain).toLowerCase());
      }
    }

    // Walk credential → (OWNS_CRED inbound from user) → check user properties + MEMBER_OF_DOMAIN edges
    for (const edge of this.ctx.graph.inEdges(credNodeId) as string[]) {
      if (this.ctx.graph.getEdgeAttributes(edge).type !== 'OWNS_CRED') continue;
      const ownerId = this.ctx.graph.source(edge);
      const ownerNode = this.getNode(ownerId);
      // Seed from owner user's domain_name property
      if (ownerNode?.domain_name) {
        domains.add(String(ownerNode.domain_name).toLowerCase());
      }
      // Also walk explicit MEMBER_OF_DOMAIN edges
      for (const domEdge of this.ctx.graph.outEdges(ownerId) as string[]) {
        if (this.ctx.graph.getEdgeAttributes(domEdge).type !== 'MEMBER_OF_DOMAIN') continue;
        const domId = this.ctx.graph.target(domEdge);
        const domNode = this.getNode(domId);
        const dName = domNode?.domain_name || domNode?.label;
        if (dName) domains.add(dName.toLowerCase());
      }
    }
    return { domains, hasNonAuthoritativeDomain };
  }

  private getParentHosts(serviceNodeId: string): string[] {
    const hosts: string[] = [];
    for (const edge of this.ctx.graph.inEdges(serviceNodeId) as string[]) {
      if (this.ctx.graph.getEdgeAttributes(edge).type === 'RUNS') {
        hosts.push(this.ctx.graph.source(edge));
      }
    }
    return hosts;
  }

  /**
   * F2: Compute the set of `user` nodes that can enroll in a given certificate
   * template. Walks CAN_ENROLL in-edges and transitively expands `group`
   * principals via MEMBER_OF. Fail-closed: returns [] if no principal has
   * CAN_ENROLL, never the universe of users.
   */
  private resolveEnrollablePrincipals(templateNodeId: string): string[] {
    const enrolleeIds = new Set<string>();
    const visited = new Set<string>();
    const queue: string[] = [];

    // Seed with direct CAN_ENROLL principals.
    for (const edge of this.ctx.graph.inEdges(templateNodeId) as string[]) {
      const attrs = this.ctx.graph.getEdgeAttributes(edge);
      if (attrs.type === 'CAN_ENROLL') {
        queue.push(this.ctx.graph.source(edge));
      }
    }

    while (queue.length > 0) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      const n = this.getNode(id);
      if (!n) continue;
      if (n.type === 'user') {
        enrolleeIds.add(id);
        continue;
      }
      if (n.type === 'group') {
        // Expand: anything that is MEMBER_OF this group.
        for (const edge of this.ctx.graph.inEdges(id) as string[]) {
          const a = this.ctx.graph.getEdgeAttributes(edge);
          if (a.type === 'MEMBER_OF') queue.push(this.ctx.graph.source(edge));
        }
      }
      // host/computer/cert principals: ignore for user-targeted ESC paths.
    }

    return Array.from(enrolleeIds);
  }

  private getNodeDomains(nodeId: string): string[] {
    const domains: string[] = [];
    for (const edge of this.ctx.graph.outEdges(nodeId) as string[]) {
      if (this.ctx.graph.getEdgeAttributes(edge).type !== 'MEMBER_OF_DOMAIN') continue;
      const domId = this.ctx.graph.target(edge);
      const domNode = this.getNode(domId);
      const dName = domNode?.domain_name || domNode?.label;
      if (dName) domains.push(dName.toLowerCase());
    }
    // Fallback: use domain_name property if no MEMBER_OF_DOMAIN edges found
    if (domains.length === 0) {
      const node = this.getNode(nodeId);
      if (node?.domain_name && typeof node.domain_name === 'string') {
        domains.push(node.domain_name.toLowerCase());
      }
    }
    return domains;
  }

  private inferOsFromServices(hostNodeId: string): void {
    const childServices = new Set<string>();
    const serviceBanners: string[] = [];
    for (const edge of this.ctx.graph.outEdges(hostNodeId) as string[]) {
      if (this.ctx.graph.getEdgeAttributes(edge).type === 'RUNS') {
        const svcNode = this.getNode(this.ctx.graph.target(edge));
        if (svcNode?.service_name) childServices.add(svcNode.service_name);
        if (svcNode?.version) serviceBanners.push(svcNode.version);
        if (svcNode?.banner) serviceBanners.push(svcNode.banner as string);
      }
    }
    if (childServices.size === 0) return;

    // Check banners for Samba — overrides service-based heuristics
    const hasSambaBanner = serviceBanners.some(b => /samba/i.test(b));

    let inferredOs: string | null = null;
    if (hasSambaBanner) {
      inferredOs = 'Linux';
    } else if ((childServices.has('kerberos') || childServices.has('ldap')) && childServices.has('smb')) {
      inferredOs = 'Windows Server';
    } else if (childServices.has('smb') && !childServices.has('ssh')) {
      inferredOs = 'Windows';
    } else if (childServices.has('ssh') && !childServices.has('smb') && !childServices.has('kerberos')) {
      inferredOs = 'Linux';
    }

    if (inferredOs) {
      const existing = this.getNode(hostNodeId);
      if (!existing) return;
      this.addNode({ ...existing, os: inferredOs, os_inferred: true });
      this.ctx.logEvent({
        description: `Inferred OS for ${hostNodeId}: ${inferredOs} (from service signatures)`,
        category: 'inference',
        event_type: 'inference_generated',
        result_classification: 'success',
        target_node_ids: [hostNodeId],
        details: { rule_id: 'rule-os-from-services', inferred_os: inferredOs, services: Array.from(childServices) },
      });
    }
  }

  private isConfirmedAssumeRoleEdge(attrs: EdgeProperties): boolean {
    return attrs.assumption_confirmed !== false || (attrs.tested === true && attrs.test_result === 'success');
  }

  private resolveSelector(selector: string, triggerNodeId: string, rule?: InferenceRule): string[] {
    const node = this.getNode(triggerNodeId);
    if (!node) return [];

    switch (selector) {
      case 'trigger_node':
      case 'trigger_service':
        return [triggerNodeId];

      case 'trigger_node_if_admin_panel_with_default_creds': {
        // S3-B4: gate for rule-admin-panel-default-creds. The webapp is the
        // SOURCE of a PATH_TO_OBJECTIVE edge only when:
        //   1. its URL or label contains an admin-panel-style path marker
        //      (/admin, /wp-admin, /manage, /console, /administrator), OR
        //      the webapp itself carries admin_interface=true, AND
        //   2. there is at least one usable default-credential candidate
        //      in the graph (either a generic default-guess or one keyed
        //      to a CMS type the webapp actually advertises).
        const url = String(node.url || node.label || '').toLowerCase();
        const adminMarker = /\/(?:admin(?:istrator)?|wp-admin|wp-login|manage|console|phpmyadmin|webmail|panel)(?:[\/?#]|$)/.test(url);
        const flagged = node.admin_interface === true;
        if (!adminMarker && !flagged) return [];
        // Verify a default-cred candidate exists. cms_type match is preferred
        // when the webapp advertises one; otherwise any default-guess cred
        // counts.
        const webappCms = typeof node.cms_type === 'string' ? node.cms_type.toLowerCase() : '';
        const creds = this.getNodesByType('credential')
          .filter(c => c.cred_is_default_guess === true && isCredentialUsableForAuth(c));
        if (creds.length === 0) return [];
        if (webappCms) {
          const matchesCms = creds.some(c => {
            const credCms = typeof c.cms_type === 'string' ? c.cms_type.toLowerCase() : '';
            return credCms === webappCms;
          });
          if (!matchesCms) return [];
        }
        return [triggerNodeId];
      }

      case 'trigger_node_if_rce_capable_dbms': {
        // S3-A2: SQLi -> RCE requires a DBMS that exposes a command/file
        // primitive (MySQL INTO OUTFILE, MSSQL xp_cmdshell, PostgreSQL COPY
        // TO PROGRAM). Other backends (SQLite, MS Access, etc.) can still
        // be SQLi-vulnerable but cannot promote to OS RCE through standard
        // SQLi techniques. If the parser stamped a recognised dbms or set
        // rce_capable=true, the trigger node propagates as the source;
        // otherwise the rule emits nothing.
        const dbmsRaw = node.dbms ?? node.dbms_type;
        const dbms = typeof dbmsRaw === 'string' ? dbmsRaw.toLowerCase() : '';
        const rceCapable = node.rce_capable === true;
        const knownCapable = /\b(mysql|mssql|microsoft sql server|postgres|postgresql)\b/.test(dbms);
        return (rceCapable || knownCapable) ? [triggerNodeId] : [];
      }

      case 'parent_host': {
        const hosts: string[] = [];
        this.ctx.graph.forEachInEdge(triggerNodeId, (_edge: string, attrs, src: string) => {
          if (attrs.type === 'RUNS') hosts.push(src);
        });
        if (node.type === 'host') hosts.push(triggerNodeId);
        // S3-A2: for vulnerability triggers, the host is two hops away
        // (vuln <- VULNERABLE_TO - webapp <- HOSTS - service <- RUNS - host).
        // Previously this selector fell through to [triggerNodeId] for
        // vulnerabilities, producing nonsensical vuln->vuln self-edges
        // that the schema later rejected. Now we walk the chain when the
        // trigger is a vulnerability, which also fixes
        // rule-sqli-credential-extraction as a side effect.
        if (hosts.length === 0 && node.type === 'vulnerability') {
          const webapps = new Set<string>();
          this.ctx.graph.forEachInEdge(triggerNodeId, (_edge: string, attrs, src: string) => {
            if (attrs.type === 'VULNERABLE_TO') webapps.add(src);
          });
          const services = new Set<string>();
          for (const webappId of webapps) {
            this.ctx.graph.forEachInEdge(webappId, (_edge: string, attrs, src: string) => {
              if (attrs.type === 'HOSTS') services.add(src);
            });
          }
          for (const serviceId of services) {
            this.ctx.graph.forEachInEdge(serviceId, (_edge: string, attrs, src: string) => {
              if (attrs.type === 'RUNS') hosts.push(src);
            });
          }
        }
        return hosts.length > 0 ? hosts : [triggerNodeId];
      }

      case 'domain_nodes':
        return this.getNodesByType('domain').map(n => n.id);

      case 'domain_users':
        return this.getNodesByType('user').filter(u => u.domain_joined !== false).map(n => n.id);

      case 'domain_admins_and_session_holders': {
        const candidates = new Set<string>();
        this.ctx.graph.forEachInEdge(triggerNodeId, (_edge: string, attrs, src: string) => {
          if ((attrs.type === 'HAS_SESSION' || attrs.type === 'ADMIN_TO') && attrs.confidence >= 0.7) {
            const srcNode = this.getNode(src);
            if (srcNode && (srcNode.type === 'user' || srcNode.type === 'group')) {
              candidates.add(src);
            }
          }
        });
        const ADMIN_GROUP_NAMES = new Set([
          'domain admins', 'enterprise admins', 'administrators',
          'schema admins', 'account operators', 'server operators',
        ]);
        this.ctx.graph.forEachNode((_id: string, _attrs) => {
          const attrs = _attrs as NodeProperties;
          if (attrs.type !== 'group') return;
          const gName = ((attrs.group_name as string) || attrs.label || '').toLowerCase().trim();
          if (ADMIN_GROUP_NAMES.has(gName)) {
            for (const edge of this.ctx.graph.inEdges(_id) as string[]) {
              if (this.ctx.graph.getEdgeAttributes(edge).type === 'MEMBER_OF') {
                candidates.add(this.ctx.graph.source(edge));
              }
            }
            candidates.add(_id);
          }
        });
        if (candidates.size > 0) return Array.from(candidates);
        // No admin/session-holder matches — return empty to avoid spurious global edges
        return [];
      }

      case 'domain_credentials':
        return this.getNodesByType('credential')
          .filter(c => isReusableDomainCredential(c))
          .map(n => n.id);

      case 'all_compromised': {
        const compromised: Set<string> = new Set();
        this.ctx.graph.forEachEdge((edge: string, attrs) => {
          if ((attrs.type === 'HAS_SESSION' || attrs.type === 'ADMIN_TO') && attrs.confidence >= 0.7) {
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

      case 'compatible_services_same_domain': {
        // Domain-scoped variant: only return services whose parent host is in
        // the same domain as the credential's owner.  Falls back to all
        // compatible services when no domain path can be resolved.
        if (!isCredentialUsableForAuth(node)) return [];
        const { domains: credDomains, hasNonAuthoritativeDomain } = this.resolveCredentialDomains(triggerNodeId);
        const allCompat = this.resolveSelector('compatible_services', triggerNodeId, rule);
        // Only fall back to global fanout when there is truly zero domain info.
        // Non-authoritative hints (parser_context) suppress global fallback —
        // these credentials wait for authoritative domain evidence before fanning out.
        if (credDomains.size === 0) {
          if (hasNonAuthoritativeDomain) return [];
          // Global fanout: cap to prevent frontier explosion on large graphs
          const maxGlobalFanout = ((this.ctx.config as unknown as Record<string, unknown>).max_global_fanout as number | undefined) ?? 50;
          if (allCompat.length > maxGlobalFanout) {
            this.ctx.logEvent({
              description: `Inference global fanout capped for credential ${triggerNodeId}`,
              category: 'inference',
              event_type: 'inference_generated',
              result_classification: 'partial',
              target_node_ids: [triggerNodeId],
              details: {
                rule_id: rule?.id,
                selector: 'compatible_services_same_domain',
                inference_status: 'fanout_capped',
                original_count: allCompat.length,
                returned_count: maxGlobalFanout,
              },
            });
            return allCompat.slice(0, maxGlobalFanout);
          }
          return allCompat;
        }
        return allCompat.filter(svcId => {
          const hostIds = this.getParentHosts(svcId);
          return hostIds.some(hId => {
            const hostDomains = this.getNodeDomains(hId);
            return hostDomains.some(d => credDomains.has(d));
          });
        });
      }

      case 'matching_domain': {
        // Hostname-suffix matching: given a trigger service node, find its
        // parent host's hostname and match against domain nodes whose name
        // is a suffix of that hostname.  Produces nothing if no match.
        const hosts = this.resolveSelector('parent_host', triggerNodeId, rule);
        const matched = new Set<string>();
        const domains = this.getNodesByType('domain');
        for (const hId of hosts) {
          const hostNode = this.getNode(hId);
          const hn = hostNode?.hostname || hostNode?.label || '';
          if (!hn || !hn.includes('.')) continue;
          const hnLower = hn.toLowerCase();
          for (const d of domains) {
            const dName = (d.domain_name || d.label || '').toLowerCase();
            if (dName && (hnLower === dName || hnLower.endsWith('.' + dName))) {
              matched.add(d.id);
            }
          }
        }
        return Array.from(matched);
      }

      case 'matching_user_domain': {
        const userDomainIds: string[] = [];
        for (const edge of this.ctx.graph.outEdges(triggerNodeId) as string[]) {
          if (this.ctx.graph.getEdgeAttributes(edge).type === 'MEMBER_OF_DOMAIN') {
            userDomainIds.push(this.ctx.graph.target(edge));
          }
        }
        if (userDomainIds.length > 0) return userDomainIds;
        if (node.domain_name && typeof node.domain_name === 'string') {
          const domNameLower = node.domain_name.toLowerCase();
          const allDomains = this.getNodesByType('domain');
          for (const d of allDomains) {
            const dName = (d.domain_name || d.label || '').toLowerCase();
            if (dName === domNameLower || domNameLower.endsWith('.' + dName) || dName.endsWith('.' + domNameLower)) {
              userDomainIds.push(d.id);
            }
          }
          if (userDomainIds.length > 0) return userDomainIds;
        }
        // No domain match found — return empty to avoid spurious global edges
        return [];
      }

      case 'enrollable_users':
        // F2: only users who actually have CAN_ENROLL on this template
        // (directly or via group membership) are enrollable. The previous
        // implementation returned every user in the graph, producing
        // spurious ESC paths.
        return this.resolveEnrollablePrincipals(triggerNodeId);

      case 'enrollable_users_if_client_auth': {
        // F2 fail-closed: if the template has no recorded EKU info we MUST
        // NOT assume client-auth is allowed. Read both the canonical
        // `ekus` (array) and legacy `eku` field. Empty/missing → no path.
        const ekuRaw = (node.ekus ?? node.eku) as unknown;
        const ekus: string[] = Array.isArray(ekuRaw)
          ? ekuRaw.filter((e): e is string => typeof e === 'string')
          : typeof ekuRaw === 'string' ? [ekuRaw] : [];
        if (ekus.length === 0) return [];
        const hasClientAuth = ekus.some(e =>
          e === '1.3.6.1.5.5.7.3.2'
          || e === '2.5.29.37.0' // anyExtendedKeyUsage
          || e === '1.3.6.1.5.2.3.4' // PKINIT client auth
          || e === '1.3.6.1.4.1.311.20.2.2' // smartcard logon
          || e.toLowerCase().includes('client authentication')
          || e.toLowerCase().includes('smartcard logon')
          || e.toLowerCase().includes('any purpose')
        );
        if (!hasClientAuth) return [];
        // S2-4 (F1-4): templates requiring manager approval are NOT exploitable
        // via ESC1/ESC2/ESC3 — the abuse depends on automatic issuance. When
        // certipy reports the property as true we suppress the rule emit; when
        // the property is missing or false we proceed (parser convention is to
        // omit when absent rather than emit false).
        if (node.manager_approval_required === true) return [];
        return this.resolveEnrollablePrincipals(triggerNodeId);
      }

      case 'enrollable_users_if_issuance_policy': {
        // ESC13: Only return enrollable users if the template has both issuance_policy_oid and issuance_policy_group_link set
        if (!node.issuance_policy_oid || !node.issuance_policy_group_link) return [];
        return this.resolveEnrollablePrincipals(triggerNodeId);
      }

      case 'edge_peers': {
        if (!rule?.trigger.requires_edge) return [];
        return this.resolveEdgePeers(triggerNodeId, rule.trigger.requires_edge);
      }

      case 'session_holders_on_host': {
        // For the trigger host, find source nodes of inbound HAS_SESSION edges
        const holders: string[] = [];
        this.ctx.graph.forEachInEdge(triggerNodeId, (_edge: string, attrs, src: string) => {
          if (attrs.type === 'HAS_SESSION' && attrs.confidence >= 0.7) {
            holders.push(src);
          }
        });
        return holders;
      }

      case 'ssh_services':
        return this.getNodesByType('service')
          .filter(s => s.service_name === 'ssh')
          .map(n => n.id);

      case 'ssh_services_related': {
        const allSsh = this.getNodesByType('service')
          .filter(s => s.service_name === 'ssh');
        const ownerHosts = new Set<string>();
        this.ctx.graph.forEachInEdge(triggerNodeId, (_edge: string, attrs, src: string) => {
          if (attrs.type === 'OWNS_CRED') {
            this.ctx.graph.forEachOutEdge(src, (_e2: string, a2, _s2: string, tgt: string) => {
              if (a2.type === 'HAS_SESSION') ownerHosts.add(tgt);
            });
          }
        });
        if (ownerHosts.size === 0) return allSsh.map(n => n.id);
        const related = allSsh.filter(s => {
          const parents = this.getParentHosts(s.id);
          return parents.some(h => ownerHosts.has(h));
        });
        return related.length > 0 ? related.map(n => n.id) : allSsh.map(n => n.id);
      }

      case 'delegation_targets': {
        const delegateList = node.allowed_to_delegate_to as string[] | undefined;
        if (!delegateList || delegateList.length === 0) {
          // No delegation list — return empty to avoid spurious global edges
          return [];
        }
        const targets = new Set<string>();
        const allHosts = this.getNodesByType('host');
        const allServices = this.getNodesByType('service');
        for (const spn of delegateList) {
          const spnLower = spn.toLowerCase();
          const slashIdx = spnLower.indexOf('/');
          const hostPart = slashIdx >= 0 ? spnLower.substring(slashIdx + 1).split(':')[0] : spnLower;
          for (const h of allHosts) {
            const hn = (h.hostname || h.label || '').toLowerCase();
            if (hn && (hn === hostPart || hn.startsWith(hostPart + '.'))) targets.add(h.id);
          }
          for (const s of allServices) {
            const sLabel = (s.label || '').toLowerCase();
            if (sLabel.includes(hostPart)) targets.add(s.id);
          }
        }
        return targets.size > 0 ? Array.from(targets) : [];
      }

      case 'all_usable_credentials':
        return this.getNodesByType('credential')
          .filter(c => isCredentialUsableForAuth(c))
          .map(n => n.id);

      case 'web_form_credentials':
        return this.getNodesByType('credential')
          .filter(c => isCredentialUsableForAuth(c) && getCredentialMaterialKind(c) === 'plaintext_password' && !c.cred_is_default_guess)
          .map(n => n.id);

      case 'default_credential_candidates':
        return this.getNodesByType('credential')
          .filter(c => c.cred_is_default_guess === true && isCredentialUsableForAuth(c))
          .map(n => n.id);

      case 'cms_credentials': {
        // Credentials with default guess flag where a webapp with matching cms_type exists
        const webapps = this.getNodesByType('webapp');
        const cmsTypes = new Set(webapps.map(w => (w.cms_type || '').toLowerCase()).filter(Boolean));
        if (cmsTypes.size === 0) return [];
        return this.getNodesByType('credential')
          .filter(c => c.cred_is_default_guess === true && isCredentialUsableForAuth(c))
          .map(n => n.id);
      }

      case 'hosted_webapps': {
        // For a credential trigger, find webapps hosted by services the credential is VALID_ON
        const webappIds: string[] = [];
        this.ctx.graph.forEachOutEdge(triggerNodeId, (_edge: string, attrs, _src: string, tgt: string) => {
          if (attrs.type !== 'VALID_ON') return;
          // tgt is a service — find webapps it hosts
          this.ctx.graph.forEachOutEdge(tgt, (_e2: string, a2, _s2: string, tgt2: string) => {
            if (a2.type === 'HOSTS') webappIds.push(tgt2);
          });
        });
        return webappIds;
      }

      case 'vulnerable_webapps': {
        // For a vulnerability trigger, find webapps that have VULNERABLE_TO pointing to it
        const webappIds: string[] = [];
        this.ctx.graph.forEachInEdge(triggerNodeId, (_edge: string, attrs, src: string) => {
          if (attrs.type !== 'VULNERABLE_TO') return;
          const srcNode = this.getNode(src);
          if (srcNode?.type === 'webapp' || srcNode?.type === 'api_endpoint') {
            webappIds.push(src);
          }
        });
        return webappIds;
      }

      case 'linked_server_hosts': {
        // Resolve linked_servers array on trigger service node to host nodes
        const triggerSvc = this.getNode(triggerNodeId);
        if (!triggerSvc?.linked_servers?.length) return [];
        const allHosts = this.getNodesByType('host');
        const matched = new Set<string>();
        for (const linked of triggerSvc.linked_servers) {
          const linkedLower = linked.toLowerCase();
          for (const h of allHosts) {
            const hn = (h.hostname || h.label || '').toLowerCase();
            const ip = h.ip || '';
            if ((hn && hn === linkedLower) || (ip && ip === linked)) {
              matched.add(h.id);
            }
          }
        }
        return Array.from(matched);
      }

      case 'target_user_credentials': {
        // Find credentials owned by the trigger user (outbound OWNS_CRED edges)
        const creds: string[] = [];
        for (const edge of this.ctx.graph.outEdges(triggerNodeId) as string[]) {
          if (this.ctx.graph.getEdgeAttributes(edge).type === 'OWNS_CRED') {
            creds.push(this.ctx.graph.target(edge));
          }
        }
        return creds;
      }

      case 'gpo_linked_hosts': {
        // Traverse RELATED edges from the GPO to find linked OUs/containers,
        // then find hosts that are MEMBER_OF those OUs (or directly linked).
        const linkedHosts = new Set<string>();
        const visited = new Set<string>();
        const queue: Array<{ id: string; depth: number }> = [{ id: triggerNodeId, depth: 0 }];
        while (queue.length > 0) {
          const { id: current, depth: curDepth } = queue.shift()!;
          if (visited.has(current)) continue;
          visited.add(current);
          if (curDepth >= 10) continue;
          const currentNode = this.getNode(current);
          if (currentNode?.type === 'host') {
            linkedHosts.add(current);
            continue;
          }
          // Follow RELATED (GPO→OU) and MEMBER_OF (OU contains child)
          for (const edge of this.ctx.graph.outEdges(current) as string[]) {
            const eAttrs = this.ctx.graph.getEdgeAttributes(edge);
            if (eAttrs.type === 'RELATED' || eAttrs.type === 'MEMBER_OF') {
              queue.push({ id: this.ctx.graph.target(edge), depth: curDepth + 1 });
            }
          }
          // Also check inbound MEMBER_OF (child → container)
          for (const edge of this.ctx.graph.inEdges(current) as string[]) {
            const eAttrs = this.ctx.graph.getEdgeAttributes(edge);
            if (eAttrs.type === 'MEMBER_OF') {
              const src = this.ctx.graph.source(edge);
              const srcNode = this.getNode(src);
              if (srcNode?.type === 'host') linkedHosts.add(src);
            }
          }
        }
        return Array.from(linkedHosts);
      }

      case 'nearest_objective': {
        // Return objective nodes — used by cloud rules that create PATH_TO_OBJECTIVE edges.
        // For overprivileged_policy rule, also gate on the trigger having wildcard actions.
        if (rule?.id === 'rule-overprivileged-policy') {
          const actions = (node.actions as string[] | undefined) || [];
          const hasWildcard = actions.some(a => a === '*:*' || a === '*' || a.endsWith(':*'));
          if (!hasWildcard) return [];
        }
        return this.getNodesByType('objective').map(n => n.id);
      }

      case 'policy_holders': {
        const targets: string[] = [];
        this.ctx.graph.forEachInEdge(triggerNodeId, (_edge: string, attrs, src: string) => {
          if (attrs.type !== 'HAS_POLICY') return;
          const srcNode = this.getNode(src);
          if (srcNode?.type === 'cloud_identity' || srcNode?.type === 'group') {
            targets.push(src);
          }
        });
        return targets;
      }

      case 'cross_account_roles': {
        // Find cloud_identity nodes reachable via ASSUMES_ROLE that have a different cloud_account
        const srcAccount = node.cloud_account;
        if (!srcAccount) return [];
        const targets: string[] = [];
        this.ctx.graph.forEachOutEdge(triggerNodeId, (_edge: string, attrs, _src: string, tgt: string) => {
          if (attrs.type !== 'ASSUMES_ROLE') return;
          if (!this.isConfirmedAssumeRoleEdge(attrs)) return;
          const tgtNode = this.getNode(tgt);
          if (tgtNode?.cloud_account && tgtNode.cloud_account !== srcAccount) {
            targets.push(tgt);
          }
        });
        return targets;
      }

      case 'transitive_assumed_roles': {
        // BFS through ASSUMES_ROLE edges (2+ hops) crossing account boundaries
        const srcAccount = node.cloud_account;
        if (!srcAccount) return [];
        const visited = new Set<string>([triggerNodeId]);
        const queue = [triggerNodeId];
        const crossAccountTargets: string[] = [];
        let depth = 0;
        let frontier = queue.length;
        while (queue.length > 0 && depth < 5) {
          const current = queue.shift()!;
          frontier--;
          this.ctx.graph.forEachOutEdge(current, (_edge: string, attrs, _src: string, tgt: string) => {
            if (attrs.type !== 'ASSUMES_ROLE') return;
            if (!this.isConfirmedAssumeRoleEdge(attrs)) return;
            if (visited.has(tgt)) return;
            visited.add(tgt);
            queue.push(tgt);
            const tgtNode = this.getNode(tgt);
            if (tgtNode?.cloud_account && tgtNode.cloud_account !== srcAccount) {
              crossAccountTargets.push(tgt);
            }
          });
          if (frontier === 0) { depth++; frontier = queue.length; }
        }
        return crossAccountTargets;
      }

      case 'imds_managed_identity': {
        // Follow MANAGED_BY outbound from a cloud_resource (EC2) to find the identity it can pivot to
        const targets: string[] = [];
        this.ctx.graph.forEachOutEdge(triggerNodeId, (_edge: string, attrs, _src: string, tgt: string) => {
          if (attrs.type !== 'MANAGED_BY') return;
          const tgtNode = this.getNode(tgt);
          if (tgtNode?.type === 'cloud_identity') {
            targets.push(tgt);
          }
        });
        return targets;
      }

      case 'lambda_attached_role': {
        // Follow MANAGED_BY from a Lambda resource to its execution role
        if (node.resource_type !== 'lambda') return [];
        const targets: string[] = [];
        this.ctx.graph.forEachOutEdge(triggerNodeId, (_edge: string, attrs, _src: string, tgt: string) => {
          if (attrs.type !== 'MANAGED_BY') return;
          const tgtNode = this.getNode(tgt);
          if (tgtNode?.type === 'cloud_identity') {
            targets.push(tgt);
          }
        });
        return targets;
      }

      case 'credentials_same_username': {
        // Find other credentials with the same cred_user property (credential reuse detection)
        const credUser = node.cred_user;
        if (!credUser || typeof credUser !== 'string') return [];
        const credUserLower = credUser.toLowerCase();
        const matches: string[] = [];
        this.ctx.graph.forEachNode((id: string, attrs) => {
          if (id === triggerNodeId) return;
          if (attrs.type !== 'credential') return;
          const otherUser = attrs.cred_user;
          if (typeof otherUser === 'string' && otherUser.toLowerCase() === credUserLower) {
            matches.push(id);
          }
        });
        return matches;
      }

      case 'ca_for_template': {
        // Resolve the CA that issued this cert_template via ISSUED_BY edge
        const cas: string[] = [];
        this.ctx.graph.forEachOutEdge(triggerNodeId, (_edge: string, attrs, _src: string, tgt: string) => {
          if (attrs.type === 'ISSUED_BY') cas.push(tgt);
        });
        return cas;
      }

      case 'writeable_by_peers': {
        // Find principals with WRITEABLE_BY, GENERIC_ALL, GENERIC_WRITE, WRITE_OWNER, or WRITE_DACL on the trigger node
        const peers = new Set<string>();
        const WRITE_TYPES = new Set(['WRITEABLE_BY', 'GENERIC_ALL', 'GENERIC_WRITE', 'WRITE_OWNER', 'WRITE_DACL']);
        this.ctx.graph.forEachInEdge(triggerNodeId, (_edge: string, attrs, src: string) => {
          if (WRITE_TYPES.has(attrs.type)) peers.add(src);
        });
        return Array.from(peers);
      }

      case 'manage_ca_peers': {
        // Find principals with explicit CA management rights (ESC7).
        // MANAGE_CA / MANAGE_CERTIFICATES are the actual abuse paths;
        // GENERIC_ALL / WRITE_DACL are kept as broader-permission fallbacks
        // because they grant the ability to grant the management rights.
        const peers = new Set<string>();
        const ESC7_TYPES = new Set(['MANAGE_CA', 'MANAGE_CERTIFICATES', 'GENERIC_ALL', 'WRITE_DACL']);
        this.ctx.graph.forEachInEdge(triggerNodeId, (_edge: string, attrs, src: string) => {
          if (ESC7_TYPES.has(attrs.type)) peers.add(src);
        });
        return Array.from(peers);
      }

      case 'ca_host_compromised_peers': {
        // ESC12: Find users with shell access to the host that runs this CA.
        // Strategy: match CA label/ca_name against host hostname/label, then find HAS_SESSION sources.
        const caLabel = (node.ca_name || node.label || '').toLowerCase();
        if (!caLabel) return [];
        const sessionHolders = new Set<string>();
        // Also check OPERATES_CA edges: domain → CA; find hosts in that domain
        const caHosts = new Set<string>();
        this.ctx.graph.forEachNode((id: string, attrs) => {
          if (attrs.type !== 'host') return;
          const hn = (attrs.hostname || attrs.label || '').toLowerCase();
          // Match if the host's first hostname component matches the CA's first component
          if (hn && hn.split('.')[0] === caLabel.split('.')[0]) caHosts.add(id);
          // Or exact DNS match / suffix match
          if (hn && (caLabel === hn || caLabel.startsWith(hn + '.'))) caHosts.add(id);
        });
        for (const hostId of caHosts) {
          this.ctx.graph.forEachInEdge(hostId, (_edge: string, attrs, src: string) => {
            if (attrs.type === 'HAS_SESSION' && attrs.confidence >= 0.7) {
              sessionHolders.add(src);
            }
          });
        }
        return Array.from(sessionHolders);
      }

      case 'http_services_via_ca': {
        // Find HTTP/HTTPS services on hosts connected to the trigger CA node via OPERATES_CA or ISSUED_BY edges
        // Used for ESC8 (NTLM relay to AD CS HTTP endpoints)
        const caHostIds = new Set<string>();
        // Collect hosts that operate or are related to this CA
        this.ctx.graph.forEachInEdge(triggerNodeId, (_edge: string, attrs, src: string) => {
          if (attrs.type === 'OPERATES_CA' || attrs.type === 'ISSUED_BY') {
            const srcNode = this.getNode(src);
            if (srcNode?.type === 'host') caHostIds.add(src);
          }
        });
        this.ctx.graph.forEachOutEdge(triggerNodeId, (_edge: string, attrs, _src: string, tgt: string) => {
          if (attrs.type === 'OPERATES_CA' || attrs.type === 'ISSUED_BY') {
            const tgtNode = this.getNode(tgt);
            if (tgtNode?.type === 'host') caHostIds.add(tgt);
          }
        });
        // If no CA host found, fall back to trigger node's parent host
        if (caHostIds.size === 0) {
          const triggerNode = this.getNode(triggerNodeId);
          if (triggerNode?.type === 'host') caHostIds.add(triggerNodeId);
        }
        // Collect HTTP/HTTPS services on those hosts
        const httpSvcs: string[] = [];
        for (const hId of caHostIds) {
          this.ctx.graph.forEachOutEdge(hId, (_edge: string, attrs, _src: string, tgt: string) => {
            if (attrs.type === 'RUNS') {
              const svcNode = this.getNode(tgt);
              if (svcNode?.type === 'service' && (svcNode.service_name === 'http' || svcNode.service_name === 'https')) {
                httpSvcs.push(tgt);
              }
            }
          });
        }
        return httpSvcs;
      }

      case 'orphan_service_host': {
        // Resolve the parent host for a service node when no RUNS edge exists yet.
        // Extracts IP from service node ID pattern: svc-{ip}-{port}
        const existingHosts = this.getParentHosts(triggerNodeId);
        if (existingHosts.length > 0) return []; // RUNS edge already exists — don't duplicate
        const svcMatch = triggerNodeId.match(/^svc-(\d+-\d+-\d+-\d+)-/);
        if (!svcMatch) return [];
        const ip = svcMatch[1].replace(/-/g, '.');
        const hostNodeId = `host-${svcMatch[1]}`;
        if (this.ctx.graph.hasNode(hostNodeId)) return [hostNodeId];
        // Fallback: search for host with matching IP
        const allHosts = this.getNodesByType('host');
        const matched = allHosts.filter(h => h.ip === ip);
        return matched.map(h => h.id);
      }

      case 'matching_user_for_cred': {
        // Find user nodes whose sam_account_name or label matches the credential's cred_user
        const credUser = node.cred_user;
        if (!credUser || typeof credUser !== 'string') return [];
        // Skip if OWNS_CRED edge already exists (from any user to this credential)
        const existingOwners = (this.ctx.graph.inEdges(triggerNodeId) as string[]).some(e =>
          this.ctx.graph.getEdgeAttributes(e).type === 'OWNS_CRED'
        );
        if (existingOwners) return [];
        const credUserLower = credUser.toLowerCase();
        const allUsers = this.getNodesByType('user');
        return allUsers
          .filter(u => {
            const sam = String(u.sam_account_name || u.label || '').toLowerCase();
            return sam === credUserLower;
          })
          .map(u => u.id);
      }

      case 'via_mock_service': {
        // Operator-controlled listener attribution: if the credential
        // carries `via_mock_service_id` (set by parsers / report_finding
        // for captures that came in through a mock_service), resolve it
        // to that node so the BAITED edge can be emitted.
        const mockId = node.via_mock_service_id;
        if (typeof mockId !== 'string' || !mockId) return [];
        const mockNode = this.getNode(mockId);
        if (!mockNode || mockNode.type !== 'mock_service') return [];
        return [mockId];
      }

      default:
        console.error(`[InferenceEngine] Unknown selector: '${selector}' — check inference rule configuration`);
        return [];
    }
  }
}
