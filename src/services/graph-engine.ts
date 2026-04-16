// ============================================================
// Overwatch — Graph Engine
// Engagement state as a directed property graph
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import { createOverwatchGraph } from './graphology-types.js';
import { existsSync } from 'fs';
import { isIpInCidr, isUrlInScope, isCloudResourceInScope, isHostExcluded, isHostInScope as isScopedHostInScope } from './cidr.js';
import { EngineContext } from './engine-context.js';
import type { ActivityLogEntry, GraphUpdateCallback, GraphUpdateDetail, OverwatchGraph } from './engine-context.js';
import { StatePersistence } from './state-persistence.js';
import { AgentManager } from './agent-manager.js';
import { InferenceEngine } from './inference-engine.js';
import { PathAnalyzer } from './path-analyzer.js';
import type { PathOptimize, PathResult } from './path-analyzer.js';
import { FrontierComputer } from './frontier.js';
import { ChainScorer } from './chain-scorer.js';
import { CampaignPlanner } from './campaign-planner.js';
import { getCredentialDisplayKind, isCredentialUsableForAuth } from './credential-utils.js';
import { runHealthChecks, summarizeHealthReport, hasADContext, contextualFilterHealthReport } from './graph-health.js';
import { summarizeInlineLabReadiness } from './lab-preflight.js';
import { normalizeFindingNode, validateFindingNode } from './finding-validation.js';
import { validateEdgeEndpoints } from './graph-schema.js';
import { normalizeNodeProvenance } from './provenance-utils.js';
import { IdentityReconciler } from './identity-reconciliation.js';
import { detectCommunities, communityStats } from './community-detection.js';
import { EvidenceStore } from './evidence-store.js';
import { BUILTIN_RULES } from './builtin-inference-rules.js';
import { BloodHoundPathEnricher } from './bloodhound-paths.js';
import type { HVTResult, PreComputedPath } from './bloodhound-paths.js';
import { KnowledgeBase } from './knowledge-base.js';
import { WebChainEnricher } from './web-attack-chains.js';
import type { MatchedChain } from './web-attack-chains.js';
import type { OpsecContext } from './opsec-tracker.js';
import {
  inferPivotReachability as _inferPivotReachability,
  inferDefaultCredentials as _inferDefaultCredentials,
  inferImdsv1Ssrf as _inferImdsv1Ssrf,
  inferManagedIdentityPivot as _inferManagedIdentityPivot,
  degradeExpiredCredentialEdges as _degradeExpiredCredentialEdges,
} from './imperative-inference.js';
import type { ImperativeInferenceHost, PivotReachabilityResult } from './imperative-inference.js';
import {
  updateScope as _updateScope,
  collectScopeSuggestions as _collectScopeSuggestions,
  previewScopeChange as _previewScopeChange,
} from './scope-manager.js';
import type { ScopeManagerHost } from './scope-manager.js';
import { ingestFindingImpl } from './finding-ingestion.js';
import type { FindingIngestionHost } from './finding-ingestion.js';
import { queryGraphImpl } from './graph-query.js';
import { inferProfile } from '../types.js';
import type {
  NodeProperties, EdgeProperties, NodeType, EdgeType,
  EngagementConfig, EngagementState, FrontierItem,
  Finding, InferenceRule, GraphQuery, GraphQueryResult,
  AgentTask, ExportedGraph, HealthReport, GraphCorrectionOperation,
  ScopeSuggestion, PhaseStatus, PhaseCriterion,
} from '../types.js';

function createGraph(): OverwatchGraph {
  return createOverwatchGraph();
}

// --- Edge types traversable in both directions for attack-path planning ---
// These represent relationships where the attacker can logically move in either
// direction (e.g., HAS_SESSION means user has access to host, traversable from
// either end). All other edge types remain strictly directional.
const BIDIRECTIONAL_EDGE_TYPES: Set<EdgeType> = new Set([
  'HAS_SESSION', 'ADMIN_TO', 'CAN_RDPINTO', 'CAN_PSREMOTE',
  'OWNS_CRED', 'VALID_ON',
  'MEMBER_OF', 'MEMBER_OF_DOMAIN',
  'RELATED', 'SAME_DOMAIN', 'TRUSTS',
  'ASSUMES_ROLE', 'MANAGED_BY',
  'AUTH_BYPASS',
]);

export { GraphUpdateCallback };

export class GraphEngine {
  private ctx: EngineContext;
  private persistence: StatePersistence;
  private agentMgr: AgentManager;
  private inference: InferenceEngine;
  private paths: PathAnalyzer;
  private frontierComputer: FrontierComputer;
  private chainScorer: ChainScorer;
  private campaignPlanner: CampaignPlanner;
  private reconciler: IdentityReconciler;
  private healthReportCache: HealthReport | null = null;
  private frontierCache: { passed: FrontierItem[]; all: FrontierItem[]; campaigns: import('../types.js').Campaign[] } | null = null;
  private evidenceStore: EvidenceStore;
  private kb: KnowledgeBase | null = null;

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
    this.chainScorer = new ChainScorer(
      this.ctx,
      this.hopsToNearestObjective.bind(this),
    );
    this.campaignPlanner = new CampaignPlanner(this.ctx);
    this.reconciler = new IdentityReconciler(this.ctx.graph, {
      getNode: this.getNode.bind(this),
      addEdge: this.addEdge.bind(this),
      logActionEvent: this.logActionEvent.bind(this),
      invalidatePathGraph: this.invalidatePathGraph.bind(this),
    });
    this.evidenceStore = new EvidenceStore(filePath);

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

    // Reconcile runtime-dependent state on startup
    this.reconcileSessionEdgesOnStartup();
    this.agentMgr.reconcileOnStartup();
    this.persist();
  }

  /** Lazy-load the cross-engagement knowledge base (returns null if file not found). */
  getKB(): KnowledgeBase | null {
    if (!this.kb) {
      try {
        this.kb = new KnowledgeBase();
      } catch {
        this.kb = null;
      }
    }
    return this.kb;
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

    // Create subnet nodes from scoped CIDRs
    for (const cidr of this.ctx.config.scope.cidrs) {
      const subnetId = `subnet-${cidr.replace(/[./]/g, '-')}`;
      if (!this.ctx.graph.hasNode(subnetId)) {
        this.addNode({
          id: subnetId,
          type: 'subnet',
          label: cidr,
          subnet_cidr: cidr,
          discovered_at: now,
          first_seen_at: now,
          last_seen_at: now,
          confidence: 1.0
        });
      }
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
  // Cold Store Helpers
  // =============================================

  private findSubnetCidr(ip?: string): string | undefined {
    if (!ip) return undefined;
    for (const cidr of this.ctx.config.scope.cidrs) {
      if (isIpInCidr(ip, cidr)) return cidr;
    }
    return undefined;
  }

  // =============================================
  // Node / Edge Operations
  // =============================================

  addNode(props: NodeProperties): string {
    if (this.ctx.graph.hasNode(props.id)) {
      // Merge properties
      this.ctx.graph.mergeNodeAttributes(props.id, props as Partial<NodeProperties>);
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
        this.ctx.graph.mergeEdgeAttributes(edgeId, props as Partial<EdgeProperties>);
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
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('already exists')) {
        const fallbackId = `${edgeId}-${uuidv4().slice(0, 8)}`;
        return { id: this.ctx.graph.addEdgeWithKey(fallbackId, source, target, props), isNew: true };
      }
      throw err;
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
    this.ctx.graph.replaceNodeAttributes(nodeId, nextAttrs as NodeProperties);
    this.invalidateHealthReport();
    return this.ctx.graph.getNodeAttributes(nodeId);
  }

  getNode(id: string): NodeProperties | null {
    if (!this.ctx.graph.hasNode(id)) return null;
    return this.ctx.graph.getNodeAttributes(id);
  }

  getNodesByType(type: NodeType): NodeProperties[] {
    const results: NodeProperties[] = [];
    this.ctx.graph.forEachNode((_id, attrs) => {
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
    return ingestFindingImpl(this.findingIngestionHost, finding);
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

  private get findingIngestionHost(): FindingIngestionHost {
    return {
      ctx: this.ctx,
      addNode: this.addNode.bind(this),
      addEdge: this.addEdge.bind(this),
      getNode: this.getNode.bind(this),
      log: this.log.bind(this),
      logActionEvent: this.logActionEvent.bind(this),
      findSubnetCidr: this.findSubnetCidr.bind(this),
      reconcileCanonicalNode: this.reconciler.reconcileCanonicalNode.bind(this.reconciler),
      runInferenceRules: this.runInferenceRules.bind(this),
      inferPivotReachability: this.inferPivotReachability.bind(this),
      inferDefaultCredentials: this.inferDefaultCredentials.bind(this),
      inferImdsv1Ssrf: this.inferImdsv1Ssrf.bind(this),
      inferManagedIdentityPivot: this.inferManagedIdentityPivot.bind(this),
      degradeExpiredCredentialEdges: this.degradeExpiredCredentialEdges.bind(this),
      evaluateObjectives: this.evaluateObjectives.bind(this),
      persist: this.persist.bind(this),
      propertiesChanged: this.propertiesChanged.bind(this),
      invalidateFrontierCache: this.invalidateFrontierCache.bind(this),
    };
  }

  private get imperativeHost(): ImperativeInferenceHost {
    return {
      ctx: this.ctx,
      addNode: this.addNode.bind(this),
      addEdge: this.addEdge.bind(this),
      getNode: this.getNode.bind(this),
      log: this.log.bind(this),
      invalidateHealthReport: this.invalidateHealthReport.bind(this),
    };
  }

  private inferPivotReachability(triggerHostId: string): PivotReachabilityResult {
    return _inferPivotReachability(this.imperativeHost, triggerHostId);
  }

  private inferDefaultCredentials(webappNodeIds: Set<string>): string[] {
    return _inferDefaultCredentials(this.imperativeHost, webappNodeIds);
  }

  private inferImdsv1Ssrf(webappNodeIds: Set<string>): string[] {
    return _inferImdsv1Ssrf(this.imperativeHost, webappNodeIds);
  }

  private inferManagedIdentityPivot(hostNodeIds: Set<string>): string[] {
    return _inferManagedIdentityPivot(this.imperativeHost, hostNodeIds);
  }

  degradeExpiredCredentialEdges(credNodeId: string): string[] {
    return _degradeExpiredCredentialEdges(this.imperativeHost, credNodeId);
  }

  // =============================================
  // Frontier Computation (delegated to FrontierComputer)
  // =============================================

  computeFrontier(): FrontierItem[] {
    if (!this.frontierCache) {
      // Inject KB for technique-aware scoring
      this.frontierComputer.setKB(this.getKB());
      const all = this.frontierComputer.compute();
      // Enrich frontier items with community data
      const communities = this.getCommunities();
      if (communities.size > 0) {
        // Count frontier items per community for community_unexplored_count
        const communityFrontierCounts = new Map<number, number>();
        for (const item of all) {
          const targetId = item.node_id || item.edge_target;
          if (targetId) {
            const cid = communities.get(targetId);
            if (cid !== undefined) {
              communityFrontierCounts.set(cid, (communityFrontierCounts.get(cid) || 0) + 1);
            }
          }
        }
        for (const item of all) {
          const targetId = item.node_id || item.edge_target;
          if (targetId) {
            const cid = communities.get(targetId);
            if (cid !== undefined) {
              item.community_id = cid;
              item.community_unexplored_count = communityFrontierCounts.get(cid);
            }
          }
        }
      }
      // Enrich frontier items with chain scoring data
      const chainGroups = this.chainScorer.scoreChains(all);

      // Generate campaigns from frontier + chain groups (phase-aware)
      const campaigns = this.campaignPlanner.generateCampaigns(all, chainGroups, this.getCurrentPhaseId());

      const { passed } = this.filterFrontier(all);
      this.frontierCache = { all, passed, campaigns };
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
  // Campaign Management (delegated to CampaignPlanner)
  // =============================================

  getCampaigns(): import('../types.js').Campaign[] {
    if (!this.frontierCache) {
      this.computeFrontier();
    }
    return this.frontierCache!.campaigns;
  }

  getCampaign(id: string): import('../types.js').Campaign | null {
    return this.campaignPlanner.getCampaign(id);
  }

  listCampaigns(filter?: { status?: string }): import('../types.js').Campaign[] {
    return this.campaignPlanner.listCampaigns(filter);
  }

  pauseCampaign(id: string): import('../types.js').Campaign | null {
    return this.campaignPlanner.pauseCampaign(id);
  }

  resumeCampaign(id: string): import('../types.js').Campaign | null {
    return this.campaignPlanner.resumeCampaign(id);
  }

  abortCampaign(id: string): import('../types.js').Campaign | null {
    return this.campaignPlanner.abortCampaign(id);
  }

  activateCampaign(id: string): import('../types.js').Campaign | null {
    return this.campaignPlanner.activateCampaign(id);
  }

  createCampaign(params: import('../services/campaign-planner.js').CreateCampaignParams): import('../types.js').Campaign {
    return this.campaignPlanner.createCampaign(params);
  }

  updateCampaign(id: string, patch: import('../services/campaign-planner.js').UpdateCampaignParams): import('../types.js').Campaign | null {
    return this.campaignPlanner.updateCampaign(id, patch);
  }

  deleteCampaign(id: string): boolean {
    return this.campaignPlanner.deleteCampaign(id);
  }

  cloneCampaign(id: string): import('../types.js').Campaign | null {
    return this.campaignPlanner.cloneCampaign(id);
  }

  updateCampaignProgress(
    campaignId: string, frontierItemId: string, result: 'success' | 'failure', findingId?: string,
  ): import('../types.js').Campaign | null {
    return this.campaignPlanner.updateCampaignProgress(campaignId, frontierItemId, result, findingId);
  }

  checkCampaignAbortConditions(campaignId: string): { should_abort: boolean; reason?: string } {
    return this.campaignPlanner.checkAbortConditions(campaignId);
  }

  findCampaignForItem(frontierItemId: string): import('../types.js').Campaign | null {
    return this.campaignPlanner.findCampaignForItem(frontierItemId);
  }

  splitCampaign(id: string, count?: number): import('../types.js').Campaign[] | null {
    return this.campaignPlanner.splitCampaign(id, count);
  }

  getCampaignChildren(parentId: string): import('../types.js').Campaign[] {
    return this.campaignPlanner.getChildren(parentId);
  }

  getCampaignParentProgress(parentId: string): import('../types.js').CampaignProgress | null {
    return this.campaignPlanner.getParentProgress(parentId);
  }

  deriveCampaignParentStatus(parentId: string): import('../types.js').CampaignStatus | null {
    return this.campaignPlanner.deriveParentStatus(parentId);
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

  findPathsToObjective(objectiveId: string, maxPaths: number = 5, optimize?: PathOptimize): Array<PathResult> {
    return this.paths.findPathsToObjective(objectiveId, maxPaths, optimize);
  }

  findPaths(fromNode: string, toNode: string, maxPaths: number = 5, optimize?: PathOptimize): Array<PathResult> {
    return this.paths.findPaths(fromNode, toNode, maxPaths, optimize);
  }

  /**
   * Post-ingest enrichment: identify HVTs and pre-compute attack paths.
   * Called after BloodHound/AzureHound ingestion.
   */
  enrichBloodHoundPaths(optimize?: PathOptimize): { hvts: HVTResult[]; paths: PreComputedPath[] } {
    const enricher = new BloodHoundPathEnricher(this.ctx);
    const hvts = enricher.computeHighValueTargets();
    const paths = enricher.preComputeAttackPaths(this.paths, optimize);
    if (hvts.length > 0) {
      this.ctx.log(`BloodHound enrichment: ${hvts.length} HVTs identified, ${paths.length} attack paths pre-computed`, undefined, { category: 'system' });
    }
    return { hvts, paths };
  }

  /**
   * Post-ingest enrichment: match web attack chain templates.
   * Called after web parser ingestion when webapp/vulnerability nodes change.
   */
  enrichWebAttackChains(): MatchedChain[] {
    const enricher = new WebChainEnricher(this.ctx);
    const chains = enricher.matchChainTemplates();
    if (chains.length > 0) {
      // Annotate frontier-relevant nodes with chain_template info
      for (const chain of chains) {
        const lastNode = chain.node_path[chain.node_path.length - 1];
        if (this.ctx.graph.hasNode(lastNode)) {
          this.ctx.graph.setNodeAttribute(lastNode, 'chain_template', chain.template_id);
        }
      }
      this.ctx.log(`Web chain enrichment: ${chains.length} chains matched (${chains.filter(c => c.completion === 1.0).length} complete)`, undefined, { category: 'system' });
    }
    return chains;
  }

  // =============================================
  // Community Detection (delegated to community-detection.ts)
  // =============================================

  getCommunities(): Map<string, number> {
    if (this.ctx.communityCache) return this.ctx.communityCache;
    const communities = detectCommunities(this.ctx.graph, {
      resolution: this.ctx.config.community_resolution,
    });
    this.ctx.communityCache = communities;
    // Write community_id onto node properties so it flows through graph exports
    for (const [nodeId, cid] of communities) {
      if (this.ctx.graph.hasNode(nodeId)) {
        this.ctx.graph.setNodeAttribute(nodeId, 'community_id', cid);
      }
    }
    return communities;
  }

  private getCommunityStats(): { community_count: number; largest_community_size: number; unexplored_community_count: number } {
    const communities = this.getCommunities();
    const stats = communityStats(communities);
    // Count communities that have at least one frontier item target.
    // Use computeFrontier() which already enriches items with community_id.
    const frontier = this.computeFrontier();
    const frontierCommunities = new Set<number>();
    for (const item of frontier) {
      if (item.community_id !== undefined) frontierCommunities.add(item.community_id);
    }
    return {
      community_count: stats.community_count,
      largest_community_size: stats.largest_community_size,
      unexplored_community_count: frontierCommunities.size,
    };
  }

  // =============================================
  // Graph Queries (full access for LLM)
  // =============================================

  queryGraph(query: GraphQuery): GraphQueryResult {
    return queryGraphImpl({ graph: this.ctx.graph, getNode: id => this.getNode(id) }, query);
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

      // 4. Annotate items whose scope cannot be verified (no resolvable IP or hostname)
      const nodeIds = [item.node_id, item.edge_source, item.edge_target].filter(Boolean) as string[];
      if (nodeIds.length > 0 && nodeIds.every(nid => !this.resolveHostIp(nid) && !this.resolveHostname(nid))) {
        item.scope_unverified = true;
      }

      // Everything else passes through to LLM
      passed.push(item);
    }

    return { passed, filtered };
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

  private resolveHostDomain(nodeId: string): string | undefined {
    // Walk outbound MEMBER_OF_DOMAIN edges to find the domain
    if (!this.ctx.graph.hasNode(nodeId)) return undefined;
    for (const edge of this.ctx.graph.outEdges(nodeId) as string[]) {
      const attrs = this.ctx.graph.getEdgeAttributes(edge);
      if (attrs.type === 'MEMBER_OF_DOMAIN') {
        const target = this.ctx.graph.target(edge);
        const targetNode = this.getNode(target);
        if (targetNode?.type === 'domain') return targetNode.label || target;
      }
    }
    // Fallback: check hostname for domain suffix
    const hostname = this.resolveHostname(nodeId);
    if (hostname && hostname.includes('.')) {
      const parts = hostname.split('.');
      if (parts.length >= 2) return parts.slice(-2).join('.');
    }
    return undefined;
  }

  private isNodeExcluded(nodeId: string): string | null {
    const ip = this.resolveHostIp(nodeId);
    const hostname = this.resolveHostname(nodeId);
    const scope = this.ctx.config.scope;

    if (ip && isHostExcluded(ip, scope.exclusions)) return ip;
    if (hostname && isHostExcluded(hostname, scope.exclusions)) return hostname;
    if (ip && isScopedHostInScope(ip, scope)) return null;
    if (hostname && isScopedHostInScope(hostname, scope)) return null;
    if (ip) return ip;
    if (hostname) return hostname;
    return null;
  }

  // =============================================
  // Validation (Layer 3 — post-LLM sanity check)
  // =============================================

  validateAction(action: {
    target_node?: string; target_ip?: string;
    edge_source?: string; edge_target?: string;
    technique?: string;
    target_url?: string; cloud_resource?: string;
  }): {
    valid: boolean;
    errors: string[];
    warnings: string[];
    opsec_context: OpsecContext;
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
      if (!isScopedHostInScope(action.target_ip, this.ctx.config.scope)) {
        errors.push(`Target IP is out of scope: ${action.target_ip}`);
      }
    }

    // URL scope check (glob matching)
    if (action.target_url) {
      const patterns = this.ctx.config.scope.url_patterns;
      if (patterns && patterns.length > 0) {
        if (!isUrlInScope(action.target_url, patterns, this.ctx.config.scope.exclusions)) {
          errors.push(`Target URL is out of scope: ${action.target_url}`);
        }
      } else {
        // Fail closed: fall back to hostname-vs-domain scope check
        try {
          const hostname = new URL(action.target_url).hostname;
          if (!isScopedHostInScope(hostname, this.ctx.config.scope)) {
            errors.push(`Target URL hostname is out of scope: ${hostname}`);
          }
        } catch {
          errors.push(`Target URL is malformed: ${action.target_url}`);
        }
      }
    }

    // Cloud resource scope check
    if (action.cloud_resource) {
      const scopeResult = isCloudResourceInScope(action.cloud_resource, this.ctx.config.scope);
      if (!scopeResult.in_scope) {
        errors.push(`Cloud resource is out of scope: ${scopeResult.reason}`);
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

    // Technique-specific graph-aware guidance
    if (action.technique) {
      const techniqueWarning = this.checkTechniqueGuidance(action);
      if (techniqueWarning) warnings.push(techniqueWarning);
    }

    // Failure pattern matching from retrospective feedback
    if (action.technique && this.ctx.config.failure_patterns) {
      for (const fp of this.ctx.config.failure_patterns) {
        if (fp.technique !== action.technique) continue;
        const targetStr = action.target_node || action.target_ip || '';
        if (!fp.target_pattern || targetStr.toLowerCase().includes(fp.target_pattern.toLowerCase())) {
          warnings.push(fp.warning);
        }
      }
    }

    // OPSEC context from adaptive tracker
    const host_id = action.target_node || action.edge_target;
    const domain = host_id ? this.resolveHostDomain(host_id) : undefined;
    const opsec_context = this.ctx.opsecTracker.getNoiseContext({ host_id: host_id || undefined, domain });

    // Noise budget warning
    if (opsec_context.noise_budget_remaining <= 0) {
      warnings.push('Noise budget exhausted — only passive/zero-noise actions recommended.');
    } else if (this.ctx.opsecTracker.isApproachingCeiling(host_id || undefined, domain)) {
      warnings.push(`Noise budget approaching ceiling (${opsec_context.noise_budget_remaining} remaining of ${this.ctx.config.opsec.max_noise}).`);
    }

    return { valid: errors.length === 0, errors, warnings, opsec_context };
  }

  private checkTechniqueGuidance(action: {
    target_node?: string; target_ip?: string;
    edge_source?: string; edge_target?: string;
    technique?: string;
  }): string | null {
    const t = action.technique;
    const targetNode = action.target_node || action.edge_target;

    switch (t) {
      case 'secretsdump': {
        if (!targetNode) return null;
        const hasAdmin = (this.ctx.graph.inEdges(targetNode) as string[]).some(e =>
          this.ctx.graph.getEdgeAttributes(e).type === 'ADMIN_TO' && this.ctx.graph.getEdgeAttributes(e).confidence >= 0.7
        );
        if (!hasAdmin) return 'No confirmed ADMIN_TO edge to this target — secretsdump requires local admin access.';
        return null;
      }
      case 'dcsync': {
        if (!targetNode) return null;
        const node = this.ctx.graph.hasNode(targetNode) ? this.ctx.graph.getNodeAttributes(targetNode) : null;
        if (node?.type !== 'domain') return null;
        const hasRights = (this.ctx.graph.inEdges(targetNode) as string[]).some(e => {
          const et = this.ctx.graph.getEdgeAttributes(e).type;
          return et === 'CAN_DCSYNC' || et === 'GENERIC_ALL';
        });
        if (!hasRights) return 'No CAN_DCSYNC or GENERIC_ALL edge to this domain — DCSync requires replication rights.';
        return null;
      }
      case 'kerberoast': {
        if (!targetNode || !this.ctx.graph.hasNode(targetNode)) return null;
        const node = this.ctx.graph.getNodeAttributes(targetNode);
        if (node.type === 'user' && !node.has_spn) return 'Target user has no SPN property set — Kerberoasting requires a servicePrincipalName.';
        return null;
      }
      case 'smb-relay':
      case 'ntlmrelay': {
        if (!targetNode) return null;
        const svcEdges = this.ctx.graph.hasNode(targetNode)
          ? (this.ctx.graph.outEdges(targetNode) as string[]).filter(e =>
            this.ctx.graph.getEdgeAttributes(e).type === 'RUNS'
          )
          : [];
        for (const e of svcEdges) {
          const svcNode = this.ctx.graph.getNodeAttributes(this.ctx.graph.target(e));
          if (svcNode.service_name === 'smb' && svcNode.smb_signing === true) {
            return 'Target host has SMB signing enabled — NTLM relay to SMB will fail.';
          }
        }
        return null;
      }
      default:
        return null;
    }
  }

  // =============================================
  // Session → Graph Integration
  // =============================================

  ingestSessionResult(result: {
    success: boolean;
    confirmed?: boolean;
    target_node: string;
    principal_node?: string;
    credential_node?: string;
    session_id?: string;
    agent_id?: string;
    action_id?: string;
    frontier_item_id?: string;
  }): void {
    const { success, target_node, principal_node, credential_node, session_id, agent_id, action_id, frontier_item_id } = result;
    const confirmed = result.confirmed !== false; // default true for backward compat

    if (success) {
      let sessionEdgeCreated = false;

      // Only create HAS_SESSION edges when auth is positively confirmed.
      // Unconfirmed success (session alive but no shell detected) is logged
      // but does NOT create graph edges — the operator can confirm manually.
      if (confirmed && principal_node && this.ctx.graph.hasNode(principal_node)) {
        const principalAttrs = this.ctx.graph.getNodeAttributes(principal_node);
        const validSourceTypes = new Set(['user', 'group', 'credential']);
        if (validSourceTypes.has(principalAttrs.type)) {
          sessionEdgeCreated = true;
          const edgeId = `session-${principal_node}-${target_node}`;
          if (!this.ctx.graph.hasEdge(edgeId)) {
            this.ctx.graph.addEdgeWithKey(edgeId, principal_node, target_node, {
              type: 'HAS_SESSION',
              confidence: 1.0,
              discovered_at: new Date().toISOString(),
              discovered_by: 'session-manager',
              tested: true,
              test_result: 'success',
              confirmed_at: new Date().toISOString(),
              session_live: true,
            });
            this.invalidateFrontierCache();
            this.invalidatePathGraph();
          } else {
            this.ctx.graph.mergeEdgeAttributes(edgeId, {
              confidence: 1.0,
              tested: true,
              test_result: 'success',
              confirmed_at: new Date().toISOString(),
              session_live: true,
              session_unconfirmed: undefined,
            });
          }
        }
      }

      // Frontier edge: confirmed = success, unconfirmed = partial (needs operator review)
      this.markFrontierEdgeTested(frontier_item_id, action_id, confirmed ? 'success' : 'partial');

      const eventType = confirmed ? 'session_access_confirmed' : 'session_access_unconfirmed';
      this.logActionEvent({
        event_type: eventType,
        description: `SSH session ${session_id || '(unknown)'} to ${target_node} ${confirmed ? 'succeeded' : 'connected but unconfirmed — no shell detected'}${principal_node ? ` as ${principal_node}` : ''}`,
        agent_id,
        action_id,
        frontier_item_id,
        category: 'system',
        details: {
          session_id,
          target_node,
          principal_node,
          credential_node,
          confirmed,
          has_session_edge_created: sessionEdgeCreated,
        },
      });
    } else {
      // Failure: mark only the specific frontier item's edge
      this.markFrontierEdgeTested(frontier_item_id, action_id, 'failure');

      this.logActionEvent({
        event_type: 'session_error',
        description: `SSH session to ${target_node} failed${principal_node ? ` as ${principal_node}` : ''}`,
        agent_id,
        action_id,
        frontier_item_id,
        category: 'system',
        outcome: 'failure',
        details: {
          session_id,
          target_node,
          principal_node,
          credential_node,
        },
      });
    }

    this.persist();
  }

  /**
   * Called when a session is closed (operator close, process exit, or shutdown).
   * Downgrades HAS_SESSION edges to historical state so get_state no longer
   * reports the host as having live access.
   */
  onSessionClosed(_sessionId: string, targetNode?: string, principalNode?: string): void {
    if (!targetNode) return;

    // Find and downgrade matching HAS_SESSION edges
    const edgesToDowngrade: string[] = [];
    this.ctx.graph.forEachEdge((_edgeId, attrs, source, target) => {
      if (attrs.type !== 'HAS_SESSION') return;
      if (target !== targetNode) return;
      if (principalNode && source !== principalNode) return;
      edgesToDowngrade.push(_edgeId);
    });

    for (const edgeId of edgesToDowngrade) {
      this.ctx.graph.mergeEdgeAttributes(edgeId, {
        session_live: false,
        session_closed_at: new Date().toISOString(),
      });
    }

    if (edgesToDowngrade.length > 0) {
      this.invalidateFrontierCache();
    }
  }

  /**
   * Reconcile all HAS_SESSION edges on startup: mark any that claim to be
   * live as no longer live, since all runtime sessions are gone after restart.
   */
  reconcileSessionEdgesOnStartup(): void {
    let downgraded = 0;
    this.ctx.graph.forEachEdge((_edgeId, attrs) => {
      if (attrs.type !== 'HAS_SESSION') return;
      // Only downgrade edges that are still marked as live (or have no session_live flag,
      // meaning they were created before this feature and never closed properly)
      if (attrs.session_live !== false) {
        this.ctx.graph.mergeEdgeAttributes(_edgeId, {
          session_live: false,
          session_closed_at: attrs.session_closed_at || new Date().toISOString(),
        });
        downgraded++;
      }
    });
    if (downgraded > 0) {
      this.log(`Reconciled ${downgraded} stale HAS_SESSION edge(s) on startup — marked as historical`, undefined, { category: 'system', event_type: 'system' });
      this.invalidateFrontierCache();
    }
  }

  private markFrontierEdgeTested(
    frontier_item_id: string | undefined,
    action_id: string | undefined,
    test_result: 'success' | 'failure' | 'partial'
  ): void {
    if (!frontier_item_id && !action_id) return;

    // If frontier_item_id is present, find the edge it refers to
    if (frontier_item_id) {
      // Frontier edge IDs follow pattern "frontier-edge-{edgeId}"
      const edgeId = frontier_item_id.replace(/^frontier-edge-/, '');
      if (edgeId !== frontier_item_id && this.ctx.graph.hasEdge(edgeId)) {
        this.ctx.graph.mergeEdgeAttributes(edgeId, {
          tested: true,
          test_result,
        });
        this.invalidateFrontierCache();
        this.invalidatePathGraph();
        return;
      }
    }

    // Fallback: if action_id is set, check the action→frontier mapping
    if (action_id && frontier_item_id) {
      // The frontier_item_id itself encodes the edge — already tried above
      // No additional blanket marking — this is intentionally scoped
    }
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
    const task = this.agentMgr.getTask(taskId);
    const ok = this.agentMgr.updateStatus(taskId, status, summary);
    if (ok) {
      // Campaign progress aggregation: when a campaign agent reaches terminal state,
      // update campaign progress and check abort conditions.
      if (task?.campaign_id && (status === 'completed' || status === 'failed')) {
        const result = status === 'completed' ? 'success' as const : 'failure' as const;
        this.campaignPlanner.updateCampaignProgress(task.campaign_id, task.frontier_item_id || '', result);
        const abort = this.campaignPlanner.checkAbortConditions(task.campaign_id);
        if (abort.should_abort) {
          this.campaignPlanner.abortCampaign(task.campaign_id);
          // Cancel remaining running agents for this campaign
          for (const agent of this.agentMgr.getAll()) {
            if (agent.campaign_id === task.campaign_id && agent.status === 'running' && agent.id !== taskId) {
              this.agentMgr.updateStatus(agent.id, 'interrupted', `Campaign aborted: ${abort.reason}`);
            }
          }
        }
      }
      this.persist();
    }
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

    // Collect nodes (skip superseded identities)
    for (const id of nodeSet) {
      const node = this.getNode(id);
      if (node && node.identity_status !== 'superseded') {
        result.nodes.push({ id, properties: node });
      }
    }

    // Collect all edges between collected (non-superseded) nodes
    const liveNodeIds = new Set(result.nodes.map(n => n.id));
    this.ctx.graph.forEachEdge((_, attrs, source, target) => {
      if (liveNodeIds.has(source) && liveNodeIds.has(target)) {
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

    this.ctx.graph.forEachEdge((_edgeId, attrs, source, target) => {
      const srcAttrs = this.ctx.graph.getNodeAttributes(source);
      const tgtAttrs = this.ctx.graph.getNodeAttributes(target);
      if (srcAttrs?.identity_status === 'superseded' || tgtAttrs?.identity_status === 'superseded') return;
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
          if (ep.type === 'ADMIN_TO' && ep.confidence >= 0.9) return true;
          if (ep.type === 'HAS_SESSION' && ep.confidence >= 0.9 && ep.session_live === true) return true;
          return false;
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
        total_nodes: Object.values(nodesByType).reduce((a, b) => a + b, 0),
        nodes_by_type: nodesByType,
        total_edges: confirmedEdges + inferredEdges,
        edges_by_type: edgesByType,
        confirmed_edges: confirmedEdges,
        inferred_edges: inferredEdges,
        ...this.getCommunityStats(),
        cold_node_count: this.ctx.coldStore.count(),
        cold_nodes_by_subnet: this.ctx.coldStore.count() > 0
          ? Object.fromEntries(
              Object.entries(this.ctx.coldStore.countBySubnet())
                .sort(([, a], [, b]) => b - a)
                .slice(0, 5)
            )
          : undefined,
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
      phases: this.getPhaseStatuses(),
      current_phase: this.getCurrentPhaseId(),
    };
  }

  // --- Phase orchestration ---

  /** Evaluate all engagement phases and return runtime statuses */
  getPhaseStatuses(): EngagementState['phases'] {
    const phases = this.ctx.config.phases;
    if (!phases || phases.length === 0) return [];

    const sorted = [...phases].sort((a, b) => a.order - b.order);
    const completedPhases = new Set<string>();
    const result: EngagementState['phases'] = [];

    for (const phase of sorted) {
      const entryMet = this.evaluateCriteria(phase.entry_criteria, completedPhases);
      const exitMet = this.evaluateCriteria(phase.exit_criteria, completedPhases);

      let status: PhaseStatus;
      if (exitMet && entryMet) {
        status = 'completed';
        completedPhases.add(phase.id);
      } else if (entryMet) {
        status = 'active';
      } else {
        status = 'locked';
      }

      result.push({
        id: phase.id,
        name: phase.name,
        order: phase.order,
        status,
        strategies: phase.strategies,
        entry_criteria_met: entryMet,
        exit_criteria_met: exitMet,
      });
    }

    return result;
  }

  /** Get the ID of the lowest-order active phase */
  getCurrentPhaseId(): string | undefined {
    const statuses = this.getPhaseStatuses();
    const active = statuses.find(p => p.status === 'active');
    return active?.id;
  }

  /** Evaluate a list of criteria — all must be met (AND logic) */
  private evaluateCriteria(
    criteria: PhaseCriterion[],
    completedPhases: Set<string>,
  ): boolean {
    if (criteria.length === 0) return true; // no criteria = always met
    return criteria.every(c => this.evaluateSingleCriterion(c, completedPhases));
  }

  /** Evaluate a single phase criterion against current graph state */
  private evaluateSingleCriterion(
    criterion: PhaseCriterion,
    completedPhases: Set<string>,
  ): boolean {
    switch (criterion.type) {
      case 'always':
        return true;
      case 'phase_completed':
        return completedPhases.has(criterion.phase_id);
      case 'objective_achieved':
        return this.ctx.config.objectives.some(
          o => o.id === criterion.objective_id && o.achieved,
        );
      case 'node_count': {
        let count = 0;
        this.ctx.graph.forEachNode((_, attrs) => {
          if (attrs.type === criterion.node_type && !attrs.superseded_by) count++;
        });
        return count >= criterion.min;
      }
      case 'access_level': {
        const levels: Record<string, number> = { none: 0, user: 1, local_admin: 2, domain_admin: 3 };
        const compromised: string[] = [];
        this.ctx.graph.forEachNode((_, attrs) => {
          if (attrs.type !== 'host' || attrs.superseded_by) return;
          const hasAccess = this.ctx.graph.inEdges(attrs.id).some((e: string) => {
            const ep = this.ctx.graph.getEdgeAttributes(e);
            if (ep.type === 'ADMIN_TO' && ep.confidence >= 0.9) return true;
            if (ep.type === 'HAS_SESSION' && ep.confidence >= 0.9 && ep.session_live === true) return true;
            return false;
          });
          if (hasAccess) compromised.push(attrs.label);
        });
        const current = this.computeAccessLevel(compromised);
        return (levels[current] ?? 0) >= (levels[criterion.min_level] ?? 0);
      }
      default:
        return false;
    }
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

  private get scopeHost(): ScopeManagerHost {
    return {
      ctx: this.ctx,
      addNode: this.addNode.bind(this),
      logActionEvent: this.logActionEvent.bind(this),
      persist: (() => this.persist()) as () => void,
      invalidateFrontierCache: this.invalidateFrontierCache.bind(this),
      invalidateHealthReport: this.invalidateHealthReport.bind(this),
      runInferenceRules: this.runInferenceRules.bind(this),
    };
  }

  updateScope(changes: {
    add_cidrs?: string[];
    remove_cidrs?: string[];
    add_domains?: string[];
    remove_domains?: string[];
    add_exclusions?: string[];
    remove_exclusions?: string[];
    reason: string;
  }): { applied: boolean; errors: string[]; before: EngagementConfig['scope']; after: EngagementConfig['scope']; affected_node_count: number } {
    return _updateScope(this.scopeHost, changes);
  }

  collectScopeSuggestions(): ScopeSuggestion[] {
    return _collectScopeSuggestions(this.scopeHost);
  }

  previewScopeChange(changes: {
    add_cidrs?: string[];
    remove_cidrs?: string[];
    add_domains?: string[];
    remove_domains?: string[];
    add_exclusions?: string[];
    remove_exclusions?: string[];
  }): { before: EngagementConfig['scope']; after: EngagementConfig['scope']; nodes_entering_scope: number; nodes_leaving_scope: number; pending_suggestions_resolved: string[] } {
    return _previewScopeChange(this.scopeHost, changes);
  }

  // =============================================
  // Persistence (delegated to StatePersistence)
  // =============================================

  persist(detail: GraphUpdateDetail = {}): void {
    this.invalidateHealthReport();
    this.persistence.persist(detail);
  }

  // =============================================
  // OPSEC Tracker
  // =============================================

  recordOpsecNoise(opts: { action_id?: string; host_id?: string; domain?: string; noise_estimate: number; noise_actual?: number }): void {
    this.ctx.opsecTracker.recordNoise(opts);
  }

  recordDefensiveSignal(signal: import('./opsec-tracker.js').DefensiveSignal): void {
    this.ctx.opsecTracker.recordDefensiveSignal(signal);
  }

  getOpsecContext(opts?: { host_id?: string; domain?: string }): OpsecContext {
    return this.ctx.opsecTracker.getNoiseContext(opts);
  }

  getOpsecTracker(): import('./opsec-tracker.js').OpsecTracker {
    return this.ctx.opsecTracker;
  }

  // =============================================
  // Pending Action Queue (Approval Gates)
  // =============================================

  getPendingActionQueue(): import('./pending-action-queue.js').PendingActionQueue {
    return this.ctx.pendingActionQueue;
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

  updateConfig(partial: Record<string, unknown>): EngagementConfig {
    const current = this.ctx.config;
    // Merge top-level scalars
    if (typeof partial.name === 'string' && partial.name.length > 0) current.name = partial.name;
    if (typeof partial.profile === 'string') current.profile = partial.profile as EngagementConfig['profile'];
    if (typeof partial.community_resolution === 'number') current.community_resolution = partial.community_resolution;

    // Merge scope (partial merge — only overwrite provided keys)
    if (partial.scope && typeof partial.scope === 'object') {
      const s = partial.scope as Record<string, unknown>;
      if (Array.isArray(s.cidrs)) current.scope.cidrs = s.cidrs;
      if (Array.isArray(s.domains)) current.scope.domains = s.domains;
      if (Array.isArray(s.exclusions)) current.scope.exclusions = s.exclusions;
      if (Array.isArray(s.hosts)) current.scope.hosts = s.hosts;
      if (Array.isArray(s.aws_accounts)) current.scope.aws_accounts = s.aws_accounts;
      if (Array.isArray(s.azure_subscriptions)) current.scope.azure_subscriptions = s.azure_subscriptions;
      if (Array.isArray(s.gcp_projects)) current.scope.gcp_projects = s.gcp_projects;
      if (Array.isArray(s.url_patterns)) current.scope.url_patterns = s.url_patterns;
    }

    // Merge opsec
    if (partial.opsec && typeof partial.opsec === 'object') {
      const o = partial.opsec as Record<string, unknown>;
      if (typeof o.name === 'string') current.opsec.name = o.name;
      if (typeof o.max_noise === 'number') current.opsec.max_noise = o.max_noise;
      if (typeof o.approval_mode === 'string') current.opsec.approval_mode = o.approval_mode as EngagementConfig['opsec']['approval_mode'];
      if (typeof o.approval_timeout_ms === 'number') current.opsec.approval_timeout_ms = o.approval_timeout_ms;
      if (Array.isArray(o.blacklisted_techniques)) current.opsec.blacklisted_techniques = o.blacklisted_techniques;
      if (o.time_window === null) current.opsec.time_window = undefined;
      else if (o.time_window && typeof o.time_window === 'object') {
        const tw = o.time_window as Record<string, unknown>;
        if (typeof tw.start_hour === 'number' && typeof tw.end_hour === 'number') {
          current.opsec.time_window = { start_hour: tw.start_hour, end_hour: tw.end_hour };
        }
      }
      if (typeof o.notes === 'string') current.opsec.notes = o.notes;
    }

    // Merge failure_patterns (full replace)
    if (Array.isArray(partial.failure_patterns)) {
      current.failure_patterns = partial.failure_patterns as EngagementConfig['failure_patterns'];
    }

    // Merge objectives (full replace if provided)
    if (Array.isArray(partial.objectives)) {
      current.objectives = partial.objectives as EngagementConfig['objectives'];
    }

    this.persist();
    return current;
  }

  addObjective(obj: { description: string; target_node_type?: string; target_criteria?: Record<string, unknown>; achievement_edge_types?: string[] }): EngagementConfig['objectives'][0] {
    const objective = {
      id: uuidv4(),
      description: obj.description,
      target_node_type: obj.target_node_type as import('../types.js').NodeType | undefined,
      target_criteria: obj.target_criteria,
      achievement_edge_types: obj.achievement_edge_types as import('../types.js').EdgeType[] | undefined,
      achieved: false,
    };
    this.ctx.config.objectives.push(objective);
    this.persist();
    return objective;
  }

  updateObjective(id: string, updates: Record<string, unknown>): boolean {
    const obj = this.ctx.config.objectives.find(o => o.id === id);
    if (!obj) return false;
    if (typeof updates.description === 'string') obj.description = updates.description;
    if (typeof updates.target_node_type === 'string') obj.target_node_type = updates.target_node_type as import('../types.js').NodeType;
    if (typeof updates.achieved === 'boolean') {
      obj.achieved = updates.achieved;
      obj.achieved_at = updates.achieved ? new Date().toISOString() : undefined;
    }
    if (updates.target_criteria !== undefined) obj.target_criteria = updates.target_criteria as Record<string, unknown>;
    if (Array.isArray(updates.achievement_edge_types)) obj.achievement_edge_types = updates.achievement_edge_types as import('../types.js').EdgeType[];
    this.persist();
    return true;
  }

  removeObjective(id: string): boolean {
    const idx = this.ctx.config.objectives.findIndex(o => o.id === id);
    if (idx === -1) return false;
    this.ctx.config.objectives.splice(idx, 1);
    this.persist();
    return true;
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

  getFrontierWeights(): { fan_out: Record<string, number>; noise: Record<string, number> } {
    return {
      fan_out: this.frontierComputer.getFanOutEstimates(),
      noise: this.frontierComputer.getNoiseEstimates(),
    };
  }

  setFrontierWeights(weights: { fan_out?: Record<string, number>; noise?: Record<string, number> }): void {
    if (weights.fan_out) this.frontierComputer.setFanOutEstimates(weights.fan_out);
    if (weights.noise) this.frontierComputer.setNoiseEstimates(weights.noise);
    this.invalidateFrontierCache();
  }

  resetFrontierWeights(): void {
    this.frontierComputer.resetWeightsToDefaults();
    this.invalidateFrontierCache();
  }

  logActionEvent(event: Omit<Partial<ActivityLogEntry>, 'event_id' | 'timestamp'> & { description: string }): ActivityLogEntry {
    return this.ctx.logEvent(event);
  }

  getStateFilePath(): string {
    return this.ctx.stateFilePath;
  }

  getEvidenceStore(): EvidenceStore {
    return this.evidenceStore;
  }

  setTrackedProcesses(processes: import('./process-tracker.js').TrackedProcess[]): void {
    this.ctx.trackedProcesses = processes;
  }

  exportGraph(options?: { includeSuperseded?: boolean }): ExportedGraph {
    const includeSuperseded = options?.includeSuperseded ?? false;
    const nodes: ExportedGraph['nodes'] = [];
    const edges: ExportedGraph['edges'] = [];

    this.ctx.graph.forEachNode((id, attrs) => {
      if (!includeSuperseded && attrs.identity_status === 'superseded') return;
      nodes.push({ id, properties: attrs });
    });

    this.ctx.graph.forEachEdge((edgeId, attrs, source, target) => {
      if (!includeSuperseded) {
        const srcAttrs = this.ctx.graph.getNodeAttributes(source);
        const tgtAttrs = this.ctx.graph.getNodeAttributes(target);
        if (srcAttrs?.identity_status === 'superseded' || tgtAttrs?.identity_status === 'superseded') return;
      }
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
      } as Partial<NodeProperties>);
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
