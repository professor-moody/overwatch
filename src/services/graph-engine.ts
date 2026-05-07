// ============================================================
// Overwatch — Graph Engine
// Engagement state as a directed property graph
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
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
import { isInTimeWindow } from './opsec-tracker.js';
import {
  inferPivotReachability as _inferPivotReachability,
  inferDefaultCredentials as _inferDefaultCredentials,
  inferImdsv1Ssrf as _inferImdsv1Ssrf,
  inferManagedIdentityPivot as _inferManagedIdentityPivot,
  degradeExpiredCredentialEdges as _degradeExpiredCredentialEdges,
} from './imperative-inference.js';
import type { ImperativeInferenceHost, PivotReachabilityResult } from './imperative-inference.js';
import { runCrossTierCorrelator as _runCrossTierCorrelator } from './cross-tier-correlator.js';
import { runCrossTierInference as _runCrossTierInference } from './cross-tier-inference.js';
import {
  updateScope as _updateScope,
  collectScopeSuggestions as _collectScopeSuggestions,
  previewScopeChange as _previewScopeChange,
} from './scope-manager.js';
import type { ScopeManagerHost } from './scope-manager.js';
import { buildDecisionLog, queryDecisionLog, type DecisionEntry, type DecisionLogQuery } from './decision-log.js';
import { explainAction, type ExplainActionResult } from './introspection.js';
import { buildTimeline, queryTimeline, type TimelineEntry, type TimelineQuery } from './timeline.js';
import { ingestFindingImpl } from './finding-ingestion.js';
import type { FindingIngestionHost } from './finding-ingestion.js';
import { resolveNodeIdentity } from './identity-resolution.js';
import {
  ingestSessionResult as _ingestSessionResult,
  onSessionClosed as _onSessionClosed,
  reconcileSessionEdgesOnStartup as _reconcileSessionEdgesOnStartup,
} from './session-tracker.js';
import type { SessionTrackerHost } from './session-tracker.js';
import {
  seedFromConfig as _seedFromConfig,
  updateConfig as _updateConfig,
} from './config-manager.js';
import type { ConfigManagerHost } from './config-manager.js';
import {
  addObjective as _addObjective,
  updateObjective as _updateObjective,
  removeObjective as _removeObjective,
  evaluateObjectives as _evaluateObjectives,
  recomputeObjectives as _recomputeObjectives,
  syncObjectiveNodes as _syncObjectiveNodes,
  getPhaseStatuses as _getPhaseStatuses,
  getCurrentPhaseId as _getCurrentPhaseId,
  getCurrentPhase as _getCurrentPhase,
  computeAccessLevel as _computeAccessLevel,
} from './objective-manager.js';
import type { ObjectiveManagerHost } from './objective-manager.js';
import { queryGraphImpl } from './graph-query.js';
import { CredentialCoverageTracker } from './credential-coverage.js';
import { inferProfile } from '../types.js';
import type {
  NodeProperties, EdgeProperties, NodeType, EdgeType,
  EngagementConfig, EngagementState, FrontierItem,
  Finding, InferenceRule, GraphQuery, GraphQueryResult,
  AgentTask, ExportedGraph, HealthReport, GraphCorrectionOperation,
  ScopeSuggestion, InferenceRuleEffectiveness,
} from '../types.js';

export interface RecentOutcome {
  target: string;
  timestamp: string;
  result: 'success' | 'failure' | 'neutral';
  reason?: string;
  technique?: string;
  action_id?: string;
}

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
      // P2.2: pin the construction-time timestamp to `created_at` so the
      // initial log event is deterministic across replays. Without this,
      // wall-clock leaks into the activity-log digest and breaks the
      // golden-master determinism guarantee.
      const seedAt = this.ctx.config.created_at;
      if (seedAt) {
        this.ctx.withClock(seedAt, () => {
          this.log('Engagement initialized from config', undefined, { category: 'system', event_type: 'system' });
        });
      } else {
        this.log('Engagement initialized from config', undefined, { category: 'system', event_type: 'system' });
      }
    }

    this.syncObjectiveNodes();

    // Reconcile runtime-dependent state on startup
    this.reconcileSessionEdgesOnStartup();
    this.agentMgr.reconcileOnStartup();
    this.persistence.persistImmediate();

    // 7.7: Auto health check on startup
    this.runAutoHealthCheck('startup');

    // Phase B: surface "OPSEC inert" state at startup. OPSEC enforcement is
    // intentionally opt-in; a config that sets max_noise/blacklist/time_window
    // but omits enabled is an easy false-sense-of-security trap. We emit a
    // single WARN log line so operators don't think 0.4 noise ceiling is
    // active when it isn't.
    this.warnIfOpsecInert();
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
    _seedFromConfig(this.configHost);
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
    // P2.1: WAL append before in-memory mutation. Differentiated record
    // for `add_node` (new) vs `merge_node_attrs` (update) so replay can
    // call the same code path the original write took.
    const isUpdate = this.ctx.graph.hasNode(props.id);
    this.ctx.journalMutation(
      isUpdate ? 'merge_node_attrs' : 'add_node',
      { props },
    );
    if (isUpdate) {
      // P2.1: type-guard on merge. Previously, a second writer (e.g. an
      // AzureHound role assignment) could overwrite an existing node's
      // `type` simply by passing the same ID with a different type — a
      // group could silently flip into a cloud_identity, polluting any
      // attack-path that walks through that node. We now refuse to merge
      // a type change. The incoming `type` is dropped, the original
      // identity is preserved, and we log an instrumentation warning so
      // operators can see when canonical IDs collide across providers.
      const existing = this.ctx.graph.getNodeAttributes(props.id) as NodeProperties;
      const merged: Partial<NodeProperties> = { ...props };
      if (existing.type && props.type && existing.type !== props.type) {
        delete (merged as { type?: NodeProperties['type'] }).type;
        try {
          this.logActionEvent({
            description: `Refused type change on merge: node ${props.id} kept type "${existing.type}", incoming "${props.type}" dropped`,
            event_type: 'instrumentation_warning',
            category: 'system',
            details: {
              node_id: props.id,
              existing_type: existing.type,
              incoming_type: props.type,
              incoming_discovered_by: props.discovered_by,
            },
          });
        } catch {
          // Don't let logging failure block ingestion.
        }
      }
      this.ctx.graph.mergeNodeAttributes(props.id, merged);
      this.invalidateHealthReport();
    } else {
      this.ctx.graph.addNode(props.id, props);
      this.invalidatePathGraph();
      this.invalidateAllCaches();
    }
    return props.id;
  }

  addEdge(source: string, target: string, props: EdgeProperties): { id: string; isNew: boolean } {
    // P2.1: journal the intent. We can't tell yet whether this will be a
    // new edge or a property-merge on an existing one, so the entry is
    // type=add_edge with the full props. Replay code re-runs addEdge so
    // it independently makes the same determination.
    this.ctx.journalMutation('add_edge', { source, target, props });
    // Check for duplicate edge of same type
    const existingEdges = this.ctx.graph.edges(source, target);
    // For scope-bearing Azure RBAC edges, dedupe must include `scope` so
    // distinct role assignments at different scopes do not collapse and
    // silently overwrite each other's scope properties.
    const scopeAware = props.type === 'HAS_POLICY' || props.type === 'POLICY_ALLOWS';
    const incomingScope = scopeAware ? (props as unknown as { scope?: string }).scope : undefined;
    for (const edgeId of existingEdges) {
      const attrs = this.ctx.graph.getEdgeAttributes(edgeId);
      if (attrs.type !== props.type) continue;
      if (scopeAware) {
        const existingScope = (attrs as { scope?: string }).scope;
        if ((existingScope || undefined) !== (incomingScope || undefined)) continue;
      }
      // Detect confirmation of inferred edge
      if (attrs.inferred_by_rule && !attrs.confirmed_at && props.confidence >= 1.0) {
        props = { ...props, confirmed_at: new Date().toISOString() };
        this.log(`Confirmed inferred edge [${attrs.inferred_by_rule}]: ${source} --[${attrs.type}]--> ${target}`, undefined, { category: 'inference', outcome: 'success', event_type: 'inference_generated' });
      }
      // Update existing edge — property-only change, no topology change
      this.ctx.graph.mergeEdgeAttributes(edgeId, props as Partial<EdgeProperties>);
      this.invalidateHealthReport();
      return { id: edgeId, isNew: false };
    }
    // New edge — topology change
    this.invalidatePathGraph();
    this.invalidateAllCaches();
    // Scope-aware edge keys keep distinct role assignments separate.
    const baseKey = `${source}--${props.type}--${target}`;
    const edgeId = scopeAware && incomingScope
      ? `${baseKey}--${createHash('sha1').update(incomingScope).digest('hex').slice(0, 10)}`
      : baseKey;
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
    // P2.1: journal the drop before applying.
    this.ctx.journalMutation('drop_edge', { source, target, edge_type: type, edge_id: edgeId });
    this.ctx.graph.dropEdge(edgeId);
    this.invalidatePathGraph();
    this.invalidateAllCaches();
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
    this.invalidateAllCaches();
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

  private static readonly DEDUP_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

  ingestFinding(finding: Finding): { new_nodes: string[]; new_edges: string[]; updated_nodes: string[]; updated_edges: string[]; inferred_edges: string[]; deduplicated?: boolean } {
    // --- Finding Deduplication (7.8) ---
    const now = Date.now();

    // Prune stale entries outside the dedup window
    for (const [hash, ts] of this.ctx.recentFindingHashes) {
      if (now - ts > GraphEngine.DEDUP_WINDOW_MS) {
        this.ctx.recentFindingHashes.delete(hash);
      }
    }

    // Compute content hash: tool_name + sorted node signatures + sorted edge keys + raw_output prefix
    // Node signatures include properties (excluding volatile fields) so that
    // re-ingestion with updated properties is NOT treated as a duplicate.
    const volatileKeys = new Set(['discovered_at', 'first_seen_at', 'last_seen_at', 'sources']);
    const sortedNodeSigs = finding.nodes
      .map(n => {
        const stableProps = Object.entries(n)
          .filter(([k]) => !volatileKeys.has(k))
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
          .join('&');
        return stableProps;
      })
      .sort()
      .join(',');
    const sortedEdgeKeys = finding.edges
      .map(e => `${e.source}-${e.target}-${e.properties.type}`)
      .sort()
      .join(',');
    const rawPrefix = (finding.raw_output || '').slice(0, 500);
    const hashInput = `${finding.tool_name || ''}|${sortedNodeSigs}|${sortedEdgeKeys}|${rawPrefix}`;
    const contentHash = createHash('sha256').update(hashInput).digest('hex');

    if (this.ctx.recentFindingHashes.has(contentHash)) {
      this.ctx.dedupCount++;
      // P3.4: when dedup hits, the graph topology stays unchanged (same
      // evidence) but we still merge new attribution onto affected nodes
      // so we don't lose the fact that a second agent / action observed
      // the same thing. Without this, re-runs of the same tool by
      // different agents within the 5-minute window vanished from the
      // cross-attribution audit trail. Resolve each finding node through
      // identity-resolution first so we land on the canonical graph node
      // ID (e.g. an IP-keyed host, not the raw label the finding used).
      const updatedNodes: string[] = [];
      if (finding.agent_id) {
        for (const n of finding.nodes) {
          const resolution = resolveNodeIdentity({
            id: n.id,
            type: n.type as NodeType,
            ip: n.ip,
            hostname: n.hostname,
            label: n.label,
            domain_name: n.domain_name,
            username: n.username,
          });
          const canonicalId = resolution.id;
          if (!this.ctx.graph.hasNode(canonicalId)) continue;
          const existing = this.ctx.graph.getNodeAttributes(canonicalId) as NodeProperties;
          const existingSources = Array.isArray(existing.sources) ? existing.sources : [];
          if (!existingSources.includes(finding.agent_id)) {
            this.ctx.graph.mergeNodeAttributes(canonicalId, {
              sources: [...existingSources, finding.agent_id],
              last_seen_at: finding.timestamp,
            });
            updatedNodes.push(canonicalId);
          }
        }
      }
      return { new_nodes: [], new_edges: [], updated_nodes: updatedNodes, updated_edges: [], inferred_edges: [], deduplicated: true };
    }

    this.ctx.recentFindingHashes.set(contentHash, now);
    const result = ingestFindingImpl(this.findingIngestionHost, finding);

    // Phase 3 (enterprise): cross-tier correlation + inference. Run after
    // each ingest so newly-ingested webapps / cloud_resources / idp_apps /
    // credentials get linked to their cross-tier counterparts.
    try {
      _runCrossTierCorrelator({
        ctx: this.ctx,
        addEdge: this.addEdge.bind(this),
        log: this.log.bind(this),
      });
      _runCrossTierInference({
        ctx: this.ctx,
        addEdge: this.addEdge.bind(this),
        log: this.log.bind(this),
      });
    } catch (err) {
      // Cross-tier inference must never fail the ingest. Log and continue.
      this.log(`Cross-tier inference error: ${err instanceof Error ? err.message : String(err)}`, undefined, { category: 'system', outcome: 'failure' });
    }

    // 7.7: Auto health check after large ingests
    if (result.new_nodes.length >= GraphEngine.HEALTH_AUTO_CHECK_THRESHOLD) {
      this.runAutoHealthCheck(`large ingest: ${result.new_nodes.length} new nodes`);
    }

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

  getInferenceRuleStats(): InferenceRuleEffectiveness[] {
    const ruleStats = new Map<string, { total: number; confirmed: number }>();
    this.ctx.graph.forEachEdge((_edgeId, attrs) => {
      if (!attrs.inferred_by_rule) return;
      const ruleId = attrs.inferred_by_rule as string;
      const stats = ruleStats.get(ruleId) || { total: 0, confirmed: 0 };
      stats.total++;
      if (attrs.confirmed_at) stats.confirmed++;
      ruleStats.set(ruleId, stats);
    });

    return Array.from(ruleStats.entries())
      .filter(([, s]) => s.total >= 3)
      .map(([rule_id, s]) => ({
        rule_id,
        total: s.total,
        confirmed: s.confirmed,
        unconfirmed: s.total - s.confirmed,
        confirmation_rate: s.total > 0 ? s.confirmed / s.total : 0,
      }))
      .sort((a, b) => b.total - a.total);
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
    const c = this.campaignPlanner.pauseCampaign(id);
    if (c) this.persist();
    return c;
  }

  resumeCampaign(id: string): import('../types.js').Campaign | null {
    const c = this.campaignPlanner.resumeCampaign(id);
    if (c) this.persist();
    return c;
  }

  abortCampaign(id: string): import('../types.js').Campaign | null {
    const c = this.campaignPlanner.abortCampaign(id);
    if (c) this.persist();
    return c;
  }

  activateCampaign(id: string): import('../types.js').Campaign | null {
    const c = this.campaignPlanner.activateCampaign(id);
    if (c) this.persist();
    return c;
  }

  createCampaign(params: import('../services/campaign-planner.js').CreateCampaignParams): import('../types.js').Campaign {
    const c = this.campaignPlanner.createCampaign(params);
    this.persist();
    return c;
  }

  updateCampaign(id: string, patch: import('../services/campaign-planner.js').UpdateCampaignParams): import('../types.js').Campaign | null {
    const c = this.campaignPlanner.updateCampaign(id, patch);
    if (c) this.persist();
    return c;
  }

  deleteCampaign(id: string): boolean {
    const ok = this.campaignPlanner.deleteCampaign(id);
    if (ok) this.persist();
    return ok;
  }

  cloneCampaign(id: string): import('../types.js').Campaign | null {
    const c = this.campaignPlanner.cloneCampaign(id);
    if (c) this.persist();
    return c;
  }

  updateCampaignProgress(
    campaignId: string, frontierItemId: string, result: 'success' | 'failure', findingId?: string,
  ): import('../types.js').Campaign | null {
    const c = this.campaignPlanner.updateCampaignProgress(campaignId, frontierItemId, result, findingId);
    if (c) this.persist();
    return c;
  }

  checkCampaignAbortConditions(campaignId: string): { should_abort: boolean; reason?: string } {
    return this.campaignPlanner.checkAbortConditions(campaignId);
  }

  findCampaignForItem(frontierItemId: string): import('../types.js').Campaign | null {
    return this.campaignPlanner.findCampaignForItem(frontierItemId);
  }

  splitCampaign(id: string, count?: number): import('../types.js').Campaign[] | null {
    const cs = this.campaignPlanner.splitCampaign(id, count);
    if (cs) this.persist();
    return cs;
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

      // 2. OPSEC hard veto (only when OPSEC enforcement is enabled)
      if (this.ctx.config.opsec.enabled && item.opsec_noise > this.ctx.config.opsec.max_noise) {
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

      // 4. Active-lease skip — items currently held by a running sub-agent
      // shouldn't be re-surfaced to the primary or another dispatch
      // attempt. Without this, next_task can return work already
      // claimed, causing duplicate validation / dispatch / execution.
      // The lease is held by-task-id; if a re-request comes in from the
      // same task we let it through (the FrontierLeases helper already
      // models that distinction via isHeldByOther).
      const lease = this.ctx.frontierLeases.get(item.id, this.now());
      if (lease) {
        filtered.push({
          item,
          reason: `frontier_item_leased: held by task ${lease.task_id} until ${lease.expires_at}`,
        });
        continue;
      }

      // 5. Annotate items whose scope cannot be verified (no resolvable IP or hostname)
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

  private isNodeVerifiedInScope(nodeId: string): boolean {
    const ip = this.resolveHostIp(nodeId);
    const hostname = this.resolveHostname(nodeId);
    const scope = this.ctx.config.scope;
    if (ip && isScopedHostInScope(ip, scope)) return true;
    if (hostname && isScopedHostInScope(hostname, scope)) return true;
    // Nodes without IP/hostname (user, group, credential, etc.) are considered in-scope
    if (!ip && !hostname) return true;
    return false;
  }

  private isNodeExcluded(nodeId: string): string | null {
    const ip = this.resolveHostIp(nodeId);
    const hostname = this.resolveHostname(nodeId);
    const scope = this.ctx.config.scope;

    // Explicitly excluded → return the identifier (truthy = excluded)
    if (ip && isHostExcluded(ip, scope.exclusions)) return ip;
    if (hostname && isHostExcluded(hostname, scope.exclusions)) return hostname;
    // Explicitly in scope → not excluded
    if (ip && isScopedHostInScope(ip, scope)) return null;
    if (hostname && isScopedHostInScope(hostname, scope)) return null;
    // Neither excluded nor confirmed in-scope → fail open, let scope_unverified annotation handle it
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
    /** Operator override: skip the fail-closed check for unverified host/service/share nodes. */
    allow_unverified_scope?: boolean;
  }): {
    valid: boolean;
    errors: string[];
    warnings: string[];
    opsec_context: OpsecContext;
    /**
     * True when OPSEC enforcement is opt-in but disabled for this engagement
     * (`opsec.enabled !== true`). Surfaced so tools can be honest with the
     * caller that blacklist/time-window/noise-ceiling checks were not run.
     * Phase 2 (B): part of the visibility pass that keeps OPSEC opt-in but
     * makes the inert state impossible to miss.
     */
    opsec_skipped?: boolean;
    recent_outcomes?: RecentOutcome[];
    technique_success_rate?: { engagement: number; engagement_attempts: number; kb: number; kb_attempts: number };
    cooldown_suggestion?: string;
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
    //    isNodeExcluded returns truthy only for explicitly excluded nodes.
    //    For host/service/share nodes that cannot be verified in-scope we
    //    fail closed (error) unless the caller passes
    //    allow_unverified_scope=true. For other node types (user, group,
    //    credential, …) we keep the historical warning behavior because
    //    they have no IP/hostname to scope-check against.
    for (const [label, nodeId] of [
      ['Target', action.target_node],
      ['Edge source', action.edge_source],
      ['Edge target', action.edge_target],
    ] as const) {
      if (!nodeId) continue;
      const excludedIp = this.isNodeExcluded(nodeId);
      if (excludedIp) {
        errors.push(`${label} is out of scope: ${excludedIp}`);
      } else if (!this.isNodeVerifiedInScope(nodeId)) {
        const nodeAttrs = this.ctx.graph.hasNode(nodeId)
          ? (this.ctx.graph.getNodeAttributes(nodeId) as { type?: string })
          : undefined;
        const nodeType = nodeAttrs?.type;
        const isNetworkNode = nodeType === 'host' || nodeType === 'service' || nodeType === 'share';
        if (isNetworkNode && !action.allow_unverified_scope) {
          errors.push(
            `${label} scope unverified: ${nodeId} — not explicitly in-scope CIDRs/domains. ` +
              `Set allow_unverified_scope:true to override.`,
          );
        } else {
          warnings.push(`${label} scope unverified: ${nodeId} — not explicitly in-scope CIDRs/domains`);
        }
      }
    }

    // OPSEC enforcement (only when enabled). P4.1: read the effective
    // profile, which folds in the active phase's `opsec_overrides`.
    const effectiveOpsec = this.getEffectiveOpsec();
    if (effectiveOpsec.enabled) {
      // Check OPSEC blacklist (engagement-level + phase-extended).
      const effectiveBlacklist = this.getEffectiveApprovalConfig().blacklisted_techniques;
      if (action.technique && effectiveBlacklist.includes(action.technique)) {
        errors.push(`Technique blacklisted by OPSEC profile: ${action.technique}`);
      }

      // Time window check (handles wrap-around, e.g. 22:00–06:00)
      if (effectiveOpsec.time_window) {
        const { start_hour, end_hour } = effectiveOpsec.time_window;
        const now = new Date();
        if (!isInTimeWindow(start_hour, end_hour, now)) {
          const hour = now.getHours();
          warnings.push(`Outside approved time window (${start_hour}:00-${end_hour}:00), current hour: ${hour}`);
        }
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

    // Noise budget warning (only when OPSEC enforcement is enabled).
    // P4.1: report against the effective max_noise (phase override if any).
    if (effectiveOpsec.enabled) {
      if (opsec_context.noise_budget_remaining <= 0) {
        warnings.push('Noise budget exhausted — only passive/zero-noise actions recommended.');
      } else if (this.ctx.opsecTracker.isApproachingCeiling(host_id || undefined, domain)) {
        warnings.push(`Noise budget approaching ceiling (${opsec_context.noise_budget_remaining} remaining of ${effectiveOpsec.max_noise}).`);
      }
    }

    // --- Outcome feedback loop ---
    let recent_outcomes: RecentOutcome[] | undefined;
    let technique_success_rate: { engagement: number; engagement_attempts: number; kb: number; kb_attempts: number } | undefined;
    let cooldown_suggestion: string | undefined;

    if (action.technique) {
      const targetIds = [action.target_node, action.edge_target].filter(Boolean) as string[];
      const targetIps = action.target_ip ? [action.target_ip] : [];

      // Gather recent outcomes for this technique from the activity log
      recent_outcomes = this.getRecentOutcomes(action.technique, targetIds, targetIps);

      // Compute engagement-level success rate for this technique
      const allForTechnique = this.ctx.activityLog.filter(e =>
        e.technique === action.technique &&
        (e.event_type === 'action_completed' || e.event_type === 'action_failed') &&
        e.outcome
      );
      if (allForTechnique.length > 0) {
        const successes = allForTechnique.filter(e => e.outcome === 'success').length;
        const engRate = successes / allForTechnique.length;
        const kb = this.getKB();
        const kbStats = kb?.getTechniqueStats(action.technique);
        technique_success_rate = {
          engagement: Math.round(engRate * 100) / 100,
          engagement_attempts: allForTechnique.length,
          kb: kbStats ? kbStats.success_rate : -1,
          kb_attempts: kbStats ? kbStats.attempts : 0,
        };
      }

      // Similar-target failure warnings via community matching
      if (targetIds.length > 0) {
        const communities = this.getCommunities();
        const targetCommunityIds = new Set<number>();
        for (const tid of targetIds) {
          const cid = communities.get(tid);
          if (cid !== undefined) targetCommunityIds.add(cid);
        }
        if (targetCommunityIds.size > 0) {
          const similarFailures = this.ctx.activityLog.filter(e =>
            e.technique === action.technique &&
            e.outcome === 'failure' &&
            e.target_node_ids?.some(nid => {
              const cid = communities.get(nid);
              return cid !== undefined && targetCommunityIds.has(cid);
            })
          );
          // Exclude entries that are already in recent_outcomes (same target)
          const directTargetSet = new Set([...targetIds, ...targetIps]);
          const uniqueSimilar = similarFailures.filter(e =>
            !e.target_node_ids?.some(nid => directTargetSet.has(nid)) &&
            !e.target_ips?.some(ip => directTargetSet.has(ip))
          );
          if (uniqueSimilar.length > 0) {
            const targetLabels = uniqueSimilar.slice(-3).map(e => {
              const nid = e.target_node_ids?.[0];
              if (nid && this.ctx.graph.hasNode(nid)) {
                return this.ctx.graph.getNodeAttribute(nid, 'label') || nid;
              }
              return e.target_ips?.[0] || nid || 'unknown';
            });
            warnings.push(
              `${action.technique} failed on ${uniqueSimilar.length} similar target(s) in the same network community: ${targetLabels.join(', ')}. Consider a different approach.`
            );
          }
        }
      }

      // Cool-down suggestion: 3+ consecutive failures with this technique
      const recentForTechnique = this.ctx.activityLog.filter(e =>
        e.technique === action.technique &&
        (e.event_type === 'action_completed' || e.event_type === 'action_failed') &&
        e.outcome
      );
      if (recentForTechnique.length >= 3) {
        const lastThree = recentForTechnique.slice(-3);
        const allFailed = lastThree.every(e => e.outcome === 'failure');
        if (allFailed) {
          const kb = this.getKB();
          const alternatives = kb ? kb.getTopTechniques(5)
            .filter(t => t.technique_id !== action.technique && t.success_rate > 0.3)
            .map(t => t.technique_id)
            .slice(0, 3) : [];
          cooldown_suggestion = `${action.technique} has failed ${recentForTechnique.filter(e => e.outcome === 'failure').length} consecutive time(s) in this engagement.`
            + (alternatives.length > 0
              ? ` Consider alternatives: ${alternatives.join(', ')}.`
              : ' Consider a different approach or verify prerequisites.');
          warnings.push(cooldown_suggestion);
        }
      }
    }

    return {
      valid: errors.length === 0, errors, warnings, opsec_context,
      ...(effectiveOpsec.enabled ? {} : { opsec_skipped: true }),
      ...(recent_outcomes && recent_outcomes.length > 0 ? { recent_outcomes } : {}),
      ...(technique_success_rate ? { technique_success_rate } : {}),
      ...(cooldown_suggestion ? { cooldown_suggestion } : {}),
    };
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

  private getRecentOutcomes(technique: string, targetIds: string[], targetIps: string[], limit: number = 5): RecentOutcome[] {
    const targetSet = new Set([...targetIds, ...targetIps]);
    const outcomes: RecentOutcome[] = [];

    // Scan activity log in reverse for matching technique × target entries
    for (let i = this.ctx.activityLog.length - 1; i >= 0 && outcomes.length < limit; i--) {
      const entry = this.ctx.activityLog[i];
      if (entry.technique !== technique) continue;
      if (entry.event_type !== 'action_completed' && entry.event_type !== 'action_failed') continue;
      if (!entry.outcome) continue;

      // Match by target node IDs or target IPs
      const matchesByNode = entry.target_node_ids?.some(nid => targetSet.has(nid));
      const matchesByIp = entry.target_ips?.some(ip => targetSet.has(ip));

      // Also accept technique-only matches (same technique, any target) for broader context
      const targetLabel = entry.target_node_ids?.[0]
        ? (this.ctx.graph.hasNode(entry.target_node_ids[0])
          ? this.ctx.graph.getNodeAttribute(entry.target_node_ids[0], 'label') || entry.target_node_ids[0]
          : entry.target_node_ids[0])
        : entry.target_ips?.[0] || 'unknown';

      if (matchesByNode || matchesByIp) {
        // Direct match — include with full detail
        outcomes.unshift({
          target: targetLabel,
          timestamp: entry.timestamp,
          result: entry.outcome as 'success' | 'failure' | 'neutral',
          reason: entry.description,
          technique: entry.technique,
          action_id: entry.action_id,
        });
      } else if (outcomes.length < limit) {
        // Same technique, different target — useful for seeing pattern
        outcomes.unshift({
          target: targetLabel,
          timestamp: entry.timestamp,
          result: entry.outcome as 'success' | 'failure' | 'neutral',
          reason: entry.description,
          technique: entry.technique,
          action_id: entry.action_id,
        });
      }
    }

    return outcomes.slice(0, limit);
  }

  // =============================================
  // Session → Graph Integration (delegated to SessionTracker)
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
    _ingestSessionResult(this.sessionHost, result);
  }

  onSessionClosed(_sessionId: string, targetNode?: string, principalNode?: string): void {
    _onSessionClosed(this.sessionHost, _sessionId, targetNode, principalNode);
  }

  reconcileSessionEdgesOnStartup(): void {
    _reconcileSessionEdgesOnStartup(this.sessionHost);
  }

  // =============================================
  // Objective Tracking (delegated to ObjectiveManager)
  // =============================================

  private evaluateObjectives(): void {
    _evaluateObjectives(this.objectiveHost);
    // P4.1: detect phase transitions whenever objectives change. The
    // `phase_entered` / `phase_exited` events get hash-chained and feed
    // the dashboard timeline + decision log.
    this.recordPhaseTransitionsIfAny();
  }

  /**
   * P4.1: compare the live active-phase id to the last-observed one and
   * emit `phase_entered` / `phase_exited` events on change. Called from
   * `evaluateObjectives` after every ingest. Idempotent — no events are
   * emitted when the phase hasn't moved.
   */
  private recordPhaseTransitionsIfAny(): void {
    const currentId = this.getCurrentPhaseId();
    const previousId = this.ctx.lastKnownPhaseId;
    if (currentId === previousId) return;
    if (previousId) {
      this.logActionEvent({
        description: `Phase exited: ${previousId}`,
        event_type: 'phase_exited',
        category: 'system',
        result_classification: 'neutral',
        details: { phase_id: previousId, next_phase_id: currentId ?? null },
      });
    }
    if (currentId) {
      this.logActionEvent({
        description: `Phase entered: ${currentId}`,
        event_type: 'phase_entered',
        category: 'system',
        result_classification: 'neutral',
        details: { phase_id: currentId, previous_phase_id: previousId ?? null },
      });
    }
    this.ctx.lastKnownPhaseId = currentId;
  }

  recomputeObjectives(): { before: Array<{ id: string; achieved: boolean; achieved_at?: string }>; after: Array<{ id: string; achieved: boolean; achieved_at?: string }> } {
    return _recomputeObjectives(this.objectiveHost);
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

  registerAgent(task: AgentTask): { ok: boolean; lease_conflict?: { existing_task_id: string; existing_agent_id: string } } {
    const result = this.agentMgr.register(task);
    this.persist();
    return result;
  }

  getRunningTaskForFrontierItem(frontierItemId: string): AgentTask | null {
    return this.agentMgr.getRunningTaskForFrontierItem(frontierItemId);
  }

  getTask(taskId: string): AgentTask | null {
    return this.agentMgr.getTask(taskId);
  }

  /** All known agent tasks (running, completed, failed, interrupted). */
  getAgentTasks(): AgentTask[] {
    return this.agentMgr.getAll();
  }

  /**
   * P1.3: read the current ISO timestamp through the engine. Honors
   * `withClock(...)` injection if active; otherwise wall-clock.
   */
  now(): string {
    return this.ctx.nowIso();
  }

  /**
   * P1.3: scoped clock injection passthrough. Used by integration tests
   * and the golden-master replay harness to pin time across a sequence
   * of MCP calls so timestamps in the recorded graph stay deterministic.
   */
  withClock<T>(now: string, fn: () => T): T {
    return this.ctx.withClock(now, fn);
  }

  /**
   * P1.2: bump and return the per-engagement deterministic-ID sequence
   * counter. Caller passes the value into `deterministicActionId(...)`.
   */
  nextDeterministicSeq(): number {
    return this.ctx.nextDeterministicSeq();
  }

  /** P0.3: heartbeat + watchdog passthrough. */
  agentHeartbeat(taskId: string, now?: string): boolean {
    const ok = this.agentMgr.heartbeat(taskId, now);
    if (ok) this.persist();
    return ok;
  }

  reapStaleAgents(now?: string): number {
    const reaped = this.agentMgr.reapStaleHeartbeats(now);
    if (reaped > 0) this.persist();
    return reaped;
  }

  /**
   * F4 (regression visibility): re-trigger the same reconciliation that
   * runs on engine startup. Used by tests and operators investigating a
   * stuck-running task surface to flip persisted-running tasks to
   * 'interrupted' and release the frontier leases they held.
   */
  reconcileAgentsOnStartup(): number {
    const count = this.agentMgr.reconcileOnStartup();
    if (count > 0) this.persist();
    return count;
  }

  /**
   * P1.4: list active frontier leases (used by `next_task` filtering and
   * by the dashboard to surface "in progress" indicators).
   */
  getActiveFrontierLeases(now?: string): import('./frontier-leases.js').FrontierLease[] {
    return this.ctx.frontierLeases.list(now ?? this.ctx.nowIso());
  }

  /** True iff `frontier_item_id` is leased by a different task than `requesterTaskId`. */
  isFrontierItemHeldByOther(frontier_item_id: string, requesterTaskId?: string, now?: string): boolean {
    return this.ctx.frontierLeases.isHeldByOther(
      frontier_item_id,
      requesterTaskId,
      now ?? this.ctx.nowIso(),
    );
  }

  /**
   * P1.4: drop frontier leases whose TTL has elapsed. Called by the
   * watchdog. Returns the dropped frontier_item_ids.
   */
  reapExpiredFrontierLeases(now?: string): string[] {
    return this.ctx.frontierLeases.reapExpired(now ?? this.ctx.nowIso());
  }

  /**
   * P3.1: derive the decision log from the activity log + frontier
   * linkage. Pure function; no caching beyond what the underlying
   * sources provide. Pass `query` to filter by action/frontier/agent/outcome.
   */
  getDecisionLog(query?: DecisionLogQuery): DecisionEntry[] {
    const all = buildDecisionLog(this.ctx.activityLog, this.ctx.frontierLinkage.getAll());
    return query ? queryDecisionLog(all, query) : all;
  }

  /**
   * P3.2: produce a single "why did the agent do X?" answer for an
   * action_id. Aggregates frontier item, log_thought chain, considered
   * alternatives, prior action references, validation/approval/outcome.
   * Read-only; no caching beyond the underlying activity log.
   */
  explainAction(actionId: string): ExplainActionResult {
    return explainAction(
      this.ctx.activityLog,
      actionId,
      (id) => this.getFrontierItem(id) ?? undefined,
    );
  }

  /**
   * P3.3: derive the engagement timeline (per-node and per-edge "when
   * was X true?") from the current graph + activity log. Pass `query`
   * to filter / scope / time-slice. Pure read; no caching.
   */
  getTimeline(query?: TimelineQuery): TimelineEntry[] {
    const all = buildTimeline(this.exportGraph(), this.ctx.activityLog);
    return query ? queryTimeline(all, query) : all;
  }

  /**
   * P4.1: effective OPSEC profile for the current phase. Returns the
   * engagement-level OPSEC merged with any `opsec_overrides` on the
   * currently-active phase. Validation paths read this instead of
   * `config.opsec` directly so phase-specific tightening (e.g., lower
   * max_noise during exploitation) actually bites.
   */
  getEffectiveOpsec(): typeof this.ctx.config.opsec {
    const phase = _getCurrentPhase(this.objectiveHost);
    const overrides = phase?.opsec_overrides;
    if (!overrides) return this.ctx.config.opsec;
    return { ...this.ctx.config.opsec, ...overrides } as typeof this.ctx.config.opsec;
  }

  /**
   * Phase B: report whether the engagement has OPSEC enforcement gates
   * configured non-trivially while `enabled !== true`. The dashboard reads
   * this to render an "OPSEC INERT" badge so the configured-but-disabled
   * state is visible to humans.
   */
  getOpsecStatus(): { enabled: boolean; configured_fields: string[]; inert: boolean } {
    const o = this.getEffectiveOpsec();
    const enabled = o.enabled === true;
    const configured: string[] = [];
    if (typeof o.max_noise === 'number' && o.max_noise < 1) configured.push('max_noise');
    if (Array.isArray(o.blacklisted_techniques) && o.blacklisted_techniques.length > 0) configured.push('blacklisted_techniques');
    if (o.time_window) configured.push('time_window');
    return { enabled, configured_fields: configured, inert: !enabled && configured.length > 0 };
  }

  private warnIfOpsecInert(): void {
    const status = this.getOpsecStatus();
    if (!status.inert) return;
    const o = this.getEffectiveOpsec();
    const parts: string[] = [];
    if (typeof o.max_noise === 'number') parts.push(`max_noise=${o.max_noise}`);
    if (Array.isArray(o.blacklisted_techniques) && o.blacklisted_techniques.length > 0) {
      parts.push(`blacklist=[${o.blacklisted_techniques.join(', ')}]`);
    }
    if (o.time_window) parts.push(`time_window=${o.time_window.start_hour}-${o.time_window.end_hour}`);
    const detail = parts.join(', ');
    console.warn(
      `[OPSEC] inert: ${detail} configured but enforcement is disabled (opsec.enabled=false). ` +
      'Set opsec.enabled=true to enforce.',
    );
    // Persist a system event so the dashboard activity panel and retrospective
    // pipeline can show this without scraping stderr. Pin the timestamp to
    // `config.created_at` when present so the event participates in golden
    // master determinism — without this, every replay would log a new wall-
    // clock timestamp and the activity digest would drift run-to-run.
    try {
      const seedAt = this.ctx.config.created_at;
      const emit = () => this.logActionEvent({
        description: 'OPSEC enforcement is configured but disabled',
        event_type: 'instrumentation_warning',
        category: 'system',
        details: {
          opsec_status: status,
          inert_fields: status.configured_fields,
          message: `OPSEC inert (${detail}); set opsec.enabled=true to enforce.`,
        },
      });
      if (seedAt) this.ctx.withClock(seedAt, emit);
      else emit();
    } catch {
      // best-effort — never fail engine startup over a warning event
    }
  }

  /**
   * P4.1: effective approval mode + blacklist for the current phase.
   * Used by `pending-action-queue.needsApproval`.
   */
  getEffectiveApprovalConfig(): { mode: import('../types.js').ApprovalMode; blacklisted_techniques: string[] } {
    const phase = _getCurrentPhase(this.objectiveHost);
    const baseMode = this.ctx.config.opsec.approval_mode ?? 'auto-approve';
    const baseBlacklist = this.ctx.config.opsec.blacklisted_techniques ?? [];
    const overrides = phase?.approval_overrides;
    return {
      mode: overrides?.mode ?? baseMode,
      // Phase blacklist EXTENDS the engagement-level one (not replaces) so
      // operator-level safety rules can't be silently weakened by a phase.
      blacklisted_techniques: overrides?.blacklisted_techniques
        ? [...new Set([...baseBlacklist, ...overrides.blacklisted_techniques])]
        : baseBlacklist,
    };
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

  getState(options?: { activityCount?: number; includeReasoning?: boolean; includeSystem?: boolean }): EngagementState {
    const activityCount = options?.activityCount ?? 20;
    const includeReasoning = options?.includeReasoning ?? false;
    const includeSystem = options?.includeSystem ?? true;
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
      // P3.3: distinguish confirmed vs inferred by provenance, not raw
      // confidence. An inference rule that ships at confidence 1.0 is still
      // inferred; a parser-discovered edge that came in at 0.9 due to noise
      // is still confirmed (observed). The previous `confidence >= 1.0`
      // bucketing mislabeled both classes. Rule:
      //   inferred  = has `inferred_by_rule` AND no `confirmed_at`
      //   confirmed = everything else (parser-observed, or inference whose
      //               edge has since been confirmed by direct evidence)
      const isInferred = !!attrs.inferred_by_rule && !attrs.confirmed_at;
      if (isInferred) inferredEdges++;
      else confirmedEdges++;
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
      recent_activity: this.filterRecentActivity({ activityCount, includeReasoning, includeSystem }),
      access_summary: {
        compromised_hosts: compromised,
        valid_credentials: validCreds,
        current_access_level: _computeAccessLevel(this.objectiveHost, compromised)
      },
      warnings: summarizeHealthReport(healthReport),
      lab_readiness: labReadiness,
      scope_suggestions: this.collectScopeSuggestions(),
      phases: this.getPhaseStatuses(),
      current_phase: this.getCurrentPhaseId(),
      inference_rule_effectiveness: this.getInferenceRuleStats(),
    credential_coverage: this.getCredentialCoverage(),
    };
  }

  // --- Phase orchestration ---

  /** Evaluate all engagement phases and return runtime statuses */
  getPhaseStatuses(): EngagementState['phases'] {
    return _getPhaseStatuses(this.objectiveHost);
  }

  getCurrentPhaseId(): string | undefined {
    return _getCurrentPhaseId(this.objectiveHost);
  }

  // =============================================
  // Scope Management
  // =============================================

  private get configHost(): ConfigManagerHost {
    return {
      ctx: this.ctx,
      addNode: this.addNode.bind(this),
      persist: (() => this.persist()) as () => void,
    };
  }

  private get sessionHost(): SessionTrackerHost {
    return {
      ctx: this.ctx,
      logActionEvent: this.logActionEvent.bind(this),
      log: this.log.bind(this),
      persist: (() => this.persist()) as () => void,
      invalidateFrontierCache: this.invalidateFrontierCache.bind(this),
      invalidatePathGraph: this.invalidatePathGraph.bind(this),
    };
  }

  private get objectiveHost(): ObjectiveManagerHost {
    return {
      ctx: this.ctx,
      getNode: this.getNode.bind(this),
      getNodesByType: this.getNodesByType.bind(this),
      queryGraph: this.queryGraph.bind(this),
      persist: (() => this.persist()) as () => void,
      log: this.log.bind(this),
    };
  }

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
    // Callers (addNode, addEdge, dropEdge, patchNodeProperties) already
    // invalidate the appropriate caches before calling persist.
    this.persistence.persist(detail);
  }

  /**
   * Execute a batch of mutations with a single coalesced persist at the end.
   * All persist() calls within `fn` are suppressed until the batch completes.
   * Batches can nest — only the outermost triggers the flush.
   */
  batchMutate(fn: () => void): void {
    this.persistence.beginBatch();
    try {
      fn();
    } finally {
      this.persistence.endBatch();
    }
  }

  /**
   * Async version of batchMutate for async operations.
   */
  async batchMutateAsync(fn: () => Promise<void>): Promise<void> {
    this.persistence.beginBatch();
    try {
      await fn();
    } finally {
      this.persistence.endBatch();
    }
  }

  /**
   * Force an immediate flush of any pending state to disk.
   * Use when you need to guarantee state is persisted before proceeding.
   */
  flushNow(): void {
    this.persistence.flushNow();
  }

  /**
   * Returns persistence performance metrics for observability.
   */
  getPersistMetrics(): import('./state-persistence.js').PersistMetrics {
    return this.persistence.getMetrics();
  }

  /**
   * Tear down timers and process listeners.
   * Call during graceful shutdown or in tests to avoid leaked state.
   */
  dispose(): void {
    this.persistence.dispose();
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

  /** True when OPSEC enforcement is enabled (drives the hard noise ceiling).
   * P4.1: honors the active phase's `opsec_overrides.enabled` if set. */
  isOpsecEnforcementEnabled(): boolean {
    return this.getEffectiveOpsec().enabled === true;
  }

  /** Effective max_noise (phase override if any; engagement-level otherwise).
   * Reused by the runner to format ceiling rejections. */
  getMaxNoise(): number {
    return this.getEffectiveOpsec().max_noise;
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
    if (ok) this.invalidateAllCaches();
    return ok;
  }

  // =============================================
  // Evidence
  // =============================================

  getFullHistory(): ActivityLogEntry[] {
    return [...this.ctx.activityLog];
  }

  /** Frontier linkage tracker: lifecycle status of every surfaced frontier item. */
  getFrontierLinkage(): import('./frontier-linkage.js').FrontierLinkageTracker {
    return this.ctx.frontierLinkage;
  }

  /**
   * Filter the recent activity tail for `get_state` consumers.
   * Defaults hide reasoning (high-volume `log_thought` output) and keep
   * system events. The full log remains available via `getFullHistory`.
   */
  private filterRecentActivity(opts: { activityCount: number; includeReasoning: boolean; includeSystem: boolean }): ActivityLogEntry[] {
    const { activityCount, includeReasoning, includeSystem } = opts;
    const log = this.ctx.activityLog;
    if (includeReasoning && includeSystem) return log.slice(-activityCount);
    // Walk backwards collecting the most recent N entries that pass the filter.
    const out: ActivityLogEntry[] = [];
    for (let i = log.length - 1; i >= 0 && out.length < activityCount; i--) {
      const entry = log[i];
      if (!includeReasoning && (entry.event_type === 'thought' || entry.category === 'reasoning')) continue;
      if (!includeSystem && entry.category === 'system') continue;
      out.push(entry);
    }
    return out.reverse();
  }

  getInferenceRules(): InferenceRule[] {
    return [...this.ctx.inferenceRules];
  }

  getConfig(): EngagementConfig {
    return this.ctx.config;
  }

  updateConfig(partial: Record<string, unknown>): EngagementConfig {
    return _updateConfig(this.configHost, partial);
  }

  addObjective(obj: { description: string; target_node_type?: string; target_criteria?: Record<string, unknown>; achievement_edge_types?: string[] }): EngagementConfig['objectives'][0] {
    return _addObjective(this.objectiveHost, obj);
  }

  updateObjective(id: string, updates: Record<string, unknown>): boolean {
    return _updateObjective(this.objectiveHost, id, updates);
  }

  removeObjective(id: string): boolean {
    return _removeObjective(this.objectiveHost, id);
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

  getCredentialCoverage(): import('../types.js').CredentialCoverage {
    const tracker = new CredentialCoverageTracker(this.ctx);
    const result = tracker.compute((nodeId) => this.hopsToNearestObjective(nodeId));
    // Return just the CredentialCoverage part (without untested_pairs array)
    const { untested_pairs: _, ...coverage } = result;
    return coverage;
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

  exportGraph(options?: { includeSuperseded?: boolean; includeCold?: boolean }): ExportedGraph {
    const includeSuperseded = options?.includeSuperseded ?? false;
    const includeCold = options?.includeCold ?? true;
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

    // P3.2: include cold-store hosts in exports so reports and downstream
    // tooling don't lose them. Cold = alive ping-sweep responders with no
    // services and no interesting edges. They are not part of the live
    // graphology graph but ARE part of the engagement inventory.
    let cold_nodes: ExportedGraph['cold_nodes'];
    if (includeCold) {
      const records: NonNullable<ExportedGraph['cold_nodes']> = [];
      this.ctx.coldStore.forEach((record) => {
        records.push({ ...record });
      });
      if (records.length > 0) cold_nodes = records;
    }

    return cold_nodes ? { nodes, edges, cold_nodes } : { nodes, edges };
  }

  private runHealthChecks(): HealthReport {
    if (!this.healthReportCache) {
      this.healthReportCache = runHealthChecks(this.ctx.graph);
    }
    return this.healthReportCache;
  }

  private invalidateHealthReport(): void {
    this.healthReportCache = null;
  }

  private static readonly HEALTH_AUTO_CHECK_THRESHOLD = 50;

  private runAutoHealthCheck(trigger: string): void {
    const report = this.runHealthChecks();
    if (report.status !== 'healthy') {
      const { critical, warning } = report.counts_by_severity;
      this.log(
        `Auto health check (${trigger}): ${critical} critical, ${warning} warning issue(s)`,
        undefined,
        { category: 'system', event_type: 'system' },
      );
    }
  }

  private invalidateAllCaches(): void {
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
    _syncObjectiveNodes(this.objectiveHost);
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
