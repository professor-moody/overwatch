// ============================================================
// Overwatch — Graph Engine
// Engagement state as a directed property graph
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import { createOverwatchGraph } from './graphology-types.js';
import { existsSync } from 'fs';
import { isIpInCidr, isUrlInScope, isCloudResourceInScope, isHostExcluded, isHostInScope as isScopedHostInScope, isCidrInScope } from './cidr.js';
import { EngineContext } from './engine-context.js';
import type {
  ActivityEventType,
  ActivityLogEntry,
  ActivityLogInput,
  GraphUpdateCallback,
  GraphUpdateDetail,
  OverwatchGraph,
} from './engine-context.js';
import { StatePersistence } from './state-persistence.js';
import { FrontierLinkageTracker } from './frontier-linkage.js';
import { AgentManager } from './agent-manager.js';
import {
  agentLabelOf,
  coordinationRecoveryWarning,
  mergeCoordinationRecoveryWarnings,
  normalizeAgentTask,
  taskIdOf,
  type AgentIdentityResolution,
  type AgentTaskInput,
} from './agent-identity.js';
import { isTargetFacing } from './agent-archetypes.js';
import { InferenceEngine } from './inference-engine.js';
import { PathAnalyzer } from './path-analyzer.js';
import type { PathOptimize, PathResult } from './path-analyzer.js';
import { FrontierComputer } from './frontier.js';
import { sourceTrust } from './source-trust.js';
import { ChainScorer } from './chain-scorer.js';
import { CampaignPlanner } from './campaign-planner.js';
import { getCredentialDisplayKind, isCredentialUsableForAuth } from './credential-utils.js';
import { runHealthChecks, summarizeHealthReport, hasADContext, contextualFilterHealthReport } from './graph-health.js';
import { summarizeInlineLabReadiness } from './lab-preflight.js';
import { normalizeFindingNode, validateFindingNode } from './finding-validation.js';
import { validateEdgeEndpoints } from './graph-schema.js';
import { normalizeNodeProvenance } from './provenance-utils.js';
import {
  planIdentityRewrite,
  type ReconciliationResult,
} from './identity-reconciliation.js';
import { detectCommunities, communityStats } from './community-detection.js';
import { EvidenceStore } from './evidence-store.js';
import { ActionOutputBuffer } from './action-output-buffer.js';
import type { SkillIndex } from './skill-index.js';
import { ReportArchive } from './report-archive.js';
import { BUILTIN_RULES } from './builtin-inference-rules.js';
import { BloodHoundPathEnricher } from './bloodhound-paths.js';
import type { HVTResult, PreComputedPath } from './bloodhound-paths.js';
import { KnowledgeBase } from './knowledge-base.js';
import {
  deterministicCollisionEdgeKey,
  edgeIdentityMatches,
  preferredEdgeKey,
} from './edge-identity.js';
import { WebChainEnricher } from './web-attack-chains.js';
import type { MatchedChain } from './web-attack-chains.js';
import type { OpsecContext } from './opsec-tracker.js';
import { isInTimeWindow } from './opsec-tracker.js';
import type { ActionResolution, DurableApprovalRecord, PendingAction } from './pending-action-queue.js';
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
  collectScopeSuggestions as _collectScopeSuggestions,
  planScopeUpdate,
  previewScopeChange as _previewScopeChange,
} from './scope-manager.js';
import type { ScopeManagerHost, ScopeUpdatePlan } from './scope-manager.js';
import { isPassiveTechnique } from './osint-techniques.js';
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
  mergeConfig,
} from './config-manager.js';
import type { ConfigManagerHost } from './config-manager.js';
import {
  EngagementConfigService,
  canonicalJson,
  computeConfigHash,
  type ConfigApplyContext,
  type ConfigCommitEvent,
  type ResolveConfigDivergenceInput,
  type ResolveConfigDivergenceResult,
} from './engagement-config-service.js';
import type {
  DropNodeMutationPayloadV1,
  GraphCorrectedMutationPayloadV1,
  IdentityRewriteMutationPayloadV1,
  MutationApplyResult,
  ScopeUpdatedMutationPayloadV1,
} from './mutation-journal.js';
import { MutationJournal } from './mutation-journal.js';
import type {
  DurableStatePatchV1,
  DurableStateSliceKey,
  DurableStateSlices,
} from './durable-state-patch.js';
import type { EngineOperation } from './engine-transaction.js';
import {
  evaluateObjectives as _evaluateObjectives,
  recomputeObjectives as _recomputeObjectives,
  getPhaseStatuses as _getPhaseStatuses,
  getCurrentPhaseId as _getCurrentPhaseId,
  getCurrentPhase as _getCurrentPhase,
  computeAccessLevel as _computeAccessLevel,
} from './objective-manager.js';
import type { ObjectiveManagerHost } from './objective-manager.js';
import { queryGraphImpl } from './graph-query.js';
import { CredentialCoverageTracker } from './credential-coverage.js';
import type { OperatorOp } from './command-interpreter.js';
import type {
  PersistedApplicationCommandV1,
  PersistedCommandOutcomeV1,
  PersistedCommandPlanV1,
  PersistedPlaybookRunV1,
  PersistedRuntimeRunV1,
  PersistedSessionDescriptorV1,
} from './persisted-state.js';
import { engagementConfigSchema, inferProfile } from '../types.js';
import type {
  NodeProperties, EdgeProperties, NodeType, EdgeType,
  EngagementConfig, EngagementState, FrontierItem,
  Finding, InferenceRule, GraphQuery, GraphQueryResult,
  AgentTask, ExportedGraph, HealthReport, GraphCorrectionOperation,
  ScopeSuggestion, InferenceRuleEffectiveness,
  PersistenceRecoveryStatus,
  ConfigRecoveryStatus,
  ConfigIntentConflict,
  SessionCapabilities,
  SessionMetadata,
  SessionDefaultValidation,
} from '../types.js';

/** Public read surfaces must not leak mutable references into durable engine
 * state. A caller holding one of those references could otherwise bypass the
 * persistence gate simply by assigning a property. */
function detached<T>(value: T): T {
  return structuredClone(value);
}

export interface RecentOutcome {
  target: string;
  timestamp: string;
  result: 'success' | 'failure' | 'neutral';
  reason?: string;
  technique?: string;
  action_id?: string;
}

export type FindingIngestResult = {
  new_nodes: string[];
  new_edges: string[];
  updated_nodes: string[];
  updated_edges: string[];
  inferred_edges: string[];
  deduplicated?: boolean;
  campaign_id?: string;
};

export interface FindingIngestCompletion {
  additional_state_keys?: readonly DurableStateSliceKey[];
  /**
   * Runs inside the finding's speculative durable draft. Command receipts and
   * terminal audit events installed here commit with the graph/campaign delta.
   */
  complete(result: FindingIngestResult): void;
}

type FindingDraftResult = {
  result: Omit<FindingIngestResult, 'deduplicated' | 'campaign_id'>;
  campaign_id?: string;
};

type ExactGraphDelta = Pick<IdentityRewriteMutationPayloadV1, 'node_changes' | 'edge_changes'>;

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

const RECOVERED_LISTENER_CAPABILITIES: SessionCapabilities = {
  has_stdin: true,
  has_stdout: true,
  supports_resize: false,
  supports_signals: false,
  tty_quality: 'dumb',
};

function persistedSessionLifecycle(
  lifecycle: SessionMetadata['state'],
): Pick<PersistedSessionDescriptorV1, 'lifecycle' | 'recovery_lifecycle'> {
  if (lifecycle === 'resume_available') {
    return { lifecycle: 'closed', recovery_lifecycle: 'resume_available' };
  }
  if (lifecycle === 'interrupted') {
    return { lifecycle: 'error', recovery_lifecycle: 'interrupted' };
  }
  return { lifecycle };
}

export { GraphUpdateCallback };

// Approval-mode strictness order — operator-policy rules may only escalate `mode`
// to a stricter value (auto-approve < approve-critical < approve-all), never relax it.
const APPROVAL_STRICTNESS: Record<string, number> = { 'auto-approve': 0, 'approve-critical': 1, 'approve-all': 2 };
const MAX_TERMINAL_RUNTIME_RUNS = 1_000;

export class GraphEngine {
  private ctx: EngineContext;
  private persistence: StatePersistence;
  private configService: EngagementConfigService;
  private agentMgr: AgentManager;
  private inference: InferenceEngine;
  private paths: PathAnalyzer;
  private frontierComputer: FrontierComputer;
  private chainScorer: ChainScorer;
  private campaignPlanner: CampaignPlanner;
  private healthReportCache: HealthReport | null = null;
  private frontierCache: { passed: FrontierItem[]; all: FrontierItem[]; campaigns: import('../types.js').Campaign[]; hidden: import('../types.js').FrontierHiddenSummary } | null = null;
  private evidenceStore!: EvidenceStore;
  private actionOutputBuffer = new ActionOutputBuffer();
  /** Shared skill methodology index (attached at app construction); null in bare/test contexts. */
  private skillIndex: SkillIndex | null = null;
  private kb: KnowledgeBase | null = null;
  private startupReconciliationDeferred = false;
  private recoveryMaintenanceInProgress = false;
  private deferredStartupRecoveryError?: string;
  private runtimeOwnershipRecoveryHandler?: () => void;
  private coordinationStoreUnsubscribers: Array<() => void> = [];
  private rollbackCoordinator?: {
    beforeRollback(): void;
    afterRollback(): void;
  };

  constructor(config: EngagementConfig, stateFilePath?: string, configFilePath?: string) {
    config = engagementConfigSchema.parse(config);
    const graph = createGraph();
    const filePath = stateFilePath || `./state-${config.id}.json`;
    this.ctx = new EngineContext(
      graph,
      config,
      filePath,
      configFilePath !== undefined,
      configFilePath,
    );
    this.ctx.inferenceRules = [...BUILTIN_RULES];
    this.persistence = new StatePersistence(
      this.ctx, BUILTIN_RULES,
      createGraph,
    );
    this.configService = new EngagementConfigService({
      getRuntimeConfig: () => this.ctx.config,
      nowIso: () => this.ctx.nowIso(),
      assertWriteAllowed: () => this.persistence.assertMigrationWriteAllowed(),
      withWriteGuard: operation => this.persistence.withMigrationWriteGuard(operation),
      applyRuntimeConfig: (next, context) => this.applyRuntimeConfig(next, context),
      commitRuntimeConfig: (next, context, event, applicationCommand) =>
        this.commitRuntimeConfigTransaction(
          next,
          context,
          event,
          applicationCommand,
        ),
      recordApplicationCommand: command => {
        this.recordApplicationCommand(command);
      },
      hasApplicationCommand: idempotencyKey =>
        this.ctx.applicationCommands.has(idempotencyKey),
      persistRuntimeState: () => this.persistence.persistImmediate(),
      recordConfigEvent: ({ description, result, details }) => {
        this.ctx.logEvent({
          description,
          event_type: result === 'success' ? 'config_updated' : 'instrumentation_warning',
          category: 'system',
          result_classification: result,
          details,
        });
      },
    }, configFilePath);
    this.agentMgr = new AgentManager(this.ctx);
    this.inference = new InferenceEngine(
      this.ctx,
      this.addEdge.bind(this),
      this.getNode.bind(this),
      this.getNodesByType.bind(this),
      this.addNode.bind(this),
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
    // One recovery state machine owns both primary and snapshot fallback.  A
    // nonempty WAL without a complete replay never falls through to config
    // seeding: the engine stays available for inspection in read-only mode.
    const hadPersistedBase = existsSync(this.ctx.stateFilePath) || this.persistence.listSnapshots().length > 0;
    const restore = this.persistence.restoreBaseAndReplay(this);
    let persistenceDegraded = restore.status === 'degraded';
    let seededFromConfig = false;
    if (restore.status === 'seed_required') {
      try {
        this.publishConfigSeedBase(hadPersistedBase);
      } catch (seedErr) {
        this.persistence.dispose();
        throw new Error(
          `State recovery failed for engagement ${this.ctx.config.id} ` +
          `(state: ${this.ctx.stateFilePath}): ${seedErr instanceof Error ? seedErr.message : String(seedErr)}`
        );
      }
      seededFromConfig = true;
    }

    this.applyRestoredRuntimeProjections();

    if (restore.rollback_pending && !persistenceDegraded) {
      try {
        this.configService.adoptRestoredRuntimeConfig('snapshot.rollback.recovery');
      } catch (error) {
        // A retained config intent or the rollback authority remains the known
        // restart path. initialize() below may finish an intent that already
        // became durable; otherwise it keeps the service read-only.
        console.error(
          `[recovery] rollback config synchronization remains pending: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    const configRecovery = this.configService.initialize({
      restored: restore.status === 'restored',
      persistence_writable: !persistenceDegraded && this.persistence.isWritable(),
      durable_config: this.persistence.getDurableConfig(),
    });
    persistenceDegraded ||= !this.persistence.isWritable();
    if (restore.rollback_pending && !configRecovery.resolution_required && !persistenceDegraded) {
      try {
        this.persistence.completePendingRollbackAuthority();
      } catch (error) {
        persistenceDegraded = true;
        console.error(
          `[recovery] rollback authority could not be released after config synchronization: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    this.evidenceStore = new EvidenceStore(filePath, {
      readOnly: persistenceDegraded
        || configRecovery.resolution_required
        || !this.persistence.isWritable(),
    });
    this.startupReconciliationDeferred = !persistenceDegraded && configRecovery.resolution_required;
    // Every guarded primitive now observes both WAL/state health and config
    // convergence. Reconciliation temporarily bypasses only the config half.
    this.ctx.persistenceWriteGuard = () => this.assertPersistenceWritable();
    this.installCoordinationStorePersistence();

    if (!persistenceDegraded && !configRecovery.resolution_required) {
      if (restore.status === 'restored') {
        this.log(
          restore.source === 'snapshot'
            ? 'Recovered engagement from persisted snapshot and WAL'
            : 'Resumed engagement from persisted state',
          undefined,
          { category: 'system', event_type: 'system' },
        );
      }
      // Catch up objective/config truth after WAL replay. A crash can occur
      // after a finding transaction commits but before its intentionally
      // separate revisioned objective/config write-through.
      this.evaluateObjectives();

      // Reconcile runtime-dependent state on startup only when the resulting
      // mutations can be durably checkpointed.
      this.reconcileSessionEdgesOnStartup();
      this.reconcileSessionDescriptorsOnStartup();
      this.reconcileAgentsOnStartup();
      this.reconcilePendingApprovalsOnStartup();
      try {
        // The checkpoint-zero bootstrap base was published earlier in this
        // constructor. Suppress rotation for this one follow-up checkpoint so
        // the just-created base is not immediately snapshotted. Do not advance
        // lastSnapshotTime: the next explicit/ordinary checkpoint retains the
        // established opportunity to rotate and compact the bootstrap WAL.
        this.persistence.persistImmediate(
          {},
          seededFromConfig ? { rotateExisting: false } : {},
        );
      } catch (error) {
        // StatePersistence retains the dirty state and owns the 250ms/1s/5s/
        // 30s retry schedule. The engine stays observable; its write gate
        // closes automatically after three consecutive failures.
        console.error(
          `[persistence] initial state write failed; retry scheduled: ${error instanceof Error ? error.message : String(error)}`,
        );
      }

      // 7.7: Auto health check on startup
      this.runAutoHealthCheck('startup');

      // Phase B: surface "OPSEC inert" state at startup.
      this.warnIfOpsecInert();
    } else {
      const stateRecovery = this.getStatePersistenceRecoveryStatus();
      const configStatus = this.getConfigRecoveryStatus();
      if (!stateRecovery.complete || !stateRecovery.writable) {
        console.error(
          `[persistence] degraded read-only startup: ${stateRecovery.reason ?? 'recovery is incomplete'}`,
        );
      } else if (configStatus.resolution_required) {
        console.error(
          `[config] read-only startup: ${configStatus.reason ?? 'configuration reconciliation is required'}`,
        );
      } else {
        const status = this.getPersistenceRecoveryStatus();
        console.error(
          `[recovery] read-only startup: ${status.reason ?? 'startup reconciliation is incomplete'}`,
        );
      }
      // Populate the health cache without recording or persisting a new event.
      this.runHealthChecks();
    }
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

  /**
   * Publish the first valid recovery base before any WAL mutation is allowed.
   *
   * A fresh engine used to seed through ordinary guarded mutators. A crash
   * after the first append but before the constructor's later state write left
   * a nonempty WAL with no base, which recovery must (correctly) keep degraded
   * forever rather than guess at an empty engagement. Build the deterministic
   * seed in memory with journaling temporarily detached, restore the same
   * journal owner, and atomically publish checkpoint zero before startup can
   * perform any ordinary durable work.
   */
  private publishConfigSeedBase(hadPersistedBase: boolean): void {
    const journal = this.ctx.mutationJournal;
    if (!journal) {
      throw new Error('fresh engagement bootstrap requires an initialized mutation journal');
    }

    this.ctx.mutationJournal = null;
    try {
      this.seedFromConfig();
      this.persistence.markConfigInitialization(hadPersistedBase);

      // P2.2: pin the construction-time timestamp to `created_at` so the
      // initial log event is deterministic across replays. Without this,
      // wall-clock leaks into the activity-log digest and breaks the
      // golden-master determinism guarantee.
      const seedAt = this.ctx.config.created_at;
      const logInitialization = () => {
        this.log(
          hadPersistedBase
            ? 'Engagement re-initialized from config after invalid persisted state'
            : 'Engagement initialized from config',
          undefined,
          { category: 'system', event_type: 'system' },
        );
      };
      if (seedAt) this.ctx.withClock(seedAt, logInitialization);
      else logInitialization();
    } finally {
      this.ctx.mutationJournal = journal;
    }

    // Keep the journal attached for this write so the shared state-writer
    // mutex and caught-up check reject any concurrent WAL head that appeared
    // after recovery. A failed bootstrap publication is fatal; it must never
    // expose seeded memory as a writable engagement.
    this.persistence.persistBootstrapBase();
  }

  private installCoordinationStorePersistence(): void {
    const guard = () => this.assertPersistenceWritable();
    this.ctx.activityTransactionRunner = event =>
      this.appendStandaloneActivityEvent(event);
    this.ctx.proposedPlanStore.setMutationGuard(guard);
    this.ctx.agentQueryStore.setMutationGuard(guard);
    this.ctx.proposedPlanStore.setMutationRunner(
      (reason, mutation) => this.transactAttachedCoordinationStore(reason, mutation),
    );
    this.ctx.agentQueryStore.setMutationRunner(
      (reason, mutation) => this.transactAttachedCoordinationStore(reason, mutation),
    );
    this.coordinationStoreUnsubscribers.push(
      this.ctx.proposedPlanStore.onChange(() => this.persist()),
      this.ctx.agentQueryStore.onChange(() => this.persist()),
      () => this.ctx.proposedPlanStore.setMutationRunner(undefined),
      () => this.ctx.agentQueryStore.setMutationRunner(undefined),
      () => { this.ctx.activityTransactionRunner = undefined; },
    );
  }

  private appendStandaloneActivityEvent(event: ActivityLogInput): ActivityLogEntry {
    const prepared = this.ctx.prepareActivityAppend(event);
    this.ctx.applyEngineTransaction(
      {
        operations: [{
          type: 'activity_append',
          payload: prepared.payload as unknown as Record<string, unknown>,
        }],
      },
      () => this.ctx.applyActivityAppend(prepared.payload),
      'activity append',
    );
    this.persist();
    return prepared.result;
  }

  private transactAttachedCoordinationStore<T>(
    reason: string,
    mutation: () => T,
  ): T {
    if (this.ctx.isDraftingTransaction()) return mutation();
    const baseline = this.ctx.captureDurableStateSlices(['plans_questions']);
    let result!: T;
    let after!: ReturnType<EngineContext['captureDurableStateSlices']>;
    try {
      this.ctx.withTransactionDraft(() => {
        result = mutation();
        after = this.ctx.captureDurableStateSlices(['plans_questions']);
      });
    } catch (error) {
      this.ctx.applyDurableStatePatch(baseline);
      throw error;
    }
    const detachedResult = structuredClone(result);
    this.ctx.applyDurableStatePatch(baseline);
    if (JSON.stringify(after) === JSON.stringify(baseline)) return detachedResult;
    const payload: DurableStatePatchV1 = {
      payload_version: 1,
      operation_id: uuidv4(),
      occurred_at: this.ctx.nowIso(),
      reason,
      slices: after,
    };
    try {
      this.ctx.applyEngineTransaction(
        {
          operations: [{
            type: 'state_patch',
            payload: payload as unknown as Record<string, unknown>,
          }],
        },
        () => this.applyStatePatchMutation(payload, false),
        'coordination state patch',
      );
    } catch (error) {
      this.ctx.applyDurableStatePatch(baseline);
      this.applyRestoredRuntimeProjections();
      this.invalidateAllCaches();
      throw error;
    }
    this.persist();
    return detachedResult;
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
        if (!this.ctx.suppressMutationEvents) {
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
      }
      // Journal the GUARDED result (post type-strip), so WAL replay records what
      // was actually applied — not the raw incoming props whose conflicting type
      // the live path refused. (updateNode already journals post-guard.)
      this.ctx.applyJournaledMutation('merge_node_attrs', { props: merged }, () => {
        // A property change on an existing node can add or resolve frontier work — e.g.
        // filling `services` clears an incomplete_node item, setting `cve_checked_at`
        // retires a cve_research item, a new `version` creates one. Previously the merge
        // branch cleared only the health report, so the frontier cache went stale:
        // resolved work stayed visible and newly-relevant work stayed hidden. Invalidate
        // the frontier too, but only when the merge actually changes an attribute (a no-op
        // re-observation shouldn't churn the cache). Shallow compare — arrays/objects
        // compare by ref, conservatively counting as changed (safe over-invalidation).
        const attrsChanged = Object.keys(merged).some(
          k => (existing as Record<string, unknown>)[k] !== (merged as Record<string, unknown>)[k],
        );
        this.ctx.graph.mergeNodeAttributes(props.id, merged);
        this.invalidateHealthReport();
        if (attrsChanged) this.invalidateFrontierCache();
      });
    } else {
      this.ctx.applyJournaledMutation('add_node', { props }, () => {
        this.ctx.graph.addNode(props.id, props);
        this.invalidatePathGraph();
        this.invalidateAllCaches();
      });
    }
    return props.id;
  }

  addEdge(
    source: string,
    target: string,
    props: EdgeProperties,
    replayEdgeId?: string,
  ): { id: string; isNew: boolean } {
    // Validate the only condition Graphology can reject before the WAL append.
    // A durable record for an impossible edge would otherwise poison every
    // subsequent restart even though no live mutation ever succeeded.
    if (!this.ctx.graph.hasNode(source) || !this.ctx.graph.hasNode(target)) {
      throw new Error(`Cannot add edge with missing endpoint(s): ${source} -> ${target}`);
    }
    // Resolve merge-vs-add and the exact graph-wide edge key before appending.
    // Persisting that identity makes later drop/merge records replay-stable.
    for (const edgeId of this.ctx.graph.edges(source, target)) {
      const attrs = this.ctx.graph.getEdgeAttributes(edgeId);
      if (!edgeIdentityMatches(attrs, props)) continue;
      let effectiveProps = props;
      const confirmedRule = attrs.inferred_by_rule && !attrs.confirmed_at && props.confidence >= 1.0
        ? attrs.inferred_by_rule
        : undefined;
      if (confirmedRule) {
        effectiveProps = {
          ...props,
          confirmed_at: props.confirmed_at ?? this.ctx.nowIso(),
        };
      }
      return this.ctx.applyJournaledMutation(
        'add_edge',
        { source, target, props: effectiveProps, edge_id: edgeId },
        () => {
          if (confirmedRule) {
            // This event is a deterministic derived effect of the journaled
            // confirmation. Replay normally suppresses incidental mutator
            // events, but suppressing this one would recover the graph while
            // silently losing its audit/hash-chain/frontier state.
            this.ctx.withClock(effectiveProps.confirmed_at!, () => {
              this.log(`Confirmed inferred edge [${confirmedRule}]: ${source} --[${attrs.type}]--> ${target}`, undefined, { category: 'inference', outcome: 'success', event_type: 'inference_generated' });
            });
          }
          this.ctx.graph.mergeEdgeAttributes(edgeId, effectiveProps as Partial<EdgeProperties>);
          this.invalidateHealthReport();
          return { id: edgeId, isNew: false };
        },
      );
    }

    const preferredId = preferredEdgeKey(source, target, props);
    const edgeId = replayEdgeId
      ?? (this.ctx.graph.hasEdge(preferredId)
        ? deterministicCollisionEdgeKey(source, target, props)
        : preferredId);
    // Fail before the WAL append if even the deterministic identity is owned by
    // another tuple. Continuing with another random suffix would be unreplayable.
    if (this.ctx.graph.hasEdge(edgeId)) {
      throw new Error(`Deterministic edge key collision for ${source} --[${props.type}]--> ${target}: ${edgeId}`);
    }
    return this.ctx.applyJournaledMutation(
      'add_edge',
      { source, target, props, edge_id: edgeId },
      () => {
        this.invalidatePathGraph();
        this.invalidateAllCaches();
        return { id: this.ctx.graph.addEdgeWithKey(edgeId, source, target, props), isNew: true };
      },
    );
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
    this.ctx.applyJournaledMutation('drop_edge', { source, target, edge_type: type, edge_id: edgeId }, () => {
      this.ctx.graph.dropEdge(edgeId);
      this.invalidatePathGraph();
      this.invalidateAllCaches();
    });
    return edgeId;
  }

  mergeEdgeAttributesDurable(
    edgeId: string,
    props: Record<string, unknown>,
  ): void {
    if (!this.ctx.graph.hasEdge(edgeId)) {
      throw new Error(`Cannot merge attributes into missing edge: ${edgeId}`);
    }
    this.ctx.applyJournaledMutation(
      'merge_edge_attrs',
      { edge_id: edgeId, props },
      () => {
        this.ctx.graph.mergeEdgeAttributes(edgeId, props);
        this.invalidateAllCaches();
      },
    );
  }

  dropNodeDurable(
    nodeId: string,
    audit: { reason: string; action_id?: string },
  ): { dropped: boolean; node_id: string; removed_edge_ids: string[] } {
    this.assertPersistenceWritable();
    if (!this.ctx.graph.hasNode(nodeId)) {
      return { dropped: false, node_id: nodeId, removed_edge_ids: [] };
    }
    const node = this.ctx.graph.getNodeAttributes(nodeId) as NodeProperties;
    const incidentEdges = this.ctx.graph.edges(nodeId)
      .map(edgeId => ({
        edge_id: edgeId,
        source: this.ctx.graph.source(edgeId),
        target: this.ctx.graph.target(edgeId),
        edge_type: String(this.ctx.graph.getEdgeAttributes(edgeId).type),
        props: detached(this.ctx.graph.getEdgeAttributes(edgeId) as EdgeProperties),
      }))
      .sort((left, right) => left.edge_id.localeCompare(right.edge_id));
    const payload: DropNodeMutationPayloadV1 = {
      payload_version: 1,
      operation_id: uuidv4(),
      occurred_at: this.ctx.nowIso(),
      reason: audit.reason,
      ...(audit.action_id ? { action_id: audit.action_id } : {}),
      node_id: nodeId,
      expected_type: node.type,
      expected_node: { node_id: nodeId, props: detached(node) },
      incident_edges: incidentEdges,
    };
    this.ensureCompositeJournal();
    const applied = this.ctx.applyJournaledMutation(
      'drop_node',
      payload as unknown as Record<string, unknown>,
      () => this.applyDropNodeMutation(payload, false),
      audit.action_id,
    );
    if (applied.status !== 'applied') throw new Error(applied.reason);
    this.persist({ removed_nodes: [nodeId], removed_edges: incidentEdges.map(edge => edge.edge_id) });
    return { dropped: true, node_id: nodeId, removed_edge_ids: incidentEdges.map(edge => edge.edge_id) };
  }

  applyDropNodeMutation(
    payload: DropNodeMutationPayloadV1,
    _recovery = true,
  ): MutationApplyResult {
    if (payload.payload_version !== 1) {
      return { status: 'skipped', reason: `unsupported drop_node payload version: ${String(payload.payload_version)}` };
    }
    const nodePresent = this.ctx.graph.hasNode(payload.node_id);
    if (nodePresent) {
      const node = this.ctx.graph.getNodeAttributes(payload.node_id) as NodeProperties;
      if (
        canonicalJson(this.identityNodeComparable(node))
        !== canonicalJson(this.identityNodeComparable(payload.expected_node.props))
      ) {
        return { status: 'skipped', reason: `drop_node node state changed for ${payload.node_id}` };
      }
      const actual = this.ctx.graph.edges(payload.node_id)
        .map(edgeId => ({
          edge_id: edgeId,
          source: this.ctx.graph.source(edgeId),
          target: this.ctx.graph.target(edgeId),
          edge_type: String(this.ctx.graph.getEdgeAttributes(edgeId).type),
          props: detached(this.ctx.graph.getEdgeAttributes(edgeId) as EdgeProperties),
        }))
        .sort((left, right) => left.edge_id.localeCompare(right.edge_id));
      const expected = [...payload.incident_edges].sort((left, right) => left.edge_id.localeCompare(right.edge_id));
      if (canonicalJson(actual) !== canonicalJson(expected)) {
        return { status: 'skipped', reason: `drop_node incident edges changed for ${payload.node_id}` };
      }
    } else {
      const reusedEdge = payload.incident_edges.find(edge => this.ctx.graph.hasEdge(edge.edge_id));
      if (reusedEdge) {
        return { status: 'skipped', reason: `drop_node edge identity ${reusedEdge.edge_id} was reused after ${payload.node_id} disappeared` };
      }
    }

    const graphSnapshot = this.ctx.graph.export();
    const activitySnapshot = detached(this.ctx.activityLog);
    const chainHashSnapshot = this.ctx.lastChainHash;
    const chainCheckpointsSnapshot = detached(this.ctx.chainCheckpoints);
    const chainEventsSnapshot = this.ctx.chainEventsSinceCheckpoint;
    const deterministicSeqSnapshot = this.ctx.deterministicSeq;
    const actionFrontierSnapshot = new Map(
      [...this.ctx.actionFrontierMap].map(([key, value]) => [key, detached(value)]),
    );
    const frontierLinkageSnapshot = detached(this.ctx.frontierLinkage.serialize());
    try {
      this.ctx.withClock(payload.occurred_at, () => {
        if (nodePresent) this.ctx.graph.dropNode(payload.node_id);
        if (
          this.ctx.graph.hasNode(payload.node_id)
          || payload.incident_edges.some(edge => this.ctx.graph.hasEdge(edge.edge_id))
        ) {
          throw new Error(`drop_node did not reach its frozen post-state for ${payload.node_id}`);
        }
        const alreadyAudited = this.ctx.activityLog.some(entry =>
          entry.event_type === 'graph_corrected'
          && entry.details?.operation_id === payload.operation_id,
        );
        if (!alreadyAudited) {
          this.ctx.logEvent({
            description: 'Graph corrected: durable node drop applied',
            action_id: payload.action_id,
            event_type: 'graph_corrected',
            category: 'system',
            result_classification: 'success',
            details: {
              operation_id: payload.operation_id,
              reason: payload.reason,
              operations: [{ kind: 'drop_node', node_id: payload.node_id }],
              dropped_nodes: [payload.node_id],
              dropped_edges: payload.incident_edges.map(edge => edge.edge_id),
            },
          });
        }
      });
      this.invalidateAllCaches();
      this.invalidatePathGraph();
      return { status: 'applied' };
    } catch (error) {
      this.ctx.graph.clear();
      this.ctx.graph.import(graphSnapshot);
      this.ctx.activityLog = activitySnapshot;
      this.ctx.lastChainHash = chainHashSnapshot;
      this.ctx.chainCheckpoints = chainCheckpointsSnapshot;
      this.ctx.chainEventsSinceCheckpoint = chainEventsSnapshot;
      this.ctx.deterministicSeq = deterministicSeqSnapshot;
      this.ctx.actionFrontierMap = actionFrontierSnapshot;
      this.ctx.frontierLinkage = FrontierLinkageTracker.deserialize(frontierLinkageSnapshot);
      this.invalidateAllCaches();
      this.invalidatePathGraph();
      if (!_recovery) throw error;
      return { status: 'skipped', reason: error instanceof Error ? error.message : String(error) };
    }
  }

  private reconcileCanonicalNodeDurable(
    canonicalNodeId: string,
    agentId?: string,
    actionId?: string,
  ): ReconciliationResult {
    const plan = planIdentityRewrite(this.ctx.graph, canonicalNodeId, {
      operation_id: uuidv4(),
      occurred_at: this.ctx.nowIso(),
      ...(agentId ? { agent_id: agentId } : {}),
      ...(actionId ? { action_id: actionId } : {}),
    });
    if (!plan.payload) return plan.result;
    this.ensureCompositeJournal();
    const applied = this.ctx.applyCompositeJournaledMutation(
      'identity_rewrite',
      plan.payload as unknown as Record<string, unknown>,
      () => this.applyIdentityRewriteMutation(plan.payload!, false),
      actionId,
    );
    if (applied.status !== 'applied') throw new Error(applied.reason);
    return detached(plan.payload.result);
  }

  applyIdentityRewriteMutation(
    payload: IdentityRewriteMutationPayloadV1,
    recovery = true,
  ): MutationApplyResult {
    if (payload.payload_version !== 1) {
      return { status: 'skipped', reason: `unsupported identity_rewrite payload version: ${String(payload.payload_version)}` };
    }
    const alreadyApplied = this.exactGraphDeltaMatches(payload, 'after');
    const readyToApply = !alreadyApplied && this.exactGraphDeltaMatches(payload, 'before');
    if (!alreadyApplied && !readyToApply) {
      return {
        status: 'skipped',
        reason: `identity_rewrite preconditions changed for operation ${payload.operation_id}`,
      };
    }

    const graphSnapshot = this.ctx.graph.export();
    const activitySnapshot = detached(this.ctx.activityLog);
    const chainHashSnapshot = this.ctx.lastChainHash;
    const chainCheckpointsSnapshot = detached(this.ctx.chainCheckpoints);
    const chainEventsSnapshot = this.ctx.chainEventsSinceCheckpoint;
    const deterministicSeqSnapshot = this.ctx.deterministicSeq;
    const actionFrontierSnapshot = new Map(
      [...this.ctx.actionFrontierMap].map(([key, value]) => [key, detached(value)]),
    );
    const frontierLinkageSnapshot = detached(this.ctx.frontierLinkage.serialize());
    try {
      this.ctx.withClock(payload.occurred_at, () => {
        if (readyToApply) {
          for (const change of payload.edge_changes) {
            if (change.before && this.ctx.graph.hasEdge(change.edge_id)) {
              this.ctx.graph.dropEdge(change.edge_id);
            }
          }
          for (const change of payload.node_changes) {
            if (!change.after && this.ctx.graph.hasNode(change.node_id)) {
              this.ctx.graph.dropNode(change.node_id);
            }
          }
          for (const change of payload.node_changes) {
            if (!change.after) continue;
            const props = detached(change.after.props);
            if (this.ctx.graph.hasNode(change.node_id)) {
              this.ctx.graph.replaceNodeAttributes(change.node_id, props);
            } else {
              this.ctx.graph.addNode(change.node_id, props);
            }
          }
          for (const change of payload.edge_changes) {
            if (!change.after) continue;
            const edge = change.after;
            if (!this.ctx.graph.hasNode(edge.source) || !this.ctx.graph.hasNode(edge.target)) {
              throw new Error(`identity_rewrite edge ${edge.edge_id} has a missing endpoint`);
            }
            this.ctx.graph.addEdgeWithKey(
              edge.edge_id,
              edge.source,
              edge.target,
              detached(edge.props),
            );
          }
          if (!this.exactGraphDeltaMatches(payload, 'after')) {
            throw new Error(`identity_rewrite did not reach its frozen post-state for operation ${payload.operation_id}`);
          }
        }

        for (const [index, event] of payload.audit_events.entries()) {
          const alreadyAudited = this.ctx.activityLog.some(entry =>
            entry.details?.identity_operation_id === payload.operation_id
            && entry.details?.identity_event_index === index,
          );
          if (alreadyAudited) continue;
          this.ctx.logEvent({
            description: event.description,
            agent_id: payload.agent_id,
            action_id: payload.action_id,
            category: event.category ?? 'system',
            event_type: event.event_type ?? 'system',
            result_classification: event.result_classification ?? 'success',
            target_node_ids: event.target_node_ids,
            details: {
              ...detached(event.details),
              identity_operation_id: payload.operation_id,
              identity_event_index: index,
            },
          });
        }
      });
      this.invalidateAllCaches();
      this.invalidatePathGraph();
      return { status: 'applied' };
    } catch (error) {
      this.ctx.graph.clear();
      this.ctx.graph.import(graphSnapshot);
      this.ctx.activityLog = activitySnapshot;
      this.ctx.lastChainHash = chainHashSnapshot;
      this.ctx.chainCheckpoints = chainCheckpointsSnapshot;
      this.ctx.chainEventsSinceCheckpoint = chainEventsSnapshot;
      this.ctx.deterministicSeq = deterministicSeqSnapshot;
      this.ctx.actionFrontierMap = actionFrontierSnapshot;
      this.ctx.frontierLinkage = FrontierLinkageTracker.deserialize(frontierLinkageSnapshot);
      this.invalidateAllCaches();
      this.invalidatePathGraph();
      if (!recovery) throw error;
      return { status: 'skipped', reason: error instanceof Error ? error.message : String(error) };
    }
  }

  private exactGraphDeltaMatches(
    payload: ExactGraphDelta,
    phase: 'before' | 'after',
  ): boolean {
    for (const change of payload.node_changes) {
      const expected = change[phase];
      if (!expected) {
        if (this.ctx.graph.hasNode(change.node_id)) return false;
      } else {
        if (!this.ctx.graph.hasNode(change.node_id)) return false;
        const actualProps = this.identityNodeComparable(
          this.ctx.graph.getNodeAttributes(change.node_id) as NodeProperties,
        );
        const expectedProps = this.identityNodeComparable(expected.props);
        if (canonicalJson(actualProps) !== canonicalJson(expectedProps)) return false;
      }
    }
    for (const change of payload.edge_changes) {
      const expected = change[phase];
      if (!expected) {
        if (this.ctx.graph.hasEdge(change.edge_id)) return false;
      } else {
        if (!this.ctx.graph.hasEdge(change.edge_id)) return false;
        if (
          this.ctx.graph.source(change.edge_id) !== expected.source
          || this.ctx.graph.target(change.edge_id) !== expected.target
          || canonicalJson(this.ctx.graph.getEdgeAttributes(change.edge_id)) !== canonicalJson(expected.props)
        ) return false;
      }
    }
    if (phase === 'before') {
      for (const change of payload.node_changes) {
        if (!change.before || change.after || !this.ctx.graph.hasNode(change.node_id)) continue;
        const expectedIncident = payload.edge_changes
          .filter(edge => edge.before?.source === change.node_id || edge.before?.target === change.node_id)
          .map(edge => edge.edge_id)
          .sort();
        const actualIncident = this.ctx.graph.edges(change.node_id).sort();
        if (canonicalJson(actualIncident) !== canonicalJson(expectedIncident)) return false;
      }
    }
    return true;
  }

  private identityNodeComparable(props: NodeProperties): NodeProperties {
    const normalized = {
      ...props,
      ...normalizeNodeProvenance(props),
    } as NodeProperties;
    if (
      normalized.id.startsWith('cred-default-')
      && normalized.type === 'credential'
      && !normalized.cred_is_default_guess
    ) {
      normalized.cred_is_default_guess = true;
    }
    return normalized;
  }

  patchNodeProperties(nodeId: string, setProperties: Record<string, unknown> = {}, unsetProperties: string[] = []): NodeProperties {
    const existing = this.getNode(nodeId);
    if (!existing) {
      throw new Error(`Node does not exist in graph: ${nodeId}`);
    }
    const nextAttrs = this.buildPatchedNode(existing, setProperties, unsetProperties);
    // Journal as a REPLACE (not merge) so replay reproduces the full-node
    // semantics of patch — including REMOVING keys cleared via unsetProperties.
    // A merge_node_attrs replay could only add/overwrite keys, leaving a cleared
    // key stale after crash recovery.
    this.ctx.applyJournaledMutation('replace_node_attrs', { props: nextAttrs }, () => {
      this.ctx.graph.replaceNodeAttributes(nodeId, nextAttrs as NodeProperties);
      this.invalidateAllCaches();
    });
    return this.ctx.graph.getNodeAttributes(nodeId);
  }

  getNode(id: string): NodeProperties | null {
    if (!this.ctx.graph.hasNode(id)) return null;
    return this.projectNodeProperties(id, this.ctx.graph.getNodeAttributes(id));
  }

  getNodesByType(type: NodeType): NodeProperties[] {
    const results: NodeProperties[] = [];
    this.ctx.graph.forEachNode((id, attrs) => {
      if (attrs.type === type && attrs.identity_status !== 'superseded') {
        results.push(this.projectNodeProperties(id, attrs));
      }
    });
    return results;
  }

  // =============================================
  // Finding Ingestion
  // =============================================

  private static readonly DEDUP_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

  ingestFinding(
    finding: Finding,
    completion?: FindingIngestCompletion,
  ): FindingIngestResult {
    this.assertPersistenceWritable();
    // --- Finding Deduplication (7.8) ---
    const now = Date.now(); // clock-ok: dedup-window elapsed-time check (transient cache; not a stored timestamp)

    // Plan stale-entry pruning without mutating the live durable map. The
    // pruned map is installed inside the same transaction as the duplicate or
    // first-ingest outcome, so an append refusal cannot leak cleanup state.
    const activeFindingHashes = new Map(
      [...this.ctx.recentFindingHashes.entries()].filter(
        ([, ts]) => now - ts <= GraphEngine.DEDUP_WINDOW_MS,
      ),
    );

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

    if (activeFindingHashes.has(contentHash)) {
      // P3.4: when dedup hits, the graph topology stays unchanged (same
      // evidence) but we still merge new attribution onto affected nodes
      // so we don't lose the fact that a second agent / action observed
      // the same thing. Without this, re-runs of the same tool by
      // different agents within the 5-minute window vanished from the
      // cross-attribution audit trail. Resolve each finding node through
      // identity-resolution first so we land on the canonical graph node
      // ID (e.g. an IP-keyed host, not the raw label the finding used).
      const updatedNodes: string[] = [];
      const attributionUpdates: NodeProperties[] = [];
      const ingestedNodeIds = new Set(
        (finding.target_node_ids ?? []).filter(nodeId => this.ctx.graph.hasNode(nodeId)),
      );
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
        ingestedNodeIds.add(canonicalId);
        if (finding.agent_id) {
          const existing = this.ctx.graph.getNodeAttributes(canonicalId) as NodeProperties;
          const existingSources = Array.isArray(existing.sources) ? existing.sources : [];
          if (!existingSources.includes(finding.agent_id)) {
            attributionUpdates.push({
              ...existing,
              sources: [...existingSources, finding.agent_id],
              last_seen_at: finding.timestamp,
            });
            updatedNodes.push(canonicalId);
          }
        }
      }

      const stateKeys = [
        ...new Set<DurableStateSliceKey>([
          'finding_counters',
          'activity',
          'frontier',
          'campaigns',
          ...(completion?.additional_state_keys ?? []),
        ]),
      ];
      const baselineSlices = this.ctx.captureDurableStateSlices(stateKeys);
      let duplicateResult!: FindingIngestResult;
      const draft = this.ctx.draftDurableStateSlices(stateKeys, () => {
        this.ctx.recentFindingHashes = new Map(activeFindingHashes);
        this.ctx.dedupCount++;
        // A duplicate-content parse still has its own finding ID and evidence
        // lineage. Emit the same canonical reference event as a normal ingest so
        // campaign detail and audit views do not degrade to a generic parse row.
        this.logActionEvent({
          description: 'Finding ingested: duplicate content matched existing graph data',
          agent_id: finding.agent_id,
          action_id: finding.action_id,
          event_type: 'finding_ingested',
          category: 'finding',
          tool_name: finding.tool_name,
          target_node_ids: [...ingestedNodeIds],
          frontier_item_id: finding.frontier_item_id,
          linked_finding_ids: [finding.id],
          result_classification: 'neutral',
          details: {
            finding_id: finding.id,
            deduplicated: true,
            new_nodes: 0,
            new_edges: 0,
            updated_nodes: updatedNodes.length,
            updated_edges: 0,
            inferred_edges: 0,
            ingested_node_ids: [...ingestedNodeIds],
          },
        });
        const campaignId = this.linkFindingToCampaign({
          finding_id: finding.id,
          frontier_item_id: finding.frontier_item_id,
          agent_id: finding.agent_id,
          action_id: finding.action_id,
        });
        duplicateResult = {
          new_nodes: [],
          new_edges: [],
          updated_nodes: updatedNodes,
          updated_edges: [],
          inferred_edges: [],
          deduplicated: true,
          ...(campaignId ? { campaign_id: campaignId } : {}),
        };
        completion?.complete(detached(duplicateResult));
        return campaignId;
      });
      const statePatch: DurableStatePatchV1 = {
        payload_version: 1,
        operation_id: uuidv4(),
        occurred_at: this.ctx.nowIso(),
        reason: 'record duplicate finding',
        slices: draft.slices,
      };
      const operations: EngineOperation[] = [
        ...attributionUpdates.map(props => ({
          type: 'merge_node_attrs' as const,
          payload: { props },
        })),
        {
          type: 'state_patch',
          payload: statePatch as unknown as Record<string, unknown>,
        },
      ];
      const nodeBaseline = attributionUpdates.map(props =>
        detached(this.ctx.graph.getNodeAttributes(props.id) as NodeProperties),
      );
      try {
        this.ctx.applyEngineTransaction(
          {
            operations,
            source_action_id: finding.action_id,
            update_detail: { updated_nodes: updatedNodes },
          },
          () => {
            for (const props of attributionUpdates) this.addNode(props);
            return this.applyStatePatchMutation(statePatch, false);
          },
          'duplicate finding ingest',
        );
      } catch (error) {
        this.restoreWebChainAnnotationBaseline(nodeBaseline);
        this.ctx.applyDurableStatePatch(baselineSlices);
        this.applyRestoredRuntimeProjections();
        throw error;
      }
      this.persist({ updated_nodes: updatedNodes });
      // A prior first-ingest may have committed immediately before its
      // objective/config follow-up. A truthful retry is deduplicated, but still
      // completes that deferred evaluation boundary.
      this.evaluateObjectives();
      return detached(duplicateResult);
    }

    const stateKeys = [
      ...new Set<DurableStateSliceKey>([
        'activity',
        'frontier',
        'finding_counters',
        'campaigns',
        'phase',
        ...(completion?.additional_state_keys ?? []),
      ]),
    ];
    const graphBaseline = detached(this.ctx.graph.export());
    const coldBaseline = detached(this.ctx.coldStore.export());
    const sliceBaseline = this.ctx.captureDurableStateSlices(stateKeys);
    const cacheBaseline = {
      pathGraphCache: new Map(this.ctx.pathGraphCache),
      communityCache: this.ctx.communityCache ? new Map(this.ctx.communityCache) : null,
      frontierCache: this.frontierCache ? detached(this.frontierCache) : null,
      healthReportCache: this.healthReportCache ? detached(this.healthReportCache) : null,
    };
    const restoreBaseline = () => {
      this.restoreFindingDraftBaseline(graphBaseline, coldBaseline, sliceBaseline);
      this.ctx.pathGraphCache = new Map(cacheBaseline.pathGraphCache);
      this.ctx.communityCache = cacheBaseline.communityCache
        ? new Map(cacheBaseline.communityCache)
        : null;
      this.frontierCache = cacheBaseline.frontierCache
        ? detached(cacheBaseline.frontierCache)
        : null;
      this.healthReportCache = cacheBaseline.healthReportCache
        ? detached(cacheBaseline.healthReportCache)
        : null;
    };

    let captured!: { result: FindingDraftResult; operations: EngineOperation[] };
    let graphAfter!: ReturnType<OverwatchGraph['export']>;
    let coldAfter!: ReturnType<EngineContext['coldStore']['export']>;
    let slicesAfter!: ReturnType<EngineContext['captureDurableStateSlices']>;
    try {
      captured = this.ctx.captureEngineOperations(() => {
        this.ctx.recentFindingHashes = new Map(activeFindingHashes);
        const result = ingestFindingImpl(
          this.findingIngestionHost,
          finding,
          { evaluateObjectives: false },
        );

        // Phase 3 (enterprise): cross-tier correlation + inference is part of
        // the same immutable finding draft as the parser-produced graph data.
        try {
          _runCrossTierCorrelator({
            ctx: this.ctx,
            addEdge: this.addEdge.bind(this),
            log: this.log.bind(this),
          });
          _runCrossTierInference({
            ctx: this.ctx,
            addNode: this.addNode.bind(this),
            addEdge: this.addEdge.bind(this),
            log: this.log.bind(this),
          });
        } catch (err) {
          // Cross-tier inference must never fail the ingest. Its failure event
          // is still captured in the finding's durable activity after-state.
          this.log(`Cross-tier inference error: ${err instanceof Error ? err.message : String(err)}`, undefined, { category: 'system', outcome: 'failure' });
        }

        if (result.new_nodes.length >= GraphEngine.HEALTH_AUTO_CHECK_THRESHOLD) {
          this.runAutoHealthCheck(`large ingest: ${result.new_nodes.length} new nodes`);
        }

        this.ctx.recentFindingHashes.set(contentHash, now);
        const campaignId = this.linkFindingToCampaign({
          finding_id: finding.id,
          frontier_item_id: finding.frontier_item_id,
          agent_id: finding.agent_id,
          action_id: finding.action_id,
        });
        const completedResult: FindingIngestResult = {
          ...result,
          ...(campaignId ? { campaign_id: campaignId } : {}),
        };
        completion?.complete(detached(completedResult));
        return { result, ...(campaignId ? { campaign_id: campaignId } : {}) };
      });
      captured = detached(captured);
      graphAfter = detached(this.ctx.graph.export());
      coldAfter = detached(this.ctx.coldStore.export());
      slicesAfter = this.ctx.captureDurableStateSlices(stateKeys);
    } finally {
      restoreBaseline();
    }

    const detail = this.deriveGraphUpdateDetail(
      graphBaseline,
      graphAfter,
      captured.result.result.inferred_edges,
    );
    const statePatch: DurableStatePatchV1 = {
      payload_version: 1,
      operation_id: uuidv4(),
      occurred_at: this.ctx.nowIso(),
      reason: 'ingest finding',
      slices: slicesAfter,
    };
    const operations: EngineOperation[] = [
      ...captured.operations,
      {
        type: 'state_patch',
        payload: statePatch as unknown as Record<string, unknown>,
      },
    ];
    const transactionDraft = {
      operations,
      source_action_id: finding.action_id,
      update_detail: detail,
    };

    // Prove the frozen operations reproduce the speculative after-state before
    // any WAL bytes are appended. This catches an uncaptured raw mutation or a
    // replay/live semantic drift without publishing a partial transaction.
    try {
      const replayed = this.persistence.applyTransactionDraft(transactionDraft, this);
      if (replayed.status === 'skipped') {
        throw new Error(`Finding operation draft could not replay: ${replayed.reason}`);
      }
      const replayGraph = detached(this.ctx.graph.export());
      const replayCold = detached(this.ctx.coldStore.export());
      const replaySlices = this.ctx.captureDurableStateSlices(stateKeys);
      if (
        canonicalJson({
          graph: replayGraph,
          cold_store: replayCold,
          slices: replaySlices,
        })
        !== canonicalJson({
          graph: graphAfter,
          cold_store: coldAfter,
          slices: slicesAfter,
        })
      ) {
        throw new Error('Finding operation draft replay did not reproduce its captured after-state.');
      }
    } finally {
      restoreBaseline();
    }

    try {
      this.ctx.applyEngineTransaction(
        transactionDraft,
        () => {
          const applied = this.persistence.applyTransactionDraft(transactionDraft, this);
          if (applied.status === 'applied') {
            this.invalidatePathGraph();
            this.invalidateAllCaches();
            this.inference.invalidateCaches();
          }
          return applied;
        },
        'finding ingest',
      );
    } catch (error) {
      restoreBaseline();
      throw error;
    }
    this.persist(detail);

    // Objective completion updates revisioned configuration and, for managed
    // engagements, engagement.json. It intentionally follows the committed
    // finding transaction as the remaining PR4-owned write-through boundary.
    // Startup and duplicate-ingest catch-up run the same evaluator if a crash
    // occurs in this narrow post-commit window.
    this.evaluateObjectives();

    return {
      ...captured.result.result,
      ...(captured.result.campaign_id ? { campaign_id: captured.result.campaign_id } : {}),
    };
  }

  // =============================================
  // Inference Engine (delegated to InferenceEngine)
  // =============================================

  addInferenceRule(rule: InferenceRule): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'add or update inference rule',
        ['inference_rules', 'activity', 'frontier'],
        () => this.addInferenceRule(rule),
      );
      return;
    }
    this.assertPersistenceWritable();
    this.inference.addRule(rule);
    this.persist();
  }

  backfillRule(rule: InferenceRule): string[] {
    this.assertPersistenceWritable();
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
      reconcileCanonicalNode: this.reconcileCanonicalNodeDurable.bind(this),
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
    this.assertPersistenceWritable();
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
      const campaigns = this.isPersistenceWritable()
        ? this.transactDurableSlices(
          'generate frontier campaigns',
          ['campaigns'],
          () => this.campaignPlanner.generateCampaigns(all, chainGroups, this.getCurrentPhaseId()),
        )
        : Array.from(this.ctx.campaigns.values());

      const { passed, filtered } = this.filterFrontier(all);
      this.frontierCache = { all, passed, campaigns, hidden: this.summarizeFilteredFrontier(filtered) };
    }
    return this.frontierCache.all;
  }

  /** Counts of frontier items intentionally hidden from the actionable frontier,
   *  grouped by reason (lease / OPSEC / dead host / scope). Computed from the SAME
   *  cached snapshot as `getCachedFilteredFrontier()` (the displayed frontier), so
   *  the "N hidden" count is always consistent with the frontier list shown next to
   *  it. The frontier cache is invalidated on ingestion / scope / session changes
   *  (not on lease acquire/release), so like the frontier list itself the count can
   *  briefly lag live lease state until the next recompute — but the two never
   *  disagree with each other. */
  getFrontierHiddenSummary(): import('../types.js').FrontierHiddenSummary {
    if (!this.frontierCache) {
      this.computeFrontier();
    }
    return detached(this.frontierCache!.hidden);
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
    return detached(this.frontierCache!.campaigns);
  }

  getCampaign(id: string): import('../types.js').Campaign | null {
    const campaign = this.campaignPlanner.getCampaign(id);
    return campaign ? detached(campaign) : null;
  }

  listCampaigns(filter?: { status?: string }): import('../types.js').Campaign[] {
    return detached(this.campaignPlanner.listCampaigns(filter));
  }

  pauseCampaign(id: string): import('../types.js').Campaign | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'pause campaign',
        ['campaigns'],
        () => this.pauseCampaign(id),
      );
    }
    this.assertPersistenceWritable();
    const c = this.campaignPlanner.pauseCampaign(id);
    if (c) this.persist();
    return c;
  }

  resumeCampaign(id: string): import('../types.js').Campaign | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'resume campaign',
        ['campaigns'],
        () => this.resumeCampaign(id),
      );
    }
    this.assertPersistenceWritable();
    const c = this.campaignPlanner.resumeCampaign(id);
    if (c) this.persist();
    return c;
  }

  /**
   * Enforce the invariant that an ABORTED campaign has no running agents: mark every
   * running agent whose campaign is aborted `no_retry` (a deliberate stop → the Phase
   * 3.1 re-offer sweep must not auto-re-dispatch their work) + `interrupted`. Keyed on
   * campaign STATUS (not a single id) so it naturally covers the whole subtree, since
   * `campaignPlanner.abortCampaign` cascades the abort to child campaigns. The OS
   * process is killed by TaskExecutionService.reconcileTerminatedTasks on the next
   * watchdog tick (it kills any tracked process whose task is no longer running).
   * Returns the count stopped.
   */
  private stopRunningAgentsOfAbortedCampaigns(reason: string): number {
    let stopped = 0;
    for (const agent of this.agentMgr.getAll()) {
      if (agent.status !== 'running' || !agent.campaign_id) continue;
      if (this.getCampaign(agent.campaign_id)?.status === 'aborted') {
        agent.no_retry = true;
        this.agentMgr.updateStatus(agent.id, 'interrupted', reason);
        stopped++;
      }
    }
    return stopped;
  }

  abortCampaign(id: string): import('../types.js').Campaign | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'abort campaign',
        ['campaigns', 'agents', 'plans_questions', 'activity', 'frontier'],
        () => this.abortCampaign(id),
      );
    }
    this.assertPersistenceWritable();
    const c = this.campaignPlanner.abortCampaign(id);
    if (c) {
      // A manual abort must actually STOP the campaign's in-flight work — otherwise
      // the campaign reads "aborted" while its agents keep executing target actions.
      // (The automatic abort-conditions path already does this; this closes the gap
      // for the operator-initiated /api/campaigns/:id/action { action: "abort" }, and
      // covers cascaded child campaigns too.)
      this.stopRunningAgentsOfAbortedCampaigns('Campaign aborted by operator');
      this.persist();
    }
    return c;
  }

  activateCampaign(id: string): import('../types.js').Campaign | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'activate campaign',
        ['campaigns'],
        () => this.activateCampaign(id),
      );
    }
    this.assertPersistenceWritable();
    const c = this.campaignPlanner.activateCampaign(id);
    if (c) this.persist();
    return c;
  }

  createCampaign(params: import('../services/campaign-planner.js').CreateCampaignParams): import('../types.js').Campaign {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'create campaign',
        ['campaigns'],
        () => this.createCampaign(params),
      );
    }
    this.assertPersistenceWritable();
    const c = this.campaignPlanner.createCampaign(params);
    this.persist();
    return c;
  }

  updateCampaign(id: string, patch: import('../services/campaign-planner.js').UpdateCampaignParams): import('../types.js').Campaign | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'update campaign',
        ['campaigns'],
        () => this.updateCampaign(id, patch),
      );
    }
    this.assertPersistenceWritable();
    const c = this.campaignPlanner.updateCampaign(id, patch);
    if (c) this.persist();
    return c;
  }

  deleteCampaign(id: string): boolean {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'delete campaign',
        ['campaigns'],
        () => this.deleteCampaign(id),
      );
    }
    this.assertPersistenceWritable();
    const ok = this.campaignPlanner.deleteCampaign(id);
    if (ok) this.persist();
    return ok;
  }

  cloneCampaign(id: string): import('../types.js').Campaign | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'clone campaign',
        ['campaigns'],
        () => this.cloneCampaign(id),
      );
    }
    this.assertPersistenceWritable();
    const c = this.campaignPlanner.cloneCampaign(id);
    if (c) this.persist();
    return c;
  }

  updateCampaignProgress(
    campaignId: string, frontierItemId: string, result: 'success' | 'failure', findingId?: string,
  ): import('../types.js').Campaign | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'update campaign progress',
        ['campaigns'],
        () => this.updateCampaignProgress(campaignId, frontierItemId, result, findingId),
      );
    }
    this.assertPersistenceWritable();
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

  /**
   * Attribute a finding to exactly one campaign. The executing task's campaign
   * is authoritative; frontier membership is used only when it is unique.
   * Ambiguous labels or cloned/split membership never cross-count findings.
   */
  linkFindingToCampaign(params: {
    finding_id: string;
    frontier_item_id?: string;
    task_id?: string;
    agent_id?: string;
    action_id?: string;
  }): string | undefined {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'link finding to campaign',
        ['campaigns'],
        () => this.linkFindingToCampaign(params),
      );
    }
    this.assertPersistenceWritable();

    let task = params.task_id ? this.agentMgr.getTask(params.task_id) : null;
    if (!task && params.action_id) {
      const linkedTaskId = [...this.ctx.activityLog].reverse().find(entry =>
        entry.action_id === params.action_id && typeof entry.linked_agent_task_id === 'string')?.linked_agent_task_id;
      if (linkedTaskId) task = this.agentMgr.getTask(linkedTaskId);
    }
    if (!task && params.agent_id) {
      const resolution = this.agentMgr.resolveTaskReference(params.agent_id);
      if (resolution.status === 'exact' || resolution.status === 'unique_legacy_label') {
        if (!params.frontier_item_id || resolution.task.frontier_item_id === params.frontier_item_id) {
          task = resolution.task;
        }
      }
    }

    let campaignId = task?.campaign_id;
    if (campaignId && !this.campaignPlanner.getCampaign(campaignId)) campaignId = undefined;
    if (!campaignId && params.frontier_item_id) {
      campaignId = this.campaignPlanner.findCampaignForItem(params.frontier_item_id)?.id;
    }
    if (!campaignId) return undefined;

    this.campaignPlanner.addFinding(campaignId, params.finding_id);
    this.persist();
    return campaignId;
  }

  splitCampaign(id: string, count?: number): import('../types.js').Campaign[] | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'split campaign',
        ['campaigns', 'agents'],
        () => this.splitCampaign(id, count),
      );
    }
    this.assertPersistenceWritable();
    const cs = this.campaignPlanner.splitCampaign(id, count);
    if (cs) {
      // Existing work follows its frontier item into the owning child. Without
      // this handoff, split progress is projected from children while in-flight
      // tasks continue updating the parent, hiding completion and findings.
      const childByItem = new Map(cs.flatMap(child => child.items.map(item => [item, child.id] as const)));
      for (const task of this.agentMgr.getAll()) {
        if (task.campaign_id !== id || !task.frontier_item_id) continue;
        const childId = childByItem.get(task.frontier_item_id);
        if (childId) task.campaign_id = childId;
      }
      const parent = this.campaignPlanner.getCampaign(id);
      for (const findingId of parent?.findings ?? []) {
        const linked = [...this.ctx.activityLog].reverse().find(event => event.linked_finding_ids?.includes(findingId));
        const childId = linked?.frontier_item_id ? childByItem.get(linked.frontier_item_id) : undefined;
        if (childId) this.campaignPlanner.addFinding(childId, findingId);
      }
      this.persist();
    }
    return cs;
  }

  // --- Agent directives (operator steering) -------------------------------
  // The engine only RECORDS directives. 'stop' is executed by
  // TaskExecutionService (process control); pause/resume/steering are observed
  // by the agent via agent_heartbeat. A new directive supersedes any still-
  // pending one for the task, so at most one is ever pending.

  issueAgentDirective(params: {
    task_id: string;
    kind: import('../types.js').AgentDirectiveKind;
    node_ids?: string[];
    frontier_types?: string[];
    note?: string;
    issued_by?: string;
  }): import('../types.js').AgentDirective {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'issue agent directive',
        ['directives', 'activity', 'frontier'],
        () => this.issueAgentDirective(params),
      );
    }
    this.assertPersistenceWritable();
    const list = this.ctx.agentDirectives.get(params.task_id) ?? [];
    for (const d of list) {
      if (d.status === 'pending') d.status = 'superseded';
    }
    const directive: import('../types.js').AgentDirective = {
      id: uuidv4(),
      task_id: params.task_id,
      kind: params.kind,
      node_ids: params.node_ids,
      frontier_types: params.frontier_types,
      note: params.note,
      issued_by: params.issued_by ?? 'primary',
      issued_at: this.ctx.nowIso(),
      status: 'pending',
    };
    list.push(directive);
    this.ctx.agentDirectives.set(params.task_id, list);
    // A directive is a queued instruction an agent picks up via
    // `acknowledge_agent_directive` — only a LIVE headless agent does that. For any
    // other backend (manual/scripted) or a missing task there's no process to
    // acknowledge it, so it is ADVISORY — recorded for the human operator, not
    // auto-applied. Say so, instead of implying enforcement.
    const targetTask = this.getTask(params.task_id);
    const advisory = !targetTask || targetTask.backend !== 'headless_mcp';
    this.logActionEvent({
      description: advisory
        ? `Directive '${directive.kind}' recorded for ${params.task_id} — advisory (no live agent to auto-apply it)`
        : `Directive '${directive.kind}' issued to agent task ${params.task_id}`,
      event_type: 'instrumentation_warning',
      category: 'system',
      result_classification: 'neutral',
      agent_id: targetTask?.agent_id,
      linked_agent_task_id: params.task_id,
      details: {
        reason: 'directive_issued',
        directive_id: directive.id,
        kind: directive.kind,
        node_ids: directive.node_ids,
        frontier_types: directive.frontier_types,
        advisory,
      },
    });
    this.persist();
    return directive;
  }

  getPendingAgentDirective(task_id: string): import('../types.js').AgentDirective | null {
    const list = this.ctx.agentDirectives.get(task_id);
    if (!list) return null;
    for (let i = list.length - 1; i >= 0; i--) {
      if (list[i].status === 'pending') return detached(list[i]);
    }
    return null;
  }

  getAgentDirectives(task_id: string): import('../types.js').AgentDirective[] {
    return detached(this.ctx.agentDirectives.get(task_id) ?? []);
  }

  acknowledgeAgentDirective(task_id: string, directive_id: string): import('../types.js').AgentDirective | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'acknowledge agent directive',
        ['directives', 'activity', 'frontier'],
        () => this.acknowledgeAgentDirective(task_id, directive_id),
      );
    }
    this.assertPersistenceWritable();
    const list = this.ctx.agentDirectives.get(task_id);
    if (!list) return null;
    const d = list.find(x => x.id === directive_id);
    if (!d) return null;
    if (d.status === 'pending') {
      d.status = 'acknowledged';
      d.acknowledged_at = this.ctx.nowIso();
      this.logActionEvent({
        description: `Agent task ${task_id} acknowledged directive '${d.kind}'`,
        event_type: 'instrumentation_warning',
        category: 'system',
        result_classification: 'neutral',
        agent_id: this.getTask(task_id)?.agent_id,
        linked_agent_task_id: task_id,
        details: { reason: 'directive_acknowledged', directive_id, kind: d.kind },
      });
      this.persist();
    }
    return d;
  }

  getCampaignChildren(parentId: string): import('../types.js').Campaign[] {
    return detached(this.campaignPlanner.getChildren(parentId));
  }

  getCampaignParentProgress(parentId: string): import('../types.js').CampaignProgress | null {
    const progress = this.campaignPlanner.getParentProgress(parentId);
    return progress ? detached(progress) : null;
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

  findPathsDetailed(fromNode: string, toNode: string, maxPaths: number = 5, optimize?: PathOptimize) {
    return this.paths.findPathsDetailed(fromNode, toNode, maxPaths, optimize);
  }

  /**
   * Post-ingest enrichment: identify HVTs and pre-compute attack paths.
   * Called after BloodHound/AzureHound ingestion.
   */
  enrichBloodHoundPaths(optimize?: PathOptimize): { hvts: HVTResult[]; paths: PreComputedPath[] } {
    this.assertPersistenceWritable();
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
    this.assertPersistenceWritable();
    const enricher = new WebChainEnricher(this.ctx);
    const chains = enricher.matchChainTemplates();
    if (chains.length > 0) {
      // Annotate frontier-relevant nodes through one committed transaction.
      // The previous raw setNodeAttribute loop could leave some annotations
      // live but unrecoverable after a crash-before-snapshot.
      const updates = new Map<string, NodeProperties>();
      for (const chain of chains) {
        const lastNode = chain.node_path[chain.node_path.length - 1];
        if (this.ctx.graph.hasNode(lastNode)) {
          const current = updates.get(lastNode)
            ?? detached(this.ctx.graph.getNodeAttributes(lastNode) as NodeProperties);
          updates.set(lastNode, {
            ...current,
            chain_template: chain.template_id,
          });
        }
      }
      const changed = [...updates.values()].filter((props) =>
        this.ctx.graph.getNodeAttribute(props.id, 'chain_template') !== props.chain_template,
      );
      if (changed.length > 0) {
        const updatedNodes = changed.map(props => props.id);
        const baseline = changed.map(props =>
          detached(this.ctx.graph.getNodeAttributes(props.id) as NodeProperties),
        );
        const operations: EngineOperation[] = changed.map(props => ({
          type: 'merge_node_attrs',
          payload: { props },
        }));
        const detail: GraphUpdateDetail = { updated_nodes: updatedNodes };
        try {
          this.ctx.applyEngineTransaction(
            { operations, update_detail: detail },
            () => {
              for (const props of changed) this.addNode(props);
            },
            'web chain enrichment',
          );
        } catch (error) {
          this.restoreWebChainAnnotationBaseline(baseline);
          throw error;
        }
        this.persist(detail);
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

  /** Bucket filterFrontier's `filtered` reasons into the dashboard's summary shape.
   *  Categorizes by the reason-string prefixes filterFrontier emits; an unrecognized
   *  reason counts toward `total` but no bucket (so total stays honest). */
  private summarizeFilteredFrontier(
    filtered: Array<{ item: FrontierItem; reason: string }>,
  ): import('../types.js').FrontierHiddenSummary {
    const by_reason = { lease: 0, opsec: 0, dead_host: 0, scope: 0 };
    for (const { reason } of filtered) {
      if (reason.startsWith('frontier_item_leased:')) by_reason.lease++;
      else if (reason.startsWith('OPSEC veto:')) by_reason.opsec++;
      else if (reason.startsWith('Dead host:')) by_reason.dead_host++;
      else if (reason.startsWith('Out of scope:')) by_reason.scope++;
    }
    return { total: filtered.length, by_reason };
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
    // A subdomain node's name IS its hostname — so scope checks (domain-suffix
    // match against scope.domains) apply to discovered subdomains instead of
    // treating them as hostname-less and trivially in-scope.
    if (node.type === 'subdomain' && typeof node.subdomain_name === 'string' && node.subdomain_name) {
      return node.subdomain_name;
    }
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
    target_node?: string; target_ip?: string; target_cidr?: string;
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

    // Scope check for scanner CIDRs. This validates the CIDR as a range
    // target instead of treating its network address as a host target.
    if (action.target_cidr) {
      if (!isCidrInScope(action.target_cidr, this.ctx.config.scope)) {
        errors.push(`Target CIDR is out of scope: ${action.target_cidr}`);
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
    // Passive OSINT (crt.sh, WHOIS, passive DNS, …) queries public sources and
    // never contacts the target, so it carries 0 noise and is exempt from the
    // noise ceiling and time window — those guard what the TARGET's defenders see.
    // The technique blacklist is still honored (explicit operator intent).
    const passiveRecon = isPassiveTechnique(action.technique);
    const effectiveOpsec = this.getEffectiveOpsec();
    if (effectiveOpsec.enabled) {
      // Check OPSEC blacklist (engagement-level + phase-extended).
      const effectiveBlacklist = this.getEffectiveApprovalConfig().blacklisted_techniques;
      if (action.technique && effectiveBlacklist.includes(action.technique)) {
        errors.push(`Technique blacklisted by OPSEC profile: ${action.technique}`);
      }

      // Time window check (handles wrap-around, e.g. 22:00–06:00) — skipped for
      // passive recon (off-target, invisible to defenders).
      if (effectiveOpsec.time_window && !passiveRecon) {
        const { start_hour, end_hour } = effectiveOpsec.time_window;
        const now = new Date(); // clock-ok: OPSEC time-window check is a real-time policy check (produces a warning, writes no state)
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

    // Noise budget warning (only when OPSEC enforcement is enabled). Passive
    // recon spends no budget, so it's exempt from the ceiling warnings.
    // P4.1: report against the effective max_noise (phase override if any).
    if (effectiveOpsec.enabled && !passiveRecon) {
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
    listener_id?: string;
    connection_generation?: number;
    agent_id?: string;
    action_id?: string;
    frontier_item_id?: string;
  }): void {
    this.assertPersistenceWritable();
    _ingestSessionResult(this.sessionHost, result);
  }

  onSessionClosed(_sessionId: string, targetNode?: string, principalNode?: string): void {
    this.assertPersistenceWritable();
    _onSessionClosed(this.sessionHost, _sessionId, targetNode, principalNode);
  }

  connectSessionGenerationDurably(
    metadata: SessionMetadata,
    description: string,
  ): void {
    const connectionId = metadata.connection_id ?? metadata.id;
    this.runAtomicGraphCommand(
      'connect session generation',
      metadata.action_id,
      () => {
        if (metadata.target_node && !this.ctx.graph.hasNode(metadata.target_node)) {
          throw new Error(
            `Cannot connect session generation: target node ${metadata.target_node} does not exist.`,
          );
        }
        if (metadata.principal_node && !this.ctx.graph.hasNode(metadata.principal_node)) {
          throw new Error(
            `Cannot connect session generation: principal node ${metadata.principal_node} does not exist.`,
          );
        }
        this.logActionEvent({
          event_type: 'session_connected',
          description,
          agent_id: metadata.agent_id,
          action_id: metadata.action_id,
          frontier_item_id: metadata.frontier_item_id,
          category: 'system',
          details: {
            session_id: metadata.id,
            listener_id: metadata.listener_id,
            connection_id: connectionId,
            connection_generation: metadata.connection_generation,
            session_kind: metadata.kind,
            session_state: metadata.state,
          },
        });
        if (metadata.target_node) {
          _ingestSessionResult(this.sessionHost, {
            success: true,
            confirmed: true,
            target_node: metadata.target_node,
            principal_node: metadata.principal_node,
            credential_node: metadata.credential_node,
            session_id: connectionId,
            listener_id: metadata.listener_id,
            connection_generation: metadata.connection_generation,
            agent_id: metadata.agent_id,
            action_id: metadata.action_id,
            frontier_item_id: metadata.frontier_item_id,
          });
        }
        this.recordSessionDescriptor(metadata);
      },
      ['session_descriptors'],
    );
  }

  closeSessionDurably(
    metadata: SessionMetadata,
    description: string,
    options: {
      preserve_descriptor?: boolean;
      connection_id?: string;
      event_type?: ActivityEventType;
    } = {},
  ): void {
    const preserveDescriptor = options.preserve_descriptor === true;
    const connectionId = options.connection_id
      ?? metadata.connection_id
      ?? metadata.last_connection_id
      ?? metadata.id;
    this.runAtomicGraphCommand(
      'close session lifecycle',
      metadata.action_id,
      () => {
        this.logActionEvent({
          event_type: options.event_type ?? 'session_closed',
          description,
          agent_id: metadata.agent_id,
          action_id: metadata.action_id,
          frontier_item_id: metadata.frontier_item_id,
          category: 'system',
          details: {
            session_id: metadata.id,
            listener_id: metadata.listener_id,
            connection_id: connectionId,
            connection_generation: metadata.connection_generation,
            session_kind: metadata.kind,
            session_state: metadata.state,
          },
        });
        _onSessionClosed(
          this.sessionHost,
          connectionId,
          metadata.target_node,
          metadata.principal_node,
        );
        if (!preserveDescriptor) {
          this.recordSessionDescriptor(metadata);
        }
      },
      preserveDescriptor ? [] : ['session_descriptors'],
    );
  }

  reconcileSessionEdgesOnStartup(): void {
    this.assertPersistenceWritable();
    _reconcileSessionEdgesOnStartup(this.sessionHost);
  }

  private reconcileSessionDescriptorsOnStartup(): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'reconcile session descriptors on startup',
        ['session_descriptors'],
        () => this.reconcileSessionDescriptorsOnStartup(),
      );
      return;
    }
    const interruptedAt = this.ctx.nowIso();
    let changed = false;
    this.ctx.sessionDescriptors = this.ctx.sessionDescriptors.map(descriptor => {
      const durableLifecycle = descriptor.recovery_lifecycle ?? descriptor.lifecycle;
      const adapter = descriptor.adapter ?? descriptor.kind;
      const listenerId = descriptor.listener_id
        ?? (descriptor.kind === 'socket' && descriptor.mode === 'listen'
          ? descriptor.session_id
          : undefined);
      const generation = descriptor.connection_generation
        ?? (durableLifecycle === 'connected' ? 1 : 0);
      const inferredConnectionId = descriptor.connection_id
        ?? (durableLifecycle === 'connected'
          ? `${descriptor.session_id}:g${Math.max(1, generation)}`
          : undefined);
      const active = durableLifecycle === 'pending' || durableLifecycle === 'connected';
      const resumableListener = descriptor.kind === 'socket'
        && descriptor.mode === 'listen'
        && descriptor.accept_mode === 'rearm'
        && descriptor.resume_intent.requested;
      const recoveredLifecycle = active
        ? (resumableListener ? 'resume_available' : 'interrupted')
        : durableLifecycle;
      const normalized: PersistedSessionDescriptorV1 = {
        ...descriptor,
        adapter,
        listener_id: listenerId,
        connection_generation: generation,
        ...persistedSessionLifecycle(recoveredLifecycle),
        closed_at: active ? undefined : descriptor.closed_at,
        connection_id: active ? undefined : descriptor.connection_id,
        connection_started_at: active ? undefined : descriptor.connection_started_at,
        last_connection_id: durableLifecycle === 'connected'
          ? inferredConnectionId
          : descriptor.last_connection_id,
        last_connection_state: durableLifecycle === 'connected'
          ? 'interrupted'
          : descriptor.last_connection_state,
        last_connection_closed_at: durableLifecycle === 'connected'
          ? interruptedAt
          : descriptor.last_connection_closed_at,
        auth_status: recoveredLifecycle === 'resume_available'
          ? undefined
          : descriptor.auth_status,
        capabilities: recoveredLifecycle === 'resume_available'
          ? detached(RECOVERED_LISTENER_CAPABILITIES)
          : descriptor.capabilities,
        resume_intent: active
          ? {
              ...descriptor.resume_intent,
              policy: resumableListener ? 'manual' : descriptor.resume_intent.policy,
              requested: resumableListener,
              prior_state: durableLifecycle === 'connected'
                ? 'connected'
                : 'pending',
              recorded_at: interruptedAt,
            }
          : descriptor.resume_intent,
      };
      if (canonicalJson(normalized) !== canonicalJson(descriptor)) changed = true;
      return normalized;
    });
    if (changed) this.persist();
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
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'record phase transition',
        ['activity', 'frontier', 'phase'],
        () => this.recordPhaseTransitionsIfAny(),
        {},
        ['frontier'],
      );
      return;
    }
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
    this.assertPersistenceWritable();
    return _recomputeObjectives(this.objectiveHost);
  }

  correctGraph(
    reason: string,
    operations: GraphCorrectionOperation[],
    actionId?: string,
  ): {
    dropped_nodes: string[];
    dropped_edges: string[];
    replaced_edges: Array<{ old_edge_id: string; new_edge_id: string }>;
    patched_nodes: string[];
  } {
    this.assertPersistenceWritable();
    if (reason.trim().length === 0) throw new Error('Graph correction reason must not be empty.');
    const nodeDrops = operations.filter((operation): operation is Extract<GraphCorrectionOperation, { kind: 'drop_node' }> =>
      operation.kind === 'drop_node',
    );
    if (nodeDrops.length > 0 && operations.length === 1) {
      const before = this.getNode(nodeDrops[0].node_id);
      if (!before) throw new Error(`Node does not exist in graph: ${nodeDrops[0].node_id}`);
      const dropped = this.dropNodeDurable(nodeDrops[0].node_id, {
        reason,
        ...(actionId ? { action_id: actionId } : {}),
      });
      return {
        dropped_nodes: [nodeDrops[0].node_id],
        dropped_edges: dropped.removed_edge_ids,
        replaced_edges: [],
        patched_nodes: [],
      };
    }
    const occurredAt = this.ctx.nowIso();
    const payload = this.planGraphCorrectionMutation(
      reason,
      operations,
      occurredAt,
      actionId,
    );
    this.ensureCompositeJournal();
    const applied = this.ctx.applyCompositeJournaledMutation(
      'graph_corrected',
      payload as unknown as Record<string, unknown>,
      () => this.applyGraphCorrectedMutation(payload, false),
      actionId,
    );
    if (applied.status !== 'applied') throw new Error(applied.reason);
    this.evaluateObjectives();
    this.persist({
      removed_nodes: payload.result.dropped_nodes,
      removed_edges: payload.result.dropped_edges,
      new_edges: payload.result.replaced_edges.map(edge => edge.new_edge_id),
      updated_nodes: payload.result.patched_nodes,
    });
    return detached(payload.result);
  }

  correctGraphApplicationCommand(
    reason: string,
    operations: GraphCorrectionOperation[],
    actionId: string | undefined,
    buildCommand: (
      result: GraphCorrectedMutationPayloadV1['result'],
    ) => PersistedApplicationCommandV1,
  ): {
    result: GraphCorrectedMutationPayloadV1['result'];
    command: PersistedApplicationCommandV1;
  } {
    this.assertPersistenceWritable();
    if (reason.trim().length === 0) {
      throw new Error('Graph correction reason must not be empty.');
    }
    const payload = this.planGraphCorrectionMutation(
      reason,
      operations,
      this.ctx.nowIso(),
      actionId,
    );
    const command = detached(buildCommand(detached(payload.result)));
    if (command.status !== 'succeeded') {
      throw new Error(
        'A graph correction application command must be terminal before it is journaled.',
      );
    }
    const stateKeys = ['command_state'] as const;
    const stateBefore = this.ctx.captureDurableStateSlices(stateKeys);
    let draft!: {
      result: PersistedApplicationCommandV1;
      slices: DurableStatePatchV1['slices'];
    };
    try {
      draft = this.ctx.draftDurableStateSlices(
        stateKeys,
        () => this.installApplicationCommandDraft(command),
      );
    } finally {
      this.applyRestoredRuntimeProjections();
    }
    const changedStateKeys = Object.keys(
      draft.slices,
    ) as DurableStateSliceKey[];
    const stateBeforePatch = Object.fromEntries(
      changedStateKeys.map(key => [key, stateBefore[key]]),
    ) as DurableStateSlices;
    payload.state_patch = {
      payload_version: 1,
      operation_id: uuidv4(),
      occurred_at: payload.occurred_at,
      reason,
      slices: draft.slices,
    };
    payload.state_patch_before_sha256 = createHash('sha256')
      .update(canonicalJson(stateBeforePatch))
      .digest('hex');
    payload.state_patch_after_sha256 = createHash('sha256')
      .update(canonicalJson(draft.slices))
      .digest('hex');

    this.ensureCompositeJournal();
    const applied = this.ctx.applyCompositeJournaledMutation(
      'graph_corrected',
      payload as unknown as Record<string, unknown>,
      () => this.applyGraphCorrectedMutation(payload, false),
      actionId,
    );
    if (applied.status !== 'applied') throw new Error(applied.reason);
    this.evaluateObjectives();
    this.persist({
      removed_nodes: payload.result.dropped_nodes,
      removed_edges: payload.result.dropped_edges,
      new_edges: payload.result.replaced_edges.map(edge => edge.new_edge_id),
      updated_nodes: payload.result.patched_nodes,
    });
    return {
      result: detached(payload.result),
      command: detached(draft.result),
    };
  }

  /**
   * Legacy engagements may predate WAL creation. Before their first composite
   * mutation, checkpoint the complete pre-state once and then start a journal
   * from that trusted base. Subsequent corrections use WAL durability and no
   * longer depend on a post-mutation forced snapshot.
   */
  private ensureCompositeJournal(): void {
    if (this.ctx.mutationJournal) return;
    this.persistence.persistImmediate();
    const journal = new MutationJournal(this.ctx.stateFilePath);
    journal.setNextSeq(this.ctx.journalSnapshotSeq, {
      appliedThroughSeq: this.ctx.journalSnapshotSeq,
    });
    this.persistence.enableMutationJournal(journal);
  }

  private planGraphCorrectionMutation(
    reason: string,
    operations: GraphCorrectionOperation[],
    occurredAt: string,
    actionId?: string,
    statePatch?: DurableStatePatchV1,
    statePatchBeforeSha256?: string,
    statePatchAfterSha256?: string,
  ): GraphCorrectedMutationPayloadV1 {
    const beforeNodes = this.collectGraphNodeStates(this.ctx.graph);
    const beforeEdges = this.collectGraphEdgeStates(this.ctx.graph);
    const scratch = createGraph();
    scratch.import(detached(this.ctx.graph.export()));
    const droppedNodes: string[] = [];
    const droppedEdges: string[] = [];
    const replacedEdges: Array<{ old_edge_id: string; new_edge_id: string }> = [];
    const patchedNodes: string[] = [];
    const beforeSummary = { total_nodes: scratch.order, total_edges: scratch.size };

    for (const operation of operations) {
      if (operation.kind === 'drop_node') {
        if (!scratch.hasNode(operation.node_id)) {
          throw new Error(`Node does not exist in graph: ${operation.node_id}`);
        }
        const incidentEdgeIds = scratch.edges(operation.node_id);
        scratch.dropNode(operation.node_id);
        droppedNodes.push(operation.node_id);
        droppedEdges.push(...incidentEdgeIds);
        continue;
      }

      if (operation.kind === 'drop_edge') {
        const edgeId = this.findEdgeInGraph(
          scratch,
          operation.source_id,
          operation.target_id,
          operation.edge_type,
        );
        if (!edgeId) {
          throw new Error(`Edge does not exist in graph: ${operation.source_id} --[${operation.edge_type}]--> ${operation.target_id}`);
        }
        scratch.dropEdge(edgeId);
        droppedEdges.push(edgeId);
        continue;
      }

      if (operation.kind === 'replace_edge') {
        const oldEdgeId = this.findEdgeInGraph(
          scratch,
          operation.source_id,
          operation.target_id,
          operation.edge_type,
        );
        if (!oldEdgeId) {
          throw new Error(`Edge does not exist in graph: ${operation.source_id} --[${operation.edge_type}]--> ${operation.target_id}`);
        }
        const previousAttrs = detached(scratch.getEdgeAttributes(oldEdgeId) as EdgeProperties);
        const sourceId = operation.new_source_id || operation.source_id;
        const targetId = operation.new_target_id || operation.target_id;
        const edgeType = operation.new_edge_type || operation.edge_type;
        if (!scratch.hasNode(sourceId) || !scratch.hasNode(targetId)) {
          throw new Error(`Replacement edge references missing nodes: ${sourceId} --[${edgeType}]--> ${targetId}`);
        }
        const sourceNode = scratch.getNodeAttributes(sourceId) as NodeProperties;
        const targetNode = scratch.getNodeAttributes(targetId) as NodeProperties;
        const validation = validateEdgeEndpoints(edgeType, sourceNode.type, targetNode.type, {
          source_id: sourceId,
          target_id: targetId,
          edge_id: oldEdgeId,
        });
        if (!validation.valid) {
          const suggestion = validation.suggested_fix?.message
            ? ` Suggested fix: ${validation.suggested_fix.message}`
            : '';
          throw new Error(`Replacement edge ${edgeType} cannot connect ${sourceNode.type} to ${targetNode.type}.${suggestion}`);
        }
        scratch.dropEdge(oldEdgeId);
        const nextProps = {
          ...previousAttrs,
          ...(operation.properties || {}),
          type: edgeType,
          confidence: operation.confidence ?? previousAttrs.confidence ?? 1,
          discovered_at: previousAttrs.discovered_at || occurredAt,
          discovered_by: previousAttrs.discovered_by,
        } as EdgeProperties;
        const newEdgeId = this.addEdgeToCorrectionDraft(
          scratch,
          sourceId,
          targetId,
          nextProps,
          occurredAt,
        );
        droppedEdges.push(oldEdgeId);
        replacedEdges.push({ old_edge_id: oldEdgeId, new_edge_id: newEdgeId });
        continue;
      }

      const existing = scratch.hasNode(operation.node_id)
        ? detached(scratch.getNodeAttributes(operation.node_id) as NodeProperties)
        : null;
      if (!existing) throw new Error(`Node does not exist in graph: ${operation.node_id}`);
      scratch.replaceNodeAttributes(
        operation.node_id,
        this.buildPatchedNode(
          existing,
          operation.set_properties,
          operation.unset_properties,
        ),
      );
      patchedNodes.push(operation.node_id);
    }

    const afterNodes = this.collectGraphNodeStates(scratch);
    const afterEdges = this.collectGraphEdgeStates(scratch);
    const nodeChanges: GraphCorrectedMutationPayloadV1['node_changes'] = [];
    for (const nodeId of [...new Set([...beforeNodes.keys(), ...afterNodes.keys()])].sort()) {
      const before = beforeNodes.get(nodeId);
      const after = afterNodes.get(nodeId);
      if (before && after && canonicalJson(before) === canonicalJson(after)) continue;
      nodeChanges.push({
        node_id: nodeId,
        ...(before ? { before } : {}),
        ...(after ? { after } : {}),
      });
    }
    const edgeChanges: GraphCorrectedMutationPayloadV1['edge_changes'] = [];
    for (const edgeId of [...new Set([...beforeEdges.keys(), ...afterEdges.keys()])].sort()) {
      const before = beforeEdges.get(edgeId);
      const after = afterEdges.get(edgeId);
      if (before && after && canonicalJson(before) === canonicalJson(after)) continue;
      edgeChanges.push({
        edge_id: edgeId,
        ...(before ? { before } : {}),
        ...(after ? { after } : {}),
      });
    }

    return JSON.parse(JSON.stringify({
      payload_version: 1,
      operation_id: uuidv4(),
      occurred_at: occurredAt,
      reason,
      ...(actionId ? { action_id: actionId } : {}),
      operations,
      node_changes: nodeChanges,
      edge_changes: edgeChanges,
      before_summary: beforeSummary,
      after_summary: { total_nodes: scratch.order, total_edges: scratch.size },
      ...(statePatch
        ? {
            state_patch: statePatch,
            state_patch_before_sha256: statePatchBeforeSha256,
            state_patch_after_sha256: statePatchAfterSha256,
          }
        : {}),
      result: {
        dropped_nodes: [...new Set(droppedNodes)],
        dropped_edges: [...new Set(droppedEdges)],
        replaced_edges: replacedEdges,
        patched_nodes: [...new Set(patchedNodes)],
      },
    })) as GraphCorrectedMutationPayloadV1;
  }

  applyGraphCorrectedMutation(
    payload: GraphCorrectedMutationPayloadV1,
    recovery = true,
  ): MutationApplyResult {
    if (payload.payload_version !== 1) {
      return { status: 'skipped', reason: `unsupported graph_corrected payload version: ${String(payload.payload_version)}` };
    }
    const graphApplied = this.exactGraphDeltaMatches(payload, 'after');
    const graphReady = this.exactGraphDeltaMatches(payload, 'before');
    const statePatchKeys = payload.state_patch
      ? Object.keys(payload.state_patch.slices) as DurableStateSliceKey[]
      : [];
    if (
      payload.state_patch
      && (
        !payload.state_patch_before_sha256
        || !payload.state_patch_after_sha256
        || !/^[a-f0-9]{64}$/.test(payload.state_patch_before_sha256)
        || !/^[a-f0-9]{64}$/.test(payload.state_patch_after_sha256)
      )
    ) {
      return {
        status: 'skipped',
        reason:
          'graph_corrected state patch is missing valid before/after hashes',
      };
    }
    const currentStateSlices = payload.state_patch
      ? this.ctx.captureDurableStateSlices(statePatchKeys)
      : {};
    const currentStateHash = createHash('sha256')
      .update(canonicalJson(currentStateSlices))
      .digest('hex');
    const statePatchReady = !payload.state_patch
      || currentStateHash === payload.state_patch_before_sha256;
    const statePatchApplied = !payload.state_patch
      || currentStateHash === payload.state_patch_after_sha256;
    const alreadyApplied = graphApplied && statePatchApplied;
    const readyToApply = (
      (graphReady || graphApplied)
      && (statePatchReady || statePatchApplied)
      && !alreadyApplied
    );
    if (!alreadyApplied && !readyToApply) {
      return {
        status: 'skipped',
        reason: [
          `graph_corrected preconditions changed for operation ${payload.operation_id}`,
          `graph=${graphReady ? 'before' : graphApplied ? 'after' : 'different'}`,
          `state=${statePatchReady ? 'before' : statePatchApplied ? 'after' : 'different'}`,
        ].join('; '),
      };
    }

    const graphSnapshot = this.ctx.graph.export();
    const activitySnapshot = detached(this.ctx.activityLog);
    const chainHashSnapshot = this.ctx.lastChainHash;
    const chainCheckpointsSnapshot = detached(this.ctx.chainCheckpoints);
    const chainEventsSnapshot = this.ctx.chainEventsSinceCheckpoint;
    const deterministicSeqSnapshot = this.ctx.deterministicSeq;
    const actionFrontierSnapshot = new Map(
      [...this.ctx.actionFrontierMap].map(([key, value]) => [key, detached(value)]),
    );
    const frontierLinkageSnapshot = detached(this.ctx.frontierLinkage.serialize());
    const statePatchSnapshot = payload.state_patch
      ? this.ctx.captureDurableStateSlices(statePatchKeys)
      : undefined;
    try {
      this.ctx.withClock(payload.occurred_at, () => {
        if (graphReady) {
          for (const change of payload.edge_changes) {
            if (change.before && this.ctx.graph.hasEdge(change.edge_id)) this.ctx.graph.dropEdge(change.edge_id);
          }
          for (const change of payload.node_changes) {
            if (!change.after && this.ctx.graph.hasNode(change.node_id)) this.ctx.graph.dropNode(change.node_id);
          }
          for (const change of payload.node_changes) {
            if (!change.after) continue;
            if (this.ctx.graph.hasNode(change.node_id)) {
              this.ctx.graph.replaceNodeAttributes(change.node_id, detached(change.after.props));
            } else {
              this.ctx.graph.addNode(change.node_id, detached(change.after.props));
            }
          }
          for (const change of payload.edge_changes) {
            if (!change.after) continue;
            const edge = change.after;
            if (!this.ctx.graph.hasNode(edge.source) || !this.ctx.graph.hasNode(edge.target)) {
              throw new Error(`graph_corrected edge ${edge.edge_id} has a missing endpoint`);
            }
            this.ctx.graph.addEdgeWithKey(
              edge.edge_id,
              edge.source,
              edge.target,
              detached(edge.props),
            );
          }
          if (!this.exactGraphDeltaMatches(payload, 'after')) {
            throw new Error(`graph_corrected did not reach its frozen post-state for operation ${payload.operation_id}`);
          }
        }
        if (payload.state_patch && statePatchReady) {
          this.ctx.applyDurableStatePatch(payload.state_patch.slices);
          const appliedStateHash = createHash('sha256')
            .update(canonicalJson(
              this.ctx.captureDurableStateSlices(statePatchKeys),
            ))
            .digest('hex');
          if (appliedStateHash !== payload.state_patch_after_sha256) {
            throw new Error(
              `graph_corrected did not reach its frozen command state for operation ${payload.operation_id}`,
            );
          }
        }
        const alreadyAudited = this.ctx.activityLog.some(entry =>
          entry.event_type === 'graph_corrected'
          && entry.details?.operation_id === payload.operation_id,
        );
        if (!alreadyAudited) {
          this.ctx.logEvent({
            description: `Graph corrected: ${payload.operations.length} operation(s) applied`,
            action_id: payload.action_id,
            event_type: 'graph_corrected',
            category: 'system',
            result_classification: 'success',
            details: {
              operation_id: payload.operation_id,
              reason: payload.reason,
              operations: payload.operations,
              before_summary: payload.before_summary,
              after_summary: payload.after_summary,
              dropped_nodes: payload.result.dropped_nodes,
              dropped_edges: payload.result.dropped_edges,
              replaced_edges: payload.result.replaced_edges,
              patched_nodes: payload.result.patched_nodes,
            },
          });
        }
      });
      this.invalidateAllCaches();
      this.invalidatePathGraph();
      return { status: 'applied' };
    } catch (error) {
      this.ctx.graph.clear();
      this.ctx.graph.import(graphSnapshot);
      this.ctx.activityLog = activitySnapshot;
      this.ctx.lastChainHash = chainHashSnapshot;
      this.ctx.chainCheckpoints = chainCheckpointsSnapshot;
      this.ctx.chainEventsSinceCheckpoint = chainEventsSnapshot;
      this.ctx.deterministicSeq = deterministicSeqSnapshot;
      this.ctx.actionFrontierMap = actionFrontierSnapshot;
      this.ctx.frontierLinkage = FrontierLinkageTracker.deserialize(frontierLinkageSnapshot);
      if (statePatchSnapshot) {
        this.ctx.applyDurableStatePatch(statePatchSnapshot);
      }
      this.invalidateAllCaches();
      this.invalidatePathGraph();
      if (!recovery) throw error;
      return { status: 'skipped', reason: error instanceof Error ? error.message : String(error) };
    }
  }

  private collectGraphNodeStates(graph: OverwatchGraph): Map<string, { node_id: string; props: NodeProperties }> {
    const states = new Map<string, { node_id: string; props: NodeProperties }>();
    graph.forEachNode((nodeId, props) => {
      states.set(nodeId, { node_id: nodeId, props: detached(props as NodeProperties) });
    });
    return states;
  }

  private collectGraphEdgeStates(graph: OverwatchGraph): Map<string, { edge_id: string; source: string; target: string; props: EdgeProperties }> {
    const states = new Map<string, { edge_id: string; source: string; target: string; props: EdgeProperties }>();
    for (const edgeId of graph.edges()) {
      states.set(edgeId, {
        edge_id: edgeId,
        source: graph.source(edgeId),
        target: graph.target(edgeId),
        props: detached(graph.getEdgeAttributes(edgeId) as EdgeProperties),
      });
    }
    return states;
  }

  private findEdgeInGraph(graph: OverwatchGraph, source: string, target: string, type: EdgeType): string | null {
    if (!graph.hasNode(source) || !graph.hasNode(target)) return null;
    const matches = graph.edges(source, target).filter(edgeId =>
      graph.getEdgeAttributes(edgeId).type === type,
    );
    if (matches.length > 1) {
      throw new Error(
        `Edge reference is ambiguous: ${source} --[${type}]--> ${target} matches ${matches.length} parallel edges.`,
      );
    }
    return matches[0] ?? null;
  }

  private addEdgeToCorrectionDraft(
    graph: OverwatchGraph,
    source: string,
    target: string,
    props: EdgeProperties,
    occurredAt: string,
  ): string {
    for (const edgeId of graph.edges(source, target)) {
      const existing = graph.getEdgeAttributes(edgeId) as EdgeProperties;
      if (!edgeIdentityMatches(existing, props)) continue;
      const effective = existing.inferred_by_rule && !existing.confirmed_at && props.confidence >= 1
        ? { ...props, confirmed_at: occurredAt }
        : props;
      graph.mergeEdgeAttributes(edgeId, detached(effective));
      return edgeId;
    }
    const preferred = preferredEdgeKey(source, target, props);
    const edgeId = graph.hasEdge(preferred)
      ? deterministicCollisionEdgeKey(source, target, props)
      : preferred;
    if (graph.hasEdge(edgeId)) throw new Error(`Deterministic correction edge collision: ${edgeId}`);
    graph.addEdgeWithKey(edgeId, source, target, detached(props));
    return edgeId;
  }

  private buildPatchedNode(
    existing: NodeProperties,
    setProperties: Record<string, unknown> = {},
    unsetProperties: string[] = [],
  ): NodeProperties {
    if (
      (typeof setProperties.id === 'string' && setProperties.id !== existing.id)
      || (typeof setProperties.type === 'string' && setProperties.type !== existing.type)
      || unsetProperties.includes('id')
      || unsetProperties.includes('type')
    ) {
      throw new Error('patch_node cannot change a node id or type.');
    }
    const nextNode = existing.type === 'credential'
      ? normalizeFindingNode({
          ...existing,
          ...setProperties,
          id: existing.id,
          type: existing.type,
          label: typeof setProperties.label === 'string' ? setProperties.label : existing.label,
        } as Partial<NodeProperties> & { id: string; type: string })
      : ({ ...existing, ...setProperties } as NodeProperties);
    for (const key of unsetProperties) delete (nextNode as Record<string, unknown>)[key];
    const validationErrors = validateFindingNode(
      nextNode as Partial<NodeProperties> & { id: string; type: string },
    );
    if (validationErrors.length > 0) {
      throw new Error(validationErrors.map(error => error.message).join('; '));
    }
    const completeNode = nextNode as NodeProperties;
    return { ...completeNode, ...normalizeNodeProvenance(completeNode) } as NodeProperties;
  }

  // =============================================
  // Agent Management (delegated to AgentManager)
  // =============================================

  registerAgent(task: AgentTaskInput | AgentTask): {
    ok: boolean;
    lease_conflict?: { existing_task_id: string; existing_agent_id: string };
    node_conflict?: { existing_task_id: string; existing_agent_id: string; node_id: string };
    cap_exceeded?: { scope: 'subnet' | 'target'; key: string; limit: number; current: number };
  } {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'register agent',
        ['agents', 'activity', 'frontier'],
        () => this.registerAgent(detached(task)),
      );
    }
    this.assertPersistenceWritable();
    const canonicalTask = normalizeAgentTask(task);
    // Operator-policy dispatch cap: refuse (don't register) when a target-facing
    // agent would exceed the per-subnet / per-target limit. Checked BEFORE
    // register() so no lease is taken and — critically — no event is logged, so
    // a refusal can't perturb replay determinism. The cap is a deferral, not a
    // drop: the caller surfaces it (429 / skip) and re-dispatches when a slot frees.
    const cap = this.checkDispatchCap(canonicalTask);
    if (cap) return { ok: false, cap_exceeded: cap };
    const result = this.agentMgr.register(canonicalTask);
    this.persist();
    return result;
  }

  /** /24 key for an IPv4 address; null for IPv6 / unparseable (exempt from the subnet cap). */
  private subnetKey(ip: string): string | null {
    const m = ip.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/);
    return m ? `${m[1]}.0/24` : null;
  }

  /** The target IP a task works on, from its seed nodes (host or service→host). */
  private taskTargetIp(task: AgentTask): string | null {
    for (const nodeId of task.subgraph_node_ids ?? []) {
      const ip = this.resolveHostIp(nodeId);
      if (ip) return ip;
    }
    return null;
  }

  /**
   * Per-subnet / per-target dispatch cap. Counts the currently running|pending
   * target-facing tasks already on the new task's target IP / /24, and refuses if
   * adding this one would exceed the policy limit. Returns null (allow) when: no
   * policy, the task is read-only, it has no resolvable target IP (exempt — matches
   * the "no-IP node is in-scope" precedent), or it's under the cap. Engagement-global
   * by design (blast radius doesn't care which campaign).
   */
  private checkDispatchCap(task: AgentTask): { scope: 'subnet' | 'target'; key: string; limit: number; current: number } | null {
    const limits = this.ctx.config.operator_policy?.dispatch_limits;
    if (!limits || (!limits.max_per_subnet && !limits.max_per_target)) return null;
    if (!isTargetFacing(task.archetype ?? task.role, limits.target_facing_archetypes)) return null;
    const ip = this.taskTargetIp(task);
    if (!ip) return null;
    const subnet = this.subnetKey(ip);

    let sameTarget = 0;
    let sameSubnet = 0;
    for (const other of this.ctx.agents.values()) {
      if (other.id === task.id) continue;
      // Count live work: a running OR queued (pending) agent holds a slot — count
      // both so a queued dispatch doesn't let the cap be over-shot. A slot frees
      // when the agent reaches a terminal status (completed/failed/interrupted),
      // including the watchdog's running→interrupted reap.
      if (other.status !== 'running' && other.status !== 'pending') continue;
      if (!isTargetFacing(other.archetype ?? other.role, limits.target_facing_archetypes)) continue;
      const otherIp = this.taskTargetIp(other);
      if (!otherIp) continue;
      if (otherIp === ip) sameTarget++;
      if (subnet && this.subnetKey(otherIp) === subnet) sameSubnet++;
    }

    if (limits.max_per_target && sameTarget >= limits.max_per_target) {
      return { scope: 'target', key: ip, limit: limits.max_per_target, current: sameTarget };
    }
    if (limits.max_per_subnet && subnet && sameSubnet >= limits.max_per_subnet) {
      return { scope: 'subnet', key: subnet, limit: limits.max_per_subnet, current: sameSubnet };
    }
    return null;
  }

  getRunningTaskForFrontierItem(frontierItemId: string): AgentTask | null {
    const task = this.agentMgr.getRunningTaskForFrontierItem(frontierItemId);
    return task ? detached(task) : null;
  }

  getTask(taskId: string): AgentTask | null {
    const task = this.agentMgr.getTask(taskId);
    return task ? detached(task) : null;
  }

  resolveAgentTaskReference(reference: string): AgentIdentityResolution {
    const result = this.agentMgr.resolveTaskReference(reference);
    return result.status === 'exact' || result.status === 'unique_legacy_label'
      ? { ...result, task: detached(result.task) }
      : detached(result);
  }

  /** All known agent tasks (running, completed, failed, interrupted). */
  getAgentTasks(): AgentTask[] {
    return detached(this.agentMgr.getAll());
  }

  /**
   * Auto-register a synthetic running task for `agent_id` if none exists.
   * Idempotent. Used by the instrumented process runner so subagents
   * that bypass `register_agent` still surface on the dashboard.
   */
  ensureRunningAgent(agentId: string | undefined): AgentTask | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'ensure running agent',
        ['agents', 'activity', 'frontier'],
        () => this.ensureRunningAgent(agentId),
      );
    }
    this.assertPersistenceWritable();
    const task = this.agentMgr.ensureRunningAgent(agentId, this.ctx.nowIso());
    if (task) this.persist();
    return task;
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
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'allocate deterministic sequence',
        ['activity'],
        () => this.nextDeterministicSeq(),
      );
    }
    this.assertPersistenceWritable();
    return this.ctx.nextDeterministicSeq();
  }

  /** P0.3: heartbeat + watchdog passthrough. Silent keepalives omit the
   * activity event, but the task/lease projection still crosses the canonical
   * durable state boundary. */
  agentHeartbeat(taskId: string, now?: string, opts?: { silent?: boolean }): boolean {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'record agent heartbeat',
        ['agents', 'activity', 'frontier'],
        () => this.applyAgentHeartbeat(taskId, now, opts),
      );
    }
    return this.applyAgentHeartbeat(taskId, now, opts);
  }

  private applyAgentHeartbeat(
    taskId: string,
    now?: string,
    opts?: { silent?: boolean },
  ): boolean {
    this.assertPersistenceWritable();
    const ok = this.agentMgr.heartbeat(taskId, now, opts);
    if (ok && !opts?.silent) this.persist();
    return ok;
  }

  /**
   * Set a task's heartbeat TTL (seconds). Used to give a headless sub-agent a
   * generous cold-start grace so the watchdog doesn't reap it before its spawn +
   * MCP bootstrap + first heartbeat complete. Returns false for an unknown task.
   */
  setAgentHeartbeatTtl(taskId: string, seconds: number): boolean {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'set agent heartbeat TTL',
        ['agents'],
        () => this.setAgentHeartbeatTtl(taskId, seconds),
      );
    }
    this.assertPersistenceWritable();
    const task = this.agentMgr.getTask(taskId);
    if (!task) return false;
    task.heartbeat_ttl_seconds = seconds;
    this.persist();
    return true;
  }

  /** Update durable scheduler flags without exposing the live AgentTask object.
   * These fields are intentionally narrow: lifecycle transitions continue to
   * go through updateAgentStatus(), which enforces terminal monotonicity. */
  updateAgentSchedulerFlags(taskId: string, patch: { no_retry?: boolean; reoffered?: boolean }): boolean {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'update agent scheduler flags',
        ['agents'],
        () => this.updateAgentSchedulerFlags(taskId, patch),
      );
    }
    this.assertPersistenceWritable();
    const task = this.agentMgr.getTask(taskId);
    if (!task) return false;
    if (patch.no_retry !== undefined) task.no_retry = patch.no_retry;
    if (patch.reoffered !== undefined) task.reoffered = patch.reoffered;
    this.persist();
    return true;
  }

  reapStaleAgents(now?: string): number {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'reap stale agents',
        ['agents', 'plans_questions', 'approvals', 'activity', 'frontier'],
        () => this.reapStaleAgents(now),
      );
    }
    this.assertPersistenceWritable();
    const runningBefore = new Set(this.agentMgr.getAll()
      .filter(task => task.status === 'running')
      .map(taskIdOf));
    const reaped = this.agentMgr.reapStaleHeartbeats(now);
    if (reaped > 0) {
      for (const taskId of runningBefore) {
        if (this.agentMgr.getTask(taskId)?.status === 'interrupted') {
          this.abortApprovalsForTask(taskId, 'heartbeat timeout');
        }
      }
    }
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
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'reconcile agents on startup',
        ['agents', 'plans_questions', 'approvals', 'activity', 'frontier'],
        () => this.reconcileAgentsOnStartup(),
      );
    }
    this.assertPersistenceWritable();
    const runningBefore = this.agentMgr.getAll()
      .filter(task => task.status === 'running')
      .map(taskIdOf);
    const count = this.agentMgr.reconcileOnStartup();
    for (const taskId of runningBefore) {
      if (this.agentMgr.getTask(taskId)?.status === 'interrupted') {
        this.abortApprovalsForTask(taskId, 'daemon restart');
      }
    }
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
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'reap expired frontier leases',
        ['agents'],
        () => this.reapExpiredFrontierLeases(now),
      );
    }
    this.assertPersistenceWritable();
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
    if (!overrides) return detached(this.ctx.config.opsec);
    return detached({ ...this.ctx.config.opsec, ...overrides } as typeof this.ctx.config.opsec);
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
  getEffectiveApprovalConfig(
    actionCtx?: { ip?: string; nodeId?: string; technique?: string },
  ): { mode: import('../types.js').ApprovalMode; blacklisted_techniques: string[]; opsec_enabled: boolean } {
    const phase = _getCurrentPhase(this.objectiveHost);
    const baseMode = this.ctx.config.opsec.approval_mode ?? 'auto-approve';
    const baseBlacklist = this.ctx.config.opsec.blacklisted_techniques ?? [];
    const overrides = phase?.approval_overrides;
    let mode: import('../types.js').ApprovalMode = overrides?.mode ?? baseMode;
    // Phase blacklist EXTENDS the engagement-level one (not replaces) so
    // operator-level safety rules can't be silently weakened by a phase.
    const blacklisted_techniques = overrides?.blacklisted_techniques
      ? [...new Set([...baseBlacklist, ...overrides.blacklisted_techniques])]
      : baseBlacklist;

    // Operator-policy approval rules can only TIGHTEN: fold every rule that
    // matches this action and take the strictest mode. A rule that resolves to a
    // looser mode is ignored — the policy is incapable of weakening the gate, so
    // the "phase/engagement is the floor" invariant holds by construction.
    const rules = this.ctx.config.operator_policy?.approval_rules;
    if (rules && rules.length > 0 && actionCtx) {
      let hostClass: 'in_scope' | 'unverified' | 'excluded' | undefined;
      if (actionCtx.nodeId) {
        hostClass = this.isNodeExcluded(actionCtx.nodeId)
          ? 'excluded'
          : this.isNodeVerifiedInScope(actionCtx.nodeId) ? 'in_scope' : 'unverified';
      }
      for (const rule of rules) {
        const m = rule.match;
        if (m.technique && m.technique !== actionCtx.technique) continue;
        if (m.host_class && m.host_class !== hostClass) continue;
        if (m.network && !(actionCtx.ip && isIpInCidr(actionCtx.ip, m.network))) continue;
        if (APPROVAL_STRICTNESS[rule.require] > APPROVAL_STRICTNESS[mode]) mode = rule.require;
      }
    }
    // The PHASE-EFFECTIVE OPSEC switch (base config folded with the active phase's
    // opsec_overrides), so approval escalation agrees with the enforcement path
    // (validateAction / filterFrontier ceiling) and the opsec_skipped the tools branch on.
    return { mode, blacklisted_techniques, opsec_enabled: this.getEffectiveOpsec().enabled === true };
  }

  updateAgentStatus(taskId: string, status: AgentTask['status'], summary?: string): boolean {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'update agent lifecycle',
        ['agents', 'campaigns', 'plans_questions', 'approvals', 'activity', 'frontier'],
        () => this.updateAgentStatus(taskId, status, summary),
      );
    }
    this.assertPersistenceWritable();
    const task = this.agentMgr.getTask(taskId);
    const ok = this.agentMgr.updateStatus(taskId, status, summary);
    if (ok) {
      if (status === 'completed' || status === 'failed' || status === 'interrupted') {
        this.abortApprovalsForTask(taskId, summary ?? `agent ${status}`);
      }
      // Campaign progress aggregation: when a campaign agent reaches terminal state,
      // update campaign progress and check abort conditions.
      if (task?.campaign_id && (status === 'completed' || status === 'failed')) {
        const result = status === 'completed' ? 'success' as const : 'failure' as const;
        this.campaignPlanner.updateCampaignProgress(task.campaign_id, task.frontier_item_id || '', result);
        const abort = this.campaignPlanner.checkAbortConditions(task.campaign_id);
        if (abort.should_abort) {
          this.campaignPlanner.abortCampaign(task.campaign_id);
          // Stop the remaining running agents of the now-aborted campaign(s). The task
          // that triggered this is already terminal (completed/failed), so it's skipped.
          this.stopRunningAgentsOfAbortedCampaigns(`Campaign aborted: ${abort.reason}`);
        }
      }
      this.persist();
    }
    return ok;
  }

  /**
   * Remove a terminal agent task from the roster (operator "dismiss"/"clear
   * finished"). Gated to terminal statuses inside AgentManager.dismiss; persists
   * a snapshot so the removal survives a restart (agent tasks aren't WAL-replayed).
   */
  dismissAgent(taskId: string): boolean {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'dismiss agent',
        ['agents', 'activity', 'frontier'],
        () => this.dismissAgent(taskId),
      );
    }
    this.assertPersistenceWritable();
    const ok = this.agentMgr.dismiss(taskId);
    if (ok) this.persist();
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

    const state: EngagementState = {
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
      frontier_hidden: this.getFrontierHiddenSummary(),
      active_agents: Array.from(this.ctx.agents.values()).filter(a => a.status === 'running'),
      agents: Array.from(this.ctx.agents.values()),
      recent_activity: this.filterRecentActivity({ activityCount, includeReasoning, includeSystem }),
      access_summary: {
        compromised_hosts: compromised,
        valid_credentials: validCreds,
        current_access_level: _computeAccessLevel(this.objectiveHost, compromised)
      },
      warnings: summarizeHealthReport(healthReport),
      lab_readiness: labReadiness,
      persistence_recovery: this.getPersistenceRecoveryStatus(),
      scope_suggestions: this.collectScopeSuggestions(),
      phases: this.getPhaseStatuses(),
      current_phase: this.getCurrentPhaseId(),
      inference_rule_effectiveness: this.getInferenceRuleStats(),
      credential_coverage: this.getCredentialCoverage(),
    };
    return detached(state);
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
      addEdge: this.addEdge.bind(this),
      mergeEdgeAttributes: this.mergeEdgeAttributesDurable.bind(this),
      persist: (() => this.persist()) as () => void,
      invalidateFrontierCache: this.invalidateFrontierCache.bind(this),
      invalidatePathGraph: this.invalidatePathGraph.bind(this),
    };
  }

  private get objectiveHost(): ObjectiveManagerHost {
    return {
      ctx: this.ctx,
      getNode: this.getNode.bind(this),
      addNode: this.addNode.bind(this),
      getNodesByType: this.getNodesByType.bind(this),
      queryGraph: this.queryGraph.bind(this),
      persist: (() => this.persist()) as () => void,
      log: this.log.bind(this),
      commitObjectives: (objectives, source) => {
        this.configService.commit(mergeConfig(this.ctx.config, { objectives }), source);
      },
      nowIso: () => this.ctx.nowIso(),
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
    this.assertPersistenceWritable();
    return this.commitScopeUpdate(changes);
  }

  /** Full-scope replacement used by the dashboard. Network and cloud/SaaS
   * fields share one WAL/config commit instead of two independently-failing
   * mutations. */
  updateScopeConfig(
    scope: EngagementConfig['scope'],
    reason: string,
  ): { applied: boolean; errors: string[]; before: EngagementConfig['scope']; after: EngagementConfig['scope']; affected_node_count: number } {
    this.assertPersistenceWritable();
    return this.commitScopeUpdate({ replace_scope: scope, reason });
  }

  /**
   * Compose a scope/config update with synchronous coordination-state effects
   * as one journaled command. The callback is drafted against the current
   * coordination state; its absolute after-state is embedded in the immutable
   * scope record and applied only when the matching before-state is present.
   *
   * This is the transaction boundary used by quick deploy: either both the
   * target enters scope and the agent/idempotency record exist, or neither does.
   */
  runAtomicScopeCommand<T>(
    changes: {
      add_cidrs?: string[];
      remove_cidrs?: string[];
      add_domains?: string[];
      remove_domains?: string[];
      add_exclusions?: string[];
      remove_exclusions?: string[];
      reason: string;
    },
    sourceActionId: string | undefined,
    stateKeys: readonly DurableStateSliceKey[],
    mutation: (scope: {
      before: EngagementConfig['scope'];
      after: EngagementConfig['scope'];
      affected_node_count: number;
    }) => T,
  ): {
    scope: {
      applied: boolean;
      errors: string[];
      before: EngagementConfig['scope'];
      after: EngagementConfig['scope'];
      affected_node_count: number;
    };
    result: T;
  } {
    this.assertPersistenceWritable();
    const plan = planScopeUpdate(this.scopeHost, changes);
    if (plan.errors.length > 0) {
      const error = new Error(plan.errors.join('; '));
      (error as Error & { code: string }).code = 'SCOPE_VALIDATION_FAILED';
      throw error;
    }

    if (canonicalJson(plan.before) === canonicalJson(plan.after)) {
      const result = this.runApplicationCommandTransaction(
        changes.reason,
        sourceActionId,
        () => mutation({
          before: detached(plan.before),
          after: detached(plan.after),
          affected_node_count: 0,
        }),
        stateKeys,
      );
      return {
        scope: {
          applied: true,
          errors: [],
          before: detached(plan.before),
          after: detached(plan.after),
          affected_node_count: 0,
        },
        result,
      };
    }

    const sourceConfig = this.ctx.config;
    const targetConfig = this.configService.prepareJournalTarget(
      mergeConfig(sourceConfig, { scope: plan.after }),
    );
    const sourceFileHash = this.configService.getStatus().file_hash ?? computeConfigHash(sourceConfig);
    const uniqueStateKeys = [...new Set(stateKeys)];
    const stateBefore = this.ctx.captureDurableStateSlices(uniqueStateKeys);
    let draft!: { result: T; slices: DurableStatePatchV1['slices'] };
    try {
      draft = this.ctx.draftDurableStateSlices(
        uniqueStateKeys,
        () => mutation({
          before: detached(plan.before),
          after: detached(plan.after),
          affected_node_count: plan.affected_node_count,
        }),
      );
    } finally {
      this.applyRestoredRuntimeProjections();
    }
    const changedStateKeys = Object.keys(draft.slices) as DurableStateSliceKey[];
    const stateBeforePatch = Object.fromEntries(
      changedStateKeys.map(key => [key, stateBefore[key]]),
    ) as DurableStateSlices;
    const statePatch = Object.keys(draft.slices).length > 0
      ? {
          payload_version: 1 as const,
          operation_id: uuidv4(),
          occurred_at: this.ctx.nowIso(),
          reason: changes.reason,
          slices: draft.slices,
        }
      : undefined;
    const scope = this.commitScopePlan(
      plan,
      targetConfig,
      changes.reason,
      sourceFileHash,
      undefined,
      undefined,
      statePatch,
      statePatch ? createHash('sha256').update(canonicalJson(stateBeforePatch)).digest('hex') : undefined,
      statePatch ? createHash('sha256').update(canonicalJson(draft.slices)).digest('hex') : undefined,
    );
    return { scope, result: draft.result };
  }

  private commitScopeUpdate(changes: {
    add_cidrs?: string[];
    remove_cidrs?: string[];
    add_domains?: string[];
    remove_domains?: string[];
    add_exclusions?: string[];
    remove_exclusions?: string[];
    replace_scope?: EngagementConfig['scope'];
    reason: string;
  }): { applied: boolean; errors: string[]; before: EngagementConfig['scope']; after: EngagementConfig['scope']; affected_node_count: number } {
    const plan = planScopeUpdate(this.scopeHost, changes);
    if (plan.errors.length > 0) {
      return {
        applied: false,
        errors: plan.errors,
        before: detached(plan.before),
        after: detached(plan.after),
        affected_node_count: 0,
      };
    }
    if (canonicalJson(plan.before) === canonicalJson(plan.after)) {
      return {
        applied: true,
        errors: [],
        before: detached(plan.before),
        after: detached(plan.after),
        affected_node_count: 0,
      };
    }

    const sourceConfig = this.ctx.config;
    const targetConfig = this.configService.prepareJournalTarget(
      mergeConfig(sourceConfig, { scope: plan.after }),
    );
    const sourceFileHash = this.configService.getStatus().file_hash ?? computeConfigHash(sourceConfig);
    return this.commitScopePlan(plan, targetConfig, changes.reason, sourceFileHash);
  }

  private commitScopePlan(
    plan: ScopeUpdatePlan,
    targetConfig: EngagementConfig,
    reason: string,
    sourceFileHash: string,
    configResolution?: 'use_file',
    supersededConfigIntent?: ConfigIntentConflict,
    statePatch?: DurableStatePatchV1,
    statePatchBeforeSha256?: string,
    statePatchAfterSha256?: string,
  ): { applied: boolean; errors: string[]; before: EngagementConfig['scope']; after: EngagementConfig['scope']; affected_node_count: number } {
    const sourceConfig = this.ctx.config;
    const occurredAt = this.ctx.nowIso();
    const derived = this.planScopeDerivedEffects(plan.promotions, targetConfig, occurredAt);
    const payload: ScopeUpdatedMutationPayloadV1 = {
      payload_version: 1,
      operation_id: uuidv4(),
      occurred_at: occurredAt,
      reason,
      source_config_hash: computeConfigHash(sourceConfig),
      source_file_hash: sourceFileHash,
      target_config: targetConfig,
      before_scope: detached(plan.before),
      after_scope: detached(plan.after),
      promotions: derived.promotions,
      inferred_edges: derived.inferred_edges,
      inference_events: derived.inference_events,
      ...(configResolution ? { config_resolution: configResolution } : {}),
      ...(supersededConfigIntent
        ? { superseded_config_intent: detached(supersededConfigIntent) }
        : {}),
      ...(statePatch
        ? {
            state_patch: statePatch,
            state_patch_before_sha256: statePatchBeforeSha256,
            state_patch_after_sha256: statePatchAfterSha256,
          }
        : {}),
      affected_node_count: plan.affected_node_count,
    };

    try {
      this.ensureCompositeJournal();
      const applied = this.ctx.applyCompositeJournaledMutation(
        'scope_updated',
        payload as unknown as Record<string, unknown>,
        () => this.applyScopeUpdatedMutation(payload, false),
      );
      if (applied.status !== 'applied') throw new Error(applied.reason);
      // The outer sequence is contiguous only after the composite helper
      // returns. Checkpoint it now so acknowledged scope changes need no replay.
      this.persistence.persistImmediate({
        new_nodes: payload.promotions.map(promotion => promotion.hot_node.id),
      });
      this.configService.completeJournalCommit(targetConfig, false);
    } catch (error) {
      this.configService.failJournalCommit(
        `Journaled scope update did not complete durably: ${error instanceof Error ? error.message : String(error)}`,
      );
      throw error;
    }

    return {
      applied: true,
      errors: [],
      before: detached(plan.before),
      after: detached(plan.after),
      affected_node_count: plan.affected_node_count,
    };
  }

  applyScopeUpdatedMutation(
    payload: ScopeUpdatedMutationPayloadV1,
    recovery = true,
  ): MutationApplyResult {
    if (payload.payload_version !== 1) {
      return { status: 'skipped', reason: `unsupported scope_updated payload version: ${String(payload.payload_version)}` };
    }
    const target = engagementConfigSchema.safeParse(payload.target_config);
    if (!target.success || target.data.config_hash !== computeConfigHash(target.data)) {
      return { status: 'skipped', reason: 'scope_updated target config failed schema/hash validation' };
    }
    if (canonicalJson(target.data.scope) !== canonicalJson(payload.after_scope)) {
      return { status: 'skipped', reason: 'scope_updated target config does not match after_scope' };
    }

    const currentHash = computeConfigHash(this.ctx.config);
    const statePatchKeys = payload.state_patch
      ? Object.keys(payload.state_patch.slices) as DurableStateSliceKey[]
      : [];
    if (
      payload.state_patch
      && (
        !payload.state_patch_before_sha256
        || !payload.state_patch_after_sha256
        || !/^[a-f0-9]{64}$/.test(payload.state_patch_before_sha256)
        || !/^[a-f0-9]{64}$/.test(payload.state_patch_after_sha256)
      )
    ) {
      return { status: 'skipped', reason: 'scope_updated state patch is missing valid before/after hashes' };
    }
    const currentStateSlices = payload.state_patch
      ? this.ctx.captureDurableStateSlices(statePatchKeys)
      : {};
    const currentStateHash = createHash('sha256')
      .update(canonicalJson(currentStateSlices))
      .digest('hex');
    const statePatchReady = !payload.state_patch
      || currentStateHash === payload.state_patch_before_sha256;
    const statePatchApplied = !payload.state_patch
      || currentStateHash === payload.state_patch_after_sha256;
    const promotionsBefore = payload.promotions.every(promotion => {
      const cold = this.ctx.coldStore.get(promotion.cold_record.id);
      return !this.ctx.graph.hasNode(promotion.hot_node.id)
        && cold !== undefined
        && canonicalJson(cold) === canonicalJson(promotion.cold_record);
    });
    const promotionsAfter = payload.promotions.every(promotion => {
      if (this.ctx.coldStore.has(promotion.cold_record.id) || !this.ctx.graph.hasNode(promotion.hot_node.id)) return false;
      return canonicalJson(this.identityNodeComparable(this.ctx.graph.getNodeAttributes(promotion.hot_node.id) as NodeProperties))
        === canonicalJson(this.identityNodeComparable(promotion.hot_node));
    });
    const edgesBefore = payload.inferred_edges.every(change => {
      if (!change.before) return !this.ctx.graph.hasEdge(change.edge_id);
      if (!this.ctx.graph.hasEdge(change.edge_id)) return false;
      return canonicalJson({
        edge_id: change.edge_id,
        source: this.ctx.graph.source(change.edge_id),
        target: this.ctx.graph.target(change.edge_id),
        props: this.ctx.graph.getEdgeAttributes(change.edge_id),
      }) === canonicalJson(change.before);
    });
    const edgesAfter = payload.inferred_edges.every(change => {
      if (!this.ctx.graph.hasEdge(change.edge_id)) return false;
      return canonicalJson({
        edge_id: change.edge_id,
        source: this.ctx.graph.source(change.edge_id),
        target: this.ctx.graph.target(change.edge_id),
        props: this.ctx.graph.getEdgeAttributes(change.edge_id),
      }) === canonicalJson(change.after);
    });
    const alreadyApplied = currentHash === target.data.config_hash
      && promotionsAfter
      && edgesAfter
      && statePatchApplied;
    const readyToApply = currentHash === payload.source_config_hash
      && promotionsBefore
      && edgesBefore
      && statePatchReady;
    if (!alreadyApplied && !readyToApply) {
      return {
        status: 'skipped',
        reason: [
          'scope_updated frozen preconditions changed',
          `config=${currentHash === payload.source_config_hash ? 'before' : currentHash === target.data.config_hash ? 'after' : 'different'}`,
          `promotions=${promotionsBefore ? 'before' : promotionsAfter ? 'after' : 'different'}`,
          `edges=${edgesBefore ? 'before' : edgesAfter ? 'after' : 'different'}`,
          `state=${statePatchReady ? 'before' : statePatchApplied ? 'after' : 'different'}`,
          ...(payload.state_patch
            ? [
                `state_hash=${currentStateHash}`,
                `expected_before=${payload.state_patch_before_sha256}`,
                `expected_after=${payload.state_patch_after_sha256}`,
              ]
            : []),
        ].join('; '),
      };
    }

    const graphSnapshot = this.ctx.graph.export();
    const coldSnapshot = detached(this.ctx.coldStore.export());
    const configSnapshot = detached(this.ctx.config);
    const activitySnapshot = detached(this.ctx.activityLog);
    const chainHashSnapshot = this.ctx.lastChainHash;
    const chainCheckpointsSnapshot = detached(this.ctx.chainCheckpoints);
    const chainEventsSnapshot = this.ctx.chainEventsSinceCheckpoint;
    const deterministicSeqSnapshot = this.ctx.deterministicSeq;
    const statePatchSnapshot = payload.state_patch
      ? this.ctx.captureDurableStateSlices(statePatchKeys)
      : undefined;

    try {
      this.ctx.withClock(payload.occurred_at, () => {
        this.configService.installJournalTarget(
          target.data,
          'scope.update',
          recovery,
          payload.source_file_hash,
        );
        if (readyToApply) {
          for (const promotion of [...payload.promotions].sort((a, b) => a.hot_node.id.localeCompare(b.hot_node.id))) {
            const promoted = this.ctx.coldStore.promote(promotion.cold_record.id);
            if (!promoted || canonicalJson(promoted) !== canonicalJson(promotion.cold_record)) {
              throw new Error(`scope_updated cold record changed for ${promotion.cold_record.id}`);
            }
            this.ctx.graph.addNode(promotion.hot_node.id, detached(promotion.hot_node));
          }
          for (const change of payload.inferred_edges) {
            if (change.before && this.ctx.graph.hasEdge(change.edge_id)) this.ctx.graph.dropEdge(change.edge_id);
            const edge = change.after;
            if (!this.ctx.graph.hasNode(edge.source) || !this.ctx.graph.hasNode(edge.target)) {
              throw new Error(`scope_updated inferred edge ${edge.edge_id} has a missing endpoint`);
            }
            this.ctx.graph.addEdgeWithKey(edge.edge_id, edge.source, edge.target, detached(edge.props));
          }
          const postPromotions = payload.promotions.every(promotion =>
            !this.ctx.coldStore.has(promotion.cold_record.id)
            && this.ctx.graph.hasNode(promotion.hot_node.id)
            && canonicalJson(this.identityNodeComparable(this.ctx.graph.getNodeAttributes(promotion.hot_node.id) as NodeProperties))
              === canonicalJson(this.identityNodeComparable(promotion.hot_node)),
          );
          const postEdges = payload.inferred_edges.every(change =>
            this.ctx.graph.hasEdge(change.edge_id)
            && canonicalJson({
              edge_id: change.edge_id,
              source: this.ctx.graph.source(change.edge_id),
              target: this.ctx.graph.target(change.edge_id),
              props: this.ctx.graph.getEdgeAttributes(change.edge_id),
            }) === canonicalJson(change.after),
          );
          if (!postPromotions || !postEdges) {
            throw new Error(`scope_updated did not reach its frozen post-state for operation ${payload.operation_id}`);
          }
          if (payload.state_patch) {
            this.ctx.applyDurableStatePatch(payload.state_patch.slices);
            const appliedStateHash = createHash('sha256')
              .update(canonicalJson(this.ctx.captureDurableStateSlices(statePatchKeys)))
              .digest('hex');
            if (appliedStateHash !== payload.state_patch_after_sha256) {
              throw new Error(`scope_updated did not reach its frozen command state for operation ${payload.operation_id}`);
            }
          }
        }
        for (const [index, event] of payload.inference_events.entries()) {
          const alreadyLogged = this.ctx.activityLog.some(entry =>
            entry.event_type === 'inference_generated'
            && entry.details?.scope_operation_id === payload.operation_id
            && entry.details?.scope_event_index === index,
          );
          if (!alreadyLogged) {
            this.ctx.logEvent({
              description: event.description,
              category: 'inference',
              event_type: 'inference_generated',
              result_classification: 'success',
              target_node_ids: event.target_node_ids,
              details: {
                ...(event.details ?? {}),
                scope_operation_id: payload.operation_id,
                scope_event_index: index,
              },
            });
          }
        }
        if (payload.config_resolution) {
          const resolutionAudited = this.ctx.activityLog.some(entry =>
            entry.event_type === 'config_updated'
            && entry.details?.operation_id === payload.operation_id,
          );
          if (!resolutionAudited) {
            this.ctx.logEvent({
              description: 'Configuration divergence resolved with file authority',
              event_type: 'config_updated',
              category: 'system',
              result_classification: 'success',
              details: {
                operation_id: payload.operation_id,
                resolution: payload.config_resolution,
                config_revision: payload.target_config.config_revision,
                config_hash: payload.target_config.config_hash,
                expected_file_hash: payload.source_file_hash,
                previous_state_hash: payload.source_config_hash,
                target_hash: payload.target_config.config_hash,
                operation_checksum: createHash('sha256')
                  .update(canonicalJson(payload))
                  .digest('hex'),
                ...(payload.superseded_config_intent
                  ? { superseded_config_intent: detached(payload.superseded_config_intent) }
                  : {}),
              },
            });
          }
        }
        const alreadyAudited = this.ctx.activityLog.some(entry =>
          entry.event_type === 'scope_updated'
          && entry.details?.operation_id === payload.operation_id,
        );
        if (!alreadyAudited) {
          this.ctx.logEvent({
            description: `Scope updated: ${payload.reason}`,
            event_type: 'scope_updated',
            category: 'system',
            result_classification: 'success',
            details: {
              operation_id: payload.operation_id,
              reason: payload.reason,
              before: payload.before_scope,
              after: payload.after_scope,
              source_config_hash: payload.source_config_hash,
              source_file_hash: payload.source_file_hash,
              target_config_hash: payload.target_config.config_hash,
              operation_checksum: createHash('sha256')
                .update(canonicalJson(payload))
                .digest('hex'),
              affected_node_count: payload.affected_node_count,
            },
          });
        }
        this.invalidateFrontierCache();
        this.invalidateHealthReport();
        this.invalidatePathGraph();
      });
      return { status: 'applied' };
    } catch (error) {
      this.ctx.graph.clear();
      this.ctx.graph.import(graphSnapshot);
      this.ctx.coldStore.import(coldSnapshot);
      this.ctx.config = configSnapshot;
      this.ctx.activityLog = activitySnapshot;
      this.ctx.lastChainHash = chainHashSnapshot;
      this.ctx.chainCheckpoints = chainCheckpointsSnapshot;
      this.ctx.chainEventsSinceCheckpoint = chainEventsSnapshot;
      this.ctx.deterministicSeq = deterministicSeqSnapshot;
      if (statePatchSnapshot) this.ctx.applyDurableStatePatch(statePatchSnapshot);
      this.invalidateAllCaches();
      this.invalidatePathGraph();
      if (!recovery) throw error;
      return { status: 'skipped', reason: error instanceof Error ? error.message : String(error) };
    }
  }

  private planScopeDerivedEffects(
    promotions: ScopeUpdatedMutationPayloadV1['promotions'],
    targetConfig: EngagementConfig,
    occurredAt: string,
  ): Pick<ScopeUpdatedMutationPayloadV1, 'promotions' | 'inferred_edges' | 'inference_events'> {
    const graph = createGraph();
    graph.import(this.ctx.graph.export());
    const scratch = new EngineContext(
      graph,
      detached(targetConfig),
      `${this.ctx.stateFilePath}.scope-plan-${process.pid}-${uuidv4()}.json`,
    );
    scratch.mutationJournal = null;
    scratch.inferenceRules = detached(this.ctx.inferenceRules);

    for (const promotion of promotions) {
      if (graph.hasNode(promotion.hot_node.id)) {
        graph.replaceNodeAttributes(promotion.hot_node.id, detached(promotion.hot_node));
      } else {
        graph.addNode(promotion.hot_node.id, detached(promotion.hot_node));
      }
    }

    const inferredEdges: ScopeUpdatedMutationPayloadV1['inferred_edges'] = [];
    const inference = new InferenceEngine(
      scratch,
      (source, target, props) => {
        const existing = graph.edges(source, target).find(edgeId =>
          edgeIdentityMatches(graph.getEdgeAttributes(edgeId) as EdgeProperties, props),
        );
        if (existing) return { id: existing, isNew: false };
        const preferred = preferredEdgeKey(source, target, props);
        const edgeId = graph.hasEdge(preferred)
          ? deterministicCollisionEdgeKey(source, target, props)
          : preferred;
        if (graph.hasEdge(edgeId)) throw new Error(`Deterministic scope inference edge collision: ${edgeId}`);
        graph.addDirectedEdgeWithKey(edgeId, source, target, detached(props));
        inferredEdges.push({
          edge_id: edgeId,
          after: { edge_id: edgeId, source, target, props: detached(props) },
        });
        return { id: edgeId, isNew: true };
      },
      id => graph.hasNode(id) ? detached(graph.getNodeAttributes(id) as NodeProperties) : null,
      type => graph.filterNodes((_id, attrs) => attrs.type === type)
        .map(id => detached(graph.getNodeAttributes(id) as NodeProperties)),
      props => {
        if (graph.hasNode(props.id)) graph.replaceNodeAttributes(props.id, detached(props));
        else graph.addNode(props.id, detached(props));
        return props.id;
      },
    );

    scratch.withClock(occurredAt, () => {
      for (const promotion of [...promotions].sort((a, b) => a.hot_node.id.localeCompare(b.hot_node.id))) {
        inference.runRules(promotion.hot_node.id);
      }
    });

    const frozenPromotions = promotions.map(promotion => ({
      cold_record: detached(promotion.cold_record),
      hot_node: detached(graph.getNodeAttributes(promotion.hot_node.id) as NodeProperties),
    }));
    const inferenceEvents = scratch.activityLog
      .filter(entry => entry.event_type === 'inference_generated')
      .map(entry => ({
        description: entry.description,
        target_node_ids: entry.target_node_ids ? detached(entry.target_node_ids) : undefined,
        details: entry.details ? detached(entry.details) : undefined,
      }));
    return {
      promotions: frozenPromotions,
      inferred_edges: inferredEdges,
      inference_events: inferenceEvents,
    };
  }

  prepareRecoveryCommit(): void {
    this.configService.prepareJournalReplayCommit();
  }

  completeRecoveryCommit(): void {
    this.configService.completeJournalReplayCommit();
  }

  abortRecoveryReplay(): void {
    this.configService.abortJournalReplay();
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

  previewScopeConfig(scope: EngagementConfig['scope']): {
    before: EngagementConfig['scope'];
    after: EngagementConfig['scope'];
    nodes_entering_scope: number;
    nodes_leaving_scope: number;
    pending_suggestions_resolved: string[];
    affected_node_count: number;
  } {
    const plan = planScopeUpdate(this.scopeHost, {
      replace_scope: scope,
      reason: 'scope replacement preview',
    });
    if (plan.errors.length > 0) {
      const error = new Error(plan.errors.join('; '));
      (error as Error & { code: string }).code = 'SCOPE_VALIDATION_FAILED';
      throw error;
    }
    const diff = (next: string[], current: string[]) => ({
      add: next.filter(value => !current.includes(value)),
      remove: current.filter(value => !next.includes(value)),
    });
    const cidrs = diff(plan.after.cidrs, plan.before.cidrs);
    const domains = diff(plan.after.domains, plan.before.domains);
    const exclusions = diff(plan.after.exclusions, plan.before.exclusions);
    const network = this.previewScopeChange({
      add_cidrs: cidrs.add,
      remove_cidrs: cidrs.remove,
      add_domains: domains.add,
      remove_domains: domains.remove,
      add_exclusions: exclusions.add,
      remove_exclusions: exclusions.remove,
    });
    return {
      ...network,
      before: detached(plan.before),
      after: detached(plan.after),
      affected_node_count: plan.affected_node_count,
    };
  }

  // =============================================
  // Persistence (delegated to StatePersistence)
  // =============================================

  persist(detail: GraphUpdateDetail = {}): void {
    if (this.ctx.isDraftingTransaction()) return;
    // Callers (addNode, addEdge, dropEdge, patchNodeProperties) already
    // invalidate the appropriate caches before calling persist.
    this.persistence.persist(detail);
  }

  private transactDurableSlices<T>(
    reason: string,
    keys: readonly DurableStateSliceKey[],
    mutate: () => T,
    detail: GraphUpdateDetail = {},
    includeUnchangedKeys: readonly DurableStateSliceKey[] = [],
  ): T {
    if (this.ctx.isDraftingTransaction()) return mutate();
    const baseline = this.ctx.captureDurableStateSlices(keys);
    let draft!: { result: T; slices: DurableStatePatchV1['slices'] };
    try {
      draft = this.ctx.draftDurableStateSlices(keys, mutate);
    } finally {
      // CampaignPlanner owns derived reverse indexes outside EngineContext.
      // Draft mutations may have changed them, so restore the live baseline
      // indexes even when draft construction throws.
      this.applyRestoredRuntimeProjections();
    }
    const slices = { ...draft.slices };
    for (const key of includeUnchangedKeys) {
      if (slices[key] === undefined && baseline[key] !== undefined) {
        slices[key] = baseline[key];
      }
    }
    if (Object.keys(slices).length === 0) return draft.result;
    const payload: DurableStatePatchV1 = {
      payload_version: 1,
      operation_id: uuidv4(),
      occurred_at: this.ctx.nowIso(),
      reason,
      slices,
    };
    try {
      this.ctx.applyEngineTransaction(
        {
          operations: [{
            type: 'state_patch',
            payload: payload as unknown as Record<string, unknown>,
          }],
          update_detail: detail,
        },
        () => this.applyStatePatchMutation(payload, false),
        'state patch',
      );
    } catch (error) {
      // The transaction is already durable and the engine is fail-stopped by
      // EngineContext. Restore the selected live slices so callers cannot
      // observe a partially-applied after-state while recovery is required.
      this.ctx.applyDurableStatePatch(baseline);
      this.applyRestoredRuntimeProjections();
      this.invalidateAllCaches();
      throw error;
    }
    this.persist(detail);
    return draft.result;
  }

  applyStatePatchMutation(
    payload: DurableStatePatchV1,
    _recovery = true,
  ): MutationApplyResult {
    if (payload.payload_version !== 1) {
      return {
        status: 'skipped',
        reason: `unsupported state_patch payload version: ${String(payload.payload_version)}`,
      };
    }
    this.ctx.applyDurableStatePatch(payload.slices);
    this.campaignPlanner.reindex();
    this.frontierComputer.resetWeightsToDefaults();
    if (this.ctx.frontierWeights) {
      this.frontierComputer.setFanOutEstimates(this.ctx.frontierWeights.fan_out);
      this.frontierComputer.setNoiseEstimates(this.ctx.frontierWeights.noise);
    }
    this.invalidateAllCaches();
    return { status: 'applied' };
  }

  /**
   * Execute a batch of mutations with a single coalesced persist at the end.
   * All persist() calls within `fn` are suppressed until the batch completes.
   * Batches can nest — only the outermost triggers the flush.
   */
  batchMutate(fn: () => void): void {
    this.assertPersistenceWritable();
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
    this.assertPersistenceWritable();
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
    if (this.ctx.isDraftingTransaction()) return;
    this.persistence.flushNow();
  }

  /** Immediately write a snapshot regardless of the dirty flag. Reserved for
   * explicit synchronization points and legacy bootstrap boundaries; composite
   * identity and graph-correction mutations are durable through the WAL. */
  persistImmediate(detail?: GraphUpdateDetail): void {
    this.persistence.persistImmediate(detail);
  }

  /**
   * Returns persistence performance metrics for observability.
   */
  getPersistMetrics(): import('./state-persistence.js').PersistMetrics {
    return this.persistence.getMetrics();
  }

  /** Per-boot persistence recovery state used by MCP, dashboard, preflight,
   *  and CLI read surfaces.  It is intentionally not itself persisted. */
  getPersistenceRecoveryStatus(): PersistenceRecoveryStatus {
    const persistence = this.persistence.getRecoveryStatus();
    const coordination_warnings = detached(this.ctx.coordinationRecoveryWarnings);
    const coordinationFields = coordination_warnings.length > 0
      ? { coordination_warnings }
      : {};
    const runtimeWarningRuns = this.ctx.runtimeRuns
      .filter(run =>
        run.lifecycle === 'unknown'
        && typeof run.recovery_warning === 'string'
        && run.recovery_warning.length > 0)
      .map(run => ({
        run_id: run.run_id,
        pid: run.pid,
        lifecycle: run.lifecycle,
        message: run.recovery_warning!,
      }));
    if (!this.isPersistenceWritable()) {
      for (const run of this.ctx.runtimeRuns) {
        if (run.lifecycle !== 'reserved' && run.lifecycle !== 'running') continue;
        if (runtimeWarningRuns.some(warning => warning.run_id === run.run_id)) continue;
        runtimeWarningRuns.push({
          run_id: run.run_id,
          pid: run.pid,
          lifecycle: run.lifecycle,
          message: 'Runtime ownership reconciliation is deferred while durable state is read-only.',
        });
      }
    }
    const runtime_ownership_warnings = runtimeWarningRuns;
    const runtimeOwnershipFields = runtime_ownership_warnings.length > 0
      ? { runtime_ownership_warnings: detached(runtime_ownership_warnings) }
      : {};
    const state_recovery = {
      outcome: persistence.outcome,
      source: persistence.source,
      complete: persistence.complete,
      writable: persistence.writable,
      ...(persistence.reason ? { reason: persistence.reason } : {}),
      highest_allocated_logical_seq:
        persistence.highest_allocated_logical_seq ?? persistence.highest_allocated_seq,
      ...(persistence.highest_allocated_frame_seq !== undefined
        ? { highest_allocated_frame_seq: persistence.highest_allocated_frame_seq }
        : {}),
      ...(persistence.highest_physical_frame_seq !== undefined
        ? { highest_physical_frame_seq: persistence.highest_physical_frame_seq }
        : {}),
      highest_contiguous_applied_logical_seq:
        persistence.highest_contiguous_applied_logical_seq
        ?? persistence.highest_contiguous_applied_seq,
    };
    const configRecovery = this.configService.getStatus();
    if (!configRecovery.resolution_required && this.startupReconciliationDeferred) {
      const deferredReason = this.deferredStartupRecoveryError
        ?? 'Startup lifecycle reconciliation is incomplete after configuration recovery.';
      const persistenceBlocked = !persistence.complete || !persistence.writable;
      return {
        ...persistence,
        ...coordinationFields,
        ...runtimeOwnershipFields,
        outcome: 'incomplete',
        complete: false,
        writable: false,
        reason: deferredReason,
        ...(persistenceBlocked
          ? { persistence_reason: persistence.reason ?? deferredReason }
          : {}),
        state_recovery,
        config_recovery: configRecovery,
      };
    }
    if (!configRecovery.resolution_required) {
      return {
        ...persistence,
        ...coordinationFields,
        ...runtimeOwnershipFields,
        state_recovery,
        config_recovery: configRecovery,
      };
    }
    const persistenceBlocked = !persistence.complete || !persistence.writable;
    const configReason = configRecovery.reason ?? 'configuration reconciliation is required';
    const reasons = [persistenceBlocked ? persistence.reason : undefined, configReason]
      .filter((reason): reason is string => Boolean(reason));
    return {
      ...persistence,
      ...coordinationFields,
      ...runtimeOwnershipFields,
      outcome: 'incomplete',
      complete: false,
      writable: false,
      reason: [...new Set(reasons)].join('; '),
      ...(persistenceBlocked && persistence.reason ? { persistence_reason: persistence.reason } : {}),
      state_recovery,
      config_recovery: configRecovery,
    };
  }

  /** Raw state/WAL recovery, excluding configuration and deferred startup
   * gates. Internal readiness checks use this to avoid reporting one config
   * divergence as two independent failures. */
  getStatePersistenceRecoveryStatus(): PersistenceRecoveryStatus {
    return this.persistence.getRecoveryStatus();
  }

  getConfigRecoveryStatus(): ConfigRecoveryStatus {
    return detached(this.configService.getStatus());
  }

  resolveConfigDivergence(input: ResolveConfigDivergenceInput): ResolveConfigDivergenceResult {
    // Config reconciliation is the sole mutation allowed past a config-only
    // gate. It may never bypass an incomplete WAL/state recovery.
    this.persistence.assertWritable();
    this.recoveryMaintenanceInProgress = true;
    try {
      const prepared = this.configService.prepareResolution(input);
      let result: ResolveConfigDivergenceResult;
      if (
        prepared.mode === 'use_file'
        && canonicalJson(prepared.config.scope) !== canonicalJson(this.ctx.config.scope)
      ) {
        const plan = planScopeUpdate(this.scopeHost, {
          replace_scope: prepared.config.scope,
          reason: 'Configuration reconciliation applied file scope',
        });
        if (plan.errors.length > 0) {
          throw new Error(`The file-authoritative scope is invalid: ${plan.errors.join('; ')}`);
        }
        result = this.configService.applyPreparedResolution(prepared, target => {
          this.commitScopePlan(
            plan,
            target,
            'Configuration reconciliation applied file scope',
            prepared.expected_file_hash,
            'use_file',
            prepared.intent_conflict,
          );
          return this.getConfig();
        });
      } else {
        result = this.configService.commitPreparedResolution(prepared);
      }
      this.resumeDeferredStartupReconciliation();
      return result;
    } catch (error) {
      if (!this.configService.isBlocked() && this.startupReconciliationDeferred) {
        this.deferredStartupRecoveryError =
          `Configuration was reconciled, but startup lifecycle recovery did not complete: ${error instanceof Error ? error.message : String(error)}`;
      }
      throw error;
    } finally {
      this.recoveryMaintenanceInProgress = false;
    }
  }

  resolveConfigDivergenceApplicationCommand(
    input: ResolveConfigDivergenceInput,
    buildCommand: (
      result: ResolveConfigDivergenceResult,
    ) => PersistedApplicationCommandV1,
  ): {
    result: ResolveConfigDivergenceResult;
    command: PersistedApplicationCommandV1;
  } {
    this.persistence.assertWritable();
    this.recoveryMaintenanceInProgress = true;
    try {
      const prepared = this.configService.prepareResolution(input);
      const expected = this.configService.previewPreparedResolution(prepared);
      const command = detached(buildCommand(expected));
      if (command.status !== 'succeeded') {
        throw new Error(
          'A recovery application command must be terminal before it is committed.',
        );
      }
      let result: ResolveConfigDivergenceResult;
      if (
        prepared.mode === 'use_file'
        && canonicalJson(prepared.config.scope)
          !== canonicalJson(this.ctx.config.scope)
      ) {
        const plan = planScopeUpdate(this.scopeHost, {
          replace_scope: prepared.config.scope,
          reason: 'Configuration reconciliation applied file scope',
        });
        if (plan.errors.length > 0) {
          throw new Error(
            `The file-authoritative scope is invalid: ${plan.errors.join('; ')}`,
          );
        }
        result = this.configService.applyPreparedResolution(
          prepared,
          target => {
            const stateKeys = ['command_state'] as const;
            const stateBefore = this.ctx.captureDurableStateSlices(stateKeys);
            let draft!: {
              result: PersistedApplicationCommandV1;
              slices: DurableStatePatchV1['slices'];
            };
            try {
              draft = this.ctx.draftDurableStateSlices(
                stateKeys,
                () => this.installApplicationCommandDraft(command),
              );
            } finally {
              this.applyRestoredRuntimeProjections();
            }
            const changedStateKeys = Object.keys(
              draft.slices,
            ) as DurableStateSliceKey[];
            const stateBeforePatch = Object.fromEntries(
              changedStateKeys.map(key => [key, stateBefore[key]]),
            ) as DurableStateSlices;
            const statePatch: DurableStatePatchV1 = {
              payload_version: 1,
              operation_id: uuidv4(),
              occurred_at: this.ctx.nowIso(),
              reason: 'Configuration reconciliation applied file scope',
              slices: draft.slices,
            };
            this.commitScopePlan(
              plan,
              target,
              'Configuration reconciliation applied file scope',
              prepared.expected_file_hash,
              'use_file',
              prepared.intent_conflict,
              statePatch,
              createHash('sha256')
                .update(canonicalJson(stateBeforePatch))
                .digest('hex'),
              createHash('sha256')
                .update(canonicalJson(draft.slices))
                .digest('hex'),
            );
            return this.getConfig();
          },
        );
      } else {
        result = this.configService.commitPreparedResolution(
          prepared,
          command,
        );
      }
      if (canonicalJson(result) !== canonicalJson(expected)) {
        throw new Error(
          'Configuration reconciliation response differed from its command intent.',
        );
      }
      this.resumeDeferredStartupReconciliation();
      return { result, command };
    } catch (error) {
      if (
        !this.configService.isBlocked()
        && this.startupReconciliationDeferred
      ) {
        this.deferredStartupRecoveryError =
          `Configuration was reconciled, but startup lifecycle recovery did not complete: ${error instanceof Error ? error.message : String(error)}`;
      }
      throw error;
    } finally {
      this.recoveryMaintenanceInProgress = false;
    }
  }

  /**
   * Retry the post-config startup lifecycle without recommitting config or
   * creating another recovery command. Safe to call for an already-complete
   * recovery replay.
   */
  resumeDeferredStartupReconciliation(): void {
    this.persistence.assertWritable();
    if (this.configService.isBlocked()) {
      throw new Error(
        'Configuration must be reconciled before startup lifecycle recovery can resume.',
      );
    }
    this.recoveryMaintenanceInProgress = true;
    try {
      if (this.startupReconciliationDeferred) {
        this.evaluateObjectives();
        this.reconcileSessionEdgesOnStartup();
        this.reconcileSessionDescriptorsOnStartup();
        this.reconcileAgentsOnStartup();
        this.reconcilePendingApprovalsOnStartup();
        this.runtimeOwnershipRecoveryHandler?.();
        this.persistence.persistImmediate();
        this.runAutoHealthCheck('configuration recovery startup reconciliation');
        this.warnIfOpsecInert();
        this.startupReconciliationDeferred = false;
        this.deferredStartupRecoveryError = undefined;
      }
      this.evidenceStore.enableWrites();
    } catch (error) {
      if (this.startupReconciliationDeferred) {
        this.deferredStartupRecoveryError =
          `Configuration was reconciled, but startup lifecycle recovery did not complete: ${error instanceof Error ? error.message : String(error)}`;
      }
      throw error;
    } finally {
      this.recoveryMaintenanceInProgress = false;
    }
  }

  setRuntimeOwnershipRecoveryHandler(handler: (() => void) | undefined): void {
    this.runtimeOwnershipRecoveryHandler = handler;
  }

  /** Whether the WAL/state persistence owner itself remains writable. */
  isStatePersistenceWritable(): boolean {
    return this.persistence.isWritable();
  }

  /** Whether a new durable mutation may be accepted right now. */
  isPersistenceWritable(): boolean {
    return this.persistence.isWritable()
      && !this.configService.isBlocked()
      && (!this.startupReconciliationDeferred || this.recoveryMaintenanceInProgress);
  }

  assertPersistenceWritable(): void {
    this.persistence.assertWritable();
    this.configService.assertWritable();
    if (this.startupReconciliationDeferred && !this.recoveryMaintenanceInProgress) {
      throw new Error(
        this.deferredStartupRecoveryError
          ?? 'Startup lifecycle recovery is incomplete; restart before accepting durable mutations.',
      );
    }
  }

  /**
   * Tear down timers and process listeners.
   * Call during graceful shutdown or in tests to avoid leaked state.
   */
  dispose(): void {
    for (const unsubscribe of this.coordinationStoreUnsubscribers.splice(0)) {
      unsubscribe();
    }
    this.ctx.proposedPlanStore.setMutationGuard(undefined);
    this.ctx.agentQueryStore.setMutationGuard(undefined);
    this.rollbackCoordinator = undefined;
    this.persistence.dispose();
    // Cancel approval timers + settle any outstanding approval promises so a
    // blocked tool call can't hang past daemon shutdown.
    this.ctx.pendingActionQueue.dispose();
  }

  // =============================================
  // OPSEC Tracker
  // =============================================

  recordOpsecNoise(opts: { action_id?: string; host_id?: string; domain?: string; campaign_id?: string; agent_id?: string; frontier_item_id?: string; noise_estimate: number; noise_actual?: number }): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'record OPSEC noise',
        ['opsec'],
        () => this.recordOpsecNoise(opts),
      );
      return;
    }
    this.assertPersistenceWritable();
    // Per-campaign noise aggregation: callers in the action lifecycle carry an
    // agent_id and/or frontier_item_id but not the campaign directly. Resolve
    // it here (one place) so the tracker can attribute noise to a campaign for
    // the operator's per-campaign OPSEC meter. Explicit campaign_id wins.
    const campaign_id = opts.campaign_id ?? this.resolveNoiseCampaignId(opts.frontier_item_id, opts.agent_id);
    this.ctx.opsecTracker.recordNoise({
      action_id: opts.action_id,
      host_id: opts.host_id,
      domain: opts.domain,
      campaign_id,
      noise_estimate: opts.noise_estimate,
      noise_actual: opts.noise_actual,
    });
  }

  /** Resolve campaign ownership by frontier item or an exact/unique task
   * reference. Duplicate legacy labels are deliberately left unattributed. */
  private resolveNoiseCampaignId(frontier_item_id?: string, agent_id?: string): string | undefined {
    if (frontier_item_id) {
      const task = this.getRunningTaskForFrontierItem(frontier_item_id);
      if (task?.campaign_id) return task.campaign_id;
    }
    if (agent_id) {
      const resolution = this.agentMgr.resolveTaskReference(agent_id);
      if (resolution.status === 'exact' || resolution.status === 'unique_legacy_label') {
        return resolution.task.campaign_id;
      }
    }
    return undefined;
  }

  recordDefensiveSignal(signal: import('./opsec-tracker.js').DefensiveSignal): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'record defensive signal',
        ['opsec'],
        () => this.recordDefensiveSignal(signal),
      );
      return;
    }
    this.assertPersistenceWritable();
    this.ctx.opsecTracker.recordDefensiveSignal(signal);
  }

  getOpsecContext(opts?: { host_id?: string; domain?: string; campaign_id?: string }): OpsecContext {
    return this.ctx.opsecTracker.getNoiseContext(opts);
  }

  getOpsecTracker(): import('./opsec-tracker.js').OpsecTracker {
    return this.ctx.opsecTracker;
  }

  /** Signed/unsigned chain checkpoints emitted so far (for verification). */
  getChainCheckpoints(): import('./activity-chain.js').ChainCheckpoint[] {
    return this.ctx.chainCheckpoints;
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

  /** 3A.2: planner-proposed plans awaiting operator confirmation. */
  getProposedPlanStore(): import('./proposed-plan-store.js').ProposedPlanStore {
    return this.ctx.proposedPlanStore;
  }

  /** 3D: agent→operator questions awaiting an answer. */
  getAgentQueryStore(): import('./agent-query-store.js').AgentQueryStore {
    return this.ctx.agentQueryStore;
  }

  private pruneCommandCoordination(now?: number): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'prune command coordination',
        ['command_state'],
        () => this.pruneCommandCoordination(now),
      );
      return;
    }
    const effectiveNow = now ?? Date.parse(this.ctx.nowIso());
    const expiredPlans = [...this.ctx.commandPlans.entries()]
      .filter(([, plan]) => plan.expires_at <= effectiveNow)
      .map(([id]) => id);
    const expiredOutcomes = [...this.ctx.commandOutcomes.entries()]
      .filter(([, outcome]) => outcome.expires_at <= effectiveNow)
      .map(([id]) => id);
    if (expiredPlans.length === 0 && expiredOutcomes.length === 0) return;
    this.assertPersistenceWritable();
    for (const id of expiredPlans) this.ctx.commandPlans.delete(id);
    for (const id of expiredOutcomes) this.ctx.commandOutcomes.delete(id);
    this.persist();
  }

  createCommandPlan(input: {
    ops: OperatorOp[];
    command: string;
    now?: number;
    ttlMs?: number;
  }): string {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'create command plan',
        ['command_state'],
        () => this.createCommandPlan(input),
      );
    }
    this.assertPersistenceWritable();
    const now = input.now ?? Date.parse(this.ctx.nowIso());
    this.pruneCommandCoordination(now);
    const planId = uuidv4();
    this.ctx.commandPlans.set(planId, {
      ops: detached(input.ops),
      command: input.command,
      created_at: now,
      expires_at: now + (input.ttlMs ?? 10 * 60_000),
    });
    this.persist();
    return planId;
  }

  getCommandPlan(
    planId: string,
    now?: number,
  ): Omit<PersistedCommandPlanV1, 'plan_id'> | undefined {
    const effectiveNow = now ?? Date.parse(this.ctx.nowIso());
    if (this.isPersistenceWritable()) this.pruneCommandCoordination(effectiveNow);
    const plan = this.ctx.commandPlans.get(planId);
    return plan && plan.expires_at > effectiveNow ? detached(plan) : undefined;
  }

  deleteCommandPlan(planId: string): boolean {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'delete command plan',
        ['command_state'],
        () => this.deleteCommandPlan(planId),
      );
    }
    this.assertPersistenceWritable();
    const deleted = this.ctx.commandPlans.delete(planId);
    if (deleted) this.persist();
    return deleted;
  }

  recordCommandOutcome(
    planId: string,
    results: unknown[],
    now?: number,
    ttlMs: number = 10 * 60_000,
  ): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'record command outcome',
        ['command_state'],
        () => this.recordCommandOutcome(planId, results, now, ttlMs),
      );
      return;
    }
    this.assertPersistenceWritable();
    const effectiveNow = now ?? Date.parse(this.ctx.nowIso());
    this.pruneCommandCoordination(effectiveNow);
    this.ctx.commandOutcomes.set(planId, {
      at: effectiveNow,
      expires_at: effectiveNow + ttlMs,
      results: detached(results),
    });
    this.persist();
  }

  getCommandOutcome(
    planId: string,
    now?: number,
  ): Omit<PersistedCommandOutcomeV1, 'plan_id'> | undefined {
    const effectiveNow = now ?? Date.parse(this.ctx.nowIso());
    if (this.isPersistenceWritable()) this.pruneCommandCoordination(effectiveNow);
    const outcome = this.ctx.commandOutcomes.get(planId);
    return outcome && outcome.expires_at > effectiveNow ? detached(outcome) : undefined;
  }

  getApplicationCommand(idempotencyKey: string): PersistedApplicationCommandV1 | undefined {
    const command = this.ctx.applicationCommands.get(idempotencyKey);
    return command ? detached(command) : undefined;
  }

  getApplicationCommandById(commandId: string): PersistedApplicationCommandV1 | undefined {
    for (const command of this.ctx.applicationCommands.values()) {
      if (command.command_id === commandId) return detached(command);
    }
    return undefined;
  }

  listApplicationCommands(): PersistedApplicationCommandV1[] {
    return [...this.ctx.applicationCommands.values()].map(command => detached(command));
  }

  recordApplicationCommand(
    command: PersistedApplicationCommandV1,
  ): PersistedApplicationCommandV1 {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        `record application command ${command.command_kind}`,
        ['command_state'],
        () => this.recordApplicationCommand(command),
      );
    }
    this.assertPersistenceWritable();
    if (!command.idempotency_key.trim()) {
      throw new Error('Application command idempotency_key must not be empty.');
    }
    if (!command.command_id.trim()) {
      throw new Error('Application command command_id must not be empty.');
    }
    const duplicateCommandId = [...this.ctx.applicationCommands.entries()]
      .find(([idempotencyKey, existing]) =>
        idempotencyKey !== command.idempotency_key
        && existing.command_id === command.command_id);
    if (duplicateCommandId) {
      const error = new Error(
        `Application command command_id ${command.command_id} is already bound to ${duplicateCommandId[0]}.`,
      );
      (error as Error & { code: string }).code = 'COMMAND_ID_CONFLICT';
      throw error;
    }
    this.ctx.applicationCommands.set(command.idempotency_key, detached(command));
    this.persist();
    return detached(command);
  }

  /** Install command state while an already-authorized composite/config
   * transaction is drafting its absolute after-state. This deliberately skips
   * the config-convergence half of the public write gate: recovery and scope
   * transactions establish their own durable authority before applying the
   * draft. */
  private installApplicationCommandDraft(
    command: PersistedApplicationCommandV1,
  ): PersistedApplicationCommandV1 {
    if (!this.ctx.isDraftingTransaction()) {
      throw new Error(
        'Application command draft installation requires an active transaction draft.',
      );
    }
    if (!command.idempotency_key.trim()) {
      throw new Error(
        'Application command idempotency_key must not be empty.',
      );
    }
    if (!command.command_id.trim()) {
      throw new Error('Application command command_id must not be empty.');
    }
    const duplicateCommandId = [...this.ctx.applicationCommands.entries()]
      .find(([idempotencyKey, existing]) =>
        idempotencyKey !== command.idempotency_key
        && existing.command_id === command.command_id);
    if (duplicateCommandId) {
      const error = new Error(
        `Application command command_id ${command.command_id} is already bound to ${duplicateCommandId[0]}.`,
      );
      (error as Error & { code: string }).code = 'COMMAND_ID_CONFLICT';
      throw error;
    }
    this.ctx.applicationCommands.set(
      command.idempotency_key,
      detached(command),
    );
    return detached(command);
  }

  deleteApplicationCommand(idempotencyKey: string): boolean {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'delete application command',
        ['command_state'],
        () => this.deleteApplicationCommand(idempotencyKey),
      );
    }
    this.assertPersistenceWritable();
    const deleted = this.ctx.applicationCommands.delete(idempotencyKey);
    if (deleted) this.persist();
    return deleted;
  }

  runApplicationCommandTransaction<T>(
    reason: string,
    sourceActionId: string | undefined,
    mutation: () => T,
    additionalStateKeys: readonly DurableStateSliceKey[] = [],
  ): T {
    return this.runAtomicGraphCommand(
      reason,
      sourceActionId,
      mutation,
      [...new Set<DurableStateSliceKey>(['command_state', ...additionalStateKeys])],
    );
  }

  getSessionDescriptors(): PersistedSessionDescriptorV1[] {
    return detached(this.ctx.sessionDescriptors);
  }

  recordSessionDescriptor(metadata: SessionMetadata): PersistedSessionDescriptorV1 {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'record session descriptor',
        ['agents', 'session_descriptors'],
        () => this.recordSessionDescriptor(metadata),
      );
    }
    this.assertPersistenceWritable();
    if (metadata.id.length === 0) throw new Error('Session id must not be empty.');
    if (metadata.transport.length === 0) throw new Error('Session transport must not be empty.');
    if (
      metadata.connection_generation !== undefined
      && (
        !Number.isSafeInteger(metadata.connection_generation)
        || metadata.connection_generation < 0
      )
    ) {
      throw new Error('Session connection_generation must be a non-negative safe integer.');
    }
    if (
      metadata.port !== undefined
      && (
        !Number.isSafeInteger(metadata.port)
        || metadata.port < 0
        || metadata.port > 65_535
      )
    ) {
      throw new Error('Session port must be an integer from 0 through 65535.');
    }
    const nonEmpty = (value: string | undefined): string | undefined =>
      value !== undefined && value.length > 0 ? value : undefined;
    let defaultValidation: SessionDefaultValidation | undefined;
    if (metadata.default_validation) {
      if (metadata.default_validation.technique.length === 0) {
        throw new Error('Session default_validation.technique must not be empty.');
      }
      defaultValidation = {
        ...detached(metadata.default_validation),
        target_ip: nonEmpty(metadata.default_validation.target_ip),
        target_url: nonEmpty(metadata.default_validation.target_url),
        target_node: nonEmpty(metadata.default_validation.target_node),
        agent_id: nonEmpty(metadata.default_validation.agent_id),
      };
    }
    const recordedAt = this.ctx.nowIso();
    const prior = this.ctx.sessionDescriptors.find(entry => entry.session_id === metadata.id);
    const ownerReference = nonEmpty(metadata.claimed_by) ?? nonEmpty(metadata.agent_id);
    const ownerResolution = ownerReference
      ? this.agentMgr.resolveTaskReference(ownerReference)
      : { status: 'missing' as const };
    const ownerTask = ownerResolution.status === 'exact'
      || ownerResolution.status === 'unique_legacy_label'
      ? ownerResolution.task
      : undefined;
    let recoveryWarning: string | undefined;
    if (ownerReference && ownerResolution.status === 'ambiguous_legacy_label') {
      const warning = coordinationRecoveryWarning({
        relationship: `session:${metadata.id}`,
        reference: ownerReference,
        candidate_task_ids: ownerResolution.candidate_task_ids,
        payload: metadata,
      });
      this.ctx.coordinationRecoveryWarnings = mergeCoordinationRecoveryWarnings(
        this.ctx.coordinationRecoveryWarnings,
        [warning],
      );
      recoveryWarning = warning.message;
    }
    const resumableListener = metadata.kind === 'socket'
      && metadata.mode === 'listen'
      && metadata.accept_mode === 'rearm'
      && (
        metadata.state === 'pending'
        || metadata.state === 'connected'
        || metadata.state === 'resume_available'
      );
    const descriptor: PersistedSessionDescriptorV1 = {
      session_id: metadata.id,
      kind: metadata.kind,
      adapter: metadata.adapter ?? metadata.kind,
      transport: metadata.transport,
      ...persistedSessionLifecycle(metadata.state),
      listener_id: nonEmpty(metadata.listener_id),
      connection_generation: metadata.connection_generation ?? 0,
      connection_id: nonEmpty(metadata.connection_id),
      connection_started_at: metadata.connection_started_at,
      last_connection_id: nonEmpty(metadata.last_connection_id),
      last_connection_state: metadata.last_connection_state,
      last_connection_closed_at: metadata.last_connection_closed_at,
      mode: metadata.mode,
      bind_host: nonEmpty(metadata.bind_host),
      advertise_host: nonEmpty(metadata.advertise_host),
      accept_mode: metadata.accept_mode,
      reachability_warnings: metadata.reachability_warnings,
      auth_status: metadata.auth_status,
      title: metadata.title,
      host: nonEmpty(metadata.host),
      user: nonEmpty(metadata.user),
      port: metadata.port,
      owner_task_id: ownerTask ? taskIdOf(ownerTask) : undefined,
      ...(recoveryWarning ? { recovery_warning: recoveryWarning } : {}),
      target_node: nonEmpty(metadata.target_node),
      principal_node: nonEmpty(metadata.principal_node),
      credential_node: nonEmpty(metadata.credential_node),
      action_id: nonEmpty(metadata.action_id),
      frontier_item_id: nonEmpty(metadata.frontier_item_id),
      started_at: metadata.started_at,
      last_activity_at: metadata.last_activity_at,
      closed_at: metadata.closed_at,
      capabilities: detached(metadata.capabilities),
      notes: metadata.notes,
      default_validation: defaultValidation,
      resume_intent: resumableListener
        ? {
            policy: 'manual',
            requested: true,
            prior_state: metadata.state === 'connected'
              ? 'connected'
              : metadata.state === 'resume_available'
                ? prior?.resume_intent.prior_state
                  ?? (metadata.last_connection_id ? 'connected' : 'pending')
                : 'pending',
            ...(metadata.state === 'resume_available'
              ? { recovery_prior_state: 'resume_available' as const }
              : {}),
            recorded_at: recordedAt,
          }
        : prior?.resume_intent.requested
          && metadata.state !== 'closed'
          && metadata.state !== 'interrupted'
          ? detached(prior.resume_intent)
          : {
              policy: 'none',
              requested: false,
              recorded_at: recordedAt,
            },
    };
    const index = this.ctx.sessionDescriptors.findIndex(
      entry => entry.session_id === descriptor.session_id,
    );
    if (index >= 0) this.ctx.sessionDescriptors[index] = descriptor;
    else this.ctx.sessionDescriptors.push(descriptor);
    this.persist();
    return detached(descriptor);
  }

  setRuntimeRuns(runs: PersistedRuntimeRunV1[]): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'replace runtime runs',
        ['runtime_runs'],
        () => this.setRuntimeRuns(runs),
      );
      return;
    }
    this.assertPersistenceWritable();
    this.ctx.runtimeRuns = detached(runs);
    this.persist();
  }

  getRuntimeRuns(): PersistedRuntimeRunV1[] {
    return detached(this.ctx.runtimeRuns);
  }

  private pruneTerminalRuntimeRuns(): void {
    const terminal = this.ctx.runtimeRuns
      .filter(run =>
        run.lifecycle === 'completed'
        || run.lifecycle === 'failed'
        || run.lifecycle === 'interrupted'
        || run.lifecycle === 'unknown')
      .sort((left, right) =>
        (left.completed_at ?? left.started_at)
          .localeCompare(right.completed_at ?? right.started_at));
    if (terminal.length <= MAX_TERMINAL_RUNTIME_RUNS) return;
    const remove = new Set(
      terminal
        .slice(0, terminal.length - MAX_TERMINAL_RUNTIME_RUNS)
        .map(run => run.run_id),
    );
    this.ctx.runtimeRuns = this.ctx.runtimeRuns.filter(run => !remove.has(run.run_id));
  }

  beginRuntimeAction(input: {
    run: {
      run_id: string;
      kind: PersistedRuntimeRunV1['kind'];
      task_id?: string;
      action_id?: string;
      agent_id?: string;
      daemon_owner: string;
      command_fingerprint: string;
      ownership_mode?: PersistedRuntimeRunV1['ownership_mode'];
      signal_scope?: PersistedRuntimeRunV1['signal_scope'];
      evidence_state?: PersistedRuntimeRunV1['evidence_state'];
      action_started_event_id?: string;
      started_at?: string;
    };
    event: ActivityLogInput;
    noise?: {
      action_id?: string;
      host_id?: string;
      domain?: string;
      campaign_id?: string;
      agent_id?: string;
      frontier_item_id?: string;
      noise_estimate: number;
      noise_actual?: number;
    };
  }): { run: PersistedRuntimeRunV1; event: ActivityLogEntry } {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'begin managed runtime action',
        ['runtime_runs', 'activity', 'opsec'],
        () => this.beginRuntimeAction(detached(input)),
      );
    }
    this.assertPersistenceWritable();
    const event = this.logActionEvent(input.event);
    if (input.noise) this.recordOpsecNoise(input.noise);
    const run = this.reserveRuntimeRun({
      ...input.run,
      action_started_event_id: event.event_id,
    });
    this.persist();
    return { run, event };
  }

  finishRuntimeAction(input: {
    run_id: string;
    event: ActivityLogInput;
    lifecycle: Extract<PersistedRuntimeRunV1['lifecycle'], 'completed' | 'failed' | 'interrupted'>;
    evidence_state?: PersistedRuntimeRunV1['evidence_state'];
    exit_code?: number | null;
    exit_signal?: string | null;
  }): { run: PersistedRuntimeRunV1 | null; event: ActivityLogEntry } {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'finish managed runtime action',
        ['runtime_runs', 'activity'],
        () => this.finishRuntimeAction(detached(input)),
      );
    }
    this.assertPersistenceWritable();
    const event = this.logActionEvent(input.event);
    const run = this.finalizeRuntimeRun({
      run_id: input.run_id,
      lifecycle: input.lifecycle,
      evidence_state: input.evidence_state,
      exit_code: input.exit_code,
      exit_signal: input.exit_signal,
      action_terminal_event_id: event.event_id,
    });
    this.persist();
    return { run, event };
  }

  reserveRuntimeRun(input: {
    run_id: string;
    kind: PersistedRuntimeRunV1['kind'];
    task_id?: string;
    action_id?: string;
    agent_id?: string;
    daemon_owner: string;
    command_fingerprint: string;
    ownership_mode?: PersistedRuntimeRunV1['ownership_mode'];
    signal_scope?: PersistedRuntimeRunV1['signal_scope'];
    evidence_state?: PersistedRuntimeRunV1['evidence_state'];
    action_started_event_id?: string;
    started_at?: string;
  }): PersistedRuntimeRunV1 {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'reserve managed runtime run',
        ['runtime_runs'],
        () => this.reserveRuntimeRun(input),
      );
    }
    this.assertPersistenceWritable();
    if (this.ctx.runtimeRuns.some(run =>
      run.run_id === input.run_id
      && (run.lifecycle === 'reserved' || run.lifecycle === 'running'))) {
      throw new Error(`Runtime run is already active: ${input.run_id}`);
    }
    const run: PersistedRuntimeRunV1 = {
      run_id: input.run_id,
      kind: input.kind,
      task_id: input.task_id,
      action_id: input.action_id,
      agent_id: input.agent_id,
      daemon_owner: input.daemon_owner,
      command_fingerprint: input.command_fingerprint,
      ownership_mode: input.ownership_mode ?? 'managed_supervisor',
      signal_scope: input.signal_scope
        ?? (process.platform === 'win32' ? 'pid' : 'process_group'),
      started_at: input.started_at ?? this.ctx.nowIso(),
      lifecycle: 'reserved',
      evidence_state: input.evidence_state ?? 'none',
      action_started_event_id: input.action_started_event_id,
    };
    this.ctx.runtimeRuns = [
      ...this.ctx.runtimeRuns.filter(candidate => candidate.run_id !== input.run_id),
      run,
    ];
    this.persist();
    return detached(run);
  }

  acknowledgeRuntimeRunOwnership(
    run_id: string,
    identity: {
      pid: number;
      process_group_id?: number;
      process_start_identity?: string;
      ownership_token?: string;
    },
  ): PersistedRuntimeRunV1 {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'acknowledge managed runtime ownership',
        ['runtime_runs'],
        () => this.acknowledgeRuntimeRunOwnership(run_id, identity),
      );
    }
    this.assertPersistenceWritable();
    const run = this.ctx.runtimeRuns.find(candidate => candidate.run_id === run_id);
    if (!run) throw new Error(`Runtime run not found: ${run_id}`);
    if (run.lifecycle !== 'reserved') {
      throw new Error(`Runtime run ${run_id} cannot acknowledge ownership from ${run.lifecycle}`);
    }
    if (!Number.isSafeInteger(identity.pid) || identity.pid <= 0) {
      throw new Error(`Runtime run ${run_id} reported an invalid supervisor pid`);
    }
    if (
      run.ownership_mode === 'managed_supervisor'
      && run.signal_scope === 'process_group'
      && process.platform !== 'win32'
      && identity.process_group_id !== identity.pid
    ) {
      throw new Error(
        `Runtime run ${run_id} did not report a supervisor-owned process group`,
      );
    }
    if (
      run.ownership_mode === 'managed_supervisor'
      && !identity.process_start_identity
    ) {
      throw new Error(
        `Runtime run ${run_id} did not report a verifiable process start identity`,
      );
    }
    if (
      run.ownership_mode === 'managed_supervisor'
      && !identity.ownership_token
    ) {
      throw new Error(
        `Runtime run ${run_id} did not report a verifiable ownership token`,
      );
    }
    const now = this.ctx.nowIso();
    run.pid = identity.pid;
    run.process_group_id = identity.process_group_id;
    run.process_start_identity = identity.process_start_identity;
    run.ownership_token = identity.ownership_token;
    run.identity_recorded_at = now;
    run.ownership_acknowledged_at = now;
    if (!identity.process_start_identity) {
      run.recovery_warning = 'Supervisor ownership was acknowledged without a verifiable process start identity.';
    } else {
      delete run.recovery_warning;
    }
    this.persist();
    return detached(run);
  }

  markRuntimeRunLaunched(run_id: string, target_pid?: number): PersistedRuntimeRunV1 {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'mark managed runtime launched',
        ['runtime_runs'],
        () => this.markRuntimeRunLaunched(run_id, target_pid),
      );
    }
    this.assertPersistenceWritable();
    const run = this.ctx.runtimeRuns.find(candidate => candidate.run_id === run_id);
    if (!run) throw new Error(`Runtime run not found: ${run_id}`);
    if (!run.ownership_acknowledged_at || !run.pid) {
      throw new Error(`Runtime run ${run_id} has no acknowledged supervisor ownership`);
    }
    if (run.lifecycle !== 'reserved' && run.lifecycle !== 'running') {
      throw new Error(`Runtime run ${run_id} cannot launch from ${run.lifecycle}`);
    }
    run.lifecycle = 'running';
    run.target_pid = target_pid;
    run.launched_at ??= this.ctx.nowIso();
    this.persist();
    return detached(run);
  }

  finalizeRuntimeRun(input: {
    run_id: string;
    lifecycle: Extract<PersistedRuntimeRunV1['lifecycle'], 'completed' | 'failed' | 'interrupted' | 'unknown'>;
    evidence_state?: PersistedRuntimeRunV1['evidence_state'];
    exit_code?: number | null;
    exit_signal?: string | null;
    action_terminal_event_id?: string;
    recovery_warning?: string;
  }): PersistedRuntimeRunV1 | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'finalize managed runtime run',
        ['runtime_runs'],
        () => this.finalizeRuntimeRun(input),
      );
    }
    this.assertPersistenceWritable();
    const run = this.ctx.runtimeRuns.find(candidate => candidate.run_id === input.run_id);
    if (!run) return null;
    if (
      run.lifecycle === 'completed'
      || run.lifecycle === 'failed'
      || run.lifecycle === 'interrupted'
      || run.lifecycle === 'unknown'
    ) {
      return detached(run);
    }
    run.lifecycle = input.lifecycle;
    run.finalization_status = input.lifecycle;
    run.completed_at = this.ctx.nowIso();
    if (input.evidence_state !== undefined) run.evidence_state = input.evidence_state;
    if (input.exit_code !== undefined) run.exit_code = input.exit_code;
    if (input.exit_signal !== undefined) run.exit_signal = input.exit_signal;
    if (input.action_terminal_event_id !== undefined) {
      run.action_terminal_event_id = input.action_terminal_event_id;
    }
    if (input.recovery_warning !== undefined) run.recovery_warning = input.recovery_warning;
    else if (input.lifecycle !== 'unknown') delete run.recovery_warning;
    this.pruneTerminalRuntimeRuns();
    this.persist();
    return detached(run);
  }

  reconcileRuntimeRunOnStartup(input: {
    run_id: string;
    outcome: 'interrupted' | 'unknown';
    reason: string;
    recovery_warning?: string;
  }): PersistedRuntimeRunV1 | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'reconcile managed runtime ownership on startup',
        ['runtime_runs', 'tracked_processes', 'activity'],
        () => this.reconcileRuntimeRunOnStartup(input),
      );
    }
    this.assertPersistenceWritable();
    const run = this.ctx.runtimeRuns.find(candidate => candidate.run_id === input.run_id);
    if (!run) return null;
    const alreadyTerminal = run.lifecycle === 'completed'
      || run.lifecycle === 'failed'
      || run.lifecycle === 'interrupted'
      || run.lifecycle === 'unknown';
    const startEventIndex = run.action_started_event_id
      ? this.ctx.activityLog.findIndex(entry => entry.event_id === run.action_started_event_id)
      : -1;
    const actionEvents = startEventIndex >= 0
      ? this.ctx.activityLog.slice(startEventIndex + 1)
      : this.ctx.activityLog.filter(entry => entry.timestamp >= run.started_at);
    const existingTerminal = run.action_id
      ? actionEvents.filter(entry =>
          entry.action_id === run.action_id
          && (entry.event_type === 'action_completed' || entry.event_type === 'action_failed'))
        .at(-1)
      : undefined;
    if (!alreadyTerminal) {
      const terminalLifecycle = existingTerminal?.event_type === 'action_completed'
        ? 'completed' as const
        : existingTerminal?.event_type === 'action_failed'
          ? existingTerminal.details?.reason === 'timeout'
            ? 'interrupted' as const
            : 'failed' as const
          : input.outcome;
      run.lifecycle = terminalLifecycle;
      run.finalization_status = terminalLifecycle;
      run.completed_at = existingTerminal?.timestamp ?? this.ctx.nowIso();
    }
    if (existingTerminal && run.lifecycle !== 'unknown') {
      delete run.recovery_warning;
    } else if (input.recovery_warning) {
      run.recovery_warning = input.recovery_warning;
    }
    const tracked = this.ctx.trackedProcesses.find(process => process.id === run.run_id);
    if (tracked?.status === 'running') {
      tracked.status = run.lifecycle === 'completed'
        ? 'completed'
        : run.lifecycle === 'failed'
          ? 'failed'
          : 'unknown';
      tracked.completed_at = run.completed_at ?? this.ctx.nowIso();
      if (tracked.status !== 'unknown') delete tracked.recovery_warning;
    }
    if (existingTerminal) {
      run.action_terminal_event_id = existingTerminal.event_id;
    } else if (run.action_id && !run.action_terminal_event_id) {
      const event = this.ctx.logEvent({
        description: input.outcome === 'interrupted'
          ? `Action interrupted during daemon restart: ${input.reason}`
          : `Action ownership unknown after daemon restart: ${input.reason}`,
        action_id: run.action_id,
        agent_id: run.agent_id,
        linked_agent_task_id: run.task_id,
        event_type: 'action_failed',
        category: 'system',
        result_classification: 'failure',
        details: {
          reason: 'runtime_ownership_recovery',
          runtime_run_id: run.run_id,
          recovery_outcome: input.outcome,
          recovery_reason: input.reason,
        },
      });
      run.action_terminal_event_id = event.event_id;
    }
    this.pruneTerminalRuntimeRuns();
    this.persist();
    return detached(run);
  }

  setPlaybookRuns(runs: PersistedPlaybookRunV1[]): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'replace playbook runs',
        ['playbook_runs'],
        () => this.setPlaybookRuns(runs),
      );
      return;
    }
    this.assertPersistenceWritable();
    this.ctx.playbookRuns = new Map(runs.map(run => [run.run_id, detached(run)]));
    this.persist();
  }

  getPlaybookRuns(): PersistedPlaybookRunV1[] {
    return detached([...this.ctx.playbookRuns.values()]);
  }

  getPlaybookRun(runId: string): PersistedPlaybookRunV1 | undefined {
    const run = this.ctx.playbookRuns.get(runId);
    return run ? detached(run) : undefined;
  }

  recordPlaybookRun(run: PersistedPlaybookRunV1): PersistedPlaybookRunV1 {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        `record playbook run ${run.run_id}`,
        ['playbook_runs'],
        () => this.recordPlaybookRun(run),
      );
    }
    this.assertPersistenceWritable();
    const stored = detached(run);
    this.ctx.playbookRuns.set(stored.run_id, stored);
    this.persist();
    return detached(stored);
  }

  recordApprovalRequest(action: Omit<PendingAction, 'status' | 'submitted_at' | 'timeout_at'>): DurableApprovalRecord {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'record approval request',
        ['agents', 'approvals'],
        () => this.recordApprovalRequest(action),
      );
    }
    this.assertPersistenceWritable();
    const ownerReference = action.task_id ?? action.agent_label ?? action.agent_id;
    const ownerResolution = ownerReference
      ? this.agentMgr.resolveTaskReference(ownerReference)
      : { status: 'missing' as const };
    let recoveryWarning: string | undefined;
    if (ownerResolution.status === 'ambiguous_legacy_label') {
      const warning = coordinationRecoveryWarning({
        relationship: `approval:${action.action_id}`,
        reference: ownerReference!,
        candidate_task_ids: ownerResolution.candidate_task_ids,
        payload: action,
      });
      this.ctx.coordinationRecoveryWarnings = mergeCoordinationRecoveryWarnings(
        this.ctx.coordinationRecoveryWarnings,
        [warning],
      );
      recoveryWarning = warning.message;
    }
    const ownerTask = ownerResolution.status === 'exact'
      || ownerResolution.status === 'unique_legacy_label'
      ? ownerResolution.task
      : undefined;
    const now = new Date(); // clock-ok: approval submitted_at/timeout_at is real-time (approval records aren't in the graph hash)
    const timeoutMs = this.ctx.config.opsec.approval_timeout_ms ?? 300_000;
    const record: DurableApprovalRecord = {
      ...action,
      task_id: ownerTask ? taskIdOf(ownerTask) : action.task_id,
      agent_label: ownerTask ? agentLabelOf(ownerTask) : action.agent_label ?? action.agent_id,
      agent_id: ownerTask ? agentLabelOf(ownerTask) : action.agent_id,
      ...(recoveryWarning ? { recovery_warning: recoveryWarning } : {}),
      status: 'pending',
      submitted_at: now.toISOString(),
      timeout_at: new Date(now.getTime() + timeoutMs).toISOString(), // clock-ok: derived from the marked approval `now` (real-time; not in the graph hash)
    };
    this.ctx.approvalRequests.set(action.action_id, record);
    this.persist();
    this.flushNow();
    return record;
  }

  resolveApprovalRequest(resolution: ActionResolution): DurableApprovalRecord | null {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'resolve approval request',
        ['approvals'],
        () => this.resolveApprovalRequest(resolution),
      );
    }
    this.assertPersistenceWritable();
    const existing = this.ctx.approvalRequests.get(resolution.action_id);
    if (!existing) return null;
    const record: DurableApprovalRecord = {
      ...existing,
      status: resolution.status,
      resolved_at: resolution.resolved_at,
      operator_notes: resolution.operator_notes,
      reason: resolution.reason,
      auto_approved: resolution.auto_approved,
      unattended_execute: resolution.unattended_execute,
    };
    this.ctx.approvalRequests.set(resolution.action_id, record);
    this.pruneResolvedApprovals();
    this.persist();
    this.flushNow();
    return record;
  }

  /**
   * Cap the durable approval log: keep every still-pending record plus the most
   * recent MAX_RESOLVED_APPROVAL_RECORDS resolved ones. Without this the map grows
   * unbounded for the life of the engagement and is fully re-serialized on every
   * state flush. Insertion order in the Map is chronological, so the oldest
   * resolved records are pruned first.
   */
  private pruneResolvedApprovals(): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'prune resolved approvals',
        ['approvals'],
        () => this.pruneResolvedApprovals(),
      );
      return;
    }
    const MAX_RESOLVED_APPROVAL_RECORDS = 200;
    const resolved = [...this.ctx.approvalRequests.entries()].filter(([, r]) => r.status !== 'pending');
    const overflow = resolved.length - MAX_RESOLVED_APPROVAL_RECORDS;
    if (overflow <= 0) return;
    for (let i = 0; i < overflow; i++) this.ctx.approvalRequests.delete(resolved[i][0]);
  }

  /**
   * Abort any pending approval gate owned by a now-terminal task: resolve the
   * live queue entries as 'aborted' AND update their durable records. Without
   * this, a blocked approval for a reaped/cancelled agent would sit pending and
   * could auto-fire on timeout (executing a command for a dead agent), and the
   * durable record + dashboard would show a stuck 'pending' forever. Matches the
   * queue's PendingAction.agent_id to the task's agent_id. Returns the count
   * aborted.
   */
  abortApprovalsForTask(task_id: string, reason = 'requesting agent terminated'): number {
    this.assertPersistenceWritable();
    const task = this.getTask(task_id);
    if (!task) return 0;
    const label = agentLabelOf(task);
    const labelIsUnique = this.agentMgr.getAll()
      .filter(candidate => agentLabelOf(candidate) === label).length === 1;
    const aborted = this.ctx.pendingActionQueue.abortByTask(
      taskIdOf(task),
      labelIsUnique ? label : undefined,
      reason,
    );
    for (const resolution of aborted) this.resolveApprovalRequest(resolution);
    return aborted.length;
  }

  /**
   * On startup, resolve any persisted 'pending' approval record to 'aborted':
   * the agent that requested it is gone after a restart, so the record would
   * otherwise sit un-actionable forever (the operator can no longer approve it
   * into a live, awaiting tool call). Mirrors `reconcileOnStartup` for agents.
   */
  reconcilePendingApprovalsOnStartup(): number {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'reconcile pending approvals on startup',
        ['approvals'],
        () => this.reconcilePendingApprovalsOnStartup(),
      );
    }
    this.assertPersistenceWritable();
    let count = 0;
    const now = new Date().toISOString(); // clock-ok: startup reconciliation timestamp (daemon restart; not on the replay path)
    for (const [id, rec] of this.ctx.approvalRequests) {
      if (rec.status !== 'pending') continue;
      this.ctx.approvalRequests.set(id, {
        ...rec,
        status: 'aborted',
        resolved_at: now,
        reason: 'daemon restarted before the approval was actioned',
      });
      count++;
    }
    if (count > 0) {
      this.persist();
      this.flushNow();
    }
    return count;
  }

  getApprovalRequests(options?: { includeResolved?: boolean; resolvedSinceMs?: number }): DurableApprovalRecord[] {
    const now = Date.now(); // clock-ok: read-only query filter (resolvedSinceMs window; writes no state)
    return detached([...this.ctx.approvalRequests.values()]
      .filter(record => {
        if (record.status === 'pending') return true;
        if (options?.includeResolved) return true;
        if (options?.resolvedSinceMs == null || !record.resolved_at) return false;
        return now - new Date(record.resolved_at).getTime() <= options.resolvedSinceMs; // clock-ok: parses a STORED timestamp for a read-only filter (not a clock read)
      })
      .sort((a, b) => (b.submitted_at || '').localeCompare(a.submitted_at || '')));
  }

  getPendingApprovalRequests(): DurableApprovalRecord[] {
    return this.getApprovalRequests().filter(record => record.status === 'pending');
  }

  getApprovalRequest(actionId: string): DurableApprovalRecord | undefined {
    const record = this.ctx.approvalRequests.get(actionId);
    return record ? detached(record) : undefined;
  }

  listSnapshots(): string[] {
    return this.persistence.listSnapshots();
  }

  rollbackToSnapshot(snapshotName: string): boolean {
    this.assertPersistenceWritable();
    this.rollbackCoordinator?.beforeRollback();
    try {
      // The selected snapshot temporarily replaces runtime config before the
      // revisioned config owner adopts it. Suppress ordinary state-patch
      // writers during that known rollback window: they would target the
      // superseded WAL and misclassify the intentional config transition as
      // external divergence.
      const restored = this.ctx.withTransactionDraft(() =>
        this.persistence.rollbackToSnapshot(
          snapshotName,
          BUILTIN_RULES,
          { deferAuthorityRelease: true },
        ),
      );
      if (!restored) return false;
      this.applyRestoredRuntimeProjections();
      this.configService.adoptRestoredRuntimeConfig('snapshot.rollback');
      // A snapshot may contain descriptors and HAS_SESSION edges that were
      // live when captured. Rollback never restores their PTY/socket handles,
      // so reconcile that durable truth before rehydrating adapters or
      // releasing rollback authority.
      this.reconcileSessionEdgesOnStartup();
      this.reconcileSessionDescriptorsOnStartup();
      this.rollbackCoordinator?.afterRollback();
      this.persistence.completePendingRollbackAuthority();
      return true;
    } finally {
      // A failed rollback may already have installed the selected state in
      // memory before durable cleanup failed and the write gate closed.
      this.invalidateAllCaches();
    }
  }

  setRollbackCoordinator(
    coordinator: {
      beforeRollback(): void;
      afterRollback(): void;
    } | undefined,
  ): void {
    this.rollbackCoordinator = coordinator;
  }

  /** Rebuild live helpers whose internal indexes/weights are not stored in ctx. */
  private applyRestoredRuntimeProjections(): void {
    this.frontierComputer.resetWeightsToDefaults();
    if (this.ctx.frontierWeights) {
      this.frontierComputer.setFanOutEstimates(this.ctx.frontierWeights.fan_out);
      this.frontierComputer.setNoiseEstimates(this.ctx.frontierWeights.noise);
    }
    this.ctx.frontierWeights = this.getFrontierWeights();
    this.campaignPlanner.reindex();
  }

  // =============================================
  // Evidence
  // =============================================

  getFullHistory(): ActivityLogEntry[] {
    return detached(this.ctx.activityLog);
  }

  /** Frontier linkage tracker: lifecycle status of every surfaced frontier item. */
  getFrontierLinkage(): import('./frontier-linkage.js').FrontierLinkageTracker {
    return FrontierLinkageTracker.deserialize(this.ctx.frontierLinkage.serialize());
  }

  /**
   * Record one next_task emission and any newly-dropped candidates as a
   * single durable frontier/activity patch.
   */
  recordFrontierEmission(frontierItemIds: string[]): {
    summary: import('./frontier-linkage.js').LinkageStatusSummary;
    dropped: import('./frontier-linkage.js').FrontierLinkageRecord[];
  } {
    if (!this.ctx.isDraftingTransaction()) {
      return this.transactDurableSlices(
        'record surfaced frontier items',
        ['frontier', 'activity'],
        () => this.recordFrontierEmission(frontierItemIds),
      );
    }
    this.assertPersistenceWritable();
    const tracker = this.ctx.frontierLinkage;
    tracker.recordEmitted([...new Set(frontierItemIds)]);
    const dropped = tracker.sweepDropped();
    const currentCallIndex = tracker.callIndex();
    for (const record of dropped) {
      this.logActionEvent({
        description: `Frontier item dropped without being pursued: ${record.frontier_item_id}`,
        event_type: 'frontier_item_dropped',
        category: 'frontier',
        provenance: 'system',
        frontier_item_id: record.frontier_item_id,
        result_classification: 'neutral',
        details: {
          emitted_at: record.emitted_at,
          emitted_call_index: record.emitted_call_index,
          last_seen_call_index: record.last_seen_call_index,
          current_call_index: currentCallIndex,
        },
      });
    }
    this.persist();
    return detached({
      summary: tracker.summary(),
      dropped,
    });
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
    return detached(this.ctx.inferenceRules);
  }

  getConfig(): EngagementConfig {
    return detached(this.ctx.config);
  }

  private recordConfigCommitEvent(event: ConfigCommitEvent): void {
    this.ctx.logEvent({
      description: event.description,
      event_type: event.result === 'success' ? 'config_updated' : 'instrumentation_warning',
      category: 'system',
      result_classification: event.result,
      details: event.details,
    });
  }

  /**
   * Commit a synchronous high-level graph command as one immutable transaction.
   * The callback may use the ordinary guarded node/edge and activity helpers;
   * their operations are captured, replay-proven, and then applied through the
   * same applier used at startup.
   */
  runAtomicGraphCommand<T>(
    reason: string,
    sourceActionId: string | undefined,
    mutation: () => T,
    additionalStateKeys: readonly DurableStateSliceKey[] = [],
  ): T {
    if (this.ctx.isDraftingTransaction()) return mutation();

    const stateKeys = [
      ...new Set<DurableStateSliceKey>([
        'activity',
        'frontier',
        ...additionalStateKeys,
      ]),
    ];
    const graphBaseline = detached(this.ctx.graph.export());
    const coldBaseline = detached(this.ctx.coldStore.export());
    const sliceBaseline = this.ctx.captureDurableStateSlices(stateKeys);
    const cacheBaseline = {
      pathGraphCache: new Map(this.ctx.pathGraphCache),
      communityCache: this.ctx.communityCache ? new Map(this.ctx.communityCache) : null,
      frontierCache: this.frontierCache ? detached(this.frontierCache) : null,
      healthReportCache: this.healthReportCache ? detached(this.healthReportCache) : null,
    };
    const restoreBaseline = () => {
      this.restoreFindingDraftBaseline(graphBaseline, coldBaseline, sliceBaseline);
      this.ctx.pathGraphCache = new Map(cacheBaseline.pathGraphCache);
      this.ctx.communityCache = cacheBaseline.communityCache
        ? new Map(cacheBaseline.communityCache)
        : null;
      this.frontierCache = cacheBaseline.frontierCache
        ? detached(cacheBaseline.frontierCache)
        : null;
      this.healthReportCache = cacheBaseline.healthReportCache
        ? detached(cacheBaseline.healthReportCache)
        : null;
    };

    let captured!: { result: T; operations: EngineOperation[] };
    let graphAfter!: ReturnType<OverwatchGraph['export']>;
    let coldAfter!: ReturnType<EngineContext['coldStore']['export']>;
    let slicesAfter!: ReturnType<EngineContext['captureDurableStateSlices']>;
    try {
      captured = this.ctx.captureEngineOperations(mutation);
      captured = detached(captured);
      graphAfter = detached(this.ctx.graph.export());
      coldAfter = detached(this.ctx.coldStore.export());
      slicesAfter = this.ctx.captureDurableStateSlices(stateKeys);
    } finally {
      restoreBaseline();
    }

    const detail = this.deriveGraphUpdateDetail(graphBaseline, graphAfter, []);
    const statePatch: DurableStatePatchV1 = {
      payload_version: 1,
      operation_id: uuidv4(),
      occurred_at: this.ctx.nowIso(),
      reason,
      slices: slicesAfter,
    };
    const operations: EngineOperation[] = [
      ...captured.operations,
      {
        type: 'state_patch',
        payload: statePatch as unknown as Record<string, unknown>,
      },
    ];
    const transactionDraft = {
      operations,
      ...(sourceActionId ? { source_action_id: sourceActionId } : {}),
      update_detail: detail,
    };

    try {
      const replayed = this.persistence.applyTransactionDraft(transactionDraft, this);
      if (replayed.status === 'skipped') {
        throw new Error(`${reason} operation draft could not replay: ${replayed.reason}`);
      }
      if (
        canonicalJson({
          graph: this.ctx.graph.export(),
          cold_store: this.ctx.coldStore.export(),
          slices: this.ctx.captureDurableStateSlices(stateKeys),
        })
        !== canonicalJson({
          graph: graphAfter,
          cold_store: coldAfter,
          slices: slicesAfter,
        })
      ) {
        throw new Error(`${reason} operation draft replay did not reproduce its captured after-state.`);
      }
    } finally {
      restoreBaseline();
    }

    try {
      this.ctx.applyEngineTransaction(
        transactionDraft,
        () => this.persistence.applyTransactionDraft(transactionDraft, this),
        reason,
      );
    } catch (error) {
      restoreBaseline();
      throw error;
    }
    this.persist(detail);
    return captured.result;
  }

  private commitRuntimeConfigTransaction(
    next: EngagementConfig,
    context: ConfigApplyContext,
    event?: ConfigCommitEvent,
    applicationCommand?: PersistedApplicationCommandV1,
  ): void {
    if (this.ctx.isDraftingTransaction()) {
      this.applyRuntimeConfig(next, context);
      if (event) this.recordConfigCommitEvent(event);
      if (applicationCommand) {
        this.recordApplicationCommand(applicationCommand);
      }
      return;
    }

    const stateKeys: DurableStateSliceKey[] = [
      'config',
      'activity',
      'frontier',
      ...(applicationCommand ? ['command_state' as const] : []),
    ];
    const graphBaseline = detached(this.ctx.graph.export());
    const coldBaseline = detached(this.ctx.coldStore.export());
    const sliceBaseline = this.ctx.captureDurableStateSlices(stateKeys);
    const cacheBaseline = {
      pathGraphCache: new Map(this.ctx.pathGraphCache),
      communityCache: this.ctx.communityCache ? new Map(this.ctx.communityCache) : null,
      frontierCache: this.frontierCache ? detached(this.frontierCache) : null,
      healthReportCache: this.healthReportCache ? detached(this.healthReportCache) : null,
    };
    const restoreBaseline = () => {
      this.restoreFindingDraftBaseline(graphBaseline, coldBaseline, sliceBaseline);
      this.ctx.pathGraphCache = new Map(cacheBaseline.pathGraphCache);
      this.ctx.communityCache = cacheBaseline.communityCache
        ? new Map(cacheBaseline.communityCache)
        : null;
      this.frontierCache = cacheBaseline.frontierCache
        ? detached(cacheBaseline.frontierCache)
        : null;
      this.healthReportCache = cacheBaseline.healthReportCache
        ? detached(cacheBaseline.healthReportCache)
        : null;
    };

    let captured!: { result: void; operations: EngineOperation[] };
    let graphAfter!: ReturnType<OverwatchGraph['export']>;
    let coldAfter!: ReturnType<EngineContext['coldStore']['export']>;
    let slicesAfter!: ReturnType<EngineContext['captureDurableStateSlices']>;
    try {
      captured = this.ctx.captureEngineOperations(() => {
        this.applyRuntimeConfig(next, context);
        if (event) this.recordConfigCommitEvent(event);
        if (applicationCommand) {
          this.recordApplicationCommand(applicationCommand);
        }
      });
      graphAfter = detached(this.ctx.graph.export());
      coldAfter = detached(this.ctx.coldStore.export());
      slicesAfter = this.ctx.captureDurableStateSlices(stateKeys);
    } finally {
      restoreBaseline();
    }

    const detail = this.deriveGraphUpdateDetail(graphBaseline, graphAfter, []);
    const statePatch: DurableStatePatchV1 = {
      payload_version: 1,
      operation_id: uuidv4(),
      occurred_at: this.ctx.nowIso(),
      reason: `commit runtime configuration (${context.source})`,
      slices: slicesAfter,
    };
    const operations: EngineOperation[] = [
      ...captured.operations,
      {
        type: 'state_patch',
        payload: statePatch as unknown as Record<string, unknown>,
      },
    ];
    const transactionDraft = { operations, update_detail: detail };

    try {
      const replayed = this.persistence.applyTransactionDraft(transactionDraft, this);
      if (replayed.status === 'skipped') {
        throw new Error(`Configuration operation draft could not replay: ${replayed.reason}`);
      }
      if (
        canonicalJson({
          graph: this.ctx.graph.export(),
          cold_store: this.ctx.coldStore.export(),
          slices: this.ctx.captureDurableStateSlices(stateKeys),
        })
        !== canonicalJson({
          graph: graphAfter,
          cold_store: coldAfter,
          slices: slicesAfter,
        })
      ) {
        throw new Error('Configuration operation draft replay did not reproduce its captured after-state.');
      }
    } finally {
      restoreBaseline();
    }

    try {
      this.ctx.applyEngineTransaction(
        transactionDraft,
        () => this.persistence.applyTransactionDraft(transactionDraft, this),
        'runtime configuration commit',
      );
    } catch (error) {
      restoreBaseline();
      throw error;
    }
    this.persist(detail);
  }

  private applyRuntimeConfig(next: EngagementConfig, context: ConfigApplyContext): void {
    const previous = this.ctx.config;
    this.ctx.config = detached(next);
    if (!context.semantic_change) return;

    this.invalidateAllCaches();
    this.invalidatePathGraph();

    const previousObjectives = new Map(previous.objectives.map(objective => [objective.id, objective]));
    for (const objective of next.objectives) {
      if (!objective.achieved || previousObjectives.get(objective.id)?.achieved) continue;
      this.ctx.logEvent({
        description: `OBJECTIVE ACHIEVED: ${objective.description}`,
        category: 'objective',
        event_type: 'objective_achieved',
        result_classification: 'success',
        target_node_ids: [`obj-${objective.id}`],
        details: {
          objective_id: objective.id,
          config_source: context.source,
          recovery: context.recovery,
        },
      });
    }

    // Keep objective graph truth aligned with the revisioned config in the
    // same recoverable write. Legacy CRUD only changed the array, leaving
    // missing/stale objective nodes until a later restart.
    const nextIds = new Set(next.objectives.map(objective => `obj-${objective.id}`));
    for (const objective of previous.objectives) {
      const nodeId = `obj-${objective.id}`;
      if (!nextIds.has(nodeId) && this.ctx.graph.hasNode(nodeId)) {
        this.dropNodeDurable(nodeId, {
          reason: `Objective removed by configuration update (${context.source})`,
        });
      }
    }
    const now = this.ctx.nowIso();
    for (const objective of next.objectives) {
      const nodeId = `obj-${objective.id}`;
      const properties: NodeProperties = {
        id: nodeId,
        type: 'objective',
        label: objective.description,
        objective_description: objective.description,
        objective_achieved: objective.achieved,
        objective_achieved_at: objective.achieved_at,
        discovered_at: now,
        first_seen_at: now,
        last_seen_at: now,
        confidence: 1,
      };
      if (this.ctx.graph.hasNode(nodeId)) {
        const existing = this.ctx.graph.getNodeAttributes(nodeId) as NodeProperties;
        this.addNode({
          ...existing,
          ...properties,
          discovered_at: existing.discovered_at,
          first_seen_at: existing.first_seen_at,
        });
      } else {
        this.addNode(properties);
      }
    }
  }

  updateConfig(partial: Record<string, unknown>): EngagementConfig {
    this.assertPersistenceWritable();
    const next = mergeConfig(this.ctx.config, partial);
    if (canonicalJson(next.scope) !== canonicalJson(this.ctx.config.scope)) {
      const plan = planScopeUpdate(this.scopeHost, {
        replace_scope: next.scope,
        reason: 'Active configuration scope updated',
      });
      if (plan.errors.length > 0) {
        throw new Error(`Invalid scope update: ${plan.errors.join('; ')}`);
      }
      const target = this.configService.prepareJournalTarget(next);
      const sourceFileHash = this.configService.getStatus().file_hash ?? computeConfigHash(this.ctx.config);
      this.commitScopePlan(plan, target, 'Active configuration scope updated', sourceFileHash);
      return this.getConfig();
    }
    return this.configService.commit(next, 'engine.update_config');
  }

  commitConfigApplicationCommand(
    nextConfig: EngagementConfig,
    source: string,
    _sourceActionId: string | undefined,
    buildCommand: (
      committedConfig: EngagementConfig,
      scopeResult: {
        before: EngagementConfig['scope'];
        after: EngagementConfig['scope'];
        affected_node_count: number;
      },
    ) => PersistedApplicationCommandV1,
  ): {
    config: EngagementConfig;
    command: PersistedApplicationCommandV1;
  } {
    this.assertPersistenceWritable();
    const parsedNext = engagementConfigSchema.parse(nextConfig);
    if (
      canonicalJson(parsedNext.scope)
      === canonicalJson(this.ctx.config.scope)
    ) {
      const scope = detached(this.ctx.config.scope);
      return this.configService.commitWithCommand(
        parsedNext,
        source,
        committedConfig => buildCommand(committedConfig, {
          before: scope,
          after: scope,
          affected_node_count: 0,
        }),
      );
    }

    const plan = planScopeUpdate(this.scopeHost, {
      replace_scope: parsedNext.scope,
      reason: source,
    });
    if (plan.errors.length > 0) {
      const error = new Error(plan.errors.join('; '));
      (error as Error & { code: string }).code = 'SCOPE_VALIDATION_FAILED';
      throw error;
    }
    const targetConfig = this.configService.prepareJournalTarget(parsedNext);
    const command = detached(buildCommand(targetConfig, {
      before: detached(plan.before),
      after: detached(plan.after),
      affected_node_count: plan.affected_node_count,
    }));
    if (command.status !== 'succeeded') {
      throw new Error(
        'A config application command must be terminal before it is journaled.',
      );
    }
    const sourceFileHash = this.configService.getStatus().file_hash
      ?? computeConfigHash(this.ctx.config);
    const stateKeys = ['command_state'] as const;
    const stateBefore = this.ctx.captureDurableStateSlices(stateKeys);
    let draft!: {
      result: PersistedApplicationCommandV1;
      slices: DurableStatePatchV1['slices'];
    };
    try {
      draft = this.ctx.draftDurableStateSlices(
        stateKeys,
        () => this.installApplicationCommandDraft(command),
      );
    } finally {
      this.applyRestoredRuntimeProjections();
    }
    const changedStateKeys = Object.keys(
      draft.slices,
    ) as DurableStateSliceKey[];
    const stateBeforePatch = Object.fromEntries(
      changedStateKeys.map(key => [key, stateBefore[key]]),
    ) as DurableStateSlices;
    const statePatch: DurableStatePatchV1 = {
      payload_version: 1,
      operation_id: uuidv4(),
      occurred_at: this.ctx.nowIso(),
      reason: source,
      slices: draft.slices,
    };
    this.commitScopePlan(
      plan,
      targetConfig,
      source,
      sourceFileHash,
      undefined,
      undefined,
      statePatch,
      createHash('sha256')
        .update(canonicalJson(stateBeforePatch))
        .digest('hex'),
      createHash('sha256')
        .update(canonicalJson(draft.slices))
        .digest('hex'),
    );
    return {
      config: this.getConfig(),
      command: detached(draft.result),
    };
  }

  addObjective(obj: { description: string; target_node_type?: string; target_criteria?: Record<string, unknown>; achievement_edge_types?: string[] }): EngagementConfig['objectives'][0] {
    this.assertPersistenceWritable();
    const objective: EngagementConfig['objectives'][0] = {
      id: uuidv4(),
      description: obj.description,
      target_node_type: obj.target_node_type as NodeType | undefined,
      target_criteria: obj.target_criteria,
      achievement_edge_types: obj.achievement_edge_types as EdgeType[] | undefined,
      achieved: false,
    };
    const next = mergeConfig(this.ctx.config, {
      objectives: [...this.ctx.config.objectives, objective],
    });
    this.configService.commit(next, 'objective.add');
    return detached(objective);
  }

  updateObjective(id: string, updates: Record<string, unknown>): boolean {
    this.assertPersistenceWritable();
    const index = this.ctx.config.objectives.findIndex(objective => objective.id === id);
    if (index < 0) return false;
    const objectives = detached(this.ctx.config.objectives);
    const objective = objectives[index];
    if (typeof updates.description === 'string') objective.description = updates.description;
    if (typeof updates.target_node_type === 'string') objective.target_node_type = updates.target_node_type as NodeType;
    if (typeof updates.achieved === 'boolean') {
      objective.achieved = updates.achieved;
      objective.achieved_at = updates.achieved ? this.ctx.nowIso() : undefined;
    }
    if (updates.target_criteria !== undefined) objective.target_criteria = updates.target_criteria as Record<string, unknown>;
    if (Array.isArray(updates.achievement_edge_types)) objective.achievement_edge_types = updates.achievement_edge_types as EdgeType[];
    this.configService.commit(mergeConfig(this.ctx.config, { objectives }), 'objective.update');
    return true;
  }

  removeObjective(id: string): boolean {
    this.assertPersistenceWritable();
    if (!this.ctx.config.objectives.some(objective => objective.id === id)) return false;
    const objectives = this.ctx.config.objectives.filter(objective => objective.id !== id);
    this.configService.commit(mergeConfig(this.ctx.config, { objectives }), 'objective.remove');
    return true;
  }

  getAllAgents(): AgentTask[] {
    return detached(Array.from(this.ctx.agents.values()));
  }

  getTrackedProcesses(): import('./process-tracker.js').TrackedProcess[] {
    return detached(this.ctx.trackedProcesses);
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

  /**
   * Resolve a frontier id against the same deterministic filters used by
   * next_task. Dashboard dispatch uses this instead of trusting client-supplied
   * node ids, so stale, leased, out-of-scope, dead-host, and OPSEC-vetoed items
   * cannot be launched through a second path.
   */
  getActionableFrontierItem(frontierItemId: string): FrontierItem | null {
    const item = this.getFrontierItem(frontierItemId);
    if (!item) return null;
    return this.filterFrontier([item]).passed[0] ?? null;
  }

  getFrontierWeights(): { fan_out: Record<string, number>; noise: Record<string, number> } {
    return {
      fan_out: this.frontierComputer.getFanOutEstimates(),
      noise: this.frontierComputer.getNoiseEstimates(),
    };
  }

  setFrontierWeights(weights: { fan_out?: Record<string, number>; noise?: Record<string, number> }): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'update frontier weights',
        ['frontier'],
        () => this.setFrontierWeights(weights),
      );
      return;
    }
    this.assertPersistenceWritable();
    if (weights.fan_out) this.frontierComputer.setFanOutEstimates(weights.fan_out);
    if (weights.noise) this.frontierComputer.setNoiseEstimates(weights.noise);
    this.ctx.frontierWeights = this.getFrontierWeights();
    this.invalidateFrontierCache();
    this.persist();
  }

  resetFrontierWeights(): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'reset frontier weights',
        ['frontier'],
        () => this.resetFrontierWeights(),
      );
      return;
    }
    this.assertPersistenceWritable();
    this.frontierComputer.resetWeightsToDefaults();
    this.ctx.frontierWeights = this.getFrontierWeights();
    this.invalidateFrontierCache();
    this.persist();
  }

  logActionEvent(event: ActivityLogInput): ActivityLogEntry {
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

  /** Live, in-memory stdout/stderr buffer for running actions (Analysis live stream). */
  getActionOutputBuffer(): ActionOutputBuffer {
    return this.actionOutputBuffer;
  }

  /** Attach the shared skill index so prompt generation + the headless runner can
   *  inline archetype methodology without re-reading the skills dir per call. */
  setSkillIndex(skillIndex: SkillIndex): void {
    this.skillIndex = skillIndex;
  }

  getSkillIndex(): SkillIndex | null {
    return this.skillIndex;
  }

  private reportArchive: ReportArchive | null = null;
  /** Lazily-instantiated per-engagement report archive (B.2). */
  getReportArchive(): ReportArchive {
    if (!this.reportArchive) this.reportArchive = new ReportArchive(this.ctx.stateFilePath);
    return this.reportArchive;
  }

  private applyTrackedProcesses(
    processes: import('./process-tracker.js').TrackedProcess[],
  ): void {
    this.ctx.trackedProcesses = detached(processes);
    const derivedRunIds = new Set(processes.map(process => process.id));
    const priorRuns = new Map(this.ctx.runtimeRuns.map(run => [run.run_id, run]));
    const nonTrackedRuns = this.ctx.runtimeRuns.filter(run => !derivedRunIds.has(run.run_id));
    const trackedRuns: PersistedRuntimeRunV1[] = processes.map(proc => {
      const prior = priorRuns.get(proc.id);
      const projectedLifecycle = proc.status === 'running'
        ? 'running' as const
        : proc.status === 'completed'
          ? 'completed' as const
          : proc.status === 'failed'
            ? 'failed' as const
            : 'unknown' as const;
      const priorTerminal = prior?.lifecycle === 'completed'
        || prior?.lifecycle === 'failed'
        || prior?.lifecycle === 'interrupted'
        || prior?.lifecycle === 'unknown';
      const lifecycle = priorTerminal
        ? prior.lifecycle
        : projectedLifecycle;
      return {
        ...detached(prior ?? {}),
        run_id: proc.id,
        kind: prior?.kind
          ?? (proc.id.startsWith('headless-') ? 'headless_agent' : 'tracked_process'),
        task_id: prior?.task_id
          ?? proc.task_id
          ?? (proc.id.startsWith('headless-') ? proc.id.slice('headless-'.length) : undefined),
        action_id: prior?.action_id ?? proc.action_id,
        agent_id: proc.agent_id ?? prior?.agent_id,
        pid: proc.pid,
        process_group_id: proc.process_group_id ?? prior?.process_group_id,
        process_start_identity: proc.process_start_identity ?? prior?.process_start_identity,
        ownership_token: proc.ownership_token ?? prior?.ownership_token,
        daemon_owner: proc.daemon_owner ?? prior?.daemon_owner,
        command_fingerprint: proc.command_fingerprint
          ?? prior?.command_fingerprint
          ?? createHash('sha256').update(proc.command).digest('hex'),
        ownership_mode: proc.ownership_mode ?? prior?.ownership_mode,
        signal_scope: proc.signal_scope ?? prior?.signal_scope,
        started_at: proc.started_at,
        completed_at: priorTerminal
          ? prior.completed_at
          : proc.completed_at ?? prior?.completed_at,
        lifecycle,
        evidence_state: prior?.evidence_state ?? 'none',
        ...(proc.status === 'unknown'
          ? {
              recovery_warning: proc.recovery_warning
                ?? prior?.recovery_warning
                ?? 'Process identity could not be verified after restart.',
            }
          : prior?.recovery_warning
            ? { recovery_warning: prior.recovery_warning }
            : {}),
      };
    });
    this.ctx.runtimeRuns = [...nonTrackedRuns, ...trackedRuns];
  }

  setTrackedProcesses(processes: import('./process-tracker.js').TrackedProcess[]): void {
    if (!this.ctx.isDraftingTransaction()) {
      this.transactDurableSlices(
        'replace tracked process state',
        ['tracked_processes', 'runtime_runs'],
        () => this.setTrackedProcesses(processes),
      );
      return;
    }
    this.assertPersistenceWritable();
    this.applyTrackedProcesses(processes);
    this.persist();
  }

  reconcileTrackedProcessesOnStartup(
    processes: import('./process-tracker.js').TrackedProcess[],
  ): void {
    if (!this.ctx.isDraftingTransaction() && this.isPersistenceWritable()) {
      this.transactDurableSlices(
        'reconcile tracked process state on startup',
        ['tracked_processes', 'runtime_runs'],
        () => this.reconcileTrackedProcessesOnStartup(processes),
      );
      return;
    }
    this.applyTrackedProcesses(processes);
    if (this.isPersistenceWritable()) this.persist();
  }

  exportGraph(options?: {
    includeSuperseded?: boolean;
    includeCold?: boolean;
    sourceTrust?: boolean;
    includeDerivedCommunities?: boolean;
  }): ExportedGraph {
    const includeSuperseded = options?.includeSuperseded ?? false;
    const includeCold = options?.includeCold ?? true;
    // Public graph exports historically exposed community_id. Keep that wire
    // contract while deriving the value outside the durable graph; callers
    // that need the canonical persistence shape can opt out explicitly.
    const withCommunities = options?.includeDerivedCommunities ?? true;
    if (withCommunities) this.getCommunities();
    // Opt-in: derive source_trust (observed/asserted/inferred) onto a shallow copy of
    // each element's properties. OFF by default so the canonical export (and the
    // golden-master replay hash that pins it) is unaffected by this presentation label —
    // report/dashboard surfaces pass { sourceTrust: true } to get the honesty labels.
    const withTrust = options?.sourceTrust ?? false;
    const nodes: ExportedGraph['nodes'] = [];
    const edges: ExportedGraph['edges'] = [];

    this.ctx.graph.forEachNode((id, attrs) => {
      if (!includeSuperseded && attrs.identity_status === 'superseded') return;
      const properties = this.projectNodeProperties(id, attrs, withCommunities);
      if (withTrust) properties.source_trust = sourceTrust(attrs);
      nodes.push({ id, properties });
    });

    this.ctx.graph.forEachEdge((edgeId, attrs, source, target) => {
      if (!includeSuperseded) {
        const srcAttrs = this.ctx.graph.getNodeAttributes(source);
        const tgtAttrs = this.ctx.graph.getNodeAttributes(target);
        if (srcAttrs?.identity_status === 'superseded' || tgtAttrs?.identity_status === 'superseded') return;
      }
      const properties = detached(attrs);
      if (withTrust) properties.source_trust = sourceTrust(attrs);
      edges.push({ id: edgeId, source, target, properties });
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

  private projectNodeProperties(
    id: string,
    attrs: NodeProperties,
    includeDerivedCommunity = true,
  ): NodeProperties {
    const properties = detached(attrs);
    // community_id is a topology-derived presentation field. Strip any
    // legacy materialized value and project the current cached assignment.
    delete properties.community_id;
    if (includeDerivedCommunity) {
      const communityId = this.ctx.communityCache?.get(id);
      if (communityId !== undefined) properties.community_id = communityId;
    }
    return properties;
  }

  private restoreWebChainAnnotationBaseline(baseline: NodeProperties[]): void {
    for (const props of baseline) {
      if (!this.ctx.graph.hasNode(props.id)) continue;
      this.ctx.graph.replaceNodeAttributes(props.id, detached(props));
    }
    this.invalidateAllCaches();
  }

  private restoreFindingDraftBaseline(
    graph: ReturnType<OverwatchGraph['export']>,
    coldStore: ReturnType<EngineContext['coldStore']['export']>,
    slices: ReturnType<EngineContext['captureDurableStateSlices']>,
  ): void {
    this.ctx.graph.clear();
    // Graphology and ColdStore may retain imported attribute/record objects.
    // Clone on every restore so a later scratch replay cannot mutate the
    // authoritative rollback snapshot by reference.
    this.ctx.graph.import(detached(graph));
    this.ctx.coldStore.import(detached(coldStore));
    this.ctx.applyDurableStatePatch(slices);
    this.applyRestoredRuntimeProjections();
    this.inference.invalidateCaches();
  }

  private deriveGraphUpdateDetail(
    before: ReturnType<OverwatchGraph['export']>,
    after: ReturnType<OverwatchGraph['export']>,
    inferredEdgeIds: string[],
  ): GraphUpdateDetail {
    const beforeNodes = new Map(before.nodes.map(node => [String(node.key), node.attributes]));
    const afterNodes = new Map(after.nodes.map(node => [String(node.key), node.attributes]));
    const beforeEdges = new Map(before.edges.map(edge => [String(edge.key), edge]));
    const afterEdges = new Map(after.edges.map(edge => [String(edge.key), edge]));
    const newNodes = [...afterNodes.keys()]
      .filter(id => !beforeNodes.has(id))
      .sort();
    const removedNodes = [...beforeNodes.keys()]
      .filter(id => !afterNodes.has(id))
      .sort();
    const updatedNodes = [...afterNodes.keys()]
      .filter(id =>
        beforeNodes.has(id)
        && canonicalJson(beforeNodes.get(id)) !== canonicalJson(afterNodes.get(id)),
      )
      .sort();
    const newEdges = [...afterEdges.keys()]
      .filter(id => !beforeEdges.has(id))
      .sort();
    const removedEdges = [...beforeEdges.keys()]
      .filter(id => !afterEdges.has(id))
      .sort();
    const updatedEdges = [...afterEdges.keys()]
      .filter(id => {
        const prior = beforeEdges.get(id);
        const next = afterEdges.get(id);
        return prior !== undefined
          && (
            prior.source !== next?.source
            || prior.target !== next?.target
            || canonicalJson(prior.attributes) !== canonicalJson(next?.attributes)
          );
      })
      .sort();
    const inferredEdges = [...new Set(inferredEdgeIds)]
      .filter(id => afterEdges.has(id))
      .sort();
    return {
      ...(newNodes.length > 0 ? { new_nodes: newNodes } : {}),
      ...(newEdges.length > 0 ? { new_edges: newEdges } : {}),
      ...(updatedNodes.length > 0 ? { updated_nodes: updatedNodes } : {}),
      ...(updatedEdges.length > 0 ? { updated_edges: updatedEdges } : {}),
      ...(inferredEdges.length > 0 ? { inferred_edges: inferredEdges } : {}),
      ...(removedNodes.length > 0 ? { removed_nodes: removedNodes } : {}),
      ...(removedEdges.length > 0 ? { removed_edges: removedEdges } : {}),
    };
  }

  invalidateFrontierCache(): void {
    this.frontierCache = null;
  }

  // =============================================
  // Helpers
  // =============================================

  private propertiesChanged(oldProps: NodeProperties, newProps: NodeProperties): boolean {
    const ignoreKeys = new Set(['discovered_at', 'discovered_by', 'last_seen_at', 'first_seen_at', 'sources']);
    for (const [key, val] of Object.entries(newProps)) {
      if (ignoreKeys.has(key)) continue;
      if (val !== undefined && val !== null && !this.valuesEqual(oldProps[key], val)) return true;
    }
    return false;
  }

  onUpdate(callback: GraphUpdateCallback): () => void {
    this.ctx.updateCallbacks.push(callback);
    return () => {
      const index = this.ctx.updateCallbacks.indexOf(callback);
      if (index >= 0) this.ctx.updateCallbacks.splice(index, 1);
    };
  }

  private resolveFrontierSeeds(frontierItemId: string): string[] {
    if (frontierItemId.startsWith('frontier-discovery-')) {
      return []; // network_discovery items have no backing graph nodes
    }

    if (frontierItemId.startsWith('frontier-node-')) {
      const nodeId = frontierItemId.slice('frontier-node-'.length);
      if (this.ctx.graph.hasNode(nodeId)) return [nodeId];
    }

    if (frontierItemId.startsWith('frontier-edge-')) {
      const edgeId = frontierItemId.slice('frontier-edge-'.length);
      if (this.ctx.graph.hasEdge(edgeId)) {
        const seeds = [this.ctx.graph.source(edgeId), this.ctx.graph.target(edgeId)];
        return seeds.filter((id, index) => seeds.indexOf(id) === index);
      }
    }

    const frontier = this.computeFrontier();
    const item = frontier.find(f => f.id === frontierItemId);
    if (item) {
      const candidateIds = [
        item.node_id,
        item.credential_id,
        item.edge_source,
        item.edge_target,
        item.pivot_host_id,
        item.via_pivot,
      ];
      return candidateIds.filter((id, index, all): id is string =>
        typeof id === 'string' &&
        all.indexOf(id) === index &&
        this.ctx.graph.hasNode(id));
    }

    return [];
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
