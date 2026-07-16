// ============================================================
// Overwatch — Engine Context
// Shared mutable state holder for all GraphEngine submodules.
// Submodules hold a reference to this object, NOT to individual
// fields. When recovery/rollback replaces ctx.graph, every
// module sees the new graph immediately.
// ============================================================

import type { AbstractGraph } from 'graphology-types';
import { v4 as uuidv4 } from 'uuid';
import type {
  EngagementConfig, InferenceRule, AgentTask, Campaign, AgentDirective,
  NodeProperties, EdgeProperties, FrontierItem,
} from '../types.js';
import type { TrackedProcess } from './process-tracker.js';
import { ColdStore, type ColdNodeRecord } from './cold-store.js';
import { OpsecTracker } from './opsec-tracker.js';
import { PendingActionQueue } from './pending-action-queue.js';
import type { DurableApprovalRecord } from './pending-action-queue.js';
import { FrontierLinkageTracker } from './frontier-linkage.js';
import { computeEventHash, shouldChainEntry, GENESIS_HASH, buildCheckpoint, signCheckpoint, loadCheckpointSigningKey, shouldEmitCheckpoint, type ChainCheckpoint, type CheckpointEmitOptions } from './activity-chain.js';
import { eventIdOrUuid } from './deterministic-id.js';
import { FrontierLeases } from './frontier-leases.js';
import {
  MutationJournal,
  type MutationApplyResult,
  type MutationType,
} from './mutation-journal.js';
import { ProposedPlanStore } from './proposed-plan-store.js';
import { AgentQueryStore } from './agent-query-store.js';
import type { CoordinationRecoveryWarning } from './agent-identity.js';
import type {
  EngineOperation,
  EngineTransactionDraft,
} from './engine-transaction.js';
import type {
  DurableStateSliceKey,
  DurableStateSlices,
} from './durable-state-patch.js';
import type {
  PersistedArtifactReferencesV1,
  PersistedApplicationCommandV1,
  PersistedCommandOutcomeV1,
  PersistedCommandPlanV1,
  PersistedPlaybookRunV1,
  PersistedRuntimeRunV1,
  PersistedSessionDescriptorV1,
} from './persisted-state.js';
import {
  ACTIVITY_APPEND_PAYLOAD_VERSION,
  type ActivityAppendItemV1,
  type ActivityAppendPayloadV1,
} from './activity-append.js';

export type OverwatchGraph = AbstractGraph<NodeProperties, EdgeProperties>;

export type ActivityEventType =
  | 'action_planned'
  | 'action_validated'
  | 'action_started'
  | 'action_completed'
  | 'action_failed'
  | 'finding_reported'
  | 'finding_ingested'
  | 'parse_output'
  | 'graph_corrected'
  | 'instrumentation_warning'
  | 'agent_registered'
  | 'agent_updated'
  | 'inference_generated'
  | 'credential_degradation'
  | 'objective_achieved'
  | 'session_opened'
  | 'session_connected'
  | 'session_updated'
  | 'session_signaled'
  | 'session_closed'
  | 'session_error'
  | 'session_access_confirmed'
  | 'session_access_unconfirmed'
  | 'scope_updated'
  | 'config_updated'
  | 'thought'
  | 'system'
  | 'frontier_item_dropped'
  | 'agent_transcript_submitted'
  | 'transcript_turn_ingested'
  | 'tape_session_started'
  | 'tape_session_stopped'
  | 'mock_service_registered'
  | 'mock_service_refreshed'
  | 'heartbeat'
  | 'phase_entered'
  | 'phase_exited'
  // 3A NL operator cockpit: a free-form planner-proposed plan, and an executed
  // operator command (NL → confirmed ops). Surfaced inline in the console.
  | 'plan_proposed'
  | 'operator_command'
  // 3D: a running agent escalated a question to the operator.
  | 'agent_query';

export type ActivityLogDetails =
  | { parsed_nodes: number; parsed_edges: number; ingested: boolean; new_nodes?: number; new_edges?: number; inferred_edges?: number; [key: string]: unknown }
  | { validation_errors: string[]; [key: string]: unknown }
  | { evidence_type?: string; evidence_id?: string; evidence_content?: string; raw_output?: string; [key: string]: unknown }
  | { warning: string; [key: string]: unknown }
  | Record<string, unknown>;

export type ActivityProvenance = 'agent' | 'operator' | 'system' | 'ingested' | 'inferred';

export type ActivityLogEntry = {
  event_id: string;
  timestamp: string;
  description: string;
  agent_id?: string;
  source_kind?: 'primary' | 'subagent' | 'runner' | 'system' | 'dashboard';
  operator_model?: string;
  operator_name?: string;
  operator_session_id?: string;
  provenance?: ActivityProvenance;
  category?: 'finding' | 'inference' | 'frontier' | 'objective' | 'agent' | 'reasoning' | 'system';
  frontier_type?: FrontierItem['type'];  // mirrors the canonical FrontierItem.type union (no drift)
  outcome?: 'success' | 'failure' | 'neutral';
  action_id?: string;
  event_type?: ActivityEventType;
  tool_name?: string;
  technique?: string;
  command_repr?: string;
  target_node_ids?: string[];
  target_ips?: string[];
  target_cidrs?: string[];
  target_edge?: { source: string; target: string; type?: string };
  frontier_item_id?: string;
  validation_result?: 'valid' | 'invalid' | 'warning_only';
  result_classification?: 'success' | 'failure' | 'partial' | 'neutral';
  linked_finding_ids?: string[];
  linked_agent_task_id?: string;
  noise_estimate?: number;
  noise_actual?: number;
  details?: ActivityLogDetails;
  // Hash-chain (Phase 6): tamper-evident chain over live agent/system events.
  // Populated only when engine.config.hash_chain_enabled === true and the entry
  // qualifies (provenance ∈ {agent, system} and event_type !== 'thought').
  // Ingested/inferred entries get chain_excluded:true and skip hash computation
  // so retro-imports don't break the live chain.
  prev_hash?: string;
  event_hash?: string;
  chain_excluded?: boolean;
};

export type ActivityLogInput =
  Omit<Partial<ActivityLogEntry>, 'event_id' | 'timestamp'>
  & { description: string };

export type GraphUpdateDetail = {
  new_nodes?: string[];
  new_edges?: string[];
  updated_nodes?: string[];
  updated_edges?: string[];
  inferred_edges?: string[];
  removed_nodes?: string[];
  removed_edges?: string[];
};

export type GraphUpdateCallback = (detail: GraphUpdateDetail) => void;
export const MAX_ACTIVITY_LOG_ENTRIES = 5000;

function isSkippedMutationApplyResult(
  value: unknown,
): value is Extract<MutationApplyResult, { status: 'skipped' }> {
  return typeof value === 'object'
    && value !== null
    && (value as { status?: unknown }).status === 'skipped'
    && typeof (value as { reason?: unknown }).reason === 'string';
}

export class EngineContext {
  graph: OverwatchGraph;            // graphology Graph instance — may be replaced on recovery
  config: EngagementConfig;
  inferenceRules: InferenceRule[];
  activityLog: ActivityLogEntry[];
  agents: Map<string, AgentTask>;
  campaigns: Map<string, Campaign>;
  // P1C: operator steering directives, keyed by agent task id → ordered history
  // (most recent last). The engine only records these; TaskExecutionService
  // executes 'stop', and the agent observes the rest via agent_heartbeat.
  agentDirectives: Map<string, AgentDirective[]>;
  stateFilePath: string;
  configFilePath?: string;
  updateCallbacks: GraphUpdateCallback[];
  lastSnapshotTime: number;
  pathGraphCache: Map<string, OverwatchGraph>;  // cached undirected projections keyed by optimize mode
  communityCache: Map<string, number> | null;  // cached Louvain community assignments
  trackedProcesses: TrackedProcess[];
  actionFrontierMap: Map<string, { frontier_item_id: string; agent_id?: string; frontier_type?: ActivityLogEntry['frontier_type'] }>;
  coldStore: ColdStore;
  opsecTracker: OpsecTracker;
  pendingActionQueue: PendingActionQueue;
  // 3A.2: planner-proposed plans awaiting operator confirmation. Persisted with
  // absolute expiry and shared by the tool and dashboard confirm path.
  proposedPlanStore: ProposedPlanStore;
  // 3D: agent→operator questions awaiting an answer. Persisted with the
  // original expiry; heartbeat redelivery remains at-least-once.
  agentQueryStore: AgentQueryStore;
  coordinationRecoveryWarnings: CoordinationRecoveryWarning[];
  /** Grammar previews + duplicate-confirm outcomes share durable ownership with
   * planner proposals instead of disappearing with DashboardServer. */
  commandPlans: Map<string, Omit<PersistedCommandPlanV1, 'plan_id'>>;
  commandOutcomes: Map<string, Omit<PersistedCommandOutcomeV1, 'plan_id'>>;
  applicationCommands: Map<string, PersistedApplicationCommandV1>;
  /** Runtime-neutral descriptors only; handles, buffers, env and secrets stay
   * in SessionManager/TaskExecutionService and are never serialized. */
  sessionDescriptors: PersistedSessionDescriptorV1[];
  runtimeRuns: PersistedRuntimeRunV1[];
  playbookRuns: Map<string, PersistedPlaybookRunV1>;
  artifactReferences: PersistedArtifactReferencesV1;
  approvalRequests: Map<string, DurableApprovalRecord>;
  recentFindingHashes: Map<string, number>;  // SHA-256 hash → timestamp (ms) for dedup
  dedupCount: number;                        // total deduplicated findings for retrospective
  frontierLinkage: FrontierLinkageTracker;   // status of every frontier item we've surfaced
  lastChainHash: string;                     // running tail of the activity hash-chain (Phase 6)
  // P0.2: chain checkpoints. Emitted periodically so verifiers can resume
  // from a known-good tail instead of replaying from genesis. Persisted as
  // part of state so they survive restarts.
  chainCheckpoints: ChainCheckpoint[];
  chainEventsSinceCheckpoint: number;        // chained-event count since the last checkpoint
  checkpointOptions: CheckpointEmitOptions;  // per-engagement override (env or config)
  // Ed25519 signing key for checkpoints, loaded from OVERWATCH_CHECKPOINT_SIGNING_KEY
  // at boot (null → emit unsigned, hash-chain tamper-evidence still applies).
  checkpointSigningKey: { privateKeyPem: string; keyId: string } | null;
  // P1.2: monotonic sequence counter used to derive deterministic IDs
  // (one per call, always increases). Persisted with state. Only consulted
  // when `config.engagement_nonce` is set; legacy engagements ignore it.
  deterministicSeq: number;
  // P1.3: caller-provided clock. When set, mutation paths that record
  // timestamps (`logEvent`, `addNode`, `addEdge`, …) read from here
  // instead of calling `new Date()`. `withClock(now, fn)` is the public
  // entry point — see method below.
  injectedNow?: string;
  // P1.4: frontier item leases. When an agent claims a frontier item it
  // takes a lease so other agents see "in progress" and skip it. Reaped
  // by the same watchdog that handles heartbeat timeouts.
  frontierLeases: FrontierLeases;
  frontierWeights?: {
    fan_out: Record<string, number>;
    noise: Record<string, number>;
  };
  // P4.1: most recently observed active-phase id, used to detect phase
  // transitions and emit `phase_entered` / `phase_exited` events.
  // Persisted with the snapshot so transitions aren't re-emitted across
  // restarts when the phase hasn't actually changed.
  lastKnownPhaseId?: string;
  // P2.1: write-ahead log. Only constructed for engagements with
  // `engagement_nonce` (deterministic-ID engagements). Legacy engagements
  // continue to rely on debounced snapshots only.
  mutationJournal: MutationJournal | null;
  journalSnapshotSeq: number;        // last seq that's already in the persisted snapshot
  /**
   * Installed by StatePersistence.  Recovery and repeated persistence failures
   * use this guard to stop new durable work before it mutates memory.
   */
  persistenceWriteGuard?: () => void;
  /** StatePersistence installs this fail-stop hook. Once a committed WAL
   * transaction cannot be applied in memory, no later durable mutation or
   * snapshot may proceed in this process. */
  persistencePostCommitFailure?: (seq: number, error: unknown) => void;
  activityTransactionRunner?:
    (event: ActivityLogInput) => ActivityLogEntry;
  /** Explicit nesting guard used by composite transaction appliers. Nested
   * primitive helpers apply to memory but never emit their own WAL record. */
  private transactionApplyDepth = 0;
  private transactionDraftDepth = 0;
  /** Operation-draft capture is separate from state-only transaction drafting.
   * Nested guarded graph/cold mutations append their immutable operations here,
   * apply to the caller's temporary live draft, and do not touch the WAL. */
  private operationDraftDepth = 0;
  private operationDraftCollector?: EngineOperation[];
  /** Set during WAL replay so the guarded mutators (addNode/addEdge) re-apply
   *  state without re-emitting their edge-case events (the type-conflict warning
   *  + inferred-edge-confirmation log) into the already-restored activity log. */
  suppressMutationEvents = false;

  constructor(
    graph: OverwatchGraph,
    config: EngagementConfig,
    stateFilePath: string,
    forceMutationJournal = false,
    configFilePath?: string,
  ) {
    this.graph = graph;
    this.config = config;
    this.inferenceRules = [];
    this.activityLog = [];
    this.agents = new Map();
    this.campaigns = new Map();
    this.agentDirectives = new Map();
    this.stateFilePath = stateFilePath;
    this.configFilePath = configFilePath;
    this.updateCallbacks = [];
    this.lastSnapshotTime = 0;
    this.pathGraphCache = new Map();
    this.communityCache = null;
    this.trackedProcesses = [];
    this.actionFrontierMap = new Map();
    this.coldStore = new ColdStore();
    this.opsecTracker = new OpsecTracker(this);
    this.pendingActionQueue = new PendingActionQueue(this);
    this.proposedPlanStore = new ProposedPlanStore();
    this.agentQueryStore = new AgentQueryStore();
    this.coordinationRecoveryWarnings = [];
    this.commandPlans = new Map();
    this.commandOutcomes = new Map();
    this.applicationCommands = new Map();
    this.sessionDescriptors = [];
    this.runtimeRuns = [];
    this.playbookRuns = new Map();
    this.artifactReferences = {
      tapes: [],
      bundles: [],
      cookie_jars: [],
    };
    this.approvalRequests = new Map();
    this.recentFindingHashes = new Map();
    this.dedupCount = 0;
    this.frontierLinkage = new FrontierLinkageTracker();
    this.lastChainHash = GENESIS_HASH;
    this.chainCheckpoints = [];
    this.chainEventsSinceCheckpoint = 0;
    this.checkpointOptions = {};
    this.checkpointSigningKey = loadCheckpointSigningKey(process.env);
    this.deterministicSeq = 0;
    this.frontierLeases = new FrontierLeases();
    // Journal v2 is the durability boundary for every engagement. The
    // force/config/data inputs remain in the signature for source compatibility
    // with older constructors, but no engagement may fall back to snapshot-only
    // mutation semantics. Detached validation/scratch contexts explicitly set
    // mutationJournal=null after construction.
    void forceMutationJournal;
    this.mutationJournal = new MutationJournal(stateFilePath);
    this.journalSnapshotSeq = 0;
  }

  /**
   * P2.1: append a mutation to the WAL when journaling is enabled.
   * No-op for legacy engagements (no engagement_nonce). Caller must invoke
   * this BEFORE applying the mutation in memory — the contract is "if it's
   * in the journal it's durable, regardless of in-memory state."
   *
   * Throws on journal write failure; callers must abort the in-memory
   * change in that case.
   */
  journalMutation(type: MutationType, payload: Record<string, unknown>, source_action_id?: string): number | undefined {
    this.persistenceWriteGuard?.();
    if (this.operationDraftDepth > 0) {
      throw new Error('journalMutation is append-only and cannot participate in an engine operation draft.');
    }
    if (
      this.transactionApplyDepth > 0
      || this.transactionDraftDepth > 0
    ) return undefined;
    if (!this.mutationJournal) return undefined;
    const transaction = this.mutationJournal.appendTransaction({
      operations: [{ type, payload }],
      ...(source_action_id ? { source_action_id } : {}),
      ts: this.nowIso(),
    });
    return transaction.seq;
  }

  /**
   * Apply a mutation under the WAL contract and advance the in-memory
   * checkpoint only after the mutation has actually succeeded.  Keeping this
   * transition in one helper prevents snapshots from claiming an appended but
   * unapplied record.
   */
  applyJournaledMutation<T>(
    type: MutationType,
    payload: Record<string, unknown>,
    apply: () => T,
    source_action_id?: string,
  ): T {
    return this.applyEngineTransaction(
      {
        operations: [{ type, payload }],
        ...(source_action_id ? { source_action_id } : {}),
      },
      apply,
      'mutation',
    );
  }

  /** Apply a high-level mutation as one WAL record while suppressing nested
   * primitive records. The outer record is the complete recovery authority. */
  applyCompositeJournaledMutation<T>(
    type: MutationType,
    payload: Record<string, unknown>,
    apply: () => T,
    source_action_id?: string,
  ): T {
    return this.applyEngineTransaction(
      {
        operations: [{ type, payload }],
        ...(source_action_id ? { source_action_id } : {}),
      },
      apply,
      'composite mutation',
    );
  }

  applyEngineTransaction<T>(
    draft: EngineTransactionDraft,
    apply: () => T,
    label = 'engine transaction',
  ): T {
    this.persistenceWriteGuard?.();
    if (this.transactionApplyDepth > 0) return apply();
    const frozenDraft: EngineTransactionDraft = structuredClone({
      operations: draft.operations as EngineOperation[],
      ...(draft.source_action_id ? { source_action_id: draft.source_action_id } : {}),
      ...(draft.update_detail === undefined ? {} : { update_detail: draft.update_detail }),
    });
    if (this.operationDraftCollector) {
      this.operationDraftCollector.push(...frozenDraft.operations);
      this.transactionApplyDepth++;
      try {
        const result = apply();
        if (isSkippedMutationApplyResult(result)) {
          throw new Error(`Draft ${label} was not applied: ${result.reason}`);
        }
        return result;
      } finally {
        this.transactionApplyDepth--;
      }
    }
    if (!this.mutationJournal) return apply();
    const transaction = this.mutationJournal.appendTransaction({
      ...frozenDraft,
      ts: this.nowIso(),
    });
    this.transactionApplyDepth++;
    try {
      const result = apply();
      if (isSkippedMutationApplyResult(result)) {
        throw new Error(`Durable ${label} was not applied: ${result.reason}`);
      }
      this.mutationJournal.markApplied(transaction.seq);
      return result;
    } catch (error) {
      this.mutationJournal.blockAppends(
        `${label} seq ${transaction.seq} was durable but failed during in-memory application`,
      );
      this.persistencePostCommitFailure?.(transaction.seq, error);
      throw error;
    } finally {
      this.transactionApplyDepth--;
    }
  }

  isDraftingTransaction(): boolean {
    return this.transactionDraftDepth > 0 || this.operationDraftDepth > 0;
  }

  withTransactionDraft<T>(mutation: () => T): T {
    this.persistenceWriteGuard?.();
    this.transactionDraftDepth++;
    try {
      return mutation();
    } finally {
      this.transactionDraftDepth--;
    }
  }

  captureEngineOperations<T>(
    mutation: () => T,
  ): { result: T; operations: EngineOperation[] } {
    // Capture only applyJournaledMutation/applyCompositeJournaledMutation (and
    // direct applyEngineTransaction) calls, because those pair an immutable
    // operation with its live effect. journalMutation() is append-only and
    // deliberately unsupported inside an operation draft.
    this.persistenceWriteGuard?.();
    if (this.transactionApplyDepth > 0) {
      throw new Error('Cannot capture engine operations while a committed transaction is applying.');
    }
    if (this.transactionDraftDepth > 0) {
      throw new Error('Cannot capture engine operations inside a state-only transaction draft.');
    }
    if (this.operationDraftCollector || this.operationDraftDepth > 0) {
      throw new Error('Nested engine operation capture is not supported.');
    }
    if (mutation.constructor.name === 'AsyncFunction') {
      throw new Error('Engine operation capture only supports synchronous mutations.');
    }
    const collector: EngineOperation[] = [];
    this.operationDraftCollector = collector;
    this.operationDraftDepth++;
    try {
      const result = mutation();
      if (
        typeof result === 'object'
        && result !== null
        && typeof (result as { then?: unknown }).then === 'function'
      ) {
        throw new Error('Engine operation capture only supports synchronous mutations.');
      }
      return {
        result,
        operations: structuredClone(collector),
      };
    } finally {
      this.operationDraftDepth--;
      this.operationDraftCollector = undefined;
    }
  }

  captureDurableStateSlices(keys: readonly DurableStateSliceKey[]): DurableStateSlices {
    const slices: DurableStateSlices = {};
    for (const key of new Set(keys)) {
      switch (key) {
        case 'activity':
          slices.activity = structuredClone({
            activityLog: this.activityLog,
            actionFrontierMap: [...this.actionFrontierMap.entries()],
            lastChainHash: this.lastChainHash,
            chainCheckpoints: this.chainCheckpoints,
            chainEventsSinceCheckpoint: this.chainEventsSinceCheckpoint,
            deterministicSeq: this.deterministicSeq,
          });
          break;
        case 'agents':
          slices.agents = structuredClone({
            agents: [...this.agents.entries()],
            frontierLeases: this.frontierLeases.serialize(),
            coordinationRecoveryWarnings: this.coordinationRecoveryWarnings,
          });
          break;
        case 'campaigns':
          slices.campaigns = structuredClone([...this.campaigns.entries()]);
          break;
        case 'directives':
          slices.directives = structuredClone([...this.agentDirectives.entries()]);
          break;
        case 'approvals':
          slices.approvals = structuredClone([...this.approvalRequests.entries()]);
          break;
        case 'inference_rules':
          slices.inference_rules = structuredClone(this.inferenceRules);
          break;
        case 'tracked_processes':
          slices.tracked_processes = structuredClone(this.trackedProcesses);
          break;
        case 'runtime_runs':
          slices.runtime_runs = structuredClone(this.runtimeRuns);
          break;
        case 'playbook_runs':
          slices.playbook_runs = structuredClone([...this.playbookRuns.entries()]);
          break;
        case 'session_descriptors':
          slices.session_descriptors = structuredClone(this.sessionDescriptors);
          break;
        case 'plans_questions':
          slices.plans_questions = structuredClone({
            proposedPlans: this.proposedPlanStore.serialize(),
            agentQueries: this.agentQueryStore.serialize(),
          });
          break;
        case 'command_state':
          slices.command_state = structuredClone({
            commandPlans: [...this.commandPlans.entries()],
            commandOutcomes: [...this.commandOutcomes.entries()],
            applicationCommands: [...this.applicationCommands.entries()],
          });
          break;
        case 'opsec':
          slices.opsec = structuredClone(this.opsecTracker.serialize());
          break;
        case 'frontier':
          slices.frontier = structuredClone({
            linkage: this.frontierLinkage.serialize(),
            weights: this.frontierWeights ?? { fan_out: {}, noise: {} },
          });
          break;
        case 'finding_counters':
          slices.finding_counters = structuredClone({
            recentFindingHashes: [...this.recentFindingHashes.entries()],
            dedupCount: this.dedupCount,
          });
          break;
        case 'phase':
          slices.phase = structuredClone({ lastKnownPhaseId: this.lastKnownPhaseId });
          break;
        case 'config':
          slices.config = structuredClone(this.config);
          break;
        case 'artifacts':
          slices.artifacts = structuredClone(this.artifactReferences);
          break;
      }
    }
    return slices;
  }

  private applyDurableStateSlices(
    slices: DurableStateSlices,
    preserveStoreIdentity: boolean,
  ): void {
    for (const [rawKey, rawValue] of Object.entries(slices)) {
      const key = rawKey as DurableStateSliceKey;
      const value = structuredClone(rawValue) as any;
      switch (key) {
        case 'activity':
          this.activityLog = value.activityLog;
          this.actionFrontierMap = new Map(value.actionFrontierMap);
          this.lastChainHash = value.lastChainHash;
          this.chainCheckpoints = value.chainCheckpoints;
          this.chainEventsSinceCheckpoint = value.chainEventsSinceCheckpoint;
          this.deterministicSeq = value.deterministicSeq;
          break;
        case 'agents':
          this.agents = new Map(value.agents);
          this.frontierLeases = FrontierLeases.deserialize(value.frontierLeases);
          this.coordinationRecoveryWarnings = value.coordinationRecoveryWarnings ?? [];
          break;
        case 'campaigns':
          this.campaigns = new Map(value);
          break;
        case 'directives':
          this.agentDirectives = new Map(value);
          break;
        case 'approvals':
          this.approvalRequests = new Map(value);
          break;
        case 'inference_rules':
          this.inferenceRules = value;
          break;
        case 'tracked_processes':
          this.trackedProcesses = value;
          break;
        case 'runtime_runs':
          this.runtimeRuns = value;
          break;
        case 'playbook_runs':
          this.playbookRuns = new Map(value);
          break;
        case 'session_descriptors':
          this.sessionDescriptors = value;
          break;
        case 'plans_questions':
          if (preserveStoreIdentity) {
            this.proposedPlanStore.restore(value.proposedPlans, Number.NEGATIVE_INFINITY);
            this.agentQueryStore.restore(value.agentQueries, Number.NEGATIVE_INFINITY);
          } else {
            this.proposedPlanStore = ProposedPlanStore.deserialize(
              value.proposedPlans,
              undefined,
              Number.NEGATIVE_INFINITY,
            );
            this.agentQueryStore = AgentQueryStore.deserialize(
              value.agentQueries,
              undefined,
              Number.NEGATIVE_INFINITY,
            );
          }
          break;
        case 'command_state':
          this.commandPlans = new Map(value.commandPlans);
          this.commandOutcomes = new Map(value.commandOutcomes);
          this.applicationCommands = new Map(value.applicationCommands ?? []);
          break;
        case 'opsec':
          this.opsecTracker = OpsecTracker.deserialize(value, this);
          break;
        case 'frontier':
          this.frontierLinkage = FrontierLinkageTracker.deserialize(value.linkage);
          this.frontierWeights = value.weights;
          break;
        case 'finding_counters':
          this.recentFindingHashes = new Map(value.recentFindingHashes);
          this.dedupCount = value.dedupCount;
          break;
        case 'phase':
          this.lastKnownPhaseId = value.lastKnownPhaseId;
          break;
        case 'config':
          this.config = value;
          break;
        case 'artifacts':
          this.artifactReferences = value;
          break;
      }
    }
  }

  applyDurableStatePatch(slices: DurableStateSlices): void {
    this.applyDurableStateSlices(slices, true);
  }

  draftDurableStateSlices<T>(
    keys: readonly DurableStateSliceKey[],
    mutate: () => T,
  ): { result: T; slices: DurableStateSlices } {
    this.persistenceWriteGuard?.();
    if (this.transactionDraftDepth > 0) {
      return { result: mutate(), slices: {} };
    }
    const baseline = this.captureDurableStateSlices(keys);
    const original = {
      activityLog: this.activityLog,
      actionFrontierMap: this.actionFrontierMap,
      lastChainHash: this.lastChainHash,
      chainCheckpoints: this.chainCheckpoints,
      chainEventsSinceCheckpoint: this.chainEventsSinceCheckpoint,
      deterministicSeq: this.deterministicSeq,
      agents: this.agents,
      frontierLeases: this.frontierLeases,
      coordinationRecoveryWarnings: this.coordinationRecoveryWarnings,
      campaigns: this.campaigns,
      agentDirectives: this.agentDirectives,
      approvalRequests: this.approvalRequests,
      inferenceRules: this.inferenceRules,
      trackedProcesses: this.trackedProcesses,
      runtimeRuns: this.runtimeRuns,
      playbookRuns: this.playbookRuns,
      sessionDescriptors: this.sessionDescriptors,
      proposedPlanStore: this.proposedPlanStore,
      agentQueryStore: this.agentQueryStore,
      commandPlans: this.commandPlans,
      commandOutcomes: this.commandOutcomes,
      applicationCommands: this.applicationCommands,
      opsecTracker: this.opsecTracker,
      frontierLinkage: this.frontierLinkage,
      frontierWeights: this.frontierWeights,
      recentFindingHashes: this.recentFindingHashes,
      dedupCount: this.dedupCount,
      lastKnownPhaseId: this.lastKnownPhaseId,
      config: this.config,
      artifactReferences: this.artifactReferences,
    };
    this.applyDurableStateSlices(baseline, false);
    this.transactionDraftDepth++;
    try {
      const result = mutate();
      const after = this.captureDurableStateSlices(keys);
      const changed: DurableStateSlices = {};
      for (const key of Object.keys(after) as DurableStateSliceKey[]) {
        if (JSON.stringify(after[key]) !== JSON.stringify(baseline[key])) {
          changed[key] = after[key];
        }
      }
      return {
        result: structuredClone(result),
        slices: changed,
      };
    } finally {
      this.transactionDraftDepth--;
      Object.assign(this, original);
    }
  }

  /**
   * Journaled cold-store writes. The cold store is durable only via the debounced
   * snapshot, so a bare `coldStore.add/promote` is lost if the process crashes in the
   * ≤500ms snapshot window (reproduced: cold_node_count 1→0 across a crash). Routing
   * cold adds/promotions through the WAL (like every other durable graph mutation)
   * makes them crash-recoverable via replay. Replay itself calls coldStore directly
   * (journaling suppressed), so these don't double-record.
   */
  coldAdd(record: ColdNodeRecord): void {
    this.applyJournaledMutation('cold_add', { record }, () => {
      this.coldStore.add(record);
    });
  }

  coldPromote(id: string): ColdNodeRecord | undefined {
    return this.applyJournaledMutation('cold_promote', { id }, () => this.coldStore.promote(id));
  }

  /**
   * P1.3: scoped clock injection. Inside `fn`, any code that reads `nowIso()`
   * gets the pinned timestamp. Used by integration tests (and the golden-
   * master replay harness) to make the recorded ISO timestamps deterministic.
   *
   * Restores the previous value on exit, so nested calls behave correctly.
   */
  withClock<T>(now: string, fn: () => T): T {
    const prev = this.injectedNow;
    this.injectedNow = now;
    try {
      return fn();
    } finally {
      this.injectedNow = prev;
    }
  }

  /**
   * P1.3: read the current timestamp. Honors `withClock` injection when set;
   * otherwise falls through to `new Date().toISOString()`.
   */
  nowIso(): string {
    return this.injectedNow ?? new Date().toISOString(); // clock-ok: THE canonical clock source (honors withClock injection)
  }

  /**
   * P1.2: bump and return the monotonic sequence counter used for
   * deterministic ID derivation. Caller should bump once per ID generation.
   */
  nextDeterministicSeq(): number {
    this.deterministicSeq += 1;
    return this.deterministicSeq;
  }

  log(message: string, agentId?: string, extra?: Partial<Pick<ActivityLogEntry, 'category' | 'frontier_type' | 'outcome'>>): void {
    this.logEvent({
      description: message,
      agent_id: agentId,
      ...extra,
    });
  }

  logEvent(event: ActivityLogInput): ActivityLogEntry {
    if (
      this.activityTransactionRunner
      && this.transactionApplyDepth === 0
      && this.transactionDraftDepth === 0
      && this.operationDraftDepth === 0
    ) {
      return this.activityTransactionRunner(event);
    }
    return this.appendActivityEventInMemory(event);
  }

  private appendActivityEventInMemory(
    event: ActivityLogInput,
    options: {
      items?: ActivityAppendItemV1[];
      observeLinkage?: boolean;
    } = {},
  ): ActivityLogEntry {
    // Auto-thread frontier_item_id from action_id mapping when caller omits it.
    // Guard against cross-agent action_id collisions: only cache/inherit when
    // the agent_id is consistent with the first writer.
    let enriched = event;
    if (event.action_id && event.frontier_item_id) {
      const existing = this.actionFrontierMap.get(event.action_id);
      if (existing && existing.agent_id && event.agent_id && existing.agent_id !== event.agent_id) {
        // Different agent reusing the same action_id — log a warning instead of overwriting
        this.appendActivityEventInMemory({
          description: `action_id ${event.action_id} collision: agent "${event.agent_id}" tried to associate fi "${event.frontier_item_id}" but it is already mapped to fi "${existing.frontier_item_id}" by agent "${existing.agent_id}"`,
          event_type: 'instrumentation_warning',
          category: 'system',
          action_id: undefined,
          frontier_item_id: undefined,
          agent_id: event.agent_id,
        }, options);
      } else {
        this.actionFrontierMap.set(event.action_id, {
          frontier_item_id: event.frontier_item_id,
          agent_id: event.agent_id,
          frontier_type: event.frontier_type,
        });
      }
    } else if (event.action_id && !event.frontier_item_id) {
      const cached = this.actionFrontierMap.get(event.action_id);
      if (cached) {
        // Only auto-thread if the agent_id matches (or one side is undefined)
        const agentMatch = !cached.agent_id || !event.agent_id || cached.agent_id === event.agent_id;
        if (agentMatch) {
          enriched = {
            ...event,
            frontier_item_id: cached.frontier_item_id,
            frontier_type: event.frontier_type || cached.frontier_type,
          };
        }
      }
    }
    // P1.3: prefer the injected clock so replay/test harnesses can pin time.
    const timestamp = this.nowIso();
    // P1.2: when the engagement carries a nonce, derive event_id
    // deterministically; otherwise fall through to uuidv4 (default
    // generated inside normalizeActivityLogEntry).
    const derivedEventId = eventIdOrUuid(
      this.config.engagement_nonce
        ? {
          engagement_nonce: this.config.engagement_nonce,
          agent_id: enriched.agent_id,
          timestamp,
          command_signature: `${enriched.event_type ?? 'event'}|${enriched.action_id ?? ''}|${enriched.description}`,
          sequence: this.nextDeterministicSeq(),
        }
        : null,
    );
    const entry = normalizeActivityLogEntry({
      ...enriched,
      event_id: derivedEventId,
      timestamp,
    } as Partial<ActivityLogEntry> & { description: string; timestamp?: string });
    let emittedCheckpoint: ChainCheckpoint | undefined;
    // Hash-chain: only when explicitly enabled. P0.2 flipped the schema
    // default to true so new engagements opt in by default. Computed before
    // push so the stored entry carries the chain fields.
    if (this.config.hash_chain_enabled) {
      if (shouldChainEntry(entry)) {
        entry.prev_hash = this.lastChainHash;
        entry.event_hash = computeEventHash(entry, this.lastChainHash);
        this.lastChainHash = entry.event_hash;
        this.chainEventsSinceCheckpoint += 1;
        // P0.2: emit a checkpoint when the policy says so. The activityLog
        // index for `entry` is its position once pushed below.
        const previous = this.chainCheckpoints[this.chainCheckpoints.length - 1];
        const secondsSince = previous
          ? (Date.parse(entry.timestamp) - Date.parse(previous.emitted_at)) / 1000
          : 0;
        const shouldEmit = shouldEmitCheckpoint({
          chained_events_since_previous: this.chainEventsSinceCheckpoint,
          seconds_since_previous_checkpoint: secondsSince,
          has_previous_checkpoint: !!previous,
        }, this.checkpointOptions);
        if (shouldEmit) {
          const checkpoint = buildCheckpoint({
            event_index: this.activityLog.length, // index after push (current length BEFORE push = new index)
            event_id: entry.event_id,
            event_hash: entry.event_hash,
            events_since_previous: this.chainEventsSinceCheckpoint,
            emitted_at: entry.timestamp,
            engagement_nonce: this.config.engagement_nonce ?? null, // anti-splice binding
          });
          // Sign when a key is configured; otherwise emit unsigned (an unsigned
          // checkpoint carries no signing_key_id so it can't masquerade as signed).
          // Signing is wrapped fail-OPEN: a crypto error must never break the activity-log
          // hot path — we fall back to an unsigned checkpoint rather than throwing.
          let toPush = checkpoint;
          if (this.checkpointSigningKey) {
            try {
              toPush = signCheckpoint(checkpoint, this.checkpointSigningKey.privateKeyPem, this.checkpointSigningKey.keyId);
            } catch {
              toPush = checkpoint; // fail-open: emit unsigned
            }
          }
          this.chainCheckpoints.push(toPush);
          emittedCheckpoint = toPush;
          this.chainEventsSinceCheckpoint = 0;
        }
      } else {
        entry.chain_excluded = true;
      }
    }
    this.activityLog.push({
      ...entry,
    });
    if (this.activityLog.length > MAX_ACTIVITY_LOG_ENTRIES) {
      this.activityLog = tieredTruncate(this.activityLog, MAX_ACTIVITY_LOG_ENTRIES);
      // Prune checkpoints whose checkpointed event aged out of the window, so
      // verify_activity_chain's binding stays valid — a checkpoint pointing at a
      // dropped event would otherwise report as a (spurious) mismatch.
      if (this.chainCheckpoints.length > 0) {
        const liveIds = new Set(this.activityLog.map(e => e.event_id));
        this.chainCheckpoints = this.chainCheckpoints.filter(cp => liveIds.has(cp.event_id));
      }
    }
    // Frontier linkage observation: update status for items this event touches.
    // Guarded so legacy code paths that initialise EngineContext indirectly
    // won't crash if the tracker hasn't been wired yet.
    if (options.observeLinkage !== false && this.frontierLinkage) {
      this.frontierLinkage.observe(entry);
    }
    options.items?.push(structuredClone({
      entry,
      ...(emittedCheckpoint ? { checkpoint: emittedCheckpoint } : {}),
    }));
    return entry;
  }

  /**
   * Build the immutable bounded activity delta without leaving speculative
   * changes in live state. Array references are restored in O(appended items):
   * tieredTruncate returns a new array and never mutates historical entries.
   */
  prepareActivityAppend(event: ActivityLogInput): {
    payload: ActivityAppendPayloadV1;
    result: ActivityLogEntry;
  } {
    this.persistenceWriteGuard?.();
    const activityRef = this.activityLog;
    const activityLength = activityRef.length;
    const checkpointRef = this.chainCheckpoints;
    const checkpointLength = checkpointRef.length;
    const actionId = event.action_id;
    const actionBefore = actionId
      ? structuredClone(this.actionFrontierMap.get(actionId))
      : undefined;
    const expected: ActivityAppendPayloadV1['expected'] = {
      activity_length: activityLength,
      activity_tail_event_id: activityRef.at(-1)?.event_id ?? null,
      last_chain_hash: this.lastChainHash,
      chain_events_since_checkpoint: this.chainEventsSinceCheckpoint,
      checkpoint_count: checkpointLength,
      checkpoint_tail_event_id: checkpointRef.at(-1)?.event_id ?? null,
      deterministic_seq: this.deterministicSeq,
    };
    const items: ActivityAppendItemV1[] = [];
    const baselineLastChainHash = this.lastChainHash;
    const baselineChainEvents = this.chainEventsSinceCheckpoint;
    const baselineDeterministicSeq = this.deterministicSeq;
    try {
      const result = this.appendActivityEventInMemory(event, {
        items,
        observeLinkage: false,
      });
      const actionAfter = actionId
        ? structuredClone(this.actionFrontierMap.get(actionId))
        : undefined;
      const mappingChanged = actionId
        && actionAfter !== undefined
        && JSON.stringify(actionBefore ?? null) !== JSON.stringify(actionAfter);
      return {
        payload: structuredClone({
          payload_version: ACTIVITY_APPEND_PAYLOAD_VERSION,
          items,
          result_event_id: result.event_id,
          expected,
          final: {
            last_chain_hash: this.lastChainHash,
            chain_events_since_checkpoint: this.chainEventsSinceCheckpoint,
            deterministic_seq: this.deterministicSeq,
          },
          ...(mappingChanged
            ? {
                action_frontier_update: {
                  action_id: actionId,
                  before: actionBefore ?? null,
                  after: actionAfter,
                },
              }
            : {}),
        }),
        result: structuredClone(result),
      };
    } finally {
      activityRef.length = activityLength;
      this.activityLog = activityRef;
      checkpointRef.length = checkpointLength;
      this.chainCheckpoints = checkpointRef;
      if (actionId) {
        if (actionBefore) this.actionFrontierMap.set(actionId, actionBefore);
        else this.actionFrontierMap.delete(actionId);
      }
      this.lastChainHash = baselineLastChainHash;
      this.chainEventsSinceCheckpoint = baselineChainEvents;
      this.deterministicSeq = baselineDeterministicSeq;
    }
  }

  /**
   * Canonical live/recovery applier for `activity_append`. Entries already
   * contain finalized IDs, timestamps, chain hashes, and signatures; replay
   * never regenerates nondeterministic material.
   */
  applyActivityAppend(
    payload: ActivityAppendPayloadV1,
  ): MutationApplyResult {
    if (payload.payload_version !== ACTIVITY_APPEND_PAYLOAD_VERSION) {
      return {
        status: 'skipped',
        reason: `unsupported activity_append payload version: ${String(payload.payload_version)}`,
      };
    }
    const expected = payload.expected;
    const continuityMatches =
      this.activityLog.length === expected.activity_length
      && (this.activityLog.at(-1)?.event_id ?? null) === expected.activity_tail_event_id
      && this.lastChainHash === expected.last_chain_hash
      && this.chainEventsSinceCheckpoint === expected.chain_events_since_checkpoint
      && this.chainCheckpoints.length === expected.checkpoint_count
      && (this.chainCheckpoints.at(-1)?.event_id ?? null) === expected.checkpoint_tail_event_id
      && this.deterministicSeq === expected.deterministic_seq;
    if (!continuityMatches) {
      return {
        status: 'skipped',
        reason: 'activity_append continuity does not match the restored activity tail',
      };
    }
    const frontierUpdate = payload.action_frontier_update;
    if (frontierUpdate) {
      const current = this.actionFrontierMap.get(frontierUpdate.action_id) ?? null;
      if (JSON.stringify(current) !== JSON.stringify(frontierUpdate.before)) {
        return {
          status: 'skipped',
          reason: `activity_append action mapping changed before ${frontierUpdate.action_id}`,
        };
      }
    }

    const activityRef = this.activityLog;
    const activityLength = activityRef.length;
    const checkpointRef = this.chainCheckpoints;
    const checkpointLength = checkpointRef.length;
    const baselineLastChainHash = this.lastChainHash;
    const baselineChainEvents = this.chainEventsSinceCheckpoint;
    const baselineDeterministicSeq = this.deterministicSeq;
    const actionBefore = frontierUpdate
      ? structuredClone(this.actionFrontierMap.get(frontierUpdate.action_id))
      : undefined;
    const linkageBefore = new Map<string, ReturnType<FrontierLinkageTracker['get']>>();
    for (const item of payload.items) {
      const frontierId = item.entry.frontier_item_id;
      if (!frontierId || linkageBefore.has(frontierId)) continue;
      const record = this.frontierLinkage.get(frontierId);
      linkageBefore.set(frontierId, record ? structuredClone(record) : undefined);
    }
    try {
      if (frontierUpdate) {
        this.actionFrontierMap.set(
          frontierUpdate.action_id,
          structuredClone(frontierUpdate.after),
        );
      }
      for (const item of payload.items) {
        if (item.checkpoint) {
          this.chainCheckpoints.push(structuredClone(item.checkpoint));
        }
        const entry = structuredClone(item.entry);
        this.activityLog.push(entry);
        if (this.activityLog.length > MAX_ACTIVITY_LOG_ENTRIES) {
          this.activityLog = tieredTruncate(
            this.activityLog,
            MAX_ACTIVITY_LOG_ENTRIES,
          );
          if (this.chainCheckpoints.length > 0) {
            const liveIds = new Set(this.activityLog.map(candidate => candidate.event_id));
            this.chainCheckpoints = this.chainCheckpoints
              .filter(checkpoint => liveIds.has(checkpoint.event_id));
          }
        }
        this.frontierLinkage.observe(entry);
      }
      this.lastChainHash = payload.final.last_chain_hash;
      this.chainEventsSinceCheckpoint = payload.final.chain_events_since_checkpoint;
      this.deterministicSeq = payload.final.deterministic_seq;
      return { status: 'applied' };
    } catch (error) {
      activityRef.length = activityLength;
      this.activityLog = activityRef;
      checkpointRef.length = checkpointLength;
      this.chainCheckpoints = checkpointRef;
      this.lastChainHash = baselineLastChainHash;
      this.chainEventsSinceCheckpoint = baselineChainEvents;
      this.deterministicSeq = baselineDeterministicSeq;
      if (frontierUpdate) {
        if (actionBefore) {
          this.actionFrontierMap.set(frontierUpdate.action_id, actionBefore);
        } else {
          this.actionFrontierMap.delete(frontierUpdate.action_id);
        }
      }
      for (const [frontierId, baseline] of linkageBefore) {
        const current = this.frontierLinkage.get(frontierId);
        if (current && baseline) {
          const mutable = current as unknown as Record<string, unknown>;
          for (const key of Object.keys(mutable)) delete mutable[key];
          Object.assign(current, baseline);
        }
      }
      throw error;
    }
  }

  rebuildActionFrontierMap(): void {
    this.actionFrontierMap.clear();
    for (const entry of this.activityLog) {
      if (entry.action_id && entry.frontier_item_id) {
        this.actionFrontierMap.set(entry.action_id, {
          frontier_item_id: entry.frontier_item_id,
          agent_id: entry.agent_id,
          frontier_type: entry.frontier_type,
        });
      }
    }
  }

  /**
   * Rebuild the running hash-chain tail from the persisted activity log.
   * Walks the log in order and adopts the last `event_hash` from a chained
   * entry. Should be called after loading state from disk so subsequent
   * `logEvent` calls extend the same chain.
   */
  rebuildChainTail(): void {
    let last = GENESIS_HASH;
    for (const entry of this.activityLog) {
      if (entry.event_hash) last = entry.event_hash;
    }
    this.lastChainHash = last;
  }

  invalidatePathGraph(): void {
    this.pathGraphCache.clear();
    this.communityCache = null;
  }

  fireUpdateCallbacks(detail: GraphUpdateDetail): void {
    for (const cb of this.updateCallbacks) {
      try { cb(detail); } catch { /* dashboard errors must not break engine */ }
    }
  }
}

export function normalizeActivityLogEntry(
  entry: Partial<ActivityLogEntry> & { description: string; timestamp?: string },
): ActivityLogEntry {
  const resolvedCategory = entry.category || inferCategoryFromEventType(entry.event_type);
  const resolvedOutcome = entry.outcome
    || normalizeOutcome(entry.result_classification, entry.validation_result)
    || inferOutcomeFromEventType(entry.event_type);
  const resolvedProvenance = entry.provenance || inferProvenance(entry, resolvedCategory);
  const resolvedSourceKind = entry.source_kind || inferSourceKind(entry, resolvedProvenance, resolvedCategory);
  const operatorName = entry.operator_name || (resolvedSourceKind === 'primary' ? process.env.OVERWATCH_OPERATOR_NAME : undefined);
  const operatorModel = entry.operator_model || (resolvedSourceKind === 'primary' ? process.env.OVERWATCH_OPERATOR_MODEL : undefined);
  return {
    event_id: entry.event_id || uuidv4(),
    timestamp: entry.timestamp || new Date().toISOString(), // clock-ok: defensive fallback; the deterministic caller (logEvent) sets timestamp via nowIso() upstream
    description: entry.description,
    agent_id: entry.agent_id,
    source_kind: resolvedSourceKind,
    operator_model: operatorModel,
    operator_name: operatorName,
    operator_session_id: entry.operator_session_id,
    provenance: resolvedProvenance,
    category: resolvedCategory,
    frontier_type: entry.frontier_type,
    outcome: resolvedOutcome,
    action_id: entry.action_id,
    event_type: entry.event_type,
    tool_name: entry.tool_name,
    technique: entry.technique,
    command_repr: entry.command_repr,
    target_node_ids: entry.target_node_ids,
    target_ips: entry.target_ips,
    target_cidrs: entry.target_cidrs,
    target_edge: entry.target_edge,
    frontier_item_id: entry.frontier_item_id,
    validation_result: entry.validation_result,
    result_classification: entry.result_classification,
    linked_finding_ids: entry.linked_finding_ids,
    linked_agent_task_id: entry.linked_agent_task_id,
    noise_estimate: entry.noise_estimate,
    noise_actual: entry.noise_actual,
    details: entry.details,
    prev_hash: entry.prev_hash,
    event_hash: entry.event_hash,
    chain_excluded: entry.chain_excluded,
  };
}

function inferSourceKind(
  entry: Partial<ActivityLogEntry>,
  provenance: ActivityProvenance,
  category: ActivityLogEntry['category'] | undefined,
): ActivityLogEntry['source_kind'] {
  const details = entry.details || {};
  const source = typeof details.source === 'string' ? details.source.toLowerCase() : '';
  const invokingTool = typeof details.invoking_tool === 'string' ? details.invoking_tool.toLowerCase() : '';
  if (source === 'dashboard' || invokingTool === 'dashboard') return 'dashboard';
  if (source.includes('runner') || invokingTool.includes('runner')) return 'runner';
  if (entry.agent_id || typeof details.agent_id === 'string' || category === 'agent') return 'subagent';
  if (category === 'system' || provenance === 'system' || provenance === 'inferred') return 'system';
  return 'primary';
}

function normalizeOutcome(
  resultClassification?: ActivityLogEntry['result_classification'],
  validationResult?: ActivityLogEntry['validation_result'],
): ActivityLogEntry['outcome'] | undefined {
  if (resultClassification === 'success') return 'success';
  if (resultClassification === 'failure') return 'failure';
  if (resultClassification === 'partial' || resultClassification === 'neutral') return 'neutral';

  if (validationResult === 'invalid') return 'failure';
  if (validationResult === 'warning_only') return 'neutral';
  if (validationResult === 'valid') return 'success';

  return undefined;
}

function inferCategoryFromEventType(eventType?: ActivityEventType): ActivityLogEntry['category'] | undefined {
  if (!eventType) return undefined;
  if (eventType.startsWith('action_')) return 'frontier';
  if (eventType.startsWith('finding_') || eventType === 'parse_output') return 'finding';
  if (eventType.startsWith('inference_')) return 'inference';
  if (eventType.startsWith('objective_')) return 'objective';
  if (eventType.startsWith('agent_')) return 'agent';
  if (eventType.startsWith('session_') || eventType === 'scope_updated' || eventType === 'graph_corrected' || eventType === 'instrumentation_warning' || eventType === 'credential_degradation' || eventType === 'system') return 'system';
  return undefined;
}

function inferOutcomeFromEventType(eventType?: ActivityEventType): ActivityLogEntry['outcome'] | undefined {
  if (!eventType) return undefined;
  if (eventType === 'action_completed' || eventType === 'finding_reported' || eventType === 'finding_ingested' || eventType === 'objective_achieved' || eventType === 'session_access_confirmed') return 'success';
  if (eventType === 'action_failed' || eventType === 'session_error') return 'failure';
  if (eventType === 'action_planned' || eventType === 'action_started' || eventType === 'action_validated') return 'neutral';
  return undefined;
}

/**
 * Infer activity provenance when the caller doesn't set it explicitly.
 *  - explicit `provenance` always wins (handled at the call site)
 *  - inference rule output is `'inferred'`
 *  - graph_corrected / instrumentation_warning / scope_updated / system events default to `'system'`
 *  - anything with an agent_id defaults to `'agent'`
 *  - everything else defaults to `'system'`
 */
function inferProvenance(
  entry: Partial<ActivityLogEntry>,
  category: ActivityLogEntry['category'] | undefined,
): ActivityProvenance {
  if (entry.event_type === 'inference_generated') return 'inferred';
  if (entry.event_type === 'system' || entry.event_type === 'instrumentation_warning'
      || entry.event_type === 'graph_corrected' || entry.event_type === 'scope_updated') return 'system';
  if (entry.agent_id) return 'agent';
  if (category === 'system') return 'system';
  if (category === 'inference') return 'inferred';
  return 'agent';
}

const MILESTONE_EVENT_TYPES: Set<ActivityEventType | undefined> = new Set([
  'objective_achieved',
  'action_completed',
  'action_failed',
  'finding_ingested',
  'finding_reported',
  'scope_updated',
  'credential_degradation',
  'session_access_confirmed',
  // Causal-linkage events needed by retrospective analysis and evidence attribution
  'action_validated',
  'parse_output',
  'instrumentation_warning',
  'session_access_unconfirmed',
  'session_error',
  'graph_corrected',
]);

export function isMilestoneEntry(entry: ActivityLogEntry): boolean {
  return MILESTONE_EVENT_TYPES.has(entry.event_type);
}

/**
 * Tiered truncation: preserves all milestone events (objectives, completed
 * actions, ingested findings) while trimming ephemeral events (action_started,
 * inference_generated, system) to stay within the budget.
 */
export function tieredTruncate(log: ActivityLogEntry[], budget: number): ActivityLogEntry[] {
  if (log.length <= budget) return log;

  // Bounded rolling window that preserves chain integrity: keep the MOST-RECENT
  // entries up to `budget`, prioritising chained (event_hash) > milestone >
  // ephemeral, and emit survivors in ORIGINAL order (never re-sort — that could
  // reorder chained entries and break the hash chain). The chained entries we
  // keep are the most-recent ones, so the surviving chained subsequence stays
  // contiguous (we only ever drop the OLDEST chained PREFIX) — verifyChain seeds
  // from the window's first prev_hash and checkpoints for aged-out events are
  // pruned by the caller. This bounds growth (the old code kept ALL chained
  // entries → unbounded) while never dropping a chained entry from the middle.
  const keep = new Array(log.length).fill(false);
  let kept = 0;
  const fill = (pred: (e: ActivityLogEntry) => boolean): void => {
    for (let i = log.length - 1; i >= 0 && kept < budget; i -= 1) {
      if (keep[i]) continue;
      if (pred(log[i])) { keep[i] = true; kept += 1; }
    }
  };
  fill(e => e.event_hash !== undefined); // most-recent chained first (contiguous suffix)
  fill(isMilestoneEntry);                 // then recent milestones
  fill(() => true);                       // then recent ephemeral to fill the budget

  return log.filter((_, i) => keep[i]);
}
