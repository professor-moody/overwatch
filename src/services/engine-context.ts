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
import { ColdStore } from './cold-store.js';
import { OpsecTracker } from './opsec-tracker.js';
import { PendingActionQueue } from './pending-action-queue.js';
import type { DurableApprovalRecord } from './pending-action-queue.js';
import { FrontierLinkageTracker } from './frontier-linkage.js';
import { computeEventHash, shouldChainEntry, GENESIS_HASH, buildCheckpoint, signCheckpoint, loadCheckpointSigningKey, shouldEmitCheckpoint, type ChainCheckpoint, type CheckpointEmitOptions } from './activity-chain.js';
import { eventIdOrUuid } from './deterministic-id.js';
import { FrontierLeases } from './frontier-leases.js';
import { MutationJournal, type MutationType } from './mutation-journal.js';
import { ProposedPlanStore } from './proposed-plan-store.js';
import { AgentQueryStore } from './agent-query-store.js';

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
  updateCallbacks: GraphUpdateCallback[];
  lastSnapshotTime: number;
  pathGraphCache: Map<string, OverwatchGraph>;  // cached undirected projections keyed by optimize mode
  communityCache: Map<string, number> | null;  // cached Louvain community assignments
  trackedProcesses: TrackedProcess[];
  actionFrontierMap: Map<string, { frontier_item_id: string; agent_id?: string; frontier_type?: ActivityLogEntry['frontier_type'] }>;
  coldStore: ColdStore;
  opsecTracker: OpsecTracker;
  pendingActionQueue: PendingActionQueue;
  // 3A.2: planner-proposed plans awaiting operator confirmation. In-memory only
  // (a plan can be re-proposed), shared between the propose_plan tool and the
  // dashboard confirm path.
  proposedPlanStore: ProposedPlanStore;
  // 3D: agent→operator questions awaiting an answer. In-memory; the ask_operator
  // tool writes, the dashboard answers, the heartbeat path drains answers back.
  agentQueryStore: AgentQueryStore;
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
  /** Set during WAL replay so the guarded mutators (addNode/addEdge) re-apply
   *  state without re-emitting their edge-case events (the type-conflict warning
   *  + inferred-edge-confirmation log) into the already-restored activity log. */
  suppressMutationEvents = false;

  constructor(graph: OverwatchGraph, config: EngagementConfig, stateFilePath: string) {
    this.graph = graph;
    this.config = config;
    this.inferenceRules = [];
    this.activityLog = [];
    this.agents = new Map();
    this.campaigns = new Map();
    this.agentDirectives = new Map();
    this.stateFilePath = stateFilePath;
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
    // P2.1: WAL is opt-in via engagement_nonce — same migration boundary
    // as deterministic IDs. Legacy engagements (no nonce) skip journaling
    // entirely so existing tests / state files continue to behave as before.
    this.mutationJournal = config.engagement_nonce ? new MutationJournal(stateFilePath) : null;
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
  journalMutation(type: MutationType, payload: Record<string, unknown>, source_action_id?: string): void {
    if (!this.mutationJournal) return;
    this.mutationJournal.append({
      type,
      payload,
      ...(source_action_id ? { source_action_id } : {}),
      ts: this.nowIso(),
    });
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

  logEvent(event: Omit<Partial<ActivityLogEntry>, 'event_id' | 'timestamp'> & { description: string }): ActivityLogEntry {
    // Auto-thread frontier_item_id from action_id mapping when caller omits it.
    // Guard against cross-agent action_id collisions: only cache/inherit when
    // the agent_id is consistent with the first writer.
    let enriched = event;
    if (event.action_id && event.frontier_item_id) {
      const existing = this.actionFrontierMap.get(event.action_id);
      if (existing && existing.agent_id && event.agent_id && existing.agent_id !== event.agent_id) {
        // Different agent reusing the same action_id — log a warning instead of overwriting
        this.logEvent({
          description: `action_id ${event.action_id} collision: agent "${event.agent_id}" tried to associate fi "${event.frontier_item_id}" but it is already mapped to fi "${existing.frontier_item_id}" by agent "${existing.agent_id}"`,
          event_type: 'instrumentation_warning',
          category: 'system',
          action_id: undefined,
          frontier_item_id: undefined,
          agent_id: event.agent_id,
        });
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
    if (this.frontierLinkage) {
      this.frontierLinkage.observe(entry);
    }
    return entry;
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
