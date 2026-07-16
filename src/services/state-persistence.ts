// ============================================================
// Overwatch — State Persistence
// Handles persist, snapshot rotation, load, and recovery.
// All state access goes through the shared EngineContext.
//
// Write Coalescing:
// Rather than writing to disk on every mutation, the persist()
// method marks state dirty and schedules a debounced flush.
// Multiple rapid mutations coalesce into a single disk write.
// Safety valves: flushNow() for immediate write, shutdown hooks,
// and batchMutate() to suppress flushes during batch operations.
// ============================================================

import { readFileSync, writeFileSync, existsSync, renameSync, unlinkSync, readdirSync, openSync, fsyncSync, closeSync, lstatSync } from 'fs';
import { dirname, basename, isAbsolute, join, relative, resolve } from 'path';
import { createHash, randomUUID } from 'crypto';
import {
  EngineContext,
  normalizeActivityLogEntry,
  type OverwatchGraph,
  type GraphUpdateDetail,
  type ActivityLogEntry,
} from './engine-context.js';
import { FrontierLinkageTracker } from './frontier-linkage.js';
import { FrontierLeases } from './frontier-leases.js';
import {
  engagementConfigSchema,
  type EngagementConfig,
  type InferenceRule,
  type NodeProperties,
  type EdgeProperties,
  type PersistenceRecoveryStatus,
  type StateMigrationStatus,
} from '../types.js';
import { normalizeNodeProvenance } from './provenance-utils.js';
import { OpsecTracker } from './opsec-tracker.js';
import {
  MutationJournal,
  type MutationApplyResult,
  type MutationReplayResult,
  type ScopeUpdatedMutationPayloadV1,
  type DropNodeMutationPayloadV1,
  type IdentityRewriteMutationPayloadV1,
  type GraphCorrectedMutationPayloadV1,
} from './mutation-journal.js';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';
import { parseJsonBytes } from './durable-json.js';
import {
  deterministicCollisionEdgeKey,
  edgeIdentityMatches,
  preferredEdgeKey,
} from './edge-identity.js';
import {
  CURRENT_JOURNAL_VERSION,
  CURRENT_STATE_VERSION,
  LEGACY_JOURNAL_VERSION,
  LEGACY_STATE_VERSION,
  PersistedJournalVersionError,
  PersistedStateVersionError,
  detectJournalVersion,
  detectStateVersion,
  validatePersistedStateV1,
  type PersistedStateV1,
  type SupportedJournalVersion,
  type SupportedStateVersion,
} from './persisted-state.js';
import { buildArtifactReferences, mergeArtifactReferences } from './state-artifacts.js';
import type {
  EngineTransactionApplier,
  EngineTransactionApplyResult,
  EngineTransactionDraft,
} from './engine-transaction.js';
import type { DurableStatePatchV1 } from './durable-state-patch.js';
import type { ActivityAppendPayloadV1 } from './activity-append.js';
import {
  agentLabelOf,
  coordinationRecoveryWarning,
  mergeCoordinationRecoveryWarnings,
  normalizeAgentTask,
  resolveAgentIdentity,
  taskIdOf,
  type CoordinationRecoveryWarning,
} from './agent-identity.js';
import {
  acquireStateMigrationLease,
  activateStateMigration,
  assertStateMigrationWriteAllowed,
  assertStateMigrationSourcesUnchanged,
  completeStateMigration,
  createJournalUpgradeBackup,
  hasStateMigrationIntent,
  prepareStateMigrationBackup,
  stateMigrationLockDirectory,
  type MigrationBackupResult,
  type StateMigrationLeaseRelease,
  withStateMigrationWriteGuard,
} from './state-migration.js';

export const MAX_SNAPSHOTS = 5;
const WAL_COMPACTION_AUTHORITY_SEMANTICS = 'full_state_sha256_json_v1' as const;

function snapshotCollisionIdentity(path: string): { family: string; ordinal: number } | undefined {
  const name = basename(path);
  const match = /^(.*\.snap-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z-\d+)(?:-(\d{4}))?\.json$/.exec(name);
  if (!match) return undefined;
  return {
    family: match[1],
    ordinal: match[2] === undefined ? 0 : Number(match[2]),
  };
}

/** Snapshot paths sort oldest-first. A same-clock/PID exclusive-create retry
 * is newer than its unsuffixed predecessor even though plain lexical ordering
 * places `-0001` before `.json`. */
function compareSnapshotPaths(a: string, b: string): number {
  const aName = basename(a);
  const bName = basename(b);
  const aCollision = snapshotCollisionIdentity(aName);
  const bCollision = snapshotCollisionIdentity(bName);
  if (
    aCollision
    && bCollision
    && aCollision.family === bCollision.family
    && aCollision.ordinal !== bCollision.ordinal
  ) {
    return aCollision.ordinal - bCollision.ordinal;
  }
  const byName = aName.localeCompare(bName);
  return byName !== 0 ? byName : a.localeCompare(b);
}

/** The guarded engine mutators WAL replay routes through, so replay re-applies
 *  state via the SAME code path (and guards) as the live write instead of a
 *  parallel raw-graph reimplementation. GraphEngine satisfies this structurally. */
export interface ReplayMutators {
  addNode(props: NodeProperties): string;
  addEdge(source: string, target: string, props: EdgeProperties, replayEdgeId?: string): { id: string; isNew: boolean };
  applyScopeUpdatedMutation(payload: ScopeUpdatedMutationPayloadV1, recovery?: boolean): MutationApplyResult;
  applyDropNodeMutation(payload: DropNodeMutationPayloadV1, recovery?: boolean): MutationApplyResult;
  applyIdentityRewriteMutation(payload: IdentityRewriteMutationPayloadV1, recovery?: boolean): MutationApplyResult;
  applyGraphCorrectedMutation(payload: GraphCorrectedMutationPayloadV1, recovery?: boolean): MutationApplyResult;
  applyStatePatchMutation(payload: DurableStatePatchV1, recovery?: boolean): MutationApplyResult;
  prepareRecoveryCommit?(): void;
  completeRecoveryCommit?(): void;
  abortRecoveryReplay?(): void;
}

// --- Coalescing configuration ---
export const FLUSH_DEBOUNCE_MS = 100;   // Wait 100ms of quiet before flushing
export const FLUSH_MAX_DELAY_MS = 500;  // Maximum time between dirty and flush
export const PERSIST_RETRY_DELAYS_MS = [250, 1_000, 5_000, 30_000] as const;
export const LEGACY_JOURNAL_CHECKPOINT_SEMANTICS = 'contiguous_applied_v1' as const;
export const JOURNAL_CHECKPOINT_SEMANTICS = 'contiguous_committed_transactions_v2' as const;

function isTrustedJournalCheckpoint(
  semantics: unknown,
  journalVersion: SupportedJournalVersion,
): boolean {
  return journalVersion === CURRENT_JOURNAL_VERSION
    ? semantics === JOURNAL_CHECKPOINT_SEMANTICS
    : semantics === LEGACY_JOURNAL_CHECKPOINT_SEMANTICS;
}

class JournalRecoveryGateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JournalRecoveryGateError';
  }
}

class StateIntegrityError extends Error {
  constructor(message: string, readonly checkpoint?: number) {
    super(message);
    this.name = 'StateIntegrityError';
  }
}

export interface RestoreResult {
  status: 'restored' | 'seed_required' | 'degraded';
  source: PersistenceRecoveryStatus['source'];
  reason?: string;
  /** A checksummed rollback authority still owns the selected config/state and
   * must remain until GraphEngine durably synchronizes engagement.json. */
  rollback_pending?: boolean;
}

interface RestoreCandidate {
  source: 'state' | 'snapshot';
  path: string;
}

interface ValidatedRestoreCandidate extends RestoreCandidate {
  data: unknown;
  rawSha256: string;
  checkpoint: number;
  stateVersion: SupportedStateVersion;
  journalVersion: SupportedJournalVersion;
  /** Lower values are newer. The primary outranks an equal-checkpoint
   * snapshot; snapshots inherit listSnapshots()'s filename chronology. */
  newnessRank: number;
}

interface RestoredBase {
  source: 'state' | 'snapshot';
  path: string;
  data: unknown;
  checkpoint: number;
  stateVersion: SupportedStateVersion;
  journalVersion: SupportedJournalVersion;
  replay?: MutationReplayResult;
  repairedIncompleteTail?: {
    quarantine_path: string;
    dropped_bytes: number;
    committed_transactions: number;
  };
}

interface RestoredCheckpoint {
  checkpoint: number;
  trusted: boolean;
  stateVersion: SupportedStateVersion;
  journalVersion: SupportedJournalVersion;
  /** Only current-writer, checksum-bound full-state snapshots may authorize
   * deletion of WAL bytes. Legacy bases remain valid for recovery but are not
   * compaction authorities. */
  compactionTrusted?: boolean;
}

interface IntegrityRejectedBase {
  source: 'state' | 'snapshot';
  path: string;
  error: string;
  checkpoint?: number;
  newnessRank: number;
  stateVersion?: SupportedStateVersion;
}

interface RollbackIntentV1 {
  version: 1;
  checkpoint: number;
  /** Path relative to the state directory. The selected snapshot remains a
   * recovery anchor while every superseded snapshot is removed. */
  selected_snapshot: string;
  selected_snapshot_sha256: string;
  /** Digest of the canonical intent fields above. This distinguishes a valid
   * rollback authority from a torn/manually-corrupted sidecar. */
  intent_checksum: string;
}

// --- Module-level shutdown flusher registry ---
// One process-level listener per signal regardless of how many
// StatePersistence instances exist. Each instance registers its
// own flush callback into this set in its ctor and removes it on dispose().
const shutdownFlushers = new Set<() => void>();
let shutdownListenersInstalled = false;

function fireAllFlushers(): void {
  for (const fn of shutdownFlushers) {
    try { fn(); } catch { /* best effort */ }
  }
}

function ensureShutdownListenersInstalled(): void {
  if (shutdownListenersInstalled) return;
  shutdownListenersInstalled = true;
  process.on('SIGTERM', fireAllFlushers);
  process.on('SIGINT', fireAllFlushers);
  process.on('beforeExit', fireAllFlushers);
}

function registerShutdownFlusher(fn: () => void): void {
  ensureShutdownListenersInstalled();
  shutdownFlushers.add(fn);
}

function unregisterShutdownFlusher(fn: () => void): void {
  shutdownFlushers.delete(fn);
}

export interface PersistMetrics {
  flushCount: number;
  totalSerializeMs: number;
  totalWriteMs: number;
  coalescedCalls: number;  // persist() calls that were coalesced (didn't cause immediate write)
  lastFlushMs: number;
  lastFlushAt?: string;
  dirty: boolean;
}

export class StatePersistence {
  private ctx: EngineContext;
  private builtinRuleIds: Set<string>;
  private builtinRules: InferenceRule[];
  private createGraph: () => OverwatchGraph;

  // --- Write coalescing state ---
  private dirty = false;
  private pendingDetail: GraphUpdateDetail = {};
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private maxDelayTimer: ReturnType<typeof setTimeout> | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private retryDelayIndex = 0;
  private consecutivePersistenceFailures = 0;
  /** Once three writes fail in one process, target-facing work has already
   * frozen around that fact. A later background retry may make bytes durable,
   * but reopening mutations in-place would split runtime and persistence truth.
   * Only a clean restart clears this latch. */
  private persistenceFailureGateTripped = false;
  private lastPersistenceError: string | undefined;
  private recoveryReadOnlyReason: string | undefined;
  private pendingRecoveryCheckpoint: number | undefined;
  private pendingRecoverySource: 'state' | 'snapshot' | undefined;
  private journalAccessError: unknown | undefined;
  private batchDepth = 0;  // >0 means inside batchMutate, suppress auto-flush
  private metrics: PersistMetrics = {
    flushCount: 0,
    totalSerializeMs: 0,
    totalWriteMs: 0,
    coalescedCalls: 0,
    lastFlushMs: 0,
    dirty: false,
  };
  private shutdownHandlers: (() => void)[] = [];
  private recoveryStatus: PersistenceRecoveryStatus;
  private stateMigrationStatus: StateMigrationStatus = {
    status: 'not_checked',
    supported_state_version: CURRENT_STATE_VERSION,
    supported_journal_version: CURRENT_JOURNAL_VERSION,
    migration_required: false,
  };
  private migrationBackup: MigrationBackupResult | undefined;
  private journalUpgradeBackup: MigrationBackupResult | undefined;
  private releaseMigrationLease: StateMigrationLeaseRelease | undefined;
  /** Present only while an explicit rollback is being installed. Persisting
   * this marker in the replacement primary makes that primary authoritative on
   * restart before destructive snapshot/WAL cleanup resumes. */
  private rollbackIntent: RollbackIntentV1 | undefined;
  /** Configuration in the last checkpointed base. It intentionally does not
   * follow an uncheckpointed prefix applied during incomplete WAL replay. */
  private durableConfig: EngagementConfig | undefined;

  constructor(ctx: EngineContext, builtinRules: InferenceRule[], createGraph?: () => OverwatchGraph) {
    this.ctx = ctx;
    this.builtinRules = [...builtinRules];
    this.builtinRuleIds = new Set(builtinRules.map(r => r.id));
    this.createGraph = createGraph ?? (() => {
      throw new Error('A graph factory is required to validate persisted recovery bases');
    });
    const journal = this.ctx.mutationJournal;
    let initialLogicalOnDiskSeq = 0;
    let initialPhysicalFrameSeq = 0;
    if (journal) {
      try {
        initialLogicalOnDiskSeq = journal.getHighestPhysicalSeq();
        initialPhysicalFrameSeq = journal.getHighestPhysicalFrameSeq();
      } catch (error) {
        this.journalAccessError = error;
        const reason = this.describeJournalAccessFailure(error);
        this.recoveryReadOnlyReason = reason;
        journal.blockAppends(reason);
      }
    }
    this.recoveryStatus = {
      outcome: this.journalAccessError ? 'incomplete' : 'clean',
      source: 'fresh',
      complete: this.journalAccessError === undefined,
      writable: this.journalAccessError === undefined,
      ...(this.journalAccessError ? { reason: this.recoveryReadOnlyReason } : {}),
      base_checkpoint: 0,
      highest_allocated_seq: journal?.getHighestAllocatedSeq() ?? 0,
      highest_allocated_logical_seq: journal?.getHighestAllocatedSeq() ?? 0,
      highest_allocated_frame_seq: journal?.getHighestAllocatedFrameSeq() ?? 0,
      highest_on_disk_seq: initialLogicalOnDiskSeq,
      highest_physical_frame_seq: initialPhysicalFrameSeq,
      highest_contiguous_applied_seq: journal?.getAppliedThroughSeq() ?? 0,
      highest_contiguous_applied_logical_seq: journal?.getAppliedThroughSeq() ?? 0,
      consecutive_persistence_failures: 0,
      journal: {
        enabled: journal !== null,
        format_version: CURRENT_JOURNAL_VERSION,
        ...(journal ? { path: journal.getPath() } : {}),
        read: 0,
        attempted: 0,
        applied: 0,
        skipped: 0,
        failed: 0,
        malformed: false,
        preserved: this.journalAccessError !== undefined,
      },
    };
    this.ctx.persistenceWriteGuard = () => this.assertWritable();
    this.ctx.persistencePostCommitFailure = (seq, error) => {
      this.latchPostCommitApplyFailure(seq, error);
    };
    this.hookShutdown();
  }

  getRecoveryStatus(): PersistenceRecoveryStatus {
    const journal = this.ctx.mutationJournal;
    const journalBlockedReason = journal?.getAppendBlockedReason();
    let migrationBlockedReason: string | undefined;
    try {
      this.assertMigrationWriteAllowed();
    } catch (error) {
      migrationBlockedReason = error instanceof Error ? error.message : String(error);
    }
    const writeBlockedReason = journalBlockedReason ?? migrationBlockedReason;
    let logicalOnDiskHighest: number | undefined;
    let physicalFrameHighest: number | undefined;
    let observedJournalFormat: number | undefined;
    let journalHasData = false;
    try {
      logicalOnDiskHighest = journal?.getHighestPhysicalSeq();
      physicalFrameHighest = journal?.getHighestPhysicalFrameSeq();
      observedJournalFormat = journal?.getObservedFormatVersion();
      journalHasData = journal?.hasData() ?? false;
    } catch (error) {
      const accessReason = this.describeJournalAccessFailure(error);
      const reason = this.recoveryReadOnlyReason
        ? this.recoveryReadOnlyReason.includes(accessReason)
          ? this.recoveryReadOnlyReason
          : `${this.recoveryReadOnlyReason}; additionally, ${accessReason}`
        : accessReason;
      this.latchJournalRecoveryFailure({
        reason,
        error,
        malformed: false,
        accessFailure: true,
      });
      logicalOnDiskHighest = this.recoveryStatus.highest_on_disk_seq;
      physicalFrameHighest = this.recoveryStatus.highest_physical_frame_seq ?? 0;
      observedJournalFormat = undefined;
      journalHasData = journal !== null;
    }
    const highestAllocatedLogicalSeq = Math.max(
      this.recoveryStatus.highest_allocated_logical_seq
        ?? this.recoveryStatus.highest_allocated_seq,
      journal?.getHighestAllocatedSeq() ?? 0,
    );
    const highestAllocatedFrameSeq = Math.max(
      this.recoveryStatus.highest_allocated_frame_seq ?? 0,
      journal?.getHighestAllocatedFrameSeq() ?? 0,
    );
    const highestLogicalOnDiskSeq = logicalOnDiskHighest === undefined
      ? this.recoveryStatus.highest_on_disk_seq
      : Math.max(this.recoveryStatus.highest_on_disk_seq, logicalOnDiskHighest);
    const highestPhysicalFrameSeq = physicalFrameHighest === undefined
      ? this.recoveryStatus.highest_physical_frame_seq ?? 0
      : Math.max(
          this.recoveryStatus.highest_physical_frame_seq ?? 0,
          physicalFrameHighest,
        );
    const highestContiguousAppliedLogicalSeq = journal?.getAppliedThroughSeq()
      ?? this.recoveryStatus.highest_contiguous_applied_logical_seq
      ?? this.recoveryStatus.highest_contiguous_applied_seq;
    this.recoveryStatus = {
      ...this.recoveryStatus,
      highest_allocated_seq: highestAllocatedLogicalSeq,
      highest_allocated_logical_seq: highestAllocatedLogicalSeq,
      highest_allocated_frame_seq: highestAllocatedFrameSeq,
      highest_on_disk_seq: highestLogicalOnDiskSeq,
      highest_physical_frame_seq: highestPhysicalFrameSeq,
      highest_contiguous_applied_seq: highestContiguousAppliedLogicalSeq,
      highest_contiguous_applied_logical_seq: highestContiguousAppliedLogicalSeq,
    };
    return {
      ...this.recoveryStatus,
      state_migration: JSON.parse(JSON.stringify(this.stateMigrationStatus)) as StateMigrationStatus,
      ...(writeBlockedReason && !this.recoveryStatus.reason ? { reason: writeBlockedReason } : {}),
      outcome: writeBlockedReason ? 'incomplete' : this.recoveryStatus.outcome,
      complete: writeBlockedReason ? false : this.recoveryStatus.complete,
      writable: this.isWritable(),
      highest_allocated_seq: highestAllocatedLogicalSeq,
      highest_allocated_logical_seq: highestAllocatedLogicalSeq,
      highest_allocated_frame_seq: highestAllocatedFrameSeq,
      // Compaction legitimately removes replayed records from the active WAL.
      // Preserve the highest logical transaction and physical frame observed
      // during recovery while still allowing later live appends to advance.
      highest_on_disk_seq: highestLogicalOnDiskSeq,
      highest_physical_frame_seq: highestPhysicalFrameSeq,
      highest_contiguous_applied_seq: highestContiguousAppliedLogicalSeq,
      highest_contiguous_applied_logical_seq: highestContiguousAppliedLogicalSeq,
      consecutive_persistence_failures: this.consecutivePersistenceFailures,
      ...(this.lastPersistenceError ? { last_persistence_error: this.lastPersistenceError } : {}),
      journal: {
        ...this.recoveryStatus.journal,
        format_version: this.reportedJournalFormatVersion(observedJournalFormat),
        // Legacy engagements can acquire a journal in-process immediately
        // before their first composite mutation. Do not keep reporting the
        // constructor-time, disabled journal metadata after that transition.
        enabled: journal !== null,
        ...(journal ? { path: journal.getPath() } : {}),
        // An append/apply ambiguity blocks the journal outside the startup
        // replay path. Surface that the bytes remain available for recovery.
        preserved: this.recoveryStatus.journal.preserved
          || (journalBlockedReason !== undefined && journalHasData),
      },
    };
  }

  /**
   * Install a WAL created after startup and refresh the cached recovery
   * metadata atomically with the EngineContext transition. Legacy engagements
   * use this before their first composite mutation.
   */
  enableMutationJournal(journal: MutationJournal): void {
    journal.setMigrationOwnerToken(this.releaseMigrationLease?.token);
    this.ctx.mutationJournal = journal;
    this.recoveryStatus = {
      ...this.recoveryStatus,
      highest_allocated_seq: journal.getHighestAllocatedSeq(),
      highest_allocated_logical_seq: journal.getHighestAllocatedSeq(),
      highest_allocated_frame_seq: journal.getHighestAllocatedFrameSeq(),
      highest_on_disk_seq: Math.max(
        this.recoveryStatus.highest_on_disk_seq,
        journal.getHighestPhysicalSeq(),
      ),
      highest_physical_frame_seq: Math.max(
        this.recoveryStatus.highest_physical_frame_seq ?? 0,
        journal.getHighestPhysicalFrameSeq(),
      ),
      highest_contiguous_applied_seq: journal.getAppliedThroughSeq(),
      highest_contiguous_applied_logical_seq: journal.getAppliedThroughSeq(),
      journal: {
        ...this.recoveryStatus.journal,
        enabled: true,
        path: journal.getPath(),
      },
    };
  }

  isWritable(): boolean {
    if (
      this.recoveryReadOnlyReason !== undefined
      || this.ctx.mutationJournal?.getAppendBlockedReason() !== undefined
      || this.persistenceFailureGateTripped
      || this.consecutivePersistenceFailures >= 3
    ) {
      return false;
    }
    try {
      this.assertMigrationWriteAllowed();
      return true;
    } catch {
      return false;
    }
  }

  assertWritable(): void {
    if (this.isWritable()) return;
    let migrationReason: string | undefined;
    try {
      this.assertMigrationWriteAllowed();
    } catch (error) {
      migrationReason = error instanceof Error ? error.message : String(error);
    }
    const reason = this.recoveryReadOnlyReason
      ?? this.ctx.mutationJournal?.getAppendBlockedReason()
      ?? migrationReason
      ?? `state persistence failed ${this.consecutivePersistenceFailures} consecutive times`;
    throw new Error(`Durable mutations are disabled while persistence is degraded: ${reason}`);
  }

  assertMigrationWriteAllowed(): void {
    assertStateMigrationWriteAllowed(
      this.ctx.stateFilePath,
      this.releaseMigrationLease?.token,
    );
  }

  withMigrationWriteGuard<T>(operation: () => T): T {
    return withStateMigrationWriteGuard(
      this.ctx.stateFilePath,
      this.releaseMigrationLease?.token,
      operation,
    );
  }

  private describeJournalAccessFailure(error: unknown): string {
    const message = error instanceof Error ? error.message : String(error);
    const path = this.ctx.mutationJournal?.getPath()
      ?? MutationJournal.pathForState(this.ctx.stateFilePath);
    return `persisted WAL could not be read at ${path}: ${message}`;
  }

  /** Status assembly must itself remain available when the WAL cannot be read.
   * Record the access failure and return the best previously known physical
   * sequence without recursively entering the recovery-status builder. */
  private highestPhysicalSeqOr(fallback: number): number {
    const journal = this.ctx.mutationJournal;
    if (!journal) return fallback;
    try {
      return journal.getHighestPhysicalSeq();
    } catch (error) {
      this.journalAccessError ??= error;
      const accessReason = this.describeJournalAccessFailure(error);
      this.recoveryReadOnlyReason ??= accessReason;
      journal.blockAppends(this.recoveryReadOnlyReason);
      this.lastPersistenceError ??= error instanceof Error ? error.message : String(error);
      const previous = (this.recoveryStatus as PersistenceRecoveryStatus | undefined)
        ?.highest_on_disk_seq ?? 0;
      return Math.max(fallback, previous);
    }
  }

  /** Physical-frame counterpart to highestPhysicalSeqOr(). Journal-v2 uses
   * multiple begin/chunk/commit frames for one logical transaction, so this
   * high-water must remain independently inspectable. */
  private highestPhysicalFrameSeqOr(fallback: number): number {
    const journal = this.ctx.mutationJournal;
    if (!journal) return fallback;
    try {
      return journal.getHighestPhysicalFrameSeq();
    } catch (error) {
      this.journalAccessError ??= error;
      const accessReason = this.describeJournalAccessFailure(error);
      this.recoveryReadOnlyReason ??= accessReason;
      journal.blockAppends(this.recoveryReadOnlyReason);
      this.lastPersistenceError ??= error instanceof Error ? error.message : String(error);
      const previous = (this.recoveryStatus as PersistenceRecoveryStatus | undefined)
        ?.highest_physical_frame_seq ?? 0;
      return Math.max(fallback, previous);
    }
  }

  /** Permanently close this process's durable-mutation gate after discovering
   * an unreadable or semantically corrupt live WAL. Retrying an ordinary state
   * write cannot repair journal ordering, so this path deliberately bypasses
   * the transient persistence retry schedule. */
  private latchJournalRecoveryFailure(input: {
    reason: string;
    error?: unknown;
    malformed: boolean;
    accessFailure?: boolean;
    subject?: 'WAL' | 'state';
    quarantine?: boolean;
  }): JournalRecoveryGateError {
    const alreadyLatched = this.recoveryReadOnlyReason === input.reason;
    this.cancelTimers();
    this.cancelRetryTimer();
    this.dirty = false;
    this.pendingDetail = {};
    this.pendingRecoveryCheckpoint = undefined;
    this.pendingRecoverySource = undefined;
    this.recoveryReadOnlyReason = input.reason;
    if (input.accessFailure) this.journalAccessError = input.error ?? input.reason;
    const message = input.error instanceof Error
      ? input.error.message
      : input.error === undefined ? input.reason : String(input.error);
    this.lastPersistenceError = message;
    this.ctx.mutationJournal?.blockAppends(input.reason);
    let journalHasData = false;
    try { journalHasData = this.ctx.mutationJournal?.hasData() ?? false; } catch { journalHasData = true; }
    const quarantine = input.quarantine !== false && !alreadyLatched && journalHasData
      ? this.quarantineJournal()
      : {};
    this.recoveryStatus = {
      ...this.recoveryStatus,
      outcome: 'incomplete',
      complete: false,
      writable: false,
      reason: input.reason,
      last_persistence_error: message,
      journal: {
        ...this.recoveryStatus.journal,
        malformed: input.malformed,
        preserved: this.recoveryStatus.journal.preserved || journalHasData,
      },
    };
    if (!alreadyLatched) {
      const subject = input.subject ?? 'WAL';
      // eslint-disable-next-line no-console
      console.error(`[persistence] degraded read-only ${subject}: ${input.reason}`);
      try {
        this.ctx.logEvent({
          description: `${subject} integrity/access failure forced degraded read-only mode`,
          event_type: 'system',
          category: 'system',
          outcome: 'failure',
          result_classification: 'failure',
          details: {
            error: message,
            malformed: input.malformed,
            quarantine_path: quarantine.path,
            quarantine_error: quarantine.error,
          },
        });
      } catch { /* recovery gating cannot depend on diagnostic logging */ }
    }
    return new JournalRecoveryGateError(input.reason);
  }

  /** Mark the boot as a deliberate config seed.  Corruption-driven seeds are
   *  distinguished from a genuinely fresh engagement for readiness surfaces. */
  markConfigInitialization(reinitialized: boolean): void {
    this.recoveryStatus = {
      ...this.recoveryStatus,
      outcome: reinitialized ? 'reinitialized' : 'clean',
      source: 'config',
      complete: true,
      writable: this.isWritable(),
      ...(reinitialized ? { reason: 'no valid persisted base was available; state was reinitialized from config' } : {}),
    };
  }

  getDurableConfig(): EngagementConfig | undefined {
    return this.durableConfig
      ? JSON.parse(JSON.stringify(this.durableConfig)) as EngagementConfig
      : undefined;
  }

  /**
   * Mark state as dirty and schedule a coalesced flush.
   * This is the primary persist entry point — callers do NOT block on disk I/O.
   * Detail objects are merged so the final flush includes all changes.
   */
  persist(detail: GraphUpdateDetail = {}): void {
    this.assertWritable();
    this.mergeDetail(detail);
    this.dirty = true;

    // Fire update callbacks immediately — dashboard needs real-time deltas
    // even when the disk write is deferred.
    this.ctx.fireUpdateCallbacks(detail);

    // If inside a batch, don't schedule — batch end will flush
    if (this.batchDepth > 0) {
      this.metrics.coalescedCalls++;
      return;
    }

    this.scheduleFlush();
  }

  /**
   * Immediately write state to disk. Bypasses coalescing.
   * Use for: rollback, recovery, process shutdown, explicit sync points.
   */
  flushNow(failureSource: 'explicit_flush' | 'debounce' | 'max_delay' = 'explicit_flush'): void {
    this.cancelTimers();
    if (!this.dirty) return;
    this.assertWritable();
    try {
      this.writeStateToDisk();
      this.finishSuccessfulWrite();
    } catch (error) {
      if (error instanceof JournalRecoveryGateError) throw error;
      this.recordPersistenceFailure(error, failureSource);
      throw error;
    }
  }

  /**
   * Immediately write state to disk regardless of dirty flag.
   * Use for: initial persist after load, rollback overwrites.
   */
  persistImmediate(
    detail: GraphUpdateDetail = {},
    options: { rotateExisting?: boolean } = {},
  ): void {
    this.cancelTimers();
    this.assertWritable();
    try {
      this.writeStateToDisk({ rotateExisting: options.rotateExisting });
      this.ctx.fireUpdateCallbacks(detail);
      this.finishSuccessfulWrite();
    } catch (error) {
      if (error instanceof JournalRecoveryGateError) throw error;
      this.dirty = true;
      this.mergeDetail(detail);
      this.recordPersistenceFailure(error, 'immediate_flush');
      throw error;
    }
  }

  /**
   * Publish the first full-state recovery base for a fresh engagement.
   *
   * The empty-WAL precondition and atomic state replacement deliberately run
   * under one cross-process writer mutex. A cooperating journal writer cannot
   * append between validation and the checkpoint-zero rename.
   */
  persistBootstrapBase(detail: GraphUpdateDetail = {}): void {
    this.cancelTimers();
    this.assertWritable();
    try {
      this.withMigrationWriteGuard(() => {
        const journal = this.ctx.mutationJournal;
        if (!journal) {
          throw new Error('fresh engagement bootstrap requires an initialized mutation journal');
        }
        this.assertNoUsableBootstrapBaseAppeared();
        if (journal.hasData()) {
          throw new Error('fresh engagement bootstrap refused a nonempty WAL without a valid base');
        }
        this.writeStateToDiskUnlocked({ rotateExisting: false });
      });
      this.ctx.fireUpdateCallbacks(detail);
      this.finishSuccessfulWrite();
    } catch (error) {
      if (error instanceof JournalRecoveryGateError) throw error;
      this.dirty = true;
      this.mergeDetail(detail);
      this.recordPersistenceFailure(error, 'bootstrap_base');
      throw error;
    }
  }

  /**
   * Recovery selected `seed_required` before the in-memory seed was built.
   * Revalidate that decision under the writer mutex so a second fresh engine
   * cannot publish a different checkpoint-zero base and then be silently
   * overwritten by this constructor.
   */
  private assertNoUsableBootstrapBaseAppeared(): void {
    let candidates: RestoreCandidate[];
    try {
      candidates = this.collectRestoreCandidates();
    } catch (error) {
      throw new Error(
        `fresh engagement bootstrap could not revalidate recovery bases: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    for (const candidate of candidates) {
      let bytes: Buffer;
      try {
        bytes = this.readPersistedBytes(candidate.path);
      } catch (error) {
        throw new Error(
          `fresh engagement bootstrap found an unreadable ${candidate.source} recovery base at ${candidate.path}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }

      let data: unknown;
      try {
        data = parseJsonBytes(bytes);
      } catch {
        // Invalid legacy/config-seed leftovers were already rejected by the
        // recovery pass and remain eligible for deliberate replacement.
        continue;
      }

      try {
        this.validateStateBase(data);
        this.validateFullStateDetached(data, this.builtinRules);
      } catch (error) {
        const record = data && typeof data === 'object' && !Array.isArray(data)
          ? data as Record<string, unknown>
          : undefined;
        const hasExplicitVersion = record !== undefined
          && (
            Object.prototype.hasOwnProperty.call(record, 'state_version')
            || Object.prototype.hasOwnProperty.call(record, 'journal_version')
          );
        if (
          error instanceof StateIntegrityError
          || error instanceof PersistedStateVersionError
          || error instanceof PersistedJournalVersionError
          || hasExplicitVersion
        ) {
          throw new Error(
            `fresh engagement bootstrap found a protected ${candidate.source} recovery base at ${candidate.path}: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
        // A schema-invalid legacy candidate was part of the original
        // seed-required decision and is safe to replace from config.
        continue;
      }

      throw new Error(
        `a valid ${candidate.source} recovery base appeared during fresh engagement bootstrap at ${candidate.path}; restart and recover it instead of overwriting it`,
      );
    }
  }

  /**
   * Begin a batch: all persist() calls within the batch are coalesced,
   * and the actual disk write happens when the outermost batch ends.
   * Batches can nest.
   */
  beginBatch(): void {
    this.batchDepth++;
  }

  /**
   * End a batch. When the outermost batch ends, flushes if dirty.
   */
  endBatch(): void {
    if (this.batchDepth <= 0) return;
    this.batchDepth--;
    if (this.batchDepth === 0 && this.dirty) {
      this.scheduleFlush();
    }
  }

  /** Returns true if there are unflushed mutations. */
  isDirty(): boolean {
    return this.dirty;
  }

  /** Returns persistence performance metrics. */
  getMetrics(): Readonly<PersistMetrics> {
    return { ...this.metrics, dirty: this.dirty };
  }

  /** Reset metrics (e.g., for testing or retrospective boundary). */
  resetMetrics(): void {
    this.metrics = { flushCount: 0, totalSerializeMs: 0, totalWriteMs: 0, coalescedCalls: 0, lastFlushMs: 0, dirty: this.dirty };
  }

  // --- Scheduling ---

  private scheduleFlush(): void {
    this.metrics.coalescedCalls++;

    // Reset debounce timer (waits for quiet)
    if (this.debounceTimer !== null) {
      clearTimeout(this.debounceTimer);
    }
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      this.flushFromTimer('debounce');
    }, FLUSH_DEBOUNCE_MS);

    // Max-delay timer ensures we don't wait forever under continuous load
    if (this.maxDelayTimer === null) {
      this.maxDelayTimer = setTimeout(() => {
        this.maxDelayTimer = null;
        this.flushFromTimer('max_delay');
      }, FLUSH_MAX_DELAY_MS);
    }
  }

  private flushFromTimer(timerKind: 'debounce' | 'max_delay'): void {
    try {
      this.flushNow(timerKind);
    } catch { /* failure logging + bounded retry are handled centrally */ }
  }

  private cancelTimers(): void {
    if (this.debounceTimer !== null) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    if (this.maxDelayTimer !== null) {
      clearTimeout(this.maxDelayTimer);
      this.maxDelayTimer = null;
    }
  }

  private cancelRetryTimer(): void {
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }

  private scheduleRetry(): void {
    if (this.retryTimer !== null) return;
    const delay = PERSIST_RETRY_DELAYS_MS[Math.min(this.retryDelayIndex, PERSIST_RETRY_DELAYS_MS.length - 1)];
    this.retryDelayIndex = Math.min(this.retryDelayIndex + 1, PERSIST_RETRY_DELAYS_MS.length - 1);
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.retryFailedWrite();
    }, delay);
    this.retryTimer.unref?.();
  }

  private retryFailedWrite(): void {
    if (!this.dirty && this.pendingRecoveryCheckpoint === undefined) return;
    const recoveredDetail = { ...this.pendingDetail };
    try {
      if (this.pendingRecoveryCheckpoint !== undefined) {
        const checkpoint = this.pendingRecoveryCheckpoint;
        this.writeStateToDisk({
          journalCheckpointSeq: checkpoint,
          rotateExisting: false,
          allowIntegrityReplacement: this.pendingRecoverySource === 'snapshot',
        });
        this.finishRecoveryCheckpoint(checkpoint, this.pendingRecoverySource ?? 'state', {
          // The GraphEngine skipped startup reconciliation while recovery was
          // degraded. A late checkpoint cannot safely reopen writes in-place.
          restartRequired: true,
        });
      } else {
        this.writeStateToDisk();
      }
      this.finishSuccessfulWrite();
      // A failed persistImmediate never emitted its update callback.  A retry
      // success also changes the recovery/write-health surface, so publish one
      // consolidated refresh. Recovery-checkpoint retries deliberately keep
      // the gate closed until a clean restart runs startup reconciliation.
      this.ctx.fireUpdateCallbacks(recoveredDetail);
    } catch (error) {
      if (error instanceof JournalRecoveryGateError) return;
      this.recordPersistenceFailure(error, 'retry');
    }
  }

  private recordPersistenceFailure(error: unknown, source: string): void {
    const message = error instanceof Error ? error.message : String(error);
    this.consecutivePersistenceFailures++;
    this.lastPersistenceError = message;
    this.dirty = true;
    if (this.consecutivePersistenceFailures >= 3 && !this.persistenceFailureGateTripped) {
      this.persistenceFailureGateTripped = true;
      const restartReason = 'state persistence failed three consecutive times; restart required after durable recovery before writes resume';
      this.recoveryReadOnlyReason ??= restartReason;
      this.ctx.mutationJournal?.blockAppends(this.recoveryReadOnlyReason);
    }
    this.recoveryStatus = {
      ...this.recoveryStatus,
      outcome: this.persistenceFailureGateTripped ? 'incomplete' : this.recoveryStatus.outcome,
      complete: this.persistenceFailureGateTripped ? false : this.recoveryStatus.complete,
      writable: this.isWritable(),
      ...(this.recoveryReadOnlyReason ? { reason: this.recoveryReadOnlyReason } : {}),
      consecutive_persistence_failures: this.consecutivePersistenceFailures,
      last_persistence_error: message,
    };
    this.scheduleRetry();
    const activityTransactionRunner = this.ctx.activityTransactionRunner;
    try {
      // This diagnostic describes a state write that is already dirty and has
      // its bounded retry scheduled above. Running it through the ordinary
      // activity transaction boundary would append another transaction and
      // schedule debounce/max-delay flushes, multiplying persistence attempts.
      // Keep the event in the dirty in-memory state so the existing retry owns
      // its durability without recursively creating more persistence work.
      this.ctx.activityTransactionRunner = undefined;
      this.ctx.logEvent({
        description: `Scheduled state persistence flush failed (${source})`,
        category: 'system',
        event_type: 'system',
        result_classification: 'failure',
        details: {
          timer_kind: source,
          state_file: this.ctx.stateFilePath,
          error: message,
          consecutive_failures: this.consecutivePersistenceFailures,
          durable_mutations_blocked: this.consecutivePersistenceFailures >= 3 || this.recoveryReadOnlyReason !== undefined,
        },
      });
    } catch {
      // Persistence retry must never depend on diagnostic event emission.
    } finally {
      this.ctx.activityTransactionRunner = activityTransactionRunner;
    }
    // Persistence health can change after the original graph delta was already
    // delivered (for example, when the debounced flush exhausts retries). Push
    // an empty consolidated update so synchronized dashboard clients receive
    // the new recovery/write gate without waiting for another mutation or 503.
    this.ctx.fireUpdateCallbacks({});
  }

  private finishSuccessfulWrite(): void {
    const hadFailures = this.consecutivePersistenceFailures > 0;
    this.cancelRetryTimer();
    this.consecutivePersistenceFailures = 0;
    this.retryDelayIndex = 0;
    this.lastPersistenceError = undefined;
    this.dirty = false;
    this.pendingDetail = {};
    this.durableConfig = JSON.parse(JSON.stringify(this.ctx.config)) as EngagementConfig;
    this.recoveryStatus = {
      ...this.recoveryStatus,
      writable: this.isWritable(),
      consecutive_persistence_failures: 0,
    };
    delete this.recoveryStatus.last_persistence_error;
    if (hadFailures) {
      try {
        const restartRequired = this.recoveryReadOnlyReason?.includes('restart required') ?? false;
        this.ctx.logEvent({
          description: restartRequired
            ? 'State persistence checkpoint recovered after retry; restart required before writes resume'
            : 'State persistence recovered after retry',
          category: 'system',
          event_type: 'system',
          result_classification: 'success',
        });
      } catch {
        // The durable write already succeeded; diagnostics cannot reverse it.
      }
    }
  }

  /** Cancel any pending flush (for shutdown / disposal). */
  cancelPendingFlush(): void {
    this.cancelTimers();
    this.cancelRetryTimer();
  }

  // --- Detail merging ---

  private mergeDetail(detail: GraphUpdateDetail): void {
    for (const key of ['new_nodes', 'new_edges', 'updated_nodes', 'updated_edges', 'inferred_edges', 'removed_nodes', 'removed_edges'] as const) {
      const incoming = detail[key];
      if (incoming && incoming.length > 0) {
        const existing = this.pendingDetail[key];
        if (existing) {
          // Deduplicate while merging
          const set = new Set(existing);
          for (const item of incoming) set.add(item);
          (this.pendingDetail as Record<string, string[]>)[key] = [...set];
        } else {
          (this.pendingDetail as Record<string, string[]>)[key] = [...incoming];
        }
      }
    }
  }

  // --- Shutdown safety ---
  // Multiple StatePersistence instances (typical in tests, possible in
  // multi-engine setups) used to each register their own SIGTERM/SIGINT/
  // beforeExit listeners on `process`. With ~10+ engines that crosses
  // Node's default MaxListeners (10) and prints noisy warnings that hide
  // real lifecycle leaks. We instead keep a module-level set of pending
  // flushers and register exactly one process listener per signal.

  private hookShutdown(): void {
    const flush = () => {
      if (this.dirty || this.pendingRecoveryCheckpoint !== undefined) {
        this.cancelTimers();
        this.cancelRetryTimer();
        try { this.retryFailedWrite(); } catch { /* best effort on shutdown */ }
      }
    };

    this.shutdownHandlers = [flush];
    registerShutdownFlusher(flush);
  }

  /**
   * Tear down timers and process listeners. Call when the engine is shutting
   * down gracefully or in tests to avoid leaked listeners / stale timer writes.
   */
  dispose(): void {
    this.cancelTimers();
    this.cancelRetryTimer();
    for (const handler of this.shutdownHandlers) {
      unregisterShutdownFlusher(handler);
    }
    this.shutdownHandlers = [];
    this.ctx.persistenceWriteGuard = undefined;
    this.ctx.persistencePostCommitFailure = undefined;
    this.releaseHeldMigrationLease();
    this.ctx.mutationJournal?.dispose();
  }

  private releaseHeldMigrationLease(): void {
    const release = this.releaseMigrationLease;
    if (!release) return;
    release();
    this.ctx.mutationJournal?.setMigrationOwnerToken(undefined);
    this.releaseMigrationLease = undefined;
  }

  private acquireMigrationLease(): void {
    if (this.releaseMigrationLease) return;
    const release = acquireStateMigrationLease(this.ctx.stateFilePath);
    this.releaseMigrationLease = release;
    this.ctx.mutationJournal?.setMigrationOwnerToken(release.token);
  }

  // --- Core durable write logic ---

  private serializePersistedState(
    journalCheckpointSeq: number,
  ): PersistedStateV1 {
    const artifactReferences = mergeArtifactReferences(
      this.ctx.artifactReferences,
      buildArtifactReferences(
        this.ctx.stateFilePath,
        this.ctx.activityLog,
      ),
    );
    this.ctx.artifactReferences = JSON.parse(JSON.stringify(artifactReferences));
    return {
      state_version: CURRENT_STATE_VERSION,
      journal_version: CURRENT_JOURNAL_VERSION,
      config: this.ctx.config,
      graph: this.ctx.graph.export(),
      activityLog: this.ctx.activityLog,
      agents: Array.from(this.ctx.agents.entries()),
      coordinationRecoveryWarnings: this.ctx.coordinationRecoveryWarnings,
      campaigns: Array.from(this.ctx.campaigns.entries()),
      agentDirectives: Array.from(this.ctx.agentDirectives.entries()),
      approvalRequests: Array.from(this.ctx.approvalRequests.entries()),
      inferenceRules: this.ctx.inferenceRules.filter(rule => !this.builtinRuleIds.has(rule.id)),
      trackedProcesses: this.ctx.trackedProcesses,
      runtimeRuns: this.ctx.runtimeRuns,
      playbookRuns: Array.from(this.ctx.playbookRuns.entries()),
      sessionDescriptors: this.ctx.sessionDescriptors,
      proposedPlans: this.ctx.proposedPlanStore.serialize(),
      agentQueries: this.ctx.agentQueryStore.serialize(),
      commandPlans: Array.from(this.ctx.commandPlans.entries()),
      commandOutcomes: Array.from(this.ctx.commandOutcomes.entries()),
      coldStore: this.ctx.coldStore.export(),
      opsecTracker: this.ctx.opsecTracker.serialize(),
      frontierLinkage: this.ctx.frontierLinkage.serialize(),
      frontierLeases: this.ctx.frontierLeases.serialize(),
      frontierWeights: this.ctx.frontierWeights ?? { fan_out: {}, noise: {} },
      artifactReferences,
      chainCheckpoints: this.ctx.chainCheckpoints,
      chainEventsSinceCheckpoint: this.ctx.chainEventsSinceCheckpoint,
      deterministicSeq: this.ctx.deterministicSeq,
      recentFindingHashes: Array.from(this.ctx.recentFindingHashes.entries()),
      dedupCount: this.ctx.dedupCount,
      lastKnownPhaseId: this.ctx.lastKnownPhaseId,
      journalSnapshotSeq: journalCheckpointSeq,
      journalCheckpointSemantics: JOURNAL_CHECKPOINT_SEMANTICS,
      ...(this.rollbackIntent ? { rollbackIntent: this.rollbackIntent } : {}),
    };
  }

  private finishStateFormatWrite(): void {
    if (this.journalUpgradeBackup) {
      this.stateMigrationStatus = {
        status: 'migrated',
        supported_state_version: CURRENT_STATE_VERSION,
        supported_journal_version: CURRENT_JOURNAL_VERSION,
        observed_state_version: CURRENT_STATE_VERSION,
        observed_journal_version: LEGACY_JOURNAL_VERSION,
        migration_required: false,
        backup_path: this.journalUpgradeBackup.directory,
        backup_manifest_sha256: this.journalUpgradeBackup.manifest_sha256,
      };
      this.journalUpgradeBackup = undefined;
      this.releaseHeldMigrationLease();
      return;
    }
    if (this.migrationBackup) {
      if (!this.releaseMigrationLease) {
        throw new Error('state migration lease is missing at the V1 publication boundary');
      }
      completeStateMigration(this.ctx.stateFilePath, this.releaseMigrationLease.token);
      this.stateMigrationStatus = {
        status: 'migrated',
        supported_state_version: CURRENT_STATE_VERSION,
        supported_journal_version: CURRENT_JOURNAL_VERSION,
        observed_state_version: LEGACY_STATE_VERSION,
        observed_journal_version: LEGACY_JOURNAL_VERSION,
        migration_required: false,
        backup_path: this.migrationBackup.directory,
        backup_manifest_sha256: this.migrationBackup.manifest_sha256,
      };
      this.migrationBackup = undefined;
      this.releaseHeldMigrationLease();
      return;
    }
    if (this.stateMigrationStatus.status === 'not_checked') {
      this.stateMigrationStatus = {
        status: 'current',
        supported_state_version: CURRENT_STATE_VERSION,
        supported_journal_version: CURRENT_JOURNAL_VERSION,
        observed_state_version: CURRENT_STATE_VERSION,
        observed_journal_version: CURRENT_JOURNAL_VERSION,
        migration_required: false,
      };
    }
  }

  private writeStateToDisk(options: {
    journalCheckpointSeq?: number;
    rotateExisting?: boolean;
    allowIntegrityReplacement?: boolean;
  } = {}): void {
    this.withMigrationWriteGuard(() => this.writeStateToDiskUnlocked(options));
  }

  private writeStateToDiskUnlocked(options: {
    journalCheckpointSeq?: number;
    rotateExisting?: boolean;
    allowIntegrityReplacement?: boolean;
  }): void {
    this.assertMigrationWriteAllowed();
    const journalCheckpointSeq = options.journalCheckpointSeq
      ?? this.ctx.mutationJournal?.getAppliedThroughSeq()
      ?? 0;
    const serializeStart = Date.now();
    const data = this.serializePersistedState(journalCheckpointSeq);
    // A base may be perfectly usable for recovery while still being too old or
    // too weakly described to authorize deletion of WAL history. Bind every
    // state emitted by this writer to its exact JSON payload; snapshot rotation
    // only compacts against copies whose authority still verifies. Legacy or
    // unknown-marker files remain readable, while a recognized mismatch is
    // explicit corruption and can never be silently reseeded over.
    // Snapshot live values exactly once. Activity/event detail bags are
    // intentionally extensible and may contain getters or toJSON hooks; hashing
    // one evaluation and emitting a second could create a self-invalid state.
    const serializedData = JSON.parse(JSON.stringify(data)) as Record<string, unknown>;
    const payloadJson = JSON.stringify(serializedData);
    const json = JSON.stringify({
      ...serializedData,
      walCompactionAuthority: {
        semantics: WAL_COMPACTION_AUTHORITY_SEMANTICS,
        payload_sha256: createHash('sha256').update(payloadJson).digest('hex'),
      },
    });
    const serializeEnd = Date.now();
    this.metrics.totalSerializeMs += (serializeEnd - serializeStart);

    const writeStart = Date.now();

    // Atomic write: write to temp, fsync, then rename (atomic on POSIX)
    const stateDir = dirname(this.ctx.stateFilePath);
    mkdirDurable(stateDir);
    let primaryIsUsableBase = false;
    let primaryCheckpoint = 0;
    if (
      options.allowIntegrityReplacement !== true
      && existsSync(this.ctx.stateFilePath)
    ) {
      const primary = this.inspectPrimaryStateIntegrity();
      primaryIsUsableBase = primary.usable;
      primaryCheckpoint = primary.checkpoint;
    }
    // Every ordinary write is followed by retention pruning, even when the
    // 30-second rotation interval has not elapsed. Inspect retained recovery
    // heads before either replacement or pruning can change durable bytes.
    if (options.rotateExisting !== false) {
      this.assertNoBlockingRetainedStateIntegrity(primaryIsUsableBase);
    }

    const now = Date.now();
    const shouldRotate = options.rotateExisting !== false
      && existsSync(this.ctx.stateFilePath)
      && now - this.ctx.lastSnapshotTime >= 30000;
    // Preserve the established, checkpoint-aware rotation diagnostics before
    // the broader stale-writer comparison. Both checks run under the same
    // cross-process writer mutex and therefore describe one durable head.
    if (shouldRotate) this.assertSnapshotJournalIntegrity();
    if (options.allowIntegrityReplacement !== true && this.ctx.mutationJournal) {
      try {
        this.ctx.mutationJournal.assertCaughtUpForStateWrite(primaryCheckpoint);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const staleWriter = message.startsWith('writer is stale:');
        throw this.latchJournalRecoveryFailure({
          reason: `state replacement refused: ${message}`,
          error,
          malformed: false,
          subject: staleWriter ? 'state' : 'WAL',
          quarantine: !staleWriter,
        });
      }
    }

    // Rotate the current durable primary before creating the replacement temp.
    // This lets a WAL-integrity preflight fail without leaving a state temp that
    // could be mistaken for a completed checkpoint.
    if (shouldRotate) {
      this.rotateSnapshot();
      this.ctx.lastSnapshotTime = now;
    }

    const tmpPath = this.ctx.stateFilePath + '.tmp';
    writeFileSync(tmpPath, json);
    const fd = openSync(tmpPath, 'r');
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }

    if (process.platform === 'win32') {
      // Windows: rename may fail if target is locked; try unlink + rename as fallback
      try {
        renameSync(tmpPath, this.ctx.stateFilePath);
      } catch {
        try { unlinkSync(this.ctx.stateFilePath); } catch { /* target may not exist */ }
        renameSync(tmpPath, this.ctx.stateFilePath);
      }
    } else {
      renameSync(tmpPath, this.ctx.stateFilePath);
    }
    fsyncDirectory(stateDir);
    this.ctx.journalSnapshotSeq = journalCheckpointSeq;
    // A failed replacement must retain every snapshot that justified any
    // preceding WAL compaction. Prune only after the new primary rename and
    // its directory entry are durable.
    if (options.rotateExisting !== false) this.pruneSnapshotsBestEffort();
    this.finishStateFormatWrite();

    const writeEnd = Date.now();
    this.metrics.totalWriteMs += (writeEnd - writeStart);
    this.metrics.lastFlushMs = writeEnd - serializeStart;
    this.metrics.lastFlushAt = new Date(writeEnd).toISOString();
    this.metrics.flushCount++;
  }

  private assertSnapshotJournalIntegrity(): void {
    const journal = this.ctx.mutationJournal;
    if (!journal) return;
    let issue;
    try {
      issue = journal.inspectIntegrity(this.ctx.journalSnapshotSeq);
    } catch (error) {
      throw this.latchJournalRecoveryFailure({
        reason: this.describeJournalAccessFailure(error),
        error,
        malformed: false,
        accessFailure: true,
      });
    }
    if (issue) {
      throw this.latchJournalRecoveryFailure({
        reason: `snapshot WAL integrity preflight failed at line ${issue.line}: ${issue.reason}`,
        error: issue.reason,
        malformed: issue.kind === 'malformed_entry',
      });
    }
  }

  private rotateSnapshot(): void {
    const dir = dirname(this.ctx.stateFilePath);
    const base = basename(this.ctx.stateFilePath, '.json');
    const snapDir = join(dir, '.snapshots');
    const journal = this.ctx.mutationJournal;
    this.assertSnapshotJournalIntegrity();
    mkdirDurable(snapDir);
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    let snapPath: string | undefined;
    let snapFd: number | undefined;
    for (let collision = 0; collision < 10_000; collision++) {
      const suffix = collision === 0 ? '' : `-${String(collision).padStart(4, '0')}`;
      const candidate = join(snapDir, `${base}.snap-${ts}-${process.pid}${suffix}.json`);
      try {
        // Exclusive creation is essential: a repeated clock/PID tuple must
        // never truncate an existing recovery anchor before the new snapshot
        // has been copied and made durable.
        snapFd = openSync(candidate, 'wx');
        snapPath = candidate;
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') continue;
        throw error;
      }
    }
    if (snapFd === undefined || snapPath === undefined) {
      throw new Error('could not allocate a collision-free snapshot filename');
    }
    // Copy the current durable primary to a durable snapshot before replacing
    // it. Creation/fsync failures abort the entire persistence attempt.
    try {
      const stateBytes = this.readPersistedBytes(this.ctx.stateFilePath);
      writeFileSync(snapFd, stateBytes);
      fsyncSync(snapFd);
      closeSync(snapFd);
      snapFd = undefined;
      fsyncDirectory(snapDir);
    } catch (error) {
      if (snapFd !== undefined) {
        try { closeSync(snapFd); } catch { /* preserve the original copy error */ }
      }
      // The path was uniquely created by this attempt, so removing an
      // incomplete copy cannot harm any pre-existing recovery anchor.
      try {
        unlinkSync(snapPath);
        fsyncDirectory(snapDir);
      } catch { /* an invalid leftover is rejected by base validation */ }
      throw error;
    }
    // Compaction happens before the replacement primary rename. Never discard
    // WAL beyond the checkpoint already present in the durable primary: a crash
    // at this boundary must leave that primary able to replay its full suffix.
    if (journal) {
      const retained = this.oldestRetainedValidSnapshotCheckpoint();
      const upTo = retained === undefined
        ? undefined
        : Math.min(retained, this.ctx.journalSnapshotSeq);
      if (upTo !== undefined && upTo > 0) {
        try {
          const result = journal.compactUpTo(upTo);
          if ('preserved' in result) {
            throw this.latchJournalRecoveryFailure({
              reason: `snapshot WAL compaction refused: ${result.reason}`,
              error: result.reason,
              malformed: false,
            });
          }
        } catch (error) {
          if (error instanceof JournalRecoveryGateError) throw error;
          throw this.latchJournalRecoveryFailure({
            reason: this.describeJournalAccessFailure(error),
            error,
            malformed: false,
            accessFailure: true,
          });
        }
      }
    }
  }

  private assertNoBlockingRetainedStateIntegrity(primaryIsUsableBase: boolean): void {
    const stateDir = dirname(this.ctx.stateFilePath);
    let snapshots: string[];
    try {
      snapshots = this.listSnapshotsStrict();
    } catch (error) {
      throw new Error(
        `state replacement could not enumerate retained recovery snapshots: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    const candidates = snapshots.map(snapshot => ({
      path: join(stateDir, snapshot),
    }));
    for (const candidate of candidates) {
      let bytes: Buffer;
      try {
        bytes = this.readPersistedBytes(candidate.path);
      } catch (error) {
        throw new Error(
          `state replacement could not read retained recovery snapshot at ${candidate.path}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      try {
        const data = parseJsonBytes(bytes);
        this.validateStateBase(data);
      } catch (error) {
        if (
          (error instanceof PersistedStateVersionError
            || error instanceof PersistedJournalVersionError)
          && error.kind === 'unsupported'
        ) {
          throw new Error(
            `state replacement found an unsupported retained format at ${candidate.path}: ${error.message}`,
          );
        }
        if (!(error instanceof StateIntegrityError)) continue;
        const blocksReplacement = error.checkpoint === undefined
          || error.checkpoint > this.ctx.journalSnapshotSeq
          || (
            error.checkpoint === this.ctx.journalSnapshotSeq
            && !primaryIsUsableBase
          );
        if (!blocksReplacement) continue;
        throw this.latchJournalRecoveryFailure({
          reason: `state replacement found a blocking recognized integrity mismatch at ${candidate.path}: ${error.message}`,
          error,
          malformed: false,
          subject: 'state',
        });
      }
    }
  }

  private inspectPrimaryStateIntegrity(): { checkpoint: number; usable: boolean } {
    let bytes: Buffer;
    try {
      bytes = this.readPersistedBytes(this.ctx.stateFilePath);
    } catch (error) {
      throw new Error(
        `state replacement could not read the durable primary at ${this.ctx.stateFilePath}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    let data: unknown;
    try {
      data = parseJsonBytes(bytes);
    } catch {
      return { checkpoint: 0, usable: false };
    }
    const record = data && typeof data === 'object'
      ? data as Record<string, unknown>
      : undefined;
    const observedCheckpoint = record
      && Number.isSafeInteger(record.journalSnapshotSeq)
      && (record.journalSnapshotSeq as number) >= 0
      ? record.journalSnapshotSeq as number
      : 0;
    try {
      const validated = this.validateStateBase(data);
      this.validateFullStateDetached(data, this.builtinRules);
      return { checkpoint: validated.checkpoint, usable: true };
    } catch (error) {
      if (
        (error instanceof PersistedStateVersionError
          || error instanceof PersistedJournalVersionError)
        && error.kind === 'unsupported'
      ) {
        throw new Error(
          `state replacement found an unsupported durable primary format: ${error.message}`,
        );
      }
      if (!(error instanceof StateIntegrityError)) {
        return { checkpoint: observedCheckpoint, usable: false };
      }
      throw this.latchJournalRecoveryFailure({
        reason: `state replacement found a recognized integrity mismatch at ${this.ctx.stateFilePath}: ${error.message}`,
        error,
        malformed: false,
        subject: 'state',
      });
    }
  }

  /** Injectable seam for deterministic read-access failure tests. Production
   * callers always use the synchronous filesystem read. */
  private readPersistedBytes(path: string): Buffer {
    return readFileSync(path);
  }

  private pruneSnapshotsBestEffort(): void {
    const dir = dirname(this.ctx.stateFilePath);
    const base = basename(this.ctx.stateFilePath, '.json');
    const snapDir = join(dir, '.snapshots');
    if (!existsSync(snapDir)) return;
    // Retaining an extra snapshot is safe, so pruning alone remains best-effort.
    let snaps: string[];
    try {
      snaps = readdirSync(snapDir)
        .filter(f => f.startsWith(`${base}.snap-`) && f.endsWith('.json'))
        .sort(compareSnapshotPaths);
    } catch {
      return;
    }
    while (snaps.length > MAX_SNAPSHOTS) {
      const oldest = snaps.shift()!;
      try {
        unlinkSync(join(snapDir, oldest));
        fsyncDirectory(snapDir);
      } catch { /* best effort: an extra recovery anchor is safe */ }
    }
  }

  listSnapshots(): string[] {
    try {
      return this.listSnapshotsStrict();
    } catch {
      return [];
    }
  }

  private listSnapshotsStrict(): string[] {
    const dir = dirname(this.ctx.stateFilePath);
    const base = basename(this.ctx.stateFilePath, '.json');
    const snapDir = join(dir, '.snapshots');
    const results: string[] = [];
    if (!existsSync(dir)) return results;
    // Check new subdirectory location
    if (existsSync(snapDir)) {
      results.push(...readdirSync(snapDir)
        .filter(f => f.startsWith(`${base}.snap-`) && f.endsWith('.json'))
        .map(f => `.snapshots/${f}`));
    }
    // Check legacy same-directory location for backward compat
    results.push(...readdirSync(dir)
      .filter(f => f.startsWith(`${base}.snap-`) && f.endsWith('.json')));
    // Compare the snapshot filenames, not their storage-directory prefixes.
    // Otherwise every legacy root snapshot sorts after every `.snapshots/`
    // entry and is incorrectly tried first after the caller reverses the list.
    return results.sort(compareSnapshotPaths);
  }

  /** Return the oldest checkpoint for a retained snapshot that is itself a
   * usable full-state base. If none are valid, retaining the complete WAL is
   * the only safe compaction policy. */
  private oldestRetainedValidSnapshotCheckpoint(): number | undefined {
    const stateDir = dirname(this.ctx.stateFilePath);
    let oldest: number | undefined;
    for (const snapshot of this.listSnapshots()) {
      let data: unknown;
      try {
        data = parseJsonBytes(this.readPersistedBytes(join(stateDir, snapshot)));
      } catch {
        // An unreadable retained file may still be the oldest valid recovery
        // anchor. It cannot authorize deletion of any WAL bytes.
        return undefined;
      }
      try {
        const { checkpoint, trusted, compactionTrusted } = this.validateCompactionAnchor(data);
        // A legacy snapshot may contain an allocation-based overclaim. It is a
        // usable graph base, but not authority to delete *any* retained WAL
        // records. Disabling compaction preserves the suffix it may need and
        // any records at/below its unproven cursor.
        if (!trusted || !compactionTrusted) return undefined;
        oldest = oldest === undefined ? checkpoint : Math.min(oldest, checkpoint);
      } catch (error) {
        if (error instanceof JournalRecoveryGateError) throw error;
        // An invalid snapshot is not a recovery anchor and therefore cannot
        // justify discarding any WAL prefix.
      }
    }
    return oldest;
  }

  rollbackToSnapshot(
    snapshotName: string,
    builtinRules: InferenceRule[],
    options: { deferAuthorityRelease?: boolean } = {},
  ): boolean {
    const dir = dirname(this.ctx.stateFilePath);
    const candidates = this.listSnapshotsStrict().map(snapshot => join(dir, snapshot));
    const requested = isAbsolute(snapshotName)
      ? resolve(snapshotName)
      : resolve(dir, snapshotName);
    let snapPath = candidates.find(candidate => resolve(candidate) === requested);
    if (!snapPath) {
      // Preserve the legacy basename lookup, but only when it resolves to a
      // file that is actually in the enumerated snapshot inventory.
      const legacyRequested = resolve(dir, basename(snapshotName));
      snapPath = candidates.find(candidate => resolve(candidate) === legacyRequested);
    }
    if (!snapPath) return false;
    const stat = lstatSync(snapPath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`Rollback snapshot must be a regular retained file: ${snapshotName}`);
    }
    return withStateMigrationWriteGuard(
      this.ctx.stateFilePath,
      this.releaseMigrationLease?.token,
      () => this._rollbackFrom(
        snapPath,
        builtinRules,
        options.deferAuthorityRelease === true,
      ),
    );
  }

  private _rollbackFrom(
    snapPath: string,
    builtinRules: InferenceRule[],
    deferAuthorityRelease: boolean,
  ): boolean {
    // Read and perform structural validation before disturbing any pending
    // persistence work. A bad rollback input must not strand an otherwise
    // writable dirty engine with its debounce/retry timers cancelled.
    let snapshotBytes: Buffer;
    let data: unknown;
    let validated: RestoredCheckpoint;
    try {
      snapshotBytes = this.readPersistedBytes(snapPath);
      data = parseJsonBytes(snapshotBytes);
      validated = this.validateStateBase(data);
      this.assertLegacyRollbackCheckpointUnambiguous(validated);
    } catch (error) {
      throw new Error(
        `Rollback to ${basename(snapPath)} did not start: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    const snapshotSeq = validated.checkpoint;
    const intent = this.createRollbackIntent({
      version: 1,
      checkpoint: snapshotSeq,
      selected_snapshot: this.snapshotPathForIntent(snapPath),
      selected_snapshot_sha256: createHash('sha256').update(snapshotBytes).digest('hex'),
    });
    const baseline = this.captureRestoreBaseline();
    const baselineJournal = this.ctx.mutationJournal;

    try {
      // Fully deserialize the selected base before publishing the rollback
      // authority. validateStateBase deliberately validates only the fields
      // needed for base ranking; auxiliary persisted fields can still make the
      // complete restore fail. Such a target must never become a restart loop.
      this._restoreFromData(data, builtinRules);
      this.ensureJournalForRestoredConfig();
      if (validated.stateVersion === LEGACY_STATE_VERSION) {
        this.beginLegacyMigration();
      }

      // The sidecar is the rollback commit point. It survives corruption of the
      // replacement primary and still names a checksummed, retained full-state
      // base from which startup can finish the operation.
      this.writeRollbackAuthority(intent);
      // All work below belongs to the committed rollback. Prevent a pending
      // timer for the superseded in-memory head from writing over it.
      this.cancelTimers();
      this.cancelRetryTimer();
      this.ctx.mutationJournal?.setNextSeq(snapshotSeq, {
        preserveAllocated: true,
        appliedThroughSeq: snapshotSeq,
      });

      // Phase 1: make the rollback target the durable recovery head. A restart
      // that sees this marker must finish this rollback before comparing any
      // newer snapshot checkpoints or replaying the superseded WAL suffix.
      this.rollbackIntent = intent;
      this.writeStateToDisk({
        journalCheckpointSeq: snapshotSeq,
        rotateExisting: false,
        allowIntegrityReplacement: true,
      });
      this.durableConfig = JSON.parse(JSON.stringify(this.ctx.config)) as EngagementConfig;

      // Phase 2 is destructive but idempotent. It is safe only after the marked
      // primary above has reached stable storage.
      this.completeRollbackCleanup(intent);
      this.ctx.log('Rolled back to snapshot: ' + basename(snapPath), undefined, { category: 'system' });

      if (deferAuthorityRelease) {
        // engagement.json is synchronized by GraphEngine while both the
        // marked primary and sidecar still make the selected rollback the
        // only restart authority. A crash here therefore resumes this same
        // rollback instead of treating the newer config file as a choice.
        this.finishSuccessfulWrite();
        this.recoveryReadOnlyReason = undefined;
        this.recoveryStatus = this.buildRecoveryStatus({
          outcome: 'recovered',
          source: 'snapshot',
          complete: true,
          writable: true,
          checkpoint: snapshotSeq,
          preserved: false,
        });
        return true;
      }

      // Phase 3: clear the intent only after cleanup is durable. If this final
      // write fails, the marked primary remains and startup retries phase 2.
      this.rollbackIntent = undefined;
      this.writeStateToDisk({
        journalCheckpointSeq: snapshotSeq,
        rotateExisting: false,
        allowIntegrityReplacement: true,
      });
      this.removeRollbackAuthority();
      this.ctx.mutationJournal?.unblockAppends();
      this.finishSuccessfulWrite();
      this.ctx.fireUpdateCallbacks({});
      this.recoveryReadOnlyReason = undefined;
      this.recoveryStatus = this.buildRecoveryStatus({
        outcome: 'recovered',
        source: 'snapshot',
        complete: true,
        writable: true,
        checkpoint: snapshotSeq,
        preserved: false,
      });
      return true;
    } catch (error) {
      // Before the authority sidecar exists, disk still names the old head.
      // Restore the original in-memory state and leave its existing timers
      // alone so a malformed rollback target cannot suppress a pending write.
      if (!existsSync(this.rollbackAuthorityPath())) {
        this.rollbackIntent = undefined;
        this.ctx.mutationJournal = baselineJournal;
        if (validated.stateVersion === LEGACY_STATE_VERSION) {
          try {
            completeStateMigration(
              this.ctx.stateFilePath,
              this.releaseMigrationLease?.token,
            );
          } catch { /* retain backup for audit */ }
          this.migrationBackup = undefined;
          try { this.releaseHeldMigrationLease(); } catch { /* rollback error remains primary */ }
        }
        try {
          this.restoreRejectedCandidateBaseline(baseline, builtinRules);
        } catch (restoreError) {
          this.cancelTimers();
          this.cancelRetryTimer();
          this.latchRollbackFailure(
            new Error(
              `rollback failed (${error instanceof Error ? error.message : String(error)}) and the original in-memory state could not be restored (${restoreError instanceof Error ? restoreError.message : String(restoreError)})`,
            ),
            snapshotSeq,
            'snapshot',
          );
        }
        throw new Error(
          `Rollback to ${basename(snapPath)} did not start: ${error instanceof Error ? error.message : String(error)}`,
        );
      }

      // Keep the in-memory marker aligned with the durable marked primary when
      // one was installed. In all cases freeze writes: memory may already hold
      // the rollback target while disk still holds either the old or pending
      // head, so an ordinary retry would be unsafe.
      this.cancelTimers();
      this.cancelRetryTimer();
      this.rollbackIntent = intent;
      this.latchRollbackFailure(error, snapshotSeq, 'snapshot');
      throw new Error(
        `Rollback to ${basename(snapPath)} did not complete durably: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /** Release a rollback authority only after the external config file and the
   * marked durable state share the rollback target revision/hash. */
  completePendingRollbackAuthority(): void {
    withStateMigrationWriteGuard(
      this.ctx.stateFilePath,
      this.releaseMigrationLease?.token,
      () => {
        const intent = this.rollbackIntent;
        if (!intent) return;
        try {
          this.rollbackIntent = undefined;
          this.writeStateToDisk({
            journalCheckpointSeq: intent.checkpoint,
            rotateExisting: false,
            allowIntegrityReplacement: true,
          });
          this.removeRollbackAuthority();
          this.ctx.mutationJournal?.unblockAppends();
          this.finishSuccessfulWrite();
          this.recoveryReadOnlyReason = undefined;
          this.recoveryStatus = this.buildRecoveryStatus({
            outcome: 'recovered',
            source: 'snapshot',
            complete: true,
            writable: true,
            checkpoint: intent.checkpoint,
            preserved: false,
          });
        } catch (error) {
          this.rollbackIntent = intent;
          this.latchRollbackFailure(error, intent.checkpoint, 'snapshot');
          throw error;
        }
      },
    );
  }

  /** A legacy checkpoint can be promoted to the current trusted marker only
   * after a complete WAL scan proves it does not hide any retained record at
   * or below its claimed cursor. */
  private assertLegacyRollbackCheckpointUnambiguous(validated: RestoredCheckpoint): void {
    if (validated.trusted) return;
    let issue;
    try {
      issue = this.ctx.mutationJournal?.inspectReplayIntegrity(
        validated.checkpoint,
        { trustedContiguousCheckpoint: false },
      );
    } catch (error) {
      throw this.latchJournalRecoveryFailure({
        reason: this.describeJournalAccessFailure(error),
        error,
        malformed: false,
        accessFailure: true,
      });
    }
    if (!issue) return;
    if (issue.kind !== 'ambiguous_checkpoint') {
      throw this.latchJournalRecoveryFailure({
        reason: `legacy rollback WAL integrity preflight failed at line ${issue.line}: ${issue.reason}`,
        error: issue.reason,
        malformed: issue.kind === 'malformed_entry',
      });
    }
    throw new Error(
      `legacy rollback checkpoint ${validated.checkpoint} is not provably contiguous: ${issue.reason}`,
    );
  }

  private snapshotPathForIntent(snapshotPath: string): string {
    const stateDir = resolve(dirname(this.ctx.stateFilePath));
    const selected = resolve(snapshotPath);
    const relativePath = relative(stateDir, selected);
    if (!relativePath || isAbsolute(relativePath) || relativePath === '..' || relativePath.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
      throw new Error('rollback snapshot must be inside the state directory');
    }
    return relativePath;
  }

  private rollbackAuthorityPath(): string {
    return `${this.ctx.stateFilePath}.rollback-intent.json`;
  }

  private rollbackIntentChecksum(
    intent: Omit<RollbackIntentV1, 'intent_checksum'>,
  ): string {
    return createHash('sha256').update(JSON.stringify([
      intent.version,
      intent.checkpoint,
      intent.selected_snapshot,
      intent.selected_snapshot_sha256,
    ])).digest('hex');
  }

  private createRollbackIntent(
    intent: Omit<RollbackIntentV1, 'intent_checksum'>,
  ): RollbackIntentV1 {
    return { ...intent, intent_checksum: this.rollbackIntentChecksum(intent) };
  }

  private writeRollbackAuthority(intent: RollbackIntentV1): void {
    const path = this.rollbackAuthorityPath();
    const dir = dirname(path);
    if (existsSync(path)) {
      const existing = this.validateStandaloneRollbackIntent(
        parseJsonBytes(this.readPersistedBytes(path)),
      );
      if (existing.intent_checksum !== intent.intent_checksum) {
        throw new Error('an existing rollback authority names a different target');
      }
      fsyncDirectory(dir);
      return;
    }
    const tmp = `${path}.tmp`;
    const json = JSON.stringify(intent);
    const fd = openSync(tmp, 'w');
    try {
      writeFileSync(fd, json);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
    fsyncDirectory(dir);
  }

  private removeRollbackAuthority(): void {
    const path = this.rollbackAuthorityPath();
    if (!existsSync(path)) return;
    unlinkSync(path);
    fsyncDirectory(dirname(path));
  }

  private completeRollbackCleanup(intent: RollbackIntentV1): void {
    const selectedPath = join(dirname(this.ctx.stateFilePath), intent.selected_snapshot);
    this.pruneSnapshotsSupersededByRollback(selectedPath, intent.checkpoint);
    if (this.ctx.mutationJournal) {
      this.ctx.mutationJournal.truncate();
      this.ctx.mutationJournal.setNextSeq(intent.checkpoint, {
        appliedThroughSeq: intent.checkpoint,
      });
    }
    this.ctx.journalSnapshotSeq = intent.checkpoint;
  }

  private pruneSnapshotsSupersededByRollback(selectedPath: string, checkpoint: number): void {
    const stateDir = dirname(this.ctx.stateFilePath);
    const selected = resolve(selectedPath);

    for (const snapshot of this.listSnapshotsStrict()) {
      const snapshotPath = join(stateDir, snapshot);
      if (resolve(snapshotPath) === selected) continue;
      // A listed-but-unreadable snapshot might still be a valid, newer base.
      // Treat filesystem failure as fatal; only parse/schema-invalid snapshots
      // are safe to ignore because startup will reject them too.
      const raw = this.readPersistedBytes(snapshotPath);
      let candidateCheckpoint: number;
      try {
        const data = parseJsonBytes(raw);
        candidateCheckpoint = this.validateStateBase(data).checkpoint;
      } catch (error) {
        if (
          (error instanceof PersistedStateVersionError
            || error instanceof PersistedJournalVersionError)
          && error.kind === 'unsupported'
        ) {
          throw new Error(
            `cannot complete rollback while retained snapshot ${snapshot} uses an unsupported format: ${error.message}`,
          );
        }
        if (error instanceof StateIntegrityError) {
          if (error.checkpoint === undefined) {
            throw new Error(
              `cannot durably complete rollback while superseded snapshot ${snapshot} has a recognized integrity mismatch and no usable checkpoint`,
            );
          }
          candidateCheckpoint = error.checkpoint;
        } else {
          // Invalid snapshots cannot outrank a valid rollback base.
          continue;
        }
      }
      if (candidateCheckpoint < checkpoint) continue;
      // I/O failures here intentionally escape: silently retaining a valid
      // superseded snapshot would make the successful result non-durable.
      unlinkSync(snapshotPath);
      fsyncDirectory(dirname(snapshotPath));
    }
  }

  /** Capture the complete mutable persistence surface before trying a recovery
   *  candidate. `_restoreFromData` necessarily updates several fields in order;
   *  this baseline lets a late validation/deserialization failure roll back all
   *  of those changes before another candidate or config seeding is attempted. */
  private captureRestoreBaseline(): unknown {
    const data = {
      state_version: CURRENT_STATE_VERSION,
      journal_version: CURRENT_JOURNAL_VERSION,
      config: this.ctx.config,
      graph: this.ctx.graph.export(),
      activityLog: this.ctx.activityLog,
      agents: Array.from(this.ctx.agents.entries()),
      coordinationRecoveryWarnings: this.ctx.coordinationRecoveryWarnings,
      campaigns: Array.from(this.ctx.campaigns.entries()),
      agentDirectives: Array.from(this.ctx.agentDirectives.entries()),
      approvalRequests: Array.from(this.ctx.approvalRequests.entries()),
      inferenceRules: this.ctx.inferenceRules.filter(rule => !this.builtinRuleIds.has(rule.id)),
      trackedProcesses: this.ctx.trackedProcesses,
      runtimeRuns: this.ctx.runtimeRuns,
      playbookRuns: Array.from(this.ctx.playbookRuns.entries()),
      sessionDescriptors: this.ctx.sessionDescriptors,
      proposedPlans: this.ctx.proposedPlanStore.serialize(),
      agentQueries: this.ctx.agentQueryStore.serialize(),
      commandPlans: Array.from(this.ctx.commandPlans.entries()),
      commandOutcomes: Array.from(this.ctx.commandOutcomes.entries()),
      coldStore: this.ctx.coldStore.export(),
      opsecTracker: this.ctx.opsecTracker.serialize(),
      frontierLinkage: this.ctx.frontierLinkage.serialize(),
      frontierWeights: this.ctx.frontierWeights ?? { fan_out: {}, noise: {} },
      artifactReferences: this.ctx.artifactReferences,
      chainCheckpoints: this.ctx.chainCheckpoints,
      chainEventsSinceCheckpoint: this.ctx.chainEventsSinceCheckpoint,
      deterministicSeq: this.ctx.deterministicSeq,
      recentFindingHashes: Array.from(this.ctx.recentFindingHashes.entries()),
      dedupCount: this.ctx.dedupCount,
      frontierLeases: this.ctx.frontierLeases.serialize(),
      lastKnownPhaseId: this.ctx.lastKnownPhaseId,
      journalSnapshotSeq: this.ctx.journalSnapshotSeq,
      journalCheckpointSemantics: JOURNAL_CHECKPOINT_SEMANTICS,
    };
    // The ordinary writer requires this state to be JSON serializable. Clone it
    // so a rejected candidate cannot mutate objects retained by the baseline.
    return JSON.parse(JSON.stringify(data));
  }

  private restoreRejectedCandidateBaseline(baseline: unknown, builtinRules: InferenceRule[]): void {
    try {
      this._restoreFromData(baseline, builtinRules);
    } catch (error) {
      throw new Error(
        `Failed to restore the pre-recovery engine state after rejecting a candidate: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  private ensureJournalForRestoredConfig(): void {
    if (!this.ctx.mutationJournal && this.ctx.config.engagement_nonce) {
      this.ctx.mutationJournal = new MutationJournal(this.ctx.stateFilePath);
    }
  }

  /**
   * Shared state-restore routine used by rollback and recovery.
   * Restores every persisted field (graph, config, agents, campaigns,
   * tracked processes, inference rules, cold store, opsec tracker, frontier
   * linkage, chain checkpoints, deterministic sequence, frontier leases,
   * last phase id) so the two paths are always in sync.
   *
   * Journal handling is intentionally left to the caller: explicit rollback
   * discards post-snapshot entries, while boot recovery replays and checkpoints
   * them before any compaction.
   *
   * Returns the raw `journalSnapshotSeq` from the snapshot data so callers
   * can reset the journal sequence to the right value.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private _restoreFromData(data: any, builtinRules: InferenceRule[]): RestoredCheckpoint {
    const stateVersion = detectStateVersion(data);
    const journalVersion = detectJournalVersion(data, stateVersion);
    if (stateVersion === CURRENT_STATE_VERSION) {
      validatePersistedStateV1(data);
    }
    this.ctx.graph.clear();
    this.ctx.config = data.config;
    this.ctx.graph.import(data.graph);
    this.normalizeLoadedNodeProvenance();
    this.migrateDefaultCredentialFlags();
    this.ctx.invalidatePathGraph();
    this.ctx.activityLog = stateVersion === CURRENT_STATE_VERSION
      ? JSON.parse(JSON.stringify(data.activityLog)) as ActivityLogEntry[]
      : (data.activityLog || []).map((entry: unknown) =>
          normalizeActivityLogEntry(entry as Partial<ActivityLogEntry> & { description: string }));
    const normalizedAgents = new Map<string, import('../types.js').AgentTask>();
    for (const entry of data.agents || []) {
      if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string') continue;
      const task = normalizeAgentTask(entry[1], entry[0]);
      normalizedAgents.set(taskIdOf(task), task);
    }
    this.ctx.agents = normalizedAgents;
    const coordinationWarnings: CoordinationRecoveryWarning[] = Array.isArray(data.coordinationRecoveryWarnings)
      ? JSON.parse(JSON.stringify(data.coordinationRecoveryWarnings))
      : [];
    const resolveOwner = (
      relationship: string,
      reference: string | undefined,
      payload: unknown,
      preserveMissingTaskId = false,
      preservedAgentLabel?: string,
    ): { task_id?: string; agent_label?: string; warning?: CoordinationRecoveryWarning } => {
      if (!reference) return {};
      const resolution = resolveAgentIdentity(this.ctx.agents.values(), reference);
      if (resolution.status === 'exact' || resolution.status === 'unique_legacy_label') {
        return {
          task_id: taskIdOf(resolution.task),
          agent_label: agentLabelOf(resolution.task),
        };
      }
      if (resolution.status === 'missing') {
        return preserveMissingTaskId
          ? { task_id: reference, agent_label: preservedAgentLabel }
          : {
              warning: coordinationRecoveryWarning({
                relationship,
                reference,
                payload,
              }),
            };
      }
      return {
        warning: coordinationRecoveryWarning({
          relationship,
          reference,
          ...(resolution.status === 'ambiguous_legacy_label'
            ? { candidate_task_ids: resolution.candidate_task_ids }
            : {}),
          payload,
        }),
      };
    };
    this.ctx.campaigns = new Map(data.campaigns || []);
    const normalizedDirectives = new Map<string, import('../types.js').AgentDirective[]>();
    for (const entry of data.agentDirectives || []) {
      if (!Array.isArray(entry) || entry.length !== 2 || !Array.isArray(entry[1])) continue;
      for (const rawDirective of entry[1]) {
        if (!rawDirective || typeof rawDirective !== 'object') continue;
        const directive = JSON.parse(JSON.stringify(rawDirective)) as import('../types.js').AgentDirective;
        const owner = resolveOwner(
          `directive:${directive.id}`,
          directive.task_id || (typeof entry[0] === 'string' ? entry[0] : undefined),
          directive,
          true,
        );
        if (!owner.task_id) {
          if (owner.warning) coordinationWarnings.push(owner.warning);
          continue;
        }
        directive.task_id = owner.task_id;
        const bucket = normalizedDirectives.get(owner.task_id) ?? [];
        bucket.push(directive);
        normalizedDirectives.set(owner.task_id, bucket);
      }
    }
    this.ctx.agentDirectives = normalizedDirectives;
    const normalizedApprovals = new Map<string, import('./pending-action-queue.js').DurableApprovalRecord>();
    for (const entry of data.approvalRequests || []) {
      if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string') continue;
      const record = JSON.parse(JSON.stringify(entry[1])) as import('./pending-action-queue.js').DurableApprovalRecord;
      const reference = record.task_id ?? record.agent_label ?? record.agent_id;
      const owner = resolveOwner(
        `approval:${record.action_id}`,
        reference,
        record,
        record.task_id !== undefined,
        record.agent_label ?? record.agent_id,
      );
      if (owner.task_id) {
        record.task_id = owner.task_id;
        record.agent_label = owner.agent_label;
        record.agent_id = owner.agent_label;
        delete record.recovery_warning;
      } else if (owner.warning) {
        delete record.task_id;
        record.recovery_warning = owner.warning.message;
        coordinationWarnings.push(owner.warning);
      }
      normalizedApprovals.set(entry[0], record);
    }
    this.ctx.approvalRequests = normalizedApprovals;
    this.ctx.trackedProcesses = data.trackedProcesses || [];
    this.ctx.runtimeRuns = Array.isArray(data.runtimeRuns)
      ? JSON.parse(JSON.stringify(data.runtimeRuns))
      : [];
    for (const run of this.ctx.runtimeRuns) {
      const reference = run.task_id ?? run.agent_id;
      const owner = resolveOwner(
        `runtime_run:${run.run_id}`,
        reference,
        run,
        run.task_id !== undefined,
        run.agent_id,
      );
      if (owner.task_id) {
        run.task_id = owner.task_id;
        run.agent_id = owner.agent_label;
      } else if (owner.warning && reference) {
        delete run.task_id;
        run.recovery_warning = owner.warning.message;
        coordinationWarnings.push(owner.warning);
      }
    }
    this.ctx.playbookRuns = new Map(data.playbookRuns || []);
    this.ctx.sessionDescriptors = Array.isArray(data.sessionDescriptors)
      ? JSON.parse(JSON.stringify(data.sessionDescriptors))
      : [];
    for (const descriptor of this.ctx.sessionDescriptors) {
      const owner = resolveOwner(
        `session:${descriptor.session_id}`,
        descriptor.owner_task_id,
        descriptor,
        descriptor.owner_task_id !== undefined,
      );
      if (owner.task_id) {
        descriptor.owner_task_id = owner.task_id;
        delete descriptor.recovery_warning;
      } else if (owner.warning && descriptor.owner_task_id) {
        delete descriptor.owner_task_id;
        descriptor.recovery_warning = owner.warning.message;
        coordinationWarnings.push(owner.warning);
      }
    }
    const proposedPlans = data.proposedPlans && typeof data.proposedPlans === 'object'
      ? JSON.parse(JSON.stringify(data.proposedPlans))
      : { plans: [], tombstones: [] };
    if (Array.isArray(proposedPlans.plans)) {
      for (const plan of proposedPlans.plans) {
        const taskReference = plan.owner_task_id ?? plan.source_task_id;
        const reference = taskReference ?? plan.owner_agent_label ?? plan.source_agent_id;
        const owner = resolveOwner(
          `plan:${plan.plan_id}`,
          reference,
          plan,
          taskReference !== undefined,
          plan.owner_agent_label ?? plan.source_agent_id,
        );
        if (owner.task_id) {
          plan.owner_task_id = owner.task_id;
          plan.owner_agent_label = owner.agent_label;
          plan.source_task_id = owner.task_id;
          plan.source_agent_id = owner.agent_label;
          delete plan.recovery_warning;
        } else if (owner.warning && reference) {
          delete plan.owner_task_id;
          delete plan.source_task_id;
          plan.recovery_warning = owner.warning.message;
          coordinationWarnings.push(owner.warning);
        }
      }
    }
    this.ctx.proposedPlanStore.restore(proposedPlans);
    const agentQueries = data.agentQueries && typeof data.agentQueries === 'object'
      ? JSON.parse(JSON.stringify(data.agentQueries))
      : { queries: [] };
    if (Array.isArray(agentQueries.queries)) {
      for (const query of agentQueries.queries) {
        const taskReference = query.owner_task_id ?? query.task_id;
        const reference = taskReference ?? query.owner_agent_label ?? query.agent_id;
        const owner = resolveOwner(
          `agent_query:${query.query_id}`,
          reference,
          query,
          taskReference !== undefined,
          query.owner_agent_label ?? query.agent_id,
        );
        if (owner.task_id) {
          query.owner_task_id = owner.task_id;
          query.owner_agent_label = owner.agent_label;
          query.task_id = owner.task_id;
          query.agent_id = owner.agent_label;
          delete query.recovery_warning;
        } else if (owner.warning && reference) {
          delete query.owner_task_id;
          delete query.task_id;
          query.recovery_warning = owner.warning.message;
          coordinationWarnings.push(owner.warning);
        }
      }
    }
    this.ctx.agentQueryStore.restore(agentQueries);
    const restoreNow = Date.now();
    this.ctx.commandPlans = new Map(
      (data.commandPlans || []).filter((entry: unknown) =>
        Array.isArray(entry)
        && entry.length === 2
        && entry[1]
        && typeof entry[1] === 'object'
        && typeof (entry[1] as { expires_at?: unknown }).expires_at === 'number'
        && (entry[1] as { expires_at: number }).expires_at > restoreNow),
    );
    this.ctx.commandOutcomes = new Map(
      (data.commandOutcomes || []).filter((entry: unknown) =>
        Array.isArray(entry)
        && entry.length === 2
        && entry[1]
        && typeof entry[1] === 'object'
        && typeof (entry[1] as { expires_at?: unknown }).expires_at === 'number'
        && (entry[1] as { expires_at: number }).expires_at > restoreNow),
    );
    this.ctx.inferenceRules = [...builtinRules];
    if (data.inferenceRules) {
      for (const rule of data.inferenceRules) {
        this.ctx.inferenceRules.push(rule);
      }
    }
    this.ctx.coldStore.import(Array.isArray(data.coldStore) ? data.coldStore : []);
    this.ctx.opsecTracker = data.opsecTracker
      ? OpsecTracker.deserialize(data.opsecTracker, this.ctx)
      : new OpsecTracker(this.ctx);
    this.ctx.frontierLinkage = FrontierLinkageTracker.deserialize(data.frontierLinkage);
    this.ctx.frontierWeights = data.frontierWeights
      ? JSON.parse(JSON.stringify(data.frontierWeights))
      : undefined;
    this.ctx.artifactReferences = data.artifactReferences
      ? JSON.parse(JSON.stringify(data.artifactReferences))
      : { tapes: [], bundles: [], cookie_jars: [] };
    this.ctx.rebuildActionFrontierMap();
    this.ctx.rebuildChainTail();
    this.ctx.chainCheckpoints = Array.isArray(data.chainCheckpoints) ? data.chainCheckpoints : [];
    this.ctx.chainEventsSinceCheckpoint = typeof data.chainEventsSinceCheckpoint === 'number'
      ? data.chainEventsSinceCheckpoint
      : 0;
    this.ctx.deterministicSeq = typeof data.deterministicSeq === 'number' ? data.deterministicSeq : 0;
    this.ctx.recentFindingHashes = new Map(data.recentFindingHashes || []);
    this.ctx.dedupCount = typeof data.dedupCount === 'number' ? data.dedupCount : 0;
    const frontierLeases = data.frontierLeases && typeof data.frontierLeases === 'object'
      ? JSON.parse(JSON.stringify(data.frontierLeases))
      : undefined;
    if (frontierLeases?.byItem && typeof frontierLeases.byItem === 'object') {
      for (const [itemId, lease] of Object.entries(frontierLeases.byItem) as Array<[string, {
        task_id?: string;
        agent_id?: string;
      }]>) {
        const reference = lease.task_id ?? lease.agent_id;
        const owner = resolveOwner(
          `frontier_lease:${itemId}`,
          reference,
          lease,
          lease.task_id !== undefined,
          lease.agent_id,
        );
        if (owner.task_id) {
          lease.task_id = owner.task_id;
          lease.agent_id = owner.agent_label;
        } else {
          delete frontierLeases.byItem[itemId];
          if (owner.warning && reference) coordinationWarnings.push(owner.warning);
        }
      }
    }
    this.ctx.frontierLeases = FrontierLeases.deserialize(frontierLeases);
    this.ctx.coordinationRecoveryWarnings = mergeCoordinationRecoveryWarnings(coordinationWarnings);
    this.ctx.lastKnownPhaseId = typeof data.lastKnownPhaseId === 'string' ? data.lastKnownPhaseId : undefined;
    const checkpoint = typeof data.journalSnapshotSeq === 'number' ? data.journalSnapshotSeq : 0;
    this.ctx.journalSnapshotSeq = checkpoint;
    return {
      checkpoint,
      trusted: isTrustedJournalCheckpoint(data.journalCheckpointSemantics, journalVersion),
      stateVersion,
      journalVersion,
    };
  }

  /**
   * Restore from the newest valid full-state base and replay every newer WAL
   * record.  Primary and snapshot recovery deliberately share this path: a
   * snapshot is only a different base candidate, never permission to discard
   * the post-snapshot journal.
   */
  restoreBaseAndReplay(mutators?: ReplayMutators): RestoreResult {
    let adoptedExistingLease = false;
    if (existsSync(stateMigrationLockDirectory(this.ctx.stateFilePath))) {
      try {
        this.acquireMigrationLease();
        adoptedExistingLease = true;
      } catch (error) {
        return this.enterExternalMigrationLeaseFailure(error);
      }
    }
    const pendingRollback = this.resumePendingRollback(mutators?.prepareRecoveryCommit !== undefined);
    if (pendingRollback) {
      return this.finishAdoptedLeaseRecovery(pendingRollback, adoptedExistingLease);
    }

    let candidates: RestoreCandidate[];
    try {
      candidates = this.collectRestoreCandidates();
    } catch (error) {
      return this.enterBaseAccessFailure(
        'snapshot',
        join(dirname(this.ctx.stateFilePath), '.snapshots'),
        error,
      );
    }
    return this.finishAdoptedLeaseRecovery(
      this.restoreCandidates(candidates, this.builtinRules, mutators),
      adoptedExistingLease,
    );
  }

  private collectRestoreCandidates(): RestoreCandidate[] {
    const candidates: RestoreCandidate[] = [];
    if (existsSync(this.ctx.stateFilePath)) {
      candidates.push({ source: 'state', path: this.ctx.stateFilePath });
    }
    const stateDir = dirname(this.ctx.stateFilePath);
    for (const snapshot of this.listSnapshotsStrict().reverse()) {
      candidates.push({ source: 'snapshot', path: join(stateDir, snapshot) });
    }
    return candidates;
  }

  private finishAdoptedLeaseRecovery(
    result: RestoreResult,
    adoptedExistingLease: boolean,
  ): RestoreResult {
    if (
      adoptedExistingLease
      && this.releaseMigrationLease
      && !this.migrationBackup
    ) {
      try {
        this.releaseHeldMigrationLease();
      } catch (error) {
        return this.enterExternalMigrationLeaseFailure(error);
      }
    }
    return result;
  }

  private enterExternalMigrationLeaseFailure(error: unknown): RestoreResult {
    const reason = `state recovery is blocked by another or unverifiable migration owner: ${error instanceof Error ? error.message : String(error)}`;
    this.recoveryReadOnlyReason = reason;
    this.ctx.mutationJournal?.blockAppends(reason);
    this.stateMigrationStatus = {
      status: 'blocked',
      supported_state_version: CURRENT_STATE_VERSION,
      supported_journal_version: CURRENT_JOURNAL_VERSION,
      migration_required: false,
      reason,
    };
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source: existsSync(this.ctx.stateFilePath) ? 'state' : 'fresh',
      complete: false,
      writable: false,
      reason,
      checkpoint: 0,
      preserved: true,
    });
    return {
      status: 'degraded',
      source: this.recoveryStatus.source,
      reason,
    };
  }

  /** A checksummed sidecar is the durable authority for an explicit rollback.
   * While it exists, the retained selected snapshot is canonical and rebuilds
   * the replaceable marked primary regardless of that primary's contents. */
  private resumePendingRollback(deferAuthorityRelease: boolean): RestoreResult | undefined {
    if (!this.hasPendingRollbackHint()) return undefined;
    try {
      return withStateMigrationWriteGuard(
        this.ctx.stateFilePath,
        this.releaseMigrationLease?.token,
        () => this.resumePendingRollbackGuarded(deferAuthorityRelease),
      );
    } catch (error) {
      return this.enterExternalMigrationLeaseFailure(error);
    }
  }

  private hasPendingRollbackHint(): boolean {
    if (existsSync(this.rollbackAuthorityPath())) return true;
    if (!existsSync(this.ctx.stateFilePath)) return false;
    try {
      const primary = parseJsonBytes(this.readPersistedBytes(this.ctx.stateFilePath));
      return Boolean(
        primary
        && typeof primary === 'object'
        && !Array.isArray(primary)
        && Object.prototype.hasOwnProperty.call(primary, 'rollbackIntent'),
      );
    } catch {
      // Ordinary candidate recovery owns malformed/unreadable-primary handling.
      return false;
    }
  }

  private resumePendingRollbackGuarded(
    deferAuthorityRelease: boolean,
  ): RestoreResult | undefined {
    const authorityPath = this.rollbackAuthorityPath();
    const hasAuthoritySidecar = existsSync(authorityPath);
    let intent: RollbackIntentV1 | undefined;
    let primaryData: unknown;
    let primaryIntent: RollbackIntentV1 | undefined;

    if (hasAuthoritySidecar) {
      try {
        const authority = parseJsonBytes(this.readPersistedBytes(authorityPath));
        intent = this.validateStandaloneRollbackIntent(authority);
      } catch (error) {
        this.latchRollbackFailure(error, this.rollbackCheckpointHintFromIntentFile(authorityPath) ?? 0, 'state');
        return { status: 'degraded', source: 'state', reason: this.recoveryReadOnlyReason };
      }
    }

    if (existsSync(this.ctx.stateFilePath)) {
      try {
        primaryData = parseJsonBytes(this.readPersistedBytes(this.ctx.stateFilePath));
        if (
          primaryData
          && typeof primaryData === 'object'
          && Object.prototype.hasOwnProperty.call(primaryData, 'rollbackIntent')
        ) {
          const validated = this.validateStateBase(primaryData);
          primaryIntent = this.validateRollbackIntent(
            primaryData as Record<string, unknown>,
            validated.checkpoint,
          )!;
          if (intent && intent.intent_checksum !== primaryIntent.intent_checksum) {
            throw new Error('rollback sidecar and marked primary disagree');
          }
          intent ??= primaryIntent;
        }
      } catch (error) {
        // A valid sidecar deliberately survives primary corruption. Without one,
        // an explicitly present but invalid marker is an unresolved rollback and
        // must degrade rather than fall through to a superseded snapshot.
        if (!intent && primaryData && typeof primaryData === 'object'
          && Object.prototype.hasOwnProperty.call(primaryData, 'rollbackIntent')) {
          this.latchRollbackFailure(error, this.rollbackCheckpointHint(primaryData) ?? 0, 'state');
          return { status: 'degraded', source: 'state', reason: this.recoveryReadOnlyReason };
        }
        primaryData = undefined;
        primaryIntent = undefined;
      }
    }

    if (!intent) return undefined;

    let recoverySource: 'state' | 'snapshot' = 'state';
    try {
      // The intent always binds the original selected snapshot. Validate those
      // bytes even when a marker-only current-writer primary is usable: that
      // primary may have been produced from a legacy checkpoint immediately
      // before a crash and therefore cannot establish the source checkpoint's
      // contiguity by itself.
      recoverySource = 'snapshot';
      const selectedPath = join(dirname(this.ctx.stateFilePath), intent.selected_snapshot);
      const selectedBytes = this.readPersistedBytes(selectedPath);
      const selectedDigest = createHash('sha256').update(selectedBytes).digest('hex');
      if (selectedDigest !== intent.selected_snapshot_sha256) {
        throw new Error('selected rollback snapshot checksum does not match the durable intent');
      }
      const selectedData = parseJsonBytes(selectedBytes);
      const selected = this.validateStateBase(selectedData);
      if (selected.checkpoint !== intent.checkpoint) {
        throw new Error('selected rollback snapshot checkpoint does not match the durable intent');
      }
      this.assertLegacyRollbackCheckpointUnambiguous(selected);
      if (selected.stateVersion === LEGACY_STATE_VERSION) {
        try {
          this.beginLegacyMigration();
        } catch (error) {
          return this.enterMigrationFailure(
            recoverySource,
            `pending rollback selected legacy state, but its migration backup failed: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      }

      // The intent binds the selected snapshot bytes, never arbitrary contents
      // of the replaceable marked primary. This remains true for marker-only
      // compatibility: matching intent metadata does not authenticate the
      // primary graph/config payload.
      const rollbackData = selectedData;

      // Marker-only pending states are upgraded to the independently durable
      // authority before any cleanup. Existing matching sidecars are reused and
      // their directory entry is freshly synchronized.
      this.writeRollbackAuthority(intent);
      this.rollbackIntent = intent;
      this._restoreFromData(rollbackData, this.builtinRules);
      this.durableConfig = JSON.parse(JSON.stringify(this.ctx.config)) as EngagementConfig;
      this.ensureJournalForRestoredConfig();
      this.ctx.mutationJournal?.setNextSeq(intent.checkpoint, {
        preserveAllocated: true,
        appliedThroughSeq: intent.checkpoint,
      });

      // Rebuild a marked primary from the selected snapshot when the old marked
      // primary was absent/corrupt, then resume destructive cleanup.
      if (recoverySource === 'snapshot') {
        this.writeStateToDisk({
          journalCheckpointSeq: intent.checkpoint,
          rotateExisting: false,
          allowIntegrityReplacement: true,
        });
      }
      this.completeRollbackCleanup(intent);
      this.ctx.logEvent({
        description: `Completed interrupted rollback to ${basename(intent.selected_snapshot)}`,
        event_type: 'system',
        category: 'system',
        outcome: 'success',
        details: { checkpoint: intent.checkpoint },
      });
      if (!deferAuthorityRelease) {
        this.rollbackIntent = undefined;
        this.writeStateToDisk({
          journalCheckpointSeq: intent.checkpoint,
          rotateExisting: false,
          allowIntegrityReplacement: true,
        });
        this.removeRollbackAuthority();
        this.ctx.mutationJournal?.unblockAppends();
      }
      this.finishSuccessfulWrite();
      this.recoveryReadOnlyReason = undefined;
      this.recoveryStatus = this.buildRecoveryStatus({
        outcome: 'recovered',
        source: recoverySource,
        complete: true,
        writable: true,
        checkpoint: intent.checkpoint,
        preserved: false,
      });
      return {
        status: 'restored',
        source: recoverySource,
        ...(deferAuthorityRelease ? { rollback_pending: true } : {}),
      };
    } catch (error) {
      if (error instanceof JournalRecoveryGateError) {
        return {
          status: 'degraded',
          source: recoverySource,
          reason: this.recoveryReadOnlyReason,
        };
      }
      const checkpoint = this.rollbackIntent?.checkpoint ?? intent.checkpoint;
      this.latchRollbackFailure(error, checkpoint, recoverySource);
      return {
        status: 'degraded',
        source: recoverySource,
        reason: this.recoveryReadOnlyReason,
      };
    }
  }

  /** Backward-compatible facade retained for direct persistence tests. */
  loadState(mutators?: ReplayMutators): void {
    const result = this.restoreBaseAndReplay(mutators);
    if (result.status === 'seed_required') {
      throw new Error(`No valid persisted state base found at ${this.ctx.stateFilePath}`);
    }
  }

  private restoreCandidates(
    candidates: RestoreCandidate[],
    builtinRules: InferenceRule[],
    mutators?: ReplayMutators,
    rankedUnderMigrationLease = false,
  ): RestoreResult {
    const rejected: Array<{ path: string; error: string }> = [];
    const integrityRejected: IntegrityRejectedBase[] = [];
    const invalidVersioned: Array<{
      candidate: RestoreCandidate;
      error: unknown;
      checkpoint?: number;
      newnessRank: number;
      observedStateVersion?: number;
      observedJournalVersion?: number;
    }> = [];
    const baseline = this.captureRestoreBaseline();

    // Parse and validate every base before choosing one. Filename order alone
    // is insufficient: a valid snapshot can carry a later durable checkpoint
    // than a stale-but-still-valid primary left by an interrupted rename.
    const validated: ValidatedRestoreCandidate[] = [];
    for (const [newnessRank, candidate] of candidates.entries()) {
      let raw: Buffer;
      let parsedData: unknown;
      try {
        raw = this.readPersistedBytes(candidate.path);
      } catch (error) {
        // A transiently unreadable base may be the newest durable state. Treating
        // it like malformed JSON and overwriting it from an older base/config
        // would turn an access problem into permanent data loss.
        return this.enterBaseAccessFailure(candidate.source, candidate.path, error);
      }
      try {
        const data = parseJsonBytes(raw);
        parsedData = data;
        const {
          checkpoint,
          stateVersion,
          journalVersion,
        } = this.validateStateBase(data);
        this.validateFullStateDetached(data, builtinRules);
        validated.push({
          ...candidate,
          data,
          rawSha256: createHash('sha256').update(raw).digest('hex'),
          checkpoint,
          stateVersion,
          journalVersion,
          newnessRank,
        });
      } catch (error) {
        if (
          (error instanceof PersistedStateVersionError
            || error instanceof PersistedJournalVersionError)
          && error.kind === 'unsupported'
        ) {
          return this.enterUnsupportedFormatFailure(candidate, error);
        }
        const parsedRecord = parsedData
          && typeof parsedData === 'object'
          && !Array.isArray(parsedData)
          ? parsedData as Record<string, unknown>
          : undefined;
        const hasExplicitStateDiscriminator = parsedRecord !== undefined
          && Object.prototype.hasOwnProperty.call(parsedRecord, 'state_version');
        const hasExplicitJournalDiscriminator = parsedRecord !== undefined
          && Object.prototype.hasOwnProperty.call(parsedRecord, 'journal_version');
        const invalidExplicitDiscriminator = (
          error instanceof PersistedStateVersionError
          || error instanceof PersistedJournalVersionError
        ) && error.kind === 'invalid'
          && (hasExplicitStateDiscriminator || hasExplicitJournalDiscriminator);
        if (
          parsedRecord?.state_version === CURRENT_STATE_VERSION
          || invalidExplicitDiscriminator
        ) {
          invalidVersioned.push({
            candidate,
            error,
            newnessRank,
            ...(typeof parsedRecord?.state_version === 'number'
              ? { observedStateVersion: parsedRecord.state_version }
              : {}),
            ...(typeof parsedRecord?.journal_version === 'number'
              ? { observedJournalVersion: parsedRecord.journal_version }
              : {}),
            ...(Number.isSafeInteger(parsedRecord?.journalSnapshotSeq)
              && (parsedRecord!.journalSnapshotSeq as number) >= 0
              ? { checkpoint: parsedRecord!.journalSnapshotSeq as number }
              : {}),
          });
        }
        if (error instanceof StateIntegrityError) {
          integrityRejected.push({
            source: candidate.source,
            path: candidate.path,
            error: error.message,
            checkpoint: error.checkpoint,
            newnessRank,
            ...(parsedRecord
              ? {
                  stateVersion: parsedRecord.state_version === CURRENT_STATE_VERSION
                    ? CURRENT_STATE_VERSION
                    : LEGACY_STATE_VERSION,
                }
              : {}),
          });
        }
        rejected.push({
          path: candidate.path,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    validated.sort((left, right) =>
      right.checkpoint - left.checkpoint || left.newnessRank - right.newnessRank,
    );

    // A recognized-checksum mismatch is not just an invalid legacy base: its
    // bytes may contain newer non-WAL state. Never overwrite such a candidate
    // with an older fallback. Older mismatched snapshots cannot block a newer
    // valid primary, but the highest-ranked recovery head remains untouched and
    // inspectable in degraded mode for explicit reconciliation.
    const bestValid = validated[0];
    const integrityRank = (candidate: IntegrityRejectedBase): number =>
      candidate.checkpoint ?? Number.MAX_SAFE_INTEGER;
    const blockingIntegrity = integrityRejected
      .filter(candidate => !bestValid
        || integrityRank(candidate) > bestValid.checkpoint
        || (
          integrityRank(candidate) === bestValid.checkpoint
          && candidate.newnessRank < bestValid.newnessRank
        ))
      .sort((left, right) =>
        integrityRank(right) - integrityRank(left) || left.newnessRank - right.newnessRank,
      );
    if (blockingIntegrity.length > 0) {
      return this.enterStateIntegrityFailure(blockingIntegrity);
    }
    const blockingInvalidVersioned = invalidVersioned
      .filter(candidate => !bestValid
        || candidate.newnessRank < bestValid.newnessRank
        || (
          candidate.checkpoint !== undefined
          && (
            candidate.checkpoint > bestValid.checkpoint
            || (
              candidate.checkpoint === bestValid.checkpoint
              && candidate.newnessRank < bestValid.newnessRank
            )
          )
        ))
      .sort((left, right) =>
        (right.checkpoint ?? -1) - (left.checkpoint ?? -1)
        || left.newnessRank - right.newnessRank,
      );
    if (blockingInvalidVersioned.length > 0) {
      return this.enterInvalidVersionedStateFailure(blockingInvalidVersioned[0]);
    }

    for (const candidate of validated) {
      let restoredCheckpoint: RestoredCheckpoint;
      try {
        restoredCheckpoint = this._restoreFromData(candidate.data, builtinRules);
        this.durableConfig = JSON.parse(JSON.stringify(this.ctx.config)) as EngagementConfig;
      } catch (error) {
        this.restoreRejectedCandidateBaseline(baseline, builtinRules);
        rejected.push({
          path: candidate.path,
          error: error instanceof Error ? error.message : String(error),
        });
        continue;
      }

      const migratingLegacyState = restoredCheckpoint.stateVersion === LEGACY_STATE_VERSION;
      const migratingLegacyJournal =
        restoredCheckpoint.journalVersion === LEGACY_JOURNAL_VERSION;
      if (migratingLegacyState || migratingLegacyJournal) {
        try {
          this.acquireMigrationLease();
          // A rollback may have committed its sidecar/marked primary after the
          // startup-level check but before this legacy candidate acquired the
          // migration lease. The lease now excludes every compliant writer, so
          // recheck and finish that rollback before reranking or backing up a
          // superseded recovery head.
          const pendingRollback = this.resumePendingRollback(
            mutators?.prepareRecoveryCommit !== undefined,
          );
          if (pendingRollback) {
            if (
              !this.migrationBackup
              && !this.journalUpgradeBackup
              && this.releaseMigrationLease
            ) {
              this.releaseHeldMigrationLease();
            }
            return pendingRollback;
          }
          if (!rankedUnderMigrationLease) {
            // Candidate discovery and ranking before the lease is advisory
            // only. Another compliant process may have installed a newer
            // primary or snapshot while this process was waiting. Restore the
            // in-memory baseline, then repeat the complete scan while the
            // migration lease excludes every ordinary writer.
            const refreshedCandidates = this.collectRestoreCandidates();
            this.restoreRejectedCandidateBaseline(baseline, builtinRules);
            this.durableConfig = JSON.parse(JSON.stringify(this.ctx.config)) as EngagementConfig;
            const reranked = this.restoreCandidates(
              refreshedCandidates,
              builtinRules,
              mutators,
              true,
            );
            if (
              !this.migrationBackup
              && !this.journalUpgradeBackup
              && this.releaseMigrationLease
            ) {
              this.releaseHeldMigrationLease();
            }
            return reranked;
          }
          // Backup exact config/state/WAL/snapshot bytes before replay can
          // authorize any V1 publication. Replay itself remains read-only.
          if (migratingLegacyState) {
            this.beginLegacyMigration();
          } else if (!this.journalUpgradeBackup) {
            this.journalUpgradeBackup = createJournalUpgradeBackup({
              stateFilePath: this.ctx.stateFilePath,
              configFilePath: this.ctx.configFilePath,
            });
          }
        } catch (error) {
          return this.enterMigrationFailure(
            candidate.source,
            `${migratingLegacyState ? 'state migration' : 'journal upgrade'} backup could not be prepared: ${error instanceof Error ? error.message : String(error)}`,
            restoredCheckpoint.stateVersion,
            migratingLegacyState,
          );
        }
      }

      this.ensureJournalForRestoredConfig();
      const journal = this.ctx.mutationJournal;
      let replay: MutationReplayResult | undefined;
      let repairedIncompleteTail:
        | Extract<ReturnType<MutationJournal['repairIncompleteTransactionTail']>, { repaired: true }>
        | undefined;
      if (journal) {
        if (this.journalAccessError !== undefined) {
          if (migratingLegacyState || migratingLegacyJournal) {
            this.releaseHeldMigrationLease();
          }
          return this.enterJournalAccessFailure(this.journalAccessError, candidate.source);
        }
        journal.unblockAppends();
        journal.setNextSeq(restoredCheckpoint.checkpoint, {
          appliedThroughSeq: restoredCheckpoint.trusted ? restoredCheckpoint.checkpoint : 0,
        });
        try {
          const preflightIssue = journal.inspectReplayIntegrity(
            restoredCheckpoint.checkpoint,
            { trustedContiguousCheckpoint: restoredCheckpoint.trusted },
          );
          if (preflightIssue?.kind === 'incomplete_transaction') {
            const repair = journal.repairIncompleteTransactionTail();
            if (repair.repaired) repairedIncompleteTail = repair;
          }
          replay = journal.replayTransactions(
            this.makeTransactionApplier(mutators),
            restoredCheckpoint.checkpoint,
            { trustedContiguousCheckpoint: restoredCheckpoint.trusted },
          );
        } catch (error) {
          mutators?.abortRecoveryReplay?.();
          if (migratingLegacyState || migratingLegacyJournal) {
            this.releaseHeldMigrationLease();
          }
          return this.enterJournalAccessFailure(error, candidate.source);
        }
        if (replay.applied > 0) {
          this.normalizeLoadedNodeProvenance();
          this.migrateDefaultCredentialFlags();
        }
      }

      const restored: RestoredBase = {
        source: candidate.source,
        path: candidate.path,
        data: candidate.data,
        checkpoint: restoredCheckpoint.checkpoint,
        stateVersion: restoredCheckpoint.stateVersion,
        journalVersion: restoredCheckpoint.journalVersion,
        ...(replay ? { replay } : {}),
        ...(repairedIncompleteTail ? { repairedIncompleteTail } : {}),
      };

      // Once the newest valid base exposes an incomplete WAL, do not reinterpret
      // its durable history against an older state. Even a complete replay from
      // that older base cannot prove it contains newer base-only legacy state.
      if (replay && !replay.complete) {
        mutators?.abortRecoveryReplay?.();
        if (restored.stateVersion === LEGACY_STATE_VERSION) {
          this.stateMigrationStatus = {
            status: 'blocked',
            supported_state_version: CURRENT_STATE_VERSION,
            supported_journal_version: CURRENT_JOURNAL_VERSION,
            observed_state_version: LEGACY_STATE_VERSION,
            observed_journal_version: restored.journalVersion,
            migration_required: true,
            ...(this.migrationBackup
              ? {
                  backup_path: this.migrationBackup.directory,
                  backup_manifest_sha256: this.migrationBackup.manifest_sha256,
                }
              : {}),
            reason: this.describeIncompleteReplay(replay),
          };
          this.releaseHeldMigrationLease();
        } else if (restored.journalVersion === LEGACY_JOURNAL_VERSION) {
          this.stateMigrationStatus = {
            status: 'blocked',
            supported_state_version: CURRENT_STATE_VERSION,
            supported_journal_version: CURRENT_JOURNAL_VERSION,
            observed_state_version: CURRENT_STATE_VERSION,
            observed_journal_version: LEGACY_JOURNAL_VERSION,
            migration_required: true,
            ...(this.journalUpgradeBackup
              ? {
                  backup_path: this.journalUpgradeBackup.directory,
                  backup_manifest_sha256: this.journalUpgradeBackup.manifest_sha256,
                }
              : {}),
            reason: this.describeIncompleteReplay(replay),
          };
          this.releaseHeldMigrationLease();
        }
        return this.enterIncompleteRecovery(restored, this.describeIncompleteReplay(replay));
      }

      if (
        restored.stateVersion !== LEGACY_STATE_VERSION
        && restored.journalVersion === CURRENT_JOURNAL_VERSION
      ) {
        const migrationCompletion = this.finishInterruptedMigrationIfPresent(candidate.source);
        if (migrationCompletion) return migrationCompletion;
        if (this.stateMigrationStatus.status !== 'migrated') {
          this.stateMigrationStatus = {
            status: 'current',
            supported_state_version: CURRENT_STATE_VERSION,
            supported_journal_version: CURRENT_JOURNAL_VERSION,
            observed_state_version: CURRENT_STATE_VERSION,
            observed_journal_version: CURRENT_JOURNAL_VERSION,
            migration_required: false,
          };
        }
      }

      return this.finishRestoredBase(restored, mutators);
    }

    if (invalidVersioned.length > 0) return this.enterInvalidVersionedStateFailure(invalidVersioned[0]);
    try {
      if (this.ctx.mutationJournal?.hasData()) {
        return this.enterNoBaseRecovery(rejected);
      }
    } catch (error) {
      return this.enterJournalAccessFailure(
        error,
        existsSync(this.ctx.stateFilePath) ? 'state' : 'fresh',
      );
    }
    if (candidates.length > 0) {
      return this.enterNoValidBaseRecovery(rejected, candidates[0]!.source);
    }
    return { status: 'seed_required', source: 'fresh' };
  }

  private enterInvalidVersionedStateFailure(input: {
    candidate: RestoreCandidate;
    error: unknown;
    checkpoint?: number;
    observedStateVersion?: number;
    observedJournalVersion?: number;
  }): RestoreResult {
    const errorMessage = input.error instanceof Error ? input.error.message : String(input.error);
    const reason = `persisted versioned recovery head at ${input.candidate.path} is invalid and cannot be replaced automatically: ${errorMessage}`;
    this.recoveryReadOnlyReason = reason;
    this.ctx.mutationJournal?.blockAppends(reason);
    this.stateMigrationStatus = {
      status: 'blocked',
      supported_state_version: CURRENT_STATE_VERSION,
      supported_journal_version: CURRENT_JOURNAL_VERSION,
      ...(input.observedStateVersion !== undefined
        ? { observed_state_version: input.observedStateVersion }
        : {}),
      ...(input.observedJournalVersion !== undefined
        ? { observed_journal_version: input.observedJournalVersion }
        : {}),
      migration_required: false,
      reason,
    };
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source: input.candidate.source,
      complete: false,
      writable: false,
      reason,
      checkpoint: input.checkpoint ?? 0,
      preserved: true,
    });
    return {
      status: 'degraded',
      source: input.candidate.source,
      reason,
    };
  }

  private finishInterruptedMigrationIfPresent(
    source: 'state' | 'snapshot',
  ): RestoreResult | undefined {
    if (!hasStateMigrationIntent(this.ctx.stateFilePath)) return undefined;
    try {
      this.acquireMigrationLease();
      const backup = completeStateMigration(
        this.ctx.stateFilePath,
        this.releaseMigrationLease?.token,
      );
      this.stateMigrationStatus = {
        status: 'migrated',
        supported_state_version: CURRENT_STATE_VERSION,
        supported_journal_version: CURRENT_JOURNAL_VERSION,
        observed_state_version:
          backup?.manifest.source_state_version ?? LEGACY_STATE_VERSION,
        observed_journal_version:
          backup?.manifest.source_journal_version ?? LEGACY_JOURNAL_VERSION,
        migration_required: false,
        ...(backup
          ? {
              backup_path: backup.directory,
              backup_manifest_sha256: backup.manifest_sha256,
            }
          : {}),
      };
      this.releaseHeldMigrationLease();
      return undefined;
    } catch (error) {
      return this.enterMigrationFailure(
        source,
        `completed V1 state has an invalid or unretirable migration intent: ${error instanceof Error ? error.message : String(error)}`,
        CURRENT_STATE_VERSION,
        false,
        CURRENT_JOURNAL_VERSION,
      );
    }
  }

  private beginLegacyMigration(): void {
    this.acquireMigrationLease();
    this.migrationBackup = prepareStateMigrationBackup({
      stateFilePath: this.ctx.stateFilePath,
      configFilePath: this.ctx.configFilePath,
    });
    this.stateMigrationStatus = {
      status: 'backup_created',
      supported_state_version: CURRENT_STATE_VERSION,
      supported_journal_version: CURRENT_JOURNAL_VERSION,
      observed_state_version: LEGACY_STATE_VERSION,
      observed_journal_version: LEGACY_JOURNAL_VERSION,
      migration_required: true,
      backup_path: this.migrationBackup.directory,
      backup_manifest_sha256: this.migrationBackup.manifest_sha256,
    };
  }

  private enterMigrationFailure(
    source: 'state' | 'snapshot',
    reason: string,
    observedStateVersion: typeof LEGACY_STATE_VERSION | typeof CURRENT_STATE_VERSION = LEGACY_STATE_VERSION,
    migrationRequired = observedStateVersion === LEGACY_STATE_VERSION,
    observedJournalVersion: SupportedJournalVersion = LEGACY_JOURNAL_VERSION,
  ): RestoreResult {
    this.recoveryReadOnlyReason = reason;
    this.ctx.mutationJournal?.blockAppends(reason);
    let journalPreserved = false;
    try { journalPreserved = this.ctx.mutationJournal?.hasData() ?? false; } catch { journalPreserved = true; }
    this.stateMigrationStatus = {
      status: 'blocked',
      supported_state_version: CURRENT_STATE_VERSION,
      supported_journal_version: CURRENT_JOURNAL_VERSION,
      observed_state_version: observedStateVersion,
      observed_journal_version: observedJournalVersion,
      migration_required: migrationRequired,
      ...(this.migrationBackup || this.journalUpgradeBackup
        ? {
            backup_path: (this.migrationBackup ?? this.journalUpgradeBackup)!.directory,
            backup_manifest_sha256: (this.migrationBackup ?? this.journalUpgradeBackup)!.manifest_sha256,
          }
        : {}),
      reason,
    };
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source,
      complete: false,
      writable: false,
      reason,
      checkpoint: 0,
      preserved: journalPreserved,
    });
    try {
      this.releaseHeldMigrationLease();
    } catch (releaseError) {
      this.stateMigrationStatus.reason =
        `${reason}; migration lease release failed: ${releaseError instanceof Error ? releaseError.message : String(releaseError)}`;
      this.recoveryStatus.reason = this.stateMigrationStatus.reason;
    }
    return {
      status: 'degraded',
      source,
      reason: this.recoveryStatus.reason ?? reason,
    };
  }

  private enterUnsupportedFormatFailure(
    candidate: RestoreCandidate,
    error: PersistedStateVersionError | PersistedJournalVersionError,
  ): RestoreResult {
    const format = error instanceof PersistedStateVersionError ? 'state' : 'journal';
    const reason = `persisted ${format} format at ${candidate.path} is newer than this binary: ${error.message}`;
    this.recoveryReadOnlyReason = reason;
    this.ctx.mutationJournal?.blockAppends(reason);
    let journalPreserved = false;
    try { journalPreserved = this.ctx.mutationJournal?.hasData() ?? false; } catch { journalPreserved = true; }
    this.stateMigrationStatus = {
      status: 'blocked',
      supported_state_version: CURRENT_STATE_VERSION,
      supported_journal_version: CURRENT_JOURNAL_VERSION,
      ...(error instanceof PersistedJournalVersionError
        ? { observed_state_version: CURRENT_STATE_VERSION }
        : {}),
      ...(error instanceof PersistedStateVersionError
        && typeof error.observedVersion === 'number'
        ? { observed_state_version: error.observedVersion }
        : {}),
      ...(error instanceof PersistedJournalVersionError
        && typeof error.observedVersion === 'number'
        ? { observed_journal_version: error.observedVersion }
        : {}),
      migration_required: false,
      reason,
    };
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source: candidate.source,
      complete: false,
      writable: false,
      reason,
      checkpoint: 0,
      preserved: journalPreserved,
    });
    this.ctx.logEvent({
      description: 'Persistence recovery blocked by an unsupported state format',
      event_type: 'system',
      category: 'system',
      outcome: 'failure',
      result_classification: 'failure',
      details: {
        reason,
        path: candidate.path,
        observed_version: error.observedVersion,
        format,
      },
    });
    return { status: 'degraded', source: candidate.source, reason };
  }

  private describeIncompleteReplay(replay: MutationReplayResult): string {
    if (
      replay.stopped_at_seq !== undefined
      && (
        replay.read_issue?.actual_seq === undefined
        || replay.stopped_at_seq < replay.read_issue.actual_seq
      )
    ) {
      return `WAL replay stopped at seq ${replay.stopped_at_seq}`;
    }
    if (replay.read_issue) {
      const issue = replay.read_issue;
      if (issue.kind === 'sequence_gap') {
        return `WAL sequence gap at line ${issue.line}: expected seq ${issue.expected_seq}, found ${issue.actual_seq}`;
      }
      if (issue.kind === 'unknown_type' || issue.kind === 'ambiguous_checkpoint') {
        return `WAL recovery cannot safely continue at line ${issue.line}: ${issue.reason}`;
      }
      return issue.unterminated_eof_fragment
        ? `WAL unterminated EOF fragment at line ${issue.line}: ${issue.reason}`
        : `WAL malformed entry at line ${issue.line}: ${issue.reason}`;
    }
    if (replay.stopped_at_seq !== undefined) {
      return `WAL replay stopped at seq ${replay.stopped_at_seq}`;
    }
    return `WAL replay stopped after contiguous seq ${replay.highest_contiguous_applied_seq}`;
  }

  private validateStateBase(data: unknown): RestoredCheckpoint {
    if (!data || typeof data !== 'object') throw new Error('persisted state is not an object');
    const record = data as Record<string, unknown>;
    const stateVersion = detectStateVersion(record);
    const journalVersion = detectJournalVersion(record, stateVersion);
    const compactionAuthority = this.walCompactionAuthorityStatus(record);
    if (compactionAuthority === 'invalid') {
      throw new StateIntegrityError(
        'persisted WAL compaction authority checksum does not match the state payload',
        Number.isSafeInteger(record.journalSnapshotSeq) && (record.journalSnapshotSeq as number) >= 0
          ? record.journalSnapshotSeq as number
          : undefined,
      );
    }
    if (stateVersion === CURRENT_STATE_VERSION) {
      validatePersistedStateV1(record);
    }
    if (!record.config || typeof record.config !== 'object') throw new Error('persisted state is missing config');
    const configValidation = engagementConfigSchema.safeParse(record.config);
    if (!configValidation.success) {
      const issues = configValidation.error.issues
        .map(issue => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
        .join('; ');
      throw new Error(`persisted state config is invalid: ${issues}`);
    }
    if (!record.graph || typeof record.graph !== 'object') throw new Error('persisted state is missing graph');
    this.validatePersistedAuxiliaryShapes(record);
    if (
      record.journalSnapshotSeq !== undefined
      && (!Number.isSafeInteger(record.journalSnapshotSeq) || (record.journalSnapshotSeq as number) < 0)
    ) {
      throw new Error('persisted journalSnapshotSeq must be a non-negative safe integer');
    }
    const checkpoint = typeof record.journalSnapshotSeq === 'number' ? record.journalSnapshotSeq : 0;
    this.validateRollbackIntent(record, checkpoint);
    const scratch = this.createGraph();
    scratch.import(record.graph as Parameters<OverwatchGraph['import']>[0]);
    return {
      checkpoint,
      trusted: isTrustedJournalCheckpoint(record.journalCheckpointSemantics, journalVersion),
      compactionTrusted: compactionAuthority === 'valid',
      stateVersion,
      journalVersion,
    };
  }

  /** Compaction requires more than a rankable config/graph/checkpoint. Only a
   * checksum-bound base emitted by this writer can authorize WAL deletion, and
   * it must pass the exact full-state deserializer in a detached context. */
  private validateCompactionAnchor(data: unknown): RestoredCheckpoint {
    const validated = this.validateStateBase(data);
    if (!validated.compactionTrusted) {
      return { ...validated, compactionTrusted: false };
    }

    this.validateFullStateDetached(data, this.builtinRules);
    return { ...validated, compactionTrusted: true };
  }

  private validateFullStateDetached(data: unknown, builtinRules: InferenceRule[]): void {
    const liveCtx = this.ctx;
    const scratchStatePath = join(
      dirname(liveCtx.stateFilePath),
      `.${basename(liveCtx.stateFilePath)}.state-validation-${process.pid}-${randomUUID()}.json`,
    );
    const scratchCtx = new EngineContext(this.createGraph(), liveCtx.config, scratchStatePath);
    // The detached context must never observe or create a persistence stream.
    scratchCtx.mutationJournal = null;
    try {
      this.ctx = scratchCtx;
      this._restoreFromData(data, builtinRules);
    } finally {
      this.ctx = liveCtx;
    }
  }

  private walCompactionAuthorityStatus(
    record: Record<string, unknown>,
  ): 'absent_or_unknown' | 'valid' | 'invalid' {
    const rawAuthority = record.walCompactionAuthority;
    if (!rawAuthority || typeof rawAuthority !== 'object' || Array.isArray(rawAuthority)) {
      return 'absent_or_unknown';
    }
    const authority = rawAuthority as Record<string, unknown>;
    if (authority.semantics !== WAL_COMPACTION_AUTHORITY_SEMANTICS) return 'absent_or_unknown';
    if (typeof authority.payload_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(authority.payload_sha256)) {
      return 'invalid';
    }
    const payload = { ...record };
    delete payload.walCompactionAuthority;
    const actual = createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    return actual === authority.payload_sha256 ? 'valid' : 'invalid';
  }

  /** Legacy snapshots may omit auxiliary fields, but a present field with the
   * wrong container shape is not a valid full-state recovery base. Several old
   * deserializers silently coerced those values to empty state, which could
   * otherwise let a corrupt snapshot authorize deletion of its WAL proof. */
  private validatePersistedAuxiliaryShapes(record: Record<string, unknown>): void {
    const arrayFields = [
      'activityLog',
      'agents',
      'campaigns',
      'agentDirectives',
      'approvalRequests',
      'inferenceRules',
      'trackedProcesses',
      'runtimeRuns',
      'playbookRuns',
      'sessionDescriptors',
      'commandPlans',
      'commandOutcomes',
      'coldStore',
      'chainCheckpoints',
      'recentFindingHashes',
    ] as const;
    for (const field of arrayFields) {
      if (Object.prototype.hasOwnProperty.call(record, field) && !Array.isArray(record[field])) {
        throw new Error(`persisted ${field} must be an array when present`);
      }
    }

    const objectFields = [
      'opsecTracker',
      'frontierLinkage',
      'frontierLeases',
      'frontierWeights',
      'artifactReferences',
      'proposedPlans',
      'agentQueries',
    ] as const;
    for (const field of objectFields) {
      const value = record[field];
      if (
        Object.prototype.hasOwnProperty.call(record, field)
        && (value === null || typeof value !== 'object' || Array.isArray(value))
      ) {
        throw new Error(`persisted ${field} must be an object when present`);
      }
    }

    if (Array.isArray(record.coldStore)) {
      for (const [index, value] of record.coldStore.entries()) {
        if (!value || typeof value !== 'object' || Array.isArray(value)
          || typeof (value as Record<string, unknown>).id !== 'string'
          || (value as Record<string, unknown>).id === '') {
          throw new Error(`persisted coldStore[${index}] must be an object with a nonempty id`);
        }
      }
    }
    if (
      record.deterministicSeq !== undefined
      && (!Number.isSafeInteger(record.deterministicSeq) || (record.deterministicSeq as number) < 0)
    ) {
      throw new Error('persisted deterministicSeq must be a non-negative safe integer');
    }
    for (const field of ['chainEventsSinceCheckpoint', 'dedupCount'] as const) {
      if (
        record[field] !== undefined
        && (!Number.isSafeInteger(record[field]) || (record[field] as number) < 0)
      ) {
        throw new Error(`persisted ${field} must be a non-negative safe integer`);
      }
    }
    if (record.lastKnownPhaseId !== undefined && typeof record.lastKnownPhaseId !== 'string') {
      throw new Error('persisted lastKnownPhaseId must be a string when present');
    }
  }

  private validateRollbackIntent(
    record: Record<string, unknown>,
    checkpoint: number,
  ): RollbackIntentV1 | undefined {
    if (!Object.prototype.hasOwnProperty.call(record, 'rollbackIntent')) return undefined;
    const raw = record.rollbackIntent;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error('persisted rollbackIntent must be an object');
    }
    const intent = raw as Record<string, unknown>;
    if (intent.version !== 1) {
      throw new Error('persisted rollbackIntent version is unsupported');
    }
    if (!Number.isSafeInteger(intent.checkpoint) || (intent.checkpoint as number) < 0) {
      throw new Error('persisted rollbackIntent checkpoint must be a non-negative safe integer');
    }
    if (intent.checkpoint !== checkpoint) {
      throw new Error('persisted rollbackIntent checkpoint does not match the state checkpoint');
    }
    if (typeof intent.selected_snapshot !== 'string' || intent.selected_snapshot.length === 0) {
      throw new Error('persisted rollbackIntent selected_snapshot must be a non-empty string');
    }
    if (typeof intent.selected_snapshot_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(intent.selected_snapshot_sha256)) {
      throw new Error('persisted rollbackIntent selected_snapshot_sha256 must be a lowercase SHA-256 digest');
    }
    if (typeof intent.intent_checksum !== 'string' || !/^[a-f0-9]{64}$/.test(intent.intent_checksum)) {
      throw new Error('persisted rollbackIntent intent_checksum must be a lowercase SHA-256 digest');
    }
    const stateDir = resolve(dirname(this.ctx.stateFilePath));
    const selected = resolve(stateDir, intent.selected_snapshot);
    const relativePath = relative(stateDir, selected);
    if (!relativePath || isAbsolute(relativePath) || relativePath === '..' || relativePath.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
      throw new Error('persisted rollbackIntent selected_snapshot escapes the state directory');
    }
    const validated: RollbackIntentV1 = {
      version: 1,
      checkpoint: intent.checkpoint as number,
      selected_snapshot: intent.selected_snapshot,
      selected_snapshot_sha256: intent.selected_snapshot_sha256,
      intent_checksum: intent.intent_checksum,
    };
    const expectedChecksum = this.rollbackIntentChecksum({
      version: validated.version,
      checkpoint: validated.checkpoint,
      selected_snapshot: validated.selected_snapshot,
      selected_snapshot_sha256: validated.selected_snapshot_sha256,
    });
    if (validated.intent_checksum !== expectedChecksum) {
      throw new Error('persisted rollbackIntent checksum is invalid');
    }
    return validated;
  }

  private validateStandaloneRollbackIntent(data: unknown): RollbackIntentV1 {
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('rollback authority sidecar must contain an object');
    }
    const checkpoint = (data as Record<string, unknown>).checkpoint;
    if (!Number.isSafeInteger(checkpoint) || (checkpoint as number) < 0) {
      throw new Error('rollback authority sidecar checkpoint must be a non-negative safe integer');
    }
    return this.validateRollbackIntent(
      { rollbackIntent: data },
      checkpoint as number,
    )!;
  }

  private rollbackCheckpointHint(data: unknown): number | undefined {
    if (!data || typeof data !== 'object') return undefined;
    const raw = (data as Record<string, unknown>).rollbackIntent;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
    const checkpoint = (raw as Record<string, unknown>).checkpoint;
    return Number.isSafeInteger(checkpoint) && (checkpoint as number) >= 0
      ? checkpoint as number
      : undefined;
  }

  private rollbackCheckpointHintFromIntentFile(path: string): number | undefined {
    try {
      const raw = parseJsonBytes(this.readPersistedBytes(path)) as Record<string, unknown>;
      const checkpoint = raw?.checkpoint;
      return Number.isSafeInteger(checkpoint) && (checkpoint as number) >= 0
        ? checkpoint as number
        : undefined;
    } catch {
      return undefined;
    }
  }

  private latchRollbackFailure(
    error: unknown,
    checkpoint: number,
    source: 'state' | 'snapshot',
  ): void {
    const message = error instanceof Error ? error.message : String(error);
    const reason = `rollback completion failed at checkpoint ${checkpoint}; restart required: ${message}`;
    this.cancelTimers();
    this.cancelRetryTimer();
    // Do not let the generic shutdown/retry path write this partially completed
    // in-memory state. The marked primary (when installed) is the only safe
    // authority for the next startup attempt.
    this.dirty = false;
    this.pendingDetail = {};
    this.pendingRecoveryCheckpoint = undefined;
    this.pendingRecoverySource = undefined;
    this.persistenceFailureGateTripped = true;
    this.lastPersistenceError = message;
    this.recoveryReadOnlyReason = reason;
    this.ctx.mutationJournal?.blockAppends(reason);
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source,
      complete: false,
      writable: false,
      reason,
      checkpoint,
      preserved: true,
    });
    this.durableConfig = JSON.parse(JSON.stringify(this.ctx.config)) as EngagementConfig;
    this.recoveryStatus.last_persistence_error = message;
  }

  private latchPostCommitApplyFailure(seq: number, error: unknown): void {
    const message = error instanceof Error ? error.message : String(error);
    const reason = `committed transaction seq ${seq} failed during in-memory application; restart required: ${message}`;
    this.cancelTimers();
    this.cancelRetryTimer();
    // Memory may contain a partial transaction. Never let the ordinary
    // snapshot/retry/shutdown path publish that state over the committed WAL.
    this.dirty = false;
    this.pendingDetail = {};
    this.pendingRecoveryCheckpoint = undefined;
    this.pendingRecoverySource = undefined;
    this.persistenceFailureGateTripped = true;
    this.lastPersistenceError = message;
    this.recoveryReadOnlyReason = reason;
    this.ctx.mutationJournal?.blockAppends(reason);
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source: this.recoveryStatus.source,
      complete: false,
      writable: false,
      reason,
      checkpoint: this.ctx.journalSnapshotSeq,
      preserved: true,
      highestContiguousAppliedSeq: this.ctx.mutationJournal?.getAppliedThroughSeq()
        ?? this.ctx.journalSnapshotSeq,
    });
    this.recoveryStatus.last_persistence_error = message;
    // eslint-disable-next-line no-console
    console.error(`[persistence] ${reason}`);
  }

  private finishRestoredBase(restored: RestoredBase, mutators?: ReplayMutators): RestoreResult {
    const replay = restored.replay;
    const checkpoint = replay?.highest_contiguous_applied_seq ?? restored.checkpoint;
    const migratingLegacyState = restored.stateVersion === LEGACY_STATE_VERSION;
    const migratingLegacyJournal = restored.journalVersion === LEGACY_JOURNAL_VERSION;
    const recovered = restored.source === 'snapshot'
      || checkpoint !== restored.checkpoint
      || migratingLegacyState
      || migratingLegacyJournal;

    if (replay && (replay.read > 0 || replay.read_issue !== undefined)) {
      this.ctx.logEvent({
        description: `WAL replay applied ${replay.applied} of ${replay.read} mutation(s)`,
        event_type: 'system',
        category: 'system',
        outcome: 'success',
        details: {
          read: replay.read,
          attempted: replay.attempted,
          applied: replay.applied,
          skipped: replay.skipped,
          failed: replay.failed,
          highest_on_disk_seq: replay.highest_on_disk_seq,
          highest_contiguous_applied_seq: replay.highest_contiguous_applied_seq,
        },
      });
    }

    if (migratingLegacyState) {
      try {
        if (!this.migrationBackup) {
          throw new Error('legacy migration backup authority is missing');
        }
        assertStateMigrationSourcesUnchanged({
          backup: this.migrationBackup,
          stateFilePath: this.ctx.stateFilePath,
          configFilePath: this.ctx.configFilePath,
        });
        activateStateMigration(
          this.ctx.stateFilePath,
          this.migrationBackup,
          this.releaseMigrationLease?.token,
        );
      } catch (error) {
        mutators?.abortRecoveryReplay?.();
        return this.enterMigrationFailure(
          restored.source,
          `legacy replay completed, but migration publication was not authorized: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    if (migratingLegacyJournal && !migratingLegacyState) {
      try {
        if (!this.journalUpgradeBackup) {
          throw new Error('journal upgrade backup authority is missing');
        }
        assertStateMigrationSourcesUnchanged({
          backup: this.journalUpgradeBackup,
          stateFilePath: this.ctx.stateFilePath,
          configFilePath: this.ctx.configFilePath,
        });
      } catch (error) {
        mutators?.abortRecoveryReplay?.();
        return this.enterMigrationFailure(
          restored.source,
          `journal-v1 replay completed, but journal-v2 publication was not authorized: ${error instanceof Error ? error.message : String(error)}`,
          restored.stateVersion,
          true,
        );
      }
    }

    // A retained, already-applied WAL prefix is a recovery anchor, not a reason
    // to rewrite state on every restart. V0 is the exception: once its complete
    // replay and byte-exact backup are proven, publish V1 even at the same
    // checkpoint.
    if (
      migratingLegacyState
      || migratingLegacyJournal
      || restored.source === 'snapshot'
      || checkpoint !== restored.checkpoint
    ) {
      try {
        mutators?.prepareRecoveryCommit?.();
        this.writeStateToDisk({
          journalCheckpointSeq: checkpoint,
          rotateExisting: false,
          allowIntegrityReplacement: restored.source === 'snapshot',
        });
        mutators?.completeRecoveryCommit?.();
        this.finishRecoveryCheckpoint(checkpoint, restored.source);
      } catch (error) {
        mutators?.abortRecoveryReplay?.();
        return this.enterCheckpointFailure(restored, checkpoint, error);
      }
    }

    this.recoveryReadOnlyReason = undefined;
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: recovered ? 'recovered' : 'clean',
      source: restored.source,
      complete: true,
      writable: true,
      checkpoint,
      replay,
      preserved: false,
    });
    if (restored.source === 'snapshot') {
      this.ctx.logEvent({
        description: `Recovered engagement from snapshot: ${basename(restored.path)}`,
        event_type: 'system',
        category: 'system',
        outcome: 'success',
        details: { checkpoint },
      });
    }
    if (restored.repairedIncompleteTail) {
      this.ctx.logEvent({
        description: 'Recovered by discarding an uncommitted journal-v2 tail',
        event_type: 'system',
        category: 'system',
        outcome: 'success',
        result_classification: 'neutral',
        details: {
          quarantine_path: restored.repairedIncompleteTail.quarantine_path,
          dropped_bytes: restored.repairedIncompleteTail.dropped_bytes,
          committed_transactions: restored.repairedIncompleteTail.committed_transactions,
        },
      });
    }
    return { status: 'restored', source: restored.source };
  }

  private enterIncompleteRecovery(restored: RestoredBase, reason: string): RestoreResult {
    const journal = this.ctx.mutationJournal;
    // Fully committed records before the first bad/skipped/failed record remain
    // authoritative and visible in degraded read-only mode. Do not checkpoint
    // them or alter the WAL; each restart deterministically reapplies the same
    // prefix from the selected base and stops at the same boundary.
    this.recoveryReadOnlyReason = reason;
    journal?.blockAppends(reason);
    const quarantine = this.quarantineJournal();
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source: restored.source,
      complete: false,
      writable: false,
      reason,
      checkpoint: restored.checkpoint,
      replay: restored.replay,
      preserved: true,
      highestContiguousAppliedSeq:
        restored.replay?.highest_contiguous_applied_seq ?? restored.checkpoint,
    });
    this.ctx.logEvent({
      description: `WAL recovery incomplete; service entered degraded read-only mode`,
      event_type: 'system',
      category: 'system',
      outcome: 'failure',
      result_classification: 'failure',
      details: {
        reason,
        base: restored.path,
        checkpoint: restored.checkpoint,
        replay: restored.replay,
        quarantine_path: quarantine.path,
        quarantine_error: quarantine.error,
      },
    });
    return { status: 'degraded', source: restored.source, reason };
  }

  private enterNoValidBaseRecovery(
    rejected: Array<{ path: string; error: string }>,
    source: 'state' | 'snapshot',
  ): RestoreResult {
    const reason = 'persisted state artifacts exist, but no valid full-state recovery base remains';
    this.recoveryReadOnlyReason = reason;
    this.ctx.mutationJournal?.blockAppends(reason);
    this.stateMigrationStatus = {
      status: 'blocked',
      supported_state_version: CURRENT_STATE_VERSION,
      supported_journal_version: CURRENT_JOURNAL_VERSION,
      migration_required: false,
      reason,
    };
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source,
      complete: false,
      writable: false,
      reason,
      checkpoint: 0,
      preserved: true,
    });
    this.ctx.logEvent({
      description: 'State recovery blocked: no valid persisted base; service entered degraded read-only mode',
      event_type: 'system',
      category: 'system',
      outcome: 'failure',
      result_classification: 'failure',
      details: {
        reason,
        rejected_bases: rejected,
      },
    });
    return { status: 'degraded', source, reason };
  }

  private enterNoBaseRecovery(rejected: Array<{ path: string; error: string }>): RestoreResult {
    const reason = 'a nonempty WAL exists without a valid full-state base';
    const journal = this.ctx.mutationJournal!;
    this.recoveryReadOnlyReason = reason;
    journal.blockAppends(reason);
    const quarantine = this.quarantineJournal();
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source: 'fresh',
      complete: false,
      writable: false,
      reason,
      checkpoint: 0,
      preserved: true,
    });
    this.ctx.logEvent({
      description: 'WAL recovery blocked: no valid base; service entered degraded read-only mode',
      event_type: 'system',
      category: 'system',
      outcome: 'failure',
      result_classification: 'failure',
      details: {
        reason,
        rejected_bases: rejected,
        quarantine_path: quarantine.path,
        quarantine_error: quarantine.error,
      },
    });
    return { status: 'degraded', source: 'fresh', reason };
  }

  private enterStateIntegrityFailure(
    rejected: IntegrityRejectedBase[],
  ): RestoreResult {
    const first = rejected[0]!;
    const reason = `persisted ${first.source} recovery base failed its recognized integrity check at ${first.path}: ${first.error}`;
    this.recoveryReadOnlyReason = reason;
    this.ctx.mutationJournal?.blockAppends(reason);
    let journalPreserved = false;
    try { journalPreserved = this.ctx.mutationJournal?.hasData() ?? false; } catch { journalPreserved = true; }
    const quarantine = journalPreserved ? this.quarantineJournal() : {};
    this.stateMigrationStatus = {
      status: 'blocked',
      supported_state_version: CURRENT_STATE_VERSION,
      supported_journal_version: CURRENT_JOURNAL_VERSION,
      ...(first.stateVersion !== undefined
        ? { observed_state_version: first.stateVersion }
        : {}),
      observed_journal_version: CURRENT_JOURNAL_VERSION,
      migration_required: first.stateVersion === LEGACY_STATE_VERSION,
      reason,
    };
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source: first.source,
      complete: false,
      writable: false,
      reason,
      checkpoint: 0,
      preserved: journalPreserved,
    });
    this.ctx.logEvent({
      description: 'Persistence recovery blocked by a state integrity mismatch',
      event_type: 'system',
      category: 'system',
      outcome: 'failure',
      result_classification: 'failure',
      details: {
        reason,
        rejected_bases: rejected,
        quarantine_path: quarantine.path,
        quarantine_error: quarantine.error,
      },
    });
    return { status: 'degraded', source: first.source, reason };
  }

  private enterJournalAccessFailure(
    error: unknown,
    source: 'fresh' | 'state' | 'snapshot',
    precedingReason?: string,
  ): RestoreResult {
    const journalReason = this.describeJournalAccessFailure(error);
    const reason = precedingReason
      ? `${precedingReason}; additionally, ${journalReason}`
      : journalReason;
    this.latchJournalRecoveryFailure({
      reason,
      error,
      malformed: false,
      accessFailure: true,
    });
    this.recoveryStatus = { ...this.recoveryStatus, source };
    return { status: 'degraded', source, reason };
  }

  private enterBaseAccessFailure(
    source: 'state' | 'snapshot',
    path: string,
    error: unknown,
  ): RestoreResult {
    const message = error instanceof Error ? error.message : String(error);
    const reason = `persisted ${source} recovery base could not be read at ${path}: ${message}`;
    if (this.journalAccessError !== undefined) {
      return this.enterJournalAccessFailure(this.journalAccessError, source, reason);
    }
    this.recoveryReadOnlyReason = reason;
    this.ctx.mutationJournal?.blockAppends(reason);
    let journalPreserved = false;
    try { journalPreserved = this.ctx.mutationJournal?.hasData() ?? false; } catch { journalPreserved = true; }
    const quarantine = journalPreserved ? this.quarantineJournal() : {};
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source,
      complete: false,
      writable: false,
      reason,
      checkpoint: 0,
      preserved: journalPreserved,
    });
    this.ctx.logEvent({
      description: 'Persistence recovery blocked by an unreadable recovery base',
      event_type: 'system',
      category: 'system',
      outcome: 'failure',
      result_classification: 'failure',
      details: {
        source,
        path,
        error: message,
        quarantine_path: quarantine.path,
        quarantine_error: quarantine.error,
      },
    });
    return { status: 'degraded', source, reason };
  }

  private enterCheckpointFailure(
    restored: RestoredBase,
    checkpoint: number,
    error: unknown,
  ): RestoreResult {
    const message = error instanceof Error ? error.message : String(error);
    const reason = `recovered state could not be checkpointed: ${message}`;
    this.pendingRecoveryCheckpoint = checkpoint;
    this.pendingRecoverySource = restored.source;
    this.recoveryReadOnlyReason = reason;
    this.dirty = true;
    this.ctx.mutationJournal?.blockAppends(reason);
    const quarantine = this.quarantineJournal();
    this.recoveryStatus = this.buildRecoveryStatus({
      outcome: 'incomplete',
      source: restored.source,
      complete: false,
      writable: false,
      reason,
      checkpoint: restored.checkpoint,
      replay: restored.replay,
      preserved: true,
    });
    if (quarantine.error) {
      this.recoveryStatus.reason = `${reason}; WAL quarantine failed: ${quarantine.error}`;
    }
    this.recordPersistenceFailure(error, 'recovery_checkpoint');
    return { status: 'degraded', source: restored.source, reason };
  }

  private quarantineJournal(): { path?: string; error?: string } {
    try {
      const path = this.ctx.mutationJournal?.quarantine();
      return path ? { path } : {};
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  }

  private finishRecoveryCheckpoint(
    checkpoint: number,
    source: 'state' | 'snapshot',
    options: { restartRequired?: boolean } = {},
  ): void {
    const journal = this.ctx.mutationJournal;
    const highestAllocatedLogicalSeq = Math.max(
      this.recoveryStatus.highest_allocated_logical_seq
        ?? this.recoveryStatus.highest_allocated_seq,
      journal?.getHighestAllocatedSeq() ?? checkpoint,
    );
    const highestAllocatedFrameSeq = Math.max(
      this.recoveryStatus.highest_allocated_frame_seq ?? 0,
      journal?.getHighestAllocatedFrameSeq() ?? checkpoint,
    );
    const highestLogicalOnDiskSeq = Math.max(
      this.recoveryStatus.highest_on_disk_seq,
      this.highestPhysicalSeqOr(checkpoint),
    );
    const highestPhysicalFrameSeq = Math.max(
      this.recoveryStatus.highest_physical_frame_seq ?? 0,
      this.highestPhysicalFrameSeqOr(0),
    );
    if (journal) {
      const oldestSnapshotCheckpoint = this.oldestRetainedValidSnapshotCheckpoint();
      // Without a retained valid snapshot, keep the whole WAL. When snapshots
      // exist, retain every record newer than the oldest one so corruption in
      // the primary/newer snapshots can still fall back through the full chain.
      if (
        oldestSnapshotCheckpoint !== undefined
        && oldestSnapshotCheckpoint > 0
        && oldestSnapshotCheckpoint <= checkpoint
      ) {
        const result = journal.compactUpTo(oldestSnapshotCheckpoint);
        if ('preserved' in result) {
          throw new Error(`recovery checkpoint committed but WAL compaction refused: ${result.reason}`);
        }
      }
      journal.setNextSeq(checkpoint);
    }
    this.pendingRecoveryCheckpoint = undefined;
    this.pendingRecoverySource = undefined;
    const restartReason = options.restartRequired
      ? 'recovery checkpoint became durable after startup; restart required to run startup reconciliation before writes resume'
      : undefined;
    this.recoveryReadOnlyReason = restartReason;
    if (journal) {
      if (restartReason) journal.blockAppends(restartReason);
      else journal.unblockAppends();
    }
    this.recoveryStatus = {
      ...this.recoveryStatus,
      outcome: restartReason ? 'incomplete' : 'recovered',
      source,
      complete: restartReason === undefined,
      writable: restartReason === undefined,
      reason: restartReason,
      base_checkpoint: checkpoint,
      highest_allocated_seq: highestAllocatedLogicalSeq,
      highest_allocated_logical_seq: highestAllocatedLogicalSeq,
      highest_allocated_frame_seq: highestAllocatedFrameSeq,
      highest_on_disk_seq: highestLogicalOnDiskSeq,
      highest_physical_frame_seq: highestPhysicalFrameSeq,
      highest_contiguous_applied_seq: checkpoint,
      highest_contiguous_applied_logical_seq: checkpoint,
      journal: { ...this.recoveryStatus.journal, preserved: false },
    };
    this.durableConfig = JSON.parse(JSON.stringify(this.ctx.config)) as EngagementConfig;
  }

  private buildRecoveryStatus(input: {
    outcome: PersistenceRecoveryStatus['outcome'];
    source: PersistenceRecoveryStatus['source'];
    complete: boolean;
    writable: boolean;
    checkpoint: number;
    replay?: MutationReplayResult;
    preserved: boolean;
    reason?: string;
    highestContiguousAppliedSeq?: number;
  }): PersistenceRecoveryStatus {
    const journal = this.ctx.mutationJournal;
    const replay = input.replay;
    const highestAllocatedLogicalSeq = journal?.getHighestAllocatedSeq()
      ?? input.checkpoint;
    const highestAllocatedFrameSeq = journal?.getHighestAllocatedFrameSeq()
      ?? input.checkpoint;
    const highestLogicalOnDiskSeq = replay?.highest_on_disk_seq
      ?? this.highestPhysicalSeqOr(input.checkpoint);
    const highestPhysicalFrameSeq = replay?.highest_physical_frame_seq
      ?? this.highestPhysicalFrameSeqOr(
        this.recoveryStatus.highest_physical_frame_seq ?? 0,
      );
    const highestContiguousAppliedLogicalSeq = input.highestContiguousAppliedSeq
      ?? replay?.highest_contiguous_applied_seq
      ?? journal?.getAppliedThroughSeq()
      ?? input.checkpoint;
    return {
      outcome: input.outcome,
      source: input.source,
      complete: input.complete,
      writable: input.writable,
      ...(input.reason ? { reason: input.reason } : {}),
      base_checkpoint: input.checkpoint,
      highest_allocated_seq: highestAllocatedLogicalSeq,
      highest_allocated_logical_seq: highestAllocatedLogicalSeq,
      highest_allocated_frame_seq: highestAllocatedFrameSeq,
      highest_on_disk_seq: highestLogicalOnDiskSeq,
      highest_physical_frame_seq: highestPhysicalFrameSeq,
      highest_contiguous_applied_seq: highestContiguousAppliedLogicalSeq,
      highest_contiguous_applied_logical_seq: highestContiguousAppliedLogicalSeq,
      consecutive_persistence_failures: this.consecutivePersistenceFailures,
      ...(this.lastPersistenceError ? { last_persistence_error: this.lastPersistenceError } : {}),
      journal: {
        enabled: journal !== null,
        format_version: this.reportedJournalFormatVersion(
          (() => {
            try {
              return journal?.getObservedFormatVersion();
            } catch {
              return undefined;
            }
          })(),
        ),
        ...(journal ? { path: journal.getPath() } : {}),
        read: replay?.read ?? 0,
        attempted: replay?.attempted ?? 0,
        applied: replay?.applied ?? 0,
        skipped: replay?.skipped ?? 0,
        failed: replay?.failed ?? 0,
        // A sequence discontinuity is not malformed JSON. Unterminated EOF
        // fragments are malformed entries and therefore do set this flag.
        malformed: replay?.read_issue?.kind === 'malformed_entry',
        preserved: input.preserved,
      },
    };
  }

  private reportedJournalFormatVersion(observed: number | undefined): number {
    if (observed !== undefined) return observed;
    if (
      (
        this.stateMigrationStatus.status === 'blocked'
        || this.stateMigrationStatus.status === 'backup_created'
      )
      && this.stateMigrationStatus.observed_journal_version !== undefined
    ) {
      return this.stateMigrationStatus.observed_journal_version;
    }
    return CURRENT_JOURNAL_VERSION;
  }

  /**
   * P2.1: factory for the MutationApplier consumed by `MutationJournal.replay`.
   * Replays each journaled mutation by calling the same code paths the
   * original write took — `addNode`/`addEdge` etc. — but with journaling
   * temporarily suppressed (via `mutationJournal: null`) so we don't
   * double-record entries during replay.
   */
  private makeMutationApplier(mutators?: ReplayMutators): import('./mutation-journal.js').MutationApplier {
    const ctx = this.ctx;
    return {
      apply(entry) {
        // During replay: suppress nested journaling (mutationJournal=null) AND
        // the guarded mutators' edge-case events (suppressMutationEvents), so we
        // re-apply state without double-recording or double-logging.
        const savedJournal = ctx.mutationJournal;
        const savedSuppress = ctx.suppressMutationEvents;
        ctx.mutationJournal = null;
        ctx.suppressMutationEvents = true;
        try {
          switch (entry.type) {
            // ROOT FIX: route node/edge replay through the SAME guarded engine
            // mutators the live write took (type-integrity guard, scope-aware
            // edge keying + dedup) instead of a parallel raw-graphology
            // reimplementation that had drifted. addNode re-determines
            // add-vs-merge; addEdge re-derives the scoped edge key.
            case 'add_node':
            case 'merge_node_attrs': {
              const props = (entry.payload as { props: NodeProperties }).props;
              if (mutators) {
                mutators.addNode(props);
              } else if (ctx.graph.hasNode(props.id)) {
                ctx.graph.mergeNodeAttributes(props.id, props as Partial<NodeProperties>);
              } else {
                ctx.graph.addNode(props.id, props);
              }
              return { status: 'applied' };
            }
            case 'replace_node_attrs': {
              // Full-node replace (from patch_node): removes keys the live path
              // cleared via unsetProperties. mergeNodeAttributes could not remove
              // keys, so a merge-based replay would leave a cleared key stale.
              const props = (entry.payload as { props: NodeProperties }).props;
              if (ctx.graph.hasNode(props.id)) {
                ctx.graph.replaceNodeAttributes(props.id, props);
              } else {
                ctx.graph.addNode(props.id, props);
              }
              return { status: 'applied' };
            }
            case 'drop_node': {
              const payload = entry.payload as unknown as DropNodeMutationPayloadV1;
              if (payload.payload_version !== 1) {
                return { status: 'skipped', reason: `unsupported drop_node payload version: ${String(payload.payload_version)}` };
              }
              if (!mutators) {
                return { status: 'skipped', reason: 'drop_node replay requires the engine node-drop applier' };
              }
              return mutators.applyDropNodeMutation(payload, true);
            }
            case 'identity_rewrite': {
              const payload = entry.payload as unknown as IdentityRewriteMutationPayloadV1;
              if (payload.payload_version !== 1) {
                return { status: 'skipped', reason: `unsupported identity_rewrite payload version: ${String(payload.payload_version)}` };
              }
              if (!mutators) {
                return { status: 'skipped', reason: 'identity_rewrite replay requires the engine identity applier' };
              }
              return mutators.applyIdentityRewriteMutation(payload, true);
            }
            case 'graph_corrected': {
              const payload = entry.payload as unknown as GraphCorrectedMutationPayloadV1;
              if (payload.payload_version !== 1) {
                return { status: 'skipped', reason: `unsupported graph_corrected payload version: ${String(payload.payload_version)}` };
              }
              if (!mutators) {
                return { status: 'skipped', reason: 'graph_corrected replay requires the engine correction applier' };
              }
              return mutators.applyGraphCorrectedMutation(payload, true);
            }
            case 'state_patch': {
              const payload = entry.payload as unknown as DurableStatePatchV1;
              if (payload.payload_version !== 1) {
                return {
                  status: 'skipped',
                  reason: `unsupported state_patch payload version: ${String(payload.payload_version)}`,
                };
              }
              if (!mutators) {
                return {
                  status: 'skipped',
                  reason: 'state_patch replay requires the engine state-patch applier',
                };
              }
              return mutators.applyStatePatchMutation(payload, true);
            }
            case 'activity_append': {
              return ctx.applyActivityAppend(
                entry.payload as unknown as ActivityAppendPayloadV1,
              );
            }
            case 'add_edge': {
              const p = entry.payload as {
                source: string;
                target: string;
                props: import('../types.js').EdgeProperties;
                edge_id?: string;
              };
              if (!ctx.graph.hasNode(p.source) || !ctx.graph.hasNode(p.target)) {
                return { status: 'skipped', reason: `missing endpoint(s): ${p.source} -> ${p.target}` };
              }
              if (mutators) {
                mutators.addEdge(p.source, p.target, p.props, p.edge_id);
              } else {
                const existingEdges = ctx.graph.edges(p.source, p.target);
                let merged = false;
                for (const eid of existingEdges) {
                  const ea = ctx.graph.getEdgeAttributes(eid);
                  if (edgeIdentityMatches(ea, p.props)) {
                    ctx.graph.mergeEdgeAttributes(eid, p.props as Partial<import('../types.js').EdgeProperties>);
                    merged = true;
                    break;
                  }
                }
                if (!merged) {
                  const preferredId = preferredEdgeKey(p.source, p.target, p.props);
                  const edgeId = p.edge_id
                    ?? (ctx.graph.hasEdge(preferredId)
                      ? deterministicCollisionEdgeKey(p.source, p.target, p.props)
                      : preferredId);
                  if (ctx.graph.hasEdge(edgeId)) {
                    return { status: 'skipped', reason: `edge identity collision: ${edgeId}` };
                  }
                  ctx.graph.addEdgeWithKey(edgeId, p.source, p.target, p.props);
                }
              }
              return { status: 'applied' };
            }
            case 'merge_edge_attrs': {
              const p = entry.payload as { edge_id: string; props: Partial<import('../types.js').EdgeProperties> };
              if (!ctx.graph.hasEdge(p.edge_id)) {
                return { status: 'skipped', reason: `missing edge: ${p.edge_id}` };
              }
              ctx.graph.mergeEdgeAttributes(p.edge_id, p.props);
              return { status: 'applied' };
            }
            case 'drop_edge': {
              const p = entry.payload as {
                edge_id: string;
                source?: string;
                target?: string;
                edge_type?: string;
              };
              let edgeId = ctx.graph.hasEdge(p.edge_id) ? p.edge_id : undefined;
              if (
                edgeId
                && p.source
                && p.target
                && p.edge_type
                && (
                  ctx.graph.source(edgeId) !== p.source
                  || ctx.graph.target(edgeId) !== p.target
                  || ctx.graph.getEdgeAttributes(edgeId).type !== p.edge_type
                )
              ) {
                edgeId = undefined;
              }
              if (!edgeId && p.source && p.target && p.edge_type) {
                const matches = ctx.graph.hasNode(p.source) && ctx.graph.hasNode(p.target)
                  ? ctx.graph.edges(p.source, p.target).filter(candidate =>
                      ctx.graph.getEdgeAttributes(candidate).type === p.edge_type)
                  : [];
                if (matches.length > 1) {
                  return {
                    status: 'skipped',
                    reason: `ambiguous legacy drop identity for ${p.source} --[${p.edge_type}]--> ${p.target}`,
                  };
                }
                [edgeId] = matches;
              }
              if (!edgeId) {
                // Prefix replay is intentionally idempotent. A trusted base may
                // already reflect this deletion, so absence is the desired end
                // state rather than an incompatible recovery chain.
                return { status: 'applied' };
              }
              ctx.graph.dropEdge(edgeId);
              return { status: 'applied' };
            }
            case 'cold_add': {
              // Re-add a cold-store node lost to a crash before the snapshot flushed.
              const record = (entry.payload as { record: import('./cold-store.js').ColdNodeRecord }).record;
              ctx.coldStore.add(record);
              return { status: 'applied' };
            }
            case 'cold_promote': {
              // A cold node was promoted to hot: remove it from the cold store (the
              // matching add_node/merge entry re-adds it to the graph). promote()
              // is deliberately idempotent when the cold record is already gone.
              const id = (entry.payload as { id: string }).id;
              ctx.coldStore.promote(id);
              return { status: 'applied' };
            }
            case 'scope_updated': {
              const payload = entry.payload as unknown as ScopeUpdatedMutationPayloadV1;
              if (payload.payload_version !== 1) {
                return { status: 'skipped', reason: `unsupported scope_updated payload version: ${String(payload.payload_version)}` };
              }
              if (!mutators) {
                return { status: 'skipped', reason: 'scope_updated replay requires the engine scope applier' };
              }
              return mutators.applyScopeUpdatedMutation(payload, true);
            }
            default:
              // Unknown / future types are tolerated (forward-compat for
              // journals written by a newer version of the engine).
              return { status: 'skipped', reason: `unsupported mutation type: ${entry.type}` };
          }
        } finally {
          ctx.mutationJournal = savedJournal;
          ctx.suppressMutationEvents = savedSuppress;
        }
      },
    };
  }

  private makeTransactionApplier(mutators?: ReplayMutators): EngineTransactionApplier {
    const operationApplier = this.makeMutationApplier(mutators);
    return {
      applyTransaction: transaction => {
        // A standalone activity append has its own O(delta) continuity checks
        // and rollback. Avoid cloning the entire growing engagement for every
        // replayed event; all other transaction shapes retain the full atomic
        // fallback baseline.
        const baseline = transaction.operations.length === 1
          && transaction.operations[0]?.type === 'activity_append'
          ? undefined
          : this.captureRestoreBaseline();
        try {
          for (const operation of transaction.operations) {
            const result = operationApplier.apply({
              seq: transaction.seq,
              ts: transaction.ts,
              type: operation.type,
              payload: operation.payload,
              ...(transaction.source_action_id
                ? { source_action_id: transaction.source_action_id }
                : {}),
            });
            if (result.status === 'skipped') {
              if (baseline !== undefined) {
                this.restoreRejectedCandidateBaseline(baseline, this.builtinRules);
              }
              return result;
            }
          }
          return { status: 'applied' };
        } catch (error) {
          if (baseline !== undefined) {
            this.restoreRejectedCandidateBaseline(baseline, this.builtinRules);
          }
          throw error;
        }
      },
    };
  }

  /**
   * Apply an immutable transaction draft through the exact operation applier
   * used by WAL recovery. Finding ingestion uses this first against a restored
   * baseline to prove its captured operations reproduce the speculative
   * after-state, then again as the live post-commit applier.
   */
  applyTransactionDraft(
    draft: EngineTransactionDraft,
    mutators?: ReplayMutators,
  ): EngineTransactionApplyResult {
    const transaction = {
      version: 2 as const,
      tx_id: 'uncommitted-draft',
      seq: 0,
      begin_frame_seq: 0,
      commit_frame_seq: 0,
      ts: this.ctx.nowIso(),
      ...structuredClone(draft),
    };
    return this.makeTransactionApplier(mutators).applyTransaction(transaction);
  }

  recoverFromSnapshot(builtinRules: InferenceRule[], mutators?: ReplayMutators): boolean {
    const dir = dirname(this.ctx.stateFilePath);
    let snapshots: string[];
    try {
      snapshots = this.listSnapshotsStrict();
    } catch (error) {
      this.enterBaseAccessFailure('snapshot', join(dir, '.snapshots'), error);
      return false;
    }
    const candidates = snapshots.reverse().map<RestoreCandidate>(snapshot => ({
      source: 'snapshot',
      path: join(dir, snapshot),
    }));
    const result = this.restoreCandidates(candidates, builtinRules, mutators);
    return result.status === 'restored';
  }

  private normalizeLoadedNodeProvenance(): void {
    this.ctx.graph.forEachNode((nodeId, attrs) => {
      this.ctx.graph.mergeNodeAttributes(nodeId, normalizeNodeProvenance(attrs) as Partial<NodeProperties>);
    });
  }

  private migrateDefaultCredentialFlags(): void {
    this.ctx.graph.forEachNode((nodeId, attrs) => {
      if (nodeId.startsWith('cred-default-') && attrs.type === 'credential' && !attrs.cred_is_default_guess) {
        this.ctx.graph.mergeNodeAttributes(nodeId, { cred_is_default_guess: true } as Partial<NodeProperties>);
      }
    });
  }
}
