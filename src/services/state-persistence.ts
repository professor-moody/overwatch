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

import { readFileSync, writeFileSync, existsSync, renameSync, unlinkSync, readdirSync, mkdirSync, openSync, fsyncSync, closeSync } from 'fs';
import { dirname, basename, join } from 'path';
import type { EngineContext, OverwatchGraph, GraphUpdateDetail, ActivityLogEntry } from './engine-context.js';
import { normalizeActivityLogEntry } from './engine-context.js';
import { FrontierLinkageTracker } from './frontier-linkage.js';
import { FrontierLeases } from './frontier-leases.js';
import type { InferenceRule, NodeProperties } from '../types.js';
import { normalizeNodeProvenance } from './provenance-utils.js';
import { OpsecTracker } from './opsec-tracker.js';

export const MAX_SNAPSHOTS = 5;

// --- Coalescing configuration ---
export const FLUSH_DEBOUNCE_MS = 100;   // Wait 100ms of quiet before flushing
export const FLUSH_MAX_DELAY_MS = 500;  // Maximum time between dirty and flush

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
}

export class StatePersistence {
  private ctx: EngineContext;
  private builtinRuleIds: Set<string>;

  // --- Write coalescing state ---
  private dirty = false;
  private pendingDetail: GraphUpdateDetail = {};
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private maxDelayTimer: ReturnType<typeof setTimeout> | null = null;
  private batchDepth = 0;  // >0 means inside batchMutate, suppress auto-flush
  private metrics: PersistMetrics = {
    flushCount: 0,
    totalSerializeMs: 0,
    totalWriteMs: 0,
    coalescedCalls: 0,
    lastFlushMs: 0,
  };
  private shutdownHandlers: (() => void)[] = [];

  constructor(ctx: EngineContext, builtinRules: InferenceRule[], _createGraph?: () => OverwatchGraph) {
    this.ctx = ctx;
    this.builtinRuleIds = new Set(builtinRules.map(r => r.id));
    this.hookShutdown();
  }

  /**
   * Mark state as dirty and schedule a coalesced flush.
   * This is the primary persist entry point — callers do NOT block on disk I/O.
   * Detail objects are merged so the final flush includes all changes.
   */
  persist(detail: GraphUpdateDetail = {}): void {
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
  flushNow(): void {
    this.cancelTimers();
    if (!this.dirty) return;
    this.writeStateToDisk();
    this.dirty = false;
    this.pendingDetail = {};
  }

  /**
   * Immediately write state to disk regardless of dirty flag.
   * Use for: initial persist after load, rollback overwrites.
   */
  persistImmediate(detail: GraphUpdateDetail = {}): void {
    this.cancelTimers();
    this.writeStateToDisk();
    this.ctx.fireUpdateCallbacks(detail);
    this.dirty = false;
    this.pendingDetail = {};
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
    return { ...this.metrics };
  }

  /** Reset metrics (e.g., for testing or retrospective boundary). */
  resetMetrics(): void {
    this.metrics = { flushCount: 0, totalSerializeMs: 0, totalWriteMs: 0, coalescedCalls: 0, lastFlushMs: 0 };
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
      this.flushNow();
    }, FLUSH_DEBOUNCE_MS);

    // Max-delay timer ensures we don't wait forever under continuous load
    if (this.maxDelayTimer === null) {
      this.maxDelayTimer = setTimeout(() => {
        this.maxDelayTimer = null;
        this.flushNow();
      }, FLUSH_MAX_DELAY_MS);
    }
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

  /** Cancel any pending flush (for shutdown / disposal). */
  cancelPendingFlush(): void {
    this.cancelTimers();
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
      if (this.dirty) {
        this.cancelTimers();
        try {
          this.writeStateToDisk();
          this.dirty = false;
          this.pendingDetail = {};
        } catch { /* best effort on shutdown */ }
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
    for (const handler of this.shutdownHandlers) {
      unregisterShutdownFlusher(handler);
    }
    this.shutdownHandlers = [];
  }

  // --- Core write logic (unchanged from original) ---

  private writeStateToDisk(): void {
    const serializeStart = Date.now();
    const data = {
      config: this.ctx.config,
      graph: this.ctx.graph.export(),
      activityLog: this.ctx.activityLog,
      agents: Array.from(this.ctx.agents.entries()),
      campaigns: Array.from(this.ctx.campaigns.entries()),
      inferenceRules: this.ctx.inferenceRules.filter(r => !this.builtinRuleIds.has(r.id)),
      trackedProcesses: this.ctx.trackedProcesses,
      coldStore: this.ctx.coldStore.export(),
      opsecTracker: this.ctx.opsecTracker.serialize(),
      frontierLinkage: this.ctx.frontierLinkage.serialize(),
      // P0.2: chain checkpoints persist with state so verifiers can resume
      // from a known-good point after restart instead of replaying genesis.
      chainCheckpoints: this.ctx.chainCheckpoints,
      // P1.2: deterministic sequence counter. Must survive restart; otherwise
      // post-restart actions would collide with pre-restart ones because the
      // counter would reset to 1.
      deterministicSeq: this.ctx.deterministicSeq,
      // P1.4: frontier leases. Survive restart so a still-running agent
      // doesn't lose its claim across an engine restart.
      frontierLeases: this.ctx.frontierLeases.serialize(),
      // P2.1: journal sequence checkpoint. The snapshot is durable AS OF
      // the journal entry numbered `journalSnapshotSeq`; on next load,
      // replay journal entries with `seq > journalSnapshotSeq` to catch
      // any post-snapshot mutations that hadn't been re-snapshotted yet.
      journalSnapshotSeq: this.ctx.mutationJournal?.peekSeq() ?? 0,
    };
    const json = JSON.stringify(data);
    const serializeEnd = Date.now();
    this.metrics.totalSerializeMs += (serializeEnd - serializeStart);

    const writeStart = Date.now();

    // Atomic write: write to temp, fsync, then rename (atomic on POSIX)
    const tmpPath = this.ctx.stateFilePath + '.tmp';
    writeFileSync(tmpPath, json);
    const fd = openSync(tmpPath, 'r');
    fsyncSync(fd);
    closeSync(fd);

    // Rotate snapshot before overwriting (throttled to once per 30s)
    const now = Date.now();
    if (existsSync(this.ctx.stateFilePath) && (now - this.ctx.lastSnapshotTime >= 30000)) {
      this.rotateSnapshot();
      this.ctx.lastSnapshotTime = now;
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

    const writeEnd = Date.now();
    this.metrics.totalWriteMs += (writeEnd - writeStart);
    this.metrics.lastFlushMs = writeEnd - serializeStart;
    this.metrics.flushCount++;
  }

  private rotateSnapshot(): void {
    try {
      const dir = dirname(this.ctx.stateFilePath);
      const base = basename(this.ctx.stateFilePath, '.json');
      const snapDir = join(dir, '.snapshots');
      mkdirSync(snapDir, { recursive: true });
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const snapPath = join(snapDir, `${base}.snap-${ts}-${process.pid}.json`);
      // Copy current state to snapshot
      writeFileSync(snapPath, readFileSync(this.ctx.stateFilePath));
      // Prune old snapshots beyond MAX_SNAPSHOTS
      const snaps = readdirSync(snapDir)
        .filter(f => f.startsWith(`${base}.snap-`) && f.endsWith('.json'))
        .sort();
      while (snaps.length > MAX_SNAPSHOTS) {
        const oldest = snaps.shift()!;
        try { unlinkSync(join(snapDir, oldest)); } catch { /* best effort */ }
      }
      // P2.1: compact the WAL — entries up to the seq stored in the
      // freshly-rotated snapshot are redundant. Read the seq back from
      // the just-written snapshot file so it matches what's on disk.
      if (this.ctx.mutationJournal) {
        try {
          const snapData = JSON.parse(readFileSync(snapPath, 'utf-8'));
          const upTo = typeof snapData.journalSnapshotSeq === 'number' ? snapData.journalSnapshotSeq : 0;
          if (upTo > 0) this.ctx.mutationJournal.compactUpTo(upTo);
        } catch { /* journal compaction is best-effort */ }
      }
    } catch (err) {
      this.ctx.log(`Snapshot rotation error: ${err instanceof Error ? err.message : String(err)}`, undefined, { category: 'system', outcome: 'failure' });
    }
  }

  listSnapshots(): string[] {
    try {
      const dir = dirname(this.ctx.stateFilePath);
      const base = basename(this.ctx.stateFilePath, '.json');
      const snapDir = join(dir, '.snapshots');
      const results: string[] = [];
      // Check new subdirectory location
      if (existsSync(snapDir)) {
        results.push(...readdirSync(snapDir)
          .filter(f => f.startsWith(`${base}.snap-`) && f.endsWith('.json'))
          .map(f => `.snapshots/${f}`));
      }
      // Check legacy same-directory location for backward compat
      results.push(...readdirSync(dir)
        .filter(f => f.startsWith(`${base}.snap-`) && f.endsWith('.json')));
      return results.sort();
    } catch {
      return [];
    }
  }

  rollbackToSnapshot(snapshotName: string, builtinRules: InferenceRule[]): boolean {
    const dir = dirname(this.ctx.stateFilePath);
    const snapPath = join(dir, snapshotName);
    if (!existsSync(snapPath)) {
      // Try legacy same-directory location
      const legacyPath = join(dir, basename(snapshotName));
      if (!existsSync(legacyPath)) return false;
      return this._rollbackFrom(legacyPath, builtinRules);
    }
    return this._rollbackFrom(snapPath, builtinRules);
  }

  private _rollbackFrom(snapPath: string, builtinRules: InferenceRule[]): boolean {
    const raw = readFileSync(snapPath, 'utf-8');
    const data = JSON.parse(raw);
    this.ctx.graph.clear();
    this.ctx.config = data.config;
    this.ctx.graph.import(data.graph);
    this.normalizeLoadedNodeProvenance();
    this.migrateDefaultCredentialFlags();
    this.ctx.invalidatePathGraph();
    this.ctx.activityLog = (data.activityLog || []).map((entry: unknown) => normalizeActivityLogEntry(entry as Partial<ActivityLogEntry> & { description: string }));
    this.ctx.agents = new Map(data.agents || []);
    this.ctx.trackedProcesses = data.trackedProcesses || [];
    // Restore inference rules: builtins + any custom rules from the snapshot
    this.ctx.inferenceRules = [...builtinRules];
    if (data.inferenceRules) {
      for (const rule of data.inferenceRules) {
        this.ctx.inferenceRules.push(rule);
      }
    }
    if (data.coldStore) {
      this.ctx.coldStore.import(data.coldStore);
    }
    this.ctx.opsecTracker = data.opsecTracker
      ? OpsecTracker.deserialize(data.opsecTracker, this.ctx)
      : new OpsecTracker(this.ctx);
    this.ctx.frontierLinkage = FrontierLinkageTracker.deserialize(data.frontierLinkage);
    this.ctx.rebuildActionFrontierMap();
    this.ctx.rebuildChainTail();
    // P0.2: restore chain checkpoints. If the field is missing (legacy
    // snapshots, or hash chain disabled), keep the empty array.
    this.ctx.chainCheckpoints = Array.isArray(data.chainCheckpoints) ? data.chainCheckpoints : [];
    this.ctx.chainEventsSinceCheckpoint = 0;
    // P1.2: restore deterministic sequence counter so post-restart IDs
    // don't collide with pre-restart ones.
    this.ctx.deterministicSeq = typeof data.deterministicSeq === 'number' ? data.deterministicSeq : 0;
    // P1.4: restore frontier leases.
    this.ctx.frontierLeases = FrontierLeases.deserialize(data.frontierLeases);
    // P2.1: rollback discards any journal entries since the snapshot —
    // they describe mutations that don't apply to this older state.
    if (this.ctx.mutationJournal) {
      this.ctx.mutationJournal.truncate();
      this.ctx.mutationJournal.setNextSeq(typeof data.journalSnapshotSeq === 'number' ? data.journalSnapshotSeq : 0);
    }
    this.ctx.log('Rolled back to snapshot: ' + basename(snapPath), undefined, { category: 'system' });
    this.persistImmediate();
    return true;
  }

  loadState(): void {
    const raw = readFileSync(this.ctx.stateFilePath, 'utf-8');
    const data = JSON.parse(raw);
    this.ctx.config = data.config;
    this.ctx.graph.clear();
    this.ctx.graph.import(data.graph);
    this.normalizeLoadedNodeProvenance();
    this.migrateDefaultCredentialFlags();
    this.ctx.activityLog = (data.activityLog || []).map((entry: unknown) => normalizeActivityLogEntry(entry as Partial<ActivityLogEntry> & { description: string }));
    this.ctx.agents = new Map(data.agents || []);
    this.ctx.campaigns = new Map(data.campaigns || []);
    this.ctx.trackedProcesses = data.trackedProcesses || [];
    if (data.inferenceRules) {
      for (const rule of data.inferenceRules) {
        this.ctx.inferenceRules.push(rule);
      }
    }
    if (data.coldStore) {
      this.ctx.coldStore.import(data.coldStore);
    }
    this.ctx.opsecTracker = data.opsecTracker
      ? OpsecTracker.deserialize(data.opsecTracker, this.ctx)
      : new OpsecTracker(this.ctx);
    this.ctx.frontierLinkage = FrontierLinkageTracker.deserialize(data.frontierLinkage);
    this.ctx.rebuildActionFrontierMap();
    this.ctx.rebuildChainTail();
    // P0.2: restore chain checkpoints. If the field is missing (legacy
    // snapshots, or hash chain disabled), keep the empty array.
    this.ctx.chainCheckpoints = Array.isArray(data.chainCheckpoints) ? data.chainCheckpoints : [];
    this.ctx.chainEventsSinceCheckpoint = 0;
    // P1.2: restore deterministic sequence counter so post-restart IDs
    // don't collide with pre-restart ones.
    this.ctx.deterministicSeq = typeof data.deterministicSeq === 'number' ? data.deterministicSeq : 0;
    // P1.4: restore frontier leases.
    this.ctx.frontierLeases = FrontierLeases.deserialize(data.frontierLeases);

    // P2.1: WAL replay. For deterministic-ID engagements, the snapshot
    // captures state AS OF `journalSnapshotSeq`. If the engine crashed
    // between a journal append and the next snapshot rotation, the journal
    // file holds entries with `seq > journalSnapshotSeq` that aren't yet
    // in this snapshot. Replay them here so the in-memory graph reflects
    // the last durable mutation. After replay, truncate the journal — the
    // re-issued snapshot covers everything we just replayed.
    if (this.ctx.mutationJournal) {
      const snapshotSeq = typeof data.journalSnapshotSeq === 'number' ? data.journalSnapshotSeq : 0;
      this.ctx.mutationJournal.setNextSeq(snapshotSeq);
      const replayed = this.ctx.mutationJournal.replay(this.makeMutationApplier(), snapshotSeq);
      if (replayed > 0) {
        this.ctx.log(`WAL replay: applied ${replayed} mutation(s) from journal`, undefined, {
          category: 'system',
        });
        // Force an immediate snapshot so the journal can be safely truncated.
        this.persistImmediate();
        this.ctx.mutationJournal.truncate();
        this.ctx.mutationJournal.setNextSeq(this.ctx.mutationJournal.peekSeq());
      }
    }
  }

  /**
   * P2.1: factory for the MutationApplier consumed by `MutationJournal.replay`.
   * Replays each journaled mutation by calling the same code paths the
   * original write took — `addNode`/`addEdge` etc. — but with journaling
   * temporarily suppressed (via `mutationJournal: null`) so we don't
   * double-record entries during replay.
   */
  private makeMutationApplier(): import('./mutation-journal.js').MutationApplier {
    const ctx = this.ctx;
    return {
      apply(entry) {
        // Suppress nested journaling during replay.
        const savedJournal = ctx.mutationJournal;
        ctx.mutationJournal = null;
        try {
          switch (entry.type) {
            case 'add_node': {
              const props = (entry.payload as { props: NodeProperties }).props;
              if (!ctx.graph.hasNode(props.id)) {
                ctx.graph.addNode(props.id, props);
              }
              break;
            }
            case 'merge_node_attrs': {
              const props = (entry.payload as { props: NodeProperties }).props;
              if (ctx.graph.hasNode(props.id)) {
                ctx.graph.mergeNodeAttributes(props.id, props as Partial<NodeProperties>);
              } else {
                ctx.graph.addNode(props.id, props);
              }
              break;
            }
            case 'add_edge': {
              const p = entry.payload as { source: string; target: string; props: import('../types.js').EdgeProperties };
              if (!ctx.graph.hasNode(p.source) || !ctx.graph.hasNode(p.target)) break;
              const existingEdges = ctx.graph.edges(p.source, p.target);
              let merged = false;
              for (const eid of existingEdges) {
                const ea = ctx.graph.getEdgeAttributes(eid);
                if (ea.type === p.props.type) {
                  ctx.graph.mergeEdgeAttributes(eid, p.props as Partial<import('../types.js').EdgeProperties>);
                  merged = true;
                  break;
                }
              }
              if (!merged) {
                const baseKey = `${p.source}--${p.props.type}--${p.target}`;
                try { ctx.graph.addEdgeWithKey(baseKey, p.source, p.target, p.props); } catch { /* edge already exists */ }
              }
              break;
            }
            case 'drop_edge': {
              const p = entry.payload as { edge_id: string };
              if (ctx.graph.hasEdge(p.edge_id)) ctx.graph.dropEdge(p.edge_id);
              break;
            }
            default:
              // Unknown / future types are tolerated (forward-compat for
              // journals written by a newer version of the engine).
              break;
          }
        } finally {
          ctx.mutationJournal = savedJournal;
        }
      },
    };
  }

  recoverFromSnapshot(builtinRules: InferenceRule[]): boolean {
    const snapshots = this.listSnapshots().reverse(); // newest first
    for (const snap of snapshots) {
      try {
        const dir = dirname(this.ctx.stateFilePath);
        const raw = readFileSync(join(dir, snap), 'utf-8');
        const data = JSON.parse(raw);
        this.ctx.graph.clear();
        this.ctx.config = data.config;
        this.ctx.graph.import(data.graph);
        this.normalizeLoadedNodeProvenance();
        this.migrateDefaultCredentialFlags();
        this.ctx.invalidatePathGraph();
        this.ctx.activityLog = (data.activityLog || []).map((entry: unknown) => normalizeActivityLogEntry(entry as Partial<ActivityLogEntry> & { description: string }));
        this.ctx.agents = new Map(data.agents || []);
        this.ctx.campaigns = new Map(data.campaigns || []);
        this.ctx.trackedProcesses = data.trackedProcesses || [];
        this.ctx.inferenceRules = [...builtinRules];
        if (data.inferenceRules) {
          for (const rule of data.inferenceRules) {
            this.ctx.inferenceRules.push(rule);
          }
        }
        if (data.coldStore) {
          this.ctx.coldStore.import(data.coldStore);
        }
        this.ctx.opsecTracker = data.opsecTracker
          ? OpsecTracker.deserialize(data.opsecTracker, this.ctx)
          : new OpsecTracker(this.ctx);
        this.ctx.frontierLinkage = FrontierLinkageTracker.deserialize(data.frontierLinkage);
        this.ctx.rebuildActionFrontierMap();
        this.ctx.rebuildChainTail();
        // Overwrite corrupted state file with valid snapshot data
        this.persistImmediate();
        return true;
      } catch {
        continue;
      }
    }
    return false;
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
