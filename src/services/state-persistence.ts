// ============================================================
// Overwatch — State Persistence
// Handles persist, snapshot rotation, load, and recovery.
// All state access goes through the shared EngineContext.
// ============================================================

import { readFileSync, writeFileSync, existsSync, renameSync, unlinkSync, readdirSync, mkdirSync } from 'fs';
import { dirname, basename, join } from 'path';
import type { EngineContext, OverwatchGraph, GraphUpdateDetail, ActivityLogEntry } from './engine-context.js';
import { normalizeActivityLogEntry } from './engine-context.js';
import type { InferenceRule, NodeProperties } from '../types.js';
import { normalizeNodeProvenance } from './provenance-utils.js';
import { OpsecTracker } from './opsec-tracker.js';

export const MAX_SNAPSHOTS = 5;

export class StatePersistence {
  private ctx: EngineContext;
  private builtinRuleIds: Set<string>;

  constructor(ctx: EngineContext, builtinRules: InferenceRule[], _createGraph?: () => OverwatchGraph) {
    this.ctx = ctx;
    this.builtinRuleIds = new Set(builtinRules.map(r => r.id));
  }

  persist(detail: GraphUpdateDetail = {}): void {
    const data = {
      config: this.ctx.config,
      graph: this.ctx.graph.export(),
      activityLog: this.ctx.activityLog,
      agents: Array.from(this.ctx.agents.entries()),
      inferenceRules: this.ctx.inferenceRules.filter(r => !this.builtinRuleIds.has(r.id)),
      trackedProcesses: this.ctx.trackedProcesses,
      coldStore: this.ctx.coldStore.export(),
      opsecTracker: this.ctx.opsecTracker.serialize(),
    };
    const json = JSON.stringify(data);

    // Atomic write: write to temp, then rename (atomic on POSIX)
    const tmpPath = this.ctx.stateFilePath + '.tmp';
    writeFileSync(tmpPath, json);

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
    this.ctx.fireUpdateCallbacks(detail);
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
    this.ctx.rebuildActionFrontierMap();
    this.ctx.log('Rolled back to snapshot: ' + basename(snapPath), undefined, { category: 'system' });
    this.persist();
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
    this.ctx.rebuildActionFrontierMap();
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
        this.ctx.rebuildActionFrontierMap();
        // Overwrite corrupted state file with valid snapshot data
        this.persist();
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
