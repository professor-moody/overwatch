// ============================================================
// Overwatch — State Persistence
// Handles persist, snapshot rotation, load, and recovery.
// All state access goes through the shared EngineContext.
// ============================================================

import { readFileSync, writeFileSync, existsSync, renameSync, unlinkSync, readdirSync } from 'fs';
import { dirname, basename, join } from 'path';
import type { EngineContext, OverwatchGraph, GraphUpdateDetail } from './engine-context.js';
import { normalizeActivityLogEntry } from './engine-context.js';
import type { InferenceRule } from '../types.js';
import { normalizeNodeProvenance } from './provenance-utils.js';

export const MAX_SNAPSHOTS = 5;

export class StatePersistence {
  private ctx: EngineContext;
  private builtinRuleIds: Set<string>;
  private createGraph: () => OverwatchGraph;

  constructor(ctx: EngineContext, builtinRules: InferenceRule[], createGraph: () => OverwatchGraph) {
    this.ctx = ctx;
    this.builtinRuleIds = new Set(builtinRules.map(r => r.id));
    this.createGraph = createGraph;
  }

  persist(detail: GraphUpdateDetail = {}): void {
    const data = {
      config: this.ctx.config,
      graph: this.ctx.graph.export(),
      activityLog: this.ctx.activityLog,
      agents: Array.from(this.ctx.agents.entries()),
      inferenceRules: this.ctx.inferenceRules.filter(r => !this.builtinRuleIds.has(r.id)),
      trackedProcesses: this.ctx.trackedProcesses,
    };
    const json = JSON.stringify(data, null, 2);

    // Atomic write: write to temp, then rename (atomic on POSIX)
    const tmpPath = this.ctx.stateFilePath + '.tmp';
    writeFileSync(tmpPath, json);

    // Rotate snapshot before overwriting (throttled to once per 30s)
    const now = Date.now();
    if (existsSync(this.ctx.stateFilePath) && (now - this.ctx.lastSnapshotTime >= 30000)) {
      this.rotateSnapshot();
      this.ctx.lastSnapshotTime = now;
    }

    renameSync(tmpPath, this.ctx.stateFilePath);
    this.ctx.fireUpdateCallbacks(detail);
  }

  private rotateSnapshot(): void {
    try {
      const dir = dirname(this.ctx.stateFilePath);
      const base = basename(this.ctx.stateFilePath, '.json');
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const snapPath = join(dir, `${base}.snap-${ts}-${process.pid}.json`);
      // Copy current state to snapshot
      writeFileSync(snapPath, readFileSync(this.ctx.stateFilePath));
      // Prune old snapshots beyond MAX_SNAPSHOTS
      const snaps = readdirSync(dir)
        .filter(f => f.startsWith(`${base}.snap-`) && f.endsWith('.json'))
        .sort();
      while (snaps.length > MAX_SNAPSHOTS) {
        const oldest = snaps.shift()!;
        try { unlinkSync(join(dir, oldest)); } catch { /* best effort */ }
      }
    } catch (err) {
      this.ctx.log(`Snapshot rotation error: ${err instanceof Error ? err.message : String(err)}`, undefined, { category: 'system', outcome: 'failure' });
    }
  }

  listSnapshots(): string[] {
    try {
      const dir = dirname(this.ctx.stateFilePath);
      const base = basename(this.ctx.stateFilePath, '.json');
      return readdirSync(dir)
        .filter(f => f.startsWith(`${base}.snap-`) && f.endsWith('.json'))
        .sort();
    } catch {
      return [];
    }
  }

  rollbackToSnapshot(snapshotName: string, builtinRules: InferenceRule[]): boolean {
    const dir = dirname(this.ctx.stateFilePath);
    const snapPath = join(dir, snapshotName);
    if (!existsSync(snapPath)) return false;

    // Load snapshot data into current engine state
    const raw = readFileSync(snapPath, 'utf-8');
    const data = JSON.parse(raw);
    this.ctx.graph.clear();
    this.ctx.config = data.config;
    this.ctx.graph.import(data.graph);
    this.normalizeLoadedNodeProvenance();
    this.ctx.invalidatePathGraph();
    this.ctx.activityLog = (data.activityLog || []).map((entry: any) => normalizeActivityLogEntry(entry));
    this.ctx.agents = new Map(data.agents || []);
    this.ctx.trackedProcesses = data.trackedProcesses || [];
    // Restore inference rules: builtins + any custom rules from the snapshot
    this.ctx.inferenceRules = [...builtinRules];
    if (data.inferenceRules) {
      for (const rule of data.inferenceRules) {
        this.ctx.inferenceRules.push(rule);
      }
    }
    this.ctx.log('Rolled back to snapshot: ' + snapshotName, undefined, { category: 'system' });
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
    this.ctx.activityLog = (data.activityLog || []).map((entry: any) => normalizeActivityLogEntry(entry));
    this.ctx.agents = new Map(data.agents || []);
    this.ctx.trackedProcesses = data.trackedProcesses || [];
    if (data.inferenceRules) {
      for (const rule of data.inferenceRules) {
        this.ctx.inferenceRules.push(rule);
      }
    }
  }

  recoverFromSnapshot(builtinRules: InferenceRule[]): boolean {
    const snapshots = this.listSnapshots().reverse(); // newest first
    for (const snap of snapshots) {
      try {
        const dir = dirname(this.ctx.stateFilePath);
        const raw = readFileSync(join(dir, snap), 'utf-8');
        const data = JSON.parse(raw);
        this.ctx.graph = this.createGraph();
        this.ctx.config = data.config;
        this.ctx.graph.import(data.graph);
        this.normalizeLoadedNodeProvenance();
        this.ctx.invalidatePathGraph();
        this.ctx.activityLog = (data.activityLog || []).map((entry: any) => normalizeActivityLogEntry(entry));
        this.ctx.agents = new Map(data.agents || []);
        this.ctx.trackedProcesses = data.trackedProcesses || [];
        this.ctx.inferenceRules = [...builtinRules];
        if (data.inferenceRules) {
          for (const rule of data.inferenceRules) {
            this.ctx.inferenceRules.push(rule);
          }
        }
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
      this.ctx.graph.mergeNodeAttributes(nodeId, normalizeNodeProvenance(attrs) as any);
    });
  }
}
