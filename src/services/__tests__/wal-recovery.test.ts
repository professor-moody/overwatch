import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'fs';
import { tmpdir } from 'os';
import { basename, join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal } from '../mutation-journal.js';
import type { MutationType } from '../mutation-journal.js';
import {
  FLUSH_DEBOUNCE_MS,
  PERSIST_RETRY_DELAYS_MS,
} from '../state-persistence.js';
import type { EngagementConfig, NodeProperties } from '../../types.js';

const NONCE = 'd'.repeat(64);
const NOW = '2026-07-15T00:00:00.000Z';

function makeConfig(id: string): EngagementConfig {
  return {
    id,
    name: `WAL recovery test ${id}`,
    created_at: NOW,
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
    engagement_nonce: NONCE,
  };
}

function host(id: string): NodeProperties {
  return {
    id,
    type: 'host',
    label: id,
    discovered_at: NOW,
    confidence: 1,
  };
}

function checkpoint(statePath: string): number {
  const state = JSON.parse(readFileSync(statePath, 'utf-8')) as {
    journalSnapshotSeq?: unknown;
  };
  if (!Number.isSafeInteger(state.journalSnapshotSeq)) {
    throw new Error('state did not contain a safe journalSnapshotSeq');
  }
  return state.journalSnapshotSeq as number;
}

function stableGraph(engine: GraphEngine): unknown {
  const graph = engine.exportGraph();
  return {
    nodes: [...graph.nodes].sort((a, b) => a.id.localeCompare(b.id)),
    edges: [...graph.edges].sort((a, b) => {
      const aKey = `${a.id ?? ''}:${a.source}:${a.target}:${a.properties.type}`;
      const bKey = `${b.id ?? ''}:${b.source}:${b.target}:${b.properties.type}`;
      return aKey.localeCompare(bKey);
    }),
    cold_nodes: [...(graph.cold_nodes ?? [])].sort((a, b) => a.id.localeCompare(b.id)),
  };
}

const ROLLBACK_PRIMARY_CORRUPTIONS: Array<{
  name: string;
  corrupt(path: string): void;
}> = [
  {
    name: 'invalid JSON',
    corrupt(path) {
      writeFileSync(path, '{corrupt marked rollback primary');
    },
  },
  {
    name: 'an unrestorable auxiliary field',
    corrupt(path) {
      const primary = JSON.parse(readFileSync(path, 'utf-8')) as Record<string, unknown>;
      primary.agents = {};
      writeFileSync(path, JSON.stringify(primary));
    },
  },
  {
    name: 'graph data not bound by the marker',
    corrupt(path) {
      const primary = JSON.parse(readFileSync(path, 'utf-8')) as Record<string, any>;
      (primary.graph.nodes as Array<unknown>).push({
        key: 'must-remain-rolled-back',
        attributes: host('must-remain-rolled-back'),
      });
      writeFileSync(path, JSON.stringify(primary));
    },
  },
];

describe('WAL recovery integration', () => {
  let tempDir: string;
  let statePath: string;
  let config: EngagementConfig;
  const liveEngines = new Set<GraphEngine>();

  function openEngine(): GraphEngine {
    const engine = new GraphEngine(config, statePath);
    liveEngines.add(engine);
    return engine;
  }

  function closeEngine(engine: GraphEngine): void {
    if (!liveEngines.delete(engine)) return;
    engine.dispose();
  }

  function journalPath(): string {
    return new MutationJournal(statePath).getPath();
  }

  function quarantineFiles(): string[] {
    const walName = basename(journalPath());
    return readdirSync(tempDir)
      .filter(name => name.startsWith(`${walName}.quarantine-`) && name.endsWith('.jsonl'))
      .sort();
  }

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'overwatch-wal-recovery-'));
    statePath = join(tempDir, 'state.json');
    config = makeConfig(basename(tempDir));
  });

  afterEach(() => {
    for (const engine of liveEngines) engine.dispose();
    liveEngines.clear();
    vi.restoreAllMocks();
    vi.useRealTimers();
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('replays a clean WAL once and keeps graph plus checkpoint stable through R2 and R3', () => {
    const r1 = openEngine();
    const baseCheckpoint = checkpoint(statePath);
    r1.addNode(host('host-from-r1-wal'));
    expect(r1.getNode('host-from-r1-wal')).toBeDefined();
    closeEngine(r1); // simulated crash: cancel timers without checkpointing the WAL mutation

    const r2 = openEngine();
    expect(r2.getNode('host-from-r1-wal')).toBeDefined();
    const r2Graph = stableGraph(r2);
    const r2Checkpoint = checkpoint(statePath);
    expect(r2Checkpoint).toBe(baseCheckpoint + 1);
    expect(r2.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      source: 'state',
      complete: true,
      writable: true,
      base_checkpoint: r2Checkpoint,
      // The active WAL was compacted, but status retains what recovery saw.
      highest_on_disk_seq: r2Checkpoint,
    });
    closeEngine(r2);

    const r3 = openEngine();
    expect(checkpoint(statePath)).toBe(r2Checkpoint);
    expect(stableGraph(r3)).toEqual(r2Graph);
    expect(r3.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'clean',
      source: 'state',
      complete: true,
      writable: true,
      base_checkpoint: r2Checkpoint,
    });
    closeEngine(r3);
  });

  it('preserves an unknown record byte-for-byte and stays read-only across three restarts with one quarantine', () => {
    const base = openEngine();
    base.addNode(host('baseline'));
    base.persist();
    base.flushNow();
    closeEngine(base);

    const stateBefore = readFileSync(statePath);
    const wal = new MutationJournal(statePath);
    wal.setNextSeq(checkpoint(statePath));
    wal.append({
      type: 'future_mutation' as MutationType,
      payload: { deliberately: 'unsupported' },
      ts: NOW,
    });
    const walBefore = readFileSync(journalPath());

    for (let restart = 1; restart <= 3; restart += 1) {
      const engine = openEngine();
      const status = engine.getPersistenceRecoveryStatus();
      expect(status).toMatchObject({
        outcome: 'incomplete',
        source: 'state',
        complete: false,
        writable: false,
        journal: {
          skipped: 1,
          failed: 0,
          preserved: true,
        },
      });
      expect(engine.isPersistenceWritable()).toBe(false);
      const graphBeforeReads = stableGraph(engine);
      engine.getState();
      expect(stableGraph(engine)).toEqual(graphBeforeReads);
      const configName = engine.getConfig().name;
      const objectiveCount = engine.getConfig().objectives.length;
      const historyCount = engine.getFullHistory().length;
      expect(() => engine.updateConfig({ name: `rejected-${restart}` })).toThrow(
        /Durable mutations are disabled while persistence is degraded/,
      );
      expect(() => engine.addObjective({ description: `rejected-${restart}` })).toThrow(
        /Durable mutations are disabled while persistence is degraded/,
      );
      expect(() => engine.logActionEvent({ description: `rejected-${restart}` })).toThrow(
        /Durable mutations are disabled while persistence is degraded/,
      );
      expect(engine.getConfig().name).toBe(configName);
      expect(engine.getConfig().objectives).toHaveLength(objectiveCount);
      expect(engine.getFullHistory()).toHaveLength(historyCount);
      expect(() => engine.addNode(host(`blocked-${restart}`))).toThrow(
        /Durable mutations are disabled while persistence is degraded/,
      );
      expect(engine.getNode(`blocked-${restart}`)).toBeNull();
      expect(readFileSync(statePath)).toEqual(stateBefore);
      expect(readFileSync(journalPath())).toEqual(walBefore);

      const quarantines = quarantineFiles();
      expect(quarantines).toHaveLength(1);
      expect(readFileSync(join(tempDir, quarantines[0]))).toEqual(walBefore);
      closeEngine(engine);
    }
  });

  it('does not compact an unknown record hidden behind an overclaimed base checkpoint', () => {
    const base = openEngine();
    base.persist();
    base.flushNow();
    closeEngine(base);

    const state = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    const wal = new MutationJournal(statePath);
    wal.setNextSeq(checkpoint(statePath));
    const unknown = wal.append({ type: 'future_mutation' as MutationType, payload: {}, ts: NOW });
    const validTail = wal.append({
      type: 'add_node',
      payload: { props: host('must-not-advance-past-unknown') },
      ts: NOW,
    });
    // Reproduce the pre-fix failure mode: a snapshot claimed the allocated
    // sequence even though the corresponding mutation was never applied.
    state.journalSnapshotSeq = unknown.seq;
    writeFileSync(statePath, JSON.stringify(state));
    const stateBeforeRecovery = readFileSync(statePath);
    const walBefore = readFileSync(journalPath());

    const recovered = openEngine();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      base_checkpoint: unknown.seq,
      highest_contiguous_applied_seq: unknown.seq,
      journal: { preserved: true },
    });
    expect(validTail.seq).toBe(unknown.seq + 1);
    expect(recovered.getNode('must-not-advance-past-unknown')).toBeNull();
    expect(recovered.getPersistenceRecoveryStatus().reason).toContain('unsupported journal mutation type');
    expect(readFileSync(statePath)).toEqual(stateBeforeRecovery);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    closeEngine(recovered);
  });

  it('degrades when an unmarked legacy checkpoint may hide a supported record', () => {
    const base = openEngine();
    base.persist();
    base.flushNow();
    closeEngine(base);
    // This case exercises the no-fallback path. A separate test below proves
    // that an older base is used when it can replay the full WAL safely.
    rmSync(join(tempDir, '.snapshots'), { recursive: true, force: true });

    const state = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    const wal = new MutationJournal(statePath);
    wal.setNextSeq(checkpoint(statePath));
    const possiblyHidden = wal.append({
      type: 'add_node',
      payload: { props: host('legacy-possibly-hidden') },
      ts: NOW,
    });
    wal.append({
      type: 'add_node',
      payload: { props: host('legacy-tail-must-not-leapfrog') },
      ts: NOW,
    });
    state.journalSnapshotSeq = possiblyHidden.seq;
    delete state.journalCheckpointSemantics;
    writeFileSync(statePath, JSON.stringify(state));
    const stateBeforeRecovery = readFileSync(statePath);
    const walBeforeRecovery = readFileSync(journalPath());

    const recovered = openEngine();
    expect(recovered.getNode('legacy-possibly-hidden')).toBeNull();
    expect(recovered.getNode('legacy-tail-must-not-leapfrog')).toBeNull();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'state',
      complete: false,
      writable: false,
      base_checkpoint: possiblyHidden.seq,
      highest_contiguous_applied_seq: 0,
      journal: { attempted: 0, applied: 0, preserved: true },
    });
    expect(recovered.getPersistenceRecoveryStatus().reason).toContain('may hide retained WAL');
    expect(readFileSync(statePath)).toEqual(stateBeforeRecovery);
    expect(readFileSync(journalPath())).toEqual(walBeforeRecovery);
    closeEngine(recovered);
  });

  it('replays an unmarked legacy WAL when every physical record is provably newer than the base', () => {
    const base = openEngine();
    base.persist();
    base.flushNow();
    closeEngine(base);

    const state = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    delete state.journalCheckpointSemantics;
    writeFileSync(statePath, JSON.stringify(state));
    rmSync(journalPath(), { force: true });
    const wal = new MutationJournal(statePath);
    wal.setNextSeq(state.journalSnapshotSeq as number);
    const tail = wal.append({
      type: 'add_node',
      payload: { props: host('safe-legacy-tail') },
      ts: NOW,
    });

    const recovered = openEngine();
    expect(recovered.getNode('safe-legacy-tail')).toBeDefined();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      base_checkpoint: tail.seq,
    });
    expect(JSON.parse(readFileSync(statePath, 'utf-8')).journalCheckpointSemantics)
      .toBe('contiguous_applied_v1');
    closeEngine(recovered);
  });

  it('skips a corrupt primary and newest corrupt snapshot, then restores an older valid snapshot plus WAL tail', () => {
    const base = openEngine();
    base.addNode(host('snapshot-base'));
    base.persist();
    base.flushNow();
    closeEngine(base);

    const validBase = readFileSync(statePath);
    const baseCheckpoint = checkpoint(statePath);
    const snapshotDir = join(tempDir, '.snapshots');
    rmSync(snapshotDir, { recursive: true, force: true });
    mkdirSync(snapshotDir, { recursive: true });
    writeFileSync(join(snapshotDir, 'state.snap-2026-01-01T00-00-00-000Z-1.json'), validBase);
    writeFileSync(join(snapshotDir, 'state.snap-2026-01-02T00-00-00-000Z-1.json'), '{newest snapshot is corrupt');

    const wal = new MutationJournal(statePath);
    wal.setNextSeq(baseCheckpoint);
    const tail = wal.append({
      type: 'add_node',
      payload: { props: host('wal-tail') },
      ts: NOW,
    });
    writeFileSync(statePath, '{primary is corrupt');

    const recovered = openEngine();
    expect(recovered.getNode('snapshot-base')).toBeDefined();
    expect(recovered.getNode('wal-tail')).toBeDefined();
    expect(checkpoint(statePath)).toBe(tail.seq);
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      source: 'snapshot',
      complete: true,
      writable: true,
      base_checkpoint: tail.seq,
    });
    closeEngine(recovered);

    const verified = openEngine();
    expect(verified.getNode('snapshot-base')).toBeDefined();
    expect(verified.getNode('wal-tail')).toBeDefined();
    expect(checkpoint(statePath)).toBe(tail.seq);
    closeEngine(verified);
  });

  it('never creates or reseeds a primary when a nonempty WAL has no valid base', () => {
    const wal = new MutationJournal(statePath);
    wal.append({
      type: 'add_node',
      payload: { props: host('wal-without-base') },
      ts: NOW,
    });
    const walBefore = readFileSync(journalPath());
    expect(existsSync(statePath)).toBe(false);

    for (let restart = 1; restart <= 3; restart += 1) {
      const engine = openEngine();
      expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
        outcome: 'incomplete',
        source: 'fresh',
        complete: false,
        writable: false,
        journal: { preserved: true },
      });
      expect(engine.isPersistenceWritable()).toBe(false);
      expect(engine.getNode('wal-without-base')).toBeNull();
      expect(() => engine.addNode(host(`not-seeded-${restart}`))).toThrow(
        /Durable mutations are disabled while persistence is degraded/,
      );
      expect(existsSync(statePath)).toBe(false);
      expect(readFileSync(journalPath())).toEqual(walBefore);
      expect(quarantineFiles()).toHaveLength(1);
      closeEngine(engine);
    }
  });

  it('does not overwrite a recovery base that is present but unreadable', () => {
    rmSync(statePath, { force: true });
    mkdirSync(statePath);

    const degraded = openEngine();
    expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'state',
      complete: false,
      writable: false,
    });
    expect(degraded.getPersistenceRecoveryStatus().reason).toContain('could not be read');
    expect(() => degraded.addNode(host('must-not-seed-over-unreadable-base'))).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );
    expect(existsSync(statePath)).toBe(true);
    closeEngine(degraded);
  });

  it('detects a physical WAL even when the incoming config has no engagement nonce', () => {
    delete config.engagement_nonce;
    const wal = new MutationJournal(statePath);
    wal.append({
      type: 'add_node',
      payload: { props: host('legacy-wal-without-base') },
      ts: NOW,
    });
    const walBefore = readFileSync(journalPath());

    const engine = openEngine();
    expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      journal: { enabled: true, preserved: true },
    });
    expect(engine.getNode('legacy-wal-without-base')).toBeNull();
    expect(existsSync(statePath)).toBe(false);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    closeEngine(engine);
  });

  it('restores the incoming config after rejecting a partially deserialized base', () => {
    const originalName = config.name;
    const writer = openEngine();
    writer.addNode(host('must-not-leak-from-rejected-base'));
    writer.persist();
    writer.flushNow();
    closeEngine(writer);

    rmSync(join(tempDir, '.snapshots'), { recursive: true, force: true });
    rmSync(journalPath(), { force: true });
    const rejected = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    rejected.config = { ...rejected.config, name: 'rejected persisted config' };
    // Graph/config restore first; iterating this invalid late field then throws.
    rejected.inferenceRules = { invalid: true };
    writeFileSync(statePath, JSON.stringify(rejected));

    const recovered = openEngine();
    expect(recovered.getConfig().name).toBe(originalName);
    expect(recovered.getNode('must-not-leak-from-rejected-base')).toBeNull();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'reinitialized',
      source: 'config',
      complete: true,
      writable: true,
    });
    closeEngine(recovered);
  });

  it('rejects a persisted base whose engagement config fails the canonical schema', () => {
    const originalName = config.name;
    const writer = openEngine();
    closeEngine(writer);

    const rejected = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    rejected.config = {
      ...rejected.config,
      name: 'invalid persisted config',
      scope: { ...rejected.config.scope, cidrs: ['999.999.999.999/99'] },
    };
    writeFileSync(statePath, JSON.stringify(rejected));

    const recovered = openEngine();
    expect(recovered.getConfig().name).toBe(originalName);
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'reinitialized',
      source: 'config',
      complete: true,
      writable: true,
    });
    closeEngine(recovered);
  });

  it('orders legacy and new snapshot locations by snapshot name, newest first', () => {
    const oldWriter = openEngine();
    oldWriter.addNode(host('old-snapshot-node'));
    oldWriter.persist();
    oldWriter.flushNow();
    closeEngine(oldWriter);
    const oldBytes = readFileSync(statePath);

    const newWriter = openEngine();
    newWriter.addNode(host('new-snapshot-node'));
    newWriter.persist();
    newWriter.flushNow();
    closeEngine(newWriter);
    const newBytes = readFileSync(statePath);

    rmSync(journalPath(), { force: true });
    rmSync(join(tempDir, '.snapshots'), { recursive: true, force: true });
    mkdirSync(join(tempDir, '.snapshots'), { recursive: true });
    writeFileSync(join(tempDir, 'state.snap-2026-01-01T00-00-00-000Z-1.json'), oldBytes);
    writeFileSync(join(tempDir, '.snapshots', 'state.snap-2026-01-02T00-00-00-000Z-1.json'), newBytes);
    writeFileSync(statePath, '{corrupt primary');

    const recovered = openEngine();
    expect(recovered.getNode('old-snapshot-node')).toBeDefined();
    expect(recovered.getNode('new-snapshot-node')).toBeDefined();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      source: 'snapshot',
      complete: true,
      writable: true,
    });
    closeEngine(recovered);
  });

  it('selects a newer valid snapshot checkpoint over a stale but valid primary', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('stale-primary-node'));
    writer.persist();
    writer.flushNow();
    const stalePrimary = readFileSync(statePath);
    const staleCheckpoint = checkpoint(statePath);

    writer.addNode(host('newer-snapshot-node'));
    writer.persist();
    writer.flushNow();
    const newerSnapshot = readFileSync(statePath);
    const newerCheckpoint = checkpoint(statePath);
    expect(newerCheckpoint).toBeGreaterThan(staleCheckpoint);
    closeEngine(writer);

    rmSync(journalPath(), { force: true });
    rmSync(join(tempDir, '.snapshots'), { recursive: true, force: true });
    mkdirSync(join(tempDir, '.snapshots'), { recursive: true });
    writeFileSync(
      join(tempDir, '.snapshots', 'state.snap-2026-01-03T00-00-00-000Z-1.json'),
      newerSnapshot,
    );
    writeFileSync(statePath, stalePrimary);

    const recovered = openEngine();
    expect(recovered.getNode('stale-primary-node')).toBeDefined();
    expect(recovered.getNode('newer-snapshot-node')).toBeDefined();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      source: 'snapshot',
      complete: true,
      writable: true,
      base_checkpoint: newerCheckpoint,
    });
    closeEngine(recovered);
  });

  it('does not reinterpret a skipped WAL record against an older snapshot', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('edge-source'));
    writer.addNode(host('edge-target'));
    writer.persist();
    writer.flushNow();
    closeEngine(writer);

    const snapshotBytes = readFileSync(statePath);
    const snapshotCheckpoint = checkpoint(statePath);
    rmSync(join(tempDir, '.snapshots'), { recursive: true, force: true });
    mkdirSync(join(tempDir, '.snapshots'), { recursive: true });
    writeFileSync(
      join(tempDir, '.snapshots', 'state.snap-2026-01-01T00-00-00-000Z-1.json'),
      snapshotBytes,
    );

    rmSync(journalPath(), { force: true });
    const wal = new MutationJournal(statePath);
    wal.setNextSeq(snapshotCheckpoint);
    const edge = wal.append({
      type: 'add_edge',
      payload: {
        source: 'edge-source',
        target: 'edge-target',
        props: { type: 'RELATED', confidence: 1, discovered_at: NOW },
      },
      ts: NOW,
    });

    const incompatiblePrimary = JSON.parse(snapshotBytes.toString('utf-8')) as Record<string, any>;
    incompatiblePrimary.graph.nodes = incompatiblePrimary.graph.nodes
      .filter((node: { key: string }) => node.key !== 'edge-target');
    writeFileSync(statePath, JSON.stringify(incompatiblePrimary));
    const stateBeforeRecovery = readFileSync(statePath);
    const walBeforeRecovery = readFileSync(journalPath());

    const recovered = openEngine();
    expect(recovered.getNode('edge-target')).toBeNull();
    expect(recovered.exportGraph().edges).toEqual([]);
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'state',
      complete: false,
      writable: false,
      base_checkpoint: snapshotCheckpoint,
      journal: { attempted: 1, applied: 0, skipped: 1, preserved: true },
    });
    expect(recovered.getPersistenceRecoveryStatus().reason).toContain(`seq ${edge.seq}`);
    expect(readFileSync(statePath)).toEqual(stateBeforeRecovery);
    expect(readFileSync(journalPath())).toEqual(walBeforeRecovery);
    closeEngine(recovered);
  });

  it('keeps an applied replay prefix visible when a later supported record cannot apply', () => {
    const writer = openEngine();
    writer.flushNow();
    const baseCheckpoint = checkpoint(statePath);
    closeEngine(writer);

    rmSync(journalPath(), { force: true });
    const wal = new MutationJournal(statePath);
    wal.setNextSeq(baseCheckpoint);
    wal.append({ type: 'add_node', payload: { props: host('prefix-node') }, ts: NOW });
    wal.append({
      type: 'add_edge',
      payload: {
        source: 'prefix-node',
        target: 'missing-target',
        props: { type: 'RELATED', confidence: 1, discovered_at: NOW },
      },
      ts: NOW,
    });
    wal.append({ type: 'add_node', payload: { props: host('unattempted-tail-node') }, ts: NOW });
    const walBeforeRecovery = readFileSync(journalPath());

    for (let restart = 1; restart <= 3; restart++) {
      const recovered = openEngine();
      expect(recovered.getNode('prefix-node')).toBeDefined();
      expect(recovered.getNode('unattempted-tail-node')).toBeNull();
      expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
        outcome: 'incomplete',
        complete: false,
        writable: false,
        base_checkpoint: baseCheckpoint,
        highest_allocated_seq: baseCheckpoint + 3,
        highest_contiguous_applied_seq: baseCheckpoint + 1,
        journal: { read: 3, attempted: 2, applied: 1, skipped: 1, preserved: true },
      });
      expect(readFileSync(journalPath())).toEqual(walBeforeRecovery);
      closeEngine(recovered);
    }
  });

  it('retains enough WAL after compaction to recover through multiple snapshot fallbacks', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('oldest-base-node'));
    writer.persist();
    writer.flushNow();
    const oldestSnapshotBytes = readFileSync(statePath);
    const oldestCheckpoint = checkpoint(statePath);

    writer.addNode(host('middle-node'));
    writer.persist();
    writer.flushNow();
    const newerSnapshotBytes = readFileSync(statePath);
    const newerCheckpoint = checkpoint(statePath);
    expect(newerCheckpoint).toBe(oldestCheckpoint + 1);

    writer.addNode(host('tail-node'));
    closeEngine(writer); // crash before the tail reaches the primary

    const snapshotDir = join(tempDir, '.snapshots');
    rmSync(snapshotDir, { recursive: true, force: true });
    mkdirSync(snapshotDir, { recursive: true });
    const oldestName = 'state.snap-2026-01-01T00-00-00-000Z-1.json';
    const newerName = 'state.snap-2026-01-02T00-00-00-000Z-1.json';
    writeFileSync(join(snapshotDir, oldestName), oldestSnapshotBytes);
    writeFileSync(join(snapshotDir, newerName), newerSnapshotBytes);

    const checkpointed = openEngine();
    expect(checkpointed.getNode('tail-node')).toBeDefined();
    const recoveredCheckpoint = checkpoint(statePath);
    expect(recoveredCheckpoint).toBe(newerCheckpoint + 1);
    closeEngine(checkpointed);

    const retainedSeqs = readFileSync(journalPath(), 'utf-8')
      .split('\n')
      .filter(Boolean)
      .map(line => (JSON.parse(line) as { seq: number }).seq);
    expect(retainedSeqs).toEqual([oldestCheckpoint + 1, oldestCheckpoint + 2]);

    writeFileSync(statePath, '{corrupt primary');
    for (const snapshotName of readdirSync(snapshotDir)) {
      if (snapshotName !== oldestName) {
        writeFileSync(join(snapshotDir, snapshotName), '{corrupt newer snapshot');
      }
    }

    const recovered = openEngine();
    expect(recovered.getNode('oldest-base-node')).toBeDefined();
    expect(recovered.getNode('middle-node')).toBeDefined();
    expect(recovered.getNode('tail-node')).toBeDefined();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      source: 'snapshot',
      complete: true,
      writable: true,
      base_checkpoint: recoveredCheckpoint,
    });
    closeEngine(recovered);
  });

  it('keeps WAL newer than the durable primary during pre-rename snapshot rotation', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('durable-primary-node'));
    writer.persist();
    writer.flushNow();
    const durableCheckpoint = checkpoint(statePath);

    writer.addNode(host('new-primary-node'));
    writer.persist();
    (writer as any).ctx.lastSnapshotTime = 0;
    writer.flushNow();

    expect(checkpoint(statePath)).toBe(durableCheckpoint + 1);
    const retainedSeqs = readFileSync(journalPath(), 'utf-8')
      .split('\n')
      .filter(Boolean)
      .map(line => (JSON.parse(line) as { seq: number }).seq);
    expect(retainedSeqs).toContain(durableCheckpoint + 1);
    closeEngine(writer);
  });

  it('does not replace the primary when durable snapshot creation fails', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('stable-primary-node'));
    writer.persist();
    writer.flushNow();
    const primaryBefore = readFileSync(statePath);

    const snapshotDir = join(tempDir, '.snapshots');
    rmSync(snapshotDir, { recursive: true, force: true });
    writeFileSync(snapshotDir, 'blocks snapshot directory creation');
    writer.addNode(host('wal-only-after-rotation-failure'));
    writer.persist();
    (writer as any).ctx.lastSnapshotTime = 0;

    expect(() => writer.flushNow()).toThrow();
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(journalPath(), 'utf-8')).toContain('wal-only-after-rotation-failure');
    closeEngine(writer);

    rmSync(snapshotDir, { force: true });
    const recovered = openEngine();
    expect(recovered.getNode('stable-primary-node')).toBeDefined();
    expect(recovered.getNode('wal-only-after-rotation-failure')).toBeDefined();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
    });
    closeEngine(recovered);
  });

  it('never truncates a colliding recovery snapshot when the replacement copy fails', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('collision-stable-primary'));
    writer.persist();
    writer.flushNow();
    const primaryBefore = readFileSync(statePath);

    const fixedNow = new Date('2026-07-15T12:34:56.789Z');
    vi.useFakeTimers();
    vi.setSystemTime(fixedNow);
    const snapshotDir = join(tempDir, '.snapshots');
    mkdirSync(snapshotDir, { recursive: true });
    const timestamp = fixedNow.toISOString().replace(/[:.]/g, '-');
    const collidingPath = join(
      snapshotDir,
      `state.snap-${timestamp}-${process.pid}.json`,
    );
    const retainedAnchor = Buffer.from('pre-existing recovery anchor bytes');
    writeFileSync(collidingPath, retainedAnchor);

    // Make the durable primary unreadable only after retaining its bytes. The
    // rotation will allocate a fresh suffixed path, fail while copying, and
    // must leave the colliding anchor byte-for-byte unchanged.
    rmSync(statePath);
    mkdirSync(statePath);
    writer.addNode(host('collision-wal-tail'));
    writer.persist();
    (writer as any).ctx.lastSnapshotTime = 0;

    expect(() => writer.flushNow()).toThrow();
    expect(readFileSync(collidingPath)).toEqual(retainedAnchor);

    rmSync(statePath, { recursive: true, force: true });
    writeFileSync(statePath, primaryBefore);
    closeEngine(writer);
    vi.useRealTimers();
  });

  it('propagates WAL compaction refusal without replacing the primary', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('compaction-anchor'));
    writer.persist();
    writer.flushNow();
    (writer as any).ctx.lastSnapshotTime = 0;
    writer.persist();
    writer.flushNow();

    const primaryBefore = readFileSync(statePath);
    const journal = (writer as any).ctx.mutationJournal as MutationJournal;
    journal.append({ type: 'future_mutation' as MutationType, payload: {}, ts: NOW });
    const walBefore = readFileSync(journalPath());
    (writer as any).ctx.lastSnapshotTime = 0;
    writer.persist();

    expect(() => writer.flushNow()).toThrow(/snapshot WAL compaction refused/);
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    closeEngine(writer);
  });

  it.each(ROLLBACK_PRIMARY_CORRUPTIONS)(
    'resumes rollback from the checksummed snapshot when the marked primary has $name',
    ({ corrupt }) => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('rollback-anchor-node'));
    writer.persist();
    writer.flushNow();
    (writer as any).ctx.lastSnapshotTime = 0;
    writer.persist();
    writer.flushNow();
    const rollbackSnapshot = writer.listSnapshots()[0];

    writer.addNode(host('must-remain-rolled-back'));
    writer.persist();
    writer.flushNow();
    (writer as any).ctx.lastSnapshotTime = 0;
    writer.persist();
    writer.flushNow();
    expect(writer.listSnapshots().length).toBeGreaterThan(1);
    expect(readFileSync(journalPath(), 'utf-8')).toContain('must-remain-rolled-back');

    const persistence = (writer as any).persistence as Record<string, unknown>;
    const cleanupFailure = vi.spyOn(
      persistence as any,
      'pruneSnapshotsSupersededByRollback',
    ).mockImplementationOnce(() => {
      throw new Error('synthetic rollback cleanup interruption');
    });
    expect(() => writer.rollbackToSnapshot(rollbackSnapshot)).toThrow(
      /synthetic rollback cleanup interruption/,
    );
    cleanupFailure.mockRestore();

    expect(writer.getNode('must-remain-rolled-back')).toBeNull();
    expect(writer.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
    });
    const pendingPrimary = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    expect(pendingPrimary.rollbackIntent).toMatchObject({
      version: 1,
      checkpoint: pendingPrimary.journalSnapshotSeq,
      selected_snapshot: rollbackSnapshot,
    });
    const rollbackAuthorityPath = `${statePath}.rollback-intent.json`;
    expect(existsSync(rollbackAuthorityPath)).toBe(true);
    closeEngine(writer);

    // The authority sidecar, not the replaceable primary alone, must survive a
    // crash in cleanup. Corrupting the marked primary must not let a newer
    // snapshot or the superseded WAL resurrect rolled-away state.
    corrupt(statePath);

    const restarted = openEngine();
    expect(restarted.getNode('rollback-anchor-node')).toBeDefined();
    expect(restarted.getNode('must-remain-rolled-back')).toBeNull();
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      complete: true,
      writable: true,
    });
    const completedPrimary = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, unknown>;
    expect(completedPrimary.rollbackIntent).toBeUndefined();
    expect(existsSync(rollbackAuthorityPath)).toBe(false);
    expect(restarted.listSnapshots()).toContain(rollbackSnapshot);
    for (const snapshot of restarted.listSnapshots()) {
      const persisted = JSON.parse(readFileSync(join(tempDir, snapshot), 'utf-8')) as Record<string, any>;
      const ids = (persisted.graph.nodes as Array<{ key: string }>).map(node => node.key);
      expect(ids).not.toContain('must-remain-rolled-back');
    }
    closeEngine(restarted);
    },
  );

  it('preserves an unterminated EOF fragment and stays degraded across three restarts', () => {
    const base = openEngine();
    base.persist();
    base.flushNow();
    closeEngine(base);
    const stateBefore = readFileSync(statePath);
    const baseCheckpoint = checkpoint(statePath);

    const wal = new MutationJournal(statePath);
    wal.setNextSeq(baseCheckpoint);
    const prefix = wal.append({ type: 'add_node', payload: { props: host('complete-prefix') }, ts: NOW });
    const eofSeq = prefix.seq + 1;
    appendFileSync(journalPath(), JSON.stringify({
      seq: eofSeq,
      ts: NOW,
      type: 'add_node',
      payload: { props: host('syntactically-complete-uncommitted-eof') },
    }));
    const walBefore = readFileSync(journalPath());

    for (let restart = 1; restart <= 3; restart += 1) {
      const recovered = openEngine();
      expect(recovered.getNode('complete-prefix')).toBeDefined();
      expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
        outcome: 'incomplete',
        complete: false,
        writable: false,
        base_checkpoint: baseCheckpoint,
        highest_on_disk_seq: eofSeq,
        highest_contiguous_applied_seq: prefix.seq,
        journal: { malformed: true, preserved: true, applied: 1, attempted: 1 },
      });
      expect(recovered.getPersistenceRecoveryStatus().reason).toContain('unterminated EOF fragment');
      expect(recovered.getNode('syntactically-complete-uncommitted-eof')).toBeNull();
      expect(readFileSync(statePath)).toEqual(stateBefore);
      expect(readFileSync(journalPath())).toEqual(walBefore);
      const quarantines = quarantineFiles();
      expect(quarantines).toHaveLength(1);
      expect(readFileSync(join(tempDir, quarantines[0]))).toEqual(walBefore);
      closeEngine(recovered);
    }
  });

  it('reports a sequence gap as incomplete but not malformed', () => {
    const base = openEngine();
    base.persist();
    base.flushNow();
    closeEngine(base);
    const baseCheckpoint = checkpoint(statePath);
    const gapSeq = baseCheckpoint + 2;
    writeFileSync(journalPath(), `${JSON.stringify({
      seq: gapSeq,
      ts: NOW,
      type: 'add_node',
      payload: { props: host('after-gap') },
    })}\n`);

    const recovered = openEngine();
    expect(recovered.getNode('after-gap')).toBeNull();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      highest_on_disk_seq: gapSeq,
      highest_contiguous_applied_seq: baseCheckpoint,
      journal: { malformed: false, preserved: true },
    });
    expect(recovered.getPersistenceRecoveryStatus().reason).toContain('sequence gap');
    closeEngine(recovered);
  });

  it('surfaces a live append/apply ambiguity as preserved and read-only', () => {
    const engine = openEngine();
    const graph = (engine as any).ctx.graph;
    vi.spyOn(graph, 'addNode').mockImplementationOnce(() => {
      throw new Error('synthetic in-memory apply failure');
    });

    expect(() => engine.addNode(host('durable-but-not-applied'))).toThrow(
      /synthetic in-memory apply failure/,
    );
    expect(engine.getNode('durable-but-not-applied')).toBeNull();
    expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      journal: { malformed: false, preserved: true },
    });
    closeEngine(engine);
  });

  it('does not let quarantine-copy failure prevent degraded read-only startup', () => {
    const base = openEngine();
    base.persist();
    base.flushNow();
    closeEngine(base);

    const wal = new MutationJournal(statePath);
    wal.setNextSeq(checkpoint(statePath));
    wal.append({ type: 'future_mutation' as MutationType, payload: {}, ts: NOW });
    const quarantineSpy = vi.spyOn(MutationJournal.prototype, 'quarantine')
      .mockImplementation(() => { throw new Error('synthetic quarantine failure'); });
    try {
      const recovered = openEngine();
      expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
        outcome: 'incomplete',
        complete: false,
        writable: false,
      });
      const recoveryEvent = recovered.getFullHistory().find(event =>
        event.description.startsWith('WAL recovery incomplete'),
      );
      expect(recoveryEvent?.details).toMatchObject({
        quarantine_error: 'synthetic quarantine failure',
      });
      expect(() => recovered.addNode(host('blocked-despite-quarantine-failure'))).toThrow(
        /Durable mutations are disabled while persistence is degraded/,
      );
      closeEngine(recovered);
    } finally {
      quarantineSpy.mockRestore();
    }
  });

  it('requires a clean restart when a failed recovery checkpoint later succeeds', async () => {
    const base = openEngine();
    base.persist();
    base.flushNow();
    closeEngine(base);

    const wal = new MutationJournal(statePath);
    wal.setNextSeq(checkpoint(statePath));
    wal.append({ type: 'add_node', payload: { props: host('replayed-before-checkpoint-failure') }, ts: NOW });
    mkdirSync(`${statePath}.tmp`);
    vi.useFakeTimers();

    const degraded = openEngine();
    expect(degraded.getNode('replayed-before-checkpoint-failure')).toBeDefined();
    expect(degraded.isPersistenceWritable()).toBe(false);
    rmSync(`${statePath}.tmp`, { recursive: true, force: true });

    await vi.advanceTimersByTimeAsync(PERSIST_RETRY_DELAYS_MS[0] + 1);
    expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      consecutive_persistence_failures: 0,
    });
    expect(degraded.getPersistenceRecoveryStatus().reason).toContain('restart required');
    expect(() => degraded.addNode(host('blocked-until-restart'))).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );
    closeEngine(degraded);

    vi.useRealTimers();
    const restarted = openEngine();
    expect(restarted.getNode('replayed-before-checkpoint-failure')).toBeDefined();
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({ complete: true, writable: true });
    closeEngine(restarted);
  });

  it('retries a scheduled persistence failure and recovers after the state path is repaired', async () => {
    const engine = openEngine();
    vi.useFakeTimers();

    rmSync(statePath, { force: true });
    mkdirSync(statePath); // rename(state.tmp, state) will fail while the target is a directory
    engine.addNode(host('persisted-after-retry'));
    engine.persist();

    await vi.advanceTimersByTimeAsync(FLUSH_DEBOUNCE_MS + 1);
    expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
      writable: true,
      consecutive_persistence_failures: 1,
    });

    rmSync(statePath, { recursive: true, force: true });
    await vi.advanceTimersByTimeAsync(PERSIST_RETRY_DELAYS_MS[0] + 1);
    expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
      writable: true,
      consecutive_persistence_failures: 0,
    });
    expect(existsSync(statePath)).toBe(true);
    expect(JSON.stringify(JSON.parse(readFileSync(statePath, 'utf-8')))).toContain('persisted-after-retry');

    closeEngine(engine);
    vi.useRealTimers();
    const verified = openEngine();
    expect(verified.getNode('persisted-after-retry')).toBeDefined();
    closeEngine(verified);
  });

  it('keeps the three-failure write gate closed after a late retry until clean restart', async () => {
    const engine = openEngine();
    vi.useFakeTimers();

    rmSync(statePath, { force: true });
    mkdirSync(statePath);
    engine.addNode(host('before-persistence-degraded'));
    engine.persist();

    await vi.advanceTimersByTimeAsync(FLUSH_DEBOUNCE_MS + 1); // initial flush failure
    await vi.advanceTimersByTimeAsync(PERSIST_RETRY_DELAYS_MS[0] + 1); // retry failure 2
    await vi.advanceTimersByTimeAsync(PERSIST_RETRY_DELAYS_MS[1] + 1); // retry failure 3

    expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
      writable: false,
      consecutive_persistence_failures: 3,
    });
    expect(engine.isPersistenceWritable()).toBe(false);
    const configName = engine.getConfig().name;
    expect(() => engine.updateConfig({ name: 'must-not-leak' })).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );
    expect(engine.getConfig().name).toBe(configName);
    const walBeforeBlockedMutation = readFileSync(journalPath());
    expect(() => engine.addNode(host('blocked-after-three-failures'))).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );
    expect(engine.getNode('blocked-after-three-failures')).toBeNull();
    expect(readFileSync(journalPath())).toEqual(walBeforeBlockedMutation);
    expect(() => engine.persist()).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );

    // A background retry may make the pending state durable, but target-facing
    // work already froze around the failure. Do not reopen this process in-place.
    rmSync(statePath, { recursive: true, force: true });
    await vi.advanceTimersByTimeAsync(PERSIST_RETRY_DELAYS_MS[2] + 1);
    expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      consecutive_persistence_failures: 0,
    });
    expect(engine.getPersistenceRecoveryStatus().reason).toContain('restart required');
    expect(existsSync(statePath)).toBe(true);
    expect(() => engine.addNode(host('still-blocked-after-late-retry'))).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );
    closeEngine(engine);

    vi.useRealTimers();
    const restarted = openEngine();
    expect(restarted.getNode('before-persistence-degraded')).toBeDefined();
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({ complete: true, writable: true });
    closeEngine(restarted);
  });
});
