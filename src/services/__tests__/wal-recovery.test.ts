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
import { createHash } from 'crypto';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal } from '../mutation-journal.js';
import type { MutationType } from '../mutation-journal.js';
import {
  FLUSH_DEBOUNCE_MS,
  MAX_SNAPSHOTS,
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

function withCompactionAuthority(state: Record<string, unknown>): Buffer {
  const payload = { ...state };
  delete payload.walCompactionAuthority;
  const payloadJson = JSON.stringify(payload);
  return Buffer.from(JSON.stringify({
    ...payload,
    walCompactionAuthority: {
      semantics: 'full_state_sha256_json_v1',
      payload_sha256: createHash('sha256').update(payloadJson).digest('hex'),
    },
  }));
}

function rollbackIntent(input: {
  checkpoint: number;
  selected_snapshot: string;
  selected_snapshot_sha256: string;
}): Record<string, unknown> {
  const body = {
    version: 1 as const,
    ...input,
  };
  return {
    ...body,
    intent_checksum: createHash('sha256').update(JSON.stringify([
      body.version,
      body.checkpoint,
      body.selected_snapshot,
      body.selected_snapshot_sha256,
    ])).digest('hex'),
  };
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

  function stageLegacyRollbackOverclaim(writer: GraphEngine): {
    snapshot: string;
    snapshotPath: string;
    snapshotBytes: Buffer;
    checkpoint: number;
  } {
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('legacy-rollback-anchor'));
    writer.persist();
    writer.flushNow();
    const durableCheckpoint = checkpoint(statePath);
    const legacy = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    delete legacy.state_version;
    delete legacy.journal_version;
    delete legacy.walCompactionAuthority;
    delete legacy.journalCheckpointSemantics;
    legacy.journalSnapshotSeq = durableCheckpoint + 1;
    const snapshotBytes = Buffer.from(JSON.stringify(legacy));
    const snapshotDir = join(tempDir, '.snapshots');
    mkdirSync(snapshotDir, { recursive: true });
    const snapshotName = 'state.snap-2026-01-01T00-00-00-000Z-1.json';
    const snapshotPath = join(snapshotDir, snapshotName);
    writeFileSync(snapshotPath, snapshotBytes);
    const journal = (writer as any).ctx.mutationJournal as MutationJournal;
    expect(journal.compactUpTo(durableCheckpoint)).toEqual({ kept: 0, dropped: durableCheckpoint });
    writer.addNode(host('legacy-rollback-hidden-wal-record'));
    return {
      snapshot: `.snapshots/${snapshotName}`,
      snapshotPath,
      snapshotBytes,
      checkpoint: durableCheckpoint + 1,
    };
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

  it('does not resurrect a dropped edge when legacy WAL edge IDs collided', () => {
    const r1 = openEngine();
    const sourceOne = 'a';
    const targetOne = 'b--RELATED--c';
    const sourceTwo = 'a--RELATED--b';
    const targetTwo = 'c';
    for (const id of [sourceOne, targetOne, sourceTwo, targetTwo]) r1.addNode(host(id));
    (r1 as any).ctx.lastSnapshotTime = Date.now();
    r1.persist();
    r1.flushNow();
    const baseCheckpoint = checkpoint(statePath);
    const props = {
      type: 'RELATED' as const,
      confidence: 1,
      discovered_at: NOW,
    };
    const first = r1.addEdge(sourceOne, targetOne, props);
    const second = r1.addEdge(sourceTwo, targetTwo, props);
    expect(first.id).not.toBe(second.id);
    expect(second.id).toContain('--collision-');
    expect(r1.dropEdgeByRef(sourceTwo, targetTwo, 'RELATED')).toBe(second.id);
    expect(r1.findEdgeId(sourceOne, targetOne, 'RELATED')).toBe(first.id);
    expect(r1.findEdgeId(sourceTwo, targetTwo, 'RELATED')).toBeNull();

    // Emulate journals emitted before edge IDs became deterministic/persisted:
    // add_edge lacked edge_id and drop_edge named a random live fallback ID.
    const legacyRecords = readFileSync(journalPath(), 'utf-8')
      .split('\n')
      .filter(Boolean)
      .map(line => JSON.parse(line) as Record<string, any>);
    for (const record of legacyRecords) {
      if (record.type === 'add_edge') delete record.payload.edge_id;
      if (record.type === 'drop_edge') record.payload.edge_id = 'legacy-random-fallback-id';
    }
    writeFileSync(journalPath(), `${legacyRecords.map(record => JSON.stringify(record)).join('\n')}\n`);
    closeEngine(r1);

    const r2 = openEngine();
    expect(r2.findEdgeId(sourceOne, targetOne, 'RELATED')).toBeTruthy();
    expect(r2.findEdgeId(sourceTwo, targetTwo, 'RELATED')).toBeNull();
    expect(r2.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      complete: true,
      writable: true,
      base_checkpoint: baseCheckpoint + 3,
      journal: { read: 3, attempted: 3, applied: 3, skipped: 0, failed: 0 },
    });
    closeEngine(r2);

    const r3 = openEngine();
    expect(r3.findEdgeId(sourceOne, targetOne, 'RELATED')).toBeTruthy();
    expect(r3.findEdgeId(sourceTwo, targetTwo, 'RELATED')).toBeNull();
    expect(r3.getPersistenceRecoveryStatus()).toMatchObject({ complete: true, writable: true });
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
    delete state.walCompactionAuthority;
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
    delete state.state_version;
    delete state.journal_version;
    delete state.journalCheckpointSemantics;
    delete state.walCompactionAuthority;
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
    delete state.state_version;
    delete state.journal_version;
    delete state.journalCheckpointSemantics;
    delete state.walCompactionAuthority;
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

  it('does not overwrite a newer recognized checksum mismatch with an older valid fallback', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('checksum-fallback-anchor'));
    writer.persist();
    writer.flushNow();
    const validAnchor = readFileSync(statePath);

    writer.addNode(host('checksum-fallback-tail'));
    writer.persist();
    writer.flushNow();
    closeEngine(writer);

    const snapshotDir = join(tempDir, '.snapshots');
    rmSync(snapshotDir, { recursive: true, force: true });
    mkdirSync(snapshotDir, { recursive: true });
    writeFileSync(
      join(snapshotDir, 'state.snap-2026-01-01T00-00-00-000Z-1.json'),
      validAnchor,
    );
    const tampered = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    tampered.graph.nodes = tampered.graph.nodes
      .filter((node: { key: string }) => node.key !== 'checksum-fallback-tail');
    const tamperedBytes = Buffer.from(JSON.stringify(tampered));
    writeFileSync(statePath, tamperedBytes);
    const walBefore = readFileSync(journalPath());

    const degraded = openEngine();
    expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'state',
      complete: false,
      writable: false,
      journal: { preserved: true },
    });
    expect(readFileSync(statePath)).toEqual(tamperedBytes);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(readFileSync(
      join(snapshotDir, 'state.snap-2026-01-01T00-00-00-000Z-1.json'),
    )).toEqual(validAnchor);
    closeEngine(degraded);
  });

  it('does not reseed over a recognized checksum mismatch when no alternate base exists', () => {
    const writer = openEngine();
    writer.addNode(host('checksum-mismatch-must-remain-on-disk'));
    writer.persist();
    writer.flushNow();
    closeEngine(writer);
    rmSync(join(tempDir, '.snapshots'), { recursive: true, force: true });
    rmSync(journalPath(), { force: true });

    const tampered = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    tampered.graph.nodes = [];
    const tamperedBytes = Buffer.from(JSON.stringify(tampered));
    writeFileSync(statePath, tamperedBytes);

    const degraded = openEngine();
    expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'state',
      complete: false,
      writable: false,
      base_checkpoint: 0,
      highest_on_disk_seq: 0,
      highest_contiguous_applied_seq: 0,
      journal: { preserved: false },
    });
    expect(degraded.getPersistenceRecoveryStatus().reason).toContain('integrity check');
    expect(readFileSync(statePath)).toEqual(tamperedBytes);
    expect(() => degraded.addNode(host('must-not-reseed-over-checksum-mismatch'))).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );
    closeEngine(degraded);
  });

  it('ranks an integrity mismatch against fully restorable candidates only', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('fully-valid-cp-one'));
    writer.persist();
    writer.flushNow();
    const validCpOne = readFileSync(statePath);

    writer.addNode(host('mismatched-cp-two'));
    writer.persist();
    writer.flushNow();
    const mismatchedCpTwo = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    mismatchedCpTwo.graph.nodes.push({
      key: 'mismatched-base-only-cp-two',
      attributes: host('mismatched-base-only-cp-two'),
    });
    const mismatchedCpTwoBytes = Buffer.from(JSON.stringify(mismatchedCpTwo));

    writer.addNode(host('unrestorable-cp-three'));
    writer.persist();
    writer.flushNow();
    closeEngine(writer);
    const unrestorableCpThree = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    delete unrestorableCpThree.walCompactionAuthority;
    unrestorableCpThree.agents = [1];
    const unrestorableCpThreeBytes = Buffer.from(JSON.stringify(unrestorableCpThree));
    writeFileSync(statePath, unrestorableCpThreeBytes);

    const snapshotDir = join(tempDir, '.snapshots');
    rmSync(snapshotDir, { recursive: true, force: true });
    mkdirSync(snapshotDir, { recursive: true });
    const validPath = join(snapshotDir, 'state.snap-2026-01-01T00-00-00-000Z-1.json');
    const mismatchPath = join(snapshotDir, 'state.snap-2026-01-02T00-00-00-000Z-1.json');
    writeFileSync(validPath, validCpOne);
    writeFileSync(mismatchPath, mismatchedCpTwoBytes);
    const walBefore = readFileSync(journalPath());

    const degraded = openEngine();
    expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'snapshot',
      complete: false,
      writable: false,
    });
    expect(readFileSync(statePath)).toEqual(unrestorableCpThreeBytes);
    expect(readFileSync(validPath)).toEqual(validCpOne);
    expect(readFileSync(mismatchPath)).toEqual(mismatchedCpTwoBytes);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    closeEngine(degraded);
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

  it('rejects invalid UTF-8 in a legacy base instead of replacement-decoding and checkpointing it', () => {
    const seed = openEngine();
    closeEngine(seed);
    const legacy = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    delete legacy.walCompactionAuthority;
    const labelMarker = 'invalid-utf8-state-label';
    legacy.graph.nodes.push({
      key: 'legacy-invalid-utf8-node',
      attributes: { ...host('legacy-invalid-utf8-node'), label: labelMarker },
    });
    const invalidBase = Buffer.from(JSON.stringify(legacy));
    const markerOffset = invalidBase.indexOf(Buffer.from(labelMarker));
    expect(markerOffset).toBeGreaterThanOrEqual(0);
    invalidBase[markerOffset] = 0xff;
    writeFileSync(statePath, invalidBase);

    const journal = new MutationJournal(statePath);
    journal.append({
      type: 'add_node',
      payload: { props: host('valid-wal-beyond-invalid-utf8-base') },
      ts: NOW,
    });
    const walBefore = readFileSync(journalPath());

    for (let restart = 1; restart <= 3; restart++) {
      const degraded = openEngine();
      expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
        outcome: 'incomplete',
        complete: false,
        writable: false,
        journal: { preserved: true },
      });
      expect(degraded.getNode('legacy-invalid-utf8-node')).toBeNull();
      expect(degraded.getNode('valid-wal-beyond-invalid-utf8-base')).toBeNull();
      expect(readFileSync(statePath)).toEqual(invalidBase);
      expect(readFileSync(journalPath())).toEqual(walBefore);
      expect(quarantineFiles()).toHaveLength(1);
      closeEngine(degraded);
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

  it('reports both base and WAL access failures when they occur together', () => {
    rmSync(statePath, { force: true });
    mkdirSync(statePath);
    mkdirSync(journalPath());

    const degraded = openEngine();
    const reason = degraded.getPersistenceRecoveryStatus().reason ?? '';
    expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'state',
      complete: false,
      writable: false,
      journal: { preserved: true },
    });
    expect(reason).toContain('persisted state recovery base could not be read');
    expect(reason).toContain('persisted WAL could not be read');
    closeEngine(degraded);
  });

  it('starts inspectable and read-only when the WAL itself cannot be read', () => {
    const writer = openEngine();
    writer.addNode(host('durable-before-unreadable-wal'));
    writer.persist();
    writer.flushNow();
    closeEngine(writer);
    const primaryBefore = readFileSync(statePath);

    rmSync(journalPath(), { recursive: true, force: true });
    mkdirSync(journalPath());

    const degraded = openEngine();
    expect(degraded.getNode('durable-before-unreadable-wal')).toBeDefined();
    expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'state',
      complete: false,
      writable: false,
      journal: { enabled: true, preserved: true },
    });
    expect(degraded.getPersistenceRecoveryStatus().reason).toContain(
      'persisted WAL could not be read',
    );
    expect(() => degraded.addNode(host('must-not-append-to-unreadable-wal'))).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(existsSync(journalPath())).toBe(true);
    closeEngine(degraded);
  });

  it('keeps recovery status inspectable when an unreadable WAL and invalid rollback authority coexist', () => {
    const writer = openEngine();
    writer.addNode(host('durable-before-combined-recovery-failure'));
    writer.persist();
    writer.flushNow();
    closeEngine(writer);
    const primaryBefore = readFileSync(statePath);

    rmSync(journalPath(), { recursive: true, force: true });
    mkdirSync(journalPath());
    const authorityPath = `${statePath}.rollback-intent.json`;
    writeFileSync(authorityPath, '{}');

    const degraded = openEngine();
    expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'state',
      complete: false,
      writable: false,
      journal: { enabled: true, preserved: true },
    });
    expect(degraded.getPersistenceRecoveryStatus().reason).toContain('rollback');
    expect(() => degraded.addNode(host('must-not-mutate-combined-failure'))).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(authorityPath, 'utf-8')).toBe('{}');
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

  it('keeps the incoming config and blocks writes after rejecting a malformed V1 base', () => {
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
    delete rejected.walCompactionAuthority;
    writeFileSync(statePath, JSON.stringify(rejected));
    const rejectedBytes = readFileSync(statePath);

    const recovered = openEngine();
    expect(recovered.getConfig().name).toBe(originalName);
    expect(recovered.getNode('must-not-leak-from-rejected-base')).toBeNull();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'state',
      complete: false,
      writable: false,
      state_migration: { status: 'blocked', observed_state_version: 1 },
    });
    expect(readFileSync(statePath)).toEqual(rejectedBytes);
    closeEngine(recovered);
  });

  it('blocks without reseeding when a V1 config fails the canonical schema', () => {
    const originalName = config.name;
    const writer = openEngine();
    closeEngine(writer);

    const rejected = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    rejected.config = {
      ...rejected.config,
      name: 'invalid persisted config',
      scope: { ...rejected.config.scope, cidrs: ['999.999.999.999/99'] },
    };
    delete rejected.walCompactionAuthority;
    writeFileSync(statePath, JSON.stringify(rejected));
    const rejectedBytes = readFileSync(statePath);

    const recovered = openEngine();
    expect(recovered.getConfig().name).toBe(originalName);
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'state',
      complete: false,
      writable: false,
      state_migration: { status: 'blocked', observed_state_version: 1 },
    });
    expect(readFileSync(statePath)).toEqual(rejectedBytes);
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

  it('treats a same-clock collision suffix as newer at an equal checkpoint', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('collision-order-old-state'));
    writer.persist();
    writer.flushNow();
    closeEngine(writer);

    const oldBytes = readFileSync(statePath);
    const newer = JSON.parse(oldBytes.toString('utf-8')) as Record<string, any>;
    newer.config = { ...newer.config, name: 'collision-order-new-state' };
    newer.graph.nodes.push({
      key: 'collision-order-new-state',
      attributes: host('collision-order-new-state'),
    });
    const newerBytes = withCompactionAuthority(newer);

    rmSync(journalPath(), { force: true });
    const snapshotDir = join(tempDir, '.snapshots');
    rmSync(snapshotDir, { recursive: true, force: true });
    mkdirSync(snapshotDir, { recursive: true });
    const family = 'state.snap-2026-07-15T12-34-56-789Z-123';
    writeFileSync(join(snapshotDir, `${family}.json`), oldBytes);
    writeFileSync(join(snapshotDir, `${family}-0001.json`), newerBytes);
    writeFileSync(statePath, '{corrupt primary');

    const recovered = openEngine();
    expect(recovered.getConfig().name).toBe('collision-order-new-state');
    expect(recovered.getNode('collision-order-new-state')).toBeDefined();
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
    delete incompatiblePrimary.walCompactionAuthority;
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

  it('retains WAL needed by a legacy fallback alongside newer trusted snapshots', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('oldest-base-node'));
    writer.persist();
    writer.flushNow();
    const oldestSnapshot = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, unknown>;
    delete oldestSnapshot.state_version;
    delete oldestSnapshot.journal_version;
    delete oldestSnapshot.journalCheckpointSemantics;
    delete oldestSnapshot.walCompactionAuthority;
    const oldestSnapshotBytes = Buffer.from(JSON.stringify(oldestSnapshot));
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
    expect(retainedSeqs).toContain(oldestCheckpoint + 1);
    expect(retainedSeqs).toContain(oldestCheckpoint + 2);
    const walBeforeFallback = readFileSync(journalPath());

    writeFileSync(statePath, '{corrupt primary');
    for (const snapshotName of readdirSync(snapshotDir)) {
      if (snapshotName !== oldestName) {
        writeFileSync(join(snapshotDir, snapshotName), '{corrupt newer snapshot');
      }
    }

    const recovered = openEngine();
    expect(recovered.getNode('oldest-base-node')).toBeDefined();
    // The retained record at/below an unmarked legacy cursor is deliberately
    // ambiguous, so recovery stays read-only rather than guessing. Crucially,
    // the newer committed suffix remains available for explicit recovery.
    expect(recovered.getNode('middle-node')).toBeNull();
    expect(recovered.getNode('tail-node')).toBeNull();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      source: 'snapshot',
      complete: false,
      writable: false,
      journal: { preserved: true },
    });
    expect(readFileSync(journalPath())).toEqual(walBeforeFallback);
    closeEngine(recovered);
  });

  it('gates an ordinary non-rotation flush before pruning an unreadable retained snapshot', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('unreadable-snapshot-anchor'));
    writer.persist();
    writer.flushNow();
    const anchorCheckpoint = checkpoint(statePath);

    writer.addNode(host('unreadable-snapshot-tail'));
    const snapshotDir = join(tempDir, '.snapshots');
    mkdirSync(snapshotDir, { recursive: true });
    const primaryBefore = readFileSync(statePath);
    for (let i = 0; i <= MAX_SNAPSHOTS; i++) {
      writeFileSync(
        join(snapshotDir, `state.snap-2026-01-0${i + 1}T00-00-00-000Z-1.json`),
        primaryBefore,
      );
    }
    const unreadable = join(snapshotDir, 'state.snap-2026-01-09T00-00-00-000Z-1.json');
    mkdirSync(unreadable);
    const snapshotsBefore = writer.listSnapshots();
    const walBefore = readFileSync(journalPath());
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.persist();
    for (let failures = 1; failures <= 3; failures++) {
      expect(() => writer.flushNow()).toThrow(/could not read retained recovery snapshot/);
      expect(writer.getPersistenceRecoveryStatus()).toMatchObject({
        writable: failures < 3,
        consecutive_persistence_failures: failures,
      });
    }

    const retainedSeqs = readFileSync(journalPath(), 'utf-8')
      .split('\n')
      .filter(Boolean)
      .map(line => (JSON.parse(line) as { seq: number }).seq);
    expect(retainedSeqs).toContain(anchorCheckpoint);
    expect(retainedSeqs).toContain(anchorCheckpoint + 1);
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(writer.listSnapshots()).toEqual(snapshotsBefore);
    expect(writer.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      consecutive_persistence_failures: 3,
      journal: { preserved: true },
    });
    closeEngine(writer);
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

    // Let the preflight inspect the primary, then fail the second primary read
    // after rotation has allocated its suffixed exclusive-create candidate.
    // This pins cleanup at the actual copy-failure boundary.
    const persistence = (writer as any).persistence as {
      readPersistedBytes(path: string): Buffer;
    };
    const readPersistedBytes = persistence.readPersistedBytes.bind(persistence);
    let primaryReads = 0;
    vi.spyOn(persistence, 'readPersistedBytes').mockImplementation((path: string) => {
      if (path === statePath && ++primaryReads === 2) {
        throw new Error('synthetic snapshot copy read failure');
      }
      return readPersistedBytes(path);
    });
    writer.addNode(host('collision-wal-tail'));
    writer.persist();
    (writer as any).ctx.lastSnapshotTime = 0;

    expect(() => writer.flushNow()).toThrow(/synthetic snapshot copy read failure/);
    expect(readFileSync(collidingPath)).toEqual(retainedAnchor);
    expect(existsSync(join(
      snapshotDir,
      `state.snap-${timestamp}-${process.pid}-0001.json`,
    ))).toBe(false);
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(journalPath(), 'utf-8')).toContain('collision-wal-tail');
    closeEngine(writer);
    vi.useRealTimers();
  });

  it('does not compact against an auxiliary-corrupt snapshot before a failed primary replacement', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    (writer as any).ctx.coldAdd({
      id: 'aux-corrupt-cold-seq-one',
      type: 'host',
      label: '10.10.10.9',
      ip: '10.10.10.9',
      discovered_at: NOW,
      last_seen_at: NOW,
      subnet_cidr: '10.10.10.0/24',
      alive: true,
    });
    writer.persist();
    writer.flushNow();
    const firstCheckpoint = checkpoint(statePath);
    rmSync(join(tempDir, '.snapshots'), { recursive: true, force: true });

    // Keep live memory valid while making the durable primary rankable by
    // config/graph/checkpoint but silently lossy to the old deserializer.
    const corruptPrimary = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, unknown>;
    corruptPrimary.coldStore = {};
    const corruptPrimaryBytes = Buffer.from(JSON.stringify(corruptPrimary));
    writeFileSync(statePath, corruptPrimaryBytes);

    writer.addNode(host('aux-corrupt-seq-two'));
    const walBefore = readFileSync(journalPath());
    const walSeqsBefore = walBefore.toString('utf-8')
      .split('\n')
      .filter(Boolean)
      .map(line => (JSON.parse(line) as { seq: number }).seq);
    expect(walSeqsBefore).toContain(firstCheckpoint);
    expect(walSeqsBefore).toContain(firstCheckpoint + 1);

    // Rotation copies the corrupt primary. The replacement then fails after
    // anchor validation, which must not have let that copy authorize compaction.
    mkdirSync(`${statePath}.tmp`);
    (writer as any).ctx.lastSnapshotTime = 0;
    writer.persist();
    expect(() => writer.flushNow()).toThrow();
    expect(readFileSync(statePath)).toEqual(corruptPrimaryBytes);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    closeEngine(writer);

    rmSync(`${statePath}.tmp`, { recursive: true, force: true });
    const restarted = openEngine();
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      journal: { preserved: true },
    });
    expect(readFileSync(journalPath())).toEqual(walBefore);
    closeEngine(restarted);
  });

  it('retains the compaction anchor until the replacement primary is durable', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('retained-valid-anchor'));
    writer.persist();
    writer.flushNow();
    const anchorCheckpoint = checkpoint(statePath);
    const validAnchorBytes = readFileSync(statePath);

    const snapshotDir = join(tempDir, '.snapshots');
    rmSync(snapshotDir, { recursive: true, force: true });
    mkdirSync(snapshotDir, { recursive: true });
    const validAnchorName = 'state.snap-2026-01-01T00-00-00-000Z-1.json';
    writeFileSync(join(snapshotDir, validAnchorName), validAnchorBytes);
    for (let day = 2; day <= MAX_SNAPSHOTS + 2; day++) {
      writeFileSync(
        join(snapshotDir, `state.snap-2026-01-${String(day).padStart(2, '0')}T00-00-00-000Z-1.json`),
        '{invalid newer snapshot',
      );
    }

    writeFileSync(statePath, '{corrupt primary before failed replacement');
    writer.addNode(host('retained-anchor-tail'));
    mkdirSync(`${statePath}.tmp`);
    (writer as any).ctx.lastSnapshotTime = 0;
    writer.persist();

    expect(() => writer.flushNow()).toThrow();
    expect(readFileSync(join(snapshotDir, validAnchorName))).toEqual(validAnchorBytes);
    const retainedSeqs = readFileSync(journalPath(), 'utf-8')
      .split('\n')
      .filter(Boolean)
      .map(line => (JSON.parse(line) as { seq: number }).seq);
    expect(retainedSeqs).toContain(anchorCheckpoint + 1);
    closeEngine(writer);

    rmSync(`${statePath}.tmp`, { recursive: true, force: true });
    const recovered = openEngine();
    expect(recovered.getNode('retained-valid-anchor')).toBeDefined();
    expect(recovered.getNode('retained-anchor-tail')).toBeDefined();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      source: 'snapshot',
      complete: true,
      writable: true,
    });
    closeEngine(recovered);
  });

  it('validates retained snapshots without mutating live hash-chain counters', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('detached-anchor-validation'));
    writer.persist();
    writer.flushNow();

    (writer as any).ctx.chainEventsSinceCheckpoint = 17;
    (writer as any).ctx.lastSnapshotTime = 0;
    writer.persist();
    writer.flushNow();

    expect((writer as any).ctx.chainEventsSinceCheckpoint).toBe(17);
    closeEngine(writer);
  });

  it('serializes live state once before hashing and emitting its compaction authority', () => {
    const writer = openEngine();
    let evaluations = 0;
    (writer as any).ctx.activityLog.push({
      event_id: 'evt-stateful-serialization',
      timestamp: NOW,
      description: 'stateful serialization fixture',
      event_type: 'system',
      details: {
        dynamic: {
          toJSON() {
            evaluations++;
            return { evaluation: evaluations };
          },
        },
      },
    });
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.persist();
    writer.flushNow();
    expect(evaluations).toBe(1);
    closeEngine(writer);

    const recovered = openEngine();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      source: 'state',
    });
    const restored = (recovered as any).ctx.activityLog.find(
      (entry: { event_id?: string }) => entry.event_id === 'evt-stateful-serialization',
    );
    expect(restored?.details?.dynamic).toEqual({ evaluation: 1 });
    closeEngine(recovered);
  });

  it('gates an ordinary flush before replacing a checksum-mismatched primary', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('live-integrity-anchor'));
    writer.persist();
    writer.flushNow();

    const mismatched = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    mismatched.graph.nodes.push({
      key: 'base-only-integrity-state',
      attributes: host('base-only-integrity-state'),
    });
    const primaryBefore = Buffer.from(JSON.stringify(mismatched));
    writeFileSync(statePath, primaryBefore);
    writer.addNode(host('live-integrity-tail'));
    const walBefore = readFileSync(journalPath());
    writer.persist();

    expect(() => writer.flushNow()).toThrow(/state replacement found a recognized integrity mismatch/);
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(writer.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      journal: { preserved: true },
    });
    closeEngine(writer);
  });

  it('fails before writing or renaming when the durable primary cannot be read', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('read-access-live-anchor'));
    writer.persist();
    writer.flushNow();

    writer.addNode(host('read-access-live-tail'));
    const primaryBefore = readFileSync(statePath);
    const walBefore = readFileSync(journalPath());
    const persistence = (writer as any).persistence as {
      readPersistedBytes(path: string): Buffer;
    };
    const readPersistedBytes = persistence.readPersistedBytes.bind(persistence);
    vi.spyOn(persistence, 'readPersistedBytes').mockImplementation((path: string) => {
      if (path === statePath) throw new Error('synthetic primary EIO');
      return readPersistedBytes(path);
    });
    writer.persist();

    expect(() => writer.flushNow()).toThrow(/synthetic primary EIO/);
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(existsSync(`${statePath}.tmp`)).toBe(false);
    expect(writer.getPersistenceRecoveryStatus()).toMatchObject({
      writable: true,
      consecutive_persistence_failures: 1,
      last_persistence_error: expect.stringContaining('synthetic primary EIO'),
    });
    expect(writer.getPersistenceRecoveryStatus().reason ?? '').not.toContain('persisted WAL could not be read');
    closeEngine(writer);
  });

  it('gates an ordinary non-rotation flush before pruning a higher-checkpoint mismatched snapshot', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('snapshot-integrity-anchor'));
    writer.persist();
    writer.flushNow();

    const snapshotDir = join(tempDir, '.snapshots');
    rmSync(snapshotDir, { recursive: true, force: true });
    mkdirSync(snapshotDir, { recursive: true });
    const mismatchPath = join(snapshotDir, 'state.snap-2026-01-01T00-00-00-000Z-1.json');
    const mismatched = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    mismatched.journalSnapshotSeq = 999;
    mismatched.graph.nodes.push({
      key: 'higher-checkpoint-base-only-state',
      attributes: host('higher-checkpoint-base-only-state'),
    });
    const mismatchBytes = Buffer.from(JSON.stringify(mismatched));
    writeFileSync(mismatchPath, mismatchBytes);
    const validSnapshotBytes = readFileSync(statePath);
    for (let i = 0; i < MAX_SNAPSHOTS; i++) {
      writeFileSync(
        join(snapshotDir, `state.snap-2026-01-0${i + 2}T00-00-00-000Z-1.json`),
        validSnapshotBytes,
      );
    }

    const primaryBefore = readFileSync(statePath);
    writer.addNode(host('snapshot-integrity-tail'));
    const walBefore = readFileSync(journalPath());
    const snapshotsBefore = writer.listSnapshots();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.persist();

    expect(() => writer.flushNow()).toThrow(/blocking recognized integrity mismatch/);
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(readFileSync(mismatchPath)).toEqual(mismatchBytes);
    expect(writer.listSnapshots()).toEqual(snapshotsBefore);
    expect(writer.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      journal: { preserved: true },
    });
    closeEngine(writer);
  });

  it('does not overwrite an equal-checkpoint mismatch when the primary is not a usable base', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('equal-checkpoint-live-anchor'));
    writer.persist();
    writer.flushNow();

    const snapshotDir = join(tempDir, '.snapshots');
    mkdirSync(snapshotDir, { recursive: true });
    const mismatchPath = join(snapshotDir, 'state.snap-2026-01-01T00-00-00-000Z-1.json');
    const mismatched = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    mismatched.graph.nodes.push({
      key: 'equal-checkpoint-base-only-state',
      attributes: host('equal-checkpoint-base-only-state'),
    });
    const mismatchBytes = Buffer.from(JSON.stringify(mismatched));
    writeFileSync(mismatchPath, mismatchBytes);
    const corruptPrimary = Buffer.from('{corrupt equal-checkpoint primary');
    writeFileSync(statePath, corruptPrimary);

    writer.addNode(host('equal-checkpoint-live-tail'));
    const walBefore = readFileSync(journalPath());
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.persist();

    expect(() => writer.flushNow()).toThrow(/blocking recognized integrity mismatch/);
    expect(readFileSync(statePath)).toEqual(corruptPrimary);
    expect(readFileSync(mismatchPath)).toEqual(mismatchBytes);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(writer.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      journal: { preserved: true },
    });
    closeEngine(writer);
  });

  it('immediately gates writes when snapshot rotation detects a corrupt WAL', () => {
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
    const snapshotsBefore = writer.listSnapshots();
    (writer as any).ctx.lastSnapshotTime = 0;
    writer.persist();

    expect(() => writer.flushNow()).toThrow(/snapshot WAL integrity preflight failed/);
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(writer.listSnapshots()).toEqual(snapshotsBefore);
    expect(writer.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      journal: { preserved: true },
    });
    expect(() => writer.addNode(host('must-not-append-after-integrity-failure'))).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );
    expect(readFileSync(journalPath())).toEqual(walBefore);
    closeEngine(writer);
  });

  it('immediately gates rotation when the physical WAL starts after the durable checkpoint gap', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('wal-head-gap-anchor'));
    writer.persist();
    writer.flushNow();
    const durableCheckpoint = checkpoint(statePath);
    const primaryBefore = readFileSync(statePath);
    const snapshotsBefore = writer.listSnapshots();
    writeFileSync(journalPath(), `${JSON.stringify({
      seq: durableCheckpoint + 2,
      ts: NOW,
      type: 'add_node',
      payload: { props: host('stranded-after-live-head-gap') },
    })}\n`);
    const walBefore = readFileSync(journalPath());

    (writer as any).ctx.lastSnapshotTime = 0;
    writer.persist();
    expect(() => writer.flushNow()).toThrow(
      new RegExp(`expected seq ${durableCheckpoint + 1}, found ${durableCheckpoint + 2}`),
    );
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(writer.listSnapshots()).toEqual(snapshotsBefore);
    expect(writer.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      highest_on_disk_seq: durableCheckpoint + 2,
      journal: { malformed: false, preserved: true },
    });
    expect(() => writer.addNode(host('must-not-append-after-head-gap'))).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );
    closeEngine(writer);
  });

  it('rejects rollback to the active primary because it is not a retained snapshot', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('active-primary-anchor'));
    writer.persist();
    writer.flushNow();
    const primaryBefore = readFileSync(statePath);
    const walBefore = readFileSync(journalPath());

    expect(writer.rollbackToSnapshot(basename(statePath))).toBe(false);
    expect(writer.isPersistenceWritable()).toBe(true);
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(existsSync(`${statePath}.rollback-intent.json`)).toBe(false);
    closeEngine(writer);
  });

  it('rejects a fresh legacy rollback target that overclaims a retained WAL record', () => {
    const writer = openEngine();
    const target = stageLegacyRollbackOverclaim(writer);
    const primaryBefore = readFileSync(statePath);
    const walBefore = readFileSync(journalPath());

    expect(() => writer.rollbackToSnapshot(target.snapshot)).toThrow(/not provably contiguous/);
    expect(writer.getNode('legacy-rollback-hidden-wal-record')).toBeDefined();
    expect(writer.isPersistenceWritable()).toBe(true);
    expect(readFileSync(statePath)).toEqual(primaryBefore);
    expect(readFileSync(target.snapshotPath)).toEqual(target.snapshotBytes);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(existsSync(`${statePath}.rollback-intent.json`)).toBe(false);
    closeEngine(writer);
  });

  it('sticky-gates a malformed or unknown WAL discovered by legacy rollback preflight', () => {
    const writer = openEngine();
    const legacy = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, unknown>;
    delete legacy.state_version;
    delete legacy.journal_version;
    delete legacy.walCompactionAuthority;
    delete legacy.journalCheckpointSemantics;
    const snapshotDir = join(tempDir, '.snapshots');
    mkdirSync(snapshotDir, { recursive: true });
    const snapshot = '.snapshots/state.snap-2026-01-01T00-00-00-000Z-1.json';
    writeFileSync(join(tempDir, snapshot), JSON.stringify(legacy));
    const journal = (writer as any).ctx.mutationJournal as MutationJournal;
    journal.append({ type: 'future_mutation' as MutationType, payload: {}, ts: NOW });
    const walBefore = readFileSync(journalPath());

    expect(() => writer.rollbackToSnapshot(snapshot)).toThrow(/WAL integrity preflight failed/);
    expect(writer.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      journal: { malformed: false, preserved: true },
    });
    expect(() => writer.addNode(host('must-not-append-after-rollback-wal-failure'))).toThrow(
      /Durable mutations are disabled while persistence is degraded/,
    );
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(existsSync(`${statePath}.rollback-intent.json`)).toBe(false);
    closeEngine(writer);
  });

  it('sticky-gates an unreadable WAL discovered by legacy rollback preflight', () => {
    const writer = openEngine();
    const legacy = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, unknown>;
    delete legacy.state_version;
    delete legacy.journal_version;
    delete legacy.walCompactionAuthority;
    delete legacy.journalCheckpointSemantics;
    const snapshotDir = join(tempDir, '.snapshots');
    mkdirSync(snapshotDir, { recursive: true });
    const snapshot = '.snapshots/state.snap-2026-01-01T00-00-00-000Z-1.json';
    writeFileSync(join(tempDir, snapshot), JSON.stringify(legacy));
    rmSync(journalPath(), { force: true });
    mkdirSync(journalPath());

    expect(() => writer.rollbackToSnapshot(snapshot)).toThrow(/persisted WAL could not be read/);
    expect(writer.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      journal: { preserved: true },
    });
    expect(writer.getPersistenceRecoveryStatus().reason).toContain('persisted WAL could not be read');
    expect(existsSync(`${statePath}.rollback-intent.json`)).toBe(false);
    closeEngine(writer);
  });

  it.each([
    { name: 'sidecar plus marked primary', sidecar: true },
    { name: 'marker-only primary', sidecar: false },
  ])('degrades a pending $name sourced from an ambiguous legacy rollback target', ({ sidecar }) => {
    const writer = openEngine();
    const target = stageLegacyRollbackOverclaim(writer);
    const walBefore = readFileSync(journalPath());
    closeEngine(writer);

    const intent = rollbackIntent({
      checkpoint: target.checkpoint,
      selected_snapshot: target.snapshot,
      selected_snapshot_sha256: createHash('sha256').update(target.snapshotBytes).digest('hex'),
    });
    const markedPayload = JSON.parse(target.snapshotBytes.toString('utf-8')) as Record<string, unknown>;
    markedPayload.journalCheckpointSemantics = 'contiguous_applied_v1';
    markedPayload.rollbackIntent = intent;
    const markedPrimary = withCompactionAuthority(markedPayload);
    writeFileSync(statePath, markedPrimary);
    const authorityPath = `${statePath}.rollback-intent.json`;
    const authorityBytes = Buffer.from(JSON.stringify(intent));
    if (sidecar) writeFileSync(authorityPath, authorityBytes);

    const degraded = openEngine();
    expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      journal: { preserved: true },
    });
    expect(degraded.getPersistenceRecoveryStatus().reason).toContain('not provably contiguous');
    expect(degraded.getNode('legacy-rollback-hidden-wal-record')).toBeNull();
    expect(readFileSync(statePath)).toEqual(markedPrimary);
    expect(readFileSync(target.snapshotPath)).toEqual(target.snapshotBytes);
    expect(readFileSync(journalPath())).toEqual(walBefore);
    expect(existsSync(authorityPath)).toBe(sidecar);
    if (sidecar) expect(readFileSync(authorityPath)).toEqual(authorityBytes);
    closeEngine(degraded);
  });

  it('uses the selected snapshot as canonical for marker-only rollback recovery', () => {
    const writer = openEngine();
    (writer as any).ctx.lastSnapshotTime = Date.now();
    writer.addNode(host('marker-only-selected-state'));
    writer.persist();
    writer.flushNow();
    closeEngine(writer);

    const selectedBytes = readFileSync(statePath);
    const selected = JSON.parse(selectedBytes.toString('utf-8')) as Record<string, any>;
    const selectedCheckpoint = selected.journalSnapshotSeq as number;
    const snapshotDir = join(tempDir, '.snapshots');
    mkdirSync(snapshotDir, { recursive: true });
    const snapshot = '.snapshots/state.snap-2026-01-01T00-00-00-000Z-1.json';
    const snapshotPath = join(tempDir, snapshot);
    writeFileSync(snapshotPath, selectedBytes);
    const intent = rollbackIntent({
      checkpoint: selectedCheckpoint,
      selected_snapshot: snapshot,
      selected_snapshot_sha256: createHash('sha256').update(selectedBytes).digest('hex'),
    });

    const markedPayload: Record<string, any> = { ...selected, rollbackIntent: intent };
    markedPayload.graph = {
      ...selected.graph,
      nodes: [
        ...selected.graph.nodes,
        {
          key: 'marker-only-primary-only-state',
          attributes: host('marker-only-primary-only-state'),
        },
      ],
    };
    const markedPrimary = withCompactionAuthority(markedPayload);
    writeFileSync(statePath, markedPrimary);
    expect(existsSync(`${statePath}.rollback-intent.json`)).toBe(false);

    const recovered = openEngine();
    expect(recovered.getNode('marker-only-selected-state')).toBeDefined();
    expect(recovered.getNode('marker-only-primary-only-state')).toBeNull();
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      source: 'snapshot',
      complete: true,
      writable: true,
    });
    const completed = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, any>;
    expect(completed.rollbackIntent).toBeUndefined();
    expect((completed.graph.nodes as Array<{ key: string }>).map(node => node.key))
      .not.toContain('marker-only-primary-only-state');
    expect(readFileSync(snapshotPath)).toEqual(selectedBytes);
    expect(existsSync(`${statePath}.rollback-intent.json`)).toBe(false);
    closeEngine(recovered);
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

  it('preserves invalid UTF-8 and its following WAL tail across three restarts', () => {
    const base = openEngine();
    base.persist();
    base.flushNow();
    closeEngine(base);
    const stateBefore = readFileSync(statePath);
    const baseCheckpoint = checkpoint(statePath);
    const invalidSeq = baseCheckpoint + 1;
    const tailSeq = invalidSeq + 1;
    const invalidFrame = Buffer.concat([
      Buffer.from(`{"seq":${invalidSeq},"ts":"${NOW}","type":"add_node","payload":{"props":{"id":"`),
      Buffer.from([0xff]),
      Buffer.from('"}}}\n'),
    ]);
    const tail = Buffer.from(`${JSON.stringify({
      seq: tailSeq,
      ts: NOW,
      type: 'add_node',
      payload: { props: host('tail-after-invalid-utf8') },
    })}\n`);
    const walBefore = Buffer.concat([invalidFrame, tail]);
    writeFileSync(journalPath(), walBefore);

    for (let restart = 1; restart <= 3; restart++) {
      const degraded = openEngine();
      expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
        outcome: 'incomplete',
        complete: false,
        writable: false,
        base_checkpoint: baseCheckpoint,
        highest_on_disk_seq: tailSeq,
        highest_contiguous_applied_seq: baseCheckpoint,
        journal: {
          read: 0,
          attempted: 0,
          applied: 0,
          malformed: true,
          preserved: true,
        },
      });
      expect(degraded.getNode('tail-after-invalid-utf8')).toBeNull();
      expect(readFileSync(statePath)).toEqual(stateBefore);
      expect(readFileSync(journalPath())).toEqual(walBefore);
      expect(quarantineFiles()).toHaveLength(1);
      expect(readFileSync(join(tempDir, quarantineFiles()[0]))).toEqual(walBefore);
      closeEngine(degraded);
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

    mkdirSync(`${statePath}.tmp`);
    (engine as any).ctx.lastSnapshotTime = Date.now();
    engine.addNode(host('persisted-after-retry'));
    engine.persist();

    await vi.advanceTimersByTimeAsync(FLUSH_DEBOUNCE_MS + 1);
    expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
      writable: true,
      consecutive_persistence_failures: 1,
    });

    rmSync(`${statePath}.tmp`, { recursive: true, force: true });
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
    const publishedRecovery: ReturnType<GraphEngine['getPersistenceRecoveryStatus']>[] = [];
    engine.onUpdate(() => publishedRecovery.push(engine.getPersistenceRecoveryStatus()));

    mkdirSync(`${statePath}.tmp`);
    (engine as any).ctx.lastSnapshotTime = Date.now();
    engine.addNode(host('before-persistence-degraded'));
    engine.persist();

    await vi.advanceTimersByTimeAsync(FLUSH_DEBOUNCE_MS + 1); // initial flush failure
    await vi.advanceTimersByTimeAsync(PERSIST_RETRY_DELAYS_MS[0] + 1); // retry failure 2
    await vi.advanceTimersByTimeAsync(PERSIST_RETRY_DELAYS_MS[1] + 1); // retry failure 3

    expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
      writable: false,
      consecutive_persistence_failures: 3,
    });
    expect(publishedRecovery.at(-1)).toMatchObject({
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
    rmSync(`${statePath}.tmp`, { recursive: true, force: true });
    await vi.advanceTimersByTimeAsync(PERSIST_RETRY_DELAYS_MS[2] + 1);
    expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      consecutive_persistence_failures: 0,
    });
    expect(publishedRecovery.at(-1)).toMatchObject({
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
