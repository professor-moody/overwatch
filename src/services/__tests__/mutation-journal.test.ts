import { describe, it, expect, afterEach } from 'vitest';
import { existsSync, unlinkSync, rmSync, readFileSync, appendFileSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal } from '../mutation-journal.js';
import type { EngagementConfig } from '../../types.js';

const NONCE = 'b'.repeat(64);
const TEST_STATE = './state-test-mutation-journal.json';
const JOURNAL_PATH = './state-test-mutation-journal.journal.jsonl';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'wal-test',
    name: 'wal test',
    created_at: '2026-01-01T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  };
}

function cleanup(): void {
  for (const f of [TEST_STATE, JOURNAL_PATH]) {
    try { if (existsSync(f)) unlinkSync(f); } catch {}
  }
  try { rmSync('./.snapshots', { recursive: true, force: true }); } catch {}
}

describe('MutationJournal (P2.1)', () => {
  describe('unit', () => {
    afterEach(() => cleanup());

    it('appends entries with monotonic seq', () => {
      const j = new MutationJournal(TEST_STATE);
      const a = j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      const b = j.append({ type: 'add_node', payload: { props: { id: 'b' } } });
      expect(a.seq).toBe(1);
      expect(b.seq).toBe(2);
      const raw = readFileSync(j.getPath(), 'utf-8');
      expect(raw.split('\n').filter(Boolean).length).toBe(2);
    });

    it('readSince returns entries strictly greater than fromSeq', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      j.append({ type: 'add_node', payload: { props: { id: 'b' } } });
      j.append({ type: 'add_node', payload: { props: { id: 'c' } } });
      expect(j.readSince(0).map(e => e.seq)).toEqual([1, 2, 3]);
      expect(j.readSince(1).map(e => e.seq)).toEqual([2, 3]);
      expect(j.readSince(3)).toEqual([]);
    });

    it('compactUpTo drops entries with seq <= upTo and keeps newer ones', () => {
      const j = new MutationJournal(TEST_STATE);
      for (let i = 0; i < 5; i++) j.append({ type: 'add_node', payload: { props: { id: `n${i}` } } });
      const result = j.compactUpTo(3);
      expect(result).toEqual({ kept: 2, dropped: 3 });
      const remaining = j.readSince(0);
      expect(remaining.map(e => e.seq)).toEqual([4, 5]);
    });

    it('truncate removes the file entirely', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      expect(existsSync(j.getPath())).toBe(true);
      j.truncate();
      expect(existsSync(j.getPath())).toBe(false);
    });

    it('readSince tolerates a malformed trailing line (simulated mid-write crash)', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      // Manually append a partial line as if a crash truncated the second write.
      const fs = require('fs');
      fs.appendFileSync(j.getPath(), '{"seq":2,"ts":"par'); // unterminated JSON
      const entries = j.readSince(0);
      // Only the well-formed first entry is returned.
      expect(entries).toHaveLength(1);
      expect(entries[0].seq).toBe(1);
    });

    it('replay reports applied, skipped, and failed entries separately', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      j.append({ type: 'add_edge', payload: { source: 'missing', target: 'also-missing' } });
      j.append({ type: 'drop_edge', payload: { edge_id: 'boom' } });

      const result = j.replay({
        apply(entry) {
          if (entry.seq === 1) return { status: 'applied' };
          if (entry.seq === 2) return { status: 'skipped', reason: 'missing endpoint(s)' };
          throw new Error('synthetic replay failure');
        },
      }, 0);

      expect(result).toMatchObject({ read: 3, applied: 1, skipped: 1, failed: 1 });
      expect(result.skipped_reasons[0]).toMatchObject({ seq: 2, type: 'add_edge', reason: 'missing endpoint(s)' });
      expect(result.failed_reasons[0]).toMatchObject({ seq: 3, type: 'drop_edge', reason: 'synthetic replay failure' });
    });
  });

  describe('integrated with engine', () => {
    afterEach(() => cleanup());

    it('does NOT journal when engagement_nonce is absent (legacy path)', () => {
      const eng = new GraphEngine(makeConfig(), TEST_STATE); // no nonce
      eng.addNode({ id: 'x', type: 'host', label: 'x', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      expect(existsSync(JOURNAL_PATH)).toBe(false);
    });

    it('journals add_node and add_edge for engagements with engagement_nonce', () => {
      const eng = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'h1', type: 'host', label: 'h1', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.addNode({ id: 's1', type: 'service', label: 'smb/445', port: 445, discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.addEdge('h1', 's1', { type: 'RUNS', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      expect(existsSync(JOURNAL_PATH)).toBe(true);
      const lines = readFileSync(JOURNAL_PATH, 'utf-8').split('\n').filter(Boolean);
      const types = lines.map(l => JSON.parse(l).type).sort();
      // Two add_node + one add_edge (subnet inference may add more, so just
      // confirm the three we explicitly issued are in the journal).
      expect(types).toContain('add_node');
      expect(types).toContain('add_edge');
    });

    it('survives a simulated crash: post-crash load replays unsnapshot mutations', () => {
      // Phase 1: write a snapshot + add post-snapshot mutations to journal.
      const eng = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'baseline', type: 'host', label: 'baseline', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.flushNow(); // snapshot durable; journal entries up through 'baseline' get compacted on snapshot rotation
      // Add a post-snapshot mutation that lands in the journal but not in the snapshot.
      // We bypass the snapshot path so this simulates "engine crashed before next persist."
      eng.addNode({ id: 'post', type: 'host', label: 'post', ip: '10.10.10.2', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      // Don't flush. Pretend we crash here.

      // Phase 2: a fresh engine reads the snapshot + replays the journal.
      const eng2 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      // The 'post' node should be present after WAL replay.
      expect(eng2.getNode('post')).toBeDefined();
      expect(eng2.getNode('baseline')).toBeDefined();
    });

    it('survives a crash: a journaled cold_add is replayed (cold_node_count preserved)', () => {
      const eng = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.flushNow(); // baseline snapshot: empty cold store
      // A cold add lands in the journal but NOT the (debounced, un-flushed) snapshot —
      // the exact window that previously lost cold nodes across a crash.
      (eng as any).ctx.coldAdd({
        id: 'host-cold', type: 'host', label: '10.10.10.9', ip: '10.10.10.9',
        discovered_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:00Z',
        subnet_cidr: '10.10.10.0/24', alive: true,
      });
      expect((eng as any).ctx.coldStore.count()).toBe(1);
      // Don't flush → crash. A fresh engine replays the journal and recovers the node.
      const eng2 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      expect((eng2 as any).ctx.coldStore.has('host-cold')).toBe(true);
      expect((eng2 as any).ctx.coldStore.count()).toBe(1);
    });

    it('replays cold_promote so a promoted node is not resurrected in the cold store', () => {
      const eng = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      (eng as any).ctx.coldAdd({
        id: 'host-p', type: 'host', label: '10.10.10.8', ip: '10.10.10.8',
        discovered_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:00Z',
        subnet_cidr: '10.10.10.0/24', alive: true,
      });
      eng.persist();  // mark dirty so flushNow actually writes...
      eng.flushNow(); // ...a snapshot that CONTAINS the cold node (compacts the journal).
      (eng as any).ctx.coldPromote('host-p'); // journaled removal, NOT yet snapshotted
      const eng2 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      // Snapshot had it; the replayed cold_promote must remove it again.
      expect((eng2 as any).ctx.coldStore.has('host-p')).toBe(false);
    });

    it('preserves the journal when replay skips unsupported or incomplete mutations', () => {
      const eng = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'baseline', type: 'host', label: 'baseline', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.flushNow();
      eng.dispose();

      const state = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      const j = new MutationJournal(TEST_STATE);
      j.setNextSeq(typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0);
      j.append({
        type: 'add_edge',
        payload: {
          source: 'missing-host',
          target: 'missing-service',
          props: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' },
        },
      });
      j.append({
        type: 'merge_edge_attrs',
        payload: { edge_id: 'missing-edge', props: { session_live: false } },
      });
      j.append({ type: 'future_mutation' as any, payload: {} });

      const eng2 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      expect(existsSync(JOURNAL_PATH)).toBe(true);
      const replayEvent = eng2.getFullHistory().find(e => e.description.startsWith('WAL replay:'));
      expect(replayEvent?.details).toMatchObject({ skipped: 3, failed: 0 });
      expect((replayEvent?.details as any).read).toBeGreaterThanOrEqual(3);
      expect(String(JSON.stringify(replayEvent?.details))).toContain('unsupported mutation type');
    });

    it('ROOT FIX: WAL replay applies the type-integrity guard (no type flip)', () => {
      const eng = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'n1', type: 'group', label: 'g', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.flushNow();
      eng.dispose();
      // A post-snapshot merge that tries to FLIP the type — as a drifted/raw
      // writer (or a pre-fix journal) would record.
      const state = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      const j = new MutationJournal(TEST_STATE);
      j.setNextSeq(typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0);
      j.append({ type: 'merge_node_attrs', payload: { props: { id: 'n1', type: 'cloud_identity', label: 'g2' } } });

      const eng2 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      // Guard held on replay: the type was NOT flipped, but the non-type merge applied.
      expect(eng2.getNode('n1')?.type).toBe('group');
      expect(eng2.getNode('n1')?.label).toBe('g2');
    });

    it('ROOT FIX: WAL replay keeps scope-aware RBAC edges distinct (scoped keying)', () => {
      const eng = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'p', type: 'cloud_identity', label: 'p', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.addNode({ id: 'r', type: 'cloud_resource', label: 'r', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.flushNow();
      eng.dispose();
      const state = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      const j = new MutationJournal(TEST_STATE);
      j.setNextSeq(typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0);
      // Two HAS_POLICY edges at DIFFERENT scopes — must not collapse into one.
      for (const scope of ['/subscriptions/A', '/subscriptions/B']) {
        j.append({ type: 'add_edge', payload: { source: 'p', target: 'r', props: { type: 'HAS_POLICY', confidence: 1, discovered_at: '2026-01-01T00:00:00Z', scope } } });
      }

      const eng2 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      const hasPolicy = eng2.exportGraph().edges.filter(e => e.source === 'p' && e.target === 'r' && e.properties.type === 'HAS_POLICY');
      expect(hasPolicy).toHaveLength(2); // distinct per scope — the raw applier collapsed them to 1
    });

    it('ROOT FIX: WAL replay flags a dropped durable tail (truncation) + preserves the journal', () => {
      const eng = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'baseline', type: 'host', label: 'baseline', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.flushNow();
      eng.dispose();
      const state = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      const j = new MutationJournal(TEST_STATE);
      j.setNextSeq(typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0);
      j.append({ type: 'add_node', payload: { props: { id: 'kept', type: 'host', label: 'kept', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 } } });
      // A malformed line MID-journal, then a valid line after it (a durable tail
      // that readSince will drop — this must be surfaced, not silently swallowed).
      appendFileSync(JOURNAL_PATH, 'THIS IS NOT JSON\n');
      appendFileSync(JOURNAL_PATH, JSON.stringify({ seq: 99999, type: 'add_node', payload: { props: { id: 'lost', type: 'host', label: 'lost', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 } } }) + '\n');

      const eng2 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      const replayEvent = eng2.getFullHistory().find(e => e.description.startsWith('WAL replay:'));
      expect((replayEvent?.details as any).truncated).toBe(true);
      expect(eng2.getNode('kept')).toBeDefined();     // pre-malformed entry applied
      expect(eng2.getNode('lost')).toBeFalsy();       // post-malformed durable tail dropped
      expect(existsSync(JOURNAL_PATH)).toBe(true);    // journal preserved (evidence, not compacted)
    });

    it('ROOT FIX: patch_node unset survives crash recovery (replace, not merge)', () => {
      const eng = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'n1', type: 'host', label: 'n1', ip: '10.10.10.1', credential_status: 'active', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 } as any);
      eng.flushNow();
      eng.dispose();
      // A post-snapshot patch that UNSET credential_status journals a full-node
      // replace WITHOUT that key (as patchNodeProperties now does).
      const state = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      const j = new MutationJournal(TEST_STATE);
      j.setNextSeq(typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0);
      j.append({ type: 'replace_node_attrs', payload: { props: { id: 'n1', type: 'host', label: 'n1', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 } } });

      const eng2 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      // The cleared key must NOT linger after recovery (merge-replay left it stale pre-fix).
      expect((eng2.getNode('n1') as any)?.credential_status).toBeFalsy();
    });

    it('ROOT FIX: a fresh append after a truncated replay does not reuse an orphaned seq', () => {
      const eng = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'baseline', type: 'host', label: 'baseline', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.flushNow();
      eng.dispose();
      const state = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      const j = new MutationJournal(TEST_STATE);
      j.setNextSeq(typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0);
      j.append({ type: 'add_node', payload: { props: { id: 'kept', type: 'host', label: 'kept', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 } } });
      appendFileSync(JOURNAL_PATH, 'CORRUPT NOT JSON\n');
      appendFileSync(JOURNAL_PATH, JSON.stringify({ seq: 99999, type: 'add_node', payload: { props: { id: 'orphan' } } }) + '\n');

      const eng2 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng2.addNode({ id: 'fresh', type: 'host', label: 'fresh', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      // The fresh append must sit ABOVE the orphaned 99999 in the preserved file.
      expect(new MutationJournal(TEST_STATE).highestSeqOnDisk()).toBeGreaterThan(99999);
    });

    it('suppressMutationEvents does not leak past replay (type-conflict warning still fires after recovery)', () => {
      const eng = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'g1', type: 'group', label: 'g1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.flushNow();
      const eng2 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE); // load → replay path toggles the flag
      const before = eng2.getFullHistory().filter(e => e.event_type === 'instrumentation_warning').length;
      eng2.addNode({ id: 'g1', type: 'cloud_identity', label: 'g1b', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 }); // type conflict → warning
      const after = eng2.getFullHistory().filter(e => e.event_type === 'instrumentation_warning').length;
      expect(after).toBeGreaterThan(before); // flag was restored after loadState — event NOT suppressed
    });

    it('legacy engagement keeps the empty manifest assertion (no journal field)', () => {
      // Sanity: snapshot persisted for a legacy engagement still works,
      // and the journal field is the no-op default (peekSeq() === 0
      // when journal is null).
      const eng = new GraphEngine(makeConfig(), TEST_STATE); // no nonce
      eng.addNode({ id: 'x', type: 'host', label: 'x', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.flushNow();
      const snap = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      // journalSnapshotSeq defaults to 0 because mutationJournal is null.
      expect(snap.journalSnapshotSeq).toBe(0);
    });
  });
});
