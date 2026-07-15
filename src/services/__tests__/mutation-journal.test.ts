import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { existsSync, mkdtempSync, rmSync, readFileSync, appendFileSync, readdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal, writeAllSync, type MutationType } from '../mutation-journal.js';
import type { EngagementConfig } from '../../types.js';

const NONCE = 'b'.repeat(64);
let testDir: string;
let TEST_STATE: string;
let JOURNAL_PATH: string;

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

const engines = new Set<GraphEngine>();

function trackedEngine(...args: ConstructorParameters<typeof GraphEngine>): GraphEngine {
  const engine = new GraphEngine(...args);
  engines.add(engine);
  return engine;
}

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'overwatch-mutation-journal-'));
  TEST_STATE = join(testDir, 'state-test-mutation-journal.json');
  JOURNAL_PATH = join(testDir, 'state-test-mutation-journal.journal.jsonl');
});

afterEach(() => {
  for (const engine of engines) engine.dispose();
  engines.clear();
  rmSync(testDir, { recursive: true, force: true });
});

describe('MutationJournal (P2.1)', () => {
  describe('unit', () => {
    it('appends entries with monotonic seq', () => {
      const j = new MutationJournal(TEST_STATE);
      const a = j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      const b = j.append({ type: 'add_node', payload: { props: { id: 'b' } } });
      expect(a.seq).toBe(1);
      expect(b.seq).toBe(2);
      const raw = readFileSync(j.getPath(), 'utf-8');
      expect(raw.split('\n').filter(Boolean).length).toBe(2);
    });

    it('writeAllSync drains short writes and rejects a writer that makes no progress', () => {
      const writtenChunks: Buffer[] = [];
      let calls = 0;
      writeAllSync(123, 'abcdef', (_fd, buffer, offset, length) => {
        calls++;
        const count = Math.min(2, length);
        writtenChunks.push(Buffer.from(buffer.subarray(offset, offset + count)));
        return count;
      });

      expect(calls).toBe(3);
      expect(Buffer.concat(writtenChunks).toString('utf-8')).toBe('abcdef');
      expect(() => writeAllSync(123, 'x', () => 0)).toThrow('invalid progress');
      expect(() => writeAllSync(123, 'x', () => 2)).toThrow('invalid progress');
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

    it('rejects a syntactically complete final JSON frame without its newline commit marker', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      const framed = readFileSync(j.getPath());
      writeFileSync(j.getPath(), framed.subarray(0, framed.length - 1));

      expect(j.readSince(0)).toEqual([]);
      expect(j.getLastReadIssue()).toMatchObject({
        kind: 'malformed_entry',
        unterminated_eof_fragment: true,
        reason: expect.stringContaining('missing newline commit marker'),
      });
      expect(j.highestSeqOnDisk()).toBe(1);
    });

    it('compactUpTo drops entries with seq <= upTo and keeps newer ones', () => {
      const j = new MutationJournal(TEST_STATE);
      for (let i = 0; i < 5; i++) j.append({ type: 'add_node', payload: { props: { id: `n${i}` } } });
      const result = j.compactUpTo(3);
      expect(result).toEqual({ kept: 2, dropped: 3 });
      // Compaction deliberately leaves the physical sequence numbers intact;
      // the snapshot checkpoint supplies the compacted-through prefix.
      const remaining = j.readSince(3);
      expect(remaining.map(e => e.seq)).toEqual([4, 5]);
    });

    it('compactUpTo preserves every byte when malformed data interrupts the journal', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      j.append({ type: 'add_node', payload: { props: { id: 'b' } } });
      appendFileSync(j.getPath(), 'MALFORMED \u2603 JOURNAL LINE\n');
      appendFileSync(j.getPath(), JSON.stringify({
        seq: 999,
        ts: '2026-01-01T00:00:00Z',
        type: 'add_node',
        payload: { props: { id: 'durable-tail' } },
      }) + '\n');
      const before = readFileSync(j.getPath());

      const result = j.compactUpTo(2);

      expect(result).toMatchObject({ kept: 0, dropped: 0, preserved: true });
      expect(readFileSync(j.getPath())).toEqual(before);
      expect(existsSync(j.getPath() + '.compact')).toBe(false);
      expect(j.highestSeqOnDisk()).toBe(999);
    });

    it('compactUpTo preserves every byte when a sequence gap interrupts the journal', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      appendFileSync(j.getPath(), JSON.stringify({
        seq: 3,
        ts: '2026-01-01T00:00:00Z',
        type: 'add_node',
        payload: { props: { id: 'after-gap' } },
      }) + '\n');
      const before = readFileSync(j.getPath());

      const result = j.compactUpTo(1);

      expect(result).toMatchObject({
        kept: 0,
        dropped: 0,
        preserved: true,
        reason: expect.stringContaining('sequence discontinuity'),
      });
      expect(readFileSync(j.getPath())).toEqual(before);
      expect(existsSync(j.getPath() + '.compact')).toBe(false);
    });

    it('compactUpTo preserves every byte when the record type is unsupported', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'future_mutation' as MutationType, payload: {} });
      const before = readFileSync(j.getPath());

      const result = j.compactUpTo(1);

      expect(result).toMatchObject({
        kept: 0,
        dropped: 0,
        preserved: true,
        reason: expect.stringContaining('unsupported journal mutation type'),
      });
      expect(readFileSync(j.getPath())).toEqual(before);
    });

    it('replay and compaction share strict per-type payload validation', () => {
      const j = new MutationJournal(TEST_STATE);
      const malformed = Buffer.from(JSON.stringify({
        seq: 1,
        ts: '2026-01-01T00:00:00.000Z',
        type: 'cold_promote',
        payload: {},
      }) + '\n');
      writeFileSync(j.getPath(), malformed);

      expect(j.readSince(0)).toEqual([]);
      expect(j.getLastReadIssue()).toMatchObject({
        kind: 'malformed_entry',
        reason: expect.stringContaining('cold_promote payload.id'),
      });
      expect(j.compactUpTo(1)).toMatchObject({
        kept: 0,
        dropped: 0,
        preserved: true,
        reason: expect.stringContaining('cold_promote payload.id'),
      });
      expect(readFileSync(j.getPath())).toEqual(malformed);
    });

    it('refuses to append a malformed known payload before allocating a sequence', () => {
      const j = new MutationJournal(TEST_STATE);
      expect(() => j.append({ type: 'cold_promote', payload: {} })).toThrow(
        'Refusing to append malformed WAL record',
      );
      expect(j.peekSeq()).toBe(0);
      expect(existsSync(j.getPath())).toBe(false);
    });

    it('truncate removes the file entirely', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      expect(existsSync(j.getPath())).toBe(true);
      j.truncate();
      expect(existsSync(j.getPath())).toBe(false);
    });

    it('readSince returns the complete prefix but flags an unterminated EOF fragment', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      // Manually append a partial line as if a crash truncated the second write.
      appendFileSync(j.getPath(), '{"seq":2,"ts":"par'); // unterminated JSON
      const entries = j.readSince(0);
      // Only the well-formed first entry is returned.
      expect(entries).toHaveLength(1);
      expect(entries[0].seq).toBe(1);
      expect(j.getLastReadIssue()).toMatchObject({
        kind: 'malformed_entry',
        unterminated_eof_fragment: true,
      });
      expect(j.wasLastReadTruncated()).toBe(true);
    });

    it('replay applies the committed prefix before an unterminated WAL fragment', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'committed-prefix' } } });
      appendFileSync(j.getPath(), '{"seq":2,"ts":"partial');
      const attempted: number[] = [];

      const result = j.replay({
        apply(entry) {
          attempted.push(entry.seq);
          return { status: 'applied' };
        },
      }, 0);

      expect(attempted).toEqual([1]);
      expect(result).toMatchObject({
        read: 1,
        attempted: 1,
        applied: 1,
        complete: false,
        highest_contiguous_applied_seq: 1,
        read_issue: {
          kind: 'malformed_entry',
          unterminated_eof_fragment: true,
        },
      });
    });

    it('replay keeps the committed prefix visible before a duplicate sequence frame', () => {
      const j = new MutationJournal(TEST_STATE);
      const committed = j.append({
        type: 'add_node',
        payload: { props: { id: 'committed-before-duplicate' } },
      });
      appendFileSync(j.getPath(), `${JSON.stringify(committed)}\n`);
      const attempted: number[] = [];

      const result = j.replay({
        apply(entry) {
          attempted.push(entry.seq);
          return { status: 'applied' };
        },
      }, 0);

      expect(attempted).toEqual([1]);
      expect(result).toMatchObject({
        read: 1,
        attempted: 1,
        applied: 1,
        complete: false,
        highest_contiguous_applied_seq: 1,
        read_issue: {
          kind: 'sequence_gap',
          expected_seq: 2,
          actual_seq: 1,
          offending_record_included: false,
        },
      });
    });

    it('replay stops at the first skipped entry without attempting the tail', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      j.append({
        type: 'add_edge',
        payload: { source: 'missing', target: 'also-missing', props: { type: 'RUNS' } },
      });
      j.append({ type: 'drop_edge', payload: { edge_id: 'boom' } });
      const attempted: number[] = [];

      const result = j.replay({
        apply(entry) {
          attempted.push(entry.seq);
          if (entry.seq === 1) return { status: 'applied' };
          if (entry.seq === 2) return { status: 'skipped', reason: 'missing endpoint(s)' };
          throw new Error('tail must not be attempted');
        },
      }, 0);

      expect(attempted).toEqual([1, 2]);
      expect(result).toMatchObject({
        read: 3,
        attempted: 2,
        applied: 1,
        skipped: 1,
        failed: 0,
        complete: false,
        stopped_at_seq: 2,
        highest_on_disk_seq: 3,
        highest_contiguous_applied_seq: 1,
      });
      expect(result.skipped_reasons[0]).toMatchObject({ seq: 2, type: 'add_edge', reason: 'missing endpoint(s)' });
      expect(result.failed_reasons).toEqual([]);
    });

    it('replay stops at the first thrown failure without attempting the tail', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      j.append({
        type: 'add_edge',
        payload: { source: 'broken', target: 'edge', props: { type: 'RUNS' } },
      });
      j.append({ type: 'drop_edge', payload: { edge_id: 'must-not-run' } });
      const attempted: number[] = [];

      const result = j.replay({
        apply(entry) {
          attempted.push(entry.seq);
          if (entry.seq === 1) return { status: 'applied' };
          if (entry.seq === 2) throw new Error('synthetic replay failure');
          return { status: 'applied' };
        },
      }, 0);

      expect(attempted).toEqual([1, 2]);
      expect(result).toMatchObject({
        read: 3,
        attempted: 2,
        applied: 1,
        skipped: 0,
        failed: 1,
        complete: false,
        stopped_at_seq: 2,
        highest_on_disk_seq: 3,
        highest_contiguous_applied_seq: 1,
      });
      expect(result.skipped_reasons).toEqual([]);
      expect(result.failed_reasons[0]).toMatchObject({
        seq: 2,
        type: 'add_edge',
        reason: 'synthetic replay failure',
      });
    });

    it('keeps physical, allocated, and contiguously-applied checkpoints separate', () => {
      const writer = new MutationJournal(TEST_STATE);
      writer.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      writer.append({ type: 'add_node', payload: { props: { id: 'b' } } });
      writer.append({ type: 'add_node', payload: { props: { id: 'c' } } });

      const recovered = new MutationJournal(TEST_STATE);
      expect(recovered.highestSeqOnDisk()).toBe(3); // physical
      expect(recovered.peekSeq()).toBe(0);          // allocated in this process
      expect(recovered.getAppliedThroughSeq()).toBe(0);

      const result = recovered.replay({
        apply(entry) {
          return entry.seq === 2
            ? { status: 'skipped', reason: 'synthetic dependency gap' }
            : { status: 'applied' };
        },
      }, 0);

      expect(result.highest_on_disk_seq).toBe(3);
      expect(result.highest_contiguous_applied_seq).toBe(1);
      expect(recovered.peekSeq()).toBe(3);          // allocated above all physical records
      expect(recovered.getAppliedThroughSeq()).toBe(1);
      expect(() => recovered.markApplied(3)).toThrow('expected seq 2, got 3');
    });

    it('degrades legacy checkpoints that retain physical records at or below the claim', () => {
      const writer = new MutationJournal(TEST_STATE);
      writer.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      writer.append({ type: 'add_node', payload: { props: { id: 'b' } } });

      const recovered = new MutationJournal(TEST_STATE);
      recovered.setNextSeq(2, { appliedThroughSeq: 0 });
      const legacyAttempted: number[] = [];
      const legacyResult = recovered.replay({
        apply(entry) {
          legacyAttempted.push(entry.seq);
          return { status: 'applied' };
        },
      }, 2, { trustedContiguousCheckpoint: false });
      expect(legacyAttempted).toEqual([]);
      expect(legacyResult).toMatchObject({
        read: 0,
        attempted: 0,
        complete: false,
        highest_contiguous_applied_seq: 0,
        read_issue: {
          kind: 'ambiguous_checkpoint',
          actual_seq: 1,
        },
      });

      const trustedAttempted: number[] = [];
      recovered.setNextSeq(2, { appliedThroughSeq: 2 });
      const trustedResult = recovered.replay({
        apply(entry) {
          trustedAttempted.push(entry.seq);
          return { status: 'applied' };
        },
      }, 2, { trustedContiguousCheckpoint: true });
      expect(trustedAttempted).toEqual([]);
      expect(trustedResult).toMatchObject({
        read: 0,
        attempted: 0,
        applied: 0,
        complete: true,
        highest_contiguous_applied_seq: 2,
      });

    });

    it('reports legacy checkpoint ambiguity before a later unknown WAL record', () => {
      const writer = new MutationJournal(TEST_STATE);
      writer.append({ type: 'add_node', payload: { props: { id: 'possibly-hidden' } } });
      writer.append({ type: 'future_mutation' as MutationType, payload: {} });

      const recovered = new MutationJournal(TEST_STATE);
      recovered.setNextSeq(2, { appliedThroughSeq: 0 });
      const attempted: number[] = [];
      const result = recovered.replay({
        apply(entry) {
          attempted.push(entry.seq);
          return { status: 'applied' };
        },
      }, 2, { trustedContiguousCheckpoint: false });

      expect(attempted).toEqual([]);
      expect(result).toMatchObject({
        attempted: 0,
        applied: 0,
        highest_contiguous_applied_seq: 0,
        read_issue: {
          kind: 'ambiguous_checkpoint',
          actual_seq: 1,
        },
      });
    });

    it('does not promote an untrusted legacy checkpoint when the first frame is malformed', () => {
      writeFileSync(JOURNAL_PATH, '{malformed legacy WAL frame\n');
      const recovered = new MutationJournal(TEST_STATE);
      recovered.setNextSeq(2, { appliedThroughSeq: 0 });

      const result = recovered.replay({
        apply() {
          throw new Error('a malformed first frame cannot be applied');
        },
      }, 2, { trustedContiguousCheckpoint: false });

      expect(result).toMatchObject({
        read: 0,
        attempted: 0,
        applied: 0,
        complete: false,
        highest_contiguous_applied_seq: 0,
        read_issue: { kind: 'malformed_entry' },
      });
    });

    it('does not promote an untrusted legacy checkpoint across a first-newer sequence gap', () => {
      writeFileSync(JOURNAL_PATH, `${JSON.stringify({
        seq: 4,
        ts: '2026-01-01T00:00:00.000Z',
        type: 'add_node',
        payload: { props: { id: 'stranded-after-gap' } },
      })}\n`);
      const recovered = new MutationJournal(TEST_STATE);
      recovered.setNextSeq(2, { appliedThroughSeq: 0 });
      const attempted: number[] = [];

      const result = recovered.replay({
        apply(entry) {
          attempted.push(entry.seq);
          return { status: 'applied' };
        },
      }, 2, { trustedContiguousCheckpoint: false });

      expect(attempted).toEqual([]);
      expect(result).toMatchObject({
        read: 1,
        attempted: 0,
        applied: 0,
        complete: false,
        highest_contiguous_applied_seq: 0,
        read_issue: {
          kind: 'sequence_gap',
          expected_seq: 3,
          actual_seq: 4,
          offending_record_included: true,
        },
      });
    });

    it('quarantines by content address and is idempotent for identical bytes', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({ type: 'add_node', payload: { props: { id: 'a' } } });
      appendFileSync(j.getPath(), 'MALFORMED \u2603 TAIL\n');
      const original = readFileSync(j.getPath());

      const first = j.quarantine();
      const second = j.quarantine();

      expect(first).toBeDefined();
      expect(second).toBe(first);
      expect(readFileSync(first!)).toEqual(original);
      expect(readFileSync(j.getPath())).toEqual(original);
      expect(readdirSync(testDir).filter(f => f.startsWith('state-test-mutation-journal.journal.jsonl.quarantine-'))).toHaveLength(1);

      appendFileSync(j.getPath(), 'different bytes\n');
      const changed = readFileSync(j.getPath());
      const third = j.quarantine();

      expect(third).toBeDefined();
      expect(third).not.toBe(first);
      expect(readFileSync(first!)).toEqual(original);
      expect(readFileSync(third!)).toEqual(changed);
      expect(readdirSync(testDir).filter(f => f.startsWith('state-test-mutation-journal.journal.jsonl.quarantine-'))).toHaveLength(2);
    });
  });

  describe('integrated with engine', () => {
    it('does NOT journal when engagement_nonce is absent (legacy path)', () => {
      const eng = trackedEngine(makeConfig(), TEST_STATE); // no nonce
      eng.addNode({ id: 'x', type: 'host', label: 'x', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      expect(existsSync(JOURNAL_PATH)).toBe(false);
    });

    it('journals add_node and add_edge for engagements with engagement_nonce', () => {
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
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
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'baseline', type: 'host', label: 'baseline', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.persist();
      eng.flushNow(); // snapshot durable; journal entries up through 'baseline' get compacted on snapshot rotation
      // Add a post-snapshot mutation that lands in the journal but not in the snapshot.
      // We bypass the snapshot path so this simulates "engine crashed before next persist."
      eng.addNode({ id: 'post', type: 'host', label: 'post', ip: '10.10.10.2', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      // Don't flush. Pretend we crash here.
      eng.dispose();

      // Phase 2: a fresh engine reads the snapshot + replays the journal.
      const eng2 = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      // The 'post' node should be present after WAL replay.
      expect(eng2.getNode('post')).toBeDefined();
      expect(eng2.getNode('baseline')).toBeDefined();
      eng2.dispose();

      // Recovery checkpointing is stable across another restart.
      const eng3 = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      expect(eng3.getNode('post')).toBeDefined();
      expect(eng3.getNode('baseline')).toBeDefined();
      expect(eng3.getPersistenceRecoveryStatus()).toMatchObject({ complete: true, writable: true });
      eng3.dispose();
    });

    it('survives a crash: a journaled cold_add is replayed (cold_node_count preserved)', () => {
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.persist();
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
      eng.dispose();
      const eng2 = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      expect((eng2 as any).ctx.coldStore.has('host-cold')).toBe(true);
      expect((eng2 as any).ctx.coldStore.count()).toBe(1);
      eng2.dispose();
    });

    it('replays cold_promote so a promoted node is not resurrected in the cold store', () => {
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      (eng as any).ctx.coldAdd({
        id: 'host-p', type: 'host', label: '10.10.10.8', ip: '10.10.10.8',
        discovered_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:00Z',
        subnet_cidr: '10.10.10.0/24', alive: true,
      });
      eng.persist();  // mark dirty so flushNow actually writes...
      eng.flushNow(); // ...a snapshot that CONTAINS the cold node (compacts the journal).
      (eng as any).ctx.coldPromote('host-p'); // journaled removal, NOT yet snapshotted
      eng.dispose();
      const eng2 = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      // Snapshot had it; the replayed cold_promote must remove it again.
      expect((eng2 as any).ctx.coldStore.has('host-p')).toBe(false);
      eng2.dispose();
    });

    it('preserves the journal when replay stops on an incomplete mutation', () => {
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'baseline', type: 'host', label: 'baseline', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.persist();
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
      const journalBeforeRecovery = readFileSync(JOURNAL_PATH);
      const checkpoint = typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0;

      // Repeated startup remains deterministically degraded: no checkpoint is
      // advanced and the active WAL remains byte-for-byte available for repair.
      for (let restart = 1; restart <= 3; restart++) {
        const recovered = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
        const status = recovered.getPersistenceRecoveryStatus();
        expect(status).toMatchObject({
          outcome: 'incomplete',
          source: 'state',
          complete: false,
          writable: false,
          base_checkpoint: checkpoint,
          highest_contiguous_applied_seq: checkpoint,
          journal: { read: 3, attempted: 1, applied: 0, skipped: 1, failed: 0, preserved: true },
        });
        const recoveryEvent = recovered.getFullHistory().find(e => e.description.startsWith('WAL recovery incomplete'));
        expect(recoveryEvent?.details).toMatchObject({
          checkpoint,
          replay: { attempted: 1, skipped: 1, failed: 0, stopped_at_seq: checkpoint + 1 },
        });
        expect(String(JSON.stringify(recoveryEvent?.details))).toContain('missing endpoint');
        expect(readFileSync(JOURNAL_PATH)).toEqual(journalBeforeRecovery);
        recovered.dispose();
      }
    });

    it('ROOT FIX: WAL replay applies the type-integrity guard (no type flip)', () => {
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'n1', type: 'group', label: 'g', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.persist();
      eng.flushNow();
      eng.dispose();
      // A post-snapshot merge that tries to FLIP the type — as a drifted/raw
      // writer (or a pre-fix journal) would record.
      const state = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      const j = new MutationJournal(TEST_STATE);
      j.setNextSeq(typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0);
      j.append({ type: 'merge_node_attrs', payload: { props: { id: 'n1', type: 'cloud_identity', label: 'g2' } } });

      const eng2 = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      // Guard held on replay: the type was NOT flipped, but the non-type merge applied.
      expect(eng2.getNode('n1')?.type).toBe('group');
      expect(eng2.getNode('n1')?.label).toBe('g2');
      eng2.dispose();
    });

    it('ROOT FIX: WAL replay keeps scope-aware RBAC edges distinct (scoped keying)', () => {
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'p', type: 'cloud_identity', label: 'p', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.addNode({ id: 'r', type: 'cloud_resource', label: 'r', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.persist();
      eng.flushNow();
      eng.dispose();
      const state = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      const j = new MutationJournal(TEST_STATE);
      j.setNextSeq(typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0);
      // Two HAS_POLICY edges at DIFFERENT scopes — must not collapse into one.
      for (const scope of ['/subscriptions/A', '/subscriptions/B']) {
        j.append({ type: 'add_edge', payload: { source: 'p', target: 'r', props: { type: 'HAS_POLICY', confidence: 1, discovered_at: '2026-01-01T00:00:00Z', scope } } });
      }

      const eng2 = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      const hasPolicy = eng2.exportGraph().edges.filter(e => e.source === 'p' && e.target === 'r' && e.properties.type === 'HAS_POLICY');
      expect(hasPolicy).toHaveLength(2); // distinct per scope — the raw applier collapsed them to 1
      eng2.dispose();
    });

    it('ROOT FIX: WAL replay flags a dropped durable tail (truncation) + preserves the journal', () => {
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'baseline', type: 'host', label: 'baseline', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.persist();
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
      const journalBeforeRecovery = readFileSync(JOURNAL_PATH);

      const eng2 = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      const status = eng2.getPersistenceRecoveryStatus();
      expect(status).toMatchObject({
        outcome: 'incomplete', complete: false, writable: false,
        journal: { read: 1, attempted: 1, applied: 1, malformed: true, preserved: true },
      });
      const recoveryEvent = eng2.getFullHistory().find(e => e.description.startsWith('WAL recovery incomplete'));
      expect((recoveryEvent?.details as any)?.replay?.truncated).toBe(true);
      expect(eng2.getNode('kept')).toBeTruthy();      // committed prefix remains visible read-only
      expect(eng2.getNode('lost')).toBeFalsy();       // post-malformed durable tail dropped
      expect(readFileSync(JOURNAL_PATH)).toEqual(journalBeforeRecovery);
      eng2.dispose();
    });

    it('ROOT FIX: patch_node unset survives crash recovery (replace, not merge)', () => {
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'n1', type: 'host', label: 'n1', ip: '10.10.10.1', credential_status: 'active', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 } as any);
      eng.persist();
      eng.flushNow();
      eng.dispose();
      // A post-snapshot patch that UNSET credential_status journals a full-node
      // replace WITHOUT that key (as patchNodeProperties now does).
      const state = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      const j = new MutationJournal(TEST_STATE);
      j.setNextSeq(typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0);
      j.append({ type: 'replace_node_attrs', payload: { props: { id: 'n1', type: 'host', label: 'n1', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 } } });

      const eng2 = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      // The cleared key must NOT linger after recovery (merge-replay left it stale pre-fix).
      expect((eng2.getNode('n1') as any)?.credential_status).toBeFalsy();
      eng2.dispose();
    });

    it('ROOT FIX: truncated replay rejects fresh appends and preserves the WAL across restarts', () => {
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'baseline', type: 'host', label: 'baseline', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.persist();
      eng.flushNow();
      eng.dispose();
      const state = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      const j = new MutationJournal(TEST_STATE);
      j.setNextSeq(typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0);
      j.append({ type: 'add_node', payload: { props: { id: 'kept', type: 'host', label: 'kept', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 } } });
      appendFileSync(JOURNAL_PATH, 'CORRUPT NOT JSON\n');
      appendFileSync(JOURNAL_PATH, JSON.stringify({ seq: 99999, type: 'add_node', payload: { props: { id: 'orphan' } } }) + '\n');
      const journalBeforeRecovery = readFileSync(JOURNAL_PATH);
      const checkpoint = typeof state.journalSnapshotSeq === 'number' ? state.journalSnapshotSeq : 0;

      for (let restart = 1; restart <= 2; restart++) {
        const recovered = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
        expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({
          outcome: 'incomplete',
          complete: false,
          writable: false,
          base_checkpoint: checkpoint,
          highest_allocated_seq: 99999,
          highest_on_disk_seq: 99999,
          highest_contiguous_applied_seq: checkpoint + 1,
          journal: { attempted: 1, applied: 1, malformed: true, preserved: true },
        });
        expect(() => recovered.addNode({
          id: 'fresh', type: 'host', label: 'fresh',
          discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
        })).toThrow(/Durable mutations are disabled while persistence is degraded/);
        expect(recovered.getNode('fresh')).toBeFalsy();
        expect(recovered.getNode('kept')).toBeTruthy();
        expect(readFileSync(JOURNAL_PATH)).toEqual(journalBeforeRecovery);
        recovered.dispose();
      }
    });

    it('suppressMutationEvents does not leak past replay (type-conflict warning still fires after recovery)', () => {
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'g1', type: 'group', label: 'g1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.persist();
      eng.flushNow();
      eng.dispose();
      const eng2 = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE); // load → replay path toggles the flag
      const before = eng2.getFullHistory().filter(e => e.event_type === 'instrumentation_warning').length;
      eng2.addNode({ id: 'g1', type: 'cloud_identity', label: 'g1b', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 }); // type conflict → warning
      const after = eng2.getFullHistory().filter(e => e.event_type === 'instrumentation_warning').length;
      expect(after).toBeGreaterThan(before); // flag was restored after loadState — event NOT suppressed
      eng2.dispose();
    });

    it('legacy engagement keeps the empty manifest assertion (no journal field)', () => {
      // Sanity: snapshot persisted for a legacy engagement still works,
      // and the journal field is the no-op default (peekSeq() === 0
      // when journal is null).
      const eng = trackedEngine(makeConfig(), TEST_STATE); // no nonce
      eng.addNode({ id: 'x', type: 'host', label: 'x', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.persist();
      eng.flushNow();
      const snap = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      // journalSnapshotSeq defaults to 0 because mutationJournal is null.
      expect(snap.journalSnapshotSeq).toBe(0);
      eng.dispose();
    });
  });
});
