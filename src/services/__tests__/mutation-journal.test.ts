import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync, rmSync, readFileSync } from 'fs';
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
