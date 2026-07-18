import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { existsSync, mkdtempSync, rmSync, readFileSync, appendFileSync, readdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import {
  MutationJournal,
  validateTransactionOperationRelationships,
  writeAllSync,
  type MutationType,
} from '../mutation-journal.js';
import { EngineContext } from '../engine-context.js';
import { createOverwatchGraph } from '../graphology-types.js';
import {
  getStateWriterLockDepth,
  withStateMigrationWriteGuard,
} from '../state-migration-lock.js';
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

function appendV2Mutation(
  journal: MutationJournal,
  type: MutationType,
  payload: Record<string, unknown>,
) {
  const transaction = journal.appendTransaction({
    operations: [{ type, payload }],
  });
  journal.markApplied(transaction.seq);
  return transaction;
}

function activityAppendPayload(
  eventId: string,
  expectedLength: number,
  expectedTail: string | null,
): Record<string, unknown> {
  return {
    payload_version: 1,
    items: [{
      entry: {
        event_id: eventId,
        timestamp: '2026-01-01T00:00:00.000Z',
        description: eventId,
      },
    }],
    result_event_id: eventId,
    expected: {
      activity_length: expectedLength,
      activity_tail_event_id: expectedTail,
      last_chain_hash: '0'.repeat(64),
      chain_events_since_checkpoint: 0,
      checkpoint_count: 0,
      checkpoint_tail_event_id: null,
      deterministic_seq: 0,
    },
    final: {
      last_chain_hash: '0'.repeat(64),
      chain_events_since_checkpoint: 0,
      deterministic_seq: 0,
    },
  };
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
  it('rejects an externalized graph audit without its matching activity append', () => {
    expect(validateTransactionOperationRelationships([{
      type: 'graph_corrected',
      payload: {
        operation_id: 'graph-op-without-audit',
        audit_event_externalized: true,
      },
    }])).toEqual({
      ok: false,
      reason: expect.stringContaining('matching activity_append'),
    });

    expect(validateTransactionOperationRelationships([{
      type: 'graph_corrected',
      payload: {
        operation_id: 'graph-op-with-audit',
        audit_event_externalized: true,
      },
    }, {
      type: 'activity_append',
      payload: {
        items: [{
          entry: {
            event_type: 'graph_corrected',
            details: { operation_id: 'graph-op-with-audit' },
          },
        }],
      },
    }])).toEqual({ ok: true });
  });
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

    it('appends journal-v2 transactions as checksum-protected begin/chunk/commit frames', () => {
      const j = new MutationJournal(TEST_STATE);
      const tx = j.appendTransaction({
        operations: [{
          type: 'add_node',
          payload: { props: { id: 'v2-node', type: 'host', label: 'v2-node' } },
        }],
        source_action_id: 'action-v2',
        ts: '2026-01-01T00:00:00.000Z',
      });
      j.markApplied(tx.seq);

      expect(tx).toMatchObject({
        version: 2,
        seq: 1,
        begin_frame_seq: 1,
        commit_frame_seq: 3,
        source_action_id: 'action-v2',
      });
      const frames = readFileSync(j.getPath(), 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map(line => JSON.parse(line) as Record<string, unknown>);
      expect(frames.map(frame => frame.record_type)).toEqual([
        'tx_begin',
        'tx_chunk',
        'tx_commit',
      ]);
      expect(frames.map(frame => frame.frame_seq)).toEqual([1, 2, 3]);
      expect(frames.every(frame => frame.tx_seq === 1)).toBe(true);
      expect(j.getHighestPhysicalSeq()).toBe(1);
      expect(j.getHighestPhysicalFrameSeq()).toBe(3);
      expect(j.readTransactionsSince(0)).toEqual([tx]);
    });

    it('rejects malformed activity_append payloads before allocating WAL state', () => {
      const j = new MutationJournal(TEST_STATE);

      expect(() => j.appendTransaction({
        operations: [{
          type: 'activity_append',
          payload: {
            payload_version: 1,
            items: [],
          },
        }],
      })).toThrow(/activity_append payload\.items/);

      expect(existsSync(j.getPath())
        ? readFileSync(j.getPath(), 'utf-8')
        : '').toBe('');
      expect(j.peekSeq()).toBe(0);
      j.dispose();
    });

    it('transfers an idle retained writer within one process and keeps the old writer stale', () => {
      const first = new MutationJournal(TEST_STATE);
      const retained = first.appendTransaction({
        operations: [{
          type: 'activity_append',
          payload: activityAppendPayload('event-one', 0, null),
        }],
      });
      first.markApplied(retained.seq);

      const second = new MutationJournal(TEST_STATE);
      second.setNextSeq(retained.seq);
      const advanced = second.appendTransaction({
        operations: [{
          type: 'add_node',
          payload: { props: { id: 'writer-two', type: 'host', label: 'writer-two' } },
        }],
      });
      second.markApplied(advanced.seq);
      expect(advanced.seq).toBe(retained.seq + 1);

      expect(() => first.appendTransaction({
        operations: [{
          type: 'add_node',
          payload: { props: { id: 'stale-writer', type: 'host', label: 'stale-writer' } },
        }],
      })).toThrow(/writer is stale/);

      first.dispose();
      second.dispose();
    });

    it('refuses retained-writer transfer while the journal owner is applying', () => {
      const first = new MutationJournal(TEST_STATE);
      const retained = first.appendTransaction({
        operations: [{
          type: 'activity_append',
          payload: activityAppendPayload('event-busy', 0, null),
        }],
      });
      first.markApplied(retained.seq);
      const second = new MutationJournal(TEST_STATE);
      second.setNextSeq(retained.seq);

      (first as any).withMigrationWriteGuard(() => {
        expect(() => second.appendTransaction({
          operations: [{
            type: 'add_node',
            payload: { props: { id: 'must-wait', type: 'host', label: 'must-wait' } },
          }],
        })).toThrow(/state writer lock is already owned/);
      });

      const next = first.appendTransaction({
        operations: [{
          type: 'add_node',
          payload: { props: { id: 'owner-remains-live', type: 'host', label: 'owner-remains-live' } },
        }],
      });
      first.markApplied(next.seq);
      expect(next.seq).toBe(retained.seq + 1);
      first.dispose();
      second.dispose();
    });

    it('does not transfer a retained owner through a nested generic state guard', () => {
      const first = new MutationJournal(TEST_STATE);
      const retained = first.appendTransaction({
        operations: [{
          type: 'activity_append',
          payload: activityAppendPayload('event-generic-guard', 0, null),
        }],
      });
      first.markApplied(retained.seq);
      const second = new MutationJournal(TEST_STATE);
      second.setNextSeq(retained.seq);

      withStateMigrationWriteGuard(TEST_STATE, undefined, () => {
        expect(getStateWriterLockDepth(TEST_STATE)).toBe(2);
        expect(() => second.appendTransaction({
          operations: [{
            type: 'add_node',
            payload: { props: { id: 'must-not-reenter', type: 'host', label: 'must-not-reenter' } },
          }],
        })).toThrow(/state writer lock is already owned/);
        expect(getStateWriterLockDepth(TEST_STATE)).toBe(2);
      });

      expect(getStateWriterLockDepth(TEST_STATE)).toBe(1);
      first.dispose();
      expect(getStateWriterLockDepth(TEST_STATE)).toBe(0);
      second.dispose();
    });

    it('chunks large transactions into bounded ordered physical frames', () => {
      const j = new MutationJournal(TEST_STATE);
      const tx = j.appendTransaction({
        operations: [{
          type: 'add_node',
          payload: {
            props: {
              id: 'large-v2-node',
              type: 'host',
              label: 'x'.repeat(150_000),
            },
          },
        }],
        ts: '2026-01-01T00:00:00.000Z',
      });
      j.markApplied(tx.seq);

      const frames = readFileSync(j.getPath(), 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map(line => JSON.parse(line) as Record<string, any>);
      const begin = frames[0];
      const chunks = frames.filter(frame => frame.record_type === 'tx_chunk');
      expect(begin.chunk_count).toBeGreaterThan(1);
      expect(chunks.map(frame => frame.chunk_index)).toEqual(
        Array.from({ length: begin.chunk_count }, (_, index) => index),
      );
      expect(chunks.every(frame => Buffer.from(frame.data, 'base64').length <= 64 * 1024)).toBe(true);
      expect(tx.commit_frame_seq).toBe(tx.begin_frame_seq + begin.chunk_count + 1);
      expect(j.readTransactionsSince(0)[0]?.operations[0]?.payload).toEqual(
        tx.operations[0]?.payload,
      );
    });

    it('refuses to append when the WAL has lost the first transaction after the durable base', () => {
      writeFileSync(TEST_STATE, JSON.stringify({ journalSnapshotSeq: 1 }));
      writeFileSync(JOURNAL_PATH, `${JSON.stringify({
        seq: 3,
        ts: '2026-01-01T00:00:02.000Z',
        type: 'add_node',
        payload: { props: { id: 'stranded-after-gap', type: 'host', label: 'stranded-after-gap' } },
      })}\n`);
      const original = readFileSync(JOURNAL_PATH);
      const recovered = new MutationJournal(TEST_STATE);
      // Model a live process that already applied seq 2 and 3 before seq 2 was
      // externally removed from the active WAL.
      recovered.setNextSeq(3, {
        appliedThroughSeq: 3,
        physicalFrameSeq: 3,
      });

      expect(() => recovered.appendTransaction({
        operations: [{
          type: 'add_node',
          payload: { props: { id: 'must-not-append', type: 'host', label: 'must-not-append' } },
        }],
        ts: '2026-01-01T00:00:03.000Z',
      })).toThrow(/expected transaction seq 2, found 3/);
      expect(readFileSync(JOURNAL_PATH)).toEqual(original);
      expect(recovered.getAppendBlockedReason()).toContain(
        'journal integrity check failed before append',
      );
    });

    it('rejects a checksum-corrupted committed v2 transaction without applying it', () => {
      const j = new MutationJournal(TEST_STATE);
      j.appendTransaction({
        operations: [{
          type: 'add_node',
          payload: { props: { id: 'checksum-node', type: 'host', label: 'checksum-node' } },
        }],
        ts: '2026-01-01T00:00:00.000Z',
      });
      const frames = readFileSync(j.getPath(), 'utf-8').split('\n').filter(Boolean);
      const commit = JSON.parse(frames.at(-1)!) as Record<string, unknown>;
      commit.commit_checksum = '0'.repeat(64);
      frames[frames.length - 1] = JSON.stringify(commit);
      writeFileSync(j.getPath(), `${frames.join('\n')}\n`);
      const attempted: number[] = [];

      const result = new MutationJournal(TEST_STATE).replayTransactions({
        applyTransaction(transaction) {
          attempted.push(transaction.seq);
          return { status: 'applied' };
        },
      }, 0);

      expect(attempted).toEqual([]);
      expect(result).toMatchObject({
        read: 0,
        attempted: 0,
        applied: 0,
        complete: false,
        read_issue: {
          kind: 'checksum_mismatch',
          actual_seq: 1,
        },
      });
    });

    it('quarantines and trims a fully framed but uncommitted v2 EOF tail', () => {
      const j = new MutationJournal(TEST_STATE);
      const committed = j.appendTransaction({
        operations: [{
          type: 'add_node',
          payload: { props: { id: 'committed-v2', type: 'host', label: 'committed-v2' } },
        }],
        ts: '2026-01-01T00:00:00.000Z',
      });
      j.markApplied(committed.seq);
      const committedBytes = readFileSync(j.getPath());
      const uncommitted = j.appendTransaction({
        operations: [{
          type: 'add_node',
          payload: { props: { id: 'uncommitted-v2', type: 'host', label: 'uncommitted-v2' } },
        }],
        ts: '2026-01-01T00:00:01.000Z',
      });
      const frames = readFileSync(j.getPath(), 'utf-8').split('\n').filter(Boolean);
      frames.pop(); // remove the complete tx_commit frame, leaving begin+chunk at EOF
      writeFileSync(j.getPath(), `${frames.join('\n')}\n`);
      const original = readFileSync(j.getPath());

      const recovered = new MutationJournal(TEST_STATE);
      expect(recovered.inspectReplayIntegrity(1, {
        trustedContiguousCheckpoint: true,
      })).toMatchObject({
        kind: 'incomplete_transaction',
        actual_seq: uncommitted.seq,
        tx_id: uncommitted.tx_id,
      });
      const repair = recovered.repairIncompleteTransactionTail();

      expect(repair).toMatchObject({
        repaired: true,
        committed_transactions: 1,
      });
      if (!repair.repaired) throw new Error('expected repair');
      expect(readFileSync(repair.quarantine_path)).toEqual(original);
      expect(readFileSync(j.getPath())).toEqual(committedBytes);
      expect(recovered.readTransactionsSince(0).map(tx => tx.seq)).toEqual([1]);
      expect(recovered.getHighestPhysicalFrameSeq()).toBe(committed.commit_frame_seq);
    });

    it('replays a legacy-v1 prefix followed by journal-v2 transactions', () => {
      const j = new MutationJournal(TEST_STATE);
      j.append({
        type: 'add_node',
        payload: { props: { id: 'legacy-prefix', type: 'host', label: 'legacy-prefix' } },
        ts: '2026-01-01T00:00:00.000Z',
      });
      j.markApplied(1);
      const current = j.appendTransaction({
        operations: [{
          type: 'add_node',
          payload: { props: { id: 'v2-suffix', type: 'host', label: 'v2-suffix' } },
        }],
        ts: '2026-01-01T00:00:01.000Z',
      });
      j.markApplied(current.seq);

      const recovered = new MutationJournal(TEST_STATE);
      const transactions = recovered.readTransactionsSince(0);
      expect(transactions.map(transaction => transaction.seq)).toEqual([1, 2]);
      expect(transactions.map(transaction => transaction.operations[0]?.type)).toEqual([
        'add_node',
        'add_node',
      ]);
      expect(transactions[0]).toMatchObject({
        tx_id: 'legacy-v1-1',
        begin_frame_seq: 1,
        commit_frame_seq: 1,
      });
      expect(transactions[1]).toMatchObject({
        seq: 2,
        begin_frame_seq: 2,
        commit_frame_seq: 4,
      });
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

    it('rejects invalid UTF-8 without applying, normalizing, or compacting the WAL', () => {
      const invalidFrame = Buffer.concat([
        Buffer.from('{"seq":1,"ts":"2026-01-01T00:00:00.000Z","type":"add_node","payload":{"props":{"id":"'),
        Buffer.from([0xff]),
        Buffer.from('"}}}\n'),
      ]);
      const validTail = Buffer.from(`${JSON.stringify({
        seq: 2,
        ts: '2026-01-01T00:00:01.000Z',
        type: 'add_node',
        payload: { props: { id: 'must-remain-after-invalid-utf8' } },
      })}\n`);
      const original = Buffer.concat([invalidFrame, validTail]);
      writeFileSync(JOURNAL_PATH, original);

      const journal = new MutationJournal(TEST_STATE);
      const attempted: number[] = [];
      const result = journal.replay({
        apply(entry) {
          attempted.push(entry.seq);
          return { status: 'applied' };
        },
      }, 0);

      expect(attempted).toEqual([]);
      expect(result).toMatchObject({
        read: 0,
        attempted: 0,
        applied: 0,
        complete: false,
        highest_on_disk_seq: 2,
        highest_contiguous_applied_seq: 0,
        read_issue: { kind: 'malformed_entry', line: 1, byte_offset: 0 },
      });
      expect(journal.compactUpTo(2)).toMatchObject({
        kept: 0,
        dropped: 0,
        preserved: true,
      });
      expect(readFileSync(JOURNAL_PATH)).toEqual(original);
      const quarantine = journal.quarantine();
      expect(quarantine).toBeDefined();
      expect(readFileSync(quarantine!)).toEqual(original);
      expect(readFileSync(JOURNAL_PATH)).toEqual(original);
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

    it('strictly validates durable node-drop audit and incident-edge descriptors', () => {
      const j = new MutationJournal(TEST_STATE);
      const valid = {
        payload_version: 1,
        operation_id: 'drop-operation',
        occurred_at: '2026-01-01T00:00:00.000Z',
        reason: 'remove duplicate',
        action_id: 'action-drop',
        node_id: 'host-drop',
        expected_type: 'host',
        expected_node: {
          node_id: 'host-drop',
          props: { id: 'host-drop', type: 'host', label: 'drop' },
        },
        incident_edges: [{
          edge_id: 'edge-drop',
          source: 'host-drop',
          target: 'host-peer',
          edge_type: 'RELATED',
          props: { type: 'RELATED', confidence: 1 },
        }],
      };
      expect(j.append({ type: 'drop_node', payload: valid })).toMatchObject({ seq: 1 });

      const invalidPayloads = [
        { ...valid, operation_id: '' },
        { ...valid, occurred_at: 'not-a-time' },
        { ...valid, action_id: '' },
        { ...valid, incident_edges: [...valid.incident_edges, { ...valid.incident_edges[0] }] },
      ];
      for (const payload of invalidPayloads) {
        expect(() => j.append({ type: 'drop_node', payload })).toThrow(
          'Refusing to append malformed WAL record',
        );
      }
      expect(j.peekSeq()).toBe(1);
    });

    it('strictly validates frozen identity-rewrite deltas', () => {
      const j = new MutationJournal(TEST_STATE);
      const before = {
        node_id: 'user-alice',
        props: { id: 'user-alice', type: 'user', label: 'Alice' },
      };
      const after = {
        node_id: 'user-alice',
        props: { id: 'user-alice', type: 'user', label: 'Alice Canonical' },
      };
      const valid = {
        payload_version: 1,
        operation_id: 'identity-operation',
        occurred_at: '2026-01-01T00:00:00.000Z',
        canonical_node_id: 'user-alice',
        node_changes: [{ node_id: 'user-alice', before, after }],
        edge_changes: [],
        audit_events: [{ description: 'Identity converged', details: {} }],
        result: {
          removed_nodes: [],
          removed_edges: [],
          new_edges: [],
          updated_edges: [],
          updated_canonical: true,
          survivor_id: 'user-alice',
        },
      };
      expect(j.append({ type: 'identity_rewrite', payload: valid })).toMatchObject({ seq: 1 });
      expect(() => j.append({
        type: 'identity_rewrite',
        payload: { ...valid, node_changes: [] },
      })).toThrow('Refusing to append malformed WAL record');
      expect(() => j.append({
        type: 'identity_rewrite',
        payload: { ...valid, audit_events: [{ description: '', details: {} }] },
      })).toThrow('Refusing to append malformed WAL record');
      expect(() => j.append({
        type: 'identity_rewrite',
        payload: {
          ...valid,
          node_changes: [valid.node_changes[0], valid.node_changes[0]],
        },
      })).toThrow('Refusing to append malformed WAL record');
      expect(j.peekSeq()).toBe(1);
    });

    it('strictly validates frozen graph-correction deltas', () => {
      const j = new MutationJournal(TEST_STATE);
      const before = {
        node_id: 'host-corrected',
        props: { id: 'host-corrected', type: 'host', label: 'Before' },
      };
      const after = {
        node_id: 'host-corrected',
        props: { id: 'host-corrected', type: 'host', label: 'After' },
      };
      const valid = {
        payload_version: 1,
        operation_id: 'correction-operation',
        occurred_at: '2026-01-01T00:00:00.000Z',
        reason: 'fix the host label',
        action_id: 'action-correction',
        operations: [{
          kind: 'patch_node',
          node_id: 'host-corrected',
          set_properties: { label: 'After' },
          unset_properties: [],
        }],
        node_changes: [{ node_id: 'host-corrected', before, after }],
        edge_changes: [],
        before_summary: { total_nodes: 1, total_edges: 0 },
        after_summary: { total_nodes: 1, total_edges: 0 },
        result: {
          dropped_nodes: [],
          dropped_edges: [],
          replaced_edges: [],
          patched_nodes: ['host-corrected'],
        },
      };
      expect(j.append({ type: 'graph_corrected', payload: valid })).toMatchObject({ seq: 1 });

      const invalidPayloads = [
        { ...valid, operation_id: '' },
        { ...valid, occurred_at: 'not-a-time' },
        { ...valid, operations: [] },
        { ...valid, operations: [{ kind: 'drop_node', node_id: '' }] },
        { ...valid, node_changes: [valid.node_changes[0], valid.node_changes[0]] },
        { ...valid, before_summary: { total_nodes: -1, total_edges: 0 } },
      ];
      for (const payload of invalidPayloads) {
        expect(() => j.append({ type: 'graph_corrected', payload })).toThrow(
          'Refusing to append malformed WAL record',
        );
      }
      expect(j.peekSeq()).toBe(1);
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

    it('does not checkpoint a live journal mutation whose applier reports skipped', () => {
      const ctx = new EngineContext(
        createOverwatchGraph(),
        makeConfig({ engagement_nonce: NONCE }),
        TEST_STATE,
      );
      const journal = ctx.mutationJournal!;

      expect(() => ctx.applyJournaledMutation(
        'add_node',
        { props: { id: 'skipped-live-node' } },
        () => ({ status: 'skipped' as const, reason: 'synthetic live precondition mismatch' }),
      )).toThrow('Durable mutation was not applied: synthetic live precondition mismatch');

      expect(journal.getHighestPhysicalSeq()).toBe(1);
      expect(journal.getAppliedThroughSeq()).toBe(0);
      expect(journal.getAppendBlockedReason()).toContain(
        'mutation seq 1 was durable but failed during in-memory application',
      );
      expect(() => ctx.applyJournaledMutation(
        'add_node',
        { props: { id: 'must-not-append-after-skipped-live-node' } },
        () => 'generic callback result',
      )).toThrow(/Mutation journal is read-only/);
      expect(journal.readTransactionsSince(0)).toHaveLength(1);
      expect(readFileSync(journal.getPath(), 'utf8').split('\n').filter(Boolean)).toHaveLength(3);
    });

    it('restores the journal and does not checkpoint a skipped live composite mutation', () => {
      const ctx = new EngineContext(
        createOverwatchGraph(),
        makeConfig({ engagement_nonce: NONCE }),
        TEST_STATE,
      );
      const journal = ctx.mutationJournal!;

      expect(() => ctx.applyCompositeJournaledMutation(
        'add_node',
        { props: { id: 'skipped-live-composite-node' } },
        () => ({ status: 'skipped' as const, reason: 'synthetic composite precondition mismatch' }),
      )).toThrow('Durable composite mutation was not applied: synthetic composite precondition mismatch');

      expect(ctx.mutationJournal).toBe(journal);
      expect(journal.getHighestPhysicalSeq()).toBe(1);
      expect(journal.getAppliedThroughSeq()).toBe(0);
      expect(journal.getAppendBlockedReason()).toContain(
        'composite mutation seq 1 was durable but failed during in-memory application',
      );
      expect(() => ctx.applyCompositeJournaledMutation(
        'add_node',
        { props: { id: 'must-not-append-after-skipped-live-composite-node' } },
        () => ({ status: 'applied' as const }),
      )).toThrow(/Mutation journal is read-only/);
      expect(journal.readTransactionsSince(0)).toHaveLength(1);
      expect(readFileSync(journal.getPath(), 'utf8').split('\n').filter(Boolean)).toHaveLength(3);
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

    it('reports a base-to-WAL gap before a later unsupported record', () => {
      writeFileSync(JOURNAL_PATH, [
        JSON.stringify({
          seq: 5,
          ts: '2026-01-01T00:00:00.000Z',
          type: 'add_node',
          payload: { props: { id: 'must-not-apply-beyond-gap' } },
        }),
        JSON.stringify({
          seq: 6,
          ts: '2026-01-01T00:00:01.000Z',
          type: 'future_mutation',
          payload: {},
        }),
        '',
      ].join('\n'));
      const recovered = new MutationJournal(TEST_STATE);
      recovered.setNextSeq(1, { appliedThroughSeq: 1 });
      const attempted: number[] = [];

      const result = recovered.replay({
        apply(entry) {
          attempted.push(entry.seq);
          return { status: 'applied' };
        },
      }, 1, { trustedContiguousCheckpoint: true });

      expect(attempted).toEqual([]);
      expect(result).toMatchObject({
        read: 2,
        attempted: 0,
        applied: 0,
        complete: false,
        highest_contiguous_applied_seq: 1,
        read_issue: {
          kind: 'sequence_gap',
          expected_seq: 2,
          actual_seq: 5,
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

  it('creates a scope WAL for an unmanaged legacy engine and replays a crash before checkpoint', () => {
    const legacy = makeConfig({ engagement_nonce: undefined });
    const first = trackedEngine(legacy, TEST_STATE);
    first.persistImmediate();
    const internal = first as unknown as {
      persistence: { persistImmediate: () => void };
      ctx: { mutationJournal: MutationJournal | null };
      ensureCompositeJournal: () => void;
    };
    internal.ensureCompositeJournal();
    internal.persistence.persistImmediate = () => {
      throw new Error('synthetic crash before scope checkpoint');
    };

    expect(() => first.updateScope({
      add_cidrs: ['10.20.20.0/24'],
      reason: 'legacy scope crash recovery',
    })).toThrow('synthetic crash');
    expect(internal.ctx.mutationJournal).not.toBeNull();
    expect(
      internal.ctx.mutationJournal!
        .readTransactionsSince(0)
        .flatMap(transaction => transaction.operations)
        .map(operation => operation.type),
    ).toContain('scope_updated');
    first.dispose();
    engines.delete(first);

    const restarted = trackedEngine(legacy, TEST_STATE);
    expect(restarted.getConfig().scope.cidrs).toContain('10.20.20.0/24');
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      journal: { enabled: true },
    });
  });

  describe('integrated with engine', () => {
    it('journals even when engagement_nonce is absent', () => {
      const eng = trackedEngine(makeConfig(), TEST_STATE); // no nonce
      eng.addNode({ id: 'x', type: 'host', label: 'x', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      expect(existsSync(JOURNAL_PATH)).toBe(true);
      expect(eng.getPersistenceRecoveryStatus().journal).toMatchObject({
        enabled: true,
        format_version: 2,
        path: JOURNAL_PATH,
      });
    });

    it('keeps the always-on journal enabled through a composite mutation', () => {
      const eng = trackedEngine(makeConfig(), TEST_STATE);
      eng.addNode({ id: 'x', type: 'host', label: 'x', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      expect(eng.getPersistenceRecoveryStatus().journal).toMatchObject({
        enabled: true,
        format_version: 2,
        path: JOURNAL_PATH,
      });

      eng.correctGraph('add durable operator annotation', [{
        kind: 'patch_node',
        node_id: 'x',
        set_properties: { operator_note: 'reviewed' },
      }]);

      expect(existsSync(JOURNAL_PATH)).toBe(true);
      expect(eng.getPersistenceRecoveryStatus().journal).toMatchObject({
        enabled: true,
        path: JOURNAL_PATH,
      });
      expect(
        new MutationJournal(TEST_STATE)
          .readTransactionsSince(0)
          .flatMap(transaction => transaction.operations)
          .map(operation => operation.type),
      ).toContain('graph_corrected');
    });

    it('journals add_node and add_edge for engagements with engagement_nonce', () => {
      const eng = trackedEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE);
      eng.addNode({ id: 'h1', type: 'host', label: 'h1', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.addNode({ id: 's1', type: 'service', label: 'smb/445', port: 445, discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.addEdge('h1', 's1', { type: 'RUNS', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      expect(existsSync(JOURNAL_PATH)).toBe(true);
      const types = new MutationJournal(TEST_STATE)
        .readTransactionsSince(0)
        .flatMap(transaction => transaction.operations)
        .map(operation => operation.type)
        .sort();
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
      appendV2Mutation(j, 'add_edge', {
        source: 'missing-host',
        target: 'missing-service',
        props: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' },
      });
      appendV2Mutation(j, 'merge_edge_attrs', {
        edge_id: 'missing-edge',
        props: { session_live: false },
      });
      appendV2Mutation(j, 'future_mutation' as MutationType, {});
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
      appendV2Mutation(j, 'merge_node_attrs', {
        props: { id: 'n1', type: 'cloud_identity', label: 'g2' },
      });

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
        appendV2Mutation(j, 'add_edge', {
          source: 'p',
          target: 'r',
          props: {
            type: 'HAS_POLICY',
            confidence: 1,
            discovered_at: '2026-01-01T00:00:00Z',
            scope,
          },
        });
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
      appendV2Mutation(j, 'add_node', {
        props: {
          id: 'kept',
          type: 'host',
          label: 'kept',
          discovered_at: '2026-01-01T00:00:00Z',
          confidence: 1,
        },
      });
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
      appendV2Mutation(j, 'replace_node_attrs', {
        props: {
          id: 'n1',
          type: 'host',
          label: 'n1',
          ip: '10.10.10.1',
          discovered_at: '2026-01-01T00:00:00Z',
          confidence: 1,
        },
      });

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
      appendV2Mutation(j, 'add_node', {
        props: {
          id: 'kept',
          type: 'host',
          label: 'kept',
          discovered_at: '2026-01-01T00:00:00Z',
          confidence: 1,
        },
      });
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

    it('persists a transaction checkpoint for an engagement without a nonce', () => {
      // WAL durability is now engagement-wide rather than nonce-gated.
      const eng = trackedEngine(makeConfig(), TEST_STATE); // no nonce
      eng.addNode({ id: 'x', type: 'host', label: 'x', ip: '10.10.10.1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
      eng.persist();
      eng.flushNow();
      const snap = JSON.parse(readFileSync(TEST_STATE, 'utf-8'));
      expect(snap.journal_version).toBe(2);
      expect(snap.journalSnapshotSeq).toBeGreaterThan(0);
      expect(snap.journalSnapshotSeq).toBe(
        eng.getPersistenceRecoveryStatus().highest_contiguous_applied_seq,
      );
      eng.dispose();
    });
  });
});
