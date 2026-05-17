// ============================================================
// Overwatch — Mutation Journal (P2.1)
//
// Write-ahead log for graph-affecting mutations. The canonical engagement
// state is `snapshot.json` + `journal.jsonl`: snapshot is a periodic full
// dump, journal is the append-only stream of mutations applied since.
//
// Crash safety contract:
//   1. Caller appends a MutationEntry to the journal (fsync).
//   2. Caller applies the mutation in memory.
//   3. Caller eventually triggers a snapshot, which truncates the journal.
//
// If the process dies between (1) and (2), startup replay reproduces (2).
// If it dies before (1), the in-memory state hasn't changed yet — nothing
// to recover.
//
// The journal is gated on `engagement_nonce` (P1.2): only deterministic-ID
// engagements get journaling. Legacy engagements keep the old
// debounced-snapshot behavior, which avoids retrofitting WAL onto state
// shapes that pre-date P1.x.
//
// Design notes:
//   * Append mode: open-write-fsync-close per entry. Per-line cost ~1ms
//     locally; fine for offensive-engagement workloads where mutation
//     rate is bursty (parser ingest) not sustained.
//   * Sequence numbers: persisted in snapshot. Survive restart. Monotonic.
//   * Replay reads each line, applies to a `MutationApplier` adapter
//     supplied by the caller. The journal itself doesn't know about the
//     graph; it's a typed stream.
// ============================================================

import { existsSync, openSync, fsyncSync, closeSync, writeSync, readFileSync, mkdirSync, renameSync, unlinkSync } from 'fs';
import { dirname, join, basename } from 'path';

export type MutationType =
  | 'add_node'
  | 'merge_node_attrs'
  | 'drop_node'
  | 'add_edge'
  | 'merge_edge_attrs'
  | 'drop_edge'
  | 'cold_add'
  | 'cold_promote'
  | 'lease_acquire'
  | 'lease_release'
  | 'lease_renew'
  | 'log_event'
  | 'scope_updated';

export interface MutationEntry {
  seq: number;
  ts: string;                  // ISO timestamp the entry was journaled
  type: MutationType;
  payload: Record<string, unknown>;
  source_action_id?: string;   // optional cross-reference to the originating action
}

export type MutationApplyResult =
  | { status: 'applied' }
  | { status: 'skipped'; reason: string };

export interface MutationReplayResult {
  read: number;
  applied: number;
  skipped: number;
  failed: number;
  skipped_reasons: Array<{ seq: number; type: string; reason: string }>;
  failed_reasons: Array<{ seq: number; type: string; reason: string }>;
}

export interface MutationApplier {
  apply(entry: MutationEntry): MutationApplyResult;
}

export class MutationJournal {
  private journalPath: string;
  private nextSeq: number = 0;

  constructor(stateFilePath: string) {
    const stateDir = dirname(stateFilePath);
    if (!existsSync(stateDir)) {
      mkdirSync(stateDir, { recursive: true });
    }
    this.journalPath = join(stateDir, basename(stateFilePath, '.json') + '.journal.jsonl');
  }

  /**
   * Set the starting sequence number — typically restored from snapshot
   * metadata so journal entries don't collide with pre-restart sequences.
   */
  setNextSeq(seq: number): void {
    this.nextSeq = seq;
  }

  /**
   * Get the next sequence number that will be assigned (without consuming it).
   * Used by snapshot writers so the snapshot's `journal_seq` field aligns
   * with where the journal currently is.
   */
  peekSeq(): number {
    return this.nextSeq;
  }

  /**
   * Append a mutation entry. Synchronously fsyncs the file before
   * returning. Throws on write failure — callers MUST treat that as
   * "the mutation is not durable, do not apply it in memory."
   */
  append(entry: Omit<MutationEntry, 'seq' | 'ts'> & { ts?: string }): MutationEntry {
    const seq = ++this.nextSeq;
    const full: MutationEntry = {
      seq,
      ts: entry.ts ?? new Date().toISOString(),
      type: entry.type,
      payload: entry.payload,
      ...(entry.source_action_id ? { source_action_id: entry.source_action_id } : {}),
    };
    const line = JSON.stringify(full) + '\n';

    // Open-append-fsync-close: simple and bulletproof; the bulkier
    // engagements that justify a long-lived stream can land later.
    const fd = openSync(this.journalPath, 'a');
    try {
      writeSync(fd, line);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    return full;
  }

  /**
   * Read all journal entries with `seq > fromSeq`. Used on startup to
   * replay entries the snapshot doesn't yet contain.
   *
   * Tolerant of malformed trailing lines (a crash mid-write may leave a
   * partial line). Stops at the first malformed line and returns what it
   * read; the caller can decide whether to truncate.
   */
  readSince(fromSeq: number): MutationEntry[] {
    if (!existsSync(this.journalPath)) return [];
    const raw = readFileSync(this.journalPath, 'utf-8');
    if (!raw) return [];
    const out: MutationEntry[] = [];
    const lines = raw.split('\n');
    for (const line of lines) {
      if (!line) continue;
      try {
        const entry = JSON.parse(line) as MutationEntry;
        if (typeof entry.seq !== 'number' || typeof entry.type !== 'string') break;
        if (entry.seq > fromSeq) out.push(entry);
      } catch {
        // Malformed line — likely a crash mid-write. Stop here; the
        // caller should snapshot+truncate to recover.
        break;
      }
    }
    return out;
  }

  /**
   * Compact the journal: drop entries with `seq <= upTo`, keep newer ones.
   * Used after a snapshot rotation — entries that are now in the snapshot
   * are redundant and can be discarded.
   *
   * Atomic on POSIX via write-tmp-then-rename.
   */
  compactUpTo(upTo: number): { kept: number; dropped: number } {
    if (!existsSync(this.journalPath)) return { kept: 0, dropped: 0 };
    const raw = readFileSync(this.journalPath, 'utf-8');
    if (!raw) return { kept: 0, dropped: 0 };
    let kept = 0;
    let dropped = 0;
    const keptLines: string[] = [];
    for (const line of raw.split('\n')) {
      if (!line) continue;
      try {
        const entry = JSON.parse(line) as MutationEntry;
        if (typeof entry.seq !== 'number') break;
        if (entry.seq > upTo) {
          keptLines.push(line);
          kept++;
        } else {
          dropped++;
        }
      } catch {
        break; // malformed trailing line; stop here
      }
    }
    if (kept === 0) {
      this.truncate();
      return { kept, dropped };
    }
    const tmp = this.journalPath + '.compact';
    const fd = openSync(tmp, 'w');
    try {
      writeSync(fd, keptLines.join('\n') + '\n');
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.journalPath);
    return { kept, dropped };
  }

  /**
   * Truncate the journal — called after a fresh snapshot is durable.
   * Atomic on POSIX via rename-to-tmp-then-unlink.
   */
  truncate(): void {
    if (!existsSync(this.journalPath)) return;
    // Rename first so a partial unlink doesn't leave the journal in a
    // weird state. The rename target is always discarded.
    const stale = this.journalPath + '.stale';
    try {
      renameSync(this.journalPath, stale);
      unlinkSync(stale);
    } catch {
      // Fallback: try direct unlink.
      try { unlinkSync(this.journalPath); } catch { /* best-effort */ }
    }
  }

  /**
   * Replay every entry in the journal through the supplied applier.
   * Returns detailed counts so callers can decide whether to truncate —
   * truncation should be skipped when entries failed or were skipped
   * unexpectedly, so the evidence is preserved for manual inspection (P2).
   */
  replay(applier: MutationApplier, fromSeq: number): MutationReplayResult {
    const entries = this.readSince(fromSeq);
    let applied = 0;
    let skipped = 0;
    let failed = 0;
    const skipped_reasons: MutationReplayResult['skipped_reasons'] = [];
    const failed_reasons: MutationReplayResult['failed_reasons'] = [];
    for (const entry of entries) {
      try {
        const result = applier.apply(entry);
        if (result.status === 'skipped') {
          skipped++;
          skipped_reasons.push({ seq: entry.seq, type: entry.type, reason: result.reason });
        } else {
          applied++;
        }
      } catch (err) {
        failed++;
        const reason = err instanceof Error ? err.message : String(err);
        failed_reasons.push({ seq: entry.seq, type: entry.type, reason });
        // eslint-disable-next-line no-console
        console.warn(`[mutation-journal] apply failed for seq=${entry.seq} type=${entry.type}: ${reason}`);
      }
    }
    if (entries.length > 0) {
      this.nextSeq = Math.max(this.nextSeq, entries[entries.length - 1].seq);
    }
    return { read: entries.length, applied, skipped, failed, skipped_reasons, failed_reasons };
  }

  /** Path to the journal file. Useful for tests + diagnostics. */
  getPath(): string {
    return this.journalPath;
  }
}
