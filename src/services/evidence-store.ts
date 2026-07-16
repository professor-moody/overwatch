// ============================================================
// Overwatch — Evidence Store
// Persists full evidence blobs to disk with stable reference IDs.
// Inline snippets remain in the activity log for fast access;
// this store holds the full-fidelity payloads.
// ============================================================

import { closeSync, createWriteStream, existsSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, renameSync, statSync, writeFileSync, type WriteStream } from 'fs';
import { join, dirname, basename } from 'path';
import { v4 as uuidv4 } from 'uuid';
import { createHash, type Hash } from 'crypto';

// Defense-in-depth: reject evidence IDs with path traversal components
function sanitizeEvidenceId(id: string): string {
  if (id !== basename(id) || id.includes('..') || id.includes('\0')) {
    throw new Error(`Invalid evidence ID: ${id}`);
  }
  return id;
}

export interface EvidenceRecord {
  evidence_id: string;
  /**
   * P1.1: sha256(content + '\\0' + raw_output) hex digest. Stable across
   * runs of the same input. Two writes producing identical bytes share
   * the same content_hash, which lets the store deduplicate (and lets
   * auditors detect tampering — modified content produces a different
   * hash). Optional for backward-compat with manifests written before P1.1.
   */
  content_hash?: string;
  action_id?: string;
  finding_id?: string;
  /**
   * Actor attribution: which agent/sub-agent task produced this evidence. Lets
   * the operator console + audit trail answer "who captured this" when multiple
   * headless sub-agents run concurrently. Optional for backward-compat.
   */
  agent_id?: string;
  task_id?: string;
  timestamp: string;
  evidence_type: 'screenshot' | 'log' | 'file' | 'command_output';
  filename?: string;
  content_length: number;
  raw_output_length: number;
  /** Set when the streaming sink encountered a write error. The blob may
   * still exist on disk but the byte counts represent only what was
   * confirmed durable. */
  capture_error?: string;
  /**
   * F1-15: set when the record was reconstructed from on-disk blob files
   * after the manifest was found corrupted. Recovered records lack the
   * original (action_id, finding_id) attribution and content_hash; consumers
   * should treat them as best-effort rather than authoritative.
   */
  recovered?: boolean;
}

function computeContentHash(content?: string, raw_output?: string): string {
  // Combine content + raw_output with a NUL separator so a write where
  // (content='ab', raw_output='c') is distinct from (content='a', raw_output='bc').
  const h = createHash('sha256');
  if (content !== undefined) h.update(content);
  h.update('\0');
  if (raw_output !== undefined) h.update(raw_output);
  return h.digest('hex');
}

export class EvidenceStore {
  private dir: string;
  private manifest: EvidenceRecord[] = [];
  private manifestPath: string;
  private readOnly: boolean;

  constructor(stateFilePath: string, options: { readOnly?: boolean } = {}) {
    const stateDir = dirname(stateFilePath);
    this.dir = join(stateDir, 'evidence');
    this.manifestPath = join(this.dir, 'manifest.json');
    this.readOnly = options.readOnly === true;
    if (!this.readOnly) this.ensureDir();
    this.loadManifest();
  }

  /** Complete deferred manifest recovery only after state + config are writable. */
  enableWrites(): void {
    if (!this.readOnly) return;
    this.ensureDir();
    this.readOnly = false;
    this.loadManifest();
  }

  private assertWritable(): void {
    if (this.readOnly) {
      throw new Error('Evidence storage is read-only while engagement recovery is incomplete.');
    }
  }

  private ensureDir(): void {
    if (!existsSync(this.dir)) {
      mkdirSync(this.dir, { recursive: true });
    }
  }

  private loadManifest(): void {
    if (!existsSync(this.manifestPath)) return;
    try {
      this.manifest = JSON.parse(readFileSync(this.manifestPath, 'utf-8'));
      return;
    } catch (err) {
      if (this.readOnly) {
        console.error(
          `[evidence-store] manifest.json at ${this.manifestPath} is unreadable during degraded recovery; preserving it byte-for-byte.`,
        );
        this.manifest = [];
        return;
      }
      // F1-15: silent reset → loud recovery. Preserve the corrupted manifest
      // for forensic investigation, log a warning, and rebuild a best-effort
      // manifest by scanning the evidence directory so existing findings that
      // reference evidence_ids still resolve.
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const preservedPath = `${this.manifestPath}.corrupt-${timestamp}.json`;
      try {
        renameSync(this.manifestPath, preservedPath);
      } catch {
        // If rename fails (permission, missing), continue — the rebuild is
        // still worth attempting and the warning will surface the failure.
      }
      const message = err instanceof Error ? err.message : String(err);
      console.error(
        `[evidence-store] manifest.json at ${this.manifestPath} failed to parse (${message}). ` +
        `Preserved as ${preservedPath}. Rebuilding from on-disk blobs; rebuilt records will be marked recovered=true.`
      );
      this.manifest = this.rebuildManifestFromBlobs();
      try {
        this.saveManifest();
      } catch {
        // Non-fatal — the in-memory manifest still serves this process.
      }
    }
  }

  /**
   * F1-15: scan `this.dir` for `<uuid>.content` and `<uuid>.raw` blob files
   * and synthesize a minimal EvidenceRecord per uuid. Used when the on-disk
   * manifest is unreadable. Records lack the original attribution and
   * content_hash; flagged `recovered: true` so downstream code can warn.
   */
  private rebuildManifestFromBlobs(): EvidenceRecord[] {
    let entries: string[];
    try {
      entries = readdirSync(this.dir);
    } catch {
      return [];
    }
    const byId = new Map<string, { contentSize: number; rawSize: number; mtimeMs: number; type: 'content' | 'raw' | 'both' }>();
    for (const name of entries) {
      const match = name.match(/^([0-9a-f-]{36})\.(content|raw)$/i);
      if (!match) continue;
      const [, evidenceId, ext] = match;
      let size = 0;
      let mtimeMs = 0;
      try {
        const stat = statSync(join(this.dir, name));
        size = stat.size;
        mtimeMs = stat.mtimeMs;
      } catch {
        continue;
      }
      const existing = byId.get(evidenceId) || { contentSize: 0, rawSize: 0, mtimeMs: 0, type: ext as 'content' | 'raw' };
      if (ext === 'content') existing.contentSize = size;
      else existing.rawSize = size;
      existing.type = existing.contentSize > 0 && existing.rawSize > 0
        ? 'both'
        : existing.contentSize > 0 ? 'content' : 'raw';
      existing.mtimeMs = Math.max(existing.mtimeMs, mtimeMs);
      byId.set(evidenceId, existing);
    }
    const rebuilt: EvidenceRecord[] = [];
    for (const [evidenceId, info] of byId) {
      rebuilt.push({
        evidence_id: evidenceId,
        timestamp: new Date(info.mtimeMs).toISOString(),
        evidence_type: 'command_output',
        content_length: info.contentSize,
        raw_output_length: info.rawSize,
        recovered: true,
      });
    }
    return rebuilt;
  }

  private saveManifest(): void {
    this.assertWritable();
    // Atomic write: serialize to a temp file, fsync via writeFileSync, then
    // rename over the manifest. rename(2) is atomic on POSIX, so a concurrent
    // reader (or a crash mid-write) never observes a torn manifest. Within this
    // single-engine process all saveManifest() calls are already serialized by
    // the event loop (no awaits), so the temp path only needs to be unique.
    const tmpPath = `${this.manifestPath}.tmp-${process.pid}`;
    writeFileSync(tmpPath, JSON.stringify(this.manifest, null, 2));
    renameSync(tmpPath, this.manifestPath);
  }

  /**
   * Store evidence and/or raw_output, returning a stable evidence_id.
   * Content is written to individual files to avoid bloating state.
   *
   * P1.1: if a prior record exists with the same `content_hash`, return
   * its evidence_id instead of writing duplicate bytes. Files on disk stay
   * UUID-keyed (path stability for any old reference); the manifest carries
   * the content_hash so lookups by either key resolve correctly.
   */
  store(opts: {
    action_id?: string;
    finding_id?: string;
    agent_id?: string;
    task_id?: string;
    evidence_type: 'screenshot' | 'log' | 'file' | 'command_output';
    filename?: string;
    content?: string;
    raw_output?: string;
  }): string {
    this.assertWritable();
    const contentHash = computeContentHash(opts.content, opts.raw_output);
    // Dedup: if we've already stored this content (regardless of which
    // action/finding referenced it), reuse the existing evidence_id and
    // append a thin attribution-only record so list() still surfaces the
    // new (action_id, finding_id) pair without re-writing the bytes.
    const existing = this.manifest.find(r => r.content_hash === contentHash);
    if (existing) {
      // Reuse the existing evidence_id; record an attribution if this is
      // a different (action_id, finding_id) tuple from the original.
      const sameAttribution =
        existing.action_id === opts.action_id && existing.finding_id === opts.finding_id;
      if (!sameAttribution) {
        const aliasRecord: EvidenceRecord = {
          evidence_id: existing.evidence_id, // shared key — file is the same
          content_hash: contentHash,
          action_id: opts.action_id,
          finding_id: opts.finding_id,
          agent_id: opts.agent_id,
          task_id: opts.task_id,
          timestamp: new Date().toISOString(),
          evidence_type: opts.evidence_type,
          filename: opts.filename,
          content_length: existing.content_length,
          raw_output_length: existing.raw_output_length,
        };
        this.manifest.push(aliasRecord);
        this.saveManifest();
      }
      return existing.evidence_id;
    }

    const evidenceId = uuidv4();
    const timestamp = new Date().toISOString();

    if (opts.content) {
      const contentPath = join(this.dir, `${evidenceId}.content`);
      writeFileSync(contentPath, opts.content);
    }
    if (opts.raw_output) {
      const rawPath = join(this.dir, `${evidenceId}.raw`);
      writeFileSync(rawPath, opts.raw_output);
    }

    const record: EvidenceRecord = {
      evidence_id: evidenceId,
      content_hash: contentHash,
      action_id: opts.action_id,
      finding_id: opts.finding_id,
      agent_id: opts.agent_id,
      task_id: opts.task_id,
      timestamp,
      evidence_type: opts.evidence_type,
      filename: opts.filename,
      content_length: opts.content?.length ?? 0,
      raw_output_length: opts.raw_output?.length ?? 0,
    };
    this.manifest.push(record);
    this.saveManifest();

    return evidenceId;
  }

  /**
   * Open a streaming evidence sink. Useful for piping live process output
   * (stdout/stderr) to disk without buffering the entire stream in memory.
   *
   * The returned handle exposes a synchronous `write(chunk)` and an async
   * `end()`. The manifest is updated when `end()` resolves so that
   * downstream consumers always observe a consistent record.
   *
   *   const sink = store.createBlobStream({ action_id, evidence_type: 'command_output', kind: 'content' });
   *   process.stdout.on('data', c => sink.write(c));
   *   process.on('close', async () => { await sink.end(); });
   */
  createBlobStream(opts: {
    action_id?: string;
    finding_id?: string;
    agent_id?: string;
    task_id?: string;
    evidence_type: 'screenshot' | 'log' | 'file' | 'command_output';
    filename?: string;
    /** 'content' writes to <id>.content; 'raw_output' writes to <id>.raw. */
    kind?: 'content' | 'raw_output';
  }): {
    evidence_id: string;
    write: (chunk: Buffer | string) => void;
    end: () => Promise<void>;
    /** Final byte count (durable). Available after end() resolves. */
    bytesWritten: () => number;
    /** First write/finalize error if any. */
    error: () => Error | null;
  } {
    this.assertWritable();
    const evidenceId = uuidv4();
    const timestamp = new Date().toISOString();
    const kind = opts.kind ?? 'content';
    const ext = kind === 'raw_output' ? 'raw' : 'content';
    const path = join(this.dir, `${evidenceId}.${ext}`);
    let stream: WriteStream | null = null;
    // Writes that have been issued vs. confirmed durable. We update the
    // public `bytes` count only on the write callback so a manifest record
    // never claims more bytes than actually landed on disk.
    let bytesDurable = 0;
    let finalized = false;
    let writeError: Error | null = null;
    // P1.1: streaming sha256 over the content, finalized when the sink is
    // closed. The companion stream (if any) is written separately and
    // gets its own evidence_id; the hash here covers only this stream.
    const hasher: Hash = createHash('sha256');
    // Backpressure: when stream.write() returns false we must wait for
    // 'drain' before issuing the next write. We serialize behind a tail
    // promise so callers can stay synchronous (`sink.write(chunk)`) while
    // still respecting backpressure semantics under load.
    let writeChain: Promise<void> = Promise.resolve();

    const ensureStream = (): WriteStream => {
      if (!stream) {
        stream = createWriteStream(path, { flags: 'w' });
        stream.on('error', (err: Error) => {
          if (!writeError) writeError = err;
        });
      }
      return stream;
    };

    const writeChunk = (buf: Buffer): Promise<void> => {
      return new Promise<void>((resolve) => {
        if (writeError) { resolve(); return; }
        const s = ensureStream();
        let settled = false;
        const done = () => { if (!settled) { settled = true; resolve(); } };
        const ok = s.write(buf, (err?: Error | null) => {
          if (err && !writeError) writeError = err;
          else if (!err) {
            bytesDurable += buf.length;
            hasher.update(buf);
          }
          // Resolve when the write itself completed OR errored. A successful write
          // under backpressure (ok=false) resolves via 'drain' below — but an ERRORED
          // write never drains, so resolving here is what stops the write chain (and
          // the tool call awaiting end()) from hanging forever.
          if (ok || err) done();
        });
        if (!ok) {
          // Backpressure: resolve on drain. But an errored/destroyed stream never
          // emits 'drain', so also settle on 'error'/'close' as a backstop — covers a
          // stream that dies after the write callback already fired without draining.
          const onSettle = () => {
            s.removeListener('drain', onSettle);
            s.removeListener('error', onSettle);
            s.removeListener('close', onSettle);
            done();
          };
          s.once('drain', onSettle);
          s.once('error', onSettle);
          s.once('close', onSettle);
        }
      });
    };

    return {
      evidence_id: evidenceId,
      write: (chunk: Buffer | string) => {
        if (finalized || writeError) return;
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        writeChain = writeChain.then(() => writeChunk(buf));
      },
      end: async () => {
        if (finalized) return;
        finalized = true;
        // Drain queued writes before closing.
        await writeChain;
        if (stream) {
          await new Promise<void>((resolve) => {
            stream!.end((err?: Error | null) => {
              if (err && !writeError) writeError = err;
              resolve();
            });
          });
        }
        // Always record the manifest entry, but if writes failed mark the
        // record so consumers can detect partial / corrupt evidence.
        // P1.1: stamp the streamed content_hash. For partial/erroring
        // streams the hash represents only the bytes that landed durably,
        // so it agrees with the recorded length.
        const contentHash = hasher.digest('hex');
        const record: EvidenceRecord & { capture_error?: string } = {
          evidence_id: evidenceId,
          content_hash: contentHash,
          action_id: opts.action_id,
          finding_id: opts.finding_id,
          agent_id: opts.agent_id,
          task_id: opts.task_id,
          timestamp,
          evidence_type: opts.evidence_type,
          filename: opts.filename,
          content_length: kind === 'content' ? bytesDurable : 0,
          raw_output_length: kind === 'raw_output' ? bytesDurable : 0,
        };
        if (writeError) record.capture_error = writeError.message;
        this.manifest.push(record);
        this.saveManifest();
        if (writeError) throw writeError;
      },
      bytesWritten: () => bytesDurable,
      error: () => writeError,
    };
  }

  /**
   * P1.1: resolve either an evidence_id (UUID) OR a content_hash (sha256
   * hex) to the canonical evidence_id used as the on-disk filename. Returns
   * null if neither matches.
   */
  resolveKey(idOrHash: string): string | null {
    // First try direct evidence_id match (cheap walk).
    if (this.manifest.some(r => r.evidence_id === idOrHash)) return idOrHash;
    // Fallback: content_hash → evidence_id. Multiple manifest rows may
    // alias the same evidence_id; the file lives once on disk so any
    // matching row tells us the right key.
    const byHash = this.manifest.find(r => r.content_hash === idOrHash);
    return byHash ? byHash.evidence_id : null;
  }

  /** Retrieve full evidence content by ID or content_hash. */
  getContent(idOrHash: string): string | null {
    const resolved = this.resolveKey(idOrHash);
    if (!resolved) return null;
    const safe = sanitizeEvidenceId(resolved);
    const path = join(this.dir, `${safe}.content`);
    if (!existsSync(path)) return null;
    return readFileSync(path, 'utf-8');
  }

  /**
   * Retrieve full evidence content as RAW BYTES (no UTF-8 decode). Use this for
   * binary blobs — e.g. a `screenshot` PNG written via `createBlobStream` — where
   * the text `getContent`/`getRawOutput` readers would corrupt the bytes.
   */
  getContentBuffer(idOrHash: string): Buffer | null {
    const resolved = this.resolveKey(idOrHash);
    if (!resolved) return null;
    const safe = sanitizeEvidenceId(resolved);
    const path = join(this.dir, `${safe}.content`);
    if (!existsSync(path)) return null;
    return readFileSync(path);
  }

  /**
   * Retrieve full raw output by ID or content_hash.
   *
   * Phase E: when `max_bytes` is provided, return null instead of loading
   * the file into memory if its size exceeds the cap. Callers that want
   * the head bytes for partial parsing should use `getRawOutputHead`.
   * Without `max_bytes` the read is unbounded — preserved for callers
   * that explicitly want the full blob (e.g. report generation).
   */
  getRawOutput(idOrHash: string, opts?: { max_bytes?: number }): string | null {
    const resolved = this.resolveKey(idOrHash);
    if (!resolved) return null;
    const safe = sanitizeEvidenceId(resolved);
    const path = join(this.dir, `${safe}.raw`);
    if (!existsSync(path)) return null;
    if (typeof opts?.max_bytes === 'number') {
      try {
        if (statSync(path).size > opts.max_bytes) return null;
      } catch {
        // If stat fails, fall through to readFileSync — reading itself
        // will surface the error to the caller.
      }
    }
    return readFileSync(path, 'utf-8');
  }

  /**
   * Phase E: streaming-friendly head read for partial parsing on oversized
   * evidence blobs. Returns at most `max_bytes` decoded as UTF-8. When the
   * file is missing or not resolvable, returns null.
   */
  getRawOutputHead(idOrHash: string, max_bytes: number): { text: string; total_bytes: number; truncated: boolean } | null {
    const resolved = this.resolveKey(idOrHash);
    if (!resolved) return null;
    const safe = sanitizeEvidenceId(resolved);
    const path = join(this.dir, `${safe}.raw`);
    if (!existsSync(path)) return null;

    const total = statSync(path).size;
    const limit = Math.min(total, Math.max(0, max_bytes | 0));
    if (limit === 0) return { text: '', total_bytes: total, truncated: total > 0 };

    const buf = Buffer.alloc(limit);
    const fd = openSync(path, 'r');
    try {
      let read = 0;
      while (read < limit) {
        const n = readSync(fd, buf, read, limit - read, read);
        if (n <= 0) break;
        read += n;
      }
      const text = buf.subarray(0, read).toString('utf-8');
      return { text, total_bytes: total, truncated: total > limit };
    } finally {
      closeSync(fd);
    }
  }

  /**
   * Bounded slice read for paging through a raw-output blob (the dashboard
   * Analysis viewer fetches large outputs in windows rather than loading a
   * potentially large blob at once — the on-disk `.raw` is uncapped; only the
   * in-memory capture buffer is bounded). Reads at most `max_bytes` starting at
   * `offset`, decoded as UTF-8. Each window is decoded independently, so a
   * multibyte character straddling a window boundary may render as a U+FFFD
   * replacement char at the seam — callers needing exact bytes should request a
   * single window covering the region. Returns null when the blob is missing or
   * unresolvable.
   */
  getRawOutputSlice(
    idOrHash: string,
    offset: number,
    max_bytes: number,
  ): { text: string; total_bytes: number; offset: number; bytes_read: number; eof: boolean } | null {
    const resolved = this.resolveKey(idOrHash);
    if (!resolved) return null;
    const safe = sanitizeEvidenceId(resolved);
    const path = join(this.dir, `${safe}.raw`);
    if (!existsSync(path)) return null;

    const total = statSync(path).size;
    // Math.trunc (not `| 0`) so offsets beyond 2^31 don't wrap negative and
    // silently page back to the head of the blob.
    const start = Math.max(0, Math.min(Math.trunc(offset) || 0, total));
    const limit = Math.min(Math.max(0, Math.trunc(max_bytes) || 0), total - start);
    if (limit === 0) {
      return { text: '', total_bytes: total, offset: start, bytes_read: 0, eof: start >= total };
    }

    const buf = Buffer.alloc(limit);
    const fd = openSync(path, 'r');
    try {
      let read = 0;
      while (read < limit) {
        const n = readSync(fd, buf, read, limit - read, start + read);
        if (n <= 0) break;
        read += n;
      }
      const text = buf.subarray(0, read).toString('utf-8');
      return { text, total_bytes: total, offset: start, bytes_read: read, eof: start + read >= total };
    } finally {
      closeSync(fd);
    }
  }

  /** Get the manifest record for a specific evidence ID or content_hash. */
  getRecord(idOrHash: string): EvidenceRecord | undefined {
    return this.manifest.find(r => r.evidence_id === idOrHash || r.content_hash === idOrHash);
  }

  /** List all evidence records, optionally filtered by action_id or finding_id. */
  list(filter?: { action_id?: string; finding_id?: string }): EvidenceRecord[] {
    if (!filter) return [...this.manifest];
    return this.manifest.filter(r => {
      if (filter.action_id && r.action_id !== filter.action_id) return false;
      if (filter.finding_id && r.finding_id !== filter.finding_id) return false;
      return true;
    });
  }

  /** Total number of stored evidence items. */
  get size(): number {
    return this.manifest.length;
  }
}
