// ============================================================
// Overwatch — Evidence Store
// Persists full evidence blobs to disk with stable reference IDs.
// Inline snippets remain in the activity log for fast access;
// this store holds the full-fidelity payloads.
// ============================================================

import {
  closeSync,
  createWriteStream,
  existsSync,
  fsyncSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  type WriteStream,
} from 'fs';
import { join, dirname, basename } from 'path';
import { v4 as uuidv4 } from 'uuid';
import { createHash, type Hash } from 'crypto';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';
import { withStateMigrationWriteGuard } from './state-migration-lock.js';

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
   * Immutable on-disk blob basename. New records use their content hash so
   * cooperating writers converge on one physical blob while evidence_id stays
   * backward-compatible. Older manifests omit this and remain UUID-addressed.
   */
  blob_key?: string;
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
   * F1-15: set when the record was reconstructed after the aggregate manifest
   * was missing or corrupt. Descriptor-backed records retain attribution;
   * descriptor-less blob scans remain best-effort.
   */
  recovered?: boolean;
}

interface EvidenceRecoveryDescriptorV1 {
  descriptor_version: 1;
  record: EvidenceRecord;
  blobs: {
    content: boolean;
    raw: boolean;
  };
}

interface EvidenceRecoveryDescriptorV2 {
  descriptor_version: 2;
  records: EvidenceRecord[];
  blobs: EvidenceRecoveryDescriptorV1['blobs'];
}

interface RecoveredEvidenceDescriptor {
  record: EvidenceRecord;
  blobs: EvidenceRecoveryDescriptorV1['blobs'];
}

function descriptorRecord(record: EvidenceRecord): EvidenceRecord {
  const { recovered: _recovered, ...durable } = record;
  return durable;
}

function recoveryRecordSignature(record: EvidenceRecord): string {
  const durable = descriptorRecord(record);
  return JSON.stringify({
    evidence_id: durable.evidence_id,
    blob_key: durable.blob_key,
    content_hash: durable.content_hash,
    action_id: durable.action_id,
    finding_id: durable.finding_id,
    agent_id: durable.agent_id,
    task_id: durable.task_id,
    timestamp: durable.timestamp,
    evidence_type: durable.evidence_type,
    filename: durable.filename,
    content_length: durable.content_length,
    raw_output_length: durable.raw_output_length,
    capture_error: durable.capture_error,
  });
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
  private syncDirectory: (directory: string) => void;

  constructor(
    stateFilePath: string,
    options: {
      readOnly?: boolean;
      /** Injectable durability boundary for deterministic filesystem tests. */
      syncDirectory?: (directory: string) => void;
    } = {},
  ) {
    const stateDir = dirname(stateFilePath);
    this.dir = join(stateDir, 'evidence');
    this.manifestPath = join(this.dir, 'manifest.json');
    this.readOnly = options.readOnly === true;
    this.syncDirectory = options.syncDirectory ?? fsyncDirectory;
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
    // Always delegate to mkdirDurable, even when the directory is visible.
    // A prior recursive mkdir may have created the path and then failed while
    // fsyncing an ancestor; mkdirDurable remembers that pending sync work and
    // retries it on the next construction.
    mkdirDurable(this.dir, this.syncDirectory);
  }

  private durableBlobWrite(path: string, content: string | Buffer): void {
    const tmpPath = `${path}.tmp-${process.pid}-${uuidv4()}`;
    let fd: number | undefined;
    try {
      fd = openSync(tmpPath, 'wx');
      writeFileSync(fd, content);
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
      renameSync(tmpPath, path);
      this.syncDirectory(dirname(path));
    } catch (error) {
      if (fd !== undefined) {
        try { closeSync(fd); } catch { /* preserve original failure */ }
      }
      if (existsSync(tmpPath)) {
        try { unlinkSync(tmpPath); } catch { /* preserve original failure */ }
      }
      throw error;
    }
  }

  private withManifestWriteLock<T>(operation: () => T): T {
    // The state writer guard is a generic, crash-reclaiming cooperating-process
    // mutex keyed by an arbitrary pathname. Keying it by manifest.json keeps
    // evidence writers independent from the engagement state/WAL lock.
    return withStateMigrationWriteGuard(
      this.manifestPath,
      undefined,
      operation,
    );
  }

  private loadManifest(): void {
    if (this.readOnly) {
      this.loadManifestUnlocked(false);
      return;
    }
    this.withManifestWriteLock(() => {
      const recovered = this.loadManifestUnlocked(true);
      if (recovered) this.saveManifestUnlocked();
    });
  }

  /**
   * Reload the authoritative manifest while the caller holds the cooperating
   * writer lock. Returns true when recovery descriptors or blob scanning
   * changed the in-memory manifest and it needs to be published.
   */
  private loadManifestUnlocked(recoverCorrupt: boolean): boolean {
    if (!existsSync(this.manifestPath)) {
      const descriptors = this.readRecoveryDescriptors();
      // A blob without a descriptor may be an interrupted write whose public
      // evidence_id was never committed or returned. Preserve the prior retry
      // behavior in that case; only durable UUID descriptors authorize
      // reconstructing a deleted aggregate manifest.
      if (descriptors.length === 0) {
        this.manifest = [];
        return false;
      }
      this.manifest = this.rebuildManifestFromBlobs(descriptors);
      return this.manifest.length > 0;
    }
    let parsedManifest: EvidenceRecord[];
    try {
      const parsed = JSON.parse(readFileSync(this.manifestPath, 'utf-8'));
      if (!Array.isArray(parsed)) {
        throw new Error('manifest root must be an array');
      }
      parsedManifest = parsed as EvidenceRecord[];
    } catch (err) {
      if (!recoverCorrupt) {
        console.error(
          `[evidence-store] manifest.json at ${this.manifestPath} is unreadable during degraded recovery; preserving it byte-for-byte.`,
        );
        this.manifest = [];
        return false;
      }
      // F1-15: silent reset → loud recovery. Preserve the corrupted manifest
      // for forensic investigation, log a warning, and rebuild a best-effort
      // manifest by scanning the evidence directory so existing findings that
      // reference evidence_ids still resolve.
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const preservedPath = `${this.manifestPath}.corrupt-${timestamp}.json`;
      try {
        renameSync(this.manifestPath, preservedPath);
        this.syncDirectory(this.dir);
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
      return true;
    }
    this.manifest = parsedManifest;
    // Descriptor publication failures are durability failures, not evidence
    // that the already-parsed manifest itself is corrupt. Keep this outside the
    // parse/recovery catch so a failed fsync never renames a valid manifest.
    if (recoverCorrupt) this.backfillRecoveryDescriptors();
    return this.mergeRecoveryDescriptors();
  }

  /**
   * Read immutable per-UUID recovery descriptors. New evidence publishes its
   * content-addressed blobs first, then this descriptor, and only then the
   * aggregate manifest. The descriptor therefore preserves the public UUID ->
   * blob mapping when manifest.json is missing, corrupt, or an older valid
   * version survived a writer crash before the final manifest rename.
   */
  private readRecoveryDescriptors(): RecoveredEvidenceDescriptor[] {
    let entries: string[];
    try {
      entries = readdirSync(this.dir);
    } catch {
      return [];
    }
    const descriptors: RecoveredEvidenceDescriptor[] = [];
    for (const name of entries) {
      const match = name.match(/^([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.record\.json$/i);
      if (!match) continue;
      try {
        const parsed = JSON.parse(
          readFileSync(join(this.dir, name), 'utf8'),
        ) as Partial<EvidenceRecoveryDescriptorV1> | Partial<EvidenceRecoveryDescriptorV2>;
        const records = parsed.descriptor_version === 1
          ? parsed.record ? [parsed.record] : []
          : parsed.descriptor_version === 2 && Array.isArray(parsed.records)
            ? parsed.records
            : [];
        if (
          records.length === 0
          || typeof parsed.blobs?.content !== 'boolean'
          || typeof parsed.blobs?.raw !== 'boolean'
        ) {
          continue;
        }
        const validRecords = records.every(record =>
          record
          && record.evidence_id === match[1]
          && typeof record.timestamp === 'string'
          && ['screenshot', 'log', 'file', 'command_output'].includes(record.evidence_type)
          && typeof record.content_length === 'number'
          && typeof record.raw_output_length === 'number'
          && typeof record.blob_key === 'string'
          && /^[0-9a-f]{64}$/i.test(record.blob_key)
          && typeof record.content_hash === 'string'
          && record.content_hash === record.blob_key
          && record.blob_key === records[0]!.blob_key);
        if (!validRecords) continue;
        const record = records[0]!;
        const contentAvailable = !parsed.blobs.content
          || existsSync(this.blobPath(record, 'content'));
        const rawAvailable = !parsed.blobs.raw
          || existsSync(this.blobPath(record, 'raw'));
        if (!contentAvailable || !rawAvailable) continue;
        const blobs = {
          content: parsed.blobs.content,
          raw: parsed.blobs.raw,
        };
        for (const recoveredRecord of records) {
          descriptors.push({ record: recoveredRecord, blobs });
        }
      } catch {
        // A damaged descriptor is not authoritative. Blob scanning below still
        // recovers the content under its hash/legacy UUID where possible.
      }
    }
    return descriptors;
  }

  private mergeRecoveryDescriptors(): boolean {
    let changed = false;
    const existing = new Set(this.manifest.map(recoveryRecordSignature));
    for (const descriptor of this.readRecoveryDescriptors()) {
      const signature = recoveryRecordSignature(descriptor.record);
      if (existing.has(signature)) continue;
      this.manifest.push({
        ...descriptor.record,
        recovered: true,
      });
      existing.add(signature);
      changed = true;
    }
    return changed;
  }

  /**
   * Upgrade current hash-keyed manifests written before recovery descriptors
   * existed. The valid manifest is authoritative here, so publish one canonical
   * descriptor per public UUID while the manifest writer lock is held.
   */
  private backfillRecoveryDescriptors(): void {
    const described = new Map<string, RecoveredEvidenceDescriptor[]>();
    for (const descriptor of this.readRecoveryDescriptors()) {
      const rows = described.get(descriptor.record.evidence_id) ?? [];
      rows.push(descriptor);
      described.set(descriptor.record.evidence_id, rows);
    }
    const byEvidenceId = new Map<string, EvidenceRecord[]>();
    for (const record of this.manifest) {
      const rows = byEvidenceId.get(record.evidence_id) ?? [];
      rows.push(record);
      byEvidenceId.set(record.evidence_id, rows);
    }
    for (const [evidenceId, records] of byEvidenceId) {
      const record = records[0]!;
      if (
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(evidenceId)
        || typeof record.blob_key !== 'string'
        || !/^[0-9a-f]{64}$/i.test(record.blob_key)
        || record.content_hash !== record.blob_key
      ) {
        // Legacy UUID-keyed blobs already retain their public ID in the
        // filename and remain recoverable through directory scanning.
        continue;
      }
      const describedSignatures = new Set(
        (described.get(evidenceId) ?? []).map(descriptor =>
          recoveryRecordSignature(descriptor.record)),
      );
      if (records.every(candidate =>
        describedSignatures.has(recoveryRecordSignature(candidate)))) continue;
      const content = existsSync(this.blobPath(record, 'content'));
      const raw = existsSync(this.blobPath(record, 'raw'));
      if (
        (record.content_length > 0 && !content)
        || (record.raw_output_length > 0 && !raw)
      ) {
        continue;
      }
      const descriptorRecords = [
        ...(described.get(evidenceId) ?? []).map(descriptor => descriptor.record),
        ...records.filter(candidate =>
          !describedSignatures.has(recoveryRecordSignature(candidate))),
      ];
      this.publishRecoveryDescriptor(descriptorRecords, { content, raw });
      described.set(evidenceId, descriptorRecords.map(candidate => ({
        record: candidate,
        blobs: { content, raw },
      })));
    }
  }

  /**
   * F1-15: rebuild from per-UUID descriptors first, then scan legacy UUID-keyed
   * and descriptor-less content-addressed blobs. Descriptor-backed records keep
   * their original public evidence_id and attribution. Blob-only records are
   * necessarily best-effort and use their on-disk key as evidence_id.
   */
  private rebuildManifestFromBlobs(
    recoveredDescriptors?: RecoveredEvidenceDescriptor[],
  ): EvidenceRecord[] {
    let entries: string[];
    try {
      entries = readdirSync(this.dir);
    } catch {
      return [];
    }
    const descriptors = recoveredDescriptors ?? this.readRecoveryDescriptors();
    const rebuilt: EvidenceRecord[] = descriptors.map(descriptor => ({
      ...descriptor.record,
      recovered: true,
    }));
    const describedBlobKeys = new Set(
      descriptors.map(descriptor =>
        descriptor.record.blob_key ?? descriptor.record.evidence_id),
    );
    const byId = new Map<string, { contentSize: number; rawSize: number; mtimeMs: number; type: 'content' | 'raw' | 'both' }>();
    for (const name of entries) {
      const match = name.match(/^([0-9a-f-]{36}|[0-9a-f]{64})\.(content|raw)$/i);
      if (!match) continue;
      const [, evidenceId, ext] = match;
      if (describedBlobKeys.has(evidenceId)) continue;
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
    for (const [evidenceId, info] of byId) {
      rebuilt.push({
        evidence_id: evidenceId,
        ...(evidenceId.length === 64
          ? { content_hash: evidenceId, blob_key: evidenceId }
          : {}),
        timestamp: new Date(info.mtimeMs).toISOString(),
        evidence_type: 'command_output',
        content_length: info.contentSize,
        raw_output_length: info.rawSize,
        recovered: true,
      });
    }
    return rebuilt;
  }

  private publishRecoveryDescriptor(
    records: EvidenceRecord | EvidenceRecord[],
    blobs: EvidenceRecoveryDescriptorV1['blobs'],
  ): void {
    const durableRecords = (Array.isArray(records) ? records : [records])
      .map(descriptorRecord);
    if (durableRecords.length === 0) {
      throw new Error('Evidence recovery descriptor requires at least one record.');
    }
    const evidenceId = sanitizeEvidenceId(durableRecords[0]!.evidence_id);
    if (durableRecords.some(record =>
      record.evidence_id !== evidenceId
      || record.blob_key !== durableRecords[0]!.blob_key
      || record.content_hash !== durableRecords[0]!.content_hash
    )) {
      throw new Error('Evidence recovery descriptor records must share one evidence ID and blob.');
    }
    this.durableBlobWrite(
      join(this.dir, `${evidenceId}.record.json`),
      JSON.stringify({
        descriptor_version: 2,
        records: durableRecords,
        blobs,
      } satisfies EvidenceRecoveryDescriptorV2, null, 2),
    );
  }

  private blobPath(record: EvidenceRecord, ext: 'content' | 'raw'): string {
    const key = sanitizeEvidenceId(record.blob_key ?? record.evidence_id);
    return join(this.dir, `${key}.${ext}`);
  }

  private saveManifestUnlocked(): void {
    this.assertWritable();
    // Atomic write: serialize to a temp file, fsync via writeFileSync, then
    // rename over the manifest. rename(2) is atomic on POSIX, so a concurrent
    // reader (or a crash mid-write) never observes a torn manifest. The caller
    // holds the cooperating-process manifest mutex, while the unique temp path
    // protects the atomic publish boundary itself.
    this.durableBlobWrite(
      this.manifestPath,
      JSON.stringify(this.manifest, null, 2),
    );
  }

  /**
   * Store evidence and/or raw_output, returning a stable evidence_id.
   * Content is written to individual files to avoid bloating state.
   *
   * P1.1: if a prior record exists with the same `content_hash`, return
   * its evidence_id instead of writing duplicate bytes. Existing UUID-keyed
   * files remain readable; new immutable blobs use the content hash as their
   * on-disk key while the manifest preserves the public evidence_id.
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
    return this.withManifestWriteLock(() => {
      // Every writer reloads after acquiring the cross-process mutex. A store
      // constructed before another process committed can therefore merge its
      // attribution instead of replacing the newer manifest with stale state.
      const recovered = this.loadManifestUnlocked(true);
      if (recovered) this.saveManifestUnlocked();

      const existing = this.manifest.find(record =>
        record.content_hash === contentHash
        && (record.content_length === 0 || existsSync(this.blobPath(record, 'content')))
        && (record.raw_output_length === 0 || existsSync(this.blobPath(record, 'raw'))));
      if (existing) {
        const sameAttribution = this.manifest.some(record =>
          record.evidence_id === existing.evidence_id
          && record.action_id === opts.action_id
          && record.finding_id === opts.finding_id
          && record.agent_id === opts.agent_id
          && record.task_id === opts.task_id);
        if (!sameAttribution) {
          const attribution: EvidenceRecord = {
            evidence_id: existing.evidence_id,
            ...(existing.blob_key ? { blob_key: existing.blob_key } : {}),
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
          const before = this.manifest;
          this.manifest = [
            ...this.manifest,
            attribution,
          ];
          try {
            this.publishRecoveryDescriptor(
              this.manifest.filter(record =>
                record.evidence_id === existing.evidence_id),
              {
                content: existing.content_length > 0,
                raw: existing.raw_output_length > 0,
              },
            );
            this.saveManifestUnlocked();
          } catch (error) {
            this.manifest = before;
            throw error;
          }
        }
        return existing.evidence_id;
      }

      const evidenceId = uuidv4();
      const timestamp = new Date().toISOString();
      const blobKey = contentHash;

      // Publish and fsync immutable content-addressed blobs before the manifest
      // is allowed to reference them. A failed manifest write can leave an
      // orphan, but never a dangling evidence reference.
      if (opts.content !== undefined) {
        this.durableBlobWrite(join(this.dir, `${blobKey}.content`), opts.content);
      }
      if (opts.raw_output !== undefined) {
        this.durableBlobWrite(join(this.dir, `${blobKey}.raw`), opts.raw_output);
      }

      const record: EvidenceRecord = {
        evidence_id: evidenceId,
        blob_key: blobKey,
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
      this.publishRecoveryDescriptor(record, {
        content: opts.content !== undefined,
        raw: opts.raw_output !== undefined,
      });
      const before = this.manifest;
      this.manifest = [...this.manifest, record];
      try {
        this.saveManifestUnlocked();
      } catch (error) {
        this.manifest = before;
        throw error;
      }

      return evidenceId;
    });
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
    /** Selects the content-addressed `.content` or `.raw` blob namespace. */
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
    const tmpPath = join(
      this.dir,
      `.stream-${evidenceId}.${ext}.tmp-${process.pid}-${uuidv4()}`,
    );
    let stream: WriteStream | null = null;
    let streamFd: number | undefined;
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
        streamFd = openSync(tmpPath, 'wx');
        stream = createWriteStream(tmpPath, {
          fd: streamFd,
          autoClose: false,
        });
        stream.on('error', (err: Error) => {
          if (!writeError) writeError = err;
        });
      }
      return stream;
    };

    const writeChunk = (buf: Buffer): Promise<void> => {
      return new Promise<void>((resolve) => {
        if (writeError) { resolve(); return; }
        let s: WriteStream;
        try {
          s = ensureStream();
        } catch (error) {
          writeError = error instanceof Error ? error : new Error(String(error));
          resolve();
          return;
        }
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
          try {
            if (streamFd === undefined) {
              throw new Error('stream evidence descriptor closed before fsync');
            }
            fsyncSync(streamFd);
            closeSync(streamFd);
            streamFd = undefined;
          } catch (error) {
            if (!writeError) {
              writeError = error instanceof Error ? error : new Error(String(error));
            }
            if (streamFd !== undefined) {
              try { closeSync(streamFd); } catch { /* preserve writeError */ }
              streamFd = undefined;
            }
            if (existsSync(tmpPath)) {
              try { unlinkSync(tmpPath); } catch { /* preserve writeError */ }
            }
            throw writeError;
          }
        }
        if (writeError && !stream) throw writeError;
        // Always record the manifest entry, but if writes failed mark the
        // record so consumers can detect partial / corrupt evidence.
        // P1.1: stamp the streamed content_hash. For partial/erroring
        // streams the hash represents only the bytes that landed durably,
        // so it agrees with the recorded length.
        const contentHash = hasher.digest('hex');
        const record: EvidenceRecord & { capture_error?: string } = {
          evidence_id: evidenceId,
          blob_key: contentHash,
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
        this.withManifestWriteLock(() => {
          const recovered = this.loadManifestUnlocked(true);
          if (recovered) this.saveManifestUnlocked();

          if (stream) {
            const contentAddressedPath = join(this.dir, `${contentHash}.${ext}`);
            if (existsSync(contentAddressedPath)) {
              // Another writer already published the same immutable bytes.
              // Keep its blob and discard this stream's private staging file.
              unlinkSync(tmpPath);
            } else {
              renameSync(tmpPath, contentAddressedPath);
            }
            this.syncDirectory(this.dir);
          }

          this.publishRecoveryDescriptor(record, {
            content: kind === 'content' && stream !== null,
            raw: kind === 'raw_output' && stream !== null,
          });
          const before = this.manifest;
          this.manifest = [...this.manifest, record];
          try {
            // Blob publication happens above; the manifest is the final
            // reference boundary and can never point at an unpublished file.
            this.saveManifestUnlocked();
          } catch (error) {
            this.manifest = before;
            throw error;
          }
        });
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
    return this.resolveRecord(idOrHash)?.evidence_id ?? null;
  }

  private resolveRecord(idOrHash: string): EvidenceRecord | undefined {
    return this.manifest.find(record =>
      record.evidence_id === idOrHash || record.content_hash === idOrHash);
  }

  private resolveBlobPath(
    idOrHash: string,
    ext: 'content' | 'raw',
  ): string | null {
    const record = this.resolveRecord(idOrHash);
    return record ? this.blobPath(record, ext) : null;
  }

  /** Retrieve full evidence content by ID or content_hash. */
  getContent(idOrHash: string): string | null {
    const path = this.resolveBlobPath(idOrHash, 'content');
    if (!path) return null;
    if (!existsSync(path)) return null;
    return readFileSync(path, 'utf-8');
  }

  /**
   * Retrieve full evidence content as RAW BYTES (no UTF-8 decode). Use this for
   * binary blobs — e.g. a `screenshot` PNG written via `createBlobStream` — where
   * the text `getContent`/`getRawOutput` readers would corrupt the bytes.
   */
  getContentBuffer(idOrHash: string): Buffer | null {
    const path = this.resolveBlobPath(idOrHash, 'content');
    if (!path) return null;
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
    const path = this.resolveBlobPath(idOrHash, 'raw');
    if (!path) return null;
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
    const path = this.resolveBlobPath(idOrHash, 'raw');
    if (!path) return null;
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
    const path = this.resolveBlobPath(idOrHash, 'raw');
    if (!path) return null;
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
    return this.resolveRecord(idOrHash);
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
