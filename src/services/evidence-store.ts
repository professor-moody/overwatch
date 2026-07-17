// ============================================================
// Overwatch — Evidence Store
// Persists full evidence blobs to disk with stable reference IDs.
// Inline snippets remain in the activity log for fast access;
// this store holds the full-fidelity payloads.
// ============================================================

import {
  closeSync,
  constants,
  createWriteStream,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
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
import { readProcessStartIdentity } from './process-identity.js';

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

interface EvidenceStreamIntentV1 {
  intent_version: 1;
  evidence_id: string;
  temporary_filename: string;
  kind: 'content' | 'raw_output';
  timestamp: string;
  action_id?: string;
  finding_id?: string;
  agent_id?: string;
  task_id?: string;
  evidence_type: EvidenceRecord['evidence_type'];
  filename?: string;
  content_hash?: string;
  bytes?: number;
  owner_pid: number;
  owner_process_start_identity?: string;
  owner_token: string;
}

const evidenceStreamOwnerToken = uuidv4();
const evidenceStreamProcessStartIdentity = readProcessStartIdentity(process.pid);
const MAX_EVIDENCE_DESCRIPTOR_BYTES = 1024 * 1024;

function readFileBounded(path: string, maxBytes: number): Buffer {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size > maxBytes) throw new Error(`Recovery metadata exceeds ${maxBytes} bytes.`);
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw new Error('Recovery metadata changed while being read.');
      offset += count;
    }
    const after = fstatSync(fd);
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
      throw new Error('Recovery metadata changed while being read.');
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function hashPinnedBlob(
  path: string,
  expectedBytes: number,
  onChunk?: (chunk: Buffer) => void,
): string {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size !== expectedBytes) {
      throw new Error(`Evidence blob size mismatch: ${path}`);
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    while (offset < before.size) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, before.size - offset), offset);
      if (count === 0) throw new Error(`Evidence blob changed while being read: ${path}`);
      const chunk = buffer.subarray(0, count);
      hash.update(chunk);
      onChunk?.(chunk);
      offset += count;
    }
    const after = fstatSync(fd);
    if (
      after.dev !== before.dev
      || after.ino !== before.ino
      || after.size !== before.size
      || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs
    ) throw new Error(`Evidence blob changed while being read: ${path}`);
    return hash.digest('hex');
  } finally {
    closeSync(fd);
  }
}

function readPinnedBlobBounded(path: string, maxBytes: number): Buffer | null {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(fd);
    if (!before.isFile()) throw new Error(`Evidence blob is not a regular file: ${path}`);
    if (before.size > maxBytes) return null;
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw new Error(`Evidence blob changed while being read: ${path}`);
      offset += count;
    }
    const after = fstatSync(fd);
    if (
      after.dev !== before.dev
      || after.ino !== before.ino
      || after.size !== before.size
      || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs
    ) throw new Error(`Evidence blob changed while being read: ${path}`);
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function processMayStillBeAlive(pid: number, expectedStartIdentity?: string): boolean {
  try {
    process.kill(pid, 0);
  } catch (error) {
    // Permission/inspection failures are unverifiable, not proof of death.
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
  }
  if (!expectedStartIdentity) return true;
  const observed = readProcessStartIdentity(pid);
  return observed === undefined || observed === expectedStartIdentity;
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
  private renameFile: (source: string, destination: string) => void;

  constructor(
    stateFilePath: string,
    options: {
      readOnly?: boolean;
      /** Injectable durability boundary for deterministic filesystem tests. */
      syncDirectory?: (directory: string) => void;
      /** Injectable quarantine boundary for corruption failure tests. */
      renameFile?: (source: string, destination: string) => void;
    } = {},
  ) {
    const stateDir = dirname(stateFilePath);
    this.dir = join(stateDir, 'evidence');
    this.manifestPath = join(this.dir, 'manifest.json');
    this.readOnly = options.readOnly === true;
    this.syncDirectory = options.syncDirectory ?? fsyncDirectory;
    this.renameFile = options.renameFile ?? renameSync;
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
    if (recoverCorrupt) this.recoverInterruptedStreamsUnlocked();
    if (!existsSync(this.manifestPath)) {
      const descriptors = this.readRecoveryDescriptors();
      // A blob without a descriptor may be an interrupted write whose public
      // evidence_id was never committed or returned. Preserve the prior retry
      // behavior in that case; only durable UUID descriptors authorize
      // reconstructing a deleted aggregate manifest.
      if (descriptors.length === 0 && recoverCorrupt) {
        this.manifest = [];
        return false;
      }
      this.manifest = this.rebuildManifestFromBlobs(descriptors);
      return recoverCorrupt && this.manifest.length > 0;
    }
    let parsedManifest: EvidenceRecord[];
    let manifestBytes: string;
    try {
      manifestBytes = readFileSync(this.manifestPath, 'utf-8');
    } catch (error) {
      if (!recoverCorrupt) {
        console.error(
          `[evidence-store] manifest.json at ${this.manifestPath} could not be read during degraded recovery; preserving it byte-for-byte.`,
        );
        this.manifest = this.rebuildManifestFromBlobs();
        return false;
      }
      // An I/O/permission error does not prove byte corruption and must never
      // trigger quarantine or replacement of a potentially valid manifest.
      throw error;
    }
    try {
      const parsed = JSON.parse(manifestBytes);
      if (!Array.isArray(parsed)) {
        throw new Error('manifest root must be an array');
      }
      parsedManifest = parsed as EvidenceRecord[];
    } catch (err) {
      if (!recoverCorrupt) {
        console.error(
          `[evidence-store] manifest.json at ${this.manifestPath} is unreadable during degraded recovery; preserving it byte-for-byte.`,
        );
        // Degraded mode must not mutate the corrupt authority, but valid
        // immutable descriptors/blobs can still be projected in memory so
        // findings retain access to their evidence during reconciliation.
        this.manifest = this.rebuildManifestFromBlobs();
        return false;
      }
      // F1-15: silent reset → loud recovery. Preserve the corrupted manifest
      // for forensic investigation, log a warning, and rebuild a best-effort
      // manifest by scanning the evidence directory so existing findings that
      // reference evidence_ids still resolve.
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const preservedPath = `${this.manifestPath}.corrupt-${timestamp}.json`;
      // Preserving the only corrupt bytes is a precondition for recovery. A
      // failed quarantine must never be followed by a manifest rewrite.
      this.renameFile(this.manifestPath, preservedPath);
      this.syncDirectory(this.dir);
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
    const recoveryDescriptors = this.readRecoveryDescriptors(false);
    if (recoverCorrupt) this.backfillRecoveryDescriptors(recoveryDescriptors);
    return this.mergeRecoveryDescriptors(recoveryDescriptors);
  }

  /** Publish a verified private stream blob without trusting a pre-existing
   * content-addressed filename. Valid duplicates deduplicate; corrupt or
   * unsafe occupants are preserved under a quarantine name before the good
   * staged bytes replace them. Caller holds the manifest writer lock. */
  private publishOrDeduplicateVerifiedBlob(
    stagedPath: string,
    destinationPath: string,
    expectedHash: string,
    expectedBytes: number,
  ): void {
    if (existsSync(destinationPath)) {
      let destinationValid = false;
      try {
        destinationValid = hashPinnedBlob(destinationPath, expectedBytes) === expectedHash;
      } catch {
        destinationValid = false;
      }
      if (destinationValid) {
        unlinkSync(stagedPath);
        this.syncDirectory(this.dir);
        return;
      }
      const quarantinePath = `${destinationPath}.corrupt-${new Date().toISOString().replace(/[:.]/g, '-')}-${uuidv4()}`;
      renameSync(destinationPath, quarantinePath);
      this.syncDirectory(this.dir);
    }
    renameSync(stagedPath, destinationPath);
    this.syncDirectory(this.dir);
  }

  /**
   * Finalize stream intents left by a dead process. The intent is published
   * before the first byte, then enriched with the final hash before the blob
   * rename. Those two states let restart recover either a partial staging file
   * or a fully-published blob whose descriptor/manifest was not yet committed.
   * Caller holds the manifest writer lock.
   */
  private recoverInterruptedStreamsUnlocked(): void {
    let names: string[];
    try { names = readdirSync(this.dir); } catch { return; }
    for (const name of names.filter(entry => entry.endsWith('.stream-intent.json'))) {
      const intentPath = join(this.dir, name);
      let intent: EvidenceStreamIntentV1;
      try {
        const parsed = JSON.parse(readFileBounded(intentPath, MAX_EVIDENCE_DESCRIPTOR_BYTES).toString('utf8')) as Partial<EvidenceStreamIntentV1>;
        if (
          parsed.intent_version !== 1
          || typeof parsed.evidence_id !== 'string'
          || !/^[0-9a-f-]{36}$/i.test(parsed.evidence_id)
          || name !== `${parsed.evidence_id}.stream-intent.json`
          || typeof parsed.temporary_filename !== 'string'
          || parsed.temporary_filename !== basename(parsed.temporary_filename)
          || !parsed.temporary_filename.startsWith(`.stream-${parsed.evidence_id}.`)
          || (parsed.kind !== 'content' && parsed.kind !== 'raw_output')
          || typeof parsed.timestamp !== 'string'
          || !['screenshot', 'log', 'file', 'command_output'].includes(parsed.evidence_type ?? '')
          || !Number.isSafeInteger(parsed.owner_pid)
          || parsed.owner_pid! <= 0
          || (parsed.owner_process_start_identity !== undefined
            && (typeof parsed.owner_process_start_identity !== 'string'
              || parsed.owner_process_start_identity.length === 0))
          || typeof parsed.owner_token !== 'string'
          || parsed.owner_token.length === 0
        ) throw new Error('invalid interrupted evidence stream intent');
        intent = parsed as EvidenceStreamIntentV1;
      } catch {
        const quarantined = `${intentPath}.corrupt-${uuidv4()}`;
        renameSync(intentPath, quarantined);
        this.syncDirectory(this.dir);
        continue;
      }

      // Normal manifest refreshes happen while active streams are open. Only a
      // different process incarnation may recover an unfinished intent.
      if (
        (intent.owner_pid === process.pid && intent.owner_token === evidenceStreamOwnerToken)
        || processMayStillBeAlive(intent.owner_pid, intent.owner_process_start_identity)
      ) continue;

      const descriptorPath = join(this.dir, `${intent.evidence_id}.record.json`);
      if (existsSync(descriptorPath)) {
        const descriptors = this.readRecoveryDescriptorFile(
          `${intent.evidence_id}.record.json`,
          true,
        );
        const matching = descriptors.some(descriptor => {
          const length = intent.kind === 'content'
            ? descriptor.record.content_length
            : descriptor.record.raw_output_length;
          const blobCommitted = intent.kind === 'content'
            ? descriptor.blobs.content
            : descriptor.blobs.raw;
          const committedEmptyWithoutBlob = intent.bytes === 0
            && intent.content_hash === createHash('sha256').digest('hex')
            && descriptor.record.content_hash === intent.content_hash
            && length === 0
            && !descriptor.blobs.content
            && !descriptor.blobs.raw;
          return (blobCommitted || committedEmptyWithoutBlob)
            && (intent.content_hash === undefined
              || descriptor.record.content_hash === intent.content_hash)
            && (intent.bytes === undefined || length === intent.bytes);
        });
        if (matching) {
          const temporaryPath = join(this.dir, intent.temporary_filename);
          if (existsSync(temporaryPath)) unlinkSync(temporaryPath);
          unlinkSync(intentPath);
          this.syncDirectory(this.dir);
          continue;
        }
        // Filename presence alone is not a commit boundary. Preserve the bad
        // descriptor for diagnosis, then let the verified intent/temp path
        // reconstruct the UUID mapping.
        renameSync(
          descriptorPath,
          `${descriptorPath}.corrupt-${new Date().toISOString().replace(/[:.]/g, '-')}-${uuidv4()}`,
        );
        this.syncDirectory(this.dir);
      }

      const temporaryPath = join(this.dir, intent.temporary_filename);
      const ext = intent.kind === 'raw_output' ? 'raw' : 'content';
      let contentHash = intent.content_hash;
      let bytes = intent.bytes;
      let blobPublished = false;

      if (existsSync(temporaryPath)) {
        const stat = lstatSync(temporaryPath);
        if (stat.isSymbolicLink() || !stat.isFile()) {
          throw new Error(`Interrupted evidence staging path is not a regular file: ${temporaryPath}`);
        }
        const fd = openSync(temporaryPath, 'r');
        const hasher = createHash('sha256');
        let total = 0;
        try {
          const buffer = Buffer.allocUnsafe(64 * 1024);
          while (true) {
            const count = readSync(fd, buffer, 0, buffer.length, null);
            if (count <= 0) break;
            hasher.update(buffer.subarray(0, count));
            total += count;
          }
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
        const observedHash = hasher.digest('hex');
        if (contentHash !== undefined && contentHash !== observedHash) {
          throw new Error(`Interrupted evidence stream hash mismatch for ${intent.evidence_id}.`);
        }
        if (bytes !== undefined && bytes !== total) {
          throw new Error(`Interrupted evidence stream byte-count mismatch for ${intent.evidence_id}.`);
        }
        contentHash = observedHash;
        bytes = total;
        const blobPath = join(this.dir, `${contentHash}.${ext}`);
        this.publishOrDeduplicateVerifiedBlob(temporaryPath, blobPath, contentHash, total);
        blobPublished = true;
      } else if (contentHash && Number.isSafeInteger(bytes) && bytes! >= 0) {
        const finalizedBytes = bytes!;
        const blobPath = join(this.dir, `${contentHash}.${ext}`);
        if (finalizedBytes === 0 && contentHash === createHash('sha256').digest('hex') && !existsSync(blobPath)) {
          // Empty streams intentionally publish no blob. The enriched intent is
          // still sufficient to restore the stable UUID and zero-byte record.
          blobPublished = false;
        } else {
          try {
            blobPublished = hashPinnedBlob(blobPath, finalizedBytes) === contentHash;
          } catch {
            blobPublished = false;
          }
          if (!blobPublished) {
            throw new Error(`Interrupted evidence stream blob is missing or corrupt for ${intent.evidence_id}.`);
          }
        }
      } else {
        contentHash = createHash('sha256').digest('hex');
        bytes = 0;
      }

      const record: EvidenceRecord = {
        evidence_id: intent.evidence_id,
        blob_key: contentHash,
        content_hash: contentHash,
        action_id: intent.action_id,
        finding_id: intent.finding_id,
        agent_id: intent.agent_id,
        task_id: intent.task_id,
        timestamp: intent.timestamp,
        evidence_type: intent.evidence_type,
        filename: intent.filename,
        content_length: intent.kind === 'content' ? bytes! : 0,
        raw_output_length: intent.kind === 'raw_output' ? bytes! : 0,
        capture_error: 'interrupted before evidence stream finalization',
        recovered: true,
      };
      this.publishRecoveryDescriptor(record, {
        content: intent.kind === 'content' && blobPublished,
        raw: intent.kind === 'raw_output' && blobPublished,
      });
      unlinkSync(intentPath);
      this.syncDirectory(this.dir);
    }
  }

  private verifyDescriptorBlobs(
    record: EvidenceRecord,
    blobs: EvidenceRecoveryDescriptorV1['blobs'],
  ): boolean {
    if (
      !Number.isSafeInteger(record.content_length)
      || record.content_length < 0
      || !Number.isSafeInteger(record.raw_output_length)
      || record.raw_output_length < 0
      || typeof record.content_hash !== 'string'
      || !/^[0-9a-f]{64}$/i.test(record.content_hash)
    ) return false;

    try {
      const combined = createHash('sha256');
      let singleBlobHash: string | undefined;
      if (blobs.content) {
        singleBlobHash = hashPinnedBlob(
          this.blobPath(record, 'content'),
          record.content_length,
          chunk => combined.update(chunk),
        );
      } else if (record.content_length !== 0) return false;
      combined.update('\0');
      if (blobs.raw) {
        const rawHash = hashPinnedBlob(
          this.blobPath(record, 'raw'),
          record.raw_output_length,
          chunk => combined.update(chunk),
        );
        singleBlobHash = blobs.content ? undefined : rawHash;
      } else if (record.raw_output_length !== 0) return false;

      const combinedHash = combined.digest('hex');
      const emptyStreamHash = createHash('sha256').digest('hex');
      return record.content_hash === combinedHash
        || record.content_hash === singleBlobHash
        || (!blobs.content && !blobs.raw
          && record.content_length === 0
          && record.raw_output_length === 0
          && record.content_hash === emptyStreamHash);
    } catch {
      return false;
    }
  }

  /**
   * Read immutable per-UUID recovery descriptors. New evidence publishes its
   * content-addressed blobs first, then this descriptor, and only then the
   * aggregate manifest. The descriptor therefore preserves the public UUID ->
   * blob mapping when manifest.json is missing, corrupt, or an older valid
   * version survived a writer crash before the final manifest rename.
   */
  private readRecoveryDescriptorFile(
    name: string,
    verifyBlobs: boolean,
  ): RecoveredEvidenceDescriptor[] {
    const match = name.match(/^([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.record\.json$/i);
    if (!match) return [];
    try {
      const parsed = JSON.parse(
        readFileBounded(join(this.dir, name), MAX_EVIDENCE_DESCRIPTOR_BYTES).toString('utf8'),
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
      ) return [];
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
        && record.blob_key === records[0]!.blob_key
        && record.content_length === records[0]!.content_length
        && record.raw_output_length === records[0]!.raw_output_length);
      if (!validRecords) return [];
      const blobs = {
        content: parsed.blobs.content,
        raw: parsed.blobs.raw,
      };
      if (verifyBlobs && !this.verifyDescriptorBlobs(records[0]!, blobs)) return [];
      return records.map(record => ({ record, blobs }));
    } catch {
      // A damaged descriptor is not authoritative. Blob scanning below still
      // recovers the content under its hash/legacy UUID where possible.
      return [];
    }
  }

  private readRecoveryDescriptors(verifyBlobs = true): RecoveredEvidenceDescriptor[] {
    let entries: string[];
    try {
      entries = readdirSync(this.dir);
    } catch {
      return [];
    }
    return entries.flatMap(name => this.readRecoveryDescriptorFile(name, verifyBlobs));
  }

  private mergeRecoveryDescriptors(
    descriptors: RecoveredEvidenceDescriptor[] = this.readRecoveryDescriptors(false),
  ): boolean {
    let changed = false;
    const existing = new Set(this.manifest.map(recoveryRecordSignature));
    for (const descriptor of descriptors) {
      const signature = recoveryRecordSignature(descriptor.record);
      if (existing.has(signature)) continue;
      if (!this.verifyDescriptorBlobs(descriptor.record, descriptor.blobs)) continue;
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
  private backfillRecoveryDescriptors(
    descriptors: RecoveredEvidenceDescriptor[] = this.readRecoveryDescriptors(false),
  ): void {
    const described = new Map<string, RecoveredEvidenceDescriptor[]>();
    for (const descriptor of descriptors) {
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
      if (!this.verifyDescriptorBlobs(record, { content, raw })) continue;
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
    const describedEvidenceIds = new Set(descriptors.map(descriptor => descriptor.record.evidence_id));
    // A finalized stream intent carries the original public UUID plus the
    // content-addressed blob identity. In degraded read-only mode, project it
    // without unlinking or publishing a descriptor so finding references keep
    // resolving under the exact UUID.
    for (const name of entries.filter(entry => entry.endsWith('.stream-intent.json'))) {
      try {
        const intent = JSON.parse(
          readFileBounded(join(this.dir, name), MAX_EVIDENCE_DESCRIPTOR_BYTES).toString('utf8'),
        ) as Partial<EvidenceStreamIntentV1>;
        if (
          intent.intent_version !== 1
          || typeof intent.evidence_id !== 'string'
          || describedEvidenceIds.has(intent.evidence_id)
          || name !== `${intent.evidence_id}.stream-intent.json`
          || (intent.kind !== 'content' && intent.kind !== 'raw_output')
          || typeof intent.content_hash !== 'string'
          || !/^[0-9a-f]{64}$/i.test(intent.content_hash)
          || !Number.isSafeInteger(intent.bytes)
          || intent.bytes! < 0
          || typeof intent.timestamp !== 'string'
          || !['screenshot', 'log', 'file', 'command_output'].includes(intent.evidence_type ?? '')
        ) continue;
        const intentBytes = intent.bytes!;
        const ext = intent.kind === 'content' ? 'content' : 'raw';
        const blobPath = join(this.dir, `${intent.content_hash}.${ext}`);
        let blobAvailable = false;
        if (intentBytes === 0 && intent.content_hash === createHash('sha256').digest('hex') && !existsSync(blobPath)) {
          blobAvailable = false;
        } else {
          try {
            blobAvailable = hashPinnedBlob(blobPath, intentBytes) === intent.content_hash;
          } catch {
            continue;
          }
        }
        rebuilt.push({
          evidence_id: intent.evidence_id,
          blob_key: intent.content_hash,
          content_hash: intent.content_hash,
          action_id: intent.action_id,
          finding_id: intent.finding_id,
          agent_id: intent.agent_id,
          task_id: intent.task_id,
          timestamp: intent.timestamp,
          evidence_type: intent.evidence_type!,
          filename: intent.filename,
          content_length: intent.kind === 'content' ? intentBytes : 0,
          raw_output_length: intent.kind === 'raw_output' ? intentBytes : 0,
          capture_error: 'interrupted before evidence stream descriptor commit',
          recovered: true,
        });
        describedEvidenceIds.add(intent.evidence_id);
        if (blobAvailable) describedBlobKeys.add(intent.content_hash);
      } catch {
        // Preserve malformed/oversized intent bytes for writable recovery or
        // manual inspection; they are not safe read-only authority.
      }
    }
    const byId = new Map<string, {
      contentSize: number;
      rawSize: number;
      hasContent: boolean;
      hasRaw: boolean;
      mtimeMs: number;
    }>();
    for (const name of entries) {
      const match = name.match(/^([0-9a-f-]{36}|[0-9a-f]{64})\.(content|raw)$/i);
      if (!match) continue;
      const [, evidenceId, ext] = match;
      if (describedBlobKeys.has(evidenceId)) continue;
      let size = 0;
      let mtimeMs = 0;
      try {
        const stat = lstatSync(join(this.dir, name));
        if (stat.isSymbolicLink() || !stat.isFile()) continue;
        size = stat.size;
        mtimeMs = stat.mtimeMs;
      } catch {
        continue;
      }
      const existing = byId.get(evidenceId) || {
        contentSize: 0, rawSize: 0, hasContent: false, hasRaw: false, mtimeMs: 0,
      };
      if (ext === 'content') {
        existing.contentSize = size;
        existing.hasContent = true;
      } else {
        existing.rawSize = size;
        existing.hasRaw = true;
      }
      existing.mtimeMs = Math.max(existing.mtimeMs, mtimeMs);
      byId.set(evidenceId, existing);
    }
    for (const [evidenceId, info] of byId) {
      try {
        const combined = createHash('sha256');
        let directContent: string | undefined;
        let directRaw: string | undefined;
        if (info.hasContent) {
          directContent = hashPinnedBlob(
            join(this.dir, `${evidenceId}.content`),
            info.contentSize,
            chunk => combined.update(chunk),
          );
        }
        combined.update('\0');
        if (info.hasRaw) {
          directRaw = hashPinnedBlob(
            join(this.dir, `${evidenceId}.raw`),
            info.rawSize,
            chunk => combined.update(chunk),
          );
        }
        if (evidenceId.length === 64) {
          const combinedHash = combined.digest('hex');
          const validContentStream = info.hasContent && !info.hasRaw && directContent === evidenceId;
          const validRawStream = info.hasRaw && !info.hasContent && directRaw === evidenceId;
          if (combinedHash !== evidenceId && !validContentStream && !validRawStream) continue;
        }
      } catch {
        continue;
      }
      rebuilt.push({
        evidence_id: evidenceId,
        ...(evidenceId.length === 64
          ? { content_hash: evidenceId, blob_key: evidenceId }
          : {}),
        timestamp: new Date(info.mtimeMs).toISOString(),
        evidence_type: 'command_output',
        content_length: info.hasContent ? info.contentSize : 0,
        raw_output_length: info.hasRaw ? info.rawSize : 0,
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
        content_length: opts.content === undefined ? 0 : Buffer.byteLength(opts.content),
        raw_output_length: opts.raw_output === undefined ? 0 : Buffer.byteLength(opts.raw_output),
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
    const intentPath = join(this.dir, `${evidenceId}.stream-intent.json`);
    const streamIntent: EvidenceStreamIntentV1 = {
      intent_version: 1,
      evidence_id: evidenceId,
      temporary_filename: basename(tmpPath),
      kind,
      timestamp,
      action_id: opts.action_id,
      finding_id: opts.finding_id,
      agent_id: opts.agent_id,
      task_id: opts.task_id,
      evidence_type: opts.evidence_type,
      filename: opts.filename,
      owner_pid: process.pid,
      ...(evidenceStreamProcessStartIdentity
        ? { owner_process_start_identity: evidenceStreamProcessStartIdentity }
        : {}),
      owner_token: evidenceStreamOwnerToken,
    };
    this.withManifestWriteLock(() => {
      this.durableBlobWrite(intentPath, `${JSON.stringify(streamIntent, null, 2)}\n`);
    });
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
        // Enrich the intent before publishing the blob. If the process dies
        // after rename but before the descriptor, restart can still locate the
        // immutable content-addressed bytes.
        this.withManifestWriteLock(() => {
          this.durableBlobWrite(intentPath, `${JSON.stringify({
            ...streamIntent,
            content_hash: contentHash,
            bytes: bytesDurable,
          } satisfies EvidenceStreamIntentV1, null, 2)}\n`);
        });
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
            this.publishOrDeduplicateVerifiedBlob(
              tmpPath,
              contentAddressedPath,
              contentHash,
              bytesDurable,
            );
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
          unlinkSync(intentPath);
          this.syncDirectory(this.dir);
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
      const limit = Math.max(0, Math.trunc(opts.max_bytes));
      const bytes = readPinnedBlobBounded(path, limit);
      return bytes?.toString('utf8') ?? null;
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

    const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const before = fstatSync(fd);
      if (!before.isFile()) throw new Error(`Evidence blob is not a regular file: ${path}`);
      const total = before.size;
      const limit = Math.min(total, Math.max(0, Math.trunc(max_bytes)));
      if (limit === 0) return { text: '', total_bytes: total, truncated: total > 0 };

      const buf = Buffer.alloc(limit);
      let read = 0;
      while (read < limit) {
        const n = readSync(fd, buf, read, limit - read, read);
        if (n <= 0) break;
        read += n;
      }
      const after = fstatSync(fd);
      if (
        after.dev !== before.dev
        || after.ino !== before.ino
        || after.size !== before.size
        || after.mtimeMs !== before.mtimeMs
        || after.ctimeMs !== before.ctimeMs
      ) throw new Error(`Evidence blob changed while it was being read: ${path}`);
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
