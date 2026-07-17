// ============================================================
// Report archive: crash-safe per-engagement rendered reports.
// ============================================================

import {
  closeSync,
  existsSync,
  fstatSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  renameSync,
  statSync,
} from 'fs';
import { open, type FileHandle } from 'fs/promises';
import { createHash, randomUUID } from 'crypto';
import { basename, dirname, join } from 'path';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';
import {
  DurableArtifactPublicationError,
  removeArtifactDurable,
  writeArtifactAtomicDurable,
} from './durable-artifact.js';
import { withStateMigrationWriteGuard } from './state-migration-lock.js';

export interface ReportArchiveOptions {
  syncDirectory?: (directory: string) => void;
  renameFile?: (source: string, destination: string) => void;
  isWritable?: () => boolean;
}

export type ReportFormat = 'markdown' | 'html' | 'json' | 'pdf';
export type ReportRedactionMode = 'operator' | 'client_safe';
export type ReportProfile = 'operator' | 'client';
export type ReportEvidenceStyle = 'proof_cards' | 'appendix' | 'full_inline';

export interface ReportRecord {
  id: string;
  generated_at: string;
  format: ReportFormat;
  redaction_mode: ReportRedactionMode;
  profile?: ReportProfile;
  evidence_style?: ReportEvidenceStyle;
  findings_count?: number;
  evidence_count?: number;
  filename: string;
  size_bytes: number;
  content_sha256: string;
  options: {
    include_evidence?: boolean;
    include_narrative?: boolean;
    include_retrospective?: boolean;
    include_compliance?: boolean;
    include_attack_paths?: boolean;
    include_attack_navigator?: boolean;
    include_gap_analysis?: boolean;
    theme?: 'light' | 'dark';
    profile?: ReportProfile;
    evidence_style?: ReportEvidenceStyle;
  };
}

export type ReportArchiveAddResult = ReportRecord & {
  /** False only when the immutable descriptor committed but aggregate repair is pending. */
  manifest_persisted: boolean;
  commit_durability: 'confirmed' | 'uncertain';
  warning?: string;
};

export interface ReportArchiveDeleteResult {
  deleted: boolean;
  cleanup_complete: boolean;
  commit_durability: 'confirmed' | 'uncertain';
  warning?: string;
}

export interface ReportArchiveRecoveryStatus {
  writable: boolean;
  uncertain_deletion_ids: string[];
  reason?: string;
}

export type ReportArchiveLookupResult =
  | { status: 'not_found' }
  | { status: 'unavailable'; record: ReportRecord; reason: string }
  | { status: 'integrity_failed'; record: ReportRecord; reason: string }
  | { status: 'ok'; record: ReportRecord; handle: FileHandle };

interface ReportRecoveryDescriptorV1 {
  descriptor_version: 1;
  record: ReportRecord;
}

interface ReportDeletionTombstoneV1 {
  tombstone_version: 1;
  report_id: string;
  deleted_at: string;
}

const MANIFEST_NAME = 'manifest.json';
const ARCHIVE_FORMAT_NAME = 'archive-format.json';
const MAX_REPORT_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_REPORT_DESCRIPTOR_BYTES = 1024 * 1024;
const MAX_REPORT_TOMBSTONE_BYTES = 64 * 1024;
const REPORT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EXT_BY_FORMAT: Record<ReportFormat, string> = {
  markdown: 'md',
  html: 'html',
  json: 'json',
  pdf: 'pdf',
};
const FORMAT_BY_EXT = new Map(Object.entries(EXT_BY_FORMAT).map(([format, ext]) => [ext, format as ReportFormat]));

function sha256(content: Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

function sha256File(path: string): string {
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  const fd = openSync(path, 'r');
  try {
    for (;;) {
      const count = readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest('hex');
}

class ReportMetadataTooLargeError extends Error {}

function readMetadataBounded(path: string, maxBytes: number): Buffer {
  const fd = openSync(path, 'r');
  try {
    const before = fstatSync(fd);
    if (!before.isFile()) throw new Error(`Report recovery metadata is not a regular file: ${path}`);
    if (before.size > maxBytes) {
      throw new ReportMetadataTooLargeError(`Report recovery metadata exceeds ${maxBytes} bytes: ${path}`);
    }
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw new Error(`Report recovery metadata changed while being read: ${path}`);
      offset += count;
    }
    const after = fstatSync(fd);
    if (
      after.dev !== before.dev
      || after.ino !== before.ino
      || after.size !== before.size
      || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs
    ) throw new Error(`Report recovery metadata changed while being read: ${path}`);
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function isReportRecord(value: unknown): value is ReportRecord {
  if (!value || typeof value !== 'object') return false;
  const record = value as Partial<ReportRecord>;
  if (
    typeof record.id !== 'string'
    || !REPORT_ID.test(record.id)
    || typeof record.generated_at !== 'string'
    || !Number.isFinite(Date.parse(record.generated_at))
    || !['markdown', 'html', 'json', 'pdf'].includes(record.format ?? '')
    || !['operator', 'client_safe'].includes(record.redaction_mode ?? '')
    || typeof record.filename !== 'string'
    || record.filename !== `${record.id}.${EXT_BY_FORMAT[record.format!]}`
    || !Number.isSafeInteger(record.size_bytes)
    || record.size_bytes! < 0
    || typeof record.content_sha256 !== 'string'
    || !/^[0-9a-f]{64}$/i.test(record.content_sha256)
    || !record.options
    || typeof record.options !== 'object'
    || Array.isArray(record.options)
  ) return false;
  if (record.profile !== undefined && !['operator', 'client'].includes(record.profile)) return false;
  if (
    record.evidence_style !== undefined
    && !['proof_cards', 'appendix', 'full_inline'].includes(record.evidence_style)
  ) return false;
  for (const count of [record.findings_count, record.evidence_count]) {
    if (count !== undefined && (!Number.isSafeInteger(count) || count < 0)) return false;
  }
  const options = record.options as Record<string, unknown>;
  for (const name of [
    'include_evidence', 'include_narrative', 'include_retrospective',
    'include_compliance', 'include_attack_paths', 'include_attack_navigator',
    'include_gap_analysis',
  ]) {
    if (options[name] !== undefined && typeof options[name] !== 'boolean') return false;
  }
  if (options.theme !== undefined && !['light', 'dark'].includes(options.theme as string)) return false;
  if (options.profile !== undefined && !['operator', 'client'].includes(options.profile as string)) return false;
  if (
    options.evidence_style !== undefined
    && !['proof_cards', 'appendix', 'full_inline'].includes(options.evidence_style as string)
  ) return false;
  return true;
}

export class ReportArchive {
  private readonly dir: string;
  private readonly manifestPath: string;
  private readonly archiveFormatPath: string;
  private readonly syncDirectory: (directory: string) => void;
  private readonly renameFile: (source: string, destination: string) => void;
  private readonly isWritable: () => boolean;

  constructor(engagementStateFilePath: string, options: ReportArchiveOptions = {}) {
    this.dir = join(dirname(engagementStateFilePath), 'reports');
    this.manifestPath = join(this.dir, MANIFEST_NAME);
    this.archiveFormatPath = join(this.dir, ARCHIVE_FORMAT_NAME);
    this.syncDirectory = options.syncDirectory ?? fsyncDirectory;
    this.renameFile = options.renameFile ?? renameSync;
    this.isWritable = options.isWritable ?? (() => true);
  }

  private ensureDir(): void {
    mkdirDurable(this.dir, this.syncDirectory);
  }

  private descriptorPath(id: string): string {
    return join(this.dir, `${id}.record.json`);
  }

  private tombstonePath(id: string): string {
    return join(this.dir, `${id}.deleted.json`);
  }

  private withWriteLock<T>(operation: () => T): T {
    this.ensureDir();
    return withStateMigrationWriteGuard(this.manifestPath, undefined, operation);
  }

  private preserveCorruptManifest(): void {
    const preservedPath = join(
      this.dir,
      `${MANIFEST_NAME}.corrupt-${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID()}`,
    );
    // Quarantine is a precondition for recovery. If it cannot be made durable,
    // fail closed rather than replacing the only corrupt bytes with a rebuild.
    this.renameFile(this.manifestPath, preservedPath);
    this.syncDirectory(this.dir);
  }

  private readManifest(repairCorruption: boolean): { records: ReportRecord[]; needsRewrite: boolean; present: boolean } {
    if (!existsSync(this.manifestPath)) return { records: [], needsRewrite: false, present: false };
    let bytes: string;
    try {
      bytes = readMetadataBounded(this.manifestPath, MAX_REPORT_MANIFEST_BYTES).toString('utf8');
    } catch (error) {
      if (error instanceof ReportMetadataTooLargeError) {
        if (repairCorruption) this.preserveCorruptManifest();
        return { records: [], needsRewrite: true, present: true };
      }
      // Read/permission/device failures are not proof of corrupt bytes. Never
      // rename or rewrite the manifest for an I/O failure.
      throw error;
    }
    try {
      const parsed = JSON.parse(bytes) as unknown;
      if (!Array.isArray(parsed) || !parsed.every(isReportRecord)) {
        throw new Error('report manifest root or record is invalid');
      }
      return { records: parsed, needsRewrite: false, present: true };
    } catch {
      if (repairCorruption) this.preserveCorruptManifest();
      return { records: [], needsRewrite: true, present: true };
    }
  }

  private readTombstones(): { committed: Set<string>; uncertain: Set<string> } {
    const committed = new Set<string>();
    const uncertain = new Set<string>();
    for (const name of readdirSync(this.dir)) {
      const match = /^([0-9a-f-]{36})\.deleted\.json$/i.exec(name);
      if (!match || !REPORT_ID.test(match[1])) continue;
      try {
        const tombstone = JSON.parse(
          readMetadataBounded(join(this.dir, name), MAX_REPORT_TOMBSTONE_BYTES).toString('utf8'),
        ) as Partial<ReportDeletionTombstoneV1>;
        if (
          tombstone.tombstone_version === 1
          && tombstone.report_id === match[1]
          && typeof tombstone.deleted_at === 'string'
          && Number.isFinite(Date.parse(tombstone.deleted_at))
        ) committed.add(match[1]);
        else uncertain.add(match[1]);
      } catch (error) {
        // The filename itself proves a deletion was in flight, but invalid or
        // unreadable bytes cannot authorize destructive cleanup. Hide the
        // report and block new archive mutations until the operator repairs or
        // removes the ambiguous tombstone; preserve every payload byte.
        uncertain.add(match[1]);
        process.stderr.write(
          `[report-archive] ambiguous deletion tombstone preserved: ${join(this.dir, name)} (${error instanceof Error ? error.message : String(error)})\n`,
        );
      }
    }
    return { committed, uncertain };
  }

  private readDescriptors(): ReportRecord[] {
    const records: ReportRecord[] = [];
    for (const name of readdirSync(this.dir)) {
      const match = /^([0-9a-f-]{36})\.record\.json$/i.exec(name);
      if (!match || !REPORT_ID.test(match[1])) continue;
      try {
          const descriptor = JSON.parse(
            readMetadataBounded(join(this.dir, name), MAX_REPORT_DESCRIPTOR_BYTES).toString('utf8'),
          ) as Partial<ReportRecoveryDescriptorV1>;
        if (
          descriptor.descriptor_version === 1
          && isReportRecord(descriptor.record)
          && descriptor.record.id === match[1]
        ) records.push(descriptor.record);
      } catch {
        // Payload scanning below can still recover a report with conservative
        // metadata. Never delete an unreadable descriptor automatically.
      }
    }
    return records;
  }

  private scanPayloads(): ReportRecord[] {
    const records: ReportRecord[] = [];
    for (const name of readdirSync(this.dir)) {
      const match = /^([0-9a-f-]{36})\.(md|html|json|pdf)$/i.exec(name);
      if (!match || !REPORT_ID.test(match[1])) continue;
      const format = FORMAT_BY_EXT.get(match[2].toLowerCase());
      if (!format) continue;
      try {
        const path = join(this.dir, name);
        const stat = statSync(path);
        if (!stat.isFile()) continue;
        records.push({
          id: match[1],
          generated_at: stat.mtime.toISOString(),
          format,
          redaction_mode: 'operator',
          filename: name,
          size_bytes: stat.size,
          content_sha256: sha256File(path),
          options: {},
        });
      } catch {
        // Leave an unreadable payload in place for manual recovery.
      }
    }
    return records;
  }

  private writeDescriptor(record: ReportRecord): void {
    writeArtifactAtomicDurable(
      this.descriptorPath(record.id),
      `${JSON.stringify({ descriptor_version: 1, record } satisfies ReportRecoveryDescriptorV1, null, 2)}\n`,
      { overwrite: false, syncDirectory: this.syncDirectory },
    );
  }

  private writeManifest(records: ReportRecord[]): void {
    writeArtifactAtomicDurable(this.manifestPath, `${JSON.stringify(records, null, 2)}\n`, {
      syncDirectory: this.syncDirectory,
    });
  }

  private writeArchiveFormatMarker(): void {
    if (existsSync(this.archiveFormatPath)) return;
    writeArtifactAtomicDurable(
      this.archiveFormatPath,
      `${JSON.stringify({ archive_format_version: 1, commit_authority: 'descriptor' }, null, 2)}\n`,
      { overwrite: false, syncDirectory: this.syncDirectory },
    );
  }

  /** Caller holds the cross-process archive lock. */
  private reconcileUnlocked(): { records: ReportRecord[]; mutation_blocked: boolean } {
    const manifest = this.readManifest(true);
    const legacyFormat = !existsSync(this.archiveFormatPath);
    const tombstones = this.readTombstones();
    const hiddenIds = new Set([...tombstones.committed, ...tombstones.uncertain]);
    const descriptors = this.readDescriptors();
    // Descriptorless payloads are authoritative only for legacy archives. New
    // archives publish the format marker before accepting a payload; a crash
    // before its descriptor must not resurrect an uncommitted report.
    const payloads = legacyFormat && (!manifest.present || manifest.needsRewrite)
      ? this.scanPayloads()
      : [];
    const byId = new Map<string, ReportRecord>();

    for (const record of manifest.records) if (!hiddenIds.has(record.id)) byId.set(record.id, record);
    // A descriptor is the durable UUID -> immutable payload commitment and is
    // therefore preferred over stale aggregate-manifest metadata.
    for (const record of descriptors) if (!hiddenIds.has(record.id)) byId.set(record.id, record);
    // Legacy archives had no descriptors. Recover payloads conservatively and
    // backfill descriptors before publishing the rebuilt aggregate manifest.
    for (const record of payloads) if (!hiddenIds.has(record.id) && !byId.has(record.id)) byId.set(record.id, record);

    const records = [...byId.values()];
    if (tombstones.uncertain.size > 0) {
      return { records, mutation_blocked: true };
    }

    // A tombstone is the deletion commit. Resume idempotent descriptor/payload
    // cleanup after any crash between that commit and the unlink boundaries.
    for (const id of tombstones.committed) {
      const candidates = [...manifest.records, ...descriptors, ...payloads]
        .filter(record => record.id === id);
      removeArtifactDurable(this.descriptorPath(id), this.syncDirectory);
      for (const record of candidates) {
        removeArtifactDurable(join(this.dir, record.filename), this.syncDirectory);
      }
      for (const ext of Object.values(EXT_BY_FORMAT)) {
        removeArtifactDurable(join(this.dir, `${id}.${ext}`), this.syncDirectory);
      }
    }

    for (const record of records) {
      const descriptorPath = this.descriptorPath(record.id);
      if (!existsSync(descriptorPath) && existsSync(join(this.dir, record.filename))) {
        this.writeDescriptor(record);
      }
    }

    const before = JSON.stringify(manifest.records);
    const after = JSON.stringify(records);
    if (manifest.needsRewrite || before !== after || (!existsSync(this.manifestPath) && records.length > 0)) {
      this.writeManifest(records);
    }
    this.writeArchiveFormatMarker();
    return { records, mutation_blocked: false };
  }

  private readRecords(): ReportRecord[] {
    if (!existsSync(this.dir)) {
      if (!this.isWritable()) return [];
      // Establish descriptor authority before any future payload can become
      // visible. An empty writable archive is still a new-format archive.
      return this.withWriteLock(() => this.reconcileUnlocked().records);
    }
    if (!this.isWritable()) {
      const manifest = this.readManifest(false);
      const legacyFormat = !existsSync(this.archiveFormatPath);
      const tombstones = this.readTombstones();
      const hiddenIds = new Set([...tombstones.committed, ...tombstones.uncertain]);
      const byId = new Map<string, ReportRecord>();
      for (const record of manifest.records) if (!hiddenIds.has(record.id)) byId.set(record.id, record);
      for (const record of this.readDescriptors()) if (!hiddenIds.has(record.id)) byId.set(record.id, record);
      if (legacyFormat && (!manifest.present || manifest.needsRewrite)) {
        for (const record of this.scanPayloads()) {
          if (!hiddenIds.has(record.id) && !byId.has(record.id)) byId.set(record.id, record);
        }
      }
      return [...byId.values()];
    }
    return this.withWriteLock(() => this.reconcileUnlocked().records);
  }

  add(
    content: Buffer | string,
    meta: Omit<ReportRecord, 'id' | 'filename' | 'size_bytes' | 'content_sha256'>,
  ): ReportArchiveAddResult {
    if (!this.isWritable()) throw new Error('Report archive is read-only while persistence recovery is degraded.');
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    return this.withWriteLock(() => {
      const reconciliation = this.reconcileUnlocked();
      if (reconciliation.mutation_blocked) {
        throw new Error('Report archive recovery is read-only because a deletion tombstone is invalid or unreadable.');
      }
      const records = reconciliation.records;
      const id = randomUUID();
      const filename = `${id}.${EXT_BY_FORMAT[meta.format]}`;
      const record: ReportRecord = {
        id,
        generated_at: meta.generated_at,
        format: meta.format,
        redaction_mode: meta.redaction_mode,
        profile: meta.profile,
        evidence_style: meta.evidence_style,
        findings_count: meta.findings_count,
        evidence_count: meta.evidence_count,
        filename,
        size_bytes: buf.byteLength,
        content_sha256: sha256(buf),
        options: meta.options,
      };

      // Payload -> immutable recovery descriptor -> aggregate manifest. A crash
      // after descriptor publication is recovered on the next construction.
      writeArtifactAtomicDurable(join(this.dir, filename), buf, {
        overwrite: false,
        syncDirectory: this.syncDirectory,
      });
      try {
        this.writeDescriptor(record);
      } catch (error) {
        if (error instanceof DurableArtifactPublicationError && error.publication_visible) {
          return {
            ...record,
            manifest_persisted: false,
            commit_durability: error.durability_confirmed ? 'confirmed' : 'uncertain',
            warning: `Report descriptor is visible, but aggregate repair is pending: ${error.message}`,
          };
        }
        throw error;
      }
      try {
        this.writeManifest([...records, record]);
        return { ...record, manifest_persisted: true, commit_durability: 'confirmed' };
      } catch (error) {
        // The immutable descriptor is the commit record. A later reconciliation
        // will rebuild the aggregate manifest; report the committed outcome so
        // callers do not retry and create a duplicate report.
        return {
          ...record,
          manifest_persisted: false,
          commit_durability: 'confirmed',
          warning: `Report committed, but aggregate manifest repair is pending: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    });
  }

  list(): ReportRecord[] {
    return this.readRecords().sort((a, b) => b.generated_at.localeCompare(a.generated_at));
  }

  get(id: string): { record: ReportRecord; content: Buffer } | null {
    const record = this.readRecords().find(candidate => candidate.id === id);
    if (!record) return null;
    try {
      const content = readFileSync(join(this.dir, record.filename));
      if (content.byteLength !== record.size_bytes || sha256(content) !== record.content_sha256) return null;
      return { record, content };
    } catch {
      return null;
    }
  }

  /** Verify a report without materializing it in the daemon heap. */
  async verifyForRead(id: string): Promise<ReportArchiveLookupResult> {
    const record = this.readRecords().find(candidate => candidate.id === id);
    if (!record) return { status: 'not_found' };
    const path = join(this.dir, record.filename);
    let handle: FileHandle | undefined;
    try {
      handle = await open(path, 'r');
      const stat = await handle.stat();
      if (!stat.isFile()) {
        await handle.close();
        handle = undefined;
        return { status: 'unavailable', record, reason: 'report payload is not a regular file' };
      }
      if (stat.size !== record.size_bytes) {
        await handle.close();
        handle = undefined;
        return { status: 'integrity_failed', record, reason: 'report size does not match the committed descriptor' };
      }
      const hash = createHash('sha256');
      for await (const chunk of handle.createReadStream({ autoClose: false, start: 0 })) hash.update(chunk as Buffer);
      if (hash.digest('hex') !== record.content_sha256) {
        await handle.close();
        handle = undefined;
        return { status: 'integrity_failed', record, reason: 'report checksum does not match the committed descriptor' };
      }
      const after = await handle.stat();
      if (
        after.size !== stat.size
        || after.mtimeMs !== stat.mtimeMs
        || after.ctimeMs !== stat.ctimeMs
      ) {
        await handle.close();
        handle = undefined;
        return { status: 'integrity_failed', record, reason: 'report changed during verification' };
      }
      return { status: 'ok', record, handle };
    } catch (error) {
      if (handle) {
        try { await handle.close(); } catch { /* preserve lookup failure */ }
      }
      return {
        status: 'unavailable',
        record,
        reason: error instanceof Error ? error.message : String(error),
      };
    }
  }

  delete(id: string): boolean {
    return this.deleteWithStatus(id).deleted;
  }

  deleteWithStatus(id: string): ReportArchiveDeleteResult {
    if (!this.isWritable()) throw new Error('Report archive is read-only while persistence recovery is degraded.');
    if (!existsSync(this.dir)) return { deleted: false, cleanup_complete: true, commit_durability: 'confirmed' };
    return this.withWriteLock(() => {
      const reconciliation = this.reconcileUnlocked();
      if (reconciliation.mutation_blocked) {
        throw new Error('Report archive recovery is read-only because a deletion tombstone is invalid or unreadable.');
      }
      const records = reconciliation.records;
      const record = records.find(candidate => candidate.id === id);
      if (!record) return { deleted: false, cleanup_complete: true, commit_durability: 'confirmed' };

      // The tombstone commits the deletion before aggregate cleanup, preventing
      // an older descriptor or manifest from resurrecting the report.
      try {
        writeArtifactAtomicDurable(
          this.tombstonePath(id),
          `${JSON.stringify({
            tombstone_version: 1,
            report_id: id,
            deleted_at: new Date().toISOString(),
          } satisfies ReportDeletionTombstoneV1, null, 2)}\n`,
          { syncDirectory: this.syncDirectory },
        );
      } catch (error) {
        if (error instanceof DurableArtifactPublicationError && error.publication_visible) {
          return {
            deleted: true,
            cleanup_complete: false,
            commit_durability: error.durability_confirmed ? 'confirmed' : 'uncertain',
            warning: `Report deletion tombstone is visible, but durability/cleanup is pending: ${error.message}`,
          };
        }
        throw error;
      }
      try {
        this.writeManifest(records.filter(candidate => candidate.id !== id));
        removeArtifactDurable(this.descriptorPath(id), this.syncDirectory);
        removeArtifactDurable(join(this.dir, record.filename), this.syncDirectory);
        return { deleted: true, cleanup_complete: true, commit_durability: 'confirmed' };
      } catch (error) {
        // The durable tombstone is the deletion commit. Never ask callers to
        // retry a mutation that already happened; startup reconciliation will
        // finish aggregate and payload cleanup idempotently.
        return {
          deleted: true,
          cleanup_complete: false,
          commit_durability: 'confirmed',
          warning: `Report deletion committed, but cleanup is pending: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    });
  }

  pathFor(id: string): string | null {
    const record = this.readRecords().find(candidate => candidate.id === id);
    if (!record) return null;
    const fullPath = join(this.dir, record.filename);
    try {
      return statSync(fullPath).isFile() ? fullPath : null;
    } catch {
      return null;
    }
  }

  totalBytes(records: ReportRecord[] = this.readRecords()): number {
    let total = 0;
    for (const record of records) {
      try {
        const stat = statSync(join(this.dir, record.filename));
        if (stat.isFile()) total += stat.size;
      } catch { /* report remains listed as unavailable */ }
    }
    return total;
  }

  /** Exposed for bundle collision checks without revealing mutable internals. */
  directoryPath(): string {
    return this.dir;
  }

  /** Stable filename helper retained for diagnostics. */
  manifestFilename(): string {
    return basename(this.manifestPath);
  }

  /** Read-only recovery projection for preflight/dashboard/CLI surfaces. */
  getRecoveryStatus(): ReportArchiveRecoveryStatus {
    if (!existsSync(this.dir)) return { writable: true, uncertain_deletion_ids: [] };
    try {
      const { uncertain } = this.readTombstones();
      const ids = [...uncertain].sort();
      return {
        writable: ids.length === 0,
        uncertain_deletion_ids: ids,
        ...(ids.length > 0
          ? { reason: 'One or more report deletion tombstones are invalid or unreadable; report mutations are read-only and affected payloads remain preserved.' }
          : {}),
      };
    } catch (error) {
      return {
        writable: false,
        uncertain_deletion_ids: [],
        reason: `The report archive directory could not be inspected; report mutations are read-only: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }
}
