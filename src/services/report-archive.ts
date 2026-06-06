// ============================================================
// Report archive: durable per-engagement store of generated reports.
//
// Each engagement gets a `<engagement-dir>/reports/` subdirectory with a
// `manifest.json` index and one file per record (`<id>.<ext>`). The
// index lets the dashboard list past renders, and each record carries
// enough metadata (format, redaction mode, render options) for the
// operator to pick the right one without re-rendering.
// ============================================================

import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { createHash, randomUUID } from 'crypto';

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

const MANIFEST_NAME = 'manifest.json';

const EXT_BY_FORMAT: Record<ReportFormat, string> = {
  markdown: 'md',
  html: 'html',
  json: 'json',
  pdf: 'pdf',
};

export class ReportArchive {
  private dir: string;
  private manifestPath: string;
  private cache: ReportRecord[] | null = null;

  /**
   * @param engagementStateFilePath - path to the engagement's state file
   *   (e.g. `./engagement.json`). The archive lives in
   *   `<dirname(state)>/reports/`. Created on first write.
   */
  constructor(engagementStateFilePath: string) {
    this.dir = join(dirname(engagementStateFilePath), 'reports');
    this.manifestPath = join(this.dir, MANIFEST_NAME);
  }

  private ensureDir(): void {
    if (!existsSync(this.dir)) mkdirSync(this.dir, { recursive: true });
  }

  private loadManifest(): ReportRecord[] {
    if (this.cache) return this.cache;
    if (!existsSync(this.manifestPath)) {
      this.cache = [];
      return this.cache;
    }
    try {
      const raw = readFileSync(this.manifestPath, 'utf8');
      const parsed = JSON.parse(raw);
      // Defensive: require an array; corrupted manifest → start fresh
      // (records on disk become orphaned but recoverable manually).
      this.cache = Array.isArray(parsed) ? parsed as ReportRecord[] : [];
    } catch {
      this.cache = [];
    }
    return this.cache;
  }

  private writeManifest(records: ReportRecord[]): void {
    this.ensureDir();
    writeFileSync(this.manifestPath, JSON.stringify(records, null, 2), 'utf8');
    this.cache = records;
  }

  /**
   * Add a rendered report to the archive. Writes the file to disk and
   * appends a manifest entry. Returns the new record. Buffer is preferred
   * for binary formats (pdf); strings auto-encode to utf8.
   */
  add(
    content: Buffer | string,
    meta: Omit<ReportRecord, 'id' | 'filename' | 'size_bytes' | 'content_sha256'>,
  ): ReportRecord {
    this.ensureDir();
    const id = randomUUID();
    const ext = EXT_BY_FORMAT[meta.format];
    const filename = `${id}.${ext}`;
    const fullPath = join(this.dir, filename);
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    writeFileSync(fullPath, buf);
    const sha = createHash('sha256').update(buf).digest('hex');
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
      content_sha256: sha,
      options: meta.options,
    };
    const records = this.loadManifest();
    records.push(record);
    this.writeManifest(records);
    return record;
  }

  /** List all archive entries, newest first. */
  list(): ReportRecord[] {
    const records = this.loadManifest();
    return [...records].sort((a, b) => b.generated_at.localeCompare(a.generated_at));
  }

  /** Get a record + content. Returns null if the manifest entry is missing OR the file on disk is gone. */
  get(id: string): { record: ReportRecord; content: Buffer } | null {
    const record = this.loadManifest().find(r => r.id === id);
    if (!record) return null;
    const fullPath = join(this.dir, record.filename);
    if (!existsSync(fullPath)) return null;
    const content = readFileSync(fullPath);
    return { record, content };
  }

  /** Returns true on successful delete, false when the id is unknown. */
  delete(id: string): boolean {
    const records = this.loadManifest();
    const idx = records.findIndex(r => r.id === id);
    if (idx < 0) return false;
    const record = records[idx];
    const fullPath = join(this.dir, record.filename);
    try { if (existsSync(fullPath)) unlinkSync(fullPath); } catch { /* leave manifest consistent */ }
    records.splice(idx, 1);
    this.writeManifest(records);
    return true;
  }

  /** Returns the absolute path to the on-disk file for a record, or null if missing. */
  pathFor(id: string): string | null {
    const record = this.loadManifest().find(r => r.id === id);
    if (!record) return null;
    const fullPath = join(this.dir, record.filename);
    if (!existsSync(fullPath)) return null;
    return fullPath;
  }

  /** Total bytes used by all archived reports (manifest excluded). */
  totalBytes(): number {
    let total = 0;
    for (const r of this.loadManifest()) {
      const fp = join(this.dir, r.filename);
      try { total += statSync(fp).size; } catch { /* file gone */ }
    }
    return total;
  }
}
