// ============================================================
// Overwatch — Evidence Store
// Persists full evidence blobs to disk with stable reference IDs.
// Inline snippets remain in the activity log for fast access;
// this store holds the full-fidelity payloads.
// ============================================================

import { existsSync, mkdirSync, writeFileSync, readFileSync, createWriteStream, type WriteStream } from 'fs';
import { join, dirname, basename } from 'path';
import { v4 as uuidv4 } from 'uuid';

// Defense-in-depth: reject evidence IDs with path traversal components
function sanitizeEvidenceId(id: string): string {
  if (id !== basename(id) || id.includes('..') || id.includes('\0')) {
    throw new Error(`Invalid evidence ID: ${id}`);
  }
  return id;
}

export interface EvidenceRecord {
  evidence_id: string;
  action_id?: string;
  finding_id?: string;
  timestamp: string;
  evidence_type: 'screenshot' | 'log' | 'file' | 'command_output';
  filename?: string;
  content_length: number;
  raw_output_length: number;
}

export class EvidenceStore {
  private dir: string;
  private manifest: EvidenceRecord[] = [];
  private manifestPath: string;

  constructor(stateFilePath: string) {
    const stateDir = dirname(stateFilePath);
    this.dir = join(stateDir, 'evidence');
    this.manifestPath = join(this.dir, 'manifest.json');
    this.ensureDir();
    this.loadManifest();
  }

  private ensureDir(): void {
    if (!existsSync(this.dir)) {
      mkdirSync(this.dir, { recursive: true });
    }
  }

  private loadManifest(): void {
    if (existsSync(this.manifestPath)) {
      try {
        this.manifest = JSON.parse(readFileSync(this.manifestPath, 'utf-8'));
      } catch {
        this.manifest = [];
      }
    }
  }

  private saveManifest(): void {
    writeFileSync(this.manifestPath, JSON.stringify(this.manifest, null, 2));
  }

  /**
   * Store evidence and/or raw_output, returning a stable evidence_id.
   * Content is written to individual files to avoid bloating state.
   */
  store(opts: {
    action_id?: string;
    finding_id?: string;
    evidence_type: 'screenshot' | 'log' | 'file' | 'command_output';
    filename?: string;
    content?: string;
    raw_output?: string;
  }): string {
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
      action_id: opts.action_id,
      finding_id: opts.finding_id,
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
    evidence_type: 'screenshot' | 'log' | 'file' | 'command_output';
    filename?: string;
    /** 'content' writes to <id>.content; 'raw_output' writes to <id>.raw. */
    kind?: 'content' | 'raw_output';
  }): {
    evidence_id: string;
    write: (chunk: Buffer | string) => void;
    end: () => Promise<void>;
  } {
    const evidenceId = uuidv4();
    const timestamp = new Date().toISOString();
    const kind = opts.kind ?? 'content';
    const ext = kind === 'raw_output' ? 'raw' : 'content';
    const path = join(this.dir, `${evidenceId}.${ext}`);
    let stream: WriteStream | null = null;
    let bytes = 0;
    let finalized = false;

    const ensureStream = (): WriteStream => {
      if (!stream) stream = createWriteStream(path, { flags: 'w' });
      return stream;
    };

    return {
      evidence_id: evidenceId,
      write: (chunk: Buffer | string) => {
        if (finalized) return;
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        bytes += buf.length;
        ensureStream().write(buf);
      },
      end: async () => {
        if (finalized) return;
        finalized = true;
        if (stream) {
          await new Promise<void>((resolve, reject) => {
            stream!.end((err?: Error | null) => err ? reject(err) : resolve());
          });
        }
        const record: EvidenceRecord = {
          evidence_id: evidenceId,
          action_id: opts.action_id,
          finding_id: opts.finding_id,
          timestamp,
          evidence_type: opts.evidence_type,
          filename: opts.filename,
          content_length: kind === 'content' ? bytes : 0,
          raw_output_length: kind === 'raw_output' ? bytes : 0,
        };
        this.manifest.push(record);
        this.saveManifest();
      },
    };
  }

  /** Retrieve full evidence content by ID. */
  getContent(evidenceId: string): string | null {
    const safe = sanitizeEvidenceId(evidenceId);
    const path = join(this.dir, `${safe}.content`);
    if (!existsSync(path)) return null;
    return readFileSync(path, 'utf-8');
  }

  /** Retrieve full raw output by ID. */
  getRawOutput(evidenceId: string): string | null {
    const safe = sanitizeEvidenceId(evidenceId);
    const path = join(this.dir, `${safe}.raw`);
    if (!existsSync(path)) return null;
    return readFileSync(path, 'utf-8');
  }

  /** Get the manifest record for a specific evidence ID. */
  getRecord(evidenceId: string): EvidenceRecord | undefined {
    return this.manifest.find(r => r.evidence_id === evidenceId);
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
