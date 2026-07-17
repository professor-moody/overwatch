// ============================================================
// B.2 — Persistent report archive.
//
// The archive lives at `<engagement-dir>/reports/manifest.json` plus
// one file per record. Operators (and the dashboard's /api/reports*
// endpoints) read from this archive to list past renders, download
// them, and delete obsolete ones without re-rendering.
// ============================================================

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ReportArchive } from '../services/report-archive.js';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

let tempDir: string;
let stateFilePath: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), 'overwatch-archive-test-'));
  stateFilePath = join(tempDir, 'engagement.json');
  // Touch a fake state file so the archive sees `dirname(state)` as
  // the engagement dir.
  writeFileSync(stateFilePath, '{}', 'utf8');
});

afterEach(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

describe('ReportArchive', () => {
  it('add → list → get → delete round-trip', () => {
    const archive = new ReportArchive(stateFilePath);
    expect(archive.list()).toEqual([]);

    const record = archive.add('# Hello\n\nReport body.', {
      generated_at: '2026-05-08T12:00:00Z',
      format: 'markdown',
      redaction_mode: 'operator',
      options: { include_evidence: true },
    });

    expect(record.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(record.filename).toMatch(/^[0-9a-f-]{36}\.md$/);
    expect(record.size_bytes).toBeGreaterThan(0);
    expect(record.content_sha256).toMatch(/^[0-9a-f]{64}$/);

    const list = archive.list();
    expect(list).toHaveLength(1);
    expect(list[0].id).toBe(record.id);

    const got = archive.get(record.id);
    expect(got).not.toBeNull();
    expect(got!.content.toString('utf8')).toContain('# Hello');

    const deleted = archive.delete(record.id);
    expect(deleted).toBe(true);
    expect(archive.list()).toEqual([]);
    expect(archive.get(record.id)).toBeNull();
  });

  it('persists across a fresh archive instance (manifest is durable)', () => {
    const a = new ReportArchive(stateFilePath);
    const r = a.add('alpha', {
      generated_at: '2026-05-08T12:00:00Z',
      format: 'json',
      redaction_mode: 'client_safe',
      options: {},
    });
    const b = new ReportArchive(stateFilePath);
    const list = b.list();
    expect(list).toHaveLength(1);
    expect(list[0].id).toBe(r.id);
    expect(b.get(r.id)?.content.toString('utf8')).toBe('alpha');
  });

  it('list() sorts newest first', () => {
    const archive = new ReportArchive(stateFilePath);
    archive.add('first', { generated_at: '2026-05-01T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    archive.add('second', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    const list = archive.list();
    expect(list[0].generated_at).toBe('2026-05-08T00:00:00Z');
    expect(list[1].generated_at).toBe('2026-05-01T00:00:00Z');
  });

  it('returns null when the underlying file is missing even if manifest still references it', () => {
    const archive = new ReportArchive(stateFilePath);
    const r = archive.add('content', { generated_at: '2026-05-08T00:00:00Z', format: 'html', redaction_mode: 'operator', options: {} });
    // Simulate disk corruption: delete the file but leave the manifest entry.
    const fp = archive.pathFor(r.id);
    expect(fp).not.toBeNull();
    rmSync(fp!);
    expect(archive.get(r.id)).toBeNull();
    expect(archive.pathFor(r.id)).toBeNull();
  });

  it('recovers from a corrupt manifest by starting fresh', () => {
    const archive = new ReportArchive(stateFilePath);
    archive.add('content', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    // Corrupt the manifest.
    const manifestPath = join(tempDir, 'reports', 'manifest.json');
    expect(existsSync(manifestPath)).toBe(true);
    writeFileSync(manifestPath, 'not json {{{', 'utf8');
    const fresh = new ReportArchive(stateFilePath);
    expect(fresh.list()).toEqual([]);
  });

  it('totalBytes() sums file sizes', () => {
    const archive = new ReportArchive(stateFilePath);
    archive.add('hello', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    archive.add('world!', { generated_at: '2026-05-08T00:00:01Z', format: 'json', redaction_mode: 'operator', options: {} });
    expect(archive.totalBytes()).toBe(5 + 6);
  });
});
