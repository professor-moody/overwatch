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
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomUUID } from 'crypto';

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
  it('reports an unreadable archive root without throwing the recovery endpoint', () => {
    writeFileSync(join(tempDir, 'reports'), 'not a directory');
    expect(new ReportArchive(stateFilePath).getRecoveryStatus()).toMatchObject({
      writable: false,
      uncertain_deletion_ids: [],
      reason: expect.stringContaining('could not be inspected'),
    });
  });

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

  it('quarantines a corrupt manifest and reconstructs every report', () => {
    const archive = new ReportArchive(stateFilePath);
    archive.add('content', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    // Corrupt the manifest.
    const manifestPath = join(tempDir, 'reports', 'manifest.json');
    expect(existsSync(manifestPath)).toBe(true);
    const corrupt = 'not json {{{';
    writeFileSync(manifestPath, corrupt, 'utf8');
    const fresh = new ReportArchive(stateFilePath);
    expect(fresh.list()).toHaveLength(1);
    expect(fresh.list()[0].content_sha256).toMatch(/^[0-9a-f]{64}$/);
    const quarantine = readdirSync(join(tempDir, 'reports')).find(name => name.startsWith('manifest.json.corrupt-'));
    expect(quarantine).toBeDefined();
    expect(readFileSync(join(tempDir, 'reports', quarantine!), 'utf8')).toBe(corrupt);
  });

  it('does not overwrite corrupt manifest bytes when quarantine fails', () => {
    const archive = new ReportArchive(stateFilePath);
    archive.add('content', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    const manifestPath = join(tempDir, 'reports', 'manifest.json');
    const corrupt = '{irreplaceable corrupt bytes';
    writeFileSync(manifestPath, corrupt);
    const failed = new ReportArchive(stateFilePath, {
      renameFile: () => { throw new Error('synthetic report quarantine failure'); },
    });
    expect(() => failed.list()).toThrow('synthetic report quarantine failure');
    expect(readFileSync(manifestPath, 'utf8')).toBe(corrupt);
  });

  it('never quarantines or rewrites corrupt bytes during read-only recovery', () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('preserve me', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    const manifestPath = join(tempDir, 'reports', 'manifest.json');
    const corrupt = '{diagnostic manifest bytes';
    writeFileSync(manifestPath, corrupt);
    const readOnly = new ReportArchive(stateFilePath, { isWritable: () => false });
    expect(readOnly.list().map(item => item.id)).toEqual([record.id]);
    expect(readFileSync(manifestPath, 'utf8')).toBe(corrupt);
    expect(readdirSync(join(tempDir, 'reports')).some(name => name.startsWith('manifest.json.corrupt-'))).toBe(false);
  });

  it('recovers a committed descriptor after aggregate-manifest loss', () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('descriptor-backed', {
      generated_at: '2026-05-08T00:00:00Z',
      format: 'markdown',
      redaction_mode: 'operator',
      options: {},
    });
    rmSync(join(tempDir, 'reports', 'manifest.json'));

    const recovered = new ReportArchive(stateFilePath);
    expect(recovered.list().map(item => item.id)).toEqual([record.id]);
    expect(recovered.get(record.id)?.content.toString()).toBe('descriptor-backed');
  });

  it('rejects invalid optional metadata in both manifests and descriptors', () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('metadata must remain schema-safe', {
      generated_at: '2026-05-08T00:00:00Z',
      format: 'markdown',
      redaction_mode: 'operator',
      profile: 'operator',
      evidence_style: 'proof_cards',
      findings_count: 1,
      evidence_count: 2,
      options: { include_evidence: true },
    });
    const reports = join(tempDir, 'reports');
    const manifestPath = join(reports, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest[0].findings_count = -1;
    writeFileSync(manifestPath, JSON.stringify(manifest));
    const descriptorPath = join(reports, `${record.id}.record.json`);
    const descriptor = JSON.parse(readFileSync(descriptorPath, 'utf8'));
    descriptor.record.profile = 'unsafe-profile';
    descriptor.record.options.include_evidence = 'yes';
    writeFileSync(descriptorPath, JSON.stringify(descriptor));

    expect(new ReportArchive(stateFilePath).list()).toEqual([]);
    expect(existsSync(join(reports, record.filename))).toBe(true);
    expect(readdirSync(reports).some(name => name.startsWith('manifest.json.corrupt-'))).toBe(true);
  });

  it('does not resurrect descriptorless payloads in the descriptor-authoritative format', () => {
    const archive = new ReportArchive(stateFilePath);
    const first = archive.add('first payload', {
      generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {},
    });
    const second = archive.add('second payload', {
      generated_at: '2026-05-08T00:00:01Z', format: 'markdown', redaction_mode: 'operator', options: {},
    });
    const reports = join(tempDir, 'reports');
    rmSync(join(reports, 'manifest.json'));
    writeFileSync(join(reports, `${second.id}.record.json`), '{damaged descriptor');

    const recovered = new ReportArchive(stateFilePath);
    expect(recovered.list().map(item => item.id)).toEqual([first.id]);
    expect(recovered.get(second.id)).toBeNull();
  });

  it('projects legacy payloads read-only when aggregate authority is absent', () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('legacy payload', {
      generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {},
    });
    const reports = join(tempDir, 'reports');
    rmSync(join(reports, 'manifest.json'));
    rmSync(join(reports, `${record.id}.record.json`));
    rmSync(join(reports, 'archive-format.json'));
    const readOnly = new ReportArchive(stateFilePath, { isWritable: () => false });
    expect(readOnly.list().map(item => item.id)).toEqual([record.id]);
    expect(existsSync(join(reports, 'manifest.json'))).toBe(false);
    expect(existsSync(join(reports, `${record.id}.record.json`))).toBe(false);
  });

  it('does not promote an orphan payload when a valid legacy manifest is authoritative', () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('listed legacy payload', {
      generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {},
    });
    const reports = join(tempDir, 'reports');
    rmSync(join(reports, 'archive-format.json'));
    rmSync(join(reports, `${record.id}.record.json`));
    const orphanId = randomUUID();
    writeFileSync(join(reports, `${orphanId}.md`), 'uncommitted orphan');

    expect(new ReportArchive(stateFilePath).list().map(item => item.id)).toEqual([record.id]);
    expect(existsSync(join(reports, `${orphanId}.md`))).toBe(true);
    expect(existsSync(join(reports, `${orphanId}.record.json`))).toBe(false);

    rmSync(join(reports, 'archive-format.json'));
    const readOnly = new ReportArchive(stateFilePath, { isWritable: () => false });
    expect(readOnly.list().map(item => item.id)).toEqual([record.id]);
  });

  it('serializes stale archive instances without losing either report', () => {
    const first = new ReportArchive(stateFilePath);
    const second = new ReportArchive(stateFilePath);
    const a = first.add('a', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    const b = second.add('b', { generated_at: '2026-05-08T00:00:01Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    expect(new Set(first.list().map(record => record.id))).toEqual(new Set([a.id, b.id]));
  });

  it('returns committed success when descriptor publication precedes a manifest fsync failure', () => {
    const seed = new ReportArchive(stateFilePath);
    seed.add('seed', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    let syncs = 0;
    const archive = new ReportArchive(stateFilePath, {
      syncDirectory: () => {
        syncs++;
        if (syncs === 5) throw new Error('synthetic aggregate manifest fsync failure');
      },
    });
    const committed = archive.add('committed once', {
      generated_at: '2026-05-08T00:00:01Z', format: 'markdown', redaction_mode: 'operator', options: {},
    });
    expect(committed).toMatchObject({
      manifest_persisted: false,
      warning: expect.stringContaining('aggregate manifest repair is pending'),
    });
    expect(existsSync(join(tempDir, 'reports', `${committed.id}.record.json`))).toBe(true);
    expect(new ReportArchive(stateFilePath).get(committed.id)?.content.toString()).toBe('committed once');
  });

  it('reports a visible but durability-unconfirmed descriptor when directory fsync fails', () => {
    const seed = new ReportArchive(stateFilePath);
    seed.list(); // establish the descriptor-authoritative archive marker
    let syncs = 0;
    const archive = new ReportArchive(stateFilePath, {
      syncDirectory: () => {
        syncs++;
        if (syncs === 3) throw new Error('synthetic descriptor directory fsync failure');
      },
    });
    const committed = archive.add('visible descriptor', {
      generated_at: '2026-05-08T00:00:01Z', format: 'markdown', redaction_mode: 'operator', options: {},
    });
    expect(committed).toMatchObject({
      manifest_persisted: false,
      commit_durability: 'uncertain',
      warning: expect.stringContaining('descriptor is visible'),
    });
    expect(new ReportArchive(stateFilePath).get(committed.id)?.content.toString()).toBe('visible descriptor');
  });

  it('does not resurrect a tombstoned report from an older manifest', () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('delete me', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    const manifestPath = join(tempDir, 'reports', 'manifest.json');
    const staleManifest = readFileSync(manifestPath);
    expect(archive.delete(record.id)).toBe(true);
    writeFileSync(manifestPath, staleManifest);
    expect(new ReportArchive(stateFilePath).list()).toEqual([]);
  });

  it('returns committed deletion when aggregate cleanup fails after the tombstone', () => {
    const seed = new ReportArchive(stateFilePath);
    const record = seed.add('delete exactly once', {
      generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {},
    });
    let syncs = 0;
    const archive = new ReportArchive(stateFilePath, {
      syncDirectory: () => {
        syncs++;
        if (syncs === 2) throw new Error('synthetic delete cleanup failure');
      },
    });
    expect(archive.deleteWithStatus(record.id)).toMatchObject({
      deleted: true,
      cleanup_complete: false,
      warning: expect.stringContaining('cleanup is pending'),
    });
    expect(new ReportArchive(stateFilePath).list()).toEqual([]);
  });

  it('reports a visible but durability-unconfirmed deletion when tombstone fsync fails', () => {
    const seed = new ReportArchive(stateFilePath);
    const record = seed.add('delete with uncertain fsync', {
      generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {},
    });
    let syncs = 0;
    const archive = new ReportArchive(stateFilePath, {
      syncDirectory: () => {
        syncs++;
        if (syncs === 1) throw new Error('synthetic tombstone directory fsync failure');
      },
    });
    expect(archive.deleteWithStatus(record.id)).toMatchObject({
      deleted: true,
      cleanup_complete: false,
      commit_durability: 'uncertain',
      warning: expect.stringContaining('tombstone is visible'),
    });
    expect(new ReportArchive(stateFilePath).list()).toEqual([]);
  });

  it('fails closed without destroying bytes when a deletion tombstone is invalid', () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('preserve behind ambiguous deletion', {
      generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {},
    });
    const reports = join(tempDir, 'reports');
    writeFileSync(join(reports, `${record.id}.deleted.json`), '{invalid tombstone');

    const recovered = new ReportArchive(stateFilePath);
    expect(recovered.list()).toEqual([]);
    expect(existsSync(join(reports, record.filename))).toBe(true);
    expect(existsSync(join(reports, `${record.id}.record.json`))).toBe(true);
    expect(() => recovered.add('blocked', {
      generated_at: '2026-05-08T00:00:01Z', format: 'markdown', redaction_mode: 'operator', options: {},
    })).toThrow(/recovery is read-only/i);
  });

  it('bounds oversized tombstone metadata and preserves the hidden report', () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('preserve behind oversized tombstone', {
      generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {},
    });
    const reports = join(tempDir, 'reports');
    writeFileSync(join(reports, `${record.id}.deleted.json`), Buffer.alloc(64 * 1024 + 1, 0x61));
    expect(new ReportArchive(stateFilePath).list()).toEqual([]);
    expect(existsSync(join(reports, record.filename))).toBe(true);
  });

  it('resumes payload and descriptor cleanup after a tombstone-only crash', () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('delete after restart', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    const reports = join(tempDir, 'reports');
    writeFileSync(join(reports, `${record.id}.deleted.json`), JSON.stringify({
      tombstone_version: 1,
      report_id: record.id,
      deleted_at: '2026-05-09T00:00:00Z',
    }));
    expect(existsSync(join(reports, record.filename))).toBe(true);
    expect(new ReportArchive(stateFilePath).list()).toEqual([]);
    expect(existsSync(join(reports, record.filename))).toBe(false);
    expect(existsSync(join(reports, `${record.id}.record.json`))).toBe(false);
  });

  it('refuses to serve content whose bytes no longer match the record', () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('original', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    writeFileSync(join(tempDir, 'reports', record.filename), 'tampered');
    expect(archive.get(record.id)).toBeNull();
  });

  it('distinguishes unavailable and integrity-failed payloads without buffering them', async () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('original', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    const verified = await archive.verifyForRead(record.id);
    expect(verified.status).toBe('ok');
    if (verified.status === 'ok') await verified.handle.close();
    writeFileSync(join(tempDir, 'reports', record.filename), 'tampered');
    expect((await archive.verifyForRead(record.id)).status).toBe('integrity_failed');
    rmSync(join(tempDir, 'reports', record.filename));
    expect((await archive.verifyForRead(record.id)).status).toBe('unavailable');
    expect((await archive.verifyForRead('00000000-0000-4000-8000-000000000000')).status).toBe('not_found');
  });

  it('streams the verified inode even when deletion unlinks its pathname', async () => {
    const archive = new ReportArchive(stateFilePath);
    const record = archive.add('pinned report bytes', {
      generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {},
    });
    const verified = await archive.verifyForRead(record.id);
    expect(verified.status).toBe('ok');
    if (verified.status !== 'ok') return;
    expect(archive.delete(record.id)).toBe(true);
    const chunks: Buffer[] = [];
    for await (const chunk of verified.handle.createReadStream({ autoClose: true, start: 0 })) {
      chunks.push(chunk as Buffer);
    }
    expect(Buffer.concat(chunks).toString()).toBe('pinned report bytes');
  });

  it('totalBytes() sums file sizes', () => {
    const archive = new ReportArchive(stateFilePath);
    archive.add('hello', { generated_at: '2026-05-08T00:00:00Z', format: 'markdown', redaction_mode: 'operator', options: {} });
    archive.add('world!', { generated_at: '2026-05-08T00:00:01Z', format: 'json', redaction_mode: 'operator', options: {} });
    expect(archive.totalBytes()).toBe(5 + 6);
  });
});
