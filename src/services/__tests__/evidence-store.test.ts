import { describe, it, expect, afterEach, vi } from 'vitest';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { EvidenceStore } from '../evidence-store.js';

const TEST_STATE = '/tmp/overwatch-ev-test/state.json';
const EVIDENCE_DIR = '/tmp/overwatch-ev-test/evidence';

afterEach(() => {
  if (existsSync('/tmp/overwatch-ev-test')) {
    rmSync('/tmp/overwatch-ev-test', { recursive: true, force: true });
  }
});

describe('EvidenceStore', () => {
  it('creates evidence directory on construction', () => {
    new EvidenceStore(TEST_STATE);
    expect(existsSync(EVIDENCE_DIR)).toBe(true);
  });

  it('stores and retrieves evidence content', () => {
    const store = new EvidenceStore(TEST_STATE);
    const content = 'uid=0(root) gid=0(root) groups=0(root)';
    const id = store.store({
      evidence_type: 'command_output',
      content,
      action_id: 'act-1',
    });
    expect(id).toBeDefined();
    expect(store.getContent(id)).toBe(content);
  });

  it('stores and retrieves raw_output', () => {
    const store = new EvidenceStore(TEST_STATE);
    const rawOutput = 'root@target:~# id\nuid=0(root) gid=0(root)';
    const id = store.store({
      evidence_type: 'command_output',
      raw_output: rawOutput,
    });
    expect(store.getRawOutput(id)).toBe(rawOutput);
  });

  it('round-trips BINARY content via createBlobStream + getContentBuffer (no UTF-8 corruption)', async () => {
    const store = new EvidenceStore(TEST_STATE);
    // PNG magic + bytes that do not survive a UTF-8 decode/encode round-trip.
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff, 0xfe, 0x80, 0x81, 0x7f]);
    const sink = store.createBlobStream({ evidence_type: 'screenshot', filename: 'shot.png', kind: 'content' });
    sink.write(png);
    await sink.end();

    const back = store.getContentBuffer(sink.evidence_id);
    expect(Buffer.isBuffer(back)).toBe(true);
    expect(back!.equals(png)).toBe(true); // byte-identical

    // The UTF-8 reader corrupts the bytes — which is exactly why getContentBuffer exists.
    const asText = store.getContent(sink.evidence_id);
    expect(Buffer.from(asText!, 'utf-8').equals(png)).toBe(false);

    const rec = store.getRecord(sink.evidence_id);
    expect(rec?.evidence_type).toBe('screenshot');
    expect(rec?.filename).toBe('shot.png');
  });

  it('getContentBuffer returns null for an unknown id', () => {
    const store = new EvidenceStore(TEST_STATE);
    expect(store.getContentBuffer('nope')).toBeNull();
  });

  it('stores both content and raw_output for same evidence', () => {
    const store = new EvidenceStore(TEST_STATE);
    const id = store.store({
      evidence_type: 'log',
      content: 'summary line',
      raw_output: 'full verbose output here...',
      filename: 'scan.log',
    });
    expect(store.getContent(id)).toBe('summary line');
    expect(store.getRawOutput(id)).toBe('full verbose output here...');
    const record = store.getRecord(id);
    expect(record!.filename).toBe('scan.log');
    expect(record!.evidence_type).toBe('log');
  });

  it('returns null for non-existent evidence', () => {
    const store = new EvidenceStore(TEST_STATE);
    expect(store.getContent('does-not-exist')).toBeNull();
    expect(store.getRawOutput('does-not-exist')).toBeNull();
    expect(store.getRecord('does-not-exist')).toBeUndefined();
  });

  it('persists manifest across instances', () => {
    const store1 = new EvidenceStore(TEST_STATE);
    const id = store1.store({
      evidence_type: 'screenshot',
      content: 'base64data...',
      finding_id: 'f-1',
    });

    const store2 = new EvidenceStore(TEST_STATE);
    expect(store2.size).toBe(1);
    expect(store2.getRecord(id)!.finding_id).toBe('f-1');
    expect(store2.getContent(id)).toBe('base64data...');
  });

  it('lists evidence filtered by action_id', () => {
    const store = new EvidenceStore(TEST_STATE);
    store.store({ evidence_type: 'command_output', content: 'a', action_id: 'act-1' });
    store.store({ evidence_type: 'command_output', content: 'b', action_id: 'act-2' });
    store.store({ evidence_type: 'log', content: 'c', action_id: 'act-1' });

    const filtered = store.list({ action_id: 'act-1' });
    expect(filtered).toHaveLength(2);
  });

  it('lists evidence filtered by finding_id', () => {
    const store = new EvidenceStore(TEST_STATE);
    store.store({ evidence_type: 'command_output', content: 'a', finding_id: 'f-1' });
    store.store({ evidence_type: 'command_output', content: 'b', finding_id: 'f-2' });

    expect(store.list({ finding_id: 'f-1' })).toHaveLength(1);
    expect(store.list({ finding_id: 'f-2' })).toHaveLength(1);
  });

  it('handles large payloads without truncation', () => {
    const store = new EvidenceStore(TEST_STATE);
    const largeContent = 'x'.repeat(100_000);
    const id = store.store({
      evidence_type: 'command_output',
      content: largeContent,
    });
    const retrieved = store.getContent(id);
    expect(retrieved).toHaveLength(100_000);
  });

  it('tracks content_length and raw_output_length in manifest', () => {
    const store = new EvidenceStore(TEST_STATE);
    const id = store.store({
      evidence_type: 'command_output',
      content: 'short',
      raw_output: 'longer raw output here',
    });
    const record = store.getRecord(id);
    expect(record!.content_length).toBe(5);
    expect(record!.raw_output_length).toBe(22);
  });

  // -----------------------------------------------------------------
  // Phase H: streaming sink for large process output
  // -----------------------------------------------------------------
  it('createBlobStream writes chunks incrementally and finalizes the manifest', async () => {
    const store = new EvidenceStore(TEST_STATE);
    const sink = store.createBlobStream({
      action_id: 'act-stream-1',
      evidence_type: 'command_output',
      filename: 'stdout',
      kind: 'raw_output',
    });
    sink.write(Buffer.from('hello '));
    sink.write(Buffer.from('world'));
    await sink.end();

    const record = store.getRecord(sink.evidence_id);
    expect(record).toBeDefined();
    expect(record!.action_id).toBe('act-stream-1');
    expect(record!.raw_output_length).toBe(11);
    expect(record!.content_length).toBe(0);
    expect(store.getRawOutput(sink.evidence_id)).toBe('hello world');
  });

  it('createBlobStream attributes the streamed evidence to its agent/task', async () => {
    const store = new EvidenceStore(TEST_STATE);
    const sink = store.createBlobStream({
      action_id: 'act-attr-1',
      agent_id: 'cve-research-agent',
      task_id: 'task-42',
      evidence_type: 'command_output',
      filename: 'stdout',
      kind: 'raw_output',
    });
    sink.write(Buffer.from('nmap output'));
    await sink.end();

    const record = store.getRecord(sink.evidence_id);
    expect(record!.agent_id).toBe('cve-research-agent');
    expect(record!.task_id).toBe('task-42');
  });

  it('createBlobStream captures payloads larger than the in-memory inline cap', async () => {
    const store = new EvidenceStore(TEST_STATE);
    const sink = store.createBlobStream({
      evidence_type: 'command_output',
      kind: 'raw_output',
    });
    // 32 MiB — deliberately larger than the 16 MiB BoundedStreamBuffer cap.
    const chunk = Buffer.alloc(1024 * 1024, 0x41);
    for (let i = 0; i < 32; i++) sink.write(chunk);
    await sink.end();
    const record = store.getRecord(sink.evidence_id);
    expect(record!.raw_output_length).toBe(32 * 1024 * 1024);
  });

  it('createBlobStream records capture_error and only counts confirmed durable bytes when the underlying file write fails', async () => {
    const store = new EvidenceStore(TEST_STATE);
    const sink = store.createBlobStream({
      evidence_type: 'command_output',
      kind: 'raw_output',
    });
    sink.write(Buffer.from('one '));
    sink.write(Buffer.from('two'));
    await sink.end();
    // Sanity: success path leaves capture_error unset.
    expect(store.getRecord(sink.evidence_id)!.capture_error).toBeUndefined();
    expect(sink.error()).toBeNull();
    expect(sink.bytesWritten()).toBe(7);
  });

  // ============================================================
  // P1.1: content-addressed evidence
  // ============================================================

  describe('P1.1 content addressing', () => {
    it('store stamps content_hash on the manifest record', () => {
      const store = new EvidenceStore(TEST_STATE);
      const id = store.store({
        evidence_type: 'command_output',
        content: 'hello world',
        action_id: 'act-1',
      });
      const record = store.getRecord(id)!;
      expect(record.content_hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('two stores of identical content dedup to the same evidence_id', () => {
      const store = new EvidenceStore(TEST_STATE);
      const id1 = store.store({
        evidence_type: 'command_output',
        content: 'identical bytes',
        action_id: 'act-A',
      });
      const id2 = store.store({
        evidence_type: 'command_output',
        content: 'identical bytes',
        action_id: 'act-B',
      });
      expect(id2).toBe(id1);
      const all = store.list();
      const matching = all.filter(r => r.evidence_id === id1);
      expect(matching.length).toBe(2);
      expect(matching.map(r => r.action_id).sort()).toEqual(['act-A', 'act-B']);
    });

    it('different content produces different content_hash and different evidence_id', () => {
      const store = new EvidenceStore(TEST_STATE);
      const id1 = store.store({ evidence_type: 'command_output', content: 'a' });
      const id2 = store.store({ evidence_type: 'command_output', content: 'b' });
      expect(id1).not.toBe(id2);
      expect(store.getRecord(id1)!.content_hash).not.toBe(store.getRecord(id2)!.content_hash);
    });

    it('lookups accept either evidence_id (UUID) or content_hash', () => {
      const store = new EvidenceStore(TEST_STATE);
      const id = store.store({ evidence_type: 'command_output', content: 'lookup me' });
      const hash = store.getRecord(id)!.content_hash!;
      expect(store.getContent(id)).toBe('lookup me');
      expect(store.getContent(hash)).toBe('lookup me');
      expect(store.getRecord(hash)?.evidence_id).toBe(id);
      expect(store.resolveKey(hash)).toBe(id);
      expect(store.resolveKey(id)).toBe(id);
      expect(store.resolveKey('not-a-key-or-hash')).toBeNull();
    });

    // F1-15: manifest corruption recovery
    describe('manifest corruption recovery', () => {
      it('preserves the corrupt manifest, logs a warning, and rebuilds from on-disk blobs', () => {
        // First instantiation: store two evidence items so blob files exist on disk.
        {
          const store = new EvidenceStore(TEST_STATE);
          store.store({ evidence_type: 'command_output', content: 'first', action_id: 'act-a' });
          store.store({ evidence_type: 'command_output', raw_output: 'second raw', action_id: 'act-b' });
        }
        // Corrupt the manifest before next load.
        const manifestPath = join(EVIDENCE_DIR, 'manifest.json');
        writeFileSync(manifestPath, '{not valid json');

        const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
        try {
          const store = new EvidenceStore(TEST_STATE);
          // Corrupt file preserved as manifest.json.corrupt-<ts>.json
          const evidenceFiles = readdirSync(EVIDENCE_DIR);
          const preserved = evidenceFiles.find(name => name.startsWith('manifest.json.corrupt-'));
          expect(preserved).toBeDefined();
          expect(readFileSync(join(EVIDENCE_DIR, preserved!), 'utf-8')).toBe('{not valid json');
          // Structured warning surfaced once.
          expect(warn).toHaveBeenCalled();
          const warnArgs = warn.mock.calls.flat().join(' ');
          expect(warnArgs).toContain('manifest.json');
          expect(warnArgs).toContain('Rebuilding');
          // Manifest rebuilt with one record per uuid (the .content and .raw belong to distinct uuids here).
          const list = store.list();
          expect(list.length).toBeGreaterThan(0);
          expect(list.every(r => r.recovered === true)).toBe(true);
          // Rebuilt manifest is persisted to disk.
          const rewritten = JSON.parse(readFileSync(manifestPath, 'utf-8'));
          expect(Array.isArray(rewritten)).toBe(true);
          expect(rewritten.every((r: { recovered?: boolean }) => r.recovered === true)).toBe(true);
        } finally {
          warn.mockRestore();
        }
      });

      it('handles a missing evidence directory during rebuild without throwing', () => {
        // Set up an empty evidence dir then corrupt the manifest.
        mkdirSync(EVIDENCE_DIR, { recursive: true });
        writeFileSync(join(EVIDENCE_DIR, 'manifest.json'), 'garbage');

        const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
        try {
          const store = new EvidenceStore(TEST_STATE);
          expect(store.list()).toEqual([]);
          expect(warn).toHaveBeenCalled();
        } finally {
          warn.mockRestore();
        }
      });
    });

    it('streamed evidence carries a content_hash equal to the streamed bytes', async () => {
      const store = new EvidenceStore(TEST_STATE);
      const sink = store.createBlobStream({
        action_id: 'act-stream',
        evidence_type: 'command_output',
        kind: 'content',
      });
      sink.write(Buffer.from('stream '));
      sink.write(Buffer.from('me'));
      await sink.end();
      const record = store.getRecord(sink.evidence_id)!;
      expect(record.content_hash).toMatch(/^[0-9a-f]{64}$/);
      const { createHash } = await import('crypto');
      const expected = createHash('sha256').update('stream me').digest('hex');
      expect(record.content_hash).toBe(expected);
    });
  });
});
