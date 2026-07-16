import { describe, it, expect, afterEach, vi } from 'vitest';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { spawn, type ChildProcess } from 'child_process';
import { createHash } from 'crypto';
import { once } from 'events';
import { join, resolve } from 'path';
import { pathToFileURL } from 'url';
import { EvidenceStore } from '../evidence-store.js';

const TEST_STATE = '/tmp/overwatch-ev-test/state.json';
const EVIDENCE_DIR = '/tmp/overwatch-ev-test/evidence';
const evidenceStoreModuleUrl = pathToFileURL(
  resolve('src/services/evidence-store.ts'),
).href;

function spawnTypeScript(script: string, args: string[]): ChildProcess {
  return spawn(
    process.execPath,
    ['--import', 'tsx', '--input-type=module', '-e', script, ...args],
    {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, NODE_NO_WARNINGS: '1' },
    },
  );
}

async function waitForReady(child: ChildProcess): Promise<void> {
  await new Promise<void>((resolveReady, reject) => {
    let stdout = '';
    const timeout = setTimeout(() => {
      reject(new Error(`evidence writer did not become ready; stdout=${stdout}`));
    }, 5_000);
    child.once('error', error => {
      clearTimeout(timeout);
      reject(error);
    });
    child.stdout!.on('data', chunk => {
      stdout += String(chunk);
      if (!stdout.includes('ready\n')) return;
      clearTimeout(timeout);
      resolveReady();
    });
  });
}

async function waitForExit(
  child: ChildProcess,
): Promise<{ code: number | null; signal: NodeJS.Signals | null; stderr: string }> {
  let stderr = '';
  child.stderr?.on('data', chunk => { stderr += String(chunk); });
  if (child.exitCode === null && child.signalCode === null) {
    const [code, signal] = await once(child, 'exit') as [number | null, NodeJS.Signals | null];
    return { code, signal, stderr };
  }
  return {
    code: child.exitCode,
    signal: child.signalCode as NodeJS.Signals | null,
    stderr,
  };
}

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

  it('retries pending directory fsync work after recursive creation became visible', () => {
    let calls = 0;
    const syncDirectory = vi.fn(() => {
      calls++;
      if (calls === 1) throw new Error('synthetic evidence directory fsync failure');
    });

    expect(() => new EvidenceStore(TEST_STATE, { syncDirectory }))
      .toThrow('synthetic evidence directory fsync failure');
    expect(existsSync(EVIDENCE_DIR)).toBe(true);

    expect(() => new EvidenceStore(TEST_STATE, { syncDirectory })).not.toThrow();
    expect(syncDirectory.mock.calls.length).toBeGreaterThan(1);
  });

  it('fsyncs the evidence directory after publishing blob, recovery descriptor, and manifest renames', () => {
    const syncDirectory = vi.fn();
    const store = new EvidenceStore(TEST_STATE, { syncDirectory });
    syncDirectory.mockClear();

    store.store({ evidence_type: 'command_output', content: 'durable evidence' });

    expect(syncDirectory).toHaveBeenCalledTimes(3);
    expect(syncDirectory).toHaveBeenNthCalledWith(1, EVIDENCE_DIR);
    expect(syncDirectory).toHaveBeenNthCalledWith(2, EVIDENCE_DIR);
    expect(syncDirectory).toHaveBeenNthCalledWith(3, EVIDENCE_DIR);
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

  it('does not hang when a backpressured write errors (drain never fires)', async () => {
    const store = new EvidenceStore(TEST_STATE);
    // Remove the evidence dir so the lazy createWriteStream fails (ENOENT) on first write.
    rmSync(EVIDENCE_DIR, { recursive: true, force: true });
    const sink = store.createBlobStream({ evidence_type: 'screenshot', filename: 'big.bin', kind: 'content' });
    // A chunk larger than the 16KB highWaterMark → write() returns false (backpressure),
    // then the stream errors — before the fix the writeChunk promise waited for a 'drain'
    // that never comes, so end() (which awaits the write chain) hung forever.
    sink.write(Buffer.alloc(64 * 1024, 0x41));
    const outcome = await Promise.race([
      sink.end().then(() => 'settled').catch(() => 'settled'),
      new Promise<string>(r => setTimeout(() => r('timeout'), 1500)),
    ]);
    expect(outcome).toBe('settled');       // did NOT hang
    expect(sink.error()).toBeTruthy();     // the capture error is surfaced, not swallowed
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

  it('merges stale cooperating writers instead of losing a newer manifest row', () => {
    const first = new EvidenceStore(TEST_STATE);
    const second = new EvidenceStore(TEST_STATE);

    const firstId = first.store({
      evidence_type: 'command_output',
      content: 'first writer',
      action_id: 'act-first',
    });
    const secondId = second.store({
      evidence_type: 'command_output',
      content: 'second writer',
      action_id: 'act-second',
    });

    const reopened = new EvidenceStore(TEST_STATE);
    expect(reopened.list().map(record => record.action_id).sort()).toEqual([
      'act-first',
      'act-second',
    ]);
    expect(reopened.getContent(firstId)).toBe('first writer');
    expect(reopened.getContent(secondId)).toBe('second writer');
  });

  it('serializes two stale child-process writers and preserves both references', async () => {
    const readyA = '/tmp/overwatch-ev-test/ready-a';
    const readyB = '/tmp/overwatch-ev-test/ready-b';
    const go = '/tmp/overwatch-ev-test/go';
    const script = `
      import { existsSync, writeFileSync } from 'fs';
      import { EvidenceStore } from ${JSON.stringify(evidenceStoreModuleUrl)};
      const [statePath, readyPath, goPath, content, actionId] = process.argv.slice(1);
      const wait = new Int32Array(new SharedArrayBuffer(4));
      const store = new EvidenceStore(statePath);
      writeFileSync(readyPath, String(process.pid));
      process.stdout.write('ready\\n');
      while (!existsSync(goPath)) Atomics.wait(wait, 0, 0, 10);
      store.store({ evidence_type: 'command_output', content, action_id: actionId });
    `;
    const first = spawnTypeScript(script, [
      TEST_STATE,
      readyA,
      go,
      'child writer A',
      'act-child-a',
    ]);
    const second = spawnTypeScript(script, [
      TEST_STATE,
      readyB,
      go,
      'child writer B',
      'act-child-b',
    ]);

    try {
      await Promise.all([waitForReady(first), waitForReady(second)]);
      expect(existsSync(readyA)).toBe(true);
      expect(existsSync(readyB)).toBe(true);
      writeFileSync(go, 'go');
      const [firstExit, secondExit] = await Promise.all([
        waitForExit(first),
        waitForExit(second),
      ]);
      expect(firstExit.code, firstExit.stderr).toBe(0);
      expect(secondExit.code, secondExit.stderr).toBe(0);

      const reopened = new EvidenceStore(TEST_STATE);
      const records = reopened.list();
      expect(records.map(record => record.action_id).sort()).toEqual([
        'act-child-a',
        'act-child-b',
      ]);
      for (const record of records) {
        expect(record.blob_key).toBe(record.content_hash);
        expect(existsSync(join(EVIDENCE_DIR, `${record.blob_key}.content`))).toBe(true);
      }
    } finally {
      if (first.exitCode === null && first.signalCode === null) {
        first.kill('SIGKILL');
        await waitForExit(first);
      }
      if (second.exitCode === null && second.signalCode === null) {
        second.kill('SIGKILL');
        await waitForExit(second);
      }
    }
  }, 15_000);

  it('recovers an orphaned content-addressed blob after a writer dies before manifest commit', async () => {
    const content = 'blob landed before reference';
    const contentHash = createHash('sha256')
      .update(content)
      .update('\0')
      .digest('hex');
    const script = `
      import { EvidenceStore } from ${JSON.stringify(evidenceStoreModuleUrl)};
      const [statePath, content] = process.argv.slice(1);
      let armed = false;
      const store = new EvidenceStore(statePath, {
        syncDirectory: () => {
          if (armed) process.kill(process.pid, 'SIGKILL');
        },
      });
      process.stdout.write('ready\\n');
      armed = true;
      store.store({ evidence_type: 'command_output', content, action_id: 'act-crashed' });
    `;
    const child = spawnTypeScript(script, [TEST_STATE, content]);

    try {
      await waitForReady(child);
      const crashed = await waitForExit(child);
      expect(crashed.signal).toBe('SIGKILL');
      expect(existsSync(join(EVIDENCE_DIR, `${contentHash}.content`))).toBe(true);
      expect(existsSync(join(EVIDENCE_DIR, 'manifest.json'))).toBe(false);

      const recovered = new EvidenceStore(TEST_STATE);
      const id = recovered.store({
        evidence_type: 'command_output',
        content,
        action_id: 'act-retry',
      });
      expect(recovered.getContent(id)).toBe(content);
      expect(recovered.getRecord(id)).toMatchObject({
        blob_key: contentHash,
        content_hash: contentHash,
        action_id: 'act-retry',
      });
      const manifest = JSON.parse(
        readFileSync(join(EVIDENCE_DIR, 'manifest.json'), 'utf8'),
      ) as Array<{ blob_key?: string }>;
      expect(manifest).toHaveLength(1);
      expect(manifest[0].blob_key).toBe(contentHash);
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL');
        await waitForExit(child);
      }
    }
  }, 10_000);

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
      expect(record.blob_key).toBe(record.content_hash);
      expect(existsSync(join(EVIDENCE_DIR, `${record.content_hash}.content`))).toBe(true);
      expect(existsSync(join(EVIDENCE_DIR, `${id}.content`))).toBe(false);
    });

    it('continues reading legacy UUID-keyed blobs without a blob_key field', () => {
      const evidenceId = '11111111-1111-4111-8111-111111111111';
      mkdirSync(EVIDENCE_DIR, { recursive: true });
      writeFileSync(join(EVIDENCE_DIR, `${evidenceId}.content`), 'legacy bytes');
      writeFileSync(join(EVIDENCE_DIR, 'manifest.json'), JSON.stringify([{
        evidence_id: evidenceId,
        content_hash: 'a'.repeat(64),
        timestamp: '2026-01-01T00:00:00.000Z',
        evidence_type: 'command_output',
        content_length: 12,
        raw_output_length: 0,
      }]));

      const store = new EvidenceStore(TEST_STATE);

      expect(store.getContent(evidenceId)).toBe('legacy bytes');
      expect(store.getContent('a'.repeat(64))).toBe('legacy bytes');
      expect(store.getRecord(evidenceId)?.blob_key).toBeUndefined();
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

    it('recovers every deduplicated attribution when the manifest is lost', () => {
      const first = new EvidenceStore(TEST_STATE);
      const id = first.store({
        evidence_type: 'command_output',
        content: 'shared attribution bytes',
        action_id: 'act-A',
        finding_id: 'finding-A',
      });
      expect(first.store({
        evidence_type: 'command_output',
        content: 'shared attribution bytes',
        action_id: 'act-B',
        finding_id: 'finding-B',
      })).toBe(id);
      rmSync(join(EVIDENCE_DIR, 'manifest.json'), { force: true });

      const recovered = new EvidenceStore(TEST_STATE);
      expect(recovered.list()
        .filter(record => record.evidence_id === id)
        .map(record => [record.action_id, record.finding_id])
        .sort()).toEqual([
        ['act-A', 'finding-A'],
        ['act-B', 'finding-B'],
      ]);
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
      it.each(['corrupt', 'delete'] as const)(
        'preserves the public UUID when the aggregate manifest is %s',
        (mode) => {
          const first = new EvidenceStore(TEST_STATE);
          const id = first.store({
            evidence_type: 'command_output',
            content: 'stable public evidence',
            raw_output: 'full stable output',
            action_id: 'act-stable',
            finding_id: 'finding-stable',
          });
          expect(id).toMatch(/^[0-9a-f-]{36}$/i);

          const manifestPath = join(EVIDENCE_DIR, 'manifest.json');
          if (mode === 'corrupt') writeFileSync(manifestPath, '{broken');
          else rmSync(manifestPath, { force: true });

          const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
          try {
            const recovered = new EvidenceStore(TEST_STATE);
            expect(recovered.getContent(id)).toBe('stable public evidence');
            expect(recovered.getRawOutput(id)).toBe('full stable output');
            expect(recovered.getRecord(id)).toMatchObject({
              evidence_id: id,
              action_id: 'act-stable',
              finding_id: 'finding-stable',
              recovered: true,
            });
            const rewritten = JSON.parse(
              readFileSync(manifestPath, 'utf8'),
            ) as Array<{ evidence_id: string }>;
            expect(rewritten.some(record => record.evidence_id === id)).toBe(true);
          } finally {
            warn.mockRestore();
          }
        },
      );

      it('backfills a descriptor for a current hash-keyed manifest before corruption', () => {
        const first = new EvidenceStore(TEST_STATE);
        const id = first.store({
          evidence_type: 'command_output',
          content: 'pre-descriptor evidence',
          action_id: 'act-before-upgrade',
        });
        const descriptorPath = join(EVIDENCE_DIR, `${id}.record.json`);
        rmSync(descriptorPath, { force: true });
        expect(existsSync(descriptorPath)).toBe(false);

        // Opening the still-valid current manifest performs the one-time
        // descriptor backfill for records written by older binaries.
        new EvidenceStore(TEST_STATE);
        expect(existsSync(descriptorPath)).toBe(true);

        writeFileSync(join(EVIDENCE_DIR, 'manifest.json'), '{broken after upgrade');
        const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
        try {
          const recovered = new EvidenceStore(TEST_STATE);
          expect(recovered.getContent(id)).toBe('pre-descriptor evidence');
          expect(recovered.getRecord(id)).toMatchObject({
            evidence_id: id,
            action_id: 'act-before-upgrade',
            recovered: true,
          });
        } finally {
          warn.mockRestore();
        }
      });

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
          // Manifest rebuilt from per-UUID descriptors (with blob scanning as
          // a fallback for legacy or interrupted writes).
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
      const expected = createHash('sha256').update('stream me').digest('hex');
      expect(record.content_hash).toBe(expected);
      expect(record.blob_key).toBe(expected);
      expect(existsSync(join(EVIDENCE_DIR, `${expected}.content`))).toBe(true);
      expect(existsSync(join(EVIDENCE_DIR, `${sink.evidence_id}.content`))).toBe(false);
    });
  });
});
