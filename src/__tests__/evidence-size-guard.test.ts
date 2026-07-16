// ============================================================
// Phase E: bounded readback for parser ingestion.
//
// _process-runner used to call EvidenceStore.getRawOutput() with no
// size guard, so a multi-hundred-MiB scanner output could OOM the MCP
// server when parsing kicked in. The new behavior:
//   - getRawOutput accepts an optional max_bytes; over the cap → null.
//   - getRawOutputHead streams the head window for partial parsing.
// This suite locks both behaviors.
// ============================================================

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { EvidenceStore } from '../services/evidence-store.js';

let testDir: string;
let stateFile: string;

function cleanup(): void {
  if (testDir) rmSync(testDir, { recursive: true, force: true });
}

describe('EvidenceStore size-bounded readback', () => {
  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-evidence-size-guard-'));
    stateFile = join(testDir, 'state.json');
  });
  afterEach(cleanup);

  it('getRawOutput honors max_bytes and returns null when the file is larger', () => {
    const store = new EvidenceStore(stateFile);
    // Manually write a fake .raw file under the store's evidence dir.
    const evidenceId = store.store({
      action_id: 'act-1',
      evidence_type: 'command_output',
      filename: 'stdout',
      raw_output: 'x'.repeat(100), // initial 100 bytes
    });

    // Then overwrite with a much larger payload (simulating a streamed write).
    const evDir = (store as unknown as { dir: string }).dir;
    const blobKey = store.getRecord(evidenceId)?.blob_key ?? evidenceId;
    const path = join(evDir, `${blobKey}.raw`);
    const big = 'a'.repeat(60 * 1024 * 1024); // 60 MiB
    writeFileSync(path, big);

    const small = store.getRawOutput(evidenceId, { max_bytes: 50 * 1024 * 1024 });
    expect(small).toBeNull();

    const unbounded = store.getRawOutput(evidenceId);
    expect(unbounded).not.toBeNull();
    expect(unbounded!.length).toBe(big.length);

  });

  it('getRawOutputHead returns the head window with truncated=true when the file overflows', () => {
    const store = new EvidenceStore(stateFile);
    const evidenceId = store.store({
      action_id: 'act-1',
      evidence_type: 'command_output',
      filename: 'stdout',
      raw_output: 'placeholder',
    });
    const evDir = (store as unknown as { dir: string }).dir;
    const blobKey = store.getRecord(evidenceId)?.blob_key ?? evidenceId;
    const path = join(evDir, `${blobKey}.raw`);
    const payload = 'HEAD' + 'x'.repeat(10 * 1024 * 1024) + 'TAIL';
    writeFileSync(path, payload);

    const head = store.getRawOutputHead(evidenceId, 1024)!;
    expect(head).not.toBeNull();
    expect(head.text.startsWith('HEAD')).toBe(true);
    expect(head.text.length).toBe(1024);
    expect(head.total_bytes).toBe(payload.length);
    expect(head.truncated).toBe(true);
  });

  it('getRawOutputHead returns the full content when the file is within budget', () => {
    const store = new EvidenceStore(stateFile);
    const evidenceId = store.store({
      action_id: 'act-1',
      evidence_type: 'command_output',
      filename: 'stdout',
      raw_output: 'small payload',
    });
    const head = store.getRawOutputHead(evidenceId, 1024)!;
    expect(head.text).toBe('small payload');
    expect(head.truncated).toBe(false);
    expect(head.total_bytes).toBe('small payload'.length);

  });

  it('getRawOutputHead returns null for missing evidence', () => {
    const store = new EvidenceStore(stateFile);
    expect(store.getRawOutputHead('missing-evidence-id', 1024)).toBeNull();
  });
});
