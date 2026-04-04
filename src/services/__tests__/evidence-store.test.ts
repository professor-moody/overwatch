import { describe, it, expect, afterEach } from 'vitest';
import { existsSync, rmSync, readFileSync } from 'fs';
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
});
