import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { publishManagedDaemonShutdownOutcome } from '../managed-daemon-record.js';

// L6: readCurrent is not exported; drive it through publishManagedDaemonShutdownOutcome,
// which needs the managed-daemon env set. A malformed record must be REJECTED (shape
// check), matching the sibling owner/lease readers — not trusted and rewritten.
describe('managed daemon record — shape validation (L6)', () => {
  const NONCE = 'test-management-nonce';
  let dir: string;
  let recordPath: string;
  const saved: Record<string, string | undefined> = {};

  function validRecord(): Record<string, unknown> {
    return {
      version: 1,
      management_nonce: NONCE,
      pid: process.pid,
      process_start_identity: 'psi',
      daemon_instance_id: 'di',
      runtime_instance_id: 'ri',
      runtime_started_at: '2026-07-24T00:00:00Z',
      build_input_sha256: 'a'.repeat(64),
      engagement_id: 'eng',
      config_path: '/tmp/config.json',
      state_file_path: '/tmp/state.json',
      config_identity_sha256: 'b'.repeat(64),
      state_identity_sha256: 'c'.repeat(64),
      transport: 'http',
      phase: 'ready',
      managed_at: '2026-07-24T00:00:00Z',
      updated_at: '2026-07-24T00:00:00Z',
    };
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-mdr-'));
    recordPath = join(dir, 'record.json');
    for (const k of ['OVERWATCH_DAEMON_MANAGED', 'OVERWATCH_DAEMON_RECORD', 'OVERWATCH_DAEMON_MANAGEMENT_NONCE']) {
      saved[k] = process.env[k];
    }
    process.env.OVERWATCH_DAEMON_MANAGED = '1';
    process.env.OVERWATCH_DAEMON_RECORD = recordPath;
    process.env.OVERWATCH_DAEMON_MANAGEMENT_NONCE = NONCE;
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    rmSync(dir, { recursive: true, force: true });
  });

  it('rejects a malformed record that carries the matching nonce+pid (regression signal)', () => {
    // Matching nonce + pid so it would reach the trust point, but an invalid phase.
    // Pre-fix: readCurrent trusts it and rewrites with phase:'stopped'. Post-fix: throws.
    const malformed = { ...validRecord(), phase: 'not_a_real_phase' };
    writeFileSync(recordPath, JSON.stringify(malformed));

    expect(() => publishManagedDaemonShutdownOutcome(true)).toThrow(/invalid/);
    // The malformed file was NOT rewritten.
    expect(JSON.parse(readFileSync(recordPath, 'utf8')).phase).toBe('not_a_real_phase');
  });

  it('rejects a version bump and missing required fields', () => {
    writeFileSync(recordPath, JSON.stringify({ ...validRecord(), version: 2 }));
    expect(() => publishManagedDaemonShutdownOutcome(true)).toThrow(/invalid/);

    const { engagement_id, ...noEngagement } = validRecord();
    void engagement_id;
    writeFileSync(recordPath, JSON.stringify(noEngagement));
    expect(() => publishManagedDaemonShutdownOutcome(true)).toThrow(/invalid/);
  });

  it('rejects a bare non-object JSON value', () => {
    writeFileSync(recordPath, '5');
    expect(() => publishManagedDaemonShutdownOutcome(true)).toThrow(/invalid/);
  });

  it('accepts a well-formed record and rewrites it to stopped', () => {
    writeFileSync(recordPath, JSON.stringify(validRecord()));
    expect(() => publishManagedDaemonShutdownOutcome(true)).not.toThrow();
    const rewritten = JSON.parse(readFileSync(recordPath, 'utf8'));
    expect(rewritten.phase).toBe('stopped');
    expect(rewritten.shutdown_succeeded).toBe(true);
  });
});
