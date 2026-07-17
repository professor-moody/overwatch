import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'fs';
import { execFileSync } from 'child_process';
import { tmpdir } from 'os';
import { basename, join } from 'path';
import type { GraphEngine } from '../graph-engine.js';
import { buildBundle, prepareBundle } from '../bundle-builder.js';

let root: string;
let statePath: string;
let configPath: string;
let writable = true;
let flushCount = 0;
let configIntentPath: string | undefined;
let history: Array<Record<string, unknown>> = [];
let configStatusOverrides: Record<string, unknown> = {};
let recoveryOverrides: Record<string, unknown> = {};

function engine(): GraphEngine {
  return {
    getStateFilePath: () => statePath,
    isPersistenceWritable: () => writable,
    flushNow: () => { flushCount++; },
    getConfig: () => ({
      id: 'bundle-test',
      created_at: '2026-07-17T00:00:00.000Z',
      config_revision: 7,
      config_hash: 'a'.repeat(64),
    }),
    getConfigRecoveryStatus: () => ({
      status: 'in_sync',
      resolution_required: false,
      file_path: configPath,
      ...(configIntentPath ? { intent_path: configIntentPath, intent_present: true } : { intent_present: false }),
      allowed_resolutions: [],
      ...configStatusOverrides,
    }),
    getPersistenceRecoveryStatus: () => ({
      outcome: writable ? 'clean' : 'incomplete',
      source: 'primary',
      complete: writable,
      writable,
      highest_allocated_logical_seq: 12,
      highest_contiguous_applied_logical_seq: 11,
      ...(writable ? {} : { reason: 'diagnostic recovery' }),
      ...recoveryOverrides,
    }),
    getFullHistory: () => history,
  } as unknown as GraphEngine;
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'overwatch-bundle-builder-'));
  statePath = join(root, 'state.json');
  configPath = join(root, 'engagement.json');
  writeFileSync(statePath, JSON.stringify({ state_version: 1, journal_version: 2 }));
  writeFileSync(configPath, JSON.stringify({ id: 'bundle-test', config_revision: 7, config_hash: 'a'.repeat(64) }));
  writeFileSync(join(root, 'state.journal.jsonl'), '{"journal_version":2}\n');
  mkdirSync(join(root, 'evidence'));
  writeFileSync(join(root, 'evidence', 'manifest.json'), '[]\n');
  mkdirSync(join(root, 'reports'));
  writeFileSync(join(root, 'reports', 'manifest.json'), '[]\n');
  writable = true;
  flushCount = 0;
  configIntentPath = undefined;
  history = [];
  configStatusOverrides = {};
  recoveryOverrides = {};
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

describe('bundle-builder durability', () => {
  it('captures isolated sources and publishes a verifiable V2 manifest', async () => {
    const output = join(root, 'exports', 'bundle.tar.gz');
    const result = await buildBundle(engine(), { outputPath: output });
    expect(basename(result.archivePath)).toBe('bundle.tar.gz');
    expect(existsSync(result.archivePath)).toBe(true);
    expect(result.sizeBytes).toBeGreaterThan(0);
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(flushCount).toBe(1);
    expect(existsSync(join(root, 'bundle-manifest.json'))).toBe(false);

    const listing = execFileSync('tar', ['tzf', output], { encoding: 'utf8' }).trim().split('\n');
    expect(listing).toEqual(expect.arrayContaining([
      basename(statePath),
      'state.journal.jsonl',
      'active-engagement-config.json',
      'evidence/manifest.json',
      'reports/manifest.json',
      'bundle-manifest.json',
    ]));
    expect(listing.some(path => path.includes('writer-lock'))).toBe(false);
    const manifest = JSON.parse(execFileSync('tar', ['xOzf', output, 'bundle-manifest.json'], { encoding: 'utf8' }));
    expect(manifest).toMatchObject({
      manifest_version: 2,
      status: 'complete',
      state_version: 1,
      journal_version: 2,
      checkpoint: {
        highest_allocated_logical_seq: 12,
        highest_contiguous_applied_logical_seq: 11,
      },
      config: { revision: 7, hash: 'a'.repeat(64) },
      recovery: { complete: true, writable: true },
    });
    expect(manifest.files.every((file: { sha256: string }) => /^[0-9a-f]{64}$/.test(file.sha256))).toBe(true);
  });

  it('supports a read-only diagnostic capture without attempting a flush', async () => {
    writable = false;
    const output = join(root, 'diagnostic.tar.gz');
    const result = await buildBundle(engine(), { outputPath: output });
    expect(flushCount).toBe(0);
    expect(result.manifest.recovery).toMatchObject({
      complete: false,
      writable: false,
      outcome: 'incomplete',
      reason: 'diagnostic recovery',
    });
    expect(basename(result.archivePath)).toBe('diagnostic.tar.gz');
  });

  it('captures a writable active config intent as an explicit recovery authority', async () => {
    configIntentPath = join(root, 'engagement.json.intent.json');
    writeFileSync(configIntentPath, '{"intent":"pending"}\n');
    const prepared = await prepareBundle(engine());
    try {
      expect(readFileSync(join(prepared.stateDir, 'recovery-artifacts', 'config-write-intent'), 'utf8'))
        .toBe('{"intent":"pending"}\n');
      expect(prepared.manifest.recovery.authorities).toContainEqual({
        kind: 'config_write_intent',
        source_path: configIntentPath,
        captured_path: 'recovery-artifacts/config-write-intent',
      });
    } finally {
      prepared.cleanup();
    }
  });

  it('captures exact config-conflict, migration-backup, and rollback authorities', async () => {
    const conflict = join(root, 'config-conflict.json');
    const backup = join(root, 'migration-backup');
    const rollback = `${statePath}.rollback-intent.json`;
    writeFileSync(conflict, 'conflict bytes');
    mkdirSync(backup);
    writeFileSync(join(backup, 'manifest.json'), 'backup manifest');
    writeFileSync(join(backup, 'state.json'), 'backup state');
    writeFileSync(rollback, 'rollback bytes');
    configStatusOverrides = {
      conflicted_intent: {
        archive_path: conflict,
        intent_sha256: 'b'.repeat(64),
        reason: 'test conflict',
        observed_file_hash: 'c'.repeat(64),
        observed_state_hash: 'd'.repeat(64),
      },
    };
    recoveryOverrides = {
      state_migration: {
        status: 'backup_created',
        supported_state_version: 1,
        supported_journal_version: 2,
        migration_required: true,
        backup_path: backup,
        backup_manifest_sha256: 'e'.repeat(64),
      },
    };
    const prepared = await prepareBundle(engine());
    try {
      expect(readFileSync(join(prepared.stateDir, 'recovery-artifacts', 'config-intent-conflict'), 'utf8'))
        .toBe('conflict bytes');
      expect(readFileSync(join(prepared.stateDir, 'recovery-artifacts', 'state-migration-backup', 'state.json'), 'utf8'))
        .toBe('backup state');
      expect(readFileSync(join(prepared.stateDir, 'recovery-artifacts', 'state-rollback-intent.json'), 'utf8'))
        .toBe('rollback bytes');
      expect(prepared.manifest.recovery.state_migration?.backup_manifest_sha256).toBe('e'.repeat(64));
      expect(prepared.manifest.recovery.authorities?.map(entry => entry.kind)).toEqual(expect.arrayContaining([
        'config_intent_conflict', 'state_migration_backup', 'state_rollback_intent',
      ]));
    } finally {
      prepared.cleanup();
    }
  });

  it('uses lock-free OS-temp staging and a temp default output while degraded', async () => {
    writable = false;
    const prepared = await prepareBundle(engine());
    try {
      expect(prepared.stateDir.startsWith(root)).toBe(false);
      expect(readdirSync(root).some(name => name.includes('bundle-stage') || name.endsWith('.writer-lock'))).toBe(false);
    } finally {
      prepared.cleanup();
    }
    const result = await buildBundle(engine());
    try {
      expect(result.archivePath.startsWith(root)).toBe(false);
      expect(existsSync(result.archivePath)).toBe(true);
    } finally {
      rmSync(result.archivePath, { force: true });
    }
  });

  it('preserves an invalid recovery head and snapshots in a diagnostic bundle', async () => {
    writable = false;
    writeFileSync(statePath, '{corrupt state bytes');
    mkdirSync(join(root, '.snapshots'));
    writeFileSync(join(root, '.snapshots', 'state-valid.json'), JSON.stringify({ state_version: 1 }));
    writeFileSync(join(root, 'state.quarantine-tail'), 'uncertain WAL tail');
    const result = await buildBundle(engine(), { outputPath: join(root, 'diagnostic-invalid.tar.gz') });
    expect(result.manifest.state_version).toBe(0);
    expect(result.manifest.recovery.state_parse_error).toBeTruthy();
    const listing = execFileSync('tar', ['tzf', result.archivePath], { encoding: 'utf8' });
    expect(listing).toContain('.snapshots/state-valid.json');
    expect(listing).toContain('recovery-artifacts/state.quarantine-tail');
    expect(execFileSync('tar', ['xOzf', result.archivePath, basename(statePath)], { encoding: 'utf8' }))
      .toBe('{corrupt state bytes');
  });

  it('captures missing and unsupported primary heads as read-only diagnostics', async () => {
    writable = false;
    rmSync(statePath);
    const missing = await buildBundle(engine(), { outputPath: join(root, 'diagnostic-missing.tar.gz') });
    expect(missing.manifest.recovery.state_parse_error).toBeTruthy();
    expect(execFileSync('tar', ['tzf', missing.archivePath], { encoding: 'utf8' })).toContain('bundle-manifest.json');

    writeFileSync(statePath, JSON.stringify({ state_version: 999, journal_version: 999 }));
    const future = await buildBundle(engine(), { outputPath: join(root, 'diagnostic-future.tar.gz') });
    expect(future.manifest.recovery.state_parse_error).toMatch(/unsupported/i);
    expect(execFileSync('tar', ['xOzf', future.archivePath, basename(statePath)], { encoding: 'utf8' }))
      .toContain('"state_version":999');
  });

  it('captures only the complete newline-terminated prefix of a live tape', async () => {
    const tape = join(root, 'live-tape.jsonl');
    writeFileSync(tape, '{"frame":1}\n{"partial"');
    history = [{ event_type: 'tape_session_started', details: { tape_path: tape } }];
    const result = await buildBundle(engine(), { outputPath: join(root, 'tape-bundle.tar.gz') });
    const tapeEntry = `tapes/0001-${basename(tape)}`;
    expect(execFileSync('tar', ['xOzf', result.archivePath, tapeEntry], { encoding: 'utf8' }))
      .toBe('{"frame":1}\n');
    expect(result.manifest.recovery.authorities).toContainEqual(expect.objectContaining({
      kind: 'mcp_tape',
      captured_path: tapeEntry,
      capture_status: 'live_prefix',
    }));
  });

  it('keeps a stable newline-terminated active tape marked as a live prefix', async () => {
    const tape = join(root, 'idle-live-tape.jsonl');
    writeFileSync(tape, '{"frame":1}\n');
    history = [{ event_type: 'tape_session_started', details: { tape_path: tape } }];
    const result = await buildBundle(engine(), { outputPath: join(root, 'idle-tape-bundle.tar.gz') });
    expect(result.manifest.recovery.authorities).toContainEqual(expect.objectContaining({
      kind: 'mcp_tape',
      source_path: tape,
      capture_status: 'live_prefix',
    }));
  });

  it('does not let a delayed terminal event retire a newer tape generation on the same path', async () => {
    const tape = join(root, 'reused-active-tape.jsonl');
    writeFileSync(tape, '{"frame":2}\n');
    history = [
      { event_id: 'start-a', event_type: 'tape_session_started', details: { session_id: 'a', tape_path: tape } },
      { event_id: 'start-b', event_type: 'tape_session_started', details: { session_id: 'b', tape_path: tape } },
      {
        event_id: 'failure-a',
        event_type: 'system',
        details: {
          session_id: 'a',
          tape_path: tape,
          tape_lifecycle: 'failed',
          started_event_id: 'start-a',
        },
      },
    ];
    const result = await buildBundle(engine(), { outputPath: join(root, 'reused-tape-bundle.tar.gz') });
    expect(result.manifest.recovery.authorities).toContainEqual(expect.objectContaining({
      kind: 'mcp_tape',
      source_path: tape,
      capture_status: 'live_prefix',
    }));
  });

  it('skips a registered tape that disappeared without aborting the bundle', async () => {
    const missingTape = join(root, 'missing-tape.jsonl');
    history = [{ event_type: 'tape_session_started', details: { tape_path: missingTape } }];
    const result = await buildBundle(engine(), { outputPath: join(root, 'missing-tape-bundle.tar.gz') });
    expect(existsSync(result.archivePath)).toBe(true);
    expect(result.manifest.tape_paths).not.toContain(missingTape);
    expect(result.manifest.recovery.authorities?.some(authority => authority.source_path === missingTape) ?? false)
      .toBe(false);
  });

  it('rejects output collisions with state and live artifact stores', async () => {
    await expect(buildBundle(engine(), { outputPath: statePath })).rejects.toThrow(/collides with live engagement data/i);
    await expect(buildBundle(engine(), { outputPath: join(root, 'evidence', 'bundle.tar.gz') })).rejects.toThrow(/live artifact storage/i);
    expect(readFileSync(statePath, 'utf8')).toContain('state_version');
  });

  it('rejects a nested missing output parent without mutating protected storage', async () => {
    const nested = join(root, 'evidence', 'new', 'nested', 'bundle.tar.gz');
    await expect(buildBundle(engine(), { outputPath: nested })).rejects.toThrow(/live artifact storage/i);
    expect(existsSync(join(root, 'evidence', 'new'))).toBe(false);
  });

  it('rejects registered tape, config-intent, and recovery-artifact output collisions', async () => {
    const tape = join(root, 'operator-tape.jsonl');
    const intent = join(root, 'engagement.json.intent.json');
    const quarantine = join(root, 'state.quarantine-tail');
    writeFileSync(tape, '{}\n');
    writeFileSync(intent, '{}\n');
    writeFileSync(quarantine, 'preserve');
    history = [{ event_type: 'tape_session_started', details: { tape_path: tape } }];
    configIntentPath = intent;
    await expect(buildBundle(engine(), { outputPath: tape })).rejects.toThrow(/collides/i);
    await expect(buildBundle(engine(), { outputPath: intent })).rejects.toThrow(/collides/i);
    await expect(buildBundle(engine(), { outputPath: quarantine })).rejects.toThrow(/collides/i);
    expect(readFileSync(tape, 'utf8')).toBe('{}\n');
    expect(readFileSync(intent, 'utf8')).toBe('{}\n');
    expect(readFileSync(quarantine, 'utf8')).toBe('preserve');
  });

  it('never replaces an existing good archive when capture fails', async () => {
    const output = join(root, 'existing.tar.gz');
    writeFileSync(output, 'known-good');
    symlinkSync(join(root, 'evidence', 'manifest.json'), join(root, 'reports', 'unsafe-link'));
    await expect(buildBundle(engine(), { outputPath: output })).rejects.toThrow(/symbolic links/i);
    expect(readFileSync(output, 'utf8')).toBe('known-good');
    expect(readdirSync(root).some(name => name.includes('.tmp-'))).toBe(false);
  });

  it('uses isolated staging trees for concurrent captures', async () => {
    const [first, second] = await Promise.all([prepareBundle(engine()), prepareBundle(engine())]);
    try {
      expect(first.stateDir).not.toBe(second.stateDir);
      expect(first.manifest.bundle_id).not.toBe(second.manifest.bundle_id);
      expect(existsSync(join(first.stateDir, 'bundle-manifest.json'))).toBe(true);
      expect(existsSync(join(second.stateDir, 'bundle-manifest.json'))).toBe(true);
    } finally {
      first.cleanup();
      second.cleanup();
    }
  });
});
