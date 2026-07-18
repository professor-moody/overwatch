import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHash } from 'crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  ftruncateSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'fs';
import { spawn } from 'child_process';
import { once } from 'events';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import type { EngagementConfig } from '../../types.js';
import {
  EngagementConfigService,
  canonicalJson,
  computeConfigHash,
  recoverInterruptedAtomicJsonWrite,
  withConfigMetadata,
  writeJsonAtomicDurable,
  type ConfigApplyContext,
} from '../engagement-config-service.js';

function config(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'config-service-test',
    name: 'Config Service Test',
    created_at: '2026-01-01T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', enabled: false, max_noise: 0.5 },
    hash_chain_enabled: true,
    subagent_isolation: 'in_process',
    ...overrides,
  };
}

function verifyConflictArchive(path: string, rawIntent: Buffer): Record<string, unknown> {
  const record = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
  const { conflict_checksum: conflictChecksum, ...body } = record;
  expect(conflictChecksum).toBe(
    createHash('sha256').update(canonicalJson(body)).digest('hex'),
  );
  expect(record.intent_sha256).toBe(createHash('sha256').update(rawIntent).digest('hex'));
  expect(Buffer.from(String(record.intent_raw_base64), 'base64')).toEqual(rawIntent);
  return record;
}

function harness(
  initial: EngagementConfig,
  persist?: () => void,
  nowIso: () => string = () => '2026-02-03T04:05:06.000Z',
) {
  let runtime = structuredClone(initial);
  const applies: ConfigApplyContext[] = [];
  const events: Array<Record<string, unknown>> = [];
  let persistCount = 0;
  return {
    host: {
      getRuntimeConfig: () => runtime,
      nowIso,
      applyRuntimeConfig: (next: EngagementConfig, context: ConfigApplyContext) => {
        runtime = structuredClone(next);
        applies.push(context);
      },
      persistRuntimeState: () => {
        persistCount += 1;
        persist?.();
      },
      recordConfigEvent: (event: { description: string; result: 'success' | 'failure'; details: Record<string, unknown> }) => {
        events.push(event);
      },
    },
    runtime: () => runtime,
    applies,
    events,
    persistCount: () => persistCount,
  };
}

describe('EngagementConfigService', () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ow-config-service-'));
    file = join(dir, 'engagement.json');
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('computes a stable canonical hash independent of object insertion order', () => {
    const left = withConfigMetadata(config(), 1);
    const right = {
      ...left,
      scope: {
        exclusions: left.scope.exclusions,
        domains: left.scope.domains,
        cidrs: left.scope.cidrs,
      },
    };
    expect(computeConfigHash(right)).toBe(left.config_hash);
  });

  it('holds one shared lock across the final compare and atomic replacement', () => {
    const initial = withConfigMetadata(config(), 1);
    const next = withConfigMetadata(config({ name: 'Locked target' }), 2);
    const competing = withConfigMetadata(config({ name: 'Competing writer' }), 3);
    writeFileSync(file, JSON.stringify(initial));

    writeJsonAtomicDurable(file, next, capturedPath => {
      expect(capturedPath).toBeTypeOf('string');
      expect(JSON.parse(readFileSync(capturedPath!, 'utf8'))).toEqual(initial);
      try {
        writeJsonAtomicDurable(file, competing);
        throw new Error('expected the competing writer to be rejected');
      } catch (error) {
        expect((error as Error & { code?: string }).code).toBe('CONFIG_FILE_LOCKED');
      }
    });

    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(next);
    expect(existsSync(`${file}.overwatch-write.lock`)).toBe(false);
  });

  it('waits for a live foreign contender and safely reclaims its unique record after exit', async () => {
    const initial = withConfigMetadata(config(), 1);
    const next = withConfigMetadata(config({ name: 'After foreign owner' }), 2);
    writeFileSync(file, JSON.stringify(initial));
    const lockDirectory = join(
      tmpdir(),
      'overwatch-durable-write-locks',
      createHash('sha256').update(resolve(file)).digest('hex'),
    );
    const childScript = `
      const { mkdirSync, unlinkSync, writeFileSync } = require('fs');
      const { execFileSync } = require('child_process');
      const { join } = require('path');
      const dir = process.argv[1];
      mkdirSync(dir, { recursive: true });
      const token = '00000000000000000000000000000000';
      const contender = join(dir, process.pid + '-' + token + '.json');
      const started = execFileSync('ps', ['-o', 'lstart=', '-p', String(process.pid)], {
        encoding: 'utf8', env: { ...process.env, TZ: 'UTC', LC_ALL: 'C', LANG: 'C' },
      }).trim();
      const processStartIdentity = 'posix-lstart-utc:' + started;
      writeFileSync(contender, JSON.stringify({
        version: 1, pid: process.pid, process_start_identity: processStartIdentity,
        token, choosing: false, ticket: 1,
      }));
      process.stdout.write('ready\\n');
      setTimeout(() => { unlinkSync(contender); process.exit(0); }, 250);
    `;
    const child = spawn(process.execPath, ['-e', childScript, lockDirectory], {
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    await once(child.stdout!, 'data');

    const started = Date.now();
    writeJsonAtomicDurable(file, next);
    const elapsed = Date.now() - started;
    if (child.exitCode === null) await once(child, 'exit');

    expect(elapsed).toBeGreaterThanOrEqual(75);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(next);
  });

  it('reclaims a stale contender even when its PID has been reused', () => {
    const initial = withConfigMetadata(config(), 1);
    const next = withConfigMetadata(config({ name: 'PID identity target' }), 2);
    writeFileSync(file, JSON.stringify(initial));
    const lockDirectory = join(
      tmpdir(),
      'overwatch-durable-write-locks',
      createHash('sha256').update(resolve(file)).digest('hex'),
    );
    mkdirSync(lockDirectory, { recursive: true });
    const staleToken = '11111111111111111111111111111111';
    const stalePath = join(lockDirectory, `${process.pid}-${staleToken}.json`);
    writeFileSync(stalePath, JSON.stringify({
      version: 1,
      pid: process.pid,
      process_start_identity: 'a previous process that reused this pid',
      token: staleToken,
      choosing: false,
      ticket: 1,
    }));

    writeJsonAtomicDurable(file, next);

    expect(existsSync(stalePath)).toBe(false);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(next);
  });

  it('preserves an uncooperative edit created after comparison and before installation', () => {
    const initial = withConfigMetadata(config(), 1);
    const next = withConfigMetadata(config({ name: 'CAS target' }), 2);
    const external = withConfigMetadata(config({ name: 'Uncooperative editor' }), 7);
    writeFileSync(file, JSON.stringify(initial));

    expect(() => writeJsonAtomicDurable(file, next, capturedPath => {
      expect(JSON.parse(readFileSync(capturedPath!, 'utf8'))).toEqual(initial);
      writeFileSync(file, JSON.stringify(external));
    })).toThrow(/external file was preserved/i);

    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(external);
  });

  it('archives delayed writes made through a descriptor to the captured inode', () => {
    const initial = withConfigMetadata(config(), 1);
    const next = withConfigMetadata(config({ name: 'Installed target' }), 2);
    const delayed = withConfigMetadata(config({ name: 'Delayed descriptor edit' }), 8);
    writeFileSync(file, JSON.stringify(initial));
    const fd = openSync(file, 'r+');
    let comparisons = 0;
    try {
      writeJsonAtomicDurable(file, next, capturedPath => {
        comparisons += 1;
        expect(JSON.parse(readFileSync(capturedPath!, 'utf8'))).toEqual(initial);
        if (comparisons === 2) {
          const bytes = Buffer.from(`${JSON.stringify(delayed)}\n`);
          writeFileSync(fd, bytes);
          ftruncateSync(fd, bytes.length);
          fsyncSync(fd);
        }
      });
    } finally {
      closeSync(fd);
    }

    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(next);
    const archives = readdirSync(dir)
      .filter(name => name.startsWith('engagement.json.overwatch-cas-') && name.endsWith('.previous.archived'))
      .map(name => join(dir, name));
    expect(archives).toHaveLength(1);
    expect(JSON.parse(readFileSync(archives[0], 'utf8'))).toEqual(delayed);
  });

  it('restores a captured pre-image after a crash in the move-aside window', () => {
    const initial = withConfigMetadata(config(), 1);
    const captured = `${file}.overwatch-cas-999-deadbeef.previous`;
    writeFileSync(captured, JSON.stringify(initial));

    recoverInterruptedAtomicJsonWrite(file);

    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(initial);
    expect(existsSync(captured)).toBe(false);
  });

  it('retires an installed-target crash pre-image before a later missing-path recovery', () => {
    const initial = withConfigMetadata(config(), 1);
    const target = withConfigMetadata(config({ name: 'Already installed' }), 2);
    writeFileSync(file, JSON.stringify(target));
    const stale = `${file}.overwatch-cas-100-first.previous`;
    writeFileSync(stale, JSON.stringify(initial));

    recoverInterruptedAtomicJsonWrite(file);
    expect(existsSync(stale)).toBe(false);
    expect(existsSync(`${stale}.archived`)).toBe(true);

    rmSync(file);
    const current = `${file}.overwatch-cas-101-second.previous`;
    writeFileSync(current, JSON.stringify(target));
    recoverInterruptedAtomicJsonWrite(file);

    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(target);
    expect(existsSync(current)).toBe(false);
  });

  it('seeds revision 1 only after converging a fresh file and runtime state', () => {
    const legacy = config();
    writeFileSync(file, JSON.stringify(legacy));
    const h = harness(legacy);
    const service = new EngagementConfigService(h.host, file);

    const status = service.initialize({ restored: false, persistence_writable: true });

    expect(status).toMatchObject({ status: 'in_sync', resolution_required: false, file_revision: 1, state_revision: 1 });
    expect(h.runtime().config_revision).toBe(1);
    expect(h.runtime().config_hash).toBe(computeConfigHash(h.runtime()));
    expect(JSON.parse(readFileSync(file, 'utf8'))).toMatchObject({
      config_revision: 1,
      config_hash: h.runtime().config_hash,
    });
    expect(h.persistCount()).toBe(1);
  });

  it('silently upgrades semantically equal legacy file/state after restore', () => {
    const legacy = config();
    writeFileSync(file, JSON.stringify(legacy));
    const h = harness(legacy);
    const service = new EngagementConfigService(h.host, file);

    const status = service.initialize({ restored: true, persistence_writable: true });

    expect(status.status).toBe('recovered');
    expect(status.resolution_required).toBe(false);
    expect(h.runtime().config_revision).toBe(1);
  });

  it('blocks unexplained semantic divergence without changing either representation', () => {
    const state = withConfigMetadata(config({ name: 'State Wins Only By Choice' }), 3);
    const disk = withConfigMetadata(config({ name: 'File Wins Only By Choice' }), 4);
    writeFileSync(file, JSON.stringify(disk));
    const h = harness(state);
    const service = new EngagementConfigService(h.host, file);

    const status = service.initialize({ restored: true, persistence_writable: true });

    expect(status).toMatchObject({ status: 'diverged', resolution_required: true, file_revision: 4, state_revision: 3 });
    expect(() => service.assertWritable()).toThrow(/read-only/i);
    expect(h.runtime().name).toBe('State Wins Only By Choice');
    expect(JSON.parse(readFileSync(file, 'utf8')).name).toBe('File Wins Only By Choice');
    expect(h.persistCount()).toBe(0);
  });

  it('blocks equal semantics with different revision metadata', () => {
    const state = withConfigMetadata(config(), 3);
    const disk = withConfigMetadata(config(), 4);
    writeFileSync(file, JSON.stringify(disk));
    const h = harness(state);
    const service = new EngagementConfigService(h.host, file);

    const status = service.initialize({ restored: true, persistence_writable: true });

    expect(status).toMatchObject({ status: 'diverged', resolution_required: true });
    expect(status.reason).toMatch(/revision\/hash metadata differs/i);
    expect(h.persistCount()).toBe(0);
  });

  it('blocks declared hashes that do not match canonical content', () => {
    const valid = withConfigMetadata(config(), 2);
    const invalid = { ...valid, config_hash: '0'.repeat(64) };
    writeFileSync(file, JSON.stringify(invalid));
    const h = harness(invalid);
    const service = new EngagementConfigService(h.host, file);

    const status = service.initialize({ restored: true, persistence_writable: true });

    expect(status).toMatchObject({ status: 'diverged', resolution_required: true });
    expect(status.reason).toMatch(/declared configuration hash/i);
    expect(h.persistCount()).toBe(0);
  });

  it('blocks mixed legacy and revisioned metadata even when semantics match', () => {
    const legacy = config();
    const disk = withConfigMetadata(legacy, 1);
    writeFileSync(file, JSON.stringify(disk));
    const h = harness(legacy);
    const service = new EngagementConfigService(h.host, file);

    const status = service.initialize({ restored: true, persistence_writable: true });

    expect(status).toMatchObject({ status: 'diverged', resolution_required: true });
    expect(status.reason).toMatch(/only one configuration representation/i);
  });

  it('commits through intent, file, runtime, and state before reporting success', () => {
    const initial = withConfigMetadata(config(), 1);
    writeFileSync(file, JSON.stringify(initial));
    const h = harness(initial);
    const service = new EngagementConfigService(h.host, file);
    service.initialize({ restored: true, persistence_writable: true });

    const updated = service.commit({ ...initial, name: 'Updated' }, 'test');

    expect(updated).toMatchObject({ name: 'Updated', config_revision: 2 });
    expect(h.runtime()).toEqual(updated);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(updated);
    expect(existsSync(`${file}.write-intent.json`)).toBe(false);
    expect(h.persistCount()).toBe(1);
    expect(h.events).toHaveLength(1);
  });

  it('permits only the known commit window and still blocks external divergence before and after it', () => {
    const initial = withConfigMetadata(config(), 1);
    const externalBefore = withConfigMetadata(config({ name: 'External before' }), 2);
    writeFileSync(file, JSON.stringify(externalBefore));
    const blockedBefore = harness(initial);
    const blockedBeforeService = new EngagementConfigService(blockedBefore.host, file);
    blockedBeforeService.initialize({ restored: true, persistence_writable: true });
    expect(() => blockedBeforeService.assertWritable()).toThrow(/read-only/i);

    writeFileSync(file, JSON.stringify(initial));
    const h = harness(initial);
    const applyRuntimeConfig = h.host.applyRuntimeConfig;
    let service!: EngagementConfigService;
    let observedCommitWindow = false;
    h.host.applyRuntimeConfig = (next, context) => {
      applyRuntimeConfig(next, context);
      expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(next);
      expect(() => service.assertWritable()).not.toThrow();
      observedCommitWindow = true;
    };
    service = new EngagementConfigService(h.host, file);
    service.initialize({ restored: true, persistence_writable: true });
    const updated = service.commit({ ...initial, name: 'Internal update' }, 'test');
    expect(observedCommitWindow).toBe(true);
    expect(updated.name).toBe('Internal update');

    const externalAfter = withConfigMetadata(config({ name: 'External after' }), 3);
    writeFileSync(file, JSON.stringify(externalAfter));
    expect(() => service.assertWritable()).toThrow(/read-only/i);
  });

  it('retains a failed write intent and completes it on the next startup', () => {
    const initial = withConfigMetadata(config(), 1);
    writeFileSync(file, JSON.stringify(initial));
    const first = harness(initial, () => { throw new Error('state fsync failed'); });
    const firstService = new EngagementConfigService(first.host, file);
    firstService.initialize({ restored: true, persistence_writable: true });

    expect(() => firstService.commit({ ...initial, name: 'Recovered Update' }, 'test')).toThrow('state fsync failed');
    expect(existsSync(`${file}.write-intent.json`)).toBe(true);
    const failed = firstService.getStatus();
    expect(failed).toMatchObject({
      status: 'write_incomplete',
      state_revision: 1,
      runtime_revision: 2,
      allowed_resolutions: [],
    });
    expect(() => firstService.resolve({
      mode: 'use_state',
      expected_file_hash: failed.file_hash!,
      expected_state_hash: failed.state_hash!,
    })).toThrow(/restart to resume/i);

    // Simulate a crash: the durable state is still the old config while the
    // atomic file rename and write intent survived.
    const restarted = harness(initial);
    const restartedService = new EngagementConfigService(restarted.host, file);
    const status = restartedService.initialize({ restored: true, persistence_writable: true });

    expect(status.status).toBe('recovered');
    expect(restarted.runtime()).toMatchObject({ name: 'Recovered Update', config_revision: 2 });
    expect(existsSync(`${file}.write-intent.json`)).toBe(false);
    expect(restarted.persistCount()).toBe(1);
    expect(restarted.events).toHaveLength(1);
    expect(restarted.events[0].details).toMatchObject({
      expected_file_hash: initial.config_hash,
      previous_state_hash: initial.config_hash,
      target_hash: restarted.runtime().config_hash,
      intent_checksum: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
  });

  it('restores a captured intent pre-image before interrupted-write recovery', () => {
    const initial = withConfigMetadata(config(), 1);
    writeFileSync(file, JSON.stringify(initial));
    const interrupted = harness(initial, () => { throw new Error('state checkpoint interrupted'); });
    const firstService = new EngagementConfigService(interrupted.host, file);
    firstService.initialize({ restored: true, persistence_writable: true });

    expect(() => firstService.commit({ ...initial, name: 'Intent target' }, 'test'))
      .toThrow('state checkpoint interrupted');
    const intentPath = `${file}.write-intent.json`;
    const capturedIntent = `${intentPath}.overwatch-cas-777-captured.previous`;
    const target = JSON.parse(readFileSync(file, 'utf8')) as EngagementConfig;
    renameSync(intentPath, capturedIntent);
    expect(existsSync(intentPath)).toBe(false);

    const restarted = harness(initial);
    const restartedService = new EngagementConfigService(restarted.host, file);
    const status = restartedService.initialize({ restored: true, persistence_writable: true });

    expect(status).toMatchObject({ status: 'recovered', resolution_required: false, intent_present: false });
    expect(restarted.runtime()).toEqual(target);
    expect(restarted.persistCount()).toBe(1);
    expect(existsSync(intentPath)).toBe(false);
    expect(existsSync(capturedIntent)).toBe(false);
  });

  it('derives intent checksums from the injected clock', () => {
    const initial = withConfigMetadata(config(), 1);
    const secondFile = join(dir, 'second-engagement.json');
    const createdAt = '2031-07-08T09:10:11.000Z';
    const checksums: string[] = [];

    for (const path of [file, secondFile]) {
      writeFileSync(path, JSON.stringify(initial));
      const h = harness(
        initial,
        () => { throw new Error('retain deterministic intent'); },
        () => createdAt,
      );
      const service = new EngagementConfigService(h.host, path);
      service.initialize({ restored: true, persistence_writable: true });
      expect(() => service.commit({ ...initial, name: 'Deterministic Update' }, 'test')).toThrow();
      const intent = JSON.parse(readFileSync(`${path}.write-intent.json`, 'utf8')) as {
        created_at: string;
        intent_checksum: string;
      };
      expect(intent.created_at).toBe(createdAt);
      checksums.push(intent.intent_checksum);
    }

    expect(checksums[0]).toBe(checksums[1]);
  });

  it('does not duplicate the config audit when state already contains an intent target', () => {
    const initial = withConfigMetadata(config(), 1);
    writeFileSync(file, JSON.stringify(initial));
    const interrupted = harness(initial, () => { throw new Error('simulate retained intent'); });
    const interruptedService = new EngagementConfigService(interrupted.host, file);
    interruptedService.initialize({ restored: true, persistence_writable: true });
    expect(() => interruptedService.commit({ ...initial, name: 'Already Durable' }, 'test')).toThrow();
    const target = JSON.parse(readFileSync(file, 'utf8')) as EngagementConfig;
    expect(existsSync(`${file}.write-intent.json`)).toBe(true);

    const restarted = harness(target);
    const restartedService = new EngagementConfigService(restarted.host, file);
    const status = restartedService.initialize({ restored: true, persistence_writable: true });

    expect(status.status).toBe('recovered');
    expect(restarted.persistCount()).toBe(0);
    expect(restarted.events).toHaveLength(0);
    expect(existsSync(`${file}.write-intent.json`)).toBe(false);
  });

  it('requires current hashes and supports both explicit resolution modes', () => {
    const state = withConfigMetadata(config({ name: 'State' }), 2);
    const disk = withConfigMetadata(config({ name: 'File' }), 2);
    writeFileSync(file, JSON.stringify(disk));
    const h = harness(state);
    const service = new EngagementConfigService(h.host, file);
    const diverged = service.initialize({ restored: true, persistence_writable: true });

    expect(() => service.resolve({
      mode: 'use_file',
      expected_file_hash: '0'.repeat(64),
      expected_state_hash: diverged.state_hash!,
    })).toThrow(/changed after it was inspected/i);
    expect(h.persistCount()).toBe(0);

    const result = service.resolve({
      mode: 'use_file',
      expected_file_hash: diverged.file_hash!,
      expected_state_hash: diverged.state_hash!,
    });
    expect(result).toMatchObject({ resolved: true, mode: 'use_file', config: { name: 'File', config_revision: 3 } });
    expect(result.recovery).toMatchObject({ status: 'recovered', resolution_required: false, last_resolution: 'use_file' });
    expect(h.events.at(-1)?.details).toMatchObject({
      expected_file_hash: diverged.file_hash,
      previous_state_hash: diverged.state_hash,
      target_hash: result.config.config_hash,
      intent_checksum: expect.stringMatching(/^[0-9a-f]{64}$/),
    });

    // Create another external divergence and select durable state this time.
    const external = withConfigMetadata(config({ name: 'External Edit' }), 4);
    writeFileSync(file, JSON.stringify(external));
    const secondService = new EngagementConfigService(h.host, file);
    const second = secondService.initialize({ restored: true, persistence_writable: true });
    const useState = secondService.resolve({
      mode: 'use_state',
      expected_file_hash: second.file_hash!,
      expected_state_hash: second.state_hash!,
    });
    expect(useState.config.name).toBe('File');
    expect(JSON.parse(readFileSync(file, 'utf8')).name).toBe('File');
  });

  it('refreshes reconciliation hashes after another external file edit', () => {
    const state = withConfigMetadata(config({ name: 'Durable' }), 2);
    const firstExternal = withConfigMetadata(config({ name: 'First external edit' }), 3);
    writeFileSync(file, JSON.stringify(firstExternal));
    const h = harness(state);
    const service = new EngagementConfigService(h.host, file);
    const inspected = service.initialize({ restored: true, persistence_writable: true });

    const secondExternal = withConfigMetadata(config({ name: 'Second external edit' }), 4);
    writeFileSync(file, JSON.stringify(secondExternal));
    expect(() => service.resolve({
      mode: 'use_state',
      expected_file_hash: inspected.file_hash!,
      expected_state_hash: inspected.state_hash!,
    })).toThrow(/refresh recovery status/i);

    const refreshed = service.getStatus();
    expect(refreshed.file_hash).toBe(secondExternal.config_hash);
    expect(refreshed.file_hash).not.toBe(inspected.file_hash);
    const resolved = service.resolve({
      mode: 'use_state',
      expected_file_hash: refreshed.file_hash!,
      expected_state_hash: refreshed.state_hash!,
    });
    expect(resolved.config).toMatchObject({ name: 'Durable', config_revision: 5 });
  });

  it('does not acknowledge success when the config file changes during state persistence', () => {
    const initial = withConfigMetadata(config(), 1);
    const external = withConfigMetadata(config({ name: 'Concurrent writer' }), 9);
    writeFileSync(file, JSON.stringify(initial));
    const h = harness(initial, () => {
      writeFileSync(file, JSON.stringify(external));
    });
    const service = new EngagementConfigService(h.host, file);
    service.initialize({ restored: true, persistence_writable: true });

    expect(() => service.commit({ ...initial, name: 'Must not acknowledge' }, 'test'))
      .toThrow(/did not converge/i);
    expect(existsSync(`${file}.write-intent.json`)).toBe(true);
    expect(service.getStatus()).toMatchObject({
      status: 'write_incomplete',
      resolution_required: true,
      intent_present: true,
      allowed_resolutions: [],
      file_hash: external.config_hash,
    });
  });

  it('quarantines a third-state intent and audits explicit state reconciliation', () => {
    const initial = withConfigMetadata(config(), 1);
    const external = withConfigMetadata(config({ name: 'Concurrent third state' }), 9);
    writeFileSync(file, JSON.stringify(initial));
    const first = harness(initial, () => {
      writeFileSync(file, JSON.stringify(external));
    });
    const firstService = new EngagementConfigService(first.host, file);
    firstService.initialize({ restored: true, persistence_writable: true });

    expect(() => firstService.commit({ ...initial, name: 'Durable target' }, 'test'))
      .toThrow(/did not converge/i);
    const durableTarget = structuredClone(first.runtime());
    const activeIntentPath = `${file}.write-intent.json`;
    const rawIntent = readFileSync(activeIntentPath);

    const restarted = harness(durableTarget);
    const restartedService = new EngagementConfigService(restarted.host, file);
    const status = restartedService.initialize({ restored: true, persistence_writable: true });

    expect(status).toMatchObject({
      status: 'diverged',
      resolution_required: true,
      intent_present: false,
      allowed_resolutions: ['use_file', 'use_state'],
      conflicted_intent: {
        intent_sha256: createHash('sha256').update(rawIntent).digest('hex'),
        observed_file_hash: external.config_hash,
        observed_state_hash: durableTarget.config_hash,
      },
    });
    expect(existsSync(activeIntentPath)).toBe(false);
    expect(restarted.runtime()).toEqual(durableTarget);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(external);
    const archivePath = status.conflicted_intent!.archive_path;
    verifyConflictArchive(archivePath, rawIntent);

    // Simulate the crash window where the archive rename was durable but the
    // active-marker unlink was not, then make the current pair look like a
    // valid from/to intent combination. The preserved conflict decision must
    // win over automatic intent replay.
    writeFileSync(activeIntentPath, rawIntent);
    writeFileSync(file, JSON.stringify(initial));
    const crashRestart = harness(durableTarget);
    const crashRestartService = new EngagementConfigService(crashRestart.host, file);
    const afterCrash = crashRestartService.initialize({ restored: true, persistence_writable: true });
    expect(afterCrash).toMatchObject({
      status: 'diverged',
      intent_present: false,
      file_hash: initial.config_hash,
      conflicted_intent: {
        archive_path: archivePath,
        observed_file_hash: external.config_hash,
      },
    });
    expect(crashRestart.runtime()).toEqual(durableTarget);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(initial);

    const resolved = crashRestartService.resolve({
      mode: 'use_state',
      expected_file_hash: afterCrash.file_hash!,
      expected_state_hash: afterCrash.state_hash!,
    });
    expect(resolved.config).toMatchObject({ name: 'Durable target', config_revision: 3 });
    expect(crashRestart.events.at(-1)?.details).toMatchObject({
      superseded_config_intent: {
        archive_path: archivePath,
        intent_sha256: status.conflicted_intent!.intent_sha256,
      },
    });
    expect(existsSync(archivePath)).toBe(true);

    const secondRestart = harness(resolved.config);
    const secondService = new EngagementConfigService(secondRestart.host, file);
    expect(secondService.initialize({ restored: true, persistence_writable: true })).toMatchObject({
      status: 'in_sync',
      resolution_required: false,
      intent_present: false,
    });
  });

  it('quarantines a pre-file intent after an external edit without changing durable state', () => {
    const initial = withConfigMetadata(config(), 1);
    const external = withConfigMetadata(config({ name: 'External before restart' }), 7);
    writeFileSync(file, JSON.stringify(initial));
    const first = harness(initial);
    const firstService = new EngagementConfigService(first.host, file);
    firstService.initialize({ restored: true, persistence_writable: true });
    (firstService as unknown as { writeConfig: (next: EngagementConfig) => void }).writeConfig = () => {
      throw new Error('injected config rename failure');
    };

    expect(() => firstService.commit({ ...initial, name: 'Never applied' }, 'test'))
      .toThrow('injected config rename failure');
    expect(first.runtime()).toEqual(initial);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(initial);
    writeFileSync(file, JSON.stringify(external));

    const restarted = harness(initial);
    const restartedService = new EngagementConfigService(restarted.host, file);
    const status = restartedService.initialize({ restored: true, persistence_writable: true });
    expect(status).toMatchObject({
      status: 'diverged',
      intent_present: false,
      file_hash: external.config_hash,
      state_hash: initial.config_hash,
    });
    expect(restarted.runtime()).toEqual(initial);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(external);

    const conflict = structuredClone(status.conflicted_intent!);
    const fourthState = withConfigMetadata(config({ name: 'Fourth external state' }), 11);
    writeFileSync(file, JSON.stringify(fourthState));
    const secondRestart = harness(initial);
    const secondRestartService = new EngagementConfigService(secondRestart.host, file);
    const afterSecondEdit = secondRestartService.initialize({ restored: true, persistence_writable: true });
    expect(afterSecondEdit).toMatchObject({
      status: 'diverged',
      file_hash: fourthState.config_hash,
      state_hash: initial.config_hash,
      conflicted_intent: {
        archive_path: conflict.archive_path,
        observed_file_hash: external.config_hash,
      },
    });

    const resolved = secondRestartService.resolve({
      mode: 'use_state',
      expected_file_hash: afterSecondEdit.file_hash!,
      expected_state_hash: afterSecondEdit.state_hash!,
    });
    expect(resolved.config).toMatchObject({ name: initial.name, config_revision: 12 });
    expect(secondRestart.events.at(-1)?.details).toMatchObject({
      superseded_config_intent: conflict,
    });
  });

  it.each([
    ['truncated JSON', Buffer.from('{"version":1')],
    ['invalid checksum', Buffer.from(JSON.stringify({
      version: 1,
      engagement_id: 'config-service-test',
      config: withConfigMetadata(config(), 2),
      intent_checksum: '0'.repeat(64),
    }))],
  ])('preserves %s intent bytes and makes quarantine idempotent', (_label, rawIntent) => {
    const initial = withConfigMetadata(config(), 1);
    const caseFile = join(dir, `${createHash('sha256').update(rawIntent).digest('hex').slice(0, 8)}.json`);
    const intentPath = `${caseFile}.write-intent.json`;
    writeFileSync(caseFile, JSON.stringify(initial));
    writeFileSync(intentPath, rawIntent);

    const first = harness(initial);
    const firstService = new EngagementConfigService(first.host, caseFile);
    const firstStatus = firstService.initialize({ restored: true, persistence_writable: true });
    expect(firstStatus).toMatchObject({ status: 'diverged', intent_present: false });
    const archivePath = firstStatus.conflicted_intent!.archive_path;
    verifyConflictArchive(archivePath, rawIntent);

    // Simulate a crash after the conflict artifact reached stable storage but
    // before the active marker was durably observed as removed.
    writeFileSync(intentPath, rawIntent);
    const second = harness(initial);
    const secondService = new EngagementConfigService(second.host, caseFile);
    const secondStatus = secondService.initialize({ restored: true, persistence_writable: true });
    expect(secondStatus).toMatchObject({
      status: 'diverged',
      intent_present: false,
      conflicted_intent: { archive_path: archivePath },
    });
    expect(existsSync(intentPath)).toBe(false);
    expect(readdirSync(dir).filter(name => name.includes('.write-intent.json.conflict-'))).toHaveLength(1);
    verifyConflictArchive(archivePath, rawIntent);
  });

  it('retains quarantined-intent audit metadata when reconciliation resumes after restart', () => {
    const initial = withConfigMetadata(config(), 1);
    writeFileSync(file, JSON.stringify(initial));
    const malformedIntent = Buffer.from('{"broken":');
    writeFileSync(`${file}.write-intent.json`, malformedIntent);
    const interrupted = harness(initial, () => { throw new Error('injected state fsync failure'); });
    const interruptedService = new EngagementConfigService(interrupted.host, file);
    const diverged = interruptedService.initialize({ restored: true, persistence_writable: true });
    const conflict = structuredClone(diverged.conflicted_intent!);

    expect(() => interruptedService.resolve({
      mode: 'use_state',
      expected_file_hash: diverged.file_hash!,
      expected_state_hash: diverged.state_hash!,
    })).toThrow('injected state fsync failure');
    expect(existsSync(`${file}.write-intent.json`)).toBe(true);

    const restarted = harness(initial);
    const restartedService = new EngagementConfigService(restarted.host, file);
    const recovered = restartedService.initialize({ restored: true, persistence_writable: true });
    expect(recovered).toMatchObject({ status: 'recovered', resolution_required: false });
    expect(restarted.events).toHaveLength(1);
    expect(restarted.events[0].details).toMatchObject({
      superseded_config_intent: conflict,
    });
    expect(existsSync(conflict.archive_path)).toBe(true);
    expect(existsSync(`${file}.write-intent.json`)).toBe(false);
  });

  it('defers a file race after scope replay prepare and quarantines its retained intent', () => {
    const initial = withConfigMetadata(config(), 1);
    const target = withConfigMetadata({
      ...initial,
      scope: { ...initial.scope, cidrs: [...initial.scope.cidrs, '10.77.0.0/24'] },
    }, 2);
    const external = withConfigMetadata(config({ name: 'Late external file race' }), 9);
    writeFileSync(file, JSON.stringify(initial));
    const replay = harness(initial);
    const replayService = new EngagementConfigService(replay.host, file);
    replayService.initialize({ restored: true, persistence_writable: true });

    replayService.installJournalTarget(target, 'scope.update', true, initial.config_hash!);
    replayService.prepareJournalReplayCommit();
    const retainedIntent = readFileSync(`${file}.write-intent.json`);
    writeFileSync(file, JSON.stringify(external));
    replayService.completeJournalReplayCommit();

    const deferred = replayService.getStatus();
    expect(deferred).toMatchObject({
      status: 'diverged',
      resolution_required: true,
      intent_present: false,
      file_hash: external.config_hash,
      state_hash: target.config_hash,
      runtime_hash: target.config_hash,
      conflicted_intent: {
        intent_sha256: createHash('sha256').update(retainedIntent).digest('hex'),
        observed_file_hash: external.config_hash,
        observed_state_hash: target.config_hash,
      },
    });
    expect(replay.runtime()).toEqual(target);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(external);
    expect(existsSync(`${file}.write-intent.json`)).toBe(false);
    verifyConflictArchive(deferred.conflicted_intent!.archive_path, retainedIntent);

    const restarted = harness(target);
    const restartedService = new EngagementConfigService(restarted.host, file);
    const blocked = restartedService.initialize({ restored: true, persistence_writable: true });
    expect(blocked).toMatchObject({
      status: 'diverged',
      conflicted_intent: { archive_path: deferred.conflicted_intent!.archive_path },
    });
    const resolved = restartedService.resolve({
      mode: 'use_state',
      expected_file_hash: blocked.file_hash!,
      expected_state_hash: blocked.state_hash!,
    });
    expect(resolved.config).toMatchObject({
      config_revision: 10,
      scope: { cidrs: expect.arrayContaining(['10.77.0.0/24']) },
    });
    expect(restarted.events.at(-1)?.details).toMatchObject({
      superseded_config_intent: deferred.conflicted_intent,
    });
  });

  it('preserves a file edit that lands at the recovered scope compare-and-swap boundary', () => {
    const initial = withConfigMetadata(config(), 1);
    const target = withConfigMetadata({
      ...initial,
      scope: { ...initial.scope, cidrs: [...initial.scope.cidrs, '10.88.0.0/24'] },
    }, 2);
    const external = withConfigMetadata(config({ name: 'CAS boundary edit' }), 12);
    writeFileSync(file, JSON.stringify(initial));
    const replay = harness(initial);
    const service = new EngagementConfigService(replay.host, file);
    service.initialize({ restored: true, persistence_writable: true });
    service.installJournalTarget(target, 'scope.update', true, initial.config_hash!);
    service.prepareJournalReplayCommit();
    const retainedIntent = readFileSync(`${file}.write-intent.json`);

    const internal = service as unknown as {
      writeJsonAtomic: (path: string, value: unknown, assertCurrent?: () => void) => void;
    };
    const originalWrite = internal.writeJsonAtomic.bind(service);
    let injected = false;
    internal.writeJsonAtomic = (path, value, assertCurrent) => {
      if (path === file && assertCurrent && !injected) {
        injected = true;
        writeFileSync(file, JSON.stringify(external));
      }
      originalWrite(path, value, assertCurrent);
    };

    service.completeJournalReplayCommit();

    expect(injected).toBe(true);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(external);
    expect(replay.runtime()).toEqual(target);
    const status = service.getStatus();
    expect(status).toMatchObject({
      status: 'diverged',
      resolution_required: true,
      file_hash: external.config_hash,
      state_hash: target.config_hash,
      runtime_hash: target.config_hash,
      conflicted_intent: {
        intent_sha256: createHash('sha256').update(retainedIntent).digest('hex'),
        observed_file_hash: external.config_hash,
      },
    });
    verifyConflictArchive(status.conflicted_intent!.archive_path, retainedIntent);
  });

  it('detects an external file edit before accepting the next mutation', () => {
    const initial = withConfigMetadata(config(), 1);
    writeFileSync(file, JSON.stringify(initial));
    const h = harness(initial);
    const service = new EngagementConfigService(h.host, file);
    service.initialize({ restored: true, persistence_writable: true });
    const external = withConfigMetadata({ ...initial, name: 'External' }, 2);
    writeFileSync(file, JSON.stringify(external));

    expect(() => service.commit({ ...initial, name: 'Internal' }, 'test')).toThrow(/read-only|changed after startup/i);
    expect(service.getStatus()).toMatchObject({ status: 'diverged', resolution_required: true });
    expect(JSON.parse(readFileSync(file, 'utf8')).name).toBe('External');
    expect(h.runtime().name).toBe(initial.name);
    expect(h.persistCount()).toBe(0);
  });

  it('can restore a missing active file with explicit durable-state authority', () => {
    const state = withConfigMetadata(config({ name: 'Durable' }), 2);
    const h = harness(state);
    const service = new EngagementConfigService(h.host, file);
    const diverged = service.initialize({ restored: true, persistence_writable: true });

    expect(diverged).toMatchObject({
      status: 'diverged',
      file_valid: false,
      allowed_resolutions: ['use_state'],
    });
    expect(diverged.file_hash).toMatch(/^[0-9a-f]{64}$/);

    const result = service.resolve({
      mode: 'use_state',
      expected_file_hash: diverged.file_hash!,
      expected_state_hash: diverged.state_hash!,
    });
    expect(result.config).toMatchObject({ name: 'Durable', config_revision: 3 });
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(result.config);
  });

  it('does not advertise file authority when immutable engagement identity differs', () => {
    const state = withConfigMetadata(config({ name: 'Durable' }), 2);
    const other = withConfigMetadata({
      ...config({ name: 'Wrong engagement' }),
      id: 'other-engagement',
    }, 3);
    writeFileSync(file, JSON.stringify(other));
    const h = harness(state);
    const service = new EngagementConfigService(h.host, file);

    const status = service.initialize({ restored: true, persistence_writable: true });

    expect(status).toMatchObject({
      status: 'diverged',
      resolution_required: true,
      allowed_resolutions: ['use_state'],
    });
  });
});
