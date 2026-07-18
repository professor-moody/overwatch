import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import {
  acquireDaemonInstanceLease,
  daemonInstanceLeasePath,
  readDaemonInstanceOwner,
  runtimePathIdentity,
  type DaemonLeaseProcessObserver,
} from '../daemon-instance-lease.js';

const roots: string[] = [];

function tempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), 'overwatch-daemon-lease-'));
  roots.push(root);
  return root;
}

function input(root: string, stateName = 'state-eng.json') {
  return {
    state_file: join(root, stateName),
    config_file: join(root, 'engagement.json'),
    engagement_id: 'eng',
    transport: 'http' as const,
    build_input_sha256: 'a'.repeat(64),
    git_sha: 'deadbeef',
    dashboard_url: 'http://127.0.0.1:8384',
    mcp_url: 'http://127.0.0.1:3000/mcp',
  };
}

const observer: DaemonLeaseProcessObserver = {
  isAlive: pid => pid === process.pid,
  startIdentity: pid => pid === process.pid ? 'current-process-start' : undefined,
};

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('DaemonInstanceLease', () => {
  it('owns the canonical state family for the process lifetime', () => {
    const root = tempRoot();
    const lease = acquireDaemonInstanceLease(input(root), observer);

    const owner = readDaemonInstanceOwner(input(root).state_file)!;
    expect(owner).toMatchObject({
      pid: process.pid,
      process_start_identity: 'current-process-start',
      engagement_id: 'eng',
      phase: 'recovering',
      state_identity_sha256: runtimePathIdentity(input(root).state_file),
      config_identity_sha256: runtimePathIdentity(input(root).config_file),
    });
    expect(() => acquireDaemonInstanceLease(input(root), observer)).toThrow(
      /already owned by Overwatch PID/,
    );

    lease.update({
      phase: 'ready_read_only',
      persistence_writable: false,
      recovery_reason: 'config divergence',
    });
    expect(lease.getStatus()).toMatchObject({
      daemon_instance_id: lease.instance_id,
      phase: 'ready_read_only',
      persistence_writable: false,
      recovery_reason: 'config divergence',
    });
    lease.update({ phase: 'ready', persistence_writable: true, recovery_reason: null });
    expect(lease.getStatus()).not.toHaveProperty('recovery_reason');

    lease.release();
    expect(readDaemonInstanceOwner(input(root).state_file)).toBeUndefined();
    const replacement = acquireDaemonInstanceLease(input(root), observer);
    replacement.release();
  });

  it('reclaims an exact dead owner but never an unreadable one', () => {
    const root = tempRoot();
    const stateFile = input(root).state_file;
    const path = daemonInstanceLeasePath(stateFile);
    const first = acquireDaemonInstanceLease(input(root), observer);
    const deadOwner = first.getOwner();
    // Simulate a crash: retain the durable record while the observer proves the
    // exact prior PID is no longer alive.
    writeFileSync(path, `${JSON.stringify({ ...deadOwner, pid: 999_999_991 })}\n`);
    const deadObserver: DaemonLeaseProcessObserver = {
      isAlive: () => false,
      startIdentity: pid => pid === process.pid ? 'new-process-start' : undefined,
    };
    const replacement = acquireDaemonInstanceLease(input(root), deadObserver);
    expect(replacement.getOwner().process_start_identity).toBe('new-process-start');
    replacement.release();

    writeFileSync(path, '{not-json');
    expect(() => acquireDaemonInstanceLease(input(root), deadObserver)).toThrow(
      /runtime owner record is unreadable/,
    );
    expect(readFileSync(path, 'utf8')).toBe('{not-json');
  });

  it('permits independent state families without weakening identity', () => {
    const root = tempRoot();
    const first = acquireDaemonInstanceLease(input(root, 'state-a.json'), observer);
    const second = acquireDaemonInstanceLease(input(root, 'state-b.json'), observer);
    expect(first.state_file).not.toBe(second.state_file);
    first.release();
    second.release();
  });

  it('fails closed when a live owner start identity is not observable', () => {
    const root = tempRoot();
    const unverifiable: DaemonLeaseProcessObserver = {
      isAlive: pid => pid === process.pid,
      startIdentity: () => undefined,
    };
    const lease = acquireDaemonInstanceLease(input(root), unverifiable);
    expect(lease.getOwner().process_start_identity).toMatch(/^unverifiable-current-process-/);
    expect(() => acquireDaemonInstanceLease(input(root), observer)).toThrow(/already owned/);
    lease.release();
  });

  it.skipIf(process.platform === 'win32')('retains a live owner written with the legacy raw start identity', () => {
    const root = tempRoot();
    const selected = input(root);
    const lease = acquireDaemonInstanceLease(selected);
    const legacyIdentity = execFileSync('ps', ['-o', 'lstart=', '-p', String(process.pid)], {
      encoding: 'utf8',
      timeout: 1_000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    writeFileSync(lease.owner_path, `${JSON.stringify({
      ...lease.getOwner(),
      process_start_identity: legacyIdentity,
    })}\n`);

    expect(() => acquireDaemonInstanceLease(selected)).toThrow(/already owned/);
  });

  it('treats symlinked parents as the same state-family owner', () => {
    const root = tempRoot();
    const physical = join(root, 'physical');
    const alias = join(root, 'alias');
    mkdirSync(physical);
    symlinkSync(physical, alias, 'dir');
    const realInput = input(physical);
    const aliasInput = input(alias);

    const lease = acquireDaemonInstanceLease(realInput, observer);
    expect(daemonInstanceLeasePath(aliasInput.state_file))
      .toBe(daemonInstanceLeasePath(realInput.state_file));
    expect(() => acquireDaemonInstanceLease(aliasInput, observer))
      .toThrow(/already owned by Overwatch PID/);
    lease.release();
  });
});
