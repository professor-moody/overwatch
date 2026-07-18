import { describe, expect, it } from 'vitest';
import { execFileSync, spawn } from 'child_process';
import {
  readProcessStartIdentity,
  processStartIdentityMatches,
  readProcessOwnershipToken,
  signalVerifiedRuntimeProcess,
  verifyRuntimeProcessIdentity,
  type ProcessIdentityObserver,
} from '../process-identity.js';

function observer(input: {
  alive: boolean;
  pid?: number;
  group?: number;
  start?: string;
  token?: string;
}): ProcessIdentityObserver {
  return {
    isAlive: () => input.alive,
    observe: pid => ({
      pid: input.pid ?? pid,
      process_group_id: input.group,
      process_start_identity: input.start,
      ownership_token: input.token,
    }),
  };
}

describe('runtime process identity', () => {
  it.skipIf(process.platform === 'win32')('uses the same start identity across caller time zones', () => {
    const prior = process.env.TZ;
    try {
      process.env.TZ = 'America/Los_Angeles';
      const pacific = readProcessStartIdentity(process.pid);
      process.env.TZ = 'UTC';
      const utc = readProcessStartIdentity(process.pid);
      expect(pacific).toMatch(/^posix-lstart-utc:/);
      expect(utc).toBe(pacific);
    } finally {
      if (prior === undefined) delete process.env.TZ;
      else process.env.TZ = prior;
    }
  });

  it.skipIf(process.platform === 'win32')('recognizes the unprefixed live-owner identity written by older versions', () => {
    const legacy = execFileSync('ps', ['-o', 'lstart=', '-p', String(process.pid)], {
      encoding: 'utf8',
    }).trim();
    expect(legacy).not.toContain('posix-lstart-utc:');
    expect(processStartIdentityMatches(process.pid, legacy)).toBe(true);
  });

  it('retains an unverifiable live-owner marker instead of treating it as stale', () => {
    expect(processStartIdentityMatches(
      process.pid,
      'unverifiable-current-process-legacy-owner',
    )).toBeUndefined();
  });

  it.skipIf(process.platform === 'win32')('fails closed when a legacy identity changes with the caller time zone', () => {
    const prior = process.env.TZ;
    try {
      process.env.TZ = 'America/Chicago';
      const legacy = execFileSync('ps', ['-o', 'lstart=', '-p', String(process.pid)], {
        encoding: 'utf8',
      }).trim();
      process.env.TZ = 'UTC';
      expect(processStartIdentityMatches(process.pid, legacy)).not.toBe(false);
    } finally {
      if (prior === undefined) delete process.env.TZ;
      else process.env.TZ = prior;
    }
  });

  it('reads an ownership token from the command line when it is not in the environment', async () => {
    const token = '77777777-7777-4777-8777-777777777777';
    const child = spawn(
      process.execPath,
      [
        '-e',
        'setInterval(() => {}, 1000)',
        '--',
        `--overwatch-runtime-token=${token}`,
      ],
      {
        env: Object.fromEntries(
          Object.entries(process.env).filter(([key]) => key !== 'OVERWATCH_RUNTIME_TOKEN'),
        ),
        stdio: 'ignore',
      },
    );
    await new Promise<void>((resolve, reject) => {
      child.once('spawn', resolve);
      child.once('error', reject);
    });
    try {
      expect(readProcessOwnershipToken(child.pid!)).toBe(token);
    } finally {
      try { child.kill('SIGKILL'); } catch {}
      await new Promise<void>(resolve => child.once('close', () => resolve()));
    }
  });

  it('verifies the same physical process', () => {
    expect(verifyRuntimeProcessIdentity(
      { pid: 123, process_group_id: 123, process_start_identity: 'start-a' },
      observer({ alive: true, group: 123, start: 'start-a' }),
    ).status).toBe('verified');
  });

  it('distinguishes a reused pid and an exited process', () => {
    expect(verifyRuntimeProcessIdentity(
      { pid: 123, process_group_id: 123, process_start_identity: 'start-a' },
      observer({ alive: true, group: 123, start: 'start-b' }),
    ).status).toBe('pid_reused');
    expect(verifyRuntimeProcessIdentity(
      { pid: 123, process_group_id: 123, process_start_identity: 'start-a' },
      observer({ alive: false }),
    ).status).toBe('not_running');
  });

  it('refuses unverifiable ownership', () => {
    expect(verifyRuntimeProcessIdentity(
      { pid: 123, process_group_id: 123 },
      observer({ alive: true, group: 123 }),
    ).status).toBe('unverifiable');
  });

  it('requires the managed supervisor ownership token to match', () => {
    const managed = {
      pid: 123,
      process_group_id: 123,
      process_start_identity: 'start-a',
      ownership_mode: 'managed_supervisor' as const,
      ownership_token: 'token-a',
      signal_scope: 'process_group' as const,
    };
    expect(verifyRuntimeProcessIdentity(
      managed,
      observer({ alive: true, group: 123, start: 'start-a', token: 'token-a' }),
    ).status).toBe('verified');
    expect(verifyRuntimeProcessIdentity(
      managed,
      observer({ alive: true, group: 123, start: 'start-a', token: 'token-b' }),
    ).status).toBe('pid_reused');
    expect(verifyRuntimeProcessIdentity(
      managed,
      observer({ alive: true, group: 123, start: 'start-a' }),
    ).status).toBe('unverifiable');
  });

  it('never signals a reused or unverifiable pid', () => {
    expect(signalVerifiedRuntimeProcess(
      { pid: 999_999_991, process_group_id: 999_999_991, process_start_identity: 'old' },
      'SIGTERM',
      observer({ alive: true, group: 999_999_991, start: 'new' }),
    ).status).toBe('pid_reused');
    expect(signalVerifiedRuntimeProcess(
      { pid: 999_999_992, process_group_id: 999_999_992 },
      'SIGTERM',
      observer({ alive: true, group: 999_999_992 }),
    ).status).toBe('unverifiable');
  });

  it('honors an explicit non-signalable ownership record', () => {
    expect(signalVerifiedRuntimeProcess(
      {
        pid: 999_999_993,
        process_group_id: 999_999_993,
        process_start_identity: 'same',
        signal_scope: 'none',
      },
      'SIGTERM',
      observer({ alive: true, group: 999_999_993, start: 'same' }),
    ).status).toBe('unverifiable');
  });

  it.skipIf(process.platform === 'win32')(
    'requires a supervisor-owned, observed process group before group signaling',
    () => {
      expect(verifyRuntimeProcessIdentity(
        {
          pid: 123,
          process_group_id: 122,
          process_start_identity: 'start-a',
          signal_scope: 'process_group',
        },
        observer({ alive: true, group: 122, start: 'start-a' }),
      ).status).toBe('unverifiable');
      expect(verifyRuntimeProcessIdentity(
        {
          pid: 123,
          process_group_id: 123,
          process_start_identity: 'start-a',
          signal_scope: 'process_group',
        },
        observer({ alive: true, start: 'start-a' }),
      ).status).toBe('unverifiable');
    },
  );

  it('converts signal races and permission failures into safe verification outcomes', () => {
    const run = {
      pid: 123,
      process_group_id: 123,
      process_start_identity: 'start-a',
      signal_scope: 'pid' as const,
    };
    expect(signalVerifiedRuntimeProcess(
      run,
      'SIGTERM',
      observer({ alive: true, group: 123, start: 'start-a' }),
      () => {
        const error = new Error('gone') as NodeJS.ErrnoException;
        error.code = 'ESRCH';
        throw error;
      },
    ).status).toBe('not_running');
    expect(signalVerifiedRuntimeProcess(
      run,
      'SIGTERM',
      observer({ alive: true, group: 123, start: 'start-a' }),
      () => {
        const error = new Error('denied') as NodeJS.ErrnoException;
        error.code = 'EPERM';
        throw error;
      },
    ).status).toBe('unverifiable');
  });
});
