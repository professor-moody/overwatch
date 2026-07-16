import { describe, expect, it } from 'vitest';
import {
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
