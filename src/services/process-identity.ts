import { createHash, randomUUID } from 'crypto';
import { execFileSync } from 'child_process';
import { readFileSync } from 'fs';
import type { PersistedRuntimeRunV1 } from './persisted-state.js';

export interface ProcessIdentity {
  pid: number;
  process_group_id?: number;
  process_start_identity?: string;
  ownership_token?: string;
}

export type ProcessIdentityVerification =
  | { status: 'verified'; observed: ProcessIdentity }
  | { status: 'not_running'; observed?: ProcessIdentity }
  | { status: 'pid_reused'; observed: ProcessIdentity }
  | { status: 'unverifiable'; observed: ProcessIdentity };

export interface ProcessIdentityObserver {
  isAlive(pid: number): boolean;
  observe(pid: number): ProcessIdentity;
}

function positiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

export function processIsAlive(pid: number): boolean {
  if (!positiveSafeInteger(pid)) return false;
  try {
    process.kill(pid, 0);
    if (process.platform === 'win32') return true;
    try {
      const state = execFileSync(
        'ps',
        ['-o', 'stat=', '-p', String(pid)],
        { encoding: 'utf8', timeout: 1_000, stdio: ['ignore', 'pipe', 'ignore'] },
      ).trim();
      return state.length > 0 && !state.startsWith('Z');
    } catch {
      return false;
    }
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

export function readProcessStartIdentity(pid: number): string | undefined {
  if (!positiveSafeInteger(pid)) return undefined;
  if (process.platform === 'win32') {
    try {
      const started = execFileSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          `(Get-Process -Id ${pid}).StartTime.ToUniversalTime().Ticks`,
        ],
        { encoding: 'utf8', timeout: 2_000, stdio: ['ignore', 'pipe', 'ignore'] },
      ).trim();
      return started ? `windows-start-ticks:${started}` : undefined;
    } catch {
      return undefined;
    }
  }
  try {
    const started = execFileSync(
      'ps',
      ['-o', 'lstart=', '-p', String(pid)],
      { encoding: 'utf8', timeout: 1_000, stdio: ['ignore', 'pipe', 'ignore'] },
    ).trim();
    return started || undefined;
  } catch {
    return undefined;
  }
}

export function readProcessOwnershipToken(pid: number): string | undefined {
  if (!positiveSafeInteger(pid)) return undefined;
  const extract = (value: string): string | undefined => {
    const match = value.match(/--overwatch-runtime-token=([0-9a-f-]{36})/i)
      ?? value.match(/OVERWATCH_RUNTIME_TOKEN=([0-9a-f-]{36})/i);
    return match?.[1];
  };
  if (process.platform === 'linux') {
    try {
      const token = extract(readFileSync(`/proc/${pid}/environ`, 'utf8').replace(/\0/g, ' '));
      if (token) return token;
    } catch {
      // Fall through to command-line inspection.
    }
  }
  if (process.platform === 'win32') {
    try {
      const commandLine = execFileSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          `(Get-CimInstance Win32_Process -Filter "ProcessId = ${pid}").CommandLine`,
        ],
        { encoding: 'utf8', timeout: 2_000, stdio: ['ignore', 'pipe', 'ignore'] },
      );
      return extract(commandLine);
    } catch {
      return undefined;
    }
  }
  try {
    const commandLine = execFileSync(
      'ps',
      ['-o', 'command=', '-p', String(pid)],
      { encoding: 'utf8', timeout: 1_000, stdio: ['ignore', 'pipe', 'ignore'] },
    );
    return extract(commandLine);
  } catch {
    return undefined;
  }
}

export function readProcessGroupId(pid: number): number | undefined {
  if (!positiveSafeInteger(pid) || process.platform === 'win32') return undefined;
  try {
    const raw = execFileSync(
      'ps',
      ['-o', 'pgid=', '-p', String(pid)],
      { encoding: 'utf8', timeout: 1_000, stdio: ['ignore', 'pipe', 'ignore'] },
    ).trim();
    const group = Number(raw);
    return positiveSafeInteger(group) ? group : undefined;
  } catch {
    return undefined;
  }
}

export function observeProcessIdentity(pid: number): ProcessIdentity {
  return {
    pid,
    process_group_id: readProcessGroupId(pid),
    process_start_identity: readProcessStartIdentity(pid),
    ownership_token: readProcessOwnershipToken(pid),
  };
}

export const defaultProcessIdentityObserver: ProcessIdentityObserver = {
  isAlive: processIsAlive,
  observe: observeProcessIdentity,
};

export function verifyRuntimeProcessIdentity(
  run: Pick<
    PersistedRuntimeRunV1,
    'pid'
    | 'process_group_id'
    | 'process_start_identity'
    | 'ownership_mode'
    | 'ownership_token'
    | 'signal_scope'
  >,
  observer: ProcessIdentityObserver = defaultProcessIdentityObserver,
): ProcessIdentityVerification {
  if (!positiveSafeInteger(run.pid)) {
    return { status: 'unverifiable', observed: { pid: run.pid ?? 0 } };
  }
  if (!observer.isAlive(run.pid)) return { status: 'not_running' };
  const observed = observer.observe(run.pid);
  if (!run.process_start_identity || !observed.process_start_identity) {
    return { status: 'unverifiable', observed };
  }
  if (run.ownership_mode === 'managed_supervisor') {
    if (!run.ownership_token || !observed.ownership_token) {
      return { status: 'unverifiable', observed };
    }
    if (run.ownership_token !== observed.ownership_token) {
      return { status: 'pid_reused', observed };
    }
  }
  if (run.process_start_identity !== observed.process_start_identity) {
    return { status: 'pid_reused', observed };
  }
  if (run.signal_scope === 'process_group' && process.platform !== 'win32') {
    if (
      !positiveSafeInteger(run.process_group_id)
      || !positiveSafeInteger(observed.process_group_id)
      || run.process_group_id !== run.pid
    ) {
      return { status: 'unverifiable', observed };
    }
  }
  if (
    run.process_group_id !== undefined
    && observed.process_group_id !== undefined
    && run.process_group_id !== observed.process_group_id
  ) {
    return { status: 'pid_reused', observed };
  }
  return { status: 'verified', observed };
}

export function signalVerifiedRuntimeProcess(
  run: Pick<
    PersistedRuntimeRunV1,
    'pid'
    | 'process_group_id'
    | 'process_start_identity'
    | 'ownership_mode'
    | 'ownership_token'
    | 'signal_scope'
  >,
  signal: NodeJS.Signals,
  observer: ProcessIdentityObserver = defaultProcessIdentityObserver,
  sendSignal: (target: number, signal: NodeJS.Signals) => void = (target, sig) => {
    if (process.platform === 'win32') {
      execFileSync(
        'taskkill.exe',
        ['/PID', String(target), '/T', '/F'],
        { timeout: 5_000, stdio: 'ignore' },
      );
      return;
    }
    process.kill(target, sig);
  },
): ProcessIdentityVerification {
  const verification = verifyRuntimeProcessIdentity(run, observer);
  if (verification.status !== 'verified') return verification;
  if (run.signal_scope === 'none') {
    return { status: 'unverifiable', observed: verification.observed };
  }
  const target = run.signal_scope === 'process_group'
    && process.platform !== 'win32'
    ? -run.process_group_id!
    : run.pid!;
  try {
    sendSignal(target, signal);
    return verification;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ESRCH'
      ? { status: 'not_running' }
      : { status: 'unverifiable', observed: verification.observed };
  }
}

const daemonStartIdentity = readProcessStartIdentity(process.pid)
  ?? `unverifiable-${process.pid}`;
const daemonOwnerNonce = randomUUID();

export function currentDaemonOwner(): string {
  const digest = createHash('sha256')
    .update(`${process.pid}\0${daemonStartIdentity}\0${daemonOwnerNonce}`)
    .digest('hex')
    .slice(0, 24);
  return `daemon-${process.pid}-${digest}`;
}
