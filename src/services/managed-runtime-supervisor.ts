import { randomUUID } from 'crypto';
import { spawn, type ChildProcess, type SpawnOptions } from 'child_process';
import { observeProcessIdentity, type ProcessIdentity } from './process-identity.js';

export interface ManagedRuntimeTarget {
  binary: string;
  args: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

export interface ManagedRuntimeSupervisorHooks {
  /**
   * Runs after the supervisor reports its identity and before the target can
   * launch. The caller must durably publish ownership here. Throwing refuses
   * acknowledgement; the supervisor exits without spawning the target.
   */
  onSupervisorReady(identity: ProcessIdentity): void;
  onTargetLaunched?(targetPid: number | undefined): void;
  onTargetExit?(exitCode: number | null, signal: NodeJS.Signals | null): void;
  onTargetError?(message: string): void;
  onBackgroundDescendants?(message: string): void;
}

export interface ManagedRuntimeSupervisorOptions {
  acknowledgementTimeoutMs?: number;
  spawnFn?: (
    command: string,
    args: string[],
    options: SpawnOptions,
  ) => ChildProcess;
}

export interface ManagedRuntimeSupervisorHandle {
  child: ChildProcess;
  token: string;
  ready: Promise<ProcessIdentity>;
  launched: Promise<number | undefined>;
  targetExit: Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>;
}

type SupervisorMessage =
  | {
      type: 'supervisor_ready';
      token: string;
      pid: number;
      process_group_id?: number;
      process_start_identity?: string;
      ownership_token?: string;
    }
  | { type: 'target_launched'; token: string; target_pid?: number }
  | {
      type: 'target_exit';
      token: string;
      exit_code: number | null;
      signal: NodeJS.Signals | null;
    }
  | {
      type: 'target_background';
      token: string;
      message: string;
      exit_code: number | null;
      signal: NodeJS.Signals | null;
    }
  | { type: 'target_error'; token: string; message: string };

const SUPERVISOR_SOURCE = String.raw`
const { spawn, execFileSync } = require('node:child_process');
const tokenArgument = process.argv.find((value) => value.startsWith('--overwatch-runtime-token='));
const token = process.env.OVERWATCH_RUNTIME_TOKEN
  || (tokenArgument ? tokenArgument.slice('--overwatch-runtime-token='.length) : undefined);
const timeoutMs = Number(process.env.OVERWATCH_RUNTIME_ACK_TIMEOUT_MS || 5000);
let target = null;
let launchAccepted = false;
// The daemon may crash while the managed target is still producing output.
// Broken stdout/stderr pipes must not take down the durable group leader; the
// replacement daemon needs that same physical owner to verify and reclaim the
// whole process group.
process.stdout.on('error', () => {});
process.stderr.on('error', () => {});
const send = (message, callback) => {
  try {
    if (process.connected) {
      process.send({ ...message, token }, () => callback && callback());
      return;
    }
  } catch {}
  if (callback) callback();
};
let gracefulExitRequested = false;
const gracefulExit = (exitCode) => {
  if (gracefulExitRequested) return;
  gracefulExitRequested = true;
  process.exitCode = exitCode;
  // Closing IPC releases the supervisor's last durable-control handle. Avoid
  // process.exit(): it can discard stdout/stderr still buffered in the pipe to
  // the daemon, which would silently truncate both responses and evidence.
  try { if (process.connected) process.disconnect(); } catch {}
};
const startIdentity = () => {
  if (process.platform === 'win32') {
    try {
      const value = execFileSync('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        '(Get-Process -Id ' + process.pid + ').StartTime.ToUniversalTime().Ticks',
      ], {
        encoding: 'utf8', timeout: 2000, stdio: ['ignore', 'pipe', 'ignore']
      }).trim();
      return value ? 'windows-start-ticks:' + value : undefined;
    } catch { return undefined; }
  }
  try {
    const value = execFileSync('ps', ['-o', 'lstart=', '-p', String(process.pid)], {
      encoding: 'utf8', timeout: 1000, stdio: ['ignore', 'pipe', 'ignore'],
      env: { ...process.env, TZ: 'UTC', LC_ALL: 'C', LANG: 'C' }
    }).trim();
    return value ? 'posix-lstart-utc:' + value : undefined;
  } catch { return undefined; }
};
const processGroupId = () => {
  if (process.platform === 'win32') return undefined;
  try {
    const value = Number(execFileSync('ps', ['-o', 'pgid=', '-p', String(process.pid)], {
      encoding: 'utf8', timeout: 1000, stdio: ['ignore', 'pipe', 'ignore']
    }).trim());
    return Number.isSafeInteger(value) && value > 0 ? value : undefined;
  } catch { return undefined; }
};
const windowsProcessRows = () => {
  if (process.platform !== 'win32') return [];
  try {
    const value = execFileSync('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      '$self = $PID; Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $self } | Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress',
    ], {
      encoding: 'utf8', timeout: 2000, stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
    if (!value) return [];
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch { return []; }
};
const windowsDescendantPids = (roots) => {
  const rows = windowsProcessRows();
  const parents = new Set(roots.filter((pid) => Number.isSafeInteger(pid) && pid > 0));
  const descendants = [];
  let changed = true;
  while (changed) {
    changed = false;
    for (const row of rows) {
      const pid = Number(row.ProcessId);
      const parent = Number(row.ParentProcessId);
      if (
        !Number.isSafeInteger(pid)
        || pid <= 0
        || parents.has(pid)
        || !parents.has(parent)
      ) continue;
      parents.add(pid);
      descendants.push(pid);
      changed = true;
    }
  }
  return descendants;
};
const groupHasOtherMembers = (ignoredPid) => {
  if (process.platform === 'win32') {
    return windowsDescendantPids([process.pid, ignoredPid]).length > 0;
  }
  const group = processGroupId();
  if (!group) return true;
  try {
    const rows = execFileSync('ps', ['-axo', 'pid=,ppid=,pgid=,comm='], {
      encoding: 'utf8', timeout: 1000, stdio: ['ignore', 'pipe', 'ignore']
    }).trim().split(/\n+/);
    return rows.some((row) => {
      const [pidRaw, parentRaw, groupRaw, ...commandParts] = row.trim().split(/\s+/);
      const pid = Number(pidRaw);
      const parent = Number(parentRaw);
      const command = commandParts.join(' ');
      if (
        Number(groupRaw) !== group
        || pid === process.pid
        || pid === ignoredPid
      ) return false;
      // execFileSync's short-lived ps inspector inherits this process group
      // and is visible in its own snapshot. It is not target work.
      if (parent === process.pid && /(?:^|\/)ps$/.test(command)) return false;
      return true;
    });
  } catch {
    // Failure to prove the group is drained must retain the stable group leader
    // so the daemon can escalate safely.
    return true;
  }
};
const exitWhenGroupDrained = (exitCode) => {
  const boundedExit = exitCode === null ? 1 : Math.max(0, Math.min(255, exitCode));
  if (!groupHasOtherMembers(undefined)) {
    gracefulExit(boundedExit);
    return;
  }
  const drainTimer = setInterval(() => {
    if (!groupHasOtherMembers(undefined)) {
      clearInterval(drainTimer);
      gracefulExit(boundedExit);
    }
  }, 50);
};
const acknowledgementTimer = setTimeout(() => {
  if (!launchAccepted) process.exit(78);
}, Math.max(50, timeoutMs));
process.on('message', (message) => {
  if (!message || message.type !== 'launch' || message.token !== token || launchAccepted) return;
  launchAccepted = true;
  clearTimeout(acknowledgementTimer);
  try {
    target = spawn(message.binary, message.args || [], {
      cwd: message.cwd || undefined,
      env: message.env || process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false,
    });
  } catch (error) {
    send({ type: 'target_error', message: error instanceof Error ? error.message : String(error) });
    process.exit(127);
    return;
  }
  if (target.stdout) target.stdout.pipe(process.stdout);
  if (target.stderr) target.stderr.pipe(process.stderr);
  target.once('error', (error) => {
    send({ type: 'target_error', message: error instanceof Error ? error.message : String(error) });
    setImmediate(() => process.exit(127));
  });
  target.once('spawn', () => send({ type: 'target_launched', target_pid: target.pid }));
  let backgroundCleanup = false;
  target.once('exit', (code, signal) => {
    if (!groupHasOtherMembers(target.pid)) return;
    backgroundCleanup = true;
    const message = 'The managed target exited while descendants remained in its managed process group. Background descendants are not supported by run_tool/run_bash; launch externally and register the PID with track_process.';
    send({
      type: 'target_background',
      message,
      exit_code: code,
      signal,
    });
    // Keep the stable supervisor group leader alive through TERM, then remove
    // the entire group. This is fail-closed: no unowned descendant survives a
    // one-shot action that attempted to daemonize.
    if (process.platform === 'win32') {
      const descendants = windowsDescendantPids([process.pid, target.pid]);
      for (const pid of descendants) {
        try {
          execFileSync('taskkill.exe', ['/PID', String(pid), '/T', '/F'], {
            timeout: 5000,
            stdio: 'ignore',
          });
        } catch {}
      }
      process.exit(125);
      return;
    }
    try { process.kill(-process.pid, 'SIGTERM'); } catch {}
    setTimeout(() => {
      try { process.kill(-process.pid, 'SIGKILL'); }
      catch { process.exit(125); }
    }, 250);
  });
  // The close event fires only after the target's stdout/stderr handles have
  // closed. Exiting on the earlier exit event can discard final buffered output.
  target.once('close', (code, signal) => {
    if (backgroundCleanup) return;
    send(
      { type: 'target_exit', exit_code: code, signal },
      () => exitWhenGroupDrained(code),
    );
  });
});
const forwardTermination = (signal) => {
  if (!target) {
    process.exit(signal === 'SIGTERM' ? 143 : 130);
    return;
  }
  // The daemon signals the whole supervisor-owned process group, so the target
  // receives this signal too. Keeping the group leader alive until the target
  // exits is critical: it lets the daemon verify the same physical owner and
  // safely escalate the entire group to SIGKILL if a descendant ignores TERM.
  try { target.kill(signal); } catch {}
};
process.on('SIGTERM', () => forwardTermination('SIGTERM'));
process.on('SIGINT', () => forwardTermination('SIGINT'));
process.on('disconnect', () => {
  if (!launchAccepted) process.exit(79);
  // After durable acknowledgement, remain alive with the target. A replacement
  // daemon can verify and terminate this process group using the published
  // supervisor identity.
});
send({
  type: 'supervisor_ready',
  pid: process.pid,
  process_group_id: processGroupId(),
  process_start_identity: startIdentity(),
  ownership_token: token,
});
`;

function validSupervisorMessage(value: unknown): value is SupervisorMessage {
  return !!value && typeof value === 'object' && typeof (value as { type?: unknown }).type === 'string';
}

function terminateUnacknowledgedSupervisor(child: ChildProcess): void {
  const pid = child.pid;
  if (pid && process.platform !== 'win32') {
    try {
      process.kill(-pid, 'SIGTERM');
      return;
    } catch {
      // Fall through to the direct-child path.
    }
  }
  try { child.kill('SIGTERM'); } catch { /* already gone */ }
}

const SUPERVISOR_DENIED_ENV = new Set([
  'OVERWATCH_MCP_TOKEN',
  'OVERWATCH_MCP_TOKEN_FILE',
  'OVERWATCH_DASHBOARD_TOKEN',
  'OVERWATCH_DAEMON_MANAGED',
  'OVERWATCH_DAEMON_RECORD',
  'OVERWATCH_DAEMON_LOG',
  'OVERWATCH_DAEMON_MANAGEMENT_NONCE',
  'OVERWATCH_RUNTIME_PROFILE',
  'OVERWATCH_CHECKPOINT_SIGNING_KEY',
]);
const SUPERVISOR_SECRET_ENV = /^OVERWATCH_.*(?:TOKEN|SECRET|SIGNING_KEY|PASSWORD)/i;

/** The durable group leader needs ordinary process environment, never daemon authority. */
export function buildManagedSupervisorEnv(
  token: string,
  acknowledgementTimeoutMs: number,
  source: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(source)) {
    if (value === undefined || SUPERVISOR_DENIED_ENV.has(name) || SUPERVISOR_SECRET_ENV.test(name)) continue;
    environment[name] = value;
  }
  environment.OVERWATCH_RUNTIME_TOKEN = token;
  environment.OVERWATCH_RUNTIME_ACK_TIMEOUT_MS = String(acknowledgementTimeoutMs);
  return environment;
}

export function spawnManagedRuntimeSupervisor(
  target: ManagedRuntimeTarget,
  hooks: ManagedRuntimeSupervisorHooks,
  options: ManagedRuntimeSupervisorOptions = {},
): ManagedRuntimeSupervisorHandle {
  const token = randomUUID();
  const spawnFn = options.spawnFn ?? spawn;
  const acknowledgementTimeoutMs = options.acknowledgementTimeoutMs ?? 5_000;
  const child = spawnFn(
    process.execPath,
    ['-e', SUPERVISOR_SOURCE, '--', `--overwatch-runtime-token=${token}`],
    {
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      detached: process.platform !== 'win32',
      env: buildManagedSupervisorEnv(token, acknowledgementTimeoutMs),
    },
  );

  let resolveReady!: (identity: ProcessIdentity) => void;
  let rejectReady!: (error: Error) => void;
  let resolveLaunched!: (pid: number | undefined) => void;
  let rejectLaunched!: (error: Error) => void;
  let resolveExit!: (result: { exitCode: number | null; signal: NodeJS.Signals | null }) => void;
  const ready = new Promise<ProcessIdentity>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  const launched = new Promise<number | undefined>((resolve, reject) => {
    resolveLaunched = resolve;
    rejectLaunched = reject;
  });
  const targetExit = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    resolveExit = resolve;
  });
  // Callers may use only the child handle. Prevent a rejected setup promise
  // from becoming an unhandled rejection when ownership publication fails.
  void ready.catch(() => undefined);
  void launched.catch(() => undefined);

  let acknowledged = false;
  let targetReportedLaunch = false;
  let targetReportedExit = false;
  let reportedTargetExit: { exitCode: number | null; signal: NodeJS.Signals | null } | undefined;
  const failSetup = (message: string): void => {
    const error = new Error(message);
    rejectReady(error);
    rejectLaunched(error);
    terminateUnacknowledgedSupervisor(child);
  };

  child.on('message', (raw: unknown) => {
    if (!validSupervisorMessage(raw) || raw.token !== token) return;
    if (raw.type === 'supervisor_ready') {
      if (acknowledged) return;
      const identity: ProcessIdentity = {
        pid: raw.pid,
        process_group_id: raw.process_group_id,
        process_start_identity: raw.process_start_identity,
        ownership_token: raw.ownership_token,
      };
      if (!child.pid || identity.pid !== child.pid) {
        failSetup('managed runtime supervisor reported a mismatched pid');
        return;
      }
      const observed = observeProcessIdentity(identity.pid);
      if (identity.ownership_token !== token || observed.ownership_token !== token) {
        failSetup('managed runtime supervisor ownership token could not be verified');
        return;
      }
      if (
        identity.process_start_identity
        && observed.process_start_identity
        && identity.process_start_identity !== observed.process_start_identity
      ) {
        failSetup('managed runtime supervisor start identity changed before acknowledgement');
        return;
      }
      try {
        hooks.onSupervisorReady(identity);
      } catch (error) {
        failSetup(
          `managed runtime ownership publication failed: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      acknowledged = true;
      resolveReady(identity);
      child.send?.(
        {
          type: 'launch',
          token,
          binary: target.binary,
          args: target.args,
          cwd: target.cwd,
          env: target.env,
        },
        error => {
          if (error) {
            rejectLaunched(new Error(`managed runtime acknowledgement delivery failed: ${error.message}`));
            terminateUnacknowledgedSupervisor(child);
          }
        },
      );
      return;
    }
    if (raw.type === 'target_launched') {
      try {
        hooks.onTargetLaunched?.(raw.target_pid);
      } catch (error) {
        rejectLaunched(
          error instanceof Error
            ? error
            : new Error(String(error)),
        );
        terminateUnacknowledgedSupervisor(child);
        return;
      }
      targetReportedLaunch = true;
      resolveLaunched(raw.target_pid);
      return;
    }
    if (raw.type === 'target_error') {
      try { hooks.onTargetError?.(raw.message); } catch { /* observation only */ }
      if (!acknowledged) failSetup(raw.message);
      else if (!targetReportedLaunch) rejectLaunched(new Error(raw.message));
      return;
    }
    if (raw.type === 'target_background') {
      targetReportedExit = true;
      reportedTargetExit = { exitCode: raw.exit_code, signal: raw.signal };
      try { hooks.onBackgroundDescendants?.(raw.message); } catch { /* observation only */ }
      try { hooks.onTargetError?.(raw.message); } catch { /* observation only */ }
      if (!targetReportedLaunch) rejectLaunched(new Error(raw.message));
      return;
    }
    if (raw.type === 'target_exit') {
      targetReportedExit = true;
      try { hooks.onTargetExit?.(raw.exit_code, raw.signal); } catch { /* observation only */ }
      reportedTargetExit = { exitCode: raw.exit_code, signal: raw.signal };
    }
  });
  child.once('error', (error) => {
    if (!acknowledged) failSetup(`managed runtime supervisor spawn failed: ${error.message}`);
  });
  child.once('close', (code, signal) => {
    if (!acknowledged) {
      failSetup(
        `managed runtime supervisor exited before acknowledgement (code=${code ?? 'null'}, signal=${signal ?? 'null'})`,
      );
    }
    resolveExit(
      targetReportedExit && reportedTargetExit
        ? reportedTargetExit
        : { exitCode: code, signal },
    );
  });

  return { child, token, ready, launched, targetExit };
}
