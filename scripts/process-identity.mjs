import { execFileSync } from 'node:child_process';

function positivePid(pid) {
  return Number.isSafeInteger(pid) && pid > 0;
}

const stableProcessEnvironment = () => ({
  ...process.env,
  TZ: 'UTC',
  LC_ALL: 'C',
  LANG: 'C',
});

export function processStartIdentity(pid) {
  if (!positivePid(pid)) return undefined;
  if (process.platform === 'win32') {
    try {
      const ticks = execFileSync('powershell.exe', [
        '-NoProfile', '-NonInteractive', '-Command',
        `(Get-Process -Id ${pid}).StartTime.ToUniversalTime().Ticks`,
      ], { encoding: 'utf8', timeout: 2_000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      return ticks ? `windows-start-ticks:${ticks}` : undefined;
    } catch { return undefined; }
  }
  try {
    const started = execFileSync('ps', ['-o', 'lstart=', '-p', String(pid)], {
      encoding: 'utf8',
      timeout: 1_000,
      stdio: ['ignore', 'pipe', 'ignore'],
      env: stableProcessEnvironment(),
    }).trim();
    return started ? `posix-lstart-utc:${started}` : undefined;
  } catch { return undefined; }
}

export function processStartIdentityMatches(pid, expected) {
  const observed = processStartIdentity(pid);
  if (observed === undefined) return undefined;
  if (observed === expected) return true;
  if (expected.startsWith('unverifiable-current-process-')) return undefined;
  if (process.platform === 'win32' || expected.startsWith('posix-lstart-utc:')) return false;
  try {
    const legacy = execFileSync('ps', ['-o', 'lstart=', '-p', String(pid)], {
      encoding: 'utf8',
      timeout: 1_000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    // A legacy identity is locale/time-zone sensitive. Only an exact match is
    // conclusive; a mismatch remains unverifiable so callers fail closed.
    return legacy === expected ? true : undefined;
  } catch { return undefined; }
}

export function processIsAlive(pid) {
  if (!positivePid(pid)) return false;
  try { process.kill(pid, 0); } catch (error) { return error?.code !== 'ESRCH'; }
  if (process.platform === 'win32') return true;
  try {
    const state = execFileSync('ps', ['-o', 'stat=', '-p', String(pid)], {
      encoding: 'utf8',
      timeout: 1_000,
      stdio: ['ignore', 'pipe', 'ignore'],
      env: stableProcessEnvironment(),
    }).trim();
    return state.length > 0 && !state.startsWith('Z');
  } catch {
    // A PID that answered signal 0 remains authoritative when its state cannot
    // be inspected; reclaiming it could admit a second writer.
    return true;
  }
}
