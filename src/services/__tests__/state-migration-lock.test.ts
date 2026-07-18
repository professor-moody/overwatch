import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'fs';
import { createHash } from 'crypto';
import { execFileSync, spawn, type ChildProcess } from 'child_process';
import { once } from 'events';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { pathToFileURL } from 'url';
import {
  acquireStateMigrationLease,
  assertStateMigrationWriteAllowed,
  stateMigrationLockDirectory,
  withStateMigrationWriteGuard,
} from '../state-migration-lock.js';

const lockModuleUrl = pathToFileURL(
  resolve('src/services/state-migration-lock.ts'),
).href;

function spawnTypeScript(
  script: string,
  args: string[],
): ChildProcess {
  return spawn(
    process.execPath,
    ['--import', 'tsx', '--input-type=module', '-e', script, ...args],
    {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, NODE_NO_WARNINGS: '1' },
    },
  );
}

async function waitForReady(child: ChildProcess): Promise<void> {
  await new Promise<void>((resolveReady, reject) => {
    let output = '';
    const timeout = setTimeout(() => {
      reject(new Error(`child did not become ready; stdout=${output}`));
    }, 5_000);
    child.once('error', error => {
      clearTimeout(timeout);
      reject(error);
    });
    child.stdout!.on('data', chunk => {
      output += String(chunk);
      if (!output.includes('ready\n')) return;
      clearTimeout(timeout);
      resolveReady();
    });
  });
}

async function waitForExit(
  child: ChildProcess,
): Promise<{ code: number | null; signal: NodeJS.Signals | null; stderr: string }> {
  let stderr = '';
  child.stderr?.on('data', chunk => { stderr += String(chunk); });
  if (child.exitCode === null && child.signalCode === null) {
    const [code, signal] = await once(child, 'exit') as [number | null, NodeJS.Signals | null];
    return { code, signal, stderr };
  }
  return {
    code: child.exitCode,
    signal: child.signalCode as NodeJS.Signals | null,
    stderr,
  };
}

describe('state migration cross-process locking', () => {
  let directory: string;
  let stateFilePath: string;
  const children = new Set<ChildProcess>();

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'ow-state-migration-lock-'));
    stateFilePath = join(directory, 'state.json');
  });

  afterEach(async () => {
    for (const child of children) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL');
        await waitForExit(child);
      }
    }
    children.clear();
    rmSync(directory, { recursive: true, force: true });
  });

  it('serializes concurrent child writers while safely reclaiming one stale contender', async () => {
    const writerDirectory = `${resolve(stateFilePath)}.writer-lock`;
    mkdirSync(writerDirectory, { recursive: true });
    const staleIdentity = 'dead process';
    const staleIdentityHash = createHash('sha256')
      .update(staleIdentity)
      .digest('hex')
      .slice(0, 16);
    const staleToken = 'd'.repeat(32);
    const stalePath = join(
      writerDirectory,
      `999999999-v-${staleIdentityHash}-${staleToken}.json`,
    );
    writeFileSync(stalePath, JSON.stringify({
      version: 1,
      pid: 999999999,
      process_start_identity: staleIdentity,
      token: staleToken,
      choosing: false,
      ticket: 1,
      created_at: '2026-01-01T00:00:00.000Z',
    }));

    const activePath = join(directory, 'active-writer');
    const violationPath = join(directory, 'overlap');
    const script = `
      import { appendFileSync, unlinkSync, writeFileSync } from 'fs';
      import { withStateMigrationWriteGuard } from ${JSON.stringify(lockModuleUrl)};
      const [stateFilePath, activePath, violationPath] = process.argv.slice(1);
      const sleep = new Int32Array(new SharedArrayBuffer(4));
      try {
        withStateMigrationWriteGuard(stateFilePath, undefined, () => {
          let ownsMarker = false;
          try {
            writeFileSync(activePath, String(process.pid), { flag: 'wx' });
            ownsMarker = true;
            Atomics.wait(sleep, 0, 0, 40);
          } catch (error) {
            appendFileSync(violationPath, String(process.pid) + '\\n');
            throw error;
          } finally {
            if (ownsMarker) unlinkSync(activePath);
          }
        });
      } catch (error) {
        console.error(error instanceof Error ? error.stack : String(error));
        process.exitCode = 1;
      }
    `;

    const contenders = Array.from({ length: 8 }, () => {
      const child = spawnTypeScript(
        script,
        [stateFilePath, activePath, violationPath],
      );
      children.add(child);
      return child;
    });
    const results = await Promise.all(contenders.map(waitForExit));
    for (const [index, result] of results.entries()) {
      expect(result.code, `child ${index} stderr: ${result.stderr}`).toBe(0);
      expect(result.signal).toBeNull();
    }

    expect(existsSync(violationPath)).toBe(false);
    expect(existsSync(activePath)).toBe(false);
    expect(existsSync(stalePath)).toBe(false);
    expect(readdirSync(writerDirectory).filter(name => name.endsWith('.json'))).toEqual([]);
  }, 15_000);

  it.skipIf(process.platform === 'win32')('retains an unprefixed legacy contender owned by a live process', () => {
    const writerDirectory = `${resolve(stateFilePath)}.writer-lock`;
    mkdirSync(writerDirectory, { recursive: true });
    const legacyIdentity = execFileSync('ps', ['-o', 'lstart=', '-p', String(process.pid)], {
      encoding: 'utf8',
    }).trim();
    const identityHash = createHash('sha256').update(legacyIdentity).digest('hex').slice(0, 16);
    const token = 'e'.repeat(32);
    const contenderPath = join(
      writerDirectory,
      `${process.pid}-v-${identityHash}-${token}.json`,
    );
    writeFileSync(contenderPath, JSON.stringify({
      version: 1,
      pid: process.pid,
      process_start_identity: legacyIdentity,
      token,
      choosing: false,
      ticket: 1,
      created_at: '2026-01-01T00:00:00.000Z',
    }));

    expect(() => withStateMigrationWriteGuard(stateFilePath, undefined, () => undefined))
      .toThrow(/state writer lock is already owned/);
    expect(existsSync(contenderPath)).toBe(true);
  }, 7_000);

  it('reclaims the unique writer contender left by a process killed in its critical section', async () => {
    const script = `
      import { withStateMigrationWriteGuard } from ${JSON.stringify(lockModuleUrl)};
      const stateFilePath = process.argv[1];
      withStateMigrationWriteGuard(stateFilePath, undefined, () => {
        process.stdout.write('ready\\n');
        process.kill(process.pid, 'SIGKILL');
      });
    `;
    const child = spawnTypeScript(script, [stateFilePath]);
    children.add(child);
    await waitForReady(child);
    const crashed = await waitForExit(child);
    expect(crashed.signal).toBe('SIGKILL');

    let entered = false;
    withStateMigrationWriteGuard(stateFilePath, undefined, () => {
      entered = true;
    });
    expect(entered).toBe(true);
    const writerDirectory = `${resolve(stateFilePath)}.writer-lock`;
    expect(readdirSync(writerDirectory).filter(name => name.endsWith('.json'))).toEqual([]);
  }, 10_000);

  it.each(['missing', 'partial'] as const)(
    'reclaims a %s migration owner left by a crash',
    ownerState => {
      const lockDirectory = stateMigrationLockDirectory(stateFilePath);
      mkdirSync(lockDirectory);
      if (ownerState === 'partial') {
        writeFileSync(join(lockDirectory, 'owner.json'), '{"version":1');
      }
      expect(() => assertStateMigrationWriteAllowed(stateFilePath)).toThrow(
        /migration lease|unreadable/i,
      );

      const release = acquireStateMigrationLease(stateFilePath);
      const owner = JSON.parse(
        readFileSync(join(lockDirectory, 'owner.json'), 'utf8'),
      ) as { token: string; pid: number };
      expect(owner).toMatchObject({
        token: release.token,
        pid: process.pid,
      });
      release();
      expect(existsSync(lockDirectory)).toBe(false);
    },
  );

  it('blocks behind a live foreign migration owner and reclaims it after a crash', async () => {
    const script = `
      import { acquireStateMigrationLease } from ${JSON.stringify(lockModuleUrl)};
      const stateFilePath = process.argv[1];
      acquireStateMigrationLease(stateFilePath);
      process.stdout.write('ready\\n');
      setInterval(() => {}, 1000);
    `;
    const child = spawnTypeScript(script, [stateFilePath]);
    children.add(child);
    await waitForReady(child);

    expect(() => withStateMigrationWriteGuard(
      stateFilePath,
      undefined,
      () => undefined,
    )).toThrow(/migration is owned|writes are blocked/i);
    expect(() => acquireStateMigrationLease(stateFilePath))
      .toThrow(/already owned/i);

    child.kill('SIGKILL');
    const crashed = await waitForExit(child);
    expect(crashed.signal).toBe('SIGKILL');

    const release = acquireStateMigrationLease(stateFilePath);
    expect(() => assertStateMigrationWriteAllowed(stateFilePath, release.token))
      .not.toThrow();
    release();
    expect(existsSync(stateMigrationLockDirectory(stateFilePath))).toBe(false);
  }, 10_000);
});
