import { afterEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { spawn } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';
import { pathToFileURL } from 'url';
import { spawnManagedRuntimeSupervisor } from '../managed-runtime-supervisor.js';
import { observeProcessIdentity, processIsAlive } from '../process-identity.js';

describe('managed runtime supervisor handshake', () => {
  const directories: string[] = [];
  const orphanGroups: number[] = [];

  afterEach(() => {
    for (const pid of orphanGroups.splice(0)) {
      if (process.platform !== 'win32') {
        try { process.kill(-pid, 'SIGKILL'); continue; } catch {}
      }
      try { process.kill(pid, 'SIGKILL'); } catch {}
    }
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('launches the target only after durable ownership acknowledgement', async () => {
    const identities: number[] = [];
    const handle = spawnManagedRuntimeSupervisor(
      {
        binary: process.execPath,
        args: ['-e', 'process.stdout.write("managed-ok")'],
      },
      {
        onSupervisorReady: identity => { identities.push(identity.pid); },
      },
      { acknowledgementTimeoutMs: 1_000 },
    );
    let stdout = '';
    handle.child.stdout?.on('data', chunk => { stdout += chunk.toString('utf8'); });

    const identity = await handle.ready;
    expect(observeProcessIdentity(identity.pid).ownership_token).toBe(handle.token);
    await handle.launched;
    const result = await handle.targetExit;

    expect(identity.pid).toBe(handle.child.pid);
    expect(identity.ownership_token).toBe(handle.token);
    expect(identities).toEqual([identity.pid]);
    expect(result).toMatchObject({ exitCode: 0, signal: null });
    expect(stdout).toBe('managed-ok');
  });

  it('does not launch the target when durable ownership publication fails', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-supervisor-refuse-'));
    directories.push(directory);
    const marker = join(directory, 'target-ran');
    const handle = spawnManagedRuntimeSupervisor(
      {
        binary: process.execPath,
        args: ['-e', `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ran')`],
      },
      {
        onSupervisorReady: () => { throw new Error('journal unavailable'); },
      },
      { acknowledgementTimeoutMs: 250 },
    );

    await expect(handle.ready).rejects.toThrow('journal unavailable');
    await new Promise<void>(resolve => handle.child.once('exit', () => resolve()));
    expect(existsSync(marker)).toBe(false);
  });

  it('forwards target stderr and exit status through the supervisor', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-supervisor-exit-'));
    directories.push(directory);
    const marker = join(directory, 'marker');
    const handle = spawnManagedRuntimeSupervisor(
      {
        binary: process.execPath,
        args: [
          '-e',
          `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'done'); process.stderr.write('boom'); process.exit(7)`,
        ],
      },
      { onSupervisorReady: () => undefined },
      { acknowledgementTimeoutMs: 1_000 },
    );
    let stderr = '';
    handle.child.stderr?.on('data', chunk => { stderr += chunk.toString('utf8'); });

    await handle.ready;
    await handle.launched;
    const result = await handle.targetExit;

    expect(readFileSync(marker, 'utf8')).toBe('done');
    expect(stderr).toBe('boom');
    expect(result).toMatchObject({ exitCode: 7, signal: null });
  });

  it('reports a target spawn error promptly instead of waiting for an action timeout', async () => {
    const started = Date.now();
    const handle = spawnManagedRuntimeSupervisor(
      {
        binary: `/definitely-missing-overwatch-target-${process.pid}`,
        args: [],
      },
      { onSupervisorReady: () => undefined },
      { acknowledgementTimeoutMs: 1_000 },
    );

    await handle.ready;
    await expect(handle.launched).rejects.toThrow(/ENOENT|missing|spawn/i);
    const result = await handle.targetExit;

    expect(Date.now() - started).toBeLessThan(1_000);
    expect(result.exitCode).toBe(127);
  });

  it.skipIf(process.platform === 'win32')(
    'keeps the group leader alive after TERM so an ignoring target can be safely escalated',
    async () => {
      const handle = spawnManagedRuntimeSupervisor(
        {
          binary: process.execPath,
          args: ['-e', 'process.on("SIGTERM", () => {}); process.stdout.write("ready"); setInterval(() => {}, 1000)'],
        },
        { onSupervisorReady: () => undefined },
        { acknowledgementTimeoutMs: 1_000 },
      );
      let output = '';
      handle.child.stdout?.on('data', chunk => { output += chunk.toString('utf8'); });
      const identity = await handle.ready;
      const targetPid = await handle.launched;
      expect(targetPid).toEqual(expect.any(Number));
      for (let attempt = 0; attempt < 20 && output !== 'ready'; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      expect(output).toBe('ready');

      process.kill(-identity.pid, 'SIGTERM');
      await new Promise(resolve => setTimeout(resolve, 100));
      expect(() => process.kill(identity.pid, 0)).not.toThrow();

      process.kill(-identity.pid, 'SIGKILL');
      await handle.targetExit;
      for (let attempt = 0; attempt < 20; attempt++) {
        try {
          process.kill(targetPid!, 0);
          await new Promise(resolve => setTimeout(resolve, 25));
        } catch {
          return;
        }
      }
      expect(() => process.kill(targetPid!, 0)).toThrow();
    },
  );

  it.skipIf(process.platform === 'win32')(
    'retains the group leader when the direct target exits but a descendant ignores TERM',
    async () => {
      const targetSource = `
        const { spawn } = require('node:child_process');
        const child = spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000)'], {
          stdio: 'ignore',
          detached: false,
        });
        process.stdout.write(String(child.pid) + '\\n');
        setInterval(() => {}, 1000);
      `;
      const handle = spawnManagedRuntimeSupervisor(
        {
          binary: process.execPath,
          args: ['-e', targetSource],
        },
        { onSupervisorReady: () => undefined },
        { acknowledgementTimeoutMs: 1_000 },
      );
      let output = '';
      handle.child.stdout?.on('data', chunk => { output += chunk.toString('utf8'); });
      const identity = await handle.ready;
      await handle.launched;
      for (let attempt = 0; attempt < 20 && !output.includes('\n'); attempt++) {
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      const descendantPid = Number(output.trim());
      expect(descendantPid).toBeGreaterThan(0);
      await new Promise(resolve => setTimeout(resolve, 100));

      process.kill(-identity.pid, 'SIGTERM');
      await new Promise(resolve => setTimeout(resolve, 150));
      expect(() => process.kill(identity.pid, 0)).not.toThrow();
      expect(() => process.kill(descendantPid, 0)).not.toThrow();

      process.kill(-identity.pid, 'SIGKILL');
      await handle.targetExit;
      for (let attempt = 0; attempt < 20; attempt++) {
        try {
          process.kill(descendantPid, 0);
          await new Promise(resolve => setTimeout(resolve, 25));
        } catch {
          return;
        }
      }
      expect(() => process.kill(descendantPid, 0)).toThrow();
    },
  );

  it.skipIf(process.platform === 'win32')(
    'self-terminates without launching a target when its parent exits before acknowledgement',
    async () => {
      const directory = mkdtempSync(join(tmpdir(), 'overwatch-supervisor-parent-exit-'));
      directories.push(directory);
      const pidFile = join(directory, 'supervisor.pid');
      const marker = join(directory, 'target-ran');
      const moduleUrl = pathToFileURL(
        join(process.cwd(), 'src/services/managed-runtime-supervisor.ts'),
      ).href;
      const helper = spawn(process.execPath, [
        '--import',
        'tsx',
        '--input-type=module',
        '--eval',
        `
          import { writeFileSync } from 'node:fs';
          import { spawnManagedRuntimeSupervisor } from ${JSON.stringify(moduleUrl)};
          spawnManagedRuntimeSupervisor(
            {
              binary: process.execPath,
              args: ['-e', ${JSON.stringify(`require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ran')`)}],
            },
            {
              onSupervisorReady(identity) {
                writeFileSync(${JSON.stringify(pidFile)}, String(identity.pid));
                process.exit(0);
              },
            },
            { acknowledgementTimeoutMs: 250 },
          );
        `,
      ], { stdio: 'ignore' });
      await new Promise<void>((resolve, reject) => {
        helper.once('error', reject);
        helper.once('exit', code => code === 0
          ? resolve()
          : reject(new Error(`helper exited ${code}`)));
      });
      const supervisorPid = Number(readFileSync(pidFile, 'utf8'));
      orphanGroups.push(supervisorPid);

      for (let attempt = 0; attempt < 40 && processIsAlive(supervisorPid); attempt++) {
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      expect(processIsAlive(supervisorPid)).toBe(false);
      expect(existsSync(marker)).toBe(false);
    },
  );

  it.skipIf(process.platform === 'win32')(
    'survives parent loss and broken output pipes until replacement cleanup',
    async () => {
      const directory = mkdtempSync(join(tmpdir(), 'overwatch-supervisor-epipe-'));
      directories.push(directory);
      const pidFile = join(directory, 'supervisor.pid');
      const moduleUrl = pathToFileURL(
        join(process.cwd(), 'src/services/managed-runtime-supervisor.ts'),
      ).href;
      const helper = spawn(process.execPath, [
        '--import',
        'tsx',
        '--input-type=module',
        '--eval',
        `
          import { writeFileSync } from 'node:fs';
          import { spawnManagedRuntimeSupervisor } from ${JSON.stringify(moduleUrl)};
          spawnManagedRuntimeSupervisor(
            {
              binary: process.execPath,
              args: ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => process.stdout.write("still-running\\\\n"), 10)'],
            },
            {
              onSupervisorReady(identity) {
                writeFileSync(${JSON.stringify(pidFile)}, String(identity.pid));
              },
              onTargetLaunched() {
                setTimeout(() => process.exit(0), 50);
              },
            },
          );
        `,
      ], { stdio: 'ignore' });
      await new Promise<void>((resolve, reject) => {
        helper.once('error', reject);
        helper.once('exit', code => code === 0
          ? resolve()
          : reject(new Error(`helper exited ${code}`)));
      });
      const supervisorPid = Number(readFileSync(pidFile, 'utf8'));
      orphanGroups.push(supervisorPid);

      await new Promise(resolve => setTimeout(resolve, 300));
      expect(processIsAlive(supervisorPid)).toBe(true);

      process.kill(-supervisorPid, 'SIGKILL');
      for (let attempt = 0; attempt < 40 && processIsAlive(supervisorPid); attempt++) {
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      expect(processIsAlive(supervisorPid)).toBe(false);
    },
  );
});
