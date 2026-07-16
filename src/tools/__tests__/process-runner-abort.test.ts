import { describe, it, expect } from 'vitest';
import { runProcess } from '../_process-runner.js';
import { processIsAlive } from '../../services/process-identity.js';

describe('runProcess cancellation', () => {
  it.each([
    'detached: true',
    '"detached": true',
    "['detached']: true",
  ])('rejects a child using %s before anything launches', async (detachedOption) => {
      const source = `
        const { spawn } = require('node:child_process');
        const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
          ${detachedOption},
          stdio: 'ignore',
        });
        child.unref();
        process.stdout.write(String(child.pid));
      `;
      const result = await runProcess(process.execPath, ['-e', source], {
        timeout_ms: 10_000,
      });

      expect(result.spawn_error).toContain('detached child-process option');
      expect(result.exit_code).toBeNull();
      expect(result.stdout.total_bytes).toBe(0);
    });

  it('rejects Python preexec_fn=os.setsid before anything launches', async () => {
    const source = `
      import os, subprocess, sys
      child = subprocess.Popen(
          [sys.executable, "-c", "import time; time.sleep(60)"],
          preexec_fn=os.setsid,
      )
      print(child.pid)
    `;
    const result = await runProcess('python3', ['-c', source], {
      timeout_ms: 10_000,
    });

    expect(result.spawn_error).toContain('new-session child-process option');
    expect(result.exit_code).toBeNull();
    expect(result.stdout.total_bytes).toBe(0);
  });

  it('rejects Ruby Process.daemon without parentheses before anything launches', async () => {
    const result = await runProcess('ruby', ['-e', 'Process.daemon; sleep 60'], {
      timeout_ms: 10_000,
    });

    expect(result.spawn_error).toContain('new-session child-process option');
    expect(result.exit_code).toBeNull();
    expect(result.stdout.total_bytes).toBe(0);
  });

  it('returns a target spawn failure promptly instead of waiting for timeout', async () => {
    const started = Date.now();
    const result = await runProcess(
      `/definitely-missing-overwatch-binary-${process.pid}`,
      [],
      { timeout_ms: 10_000 },
    );

    expect(Date.now() - started).toBeLessThan(1_000);
    expect(result.spawn_error).toMatch(/ENOENT|missing|spawn/i);
    expect(result.timed_out).toBe(false);
    expect(result.exit_code).toBe(127);
  });

  it('kills a running child when the signal aborts (does not run to completion)', async () => {
    const controller = new AbortController();
    // `sleep 5` would run 5s; abort after ~100ms must terminate it.
    const started = Date.now();
    const p = runProcess('sleep', ['5'], { timeout_ms: 30_000, signal: controller.signal });
    setTimeout(() => controller.abort(), 100);
    const result = await p;
    const elapsed = Date.now() - started;
    expect(elapsed).toBeLessThan(3_000);           // killed, not the full 5s
    expect(result.signal).toBeTruthy();            // died from a signal (SIGTERM)
    expect(result.timed_out).toBe(false);          // it was cancelled, not a timeout
  }, 10_000);

  it('an already-aborted signal terminates the child immediately', async () => {
    const controller = new AbortController();
    controller.abort();
    const started = Date.now();
    const result = await runProcess('sleep', ['5'], { timeout_ms: 30_000, signal: controller.signal });
    expect(Date.now() - started).toBeLessThan(3_000);
    expect(result.signal).toBeTruthy();
  }, 10_000);

  it('a normally-exiting child resolves cleanly with no lingering kill (signal wired but never aborts)', async () => {
    const controller = new AbortController();
    const result = await runProcess('sh', ['-c', 'exit 0'], { timeout_ms: 30_000, signal: controller.signal });
    expect(result.exit_code).toBe(0);
    expect(result.signal).toBeNull();
    expect(result.timed_out).toBe(false);
    // Aborting AFTER the process already exited is a no-op (no throw, listener removed).
    expect(() => controller.abort()).not.toThrow();
  }, 10_000);

  it.skipIf(process.platform === 'win32')(
    'does not let a TERM-ignoring descendant escape cancellation',
    async () => {
      const controller = new AbortController();
      let descendantPid: number | undefined;
      const source = `
        const { spawn } = require('node:child_process');
        const child = spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); process.stdout.write("ready"); setInterval(() => {}, 1000)'], {
          stdio: ['ignore', 'pipe', 'ignore'],
          detached: false,
        });
        child.stdout.once('data', () => process.stdout.write(String(child.pid) + '\\n'));
        setInterval(() => {}, 1000);
      `;
      const result = await runProcess(process.execPath, ['-e', source], {
        timeout_ms: 10_000,
        kill_grace_ms: 100,
        signal: controller.signal,
        onStdout: chunk => {
          const parsed = Number(chunk.toString('utf8').trim());
          if (Number.isSafeInteger(parsed) && parsed > 0) {
            descendantPid = parsed;
            controller.abort();
          }
        },
      });

      expect(descendantPid).toEqual(expect.any(Number));
      expect(result.signal).toBe('SIGTERM');
      expect(result.timed_out).toBe(false);
      expect(processIsAlive(descendantPid!)).toBe(false);
    },
    10_000,
  );
});
