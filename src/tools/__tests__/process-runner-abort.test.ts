import { describe, it, expect } from 'vitest';
import { runProcess } from '../_process-runner.js';

describe('runProcess cancellation', () => {
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
});
