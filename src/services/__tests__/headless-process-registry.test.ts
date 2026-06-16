import { describe, it, expect } from 'vitest';
import { spawn } from 'child_process';
import { HeadlessProcessRegistry } from '../headless-process-registry.js';

const settle = (ms: number) => new Promise(r => setTimeout(r, ms));

function isDead(child: { exitCode: number | null; signalCode: NodeJS.Signals | null; killed: boolean }): boolean {
  return child.killed || child.exitCode !== null || child.signalCode !== null;
}

describe('HeadlessProcessRegistry.killAllAndWait (P2 shutdown guarantee)', () => {
  it('resolves once a normal child exits on SIGTERM', async () => {
    const reg = new HeadlessProcessRegistry();
    const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
    await settle(120);
    reg.register('t1', child);
    await reg.killAllAndWait({ graceMs: 5000 }); // SIGTERM kills a normal child well before grace
    expect(isDead(child)).toBe(true);
  }, 15000);

  it('escalates to SIGKILL and still resolves for a SIGTERM-ignoring child', async () => {
    const reg = new HeadlessProcessRegistry();
    // Traps SIGTERM (ignores it) — only SIGKILL can stop it.
    const child = spawn(process.execPath, ['-e', "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)"], { stdio: 'ignore' });
    await settle(120);
    reg.register('t2', child);
    const start = Date.now();
    await reg.killAllAndWait({ graceMs: 200 }); // SIGTERM ignored → SIGKILL after 200ms
    expect(isDead(child)).toBe(true);
    expect(Date.now() - start).toBeGreaterThanOrEqual(150); // waited for escalation, didn't return early
  }, 15000);

  it('resolves immediately when there are no tracked processes', async () => {
    const reg = new HeadlessProcessRegistry();
    await expect(reg.killAllAndWait()).resolves.toBeUndefined();
  });
});
