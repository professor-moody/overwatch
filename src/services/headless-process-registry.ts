// ============================================================
// Overwatch — Headless Process Registry
//
// Tracks the OS processes for headless `claude -p` sub-agents so a running
// agent can actually be stopped (cancel, timeout, daemon shutdown). Keyed by
// agent task id. Reuses the process-group SIGTERM→SIGKILL kill pattern from
// _process-runner.ts so killing a child also reaps any grandchildren it spawned.
// ============================================================

import type { ChildProcess } from 'child_process';
import { unlinkSync } from 'fs';

const DEFAULT_GRACE_MS = 5_000;

export interface HeadlessProcessEntry {
  task_id: string;
  child: ChildProcess;
  /** Temp --mcp-config path to unlink when the process ends. */
  configPath?: string;
  started_at: string;
  /** Wall-clock ms of the process's most recent stdout/stderr chunk — a liveness
   *  signal for wedged-detection: a working `claude -p` streams output as it thinks
   *  and calls tools; a hung one is silent. Undefined until the first chunk. */
  last_output_at?: number;
}

/**
 * Kill a child's whole process group (POSIX) or the direct child (Windows).
 * Mirrors the helper in _process-runner.ts. Returns whether group-kill was used.
 */
export function killProcessTree(child: ChildProcess, sig: NodeJS.Signals): boolean {
  const pid = child.pid;
  if (pid && process.platform !== 'win32') {
    try {
      process.kill(-pid, sig); // negative PID → process group
      return true;
    } catch {
      // group already gone — fall through to direct kill
    }
  }
  try { child.kill(sig); } catch { /* already exited */ }
  return false;
}

export class HeadlessProcessRegistry {
  private entries = new Map<string, HeadlessProcessEntry>();
  /** Pending SIGKILL escalation timers, so we can clear them if the child exits first. */
  private killTimers = new Map<string, ReturnType<typeof setTimeout>>();

  register(task_id: string, child: ChildProcess, configPath?: string, startedAtIso?: string): HeadlessProcessEntry {
    const entry: HeadlessProcessEntry = {
      task_id,
      child,
      configPath,
      started_at: startedAtIso ?? new Date().toISOString(),
    };
    this.entries.set(task_id, entry);
    return entry;
  }

  get(task_id: string): HeadlessProcessEntry | undefined {
    return this.entries.get(task_id);
  }

  /** Record that the process produced output — updates the liveness timestamp used
   *  to detect a wedged (alive-but-silent) process. No-op if the task isn't
   *  registered yet (a chunk that races ahead of register()). */
  noteOutput(task_id: string, atMs: number): void {
    const entry = this.entries.get(task_id);
    if (entry) entry.last_output_at = atMs;
  }

  has(task_id: string): boolean {
    return this.entries.has(task_id);
  }

  /** Remove the registry entry (call from the child's exit handler). */
  unregister(task_id: string): void {
    this.entries.delete(task_id);
    const timer = this.killTimers.get(task_id);
    if (timer) {
      clearTimeout(timer);
      this.killTimers.delete(task_id);
    }
  }

  listActive(): HeadlessProcessEntry[] {
    return [...this.entries.values()];
  }

  size(): number {
    return this.entries.size;
  }

  /**
   * Kill the process for a task: SIGTERM first (lets `claude` flush stream-json
   * and close its MCP session so a final submit_agent_transcript can land), then
   * SIGKILL the group after a grace period. Returns false if no such process.
   * The entry is removed by the child's own exit handler, not here.
   */
  kill(task_id: string, opts: { graceMs?: number } = {}): boolean {
    const entry = this.entries.get(task_id);
    if (!entry) return false;
    const graceMs = opts.graceMs ?? DEFAULT_GRACE_MS;
    killProcessTree(entry.child, 'SIGTERM');
    // Best-effort temp-config cleanup at kill time. The child's exit handler
    // also unlinks on a normal exit, but a killed child (or a parent that exits
    // before the child's 'exit' event is processed) would otherwise leak the
    // bearer-token-bearing config file. Unlinking now is safe — the process is
    // terminating and no longer needs it; a later double-unlink is swallowed.
    if (entry.configPath) {
      try { unlinkSync(entry.configPath); } catch { /* already gone */ }
    }
    if (!this.killTimers.has(task_id)) {
      const timer = setTimeout(() => {
        const still = this.entries.get(task_id);
        if (still) killProcessTree(still.child, 'SIGKILL');
        this.killTimers.delete(task_id);
      }, graceMs);
      if (typeof timer.unref === 'function') timer.unref();
      this.killTimers.set(task_id, timer);
    }
    return true;
  }

  /** Kill every tracked process (daemon shutdown). */
  killAll(opts: { graceMs?: number } = {}): void {
    for (const task_id of [...this.entries.keys()]) {
      this.kill(task_id, opts);
    }
  }

  /**
   * Shutdown-safe kill that AWAITS termination. Unlike killAll() — which sends
   * SIGTERM and schedules SIGKILL on an unref()'d timer (so the daemon can exit
   * before the timer fires, orphaning a stubborn child) — this resolves only
   * once every child has actually exited (escalating SIGTERM→SIGKILL after
   * graceMs), with a hard fallback so shutdown can never hang. The child's own
   * exit handler still performs config cleanup + reconciliation.
   */
  async killAllAndWait(opts: { graceMs?: number } = {}): Promise<void> {
    const graceMs = opts.graceMs ?? DEFAULT_GRACE_MS;
    await Promise.all([...this.entries.values()].map(e => this.waitForExit(e, graceMs)));
  }

  private waitForExit(entry: HeadlessProcessEntry, graceMs: number): Promise<void> {
    const child = entry.child;
    return new Promise<void>((resolve) => {
      if (child.exitCode != null || child.signalCode != null) return resolve(); // already dead
      let settled = false;
      let killTimer: ReturnType<typeof setTimeout>;
      let hardTimer: ReturnType<typeof setTimeout>;
      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(killTimer);
        clearTimeout(hardTimer);
        resolve();
      };
      child.once('exit', finish);
      killProcessTree(child, 'SIGTERM');
      killTimer = setTimeout(() => killProcessTree(child, 'SIGKILL'), graceMs);
      hardTimer = setTimeout(finish, graceMs + 2000); // never hang shutdown
    });
  }
}
