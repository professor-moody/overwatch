// ============================================================
// Overwatch — Agent Watchdog (P0.3)
//
// Periodically walks running agent tasks and interrupts any whose heartbeat
// is older than their TTL. Tasks that have NEVER heartbeated are exempt
// (preserves backward-compat for tools that don't heartbeat yet).
//
// Lifecycle:
//   - start() begins the timer at INTERVAL_MS (default 30s)
//   - stop()  clears the timer; safe to call multiple times
//   - tick()  exposed for tests so we don't have to wait on timers
//
// Design notes:
//   * The watchdog is a thin wrapper around `engine.reapStaleAgents()`.
//     Putting the timer here keeps GraphEngine free of `setInterval` calls
//     so it stays cheap to construct in unit tests.
//   * If an instance is never start()'d, no work happens — explicit opt-in.
// ============================================================

import type { GraphEngine } from './graph-engine.js';

const DEFAULT_INTERVAL_MS = 30_000;

export interface AgentWatchdogOptions {
  /** Tick interval in milliseconds. Defaults to 30s. */
  intervalMs?: number;
  /** Optional clock injection (used by tests). */
  now?: () => string;
  /**
   * Runs at the START of every tick, BEFORE reaping. The owner
   * (TaskExecutionService) uses this to refresh liveness for supervised
   * long-lived agents (the persistent orchestrator) whose heartbeat would
   * otherwise only advance when the model calls `agent_heartbeat` — so a
   * busy-but-quiet one isn't reaped mid-work. Ordering matters: this must run
   * before `reapStaleAgents`, or the refresh lands too late to save it.
   */
  beforeTick?: () => void;
  /**
   * Runs at the end of every tick, after reaping. The owner (TaskExecutionService)
   * uses this to reconcile reaped tasks with the OS-process registry — heartbeat
   * reaping flips a task to 'interrupted' but does NOT fire onUpdate or touch the
   * process, so without this hook a reaped headless agent keeps running.
   */
  afterTick?: () => void;
}

export class AgentWatchdog {
  private engine: GraphEngine;
  private intervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private now: () => string;
  private beforeTick?: () => void;
  private afterTick?: () => void;
  private reapedTotal = 0;
  /** True once a hook error has been logged for that phase; suppresses repeats so a
   *  persistently-failing hook (every interval) can't flood the log. Reset on the
   *  next successful run so a recovered-then-failed-again error re-logs. */
  private beforeTickErrorLogged = false;
  private afterTickErrorLogged = false;

  constructor(engine: GraphEngine, options: AgentWatchdogOptions = {}) {
    this.engine = engine;
    this.intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.now = options.now ?? (() => new Date().toISOString());
    this.beforeTick = options.beforeTick;
    this.afterTick = options.afterTick;
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => this.tick(), this.intervalMs);
    // Don't keep the event loop alive for the watchdog timer alone.
    if (typeof this.timer.unref === 'function') this.timer.unref();
  }

  stop(): void {
    if (!this.timer) return;
    clearInterval(this.timer);
    this.timer = null;
  }

  /**
   * Run one watchdog cycle. Returns the number of tasks interrupted on this
   * tick. Exposed for tests; production code calls `start()` and lets the
   * timer drive ticks.
   *
   * Also reaps expired frontier leases (P1.4) — covers the edge case
   * where a lease's TTL elapses without the owning task being eligible
   * for heartbeat-based reaping (e.g., the task was already terminal
   * but the lease wasn't released cleanly).
   */
  /**
   * Run a tick hook (before-reap liveness refresh, or post-tick reconcile) without
   * ever letting it break the timer or skip the reap. Logs the FIRST failure of a
   * streak (not every interval — a persistently-throwing hook would flood the log),
   * with a stderr fallback, and re-arms once the hook succeeds again.
   */
  private invokeHook(fn: () => void, phase: 'before-reap' | 'post-tick'): void {
    const alreadyLogged = phase === 'before-reap' ? this.beforeTickErrorLogged : this.afterTickErrorLogged;
    try {
      fn();
      if (phase === 'before-reap') this.beforeTickErrorLogged = false; else this.afterTickErrorLogged = false;
    } catch (err) {
      if (alreadyLogged) return; // already logged this streak
      if (phase === 'before-reap') this.beforeTickErrorLogged = true; else this.afterTickErrorLogged = true;
      const msg = err instanceof Error ? err.message : String(err);
      try {
        this.engine.logActionEvent({
          description: `Watchdog ${phase} hook failed: ${msg}`,
          event_type: 'instrumentation_warning',
          category: 'system',
          result_classification: 'failure',
          details: { reason: 'watchdog_hook_error', phase },
        });
      } catch {
        try { console.error(`[overwatch] watchdog ${phase} hook failed and could not be logged: ${msg}`); } catch { /* never break the timer */ }
      }
    }
  }

  tick(): number {
    // Persistence can close asynchronously after the watchdog was started.
    // Maintenance must become a no-op instead of letting a guarded engine
    // mutation escape from the interval callback and crash the daemon.
    if (!this.engine.isPersistenceWritable()) {
      this.stop();
      return 0;
    }
    const now = this.now();
    // Refresh supervised long-lived liveness BEFORE reaping — the owner keeps the
    // orchestrator's heartbeat fresh while its process is alive, so a busy-but-quiet
    // one isn't reaped on this very tick. A throwing hook is logged (once per streak)
    // but never breaks the timer or skips the reap.
    if (this.beforeTick) this.invokeHook(this.beforeTick, 'before-reap');
    // A before-tick hook may itself observe the writable→read-only transition
    // and freeze the owning service. Recheck before touching durable agent state.
    if (!this.engine.isPersistenceWritable()) {
      this.stop();
      return 0;
    }
    const reaped = this.engine.reapStaleAgents(now);
    // Drop expired leases. Heartbeat-based reaping above already released
    // leases for tasks that got interrupted on this same tick; this catches
    // the edge case where a lease outlives its owning task without a
    // heartbeat-driven interrupt.
    const droppedItems = this.engine.reapExpiredFrontierLeases(now);
    if (droppedItems.length > 0) {
      this.engine.logActionEvent({
        description: `Reaped ${droppedItems.length} expired frontier lease(s)`,
        event_type: 'instrumentation_warning',
        category: 'system',
        result_classification: 'neutral',
        details: { reason: 'frontier_lease_expired', items: droppedItems },
      });
    }
    this.reapedTotal += reaped;
    // Reconcile reaped tasks with the OS-process registry / approval queue. A
    // repeatedly-throwing reconcile means orphaned processes aren't being cleaned
    // up, so the hook logs its failures (once per streak) rather than failing silently.
    if (this.afterTick) this.invokeHook(this.afterTick, 'post-tick');
    return reaped;
  }

  /** Cumulative tasks interrupted by this watchdog instance. */
  getReapedCount(): number {
    return this.reapedTotal;
  }
}
