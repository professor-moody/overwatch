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
  private afterTick?: () => void;
  private reapedTotal = 0;

  constructor(engine: GraphEngine, options: AgentWatchdogOptions = {}) {
    this.engine = engine;
    this.intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.now = options.now ?? (() => new Date().toISOString());
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
  tick(): number {
    const now = this.now();
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
    // Reconcile reaped tasks with the OS-process registry / approval queue.
    // Wrapped so a reconcile error never kills the watchdog timer.
    if (this.afterTick) {
      try { this.afterTick(); } catch { /* best effort — never break the timer */ }
    }
    return reaped;
  }

  /** Cumulative tasks interrupted by this watchdog instance. */
  getReapedCount(): number {
    return this.reapedTotal;
  }
}
