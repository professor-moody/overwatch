// ============================================================
// Process Tracker
// Track long-running scans: PID, start time, command, status
// ============================================================

import {
  defaultProcessIdentityObserver,
  verifyRuntimeProcessIdentity,
  type ProcessIdentityObserver,
} from './process-identity.js';

export interface TrackedProcess {
  id: string;
  pid: number;
  command: string;
  description: string;
  started_at: string;
  completed_at?: string;
  status: 'running' | 'completed' | 'failed' | 'unknown';
  task_id?: string;
  action_id?: string;
  agent_id?: string;
  target_node?: string;
  process_group_id?: number;
  process_start_identity?: string;
  ownership_token?: string;
  daemon_owner?: string;
  command_fingerprint?: string;
  ownership_mode?: 'managed_supervisor' | 'external_adopted';
  signal_scope?: 'process_group' | 'pid' | 'none';
  recovery_warning?: string;
}

const MAX_COMPLETED = 50;

export class ProcessTracker {
  private processes: Map<string, TrackedProcess> = new Map();
  private listeners = new Set<() => void>();
  private mutationGuard: (() => void) | undefined;

  constructor(
    private readonly identityObserver: ProcessIdentityObserver = defaultProcessIdentityObserver,
  ) {}

  onChange(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Install the same pre-mutation durability gate used by the engine-owned
   * coordination stores. The guard runs before any in-memory process state is
   * changed, so a degraded engagement cannot retain a mutation that its caller
   * was told had failed.
   */
  setMutationGuard(guard: (() => void) | undefined): void {
    this.mutationGuard = guard;
  }

  private notifyChange(): void {
    let firstError: unknown;
    for (const listener of this.listeners) {
      try { listener(); } catch (error) { firstError ??= error; }
    }
    if (firstError !== undefined) throw firstError;
  }

  private snapshotProcesses(): Map<string, TrackedProcess> {
    return new Map(
      Array.from(this.processes, ([id, proc]) => [id, { ...proc }]),
    );
  }

  private mutateAndNotify<T>(mutation: () => T): T {
    const before = this.snapshotProcesses();
    try {
      const result = mutation();
      this.notifyChange();
      return result;
    } catch (error) {
      // The engine's change listener is the durable transaction boundary for
      // process ownership. If journaling rejects the update, keep the live
      // projection aligned with the state callers were told remained durable.
      this.processes = before;
      throw error;
    }
  }

  register(
    proc: Omit<TrackedProcess, 'status' | 'started_at' | 'completed_at'>,
    options: {
      status?: TrackedProcess['status'];
      recovery_warning?: string;
    } = {},
  ): TrackedProcess {
    this.mutationGuard?.();
    const status = options.status ?? 'running';
    const now = new Date().toISOString();
    const tracked: TrackedProcess = {
      ...proc,
      started_at: now,
      status,
      ...(status === 'running' ? {} : { completed_at: now }),
      ...(options.recovery_warning
        ? { recovery_warning: options.recovery_warning }
        : {}),
    };
    const registered = this.mutateAndNotify(() => {
      this.processes.set(tracked.id, tracked);
      if (status !== 'running') this.pruneCompleted();
      return tracked;
    });
    return { ...registered };
  }

  update(id: string, status: TrackedProcess['status']): boolean {
    const proc = this.processes.get(id);
    if (!proc) return false;
    this.mutationGuard?.();
    return this.mutateAndNotify(() => {
      proc.status = status;
      if (status !== 'running') {
        proc.completed_at = new Date().toISOString();
      }
      if (status !== 'running') {
        this.pruneCompleted();
      }
      return true;
    });
  }

  /**
   * Remove a process reservation that never became a successfully-owned run.
   * Used by fail-closed launch setup: if a child was spawned but a later
   * registry/TTL/ownership transaction fails, no durable process row may remain
   * claiming that the killed child is still supervised.
   */
  remove(id: string): boolean {
    if (!this.processes.has(id)) return false;
    this.mutationGuard?.();
    return this.mutateAndNotify(() => this.processes.delete(id));
  }

  private pruneCompleted(): void {
    const completed = Array.from(this.processes.values())
      .filter(p => p.status !== 'running')
      .sort((a, b) => (a.completed_at || '').localeCompare(b.completed_at || ''));
    while (completed.length > MAX_COMPLETED) {
      const oldest = completed.shift()!;
      this.processes.delete(oldest.id);
    }
  }

  get(id: string): TrackedProcess | null {
    const process = this.processes.get(id);
    return process ? { ...process } : null;
  }

  listAll(): TrackedProcess[] {
    return Array.from(this.processes.values(), process => ({ ...process }));
  }

  listActive(): TrackedProcess[] {
    return this.listAll().filter(p => p.status === 'running');
  }

  /**
   * Verify that a tracked PID still belongs to the process originally
   * registered. PID existence alone is not ownership: operating systems reuse
   * PIDs, so a matching start identity is required to keep reporting a run as
   * live. Missing, dead, reused, or otherwise unverifiable identities resolve
   * to `unknown`; callers with direct lifecycle visibility must explicitly
   * report `completed` or `failed`.
   */
  refreshStatuses(): boolean {
    const transitioned = Array.from(this.processes.values())
      .filter(proc => proc.status === 'running')
      .map(proc => ({
        proc,
        verification: verifyRuntimeProcessIdentity(proc, this.identityObserver),
      }))
      .filter(({ verification }) => verification.status !== 'verified');
    if (transitioned.length === 0) return false;

    this.mutationGuard?.();
    return this.mutateAndNotify(() => {
      const completedAt = new Date().toISOString();
      for (const { proc, verification } of transitioned) {
        proc.status = 'unknown';
        proc.completed_at = completedAt;
        proc.recovery_warning = verification.status === 'pid_reused'
          ? 'Tracked PID was reused by a different process; ownership was not assumed.'
          : verification.status === 'not_running'
            ? 'Tracked process is no longer running; its terminal outcome is unknown.'
            : 'Tracked process identity could not be verified; ownership was not assumed.';
      }
      this.pruneCompleted();
      return true;
    });
  }

  /**
   * Serialize for inclusion in get_state response.
   */
  toSummary(): { active: number; completed: number; processes: TrackedProcess[] } {
    this.refreshStatuses();
    const all = this.listAll();
    return {
      active: all.filter(p => p.status === 'running').length,
      completed: all.filter(p => p.status !== 'running').length,
      processes: all,
    };
  }

  serialize(): TrackedProcess[] {
    return this.listAll();
  }

  /**
   * Replace the live tracker contents from an authoritative durable projection.
   * Rollback/recovery coordinators use this to prevent stale runtime metadata
   * from being written back over the restored state.
   */
  restore(data: TrackedProcess[], options: { notify?: boolean } = {}): void {
    this.mutationGuard?.();
    if (options.notify === false) {
      this.replaceWithoutNotification(data);
      return;
    }
    this.mutateAndNotify(() => {
      this.replaceWithoutNotification(data);
    });
  }

  /** Explicit empty-or-replace alias for lifecycle coordinators. */
  reset(data: TrackedProcess[] = [], options: { notify?: boolean } = {}): void {
    this.restore(data, options);
  }

  static deserialize(
    data: TrackedProcess[],
    identityObserver: ProcessIdentityObserver = defaultProcessIdentityObserver,
  ): ProcessTracker {
    const tracker = new ProcessTracker(identityObserver);
    tracker.replaceWithoutNotification(data);
    return tracker;
  }

  private replaceWithoutNotification(data: TrackedProcess[]): void {
    this.processes = new Map(data.map(proc => [proc.id, { ...proc }]));
  }
}
