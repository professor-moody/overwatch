// ============================================================
// Process Tracker
// Track long-running scans: PID, start time, command, status
// ============================================================

export interface TrackedProcess {
  id: string;
  pid: number;
  command: string;
  description: string;
  started_at: string;
  completed_at?: string;
  status: 'running' | 'completed' | 'failed' | 'unknown';
  agent_id?: string;
  target_node?: string;
}

const MAX_COMPLETED = 50;

export class ProcessTracker {
  private processes: Map<string, TrackedProcess> = new Map();
  private listeners = new Set<() => void>();
  private mutationGuard: (() => void) | undefined;

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

  register(proc: Omit<TrackedProcess, 'status' | 'started_at'>): TrackedProcess {
    this.mutationGuard?.();
    const tracked: TrackedProcess = {
      ...proc,
      started_at: new Date().toISOString(),
      status: 'running',
    };
    const registered = this.mutateAndNotify(() => {
      this.processes.set(tracked.id, tracked);
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
      if (status === 'completed' || status === 'failed') {
        proc.completed_at = new Date().toISOString();
      }
      if (status === 'completed' || status === 'failed') {
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
      .filter(p => p.status === 'completed' || p.status === 'failed')
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
   * Check if tracked PIDs are still alive and update status accordingly.
   *
   * P4.1: a missing PID is reported as `unknown`, not `completed`. From
   * outside the process we can't distinguish a clean exit from a crash —
   * `kill(pid, 0)` only tells us "no longer alive." Marking these as
   * `completed` was wrong and made retrospective truth weaker. Callers
   * with actual lifecycle visibility (e.g. spawn() exit handlers) should
   * call `update(id, 'completed' | 'failed')` explicitly.
   */
  refreshStatuses(): boolean {
    const transitioned = Array.from(this.processes.values())
      .filter(proc => proc.status === 'running' && !this.isPidAlive(proc.pid));
    if (transitioned.length === 0) return false;

    this.mutationGuard?.();
    return this.mutateAndNotify(() => {
      const completedAt = new Date().toISOString();
      for (const proc of transitioned) {
        proc.status = 'unknown';
        proc.completed_at = completedAt;
      }
      this.pruneCompleted();
      return true;
    });
  }

  private isPidAlive(pid: number): boolean {
    try {
      // signal 0 doesn't kill — just checks if process exists
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
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

  static deserialize(data: TrackedProcess[]): ProcessTracker {
    const tracker = new ProcessTracker();
    tracker.replaceWithoutNotification(data);
    return tracker;
  }

  private replaceWithoutNotification(data: TrackedProcess[]): void {
    this.processes = new Map(data.map(proc => [proc.id, { ...proc }]));
  }
}
