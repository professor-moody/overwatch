// ============================================================
// Process Tracker
// Track long-running scans: PID, start time, command, status
// ============================================================

import { execSync } from 'child_process';

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

  register(proc: Omit<TrackedProcess, 'status' | 'started_at'>): TrackedProcess {
    const tracked: TrackedProcess = {
      ...proc,
      started_at: new Date().toISOString(),
      status: 'running',
    };
    this.processes.set(tracked.id, tracked);
    return tracked;
  }

  update(id: string, status: TrackedProcess['status']): boolean {
    const proc = this.processes.get(id);
    if (!proc) return false;
    proc.status = status;
    if (status === 'completed' || status === 'failed') {
      proc.completed_at = new Date().toISOString();
      this.pruneCompleted();
    }
    return true;
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
    return this.processes.get(id) || null;
  }

  listAll(): TrackedProcess[] {
    return Array.from(this.processes.values());
  }

  listActive(): TrackedProcess[] {
    return this.listAll().filter(p => p.status === 'running');
  }

  /**
   * Check if tracked PIDs are still alive and update status accordingly.
   */
  refreshStatuses(): void {
    for (const proc of this.processes.values()) {
      if (proc.status !== 'running') continue;
      if (!this.isPidAlive(proc.pid)) {
        proc.status = 'completed';
        proc.completed_at = new Date().toISOString();
      }
    }
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
}
