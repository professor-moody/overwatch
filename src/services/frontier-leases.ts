// ============================================================
// Overwatch — Frontier Leases (P1.4)
//
// When an agent claims a frontier item, it takes a lease with a TTL.
// Other agents see the item as "in progress" via `next_task` and skip it.
// Leases extend on heartbeat and release on terminal status. Stale leases
// (heartbeat timeout) are reaped by the same watchdog that interrupts
// stale agent tasks.
//
// Today the engine runs single-threaded so the race window is small —
// but the lease infrastructure is the prerequisite for any future
// multi-instance deployment (sub-agents in separate processes per F3).
// ============================================================

export interface FrontierLease {
  frontier_item_id: string;
  agent_id: string;
  task_id: string;
  leased_at: string;     // ISO timestamp
  expires_at: string;    // ISO timestamp (leased_at + ttl_seconds * 1000)
  ttl_seconds: number;
}

export const DEFAULT_LEASE_TTL_SECONDS = 600;

export interface FrontierLeasesState {
  // Index by frontier_item_id; one lease per item.
  byItem: Record<string, FrontierLease>;
}

export class FrontierLeases {
  private byItem: Map<string, FrontierLease> = new Map();
  /** Secondary ownership index. Heartbeats and terminal transitions are keyed
   * by task, so walking every historical lease made their cost proportional to
   * the complete engagement instead of the touched runtime. */
  private byTask: Map<string, Set<string>> = new Map();

  /**
   * Acquire a lease. Refuses if a different agent already holds an active
   * lease on this item; succeeds (idempotent) if the same task already
   * holds the lease (renews TTL).
   */
  acquire(args: {
    frontier_item_id: string;
    agent_id: string;
    task_id: string;
    now: string;
    ttl_seconds?: number;
  }): { ok: boolean; lease?: FrontierLease; existing?: FrontierLease } {
    const ttl = args.ttl_seconds ?? DEFAULT_LEASE_TTL_SECONDS;
    const existing = this.byItem.get(args.frontier_item_id);
    if (existing && this.isActive(existing, args.now)) {
      const sameOwner = existing.task_id === args.task_id;
      if (!sameOwner) return { ok: false, existing };
      // Same owner re-acquires → renew.
      const renewed: FrontierLease = {
        ...existing,
        leased_at: args.now,
        expires_at: frontierLeaseExpiry(args.now, ttl),
        ttl_seconds: ttl,
      };
      this.byItem.set(args.frontier_item_id, renewed);
      return { ok: true, lease: renewed };
    }
    if (existing) this.unindex(existing);
    const lease: FrontierLease = {
      frontier_item_id: args.frontier_item_id,
      agent_id: args.agent_id,
      task_id: args.task_id,
      leased_at: args.now,
      expires_at: frontierLeaseExpiry(args.now, ttl),
      ttl_seconds: ttl,
    };
    this.byItem.set(args.frontier_item_id, lease);
    this.index(lease);
    return { ok: true, lease };
  }

  /**
   * Extend the lease for a given task. No-op if the task no longer holds
   * the lease (it was released or another agent took over after expiry).
   */
  renew(taskId: string, now: string): boolean {
    const itemIds = this.byTask.get(taskId);
    if (!itemIds) return false;
    let renewed = false;
    for (const itemId of itemIds) {
      const lease = this.byItem.get(itemId);
      if (!lease || lease.task_id !== taskId) continue;
      this.byItem.set(itemId, {
        ...lease,
        leased_at: now,
        expires_at: frontierLeaseExpiry(now, lease.ttl_seconds),
      });
      renewed = true;
    }
    return renewed;
  }

  /** Release every lease held by this task (on terminal status). */
  releaseByTask(taskId: string): number {
    const itemIds = this.byTask.get(taskId);
    if (!itemIds) return 0;
    let released = 0;
    for (const itemId of itemIds) {
      const lease = this.byItem.get(itemId);
      if (!lease || lease.task_id !== taskId) continue;
      this.byItem.delete(itemId);
      released++;
    }
    this.byTask.delete(taskId);
    return released;
  }

  /** Drop expired leases. Returns the dropped frontier_item_ids for telemetry. */
  reapExpired(now: string): string[] {
    const dropped: string[] = [];
    for (const [itemId, lease] of this.byItem) {
      if (!this.isActive(lease, now)) {
        this.byItem.delete(itemId);
        this.unindex(lease);
        dropped.push(itemId);
      }
    }
    return dropped;
  }

  /** Return the active lease (if any) on a given frontier item. */
  get(frontier_item_id: string, now: string): FrontierLease | null {
    const lease = this.byItem.get(frontier_item_id);
    if (!lease) return null;
    return this.isActive(lease, now) ? lease : null;
  }

  /**
   * True iff `frontier_item_id` is currently leased by a DIFFERENT task
   * than `requesterTaskId`. Used by `next_task` to filter out items that
   * are already being worked.
   */
  isHeldByOther(frontier_item_id: string, requesterTaskId: string | undefined, now: string): boolean {
    const lease = this.get(frontier_item_id, now);
    if (!lease) return false;
    if (!requesterTaskId) return true;
    return lease.task_id !== requesterTaskId;
  }

  /** Snapshot all currently-active leases. */
  list(now: string): FrontierLease[] {
    const result: FrontierLease[] = [];
    for (const lease of this.byItem.values()) {
      if (this.isActive(lease, now)) result.push(lease);
    }
    return result;
  }

  /** Exact durable image, including an expired lease. Coordination CAS uses
   * this rather than `get()` so replay compares against persisted truth without
   * making wall-clock expiry part of transaction application. */
  getSnapshot(frontier_item_id: string): FrontierLease | null {
    const lease = this.byItem.get(frontier_item_id);
    return lease ? structuredClone(lease) : null;
  }

  /** Exact durable images owned by one task. The result is stable so bounded
   * coordination records remain byte-deterministic across recovery order. */
  getSnapshotsByTask(taskId: string): FrontierLease[] {
    const itemIds = this.byTask.get(taskId);
    if (!itemIds) return [];
    return [...itemIds]
      .sort()
      .map(itemId => this.byItem.get(itemId))
      .filter((lease): lease is FrontierLease => lease?.task_id === taskId)
      .map(lease => structuredClone(lease));
  }

  /** Read expired durable images without mutating them. The watchdog uses this
   * preflight to avoid drafting a roster-sized transaction on a no-op tick. */
  getExpiredSnapshots(now: string): FrontierLease[] {
    const expired: FrontierLease[] = [];
    for (const lease of this.byItem.values()) {
      if (!this.isActive(lease, now)) expired.push(structuredClone(lease));
    }
    return expired.sort((left, right) =>
      left.frontier_item_id < right.frontier_item_id ? -1
        : left.frontier_item_id > right.frontier_item_id ? 1 : 0);
  }

  /** Install one validated durable image. Only bounded recovery/coordination
   * appliers should call this; ordinary ownership uses acquire/renew/release. */
  applySnapshot(frontier_item_id: string, lease: FrontierLease | null): void {
    if (lease && lease.frontier_item_id !== frontier_item_id) {
      throw new Error(`Frontier lease snapshot key ${frontier_item_id} does not match ${lease.frontier_item_id}.`);
    }
    const existing = this.byItem.get(frontier_item_id);
    if (existing) this.unindex(existing);
    if (lease) {
      const installed = structuredClone(lease);
      this.byItem.set(frontier_item_id, installed);
      this.index(installed);
    } else {
      this.byItem.delete(frontier_item_id);
    }
  }

  // ---- Persistence ----

  serialize(): FrontierLeasesState {
    return { byItem: Object.fromEntries(this.byItem) };
  }

  static deserialize(state: FrontierLeasesState | undefined): FrontierLeases {
    const leases = new FrontierLeases();
    if (state?.byItem) {
      for (const [itemId, lease] of Object.entries(state.byItem)) {
        leases.applySnapshot(itemId, lease);
      }
    }
    return leases;
  }

  // ---- Internals ----

  private isActive(lease: FrontierLease, now: string): boolean {
    return Date.parse(now) < Date.parse(lease.expires_at);
  }

  private index(lease: FrontierLease): void {
    const itemIds = this.byTask.get(lease.task_id) ?? new Set<string>();
    itemIds.add(lease.frontier_item_id);
    this.byTask.set(lease.task_id, itemIds);
  }

  private unindex(lease: FrontierLease): void {
    const itemIds = this.byTask.get(lease.task_id);
    if (!itemIds) return;
    itemIds.delete(lease.frontier_item_id);
    if (itemIds.size === 0) this.byTask.delete(lease.task_id);
  }
}

export function frontierLeaseExpiry(isoTs: string, seconds: number): string {
  return new Date(Date.parse(isoTs) + seconds * 1000).toISOString();
}
