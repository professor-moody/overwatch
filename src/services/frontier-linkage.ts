// Overwatch — Frontier Linkage Tracker
//
// Bookkeeping for "what happened to each frontier item we surfaced?"
//
// The deterministic layer emits candidate actions (`next_task`); the agent then
// either pursues, validates, rejects, or silently ignores them. This tracker
// lets us tell the difference between *rejected with reasoning* and *silently
// dropped* without forcing the model to reply on every item.
//
// Status lifecycle:
//   open  --validate_action / action_validated--> validated
//         --action_started / action_completed --> pursued
//         --log_thought(kind=rejection) -------> rejected_explicit
//         --N next_task calls without progress-> dropped
//
// `dropped` is sticky and only set by an explicit sweep in `next_task`, which
// emits a `frontier_item_dropped` event so the retrospective sees the gap.

import type { ActivityLogEntry } from './engine-context.js';

export type FrontierLinkageStatus =
  | 'open'
  | 'validated'
  | 'pursued'
  | 'rejected_explicit'
  | 'dropped';

export interface FrontierLinkageRecord {
  frontier_item_id: string;
  emitted_at: string;          // ISO timestamp of first emission
  emitted_call_index: number;  // next_task call index when first surfaced
  last_seen_call_index: number; // last next_task call where it was still in the candidate list
  linkage_status: FrontierLinkageStatus;
  last_event_id?: string;      // most recent activity event that touched it
  status_set_at?: string;      // ISO timestamp of the most recent status change
}

export interface LinkageStatusSummary {
  total: number;
  open: number;
  validated: number;
  pursued: number;
  rejected_explicit: number;
  dropped: number;
}

export interface SerializedFrontierLinkage {
  next_task_call_index: number;
  records: FrontierLinkageRecord[];
}

/**
 * Default number of consecutive `next_task` calls a frontier item can go
 * unseen / un-acted-upon before it's marked as `dropped`.
 */
export const DEFAULT_DROP_THRESHOLD = 5;

export class FrontierLinkageTracker {
  private records: Map<string, FrontierLinkageRecord> = new Map();
  private nextTaskCallIndex = 0;

  /**
   * Record that a batch of frontier item IDs was just surfaced via `next_task`.
   * Returns the call index that was assigned to this batch.
   */
  recordEmitted(frontierItemIds: string[]): number {
    this.nextTaskCallIndex += 1;
    const idx = this.nextTaskCallIndex;
    const nowIso = new Date().toISOString();
    for (const id of frontierItemIds) {
      const existing = this.records.get(id);
      if (existing) {
        existing.last_seen_call_index = idx;
        // If a previously-dropped item shows back up, give it another chance.
        if (existing.linkage_status === 'dropped') {
          existing.linkage_status = 'open';
          existing.status_set_at = nowIso;
        }
      } else {
        this.records.set(id, {
          frontier_item_id: id,
          emitted_at: nowIso,
          emitted_call_index: idx,
          last_seen_call_index: idx,
          linkage_status: 'open',
          status_set_at: nowIso,
        });
      }
    }
    return idx;
  }

  /**
   * Inspect an activity log entry and update the linkage record for any
   * frontier item it references.
   */
  observe(entry: ActivityLogEntry): void {
    const fid = entry.frontier_item_id;
    if (!fid) return;
    const record = this.records.get(fid);
    if (!record) return;

    let nextStatus: FrontierLinkageStatus | null = null;
    if (entry.event_type === 'action_validated') nextStatus = 'validated';
    if (entry.event_type === 'action_started' || entry.event_type === 'action_completed') nextStatus = 'pursued';
    if (entry.event_type === 'thought' && entry.details && (entry.details as Record<string, unknown>).kind === 'rejection') {
      nextStatus = 'rejected_explicit';
    }

    if (nextStatus !== null && shouldUpgrade(record.linkage_status, nextStatus)) {
      record.linkage_status = nextStatus;
      record.status_set_at = entry.timestamp;
    }
    record.last_event_id = entry.event_id;
  }

  /**
   * Mark items that haven't been seen in the candidate list for `threshold`
   * consecutive `next_task` calls AND remain in `open` status as `dropped`.
   * Returns the records that transitioned for the caller to log events for.
   */
  sweepDropped(threshold: number = DEFAULT_DROP_THRESHOLD): FrontierLinkageRecord[] {
    const dropped: FrontierLinkageRecord[] = [];
    const nowIso = new Date().toISOString();
    for (const record of this.records.values()) {
      if (record.linkage_status !== 'open') continue;
      const age = this.nextTaskCallIndex - record.last_seen_call_index;
      if (age >= threshold) {
        record.linkage_status = 'dropped';
        record.status_set_at = nowIso;
        dropped.push(record);
      }
    }
    return dropped;
  }

  summary(): LinkageStatusSummary {
    const out: LinkageStatusSummary = {
      total: 0,
      open: 0,
      validated: 0,
      pursued: 0,
      rejected_explicit: 0,
      dropped: 0,
    };
    for (const r of this.records.values()) {
      out.total += 1;
      out[r.linkage_status] += 1;
    }
    return out;
  }

  get(id: string): FrontierLinkageRecord | undefined {
    return this.records.get(id);
  }

  size(): number {
    return this.records.size;
  }

  callIndex(): number {
    return this.nextTaskCallIndex;
  }

  serialize(): SerializedFrontierLinkage {
    return {
      next_task_call_index: this.nextTaskCallIndex,
      records: Array.from(this.records.values()),
    };
  }

  static deserialize(data: SerializedFrontierLinkage | null | undefined): FrontierLinkageTracker {
    const t = new FrontierLinkageTracker();
    if (!data) return t;
    t.nextTaskCallIndex = data.next_task_call_index || 0;
    for (const r of data.records || []) {
      t.records.set(r.frontier_item_id, { ...r });
    }
    return t;
  }
}

const STATUS_RANK: Record<FrontierLinkageStatus, number> = {
  open: 0,
  dropped: 1,
  validated: 2,
  rejected_explicit: 3,
  pursued: 4,
};

/**
 * Only allow status transitions that move "forward" along the lifecycle.
 * Once an item is `pursued` we don't downgrade it back to `validated`, etc.
 */
function shouldUpgrade(current: FrontierLinkageStatus, next: FrontierLinkageStatus): boolean {
  return STATUS_RANK[next] > STATUS_RANK[current];
}
