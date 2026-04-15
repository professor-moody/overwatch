// ============================================================
// Overwatch — Pending Action Queue
// Async approval gate for validate_action(). When approval_mode
// is not 'auto-approve', actions are queued for operator review.
// The MCP tool blocks (awaits) until resolution or timeout.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { OpsecContext } from './opsec-tracker.js';
import type { ApprovalMode } from '../types.js';

// --- Types ---

export interface PendingAction {
  action_id: string;
  submitted_at: string;
  timeout_at: string;
  technique?: string;
  target_node?: string;
  target_ip?: string;
  description: string;
  opsec_context: OpsecContext;
  validation_result: 'valid' | 'warning_only';
  frontier_item_id?: string;
  agent_id?: string;
  status: 'pending' | 'approved' | 'denied' | 'timeout';
}

export interface ActionResolution {
  action_id: string;
  status: 'approved' | 'denied' | 'timeout';
  resolved_at: string;
  operator_notes?: string;
  reason?: string;
}

export type ActionEventCallback = (event: 'action_pending' | 'action_resolved', data: PendingAction | ActionResolution) => void;

const DEFAULT_TIMEOUT_MS = 300_000; // 5 minutes
const MAX_RESOLVED_HISTORY = 200;

// --- Service ---

export class PendingActionQueue {
  private ctx: EngineContext;
  private pending: Map<string, PendingAction> = new Map();
  private resolved: Map<string, ActionResolution> = new Map();
  private resolveCallbacks: Map<string, (resolution: ActionResolution) => void> = new Map();
  private timeoutTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();
  private eventCallback: ActionEventCallback | null = null;

  constructor(ctx: EngineContext) {
    this.ctx = ctx;
  }

  onEvent(cb: ActionEventCallback): void {
    this.eventCallback = cb;
  }

  // ---- Approval mode logic ----

  needsApproval(opsecContext: OpsecContext, technique?: string): boolean {
    const mode = this.getApprovalMode();
    if (mode === 'auto-approve') return false;
    if (mode === 'approve-all') return true;

    // approve-critical: require approval for high-noise or blacklisted actions
    const maxNoise = this.ctx.config.opsec.max_noise;
    const noiseThreshold = maxNoise * 0.5;
    if (opsecContext.global_noise_spent + noiseThreshold >= maxNoise) return true;
    if (technique && this.ctx.config.opsec.blacklisted_techniques?.includes(technique)) return true;
    if (opsecContext.defensive_signals.length > 0) return true;
    if (opsecContext.noise_budget_remaining <= 0) return true;

    return false;
  }

  // ---- Submit / resolve ----

  submit(action: Omit<PendingAction, 'status' | 'submitted_at' | 'timeout_at'>): Promise<ActionResolution> {
    const now = new Date();
    const timeoutMs = this.ctx.config.opsec.approval_timeout_ms ?? DEFAULT_TIMEOUT_MS;
    const pendingAction: PendingAction = {
      ...action,
      status: 'pending',
      submitted_at: now.toISOString(),
      timeout_at: new Date(now.getTime() + timeoutMs).toISOString(),
    };

    this.pending.set(action.action_id, pendingAction);
    this.eventCallback?.('action_pending', pendingAction);

    return new Promise<ActionResolution>((resolve) => {
      this.resolveCallbacks.set(action.action_id, resolve);

      // Auto-approve on timeout
      const timer = setTimeout(() => {
        if (this.pending.has(action.action_id)) {
          this.resolveAction(action.action_id, {
            action_id: action.action_id,
            status: 'timeout',
            resolved_at: new Date().toISOString(),
            reason: `Auto-approved after ${timeoutMs / 1000}s timeout — no operator response.`,
          });
        }
      }, timeoutMs);

      this.timeoutTimers.set(action.action_id, timer);
    });
  }

  approve(action_id: string, operator_notes?: string): ActionResolution | null {
    if (!this.pending.has(action_id)) return null;

    const resolution: ActionResolution = {
      action_id,
      status: 'approved',
      resolved_at: new Date().toISOString(),
      operator_notes,
    };
    this.resolveAction(action_id, resolution);
    return resolution;
  }

  deny(action_id: string, reason?: string): ActionResolution | null {
    if (!this.pending.has(action_id)) return null;

    const resolution: ActionResolution = {
      action_id,
      status: 'denied',
      resolved_at: new Date().toISOString(),
      reason,
    };
    this.resolveAction(action_id, resolution);
    return resolution;
  }

  private resolveAction(action_id: string, resolution: ActionResolution): void {
    const action = this.pending.get(action_id);
    if (action) {
      action.status = resolution.status === 'timeout' ? 'timeout' : resolution.status;
    }

    // Clear timeout timer
    const timer = this.timeoutTimers.get(action_id);
    if (timer) {
      clearTimeout(timer);
      this.timeoutTimers.delete(action_id);
    }

    // Move from pending to resolved
    this.pending.delete(action_id);
    this.resolved.set(action_id, resolution);

    // Prune old resolved entries
    if (this.resolved.size > MAX_RESOLVED_HISTORY) {
      const keys = [...this.resolved.keys()];
      for (let i = 0; i < keys.length - MAX_RESOLVED_HISTORY; i++) {
        this.resolved.delete(keys[i]);
      }
    }

    // Notify event listener
    this.eventCallback?.('action_resolved', resolution);

    // Resolve the awaiting Promise
    const cb = this.resolveCallbacks.get(action_id);
    if (cb) {
      cb(resolution);
      this.resolveCallbacks.delete(action_id);
    }
  }

  // ---- Getters ----

  getPending(): PendingAction[] {
    return [...this.pending.values()];
  }

  getAction(action_id: string): PendingAction | undefined {
    return this.pending.get(action_id);
  }

  getResolution(action_id: string): ActionResolution | undefined {
    return this.resolved.get(action_id);
  }

  getPendingCount(): number {
    return this.pending.size;
  }

  // ---- Utilities ----

  private getApprovalMode(): ApprovalMode {
    return this.ctx.config.opsec.approval_mode ?? 'auto-approve';
  }

  /** Cancel all pending timers (for cleanup in tests). */
  dispose(): void {
    for (const timer of this.timeoutTimers.values()) {
      clearTimeout(timer);
    }
    this.timeoutTimers.clear();
    // Resolve any outstanding promises so they don't hang
    for (const [id, cb] of this.resolveCallbacks) {
      cb({
        action_id: id,
        status: 'timeout',
        resolved_at: new Date().toISOString(),
        reason: 'Queue disposed.',
      });
    }
    this.resolveCallbacks.clear();
    this.pending.clear();
  }
}
