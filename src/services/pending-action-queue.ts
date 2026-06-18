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
  target_cidr?: string;
  description: string;
  opsec_context: OpsecContext;
  validation_result: 'valid' | 'warning_only';
  frontier_item_id?: string;
  agent_id?: string;
  status: 'pending' | 'approved' | 'denied' | 'timeout' | 'aborted';
}

export interface ActionResolution {
  action_id: string;
  // 'aborted' = the requesting MCP client disconnected (or cancelled the
  // request) before the operator responded. Distinct from 'denied' (an explicit
  // operator decision) so the retrospective can tell a dropped client from a
  // rejection. An aborted action is NOT executed.
  status: 'approved' | 'denied' | 'timeout' | 'aborted';
  resolved_at: string;
  operator_notes?: string;
  reason?: string;
  /**
   * True when the runner proceeded without explicit operator input — currently
   * only set on `status: 'timeout'`. Surfaced into OPSEC logs and the
   * retrospective so unattended executions are visible after the fact.
   */
  auto_approved?: boolean;
  /** Convenience flag mirroring auto_approved + status==='timeout' for downstream filters. */
  unattended_execute?: boolean;
}

export interface DurableApprovalRecord extends PendingAction {
  resolved_at?: string;
  operator_notes?: string;
  reason?: string;
  auto_approved?: boolean;
  unattended_execute?: boolean;
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
  // Per-action abort listeners, so resolveAction() can detach them and avoid
  // leaking a listener on a long-lived request AbortSignal after the action
  // resolves by some other means (approve/deny/timeout).
  private abortListeners: Map<string, { signal: AbortSignal; handler: () => void }> = new Map();
  private eventCallback: ActionEventCallback | null = null;

  constructor(ctx: EngineContext) {
    this.ctx = ctx;
  }

  onEvent(cb: ActionEventCallback): void {
    this.eventCallback = cb;
  }

  // ---- Approval mode logic ----

  /**
   * P4.1: optional `phaseEffective` carries the resolved phase-aware
   * approval mode + blacklist. When provided, it overrides the
   * engagement-level config. Engine.runProcess passes this from
   * `getEffectiveApprovalConfig()`. Legacy callers still get the
   * engagement-level behavior because the parameter is optional.
   */
  needsApproval(
    opsecContext: OpsecContext,
    technique?: string,
    phaseEffective?: { mode: ApprovalMode; blacklisted_techniques: string[] },
  ): boolean {
    const mode = phaseEffective?.mode ?? this.getApprovalMode();
    if (mode === 'auto-approve') return false;
    if (mode === 'approve-all') return true;

    // approve-critical: require approval for high-noise or blacklisted actions
    const maxNoise = this.ctx.config.opsec.max_noise;
    const noiseThreshold = maxNoise * 0.5;
    const blacklist = phaseEffective?.blacklisted_techniques
      ?? this.ctx.config.opsec.blacklisted_techniques
      ?? [];
    if (opsecContext.global_noise_spent + noiseThreshold >= maxNoise) return true;
    if (technique && blacklist.includes(technique)) return true;
    if (opsecContext.defensive_signals.length > 0) return true;
    if (opsecContext.noise_budget_remaining <= 0) return true;

    return false;
  }

  // ---- Submit / resolve ----

  submit(
    action: Omit<PendingAction, 'status' | 'submitted_at' | 'timeout_at'>,
    opts?: { signal?: AbortSignal },
  ): Promise<ActionResolution> {
    const now = new Date();
    const timeoutMs = this.ctx.config.opsec.approval_timeout_ms ?? DEFAULT_TIMEOUT_MS;
    const pendingAction: PendingAction = {
      ...action,
      status: 'pending',
      submitted_at: now.toISOString(),
      timeout_at: new Date(now.getTime() + timeoutMs).toISOString(),
    };

    const signal = opts?.signal;
    const abortResolution = (): ActionResolution => ({
      action_id: action.action_id,
      status: 'aborted',
      resolved_at: new Date().toISOString(),
      reason: 'approval request aborted — client disconnected before operator response',
    });

    // Already aborted before we even queued: resolve immediately, never block.
    if (signal?.aborted) {
      return Promise.resolve(abortResolution());
    }

    this.pending.set(action.action_id, pendingAction);
    this.eventCallback?.('action_pending', pendingAction);

    return new Promise<ActionResolution>((resolve) => {
      this.resolveCallbacks.set(action.action_id, resolve);

      // Auto-approve on timeout (loud: tagged unattended_execute so OPSEC
      // logs and the retrospective surface it, instead of silently looking
      // like a normal approval).
      const timer = setTimeout(() => {
        if (this.pending.has(action.action_id)) {
          this.resolveAction(action.action_id, {
            action_id: action.action_id,
            status: 'timeout',
            resolved_at: new Date().toISOString(),
            reason: `unattended-execute: no operator response within ${timeoutMs / 1000}s`,
            auto_approved: true,
            unattended_execute: true,
          });
        }
      }, timeoutMs);

      this.timeoutTimers.set(action.action_id, timer);

      // If the requesting client disconnects or cancels mid-wait, resolve the
      // pending action as 'aborted' (not executed) so the awaiting tool unblocks
      // and the slot is reclaimed instead of orphaned until timeout.
      if (signal) {
        const handler = () => {
          if (this.pending.has(action.action_id)) {
            this.resolveAction(action.action_id, abortResolution());
          }
        };
        this.abortListeners.set(action.action_id, { signal, handler });
        signal.addEventListener('abort', handler, { once: true });
      }
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

  /**
   * Abort every pending action submitted by `agentId`, resolving each as
   * 'aborted' (NOT executed). Called when the owning agent task goes terminal
   * (operator stop, watchdog heartbeat-reap, wall-clock timeout) so a blocked
   * approval can't later auto-fire on timeout and run a command on behalf of a
   * dead agent. Returns the resolutions produced, so the engine can also update
   * the matching durable approval records. No-op for a falsy agentId (avoids
   * sweeping up primary-session actions that carry no agent_id).
   */
  abortByAgent(agentId: string | undefined, reason = 'requesting agent terminated'): ActionResolution[] {
    if (!agentId) return [];
    const out: ActionResolution[] = [];
    for (const [id, action] of [...this.pending]) {
      if (action.agent_id !== agentId) continue;
      const resolution: ActionResolution = {
        action_id: id,
        status: 'aborted',
        resolved_at: new Date().toISOString(),
        reason,
      };
      this.resolveAction(id, resolution);
      out.push(resolution);
    }
    return out;
  }

  private resolveAction(action_id: string, resolution: ActionResolution): void {
    const action = this.pending.get(action_id);
    if (action) {
      action.status = resolution.status;
    }

    // Clear timeout timer
    const timer = this.timeoutTimers.get(action_id);
    if (timer) {
      clearTimeout(timer);
      this.timeoutTimers.delete(action_id);
    }

    // Detach any abort listener so it can't fire (or leak) after resolution.
    const abort = this.abortListeners.get(action_id);
    if (abort) {
      abort.signal.removeEventListener('abort', abort.handler);
      this.abortListeners.delete(action_id);
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
