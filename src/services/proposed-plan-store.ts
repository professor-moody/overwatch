// ============================================================
// Overwatch — Proposed Plan Store (Phase 3A.2)
//
// A headless 'planner' sub-agent translates a free-form operator command into a
// list of OperatorOps and submits it via the propose_plan tool. The operator
// then confirms the plan, which executes through the SAME validated executeOps
// path the deterministic grammar uses (directive / scope / approve / deny) — so
// OPSEC/scope/lease/approval guards still apply. The plan is never auto-executed.
//
// This store is the shared hand-off point: the propose_plan tool (which only has
// the GraphEngine) writes here, and the dashboard's /api/commands confirm path
// reads here. The store serializes with an absolute TTL so restart neither
// discards an open decision nor extends its operator-confirmation window.
// ============================================================

import { randomUUID } from 'crypto';
import type { OperatorOp } from './command-interpreter.js';
import type { ScopePreview } from './scope-preview.js';

export type ProposedPlanStatus = 'open' | 'confirmed' | 'denied' | 'expired';

export interface ProposedPlan {
  plan_id: string;
  /** The operator's free-form command this plan answers. */
  command: string;
  ops: OperatorOp[];
  summary: string;
  rationale?: string;
  /** The planner task/agent that produced this plan (for correlation + console attribution). */
  source_task_id?: string;
  source_agent_id?: string;
  /** Dry-run scope-impact preview, present when the plan has scope op(s). */
  scope_preview?: ScopePreview;
  created_at: number;
  /** Absolute expiry; restart never extends the operator decision window. */
  expires_at: number;
  status: ProposedPlanStatus;
}

export interface AddProposedPlanArgs {
  command: string;
  ops: OperatorOp[];
  summary: string;
  rationale?: string;
  source_task_id?: string;
  source_agent_id?: string;
  scope_preview?: ScopePreview;
  /** Injectable clock (ms) for deterministic tests. Defaults to Date.now(). */
  now?: number;
}

const DEFAULT_TTL_MS = 10 * 60_000; // 10 min, matches the grammar-plan TTL

/**
 * In-memory store of planner-proposed plans awaiting operator confirmation.
 * Self-contained (no engine ref needed) so it's trivially unit-testable.
 */
/**
 * Why a confirm found no open plan. Lets the confirm path give ACCURATE advice
 * instead of a blanket "re-issue the command" that manufactures a duplicate
 * planner/dispatch when the plan was actually already handled elsewhere (the
 * "Needs you" queue can confirm/deny the same plan_id).
 */
export type PlanResolution = 'open' | 'confirmed' | 'denied' | 'expired' | 'unknown';

// Bounded history of terminal plan dispositions, so `describeResolution` can still
// answer after the plan itself has been pruned from the live map.
const TOMBSTONE_CAP = 200;

export interface SerializedProposedPlanStore {
  plans: ProposedPlan[];
  tombstones: Array<[string, 'confirmed' | 'denied' | 'expired']>;
}

export class ProposedPlanStore {
  private plans = new Map<string, ProposedPlan>();
  // plan_id → how it ended (confirmed/denied/expired). Insertion-ordered + capped.
  private tombstones = new Map<string, 'confirmed' | 'denied' | 'expired'>();
  private listeners = new Set<() => void>();
  private mutationGuard: (() => void) | undefined;
  private mutationRunner:
    | (<T>(reason: string, mutation: () => T) => T)
    | undefined;

  constructor(private ttlMs: number = DEFAULT_TTL_MS) {}

  private tombstone(plan_id: string, disposition: 'confirmed' | 'denied' | 'expired'): void {
    this.tombstones.delete(plan_id); // re-insert to move to the newest (MRU) position
    this.tombstones.set(plan_id, disposition);
    if (this.tombstones.size > TOMBSTONE_CAP) {
      const oldest = this.tombstones.keys().next().value;
      if (oldest !== undefined) this.tombstones.delete(oldest);
    }
  }

  /** Register a change listener (dashboard broadcast + persistence coexist). */
  onChange(cb: () => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  setMutationGuard(guard: (() => void) | undefined): void {
    this.mutationGuard = guard;
  }

  setMutationRunner(
    runner: (<T>(reason: string, mutation: () => T) => T) | undefined,
  ): void {
    this.mutationRunner = runner;
  }

  private runMutation<T>(reason: string, mutation: () => T): T {
    this.mutationGuard?.();
    return this.mutationRunner
      ? this.mutationRunner(reason, mutation)
      : mutation();
  }

  private notifyChange(): void {
    let firstError: unknown;
    for (const listener of this.listeners) {
      try { listener(); } catch (error) { firstError ??= error; }
    }
    if (firstError !== undefined) throw firstError;
  }

  /** Record a freshly-proposed plan. Returns the stored record (with its plan_id). */
  add(args: AddProposedPlanArgs): ProposedPlan {
    return this.runMutation('add proposed plan', () => {
      const now = args.now ?? Date.now();
      this.pruneInternal(now, false);
      const plan: ProposedPlan = {
        plan_id: randomUUID(),
        command: args.command,
        ops: args.ops,
        summary: args.summary,
        rationale: args.rationale,
        source_task_id: args.source_task_id,
        source_agent_id: args.source_agent_id,
        scope_preview: args.scope_preview,
        created_at: now,
        expires_at: now + this.ttlMs,
        status: 'open',
      };
      this.plans.set(plan.plan_id, plan);
      this.notifyChange();
      return plan;
    });
  }

  /** Look up a plan by id (does not expire on read — confirm-path checks status). */
  get(plan_id: string): ProposedPlan | undefined {
    return this.plans.get(plan_id);
  }

  /** All currently-open plans, newest first. */
  getOpen(now: number = Date.now()): ProposedPlan[] {
    try { this.prune(now); } catch { /* degraded reads filter without mutating */ }
    return [...this.plans.values()]
      .filter(p => p.status === 'open' && p.expires_at > now)
      .sort((a, b) => b.created_at - a.created_at);
  }

  /**
   * Mark a plan resolved (confirmed/denied) so it can't be confirmed twice.
   * Returns the plan if it was open, else null (already resolved / unknown /
   * expired). Prunes first so a plan past its TTL can never be confirmed — this
   * keeps the confirm path symmetric with the grammar path (which prunes at the
   * top of handleCommand) instead of relying on a GET /api/plans poll to sweep.
   */
  resolve(plan_id: string, status: 'confirmed' | 'denied', now: number = Date.now()): ProposedPlan | null {
    return this.runMutation(`resolve proposed plan as ${status}`, () => {
      this.pruneInternal(now, false);
      const plan = this.plans.get(plan_id);
      if (!plan || plan.status !== 'open') return null;
      plan.status = status;
      this.tombstone(plan_id, status);
      this.notifyChange();
      return plan;
    });
  }

  /**
   * Explain what happened to a plan_id that `resolve` couldn't confirm. Reads the
   * live plan first (still open / resolved but not yet pruned), then the tombstone
   * history for one that's already been swept. `unknown` = never seen (or aged out
   * of both). Prunes first so an expired-but-unswept plan reports `expired`.
   */
  describeResolution(plan_id: string, now: number = Date.now()): PlanResolution {
    try { this.prune(now); } catch { /* degraded reads remain available */ }
    const plan = this.plans.get(plan_id);
    if (plan && plan.expires_at <= now) return 'expired';
    if (plan) return plan.status; // 'open' | 'confirmed' | 'denied' (expired ones are pruned, not kept)
    return this.tombstones.get(plan_id) ?? 'unknown';
  }

  /** Sweep plans older than the TTL, tombstoning still-open ones as expired before dropping. */
  prune(now: number = Date.now()): void {
    this.runMutation('prune proposed plans', () => this.pruneInternal(now, false));
  }

  private pruneInternal(now: number, guard: boolean, notify = true): void {
    const expired = [...this.plans.entries()]
      .filter(([, plan]) => {
        const expiresAt = Number.isFinite(plan.expires_at)
          ? plan.expires_at
          : plan.created_at + this.ttlMs;
        return expiresAt <= now;
      });
    if (expired.length === 0) return;
    if (guard) this.mutationGuard?.();
    for (const [id, plan] of expired) {
      // A still-open plan that timed out is 'expired'; a resolved one already has
      // its confirmed/denied tombstone from resolve() — don't overwrite it.
      if (plan.status === 'open') this.tombstone(id, 'expired');
      this.plans.delete(id);
    }
    if (notify) this.notifyChange();
  }

  serialize(): SerializedProposedPlanStore {
    return JSON.parse(JSON.stringify({
      plans: [...this.plans.values()],
      tombstones: [...this.tombstones.entries()],
    })) as SerializedProposedPlanStore;
  }

  /** Restore in place so dashboard/persistence listeners remain attached. */
  restore(data: unknown, now: number = Date.now()): void {
    const record = data && typeof data === 'object' && !Array.isArray(data)
      ? data as Partial<SerializedProposedPlanStore>
      : {};
    const plans = Array.isArray(record.plans) ? record.plans : [];
    const tombstones = Array.isArray(record.tombstones) ? record.tombstones : [];
    this.plans.clear();
    this.tombstones.clear();
    for (const candidate of plans) {
      if (!candidate || typeof candidate !== 'object') continue;
      const plan = candidate as ProposedPlan;
      if (typeof plan.plan_id !== 'string' || typeof plan.created_at !== 'number') continue;
      this.plans.set(plan.plan_id, {
        ...(JSON.parse(JSON.stringify(plan)) as ProposedPlan),
        expires_at: Number.isFinite(plan.expires_at)
          ? plan.expires_at
          : plan.created_at + this.ttlMs,
      });
    }
    for (const candidate of tombstones) {
      if (!Array.isArray(candidate) || candidate.length !== 2) continue;
      const [id, disposition] = candidate;
      if (
        typeof id === 'string'
        && (disposition === 'confirmed' || disposition === 'denied' || disposition === 'expired')
      ) {
        this.tombstone(id, disposition);
      }
    }
    // Expire against the original absolute deadline, never restart time.
    this.pruneInternal(now, false, false);
  }

  static deserialize(data: unknown, ttlMs: number = DEFAULT_TTL_MS, now: number = Date.now()): ProposedPlanStore {
    const store = new ProposedPlanStore(ttlMs);
    store.restore(data, now);
    return store;
  }

  /** Test/inspection helper. */
  size(): number {
    return this.plans.size;
  }
}
