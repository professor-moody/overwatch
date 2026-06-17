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
// reads here. It is in-memory only (a proposed-but-unconfirmed plan can be
// re-proposed) with a TTL, mirroring DashboardServer.commandPlans for the
// grammar path.
// ============================================================

import { randomUUID } from 'crypto';
import type { OperatorOp } from './command-interpreter.js';

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
  created_at: number;
  status: ProposedPlanStatus;
}

export interface AddProposedPlanArgs {
  command: string;
  ops: OperatorOp[];
  summary: string;
  rationale?: string;
  source_task_id?: string;
  source_agent_id?: string;
  /** Injectable clock (ms) for deterministic tests. Defaults to Date.now(). */
  now?: number;
}

const DEFAULT_TTL_MS = 10 * 60_000; // 10 min, matches the grammar-plan TTL

/**
 * In-memory store of planner-proposed plans awaiting operator confirmation.
 * Self-contained (no engine ref needed) so it's trivially unit-testable.
 */
export class ProposedPlanStore {
  private plans = new Map<string, ProposedPlan>();
  private onChangeCb: (() => void) | null = null;

  constructor(private ttlMs: number = DEFAULT_TTL_MS) {}

  /** Register a change listener (the dashboard uses this to broadcast). */
  onChange(cb: () => void): void {
    this.onChangeCb = cb;
  }

  /** Record a freshly-proposed plan. Returns the stored record (with its plan_id). */
  add(args: AddProposedPlanArgs): ProposedPlan {
    const now = args.now ?? Date.now();
    this.prune(now);
    const plan: ProposedPlan = {
      plan_id: randomUUID(),
      command: args.command,
      ops: args.ops,
      summary: args.summary,
      rationale: args.rationale,
      source_task_id: args.source_task_id,
      source_agent_id: args.source_agent_id,
      created_at: now,
      status: 'open',
    };
    this.plans.set(plan.plan_id, plan);
    this.onChangeCb?.();
    return plan;
  }

  /** Look up a plan by id (does not expire on read — confirm-path checks status). */
  get(plan_id: string): ProposedPlan | undefined {
    return this.plans.get(plan_id);
  }

  /** All currently-open plans, newest first. */
  getOpen(now: number = Date.now()): ProposedPlan[] {
    this.prune(now);
    return [...this.plans.values()]
      .filter(p => p.status === 'open')
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
    this.prune(now);
    const plan = this.plans.get(plan_id);
    if (!plan || plan.status !== 'open') return null;
    plan.status = status;
    this.onChangeCb?.();
    return plan;
  }

  /** Sweep plans older than the TTL, marking still-open ones expired then dropping all stale. */
  prune(now: number = Date.now()): void {
    const cutoff = now - this.ttlMs;
    for (const [id, p] of this.plans) {
      if (p.created_at < cutoff) this.plans.delete(id);
    }
  }

  /** Test/inspection helper. */
  size(): number {
    return this.plans.size;
  }
}
