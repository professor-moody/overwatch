// ============================================================
// Overwatch — Agent Manager
// CRUD for agent task lifecycle.
// All state access goes through the shared EngineContext.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { AgentTask } from '../types.js';

/**
 * Default heartbeat TTL (seconds) for a running agent that didn't specify one.
 * A task whose last heartbeat is older than this is reaped as stale. The runner
 * grants cold-starting headless agents a longer TTL explicitly (its own
 * `HEADLESS_STARTUP_TTL_SECONDS`); this is the floor for everything else.
 */
const DEFAULT_HEARTBEAT_TTL_SECONDS = 120;

export class AgentManager {
  private ctx: EngineContext;

  constructor(ctx: EngineContext) {
    this.ctx = ctx;
  }

  register(task: AgentTask): { ok: boolean; lease_conflict?: { existing_task_id: string; existing_agent_id: string } } {
    // P1.4: take a frontier lease before claiming the task. If another
    // agent already holds the lease, refuse the registration. This makes
    // race-resolution explicit instead of relying on
    // `getRunningTaskForFrontierItem`'s implicit ordering.
    if (task.frontier_item_id) {
      const result = this.ctx.frontierLeases.acquire({
        frontier_item_id: task.frontier_item_id,
        agent_id: task.agent_id,
        task_id: task.id,
        now: this.ctx.nowIso(),
      });
      if (!result.ok && result.existing) {
        this.ctx.logEvent({
          description: `Agent registration refused: ${task.agent_id} cannot claim ${task.frontier_item_id} (held by task ${result.existing.task_id})`,
          agent_id: task.agent_id,
          category: 'agent',
          event_type: 'instrumentation_warning',
          frontier_item_id: task.frontier_item_id,
          result_classification: 'failure',
          details: {
            reason: 'frontier_lease_conflict',
            existing_task_id: result.existing.task_id,
            existing_agent_id: result.existing.agent_id,
          },
        });
        return {
          ok: false,
          lease_conflict: {
            existing_task_id: result.existing.task_id,
            existing_agent_id: result.existing.agent_id,
          },
        };
      }
    }
    // F3: initialize heartbeat_at to the registration time so the
    // watchdog has a baseline. Without this, a task that crashes before
    // its first heartbeat is exempt from reaping forever — the frontier
    // lease then blocks every dispatch attempt against the same item
    // until manual intervention. With the baseline set, the task gets
    // one TTL window (default 120s) to call agent_heartbeat; failing
    // that, the watchdog reaps it and releases the lease.
    if (task.status === 'running' && !task.heartbeat_at) {
      task.heartbeat_at = this.ctx.nowIso();
    }
    this.ctx.agents.set(task.id, task);
    this.ctx.logEvent({
      description: `Agent dispatched: ${task.agent_id} for ${task.frontier_item_id}`,
      agent_id: task.agent_id,
      category: 'agent',
      event_type: 'agent_registered',
      frontier_item_id: task.frontier_item_id,
      linked_agent_task_id: task.id,
      result_classification: 'neutral',
      details: {
        skill: task.skill,
        subgraph_node_ids: task.subgraph_node_ids,
      },
    });
    return { ok: true };
  }

  getRunningTaskForFrontierItem(frontierItemId: string): AgentTask | null {
    for (const task of this.ctx.agents.values()) {
      if (task.frontier_item_id === frontierItemId && task.status === 'running') {
        return task;
      }
    }
    return null;
  }

  getTask(taskId: string): AgentTask | null {
    return this.ctx.agents.get(taskId) || null;
  }

  updateStatus(taskId: string, status: AgentTask['status'], summary?: string): boolean {
    const task = this.ctx.agents.get(taskId);
    if (!task) return false;
    // Idempotency guard: once an agent has reached a terminal state, swallow
    // duplicate terminal transitions instead of re-emitting events and
    // double-counting downstream campaign progress. We allow `interrupted`
    // to win over a prior `completed`/`failed` so external cancellation
    // signals are still expressible, but symmetric replays no-op.
    const TERMINAL: AgentTask['status'][] = ['completed', 'failed', 'interrupted'];
    const currentTerminal = TERMINAL.includes(task.status);
    const incomingTerminal = TERMINAL.includes(status);
    if (currentTerminal && incomingTerminal && task.status === status) {
      return false;
    }
    task.status = status;
    if (summary) task.result_summary = summary;
    if (status === 'completed' || status === 'failed') {
      task.completed_at = new Date().toISOString();
    }
    // P1.4: release any frontier lease this task held.
    if (status === 'completed' || status === 'failed' || status === 'interrupted') {
      this.ctx.frontierLeases.releaseByTask(taskId);
      // 3D: drop this task's open/answered questions so a dead agent's question
      // doesn't linger in the operator inbox or get answered into the void.
      this.ctx.agentQueryStore.expireForTask(taskId);
    }
    this.ctx.logEvent({
      description: `Agent ${task.agent_id} ${status}${summary ? `: ${summary}` : ''}`,
      agent_id: task.agent_id,
      category: 'agent',
      event_type: 'agent_updated',
      frontier_item_id: task.frontier_item_id,
      linked_agent_task_id: task.id,
      result_classification: status === 'completed' ? 'success' : status === 'failed' ? 'failure' : 'neutral',
      details: {
        status,
        summary,
      },
    });
    return true;
  }

  getAll(): AgentTask[] {
    return Array.from(this.ctx.agents.values());
  }

  /**
   * Auto-register a synthetic running task for an `agent_id` we've never
   * seen before. Called from the instrumented process runner so that
   * subagents which never call `register_agent` / `dispatch_agents`
   * still surface in the dashboard's AgentsPanel.
   *
   * Idempotent — if any running task already exists for this agent_id,
   * returns it unchanged. Synthetic tasks carry `skill: 'auto'` so the
   * operator can distinguish them from explicitly-dispatched agents.
   *
   * Returns null if `agent_id` is missing/blank (no synthesis).
   */
  ensureRunningAgent(agentId: string | undefined, now?: string): AgentTask | null {
    if (!agentId || agentId.trim().length === 0) return null;
    for (const task of this.ctx.agents.values()) {
      if (task.agent_id === agentId && task.status === 'running') return task;
    }
    const ts = now ?? this.ctx.nowIso();
    const task: AgentTask = {
      id: `auto-${agentId}-${ts}`,
      agent_id: agentId,
      assigned_at: ts,
      status: 'running',
      subgraph_node_ids: [],
      skill: 'auto',
      heartbeat_at: ts,
    };
    // No frontier_item_id → no lease attempt → register cannot fail.
    this.register(task);
    return task;
  }

  /**
   * P0.3: heartbeat from a long-running sub-agent. Updates `heartbeat_at`
   * and emits a low-volume `heartbeat` activity event (excluded from the
   * hash chain — same class as `thought`). Returns false if the task is
   * unknown or already terminal; true on success.
   */
  heartbeat(taskId: string, now?: string): boolean {
    const task = this.ctx.agents.get(taskId);
    if (!task) return false;
    const TERMINAL: AgentTask['status'][] = ['completed', 'failed', 'interrupted'];
    if (TERMINAL.includes(task.status)) return false;
    task.heartbeat_at = now ?? new Date().toISOString();
    // P1.4: heartbeat extends any lease this task holds.
    this.ctx.frontierLeases.renew(task.id, task.heartbeat_at);
    this.ctx.logEvent({
      description: `Agent heartbeat: ${task.agent_id}`,
      agent_id: task.agent_id,
      category: 'agent',
      event_type: 'heartbeat',
      linked_agent_task_id: task.id,
      frontier_item_id: task.frontier_item_id,
      result_classification: 'neutral',
      details: { heartbeat_at: task.heartbeat_at },
    });
    return true;
  }

  /**
   * P0.3: walk running tasks and interrupt any whose heartbeat is older
   * than their TTL. Tasks without a heartbeat field are exempt
   * (preserves backward-compat for tools that don't yet heartbeat).
   * Returns the number of tasks interrupted.
   */
  reapStaleHeartbeats(now?: string): number {
    const cutoffNow = now ? Date.parse(now) : Date.now();
    let reaped = 0;
    for (const task of this.ctx.agents.values()) {
      if (task.status !== 'running') continue;
      if (!task.heartbeat_at) continue; // never heartbeated → exempt
      const ttl = (task.heartbeat_ttl_seconds ?? DEFAULT_HEARTBEAT_TTL_SECONDS) * 1000;
      const last = Date.parse(task.heartbeat_at);
      if (Number.isNaN(last)) continue;
      if (cutoffNow - last <= ttl) continue;
      task.status = 'interrupted';
      task.completed_at = new Date(cutoffNow).toISOString();
      task.result_summary = task.result_summary ?? `heartbeat_timeout: last beat ${task.heartbeat_at}, ttl ${ttl / 1000}s`;
      // P1.4: release lease the moment the task is declared dead.
      this.ctx.frontierLeases.releaseByTask(task.id);
      this.ctx.logEvent({
        description: `Agent ${task.agent_id} interrupted: heartbeat timeout`,
        agent_id: task.agent_id,
        category: 'agent',
        event_type: 'instrumentation_warning',
        linked_agent_task_id: task.id,
        frontier_item_id: task.frontier_item_id,
        result_classification: 'failure',
        details: {
          reason: 'heartbeat_timeout',
          heartbeat_at: task.heartbeat_at,
          heartbeat_ttl_seconds: task.heartbeat_ttl_seconds ?? DEFAULT_HEARTBEAT_TTL_SECONDS,
        },
      });
      reaped++;
    }
    return reaped;
  }

  /**
   * On startup, mark any persisted 'running' agents as 'interrupted'
   * since the runtime that spawned them no longer exists.
   *
   * F4: also release the frontier lease each interrupted task held.
   * The normal `updateStatus` terminal path releases via
   * `frontierLeases.releaseByTask`, but this method mutates status
   * directly and used to leave persisted leases sitting in the lease
   * map until their TTL elapsed (default 600s) — blocking every
   * dispatch attempt against the same item across that window.
   */
  reconcileOnStartup(): number {
    let count = 0;
    for (const task of this.ctx.agents.values()) {
      if (task.status === 'running') {
        task.status = 'interrupted';
        task.completed_at = new Date().toISOString();
        this.ctx.frontierLeases.releaseByTask(task.id);
        count++;
      }
    }
    if (count > 0) {
      this.ctx.logEvent({
        description: `Reconciled ${count} agent(s) from 'running' to 'interrupted' on startup`,
        category: 'system',
        event_type: 'system',
        result_classification: 'neutral',
      });
    }
    return count;
  }

  /**
   * Remove a terminal (completed/failed/interrupted) agent task from the roster.
   * Refuses to dismiss a live (running/pending) task — those must be cancelled
   * first, which releases the lease and kills the process. Returns true if a
   * task was removed. Agent tasks are snapshot-persisted (not WAL-journaled), so
   * the caller (GraphEngine.dismissAgent) just needs to persist a snapshot; there
   * is no replay entry to add.
   */
  dismiss(taskId: string): boolean {
    const task = this.ctx.agents.get(taskId);
    if (!task) return false;
    const TERMINAL: AgentTask['status'][] = ['completed', 'failed', 'interrupted'];
    if (!TERMINAL.includes(task.status)) return false;
    this.ctx.agents.delete(taskId);
    this.ctx.logEvent({
      description: `Agent ${task.agent_id} dismissed from the roster`,
      agent_id: task.agent_id,
      category: 'agent',
      event_type: 'agent_updated',
      linked_agent_task_id: task.id,
      frontier_item_id: task.frontier_item_id,
      result_classification: 'neutral',
      details: { reason: 'dismissed', prior_status: task.status },
    });
    return true;
  }
}
