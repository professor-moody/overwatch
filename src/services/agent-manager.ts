// ============================================================
// Overwatch — Agent Manager
// CRUD for agent task lifecycle.
// All state access goes through the shared EngineContext.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { AgentTask } from '../types.js';
import {
  agentLabelOf,
  normalizeAgentTask,
  resolveAgentIdentity,
  taskIdOf,
  type AgentIdentityResolution,
} from './agent-identity.js';

/**
 * Default heartbeat TTL (seconds) for a running agent that didn't specify one.
 * A task whose last heartbeat is older than this is reaped as stale. The runner
 * grants cold-starting headless agents a longer TTL explicitly (its own
 * `HEADLESS_STARTUP_TTL_SECONDS`); this is the floor for everything else.
 */
export const DEFAULT_HEARTBEAT_TTL_SECONDS = 120;

export class AgentManager {
  private ctx: EngineContext;

  constructor(ctx: EngineContext) {
    this.ctx = ctx;
  }

  register(task: AgentTask): {
    ok: boolean;
    lease_conflict?: { existing_task_id: string; existing_agent_id: string };
    node_conflict?: { existing_task_id: string; existing_agent_id: string; node_id: string };
  } {
    // Normalize once at the durable boundary. Mutating the caller's object keeps
    // the historical object-identity behavior of AgentManager.register while
    // ensuring every stored task has canonical fields and synchronized aliases.
    Object.assign(task, normalizeAgentTask(task));
    const taskId = taskIdOf(task);
    const agentLabel = agentLabelOf(task);
    // Node-scoped dispatch dedup: a dispatch with target nodes but NO frontier_item_id
    // (planner `dispatch` op / deploy-at-node) can't take a frontier lease, so nothing
    // stopped a re-issued command from launching a SECOND identical agent at the same
    // node. Refuse when a running/pending agent with the SAME archetype+role already
    // covers one of these nodes — a DIFFERENT archetype on the same host (e.g. a
    // web-crawl alongside a port-scan) is legitimate, so key on (archetype,role,node),
    // not node alone. Frontier-scoped work is deduped by its lease below, not here.
    if (!task.frontier_item_id && task.subgraph_node_ids?.length) {
      const targetNodes = new Set(task.subgraph_node_ids);
      const sig = `${task.archetype ?? ''}|${task.role ?? ''}`;
      for (const other of this.ctx.agents.values()) {
        if (taskIdOf(other) === taskId) continue;
        if (other.status !== 'running' && other.status !== 'pending') continue;
        if (other.frontier_item_id) continue; // frontier work is deduped by its lease
        if (`${other.archetype ?? ''}|${other.role ?? ''}` !== sig) continue;
        const overlap = (other.subgraph_node_ids ?? []).find(n => targetNodes.has(n));
        if (overlap) {
          this.ctx.logEvent({
            description: `Agent registration refused: ${agentLabel} duplicates work at ${overlap} (held by ${agentLabelOf(other)})`,
            agent_id: agentLabel,
            category: 'agent',
            event_type: 'instrumentation_warning',
            linked_agent_task_id: taskId,
            result_classification: 'failure',
            details: { reason: 'node_dispatch_dedup', node_id: overlap, existing_task_id: taskIdOf(other), existing_agent_id: agentLabelOf(other) },
          });
          return { ok: false, node_conflict: { existing_task_id: taskIdOf(other), existing_agent_id: agentLabelOf(other), node_id: overlap } };
        }
      }
    }

    // P1.4: take a frontier lease before claiming the task. If another
    // agent already holds the lease, refuse the registration. This makes
    // race-resolution explicit instead of relying on
    // `getRunningTaskForFrontierItem`'s implicit ordering.
    if (task.frontier_item_id) {
      const result = this.ctx.frontierLeases.acquire({
        frontier_item_id: task.frontier_item_id,
        agent_id: agentLabel,
        task_id: taskId,
        now: this.ctx.nowIso(),
      });
      if (!result.ok && result.existing) {
        this.ctx.logEvent({
          description: `Agent registration refused: ${agentLabel} cannot claim ${task.frontier_item_id} (held by task ${result.existing.task_id})`,
          agent_id: agentLabel,
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
    //
    // A headless task QUEUED behind the concurrency cap has no process yet to beat
    // for itself — TaskExecutionService keeps its heartbeat (and thus its lease)
    // fresh via the watchdog's before-reap hook until a slot frees and it launches.
    if (task.status === 'running' && !task.heartbeat_at) {
      task.heartbeat_at = this.ctx.nowIso();
    }
    this.ctx.agents.set(taskId, task);
    const dispatchTarget = task.frontier_item_id
      ? `for frontier ${task.frontier_item_id}`
      : task.role === 'planner'
        ? 'as operator planner'
        : task.subgraph_node_ids?.length
          ? `at ${task.subgraph_node_ids.length} node(s)`
          : task.objective
            ? 'for an operator objective'
            : 'without a frontier lease';
    this.ctx.logEvent({
      description: `Agent dispatched: ${agentLabel} ${dispatchTarget}`,
      agent_id: agentLabel,
      category: 'agent',
      event_type: 'agent_registered',
      frontier_item_id: task.frontier_item_id,
      linked_agent_task_id: taskId,
      result_classification: 'neutral',
      details: {
        task_id: taskId,
        agent_label: agentLabel,
        archetype: task.archetype,
        role: task.role,
        backend: task.backend,
        frontier_item_id: task.frontier_item_id,
        campaign_id: task.campaign_id,
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

  resolveTaskReference(reference: string): AgentIdentityResolution {
    return resolveAgentIdentity(this.ctx.agents.values(), reference);
  }

  updateStatus(taskId: string, status: AgentTask['status'], summary?: string): boolean {
    const task = this.ctx.agents.get(taskId);
    if (!task) return false;
    return this.transition(task, status, {
      summary,
      completedAt: this.ctx.nowIso(),
      eventType: 'agent_updated',
    });
  }

  private transition(
    task: AgentTask,
    status: AgentTask['status'],
    options: {
      summary?: string;
      completedAt: string;
      eventType: 'agent_updated' | 'instrumentation_warning';
      reason?: string;
      details?: Record<string, unknown>;
      preserveOpenQuestions?: boolean;
    },
  ): boolean {
    // Terminal states are strictly monotonic. Once durable truth says a task
    // completed, failed, or was interrupted, later process races cannot rewrite
    // that outcome into a different terminal state.
    const TERMINAL: AgentTask['status'][] = ['completed', 'failed', 'interrupted'];
    const currentTerminal = TERMINAL.includes(task.status);
    const incomingTerminal = TERMINAL.includes(status);
    if (currentTerminal) return false;
    task.status = status;
    if (options.summary) task.result_summary = options.summary;
    const taskId = taskIdOf(task);
    const agentLabel = agentLabelOf(task);
    if (incomingTerminal) {
      task.completed_at = task.completed_at ?? options.completedAt;
      this.ctx.frontierLeases.releaseByTask(taskId);
      if (!options.preserveOpenQuestions) {
        this.ctx.agentQueryStore.expireForTask(taskId, Date.parse(options.completedAt));
      }
    }
    this.ctx.logEvent({
      description: `Agent ${agentLabel} ${status}${options.summary ? `: ${options.summary}` : ''}`,
      agent_id: agentLabel,
      category: 'agent',
      event_type: options.eventType,
      frontier_item_id: task.frontier_item_id,
      linked_agent_task_id: taskId,
      result_classification: status === 'completed' ? 'success' : status === 'failed' ? 'failure' : 'neutral',
      details: {
        status,
        summary: options.summary,
        reason: options.reason,
        ...options.details,
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
    const matches = [...this.ctx.agents.values()]
      .filter(task => agentLabelOf(task) === agentId && task.status === 'running');
    if (matches.length === 1) return matches[0];
    if (matches.length > 1) {
      this.ctx.logEvent({
        description: `Agent label "${agentId}" is ambiguous; process activity was left unlinked`,
        agent_id: agentId,
        category: 'agent',
        event_type: 'instrumentation_warning',
        result_classification: 'failure',
        details: {
          reason: 'ambiguous_legacy_agent_label',
          candidate_task_ids: matches.map(taskIdOf).sort(),
        },
      });
      return null;
    }
    const ts = now ?? this.ctx.nowIso();
    const task: AgentTask = {
      task_id: `auto-${agentId}-${ts}`,
      agent_label: agentId,
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
  heartbeat(taskId: string, now?: string, opts?: { silent?: boolean }): boolean {
    const task = this.ctx.agents.get(taskId);
    if (!task) return false;
    const TERMINAL: AgentTask['status'][] = ['completed', 'failed', 'interrupted'];
    if (TERMINAL.includes(task.status)) return false;
    task.heartbeat_at = now ?? new Date().toISOString();
    // P1.4: heartbeat extends any lease this task holds.
    this.ctx.frontierLeases.renew(taskIdOf(task), task.heartbeat_at);
    // A `silent` keepalive (supervisor-driven liveness) skips the activity event —
    // it's not agent progress, and emitting one per queued task per tick would spam
    // the log. The beat + lease renewal above are all the reaper needs.
    if (opts?.silent) return true;
    this.ctx.logEvent({
      description: `Agent heartbeat: ${agentLabelOf(task)}`,
      agent_id: agentLabelOf(task),
      category: 'agent',
      event_type: 'heartbeat',
      linked_agent_task_id: taskIdOf(task),
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
      const summary = task.result_summary
        ?? `heartbeat_timeout: last beat ${task.heartbeat_at}, ttl ${ttl / 1000}s`;
      if (this.transition(task, 'interrupted', {
        summary,
        completedAt: new Date(cutoffNow).toISOString(),
        eventType: 'instrumentation_warning',
        reason: 'heartbeat_timeout',
        details: {
          heartbeat_at: task.heartbeat_at,
          heartbeat_ttl_seconds: task.heartbeat_ttl_seconds ?? DEFAULT_HEARTBEAT_TTL_SECONDS,
        },
      })) reaped++;
    }
    return reaped;
  }

  /** Read-only watchdog preflight. It deliberately returns only IDs so a no-op
   * tick never clones the historical roster or drafts a durable state slice. */
  getStaleHeartbeatTaskIds(now?: string): string[] {
    const cutoffNow = now ? Date.parse(now) : Date.now();
    const stale: string[] = [];
    for (const task of this.ctx.agents.values()) {
      if (task.status !== 'running' || !task.heartbeat_at) continue;
      const last = Date.parse(task.heartbeat_at);
      if (!Number.isFinite(last)) continue;
      const ttl = (task.heartbeat_ttl_seconds ?? DEFAULT_HEARTBEAT_TTL_SECONDS) * 1_000;
      if (cutoffNow - last > ttl) stale.push(taskIdOf(task));
    }
    return stale;
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
        if (this.transition(task, 'interrupted', {
          summary: task.result_summary ?? 'interrupted by daemon restart',
          completedAt: this.ctx.nowIso(),
          eventType: 'agent_updated',
          reason: 'startup_reconciliation',
          // Restart interrupts the runtime, not the operator decision. Keep an
          // unexpired question in the inbox so it remains answerable for a
          // future resume/retry instead of silently discarding the handoff.
          preserveOpenQuestions: true,
        })) count++;
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
      description: `Agent ${agentLabelOf(task)} dismissed from the roster`,
      agent_id: agentLabelOf(task),
      category: 'agent',
      event_type: 'agent_updated',
      linked_agent_task_id: taskIdOf(task),
      frontier_item_id: task.frontier_item_id,
      result_classification: 'neutral',
      details: { reason: 'dismissed', prior_status: task.status },
    });
    return true;
  }
}
