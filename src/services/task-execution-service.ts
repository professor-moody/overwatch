// ============================================================
// Overwatch — Task Execution Service
//
// App-level owner of agent-task execution. Decouples execution from the
// dashboard (it must run whether or not the dashboard is open) and routes each
// registered AgentTask to its execution backend:
//
//   - 'scripted'     : in-process deterministic runner (credential_test, token
//                      validation). Handled by ScriptedAgentRunner.
//   - 'headless_mcp' : a headless `claude -p` reasoning sub-agent connected back
//                      to this daemon's /mcp endpoint. Spawned by
//                      HeadlessMcpRunner; tracked + killable via the registry.
//                      Only launched when an HTTP endpoint is available (daemon
//                      mode); in stdio mode these tasks defer to manual.
//   - 'manual'       : a human operator drives it; no automated execution.
//
// Also owns the AgentWatchdog (previously never started in production) and the
// headless process registry (so cancel / timeout / shutdown can stop agents).
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import type { GraphEngine } from './graph-engine.js';
import type { ProcessTracker } from './process-tracker.js';
import type { AgentTask, TaskBackend } from '../types.js';
import { ScriptedAgentRunner, scriptedCanHandle } from './scripted-agent-runner.js';
import { AgentWatchdog } from './agent-watchdog.js';
import { DEFAULT_HEARTBEAT_TTL_SECONDS } from './agent-manager.js';
import { HeadlessProcessRegistry } from './headless-process-registry.js';
import { HeadlessMcpRunner, type HeadlessEndpoint, type HeadlessMcpRunnerOptions } from './headless-mcp-runner.js';
import { ApplicationCommandService } from './application-command-service.js';

/**
 * Resolve which backend should execute a task. Explicit `task.backend` wins;
 * otherwise defaults to 'scripted' (preserves legacy behavior where the scripted
 * runner picked up every running task). Frontier-type-aware defaults can be
 * layered in here once headless execution is the norm.
 */
export function resolveTaskBackend(task: AgentTask): TaskBackend {
  return task.backend ?? 'scripted';
}

const DEFAULT_MAX_HEADLESS = 3;
const DEFAULT_MAX_HEADLESS_PLANNERS = 1;
const DEFAULT_HEADLESS_TIMEOUT_MS = 30 * 60_000; // 30 minutes
// Persistent orchestrator crash-loop backoff: exponential from 30s, capped at
// 10 min; a run that lasted this long counts as healthy and resets the backoff.
const ORCHESTRATOR_BACKOFF_BASE_MS = 30_000;
const ORCHESTRATOR_BACKOFF_CAP_MS = 10 * 60_000;
const ORCHESTRATOR_HEALTHY_MS = 5 * 60_000;
// Wedged-primary ceiling: if the orchestrator's process is alive but has produced NO
// output this long, treat it as hung and restart it. A healthy primary delegates
// long-running work to sub-agents (dispatch is async — it keeps polling get_state and
// streaming output while they run), so it goes silent this long only if it DIRECTLY
// awaits a single long tool call — which it should avoid. That residual case (and the
// recovery speed for a true hang) is why the ceiling is tunable via options.
const ORCHESTRATOR_WEDGED_CEILING_MS = 30 * 60_000;

export interface TaskExecutionServiceOptions {
  /** Watchdog tick interval (ms). Defaults to the watchdog's own default (30s). */
  watchdogIntervalMs?: number;
  /** Max concurrently-running headless sub-agents. Default 3. */
  maxConcurrentHeadless?: number;
  /** Max concurrently-running operator planners. Planners use a bounded
   *  control-plane lane outside the target-worker pool. Default 1. */
  maxConcurrentPlanners?: number;
  /** Per-task wall-clock timeout for headless sub-agents (ms). Default 30 min. */
  headlessTimeoutMs?: number;
  /** Poll interval for detecting a live writable→read-only persistence
   *  transition.  This is intentionally much shorter than the agent watchdog:
   *  target work must be frozen promptly when durable state becomes unavailable. */
  persistenceGatePollMs?: number;
  /** A persistent-orchestrator run lasting at least this long counts as healthy and
   *  resets the crash-loop backoff. Default 5 min (lowered in tests). */
  orchestratorHealthyMs?: number;
  /** If the orchestrator's process is alive but it makes no genuine heartbeat for
   *  this long, it's treated as wedged and restarted. Default 30 min (lowered in tests). */
  orchestratorWedgedCeilingMs?: number;
  /** Options forwarded to HeadlessMcpRunner (claude binary, spawnFn for tests, etc.). */
  headless?: HeadlessMcpRunnerOptions;
}

export class TaskExecutionService {
  private engine: GraphEngine;
  private scripted: ScriptedAgentRunner;
  private watchdog: AgentWatchdog;
  private registry: HeadlessProcessRegistry;
  private headlessRunner: HeadlessMcpRunner;
  private running = false;
  private startRequested = false;
  private persistenceGateTimer: ReturnType<typeof setInterval> | null = null;
  private updateUnsubscribe: (() => void) | null = null;
  private recoveryResumeTimer: ReturnType<typeof setTimeout> | null = null;
  private recoveryResumeFailures = 0;

  /** HTTP endpoint headless children connect to. Unset in stdio mode. */
  private endpoint: HeadlessEndpoint | null = null;
  /** Task ids we've already spawned a headless process for (dedupe re-drains). */
  private launched = new Set<string>();
  /** Per-task wall-clock timeout timers for headless agents. */
  private timeoutTimers = new Map<string, ReturnType<typeof setTimeout>>();
  /** Tasks for which we've already logged a "no automated backend" deferral. */
  private deferredLogged = new Set<string>();
  /** cve_research frontier item ids we've already auto-dispatched this session. */
  private cveAttempted = new Set<string>();
  /** Persistent orchestrator ("primary") lifecycle: the current orchestrator task,
   *  when it spawned, and crash-loop backoff state. */
  private orchestratorTaskId: string | null = null;
  private orchestratorSpawnedAt = 0;
  private orchestratorFailures = 0;
  private orchestratorNextSpawnAt = 0;

  private maxConcurrentHeadless: number;
  private maxConcurrentPlanners: number;
  private headlessTimeoutMs: number;
  private persistenceGatePollMs: number;
  private orchestratorHealthyMs: number;
  private orchestratorWedgedCeilingMs: number;

  constructor(engine: GraphEngine, processTracker: ProcessTracker, options: TaskExecutionServiceOptions = {}) {
    this.engine = engine;
    this.scripted = new ScriptedAgentRunner(engine);
    this.watchdog = new AgentWatchdog(engine, {
      intervalMs: options.watchdogIntervalMs,
      // Before each reap, keep supervised tasks' heartbeats fresh: the orchestrator
      // while its process is alive (its beat otherwise only advances when the model
      // calls agent_heartbeat), and sub-agents queued behind the cap (no process yet).
      beforeTick: () => this.refreshSupervisedLiveness(),
      // After each reap, kill any headless process whose task is now terminal
      // and abort its blocked approvals (heartbeat-reap doesn't do either).
      afterTick: () => { this.reconcileTerminatedTasks(); this.reofferStrandedWork(); this.reconcileOrchestrator(); },
    });
    this.registry = new HeadlessProcessRegistry();
    this.headlessRunner = new HeadlessMcpRunner(engine, this.registry, processTracker, options.headless);
    // Normal stop/shutdown still lets child exit handlers finalize lifecycle
    // state. Only persistence degradation suppresses those durable callbacks.
    this.headlessRunner.setMutationGuard(() => this.engine.isPersistenceWritable());
    this.maxConcurrentHeadless = options.maxConcurrentHeadless ?? DEFAULT_MAX_HEADLESS;
    this.maxConcurrentPlanners = options.maxConcurrentPlanners ?? DEFAULT_MAX_HEADLESS_PLANNERS;
    this.headlessTimeoutMs = options.headlessTimeoutMs ?? DEFAULT_HEADLESS_TIMEOUT_MS;
    this.persistenceGatePollMs = options.persistenceGatePollMs ?? 250;
    this.orchestratorHealthyMs = options.orchestratorHealthyMs ?? ORCHESTRATOR_HEALTHY_MS;
    this.orchestratorWedgedCeilingMs = options.orchestratorWedgedCeilingMs ?? ORCHESTRATOR_WEDGED_CEILING_MS;
  }

  /**
   * Provide the /mcp endpoint headless sub-agents should connect to. Called by
   * startHttpApp once the server is bound. Setting it enables the headless
   * backend and triggers a drain for any waiting headless tasks.
   */
  setHttpEndpoint(endpoint: HeadlessEndpoint): void {
    this.endpoint = endpoint;
    // A degraded-recovery daemon still exposes MCP/dashboard reads, but must not
    // turn a newly-bound HTTP endpoint into permission to launch persisted work.
    // start() remains retryable: if persistence later recovers, a subsequent
    // start() sees this retained endpoint and drains normally.
    if (!this.running || !this.engine.isPersistenceWritable()) return;
    this.drainHeadless();
    this.reconcileOrchestrator(); // headless is now available — start the primary if opted in
  }

  /**
   * Engine-aware backend routing. Explicit task.backend wins. Otherwise the
   * scripted runner only takes work it can actually handle (scriptedCanHandle);
   * all open-ended/reasoning work goes to a real headless agent when the HTTP
   * runtime is available, falling back to scripted only when it isn't (so tasks
   * aren't left stuck in stdio mode). This is what makes register_agent /
   * dispatch_agents / subnet+campaign dispatch spin up real reasoning agents.
   */
  private resolveBackend(task: AgentTask): TaskBackend {
    if (task.backend) return task.backend;
    if (scriptedCanHandle(this.engine, task)) return 'scripted';
    return this.endpoint ? 'headless_mcp' : 'scripted';
  }

  start(): void {
    this.startRequested = true;
    if (this.running) return;
    if (!this.engine.isPersistenceWritable()) {
      const recovery = this.engine.getPersistenceRecoveryStatus();
      console.error(
        `[persistence] task execution not started while persistence is read-only: ${recovery.reason ?? recovery.last_persistence_error ?? recovery.outcome}`,
      );
      return;
    }
    this.running = true;
    let subscribedDuringStart = false;
    try {
      this.startPersistenceGateMonitor();
      // The scripted runner only picks up tasks our routing assigns to it.
      this.scripted.setShouldHandle((task) => (
        this.engine.isPersistenceWritable() && this.resolveBackend(task) === 'scripted'
      ));
      this.scripted.start();
      this.watchdog.start();
      if (!this.updateUnsubscribe) {
        subscribedDuringStart = true;
        this.updateUnsubscribe = this.engine.onUpdate(() => {
          if (!this.running) return;
          if (!this.ensurePersistenceWritable()) return;
          this.drainDirectives();
          this.drainCveResearch();
          this.drainHeadless();
        });
      }
      this.drainCveResearch();
      this.drainHeadless();
      this.reconcileOrchestrator(); // in case the endpoint is already set
      this.clearRecoveryResumeRetry();
    } catch (error) {
      // Startup is an all-or-nothing lifecycle boundary. A synchronous drain
      // failure must not leave `running=true` (which would make every future
      // recovery resume a no-op) or leave timers/subscriptions/processes alive.
      this.running = false;
      this.stopPersistenceGateMonitor();
      this.scripted.stop();
      this.watchdog.stop();
      for (const timer of this.timeoutTimers.values()) clearTimeout(timer);
      this.timeoutTimers.clear();
      if (subscribedDuringStart) {
        this.updateUnsubscribe?.();
        this.updateUnsubscribe = null;
      }
      if (this.engine.isPersistenceWritable()) {
        for (const entry of this.registry.listActive()) {
          this.cancelHeadless(entry.task_id, 'task execution startup failed');
        }
      }
      this.registry.killAll();
      throw error;
    }
  }

  /** Resume a start that was intentionally deferred by read-only recovery. */
  resumeAfterRecovery(): void {
    if (!this.startRequested) return;
    try {
      this.start();
    } catch (error) {
      this.scheduleRecoveryResumeRetry();
      throw error;
    }
  }

  private scheduleRecoveryResumeRetry(): void {
    if (this.recoveryResumeTimer || !this.startRequested || this.running) return;
    const delays = [250, 1_000, 5_000, 30_000] as const;
    const failure = this.recoveryResumeFailures++;
    const delay = delays[Math.min(failure, delays.length - 1)];
    this.recoveryResumeTimer = setTimeout(() => {
      this.recoveryResumeTimer = null;
      if (!this.startRequested || this.running || !this.engine.isPersistenceWritable()) return;
      try {
        this.start();
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`[recovery] task execution retry ${this.recoveryResumeFailures} failed: ${message}`);
        this.scheduleRecoveryResumeRetry();
      }
    }, delay);
    this.recoveryResumeTimer.unref?.();
  }

  private clearRecoveryResumeRetry(): void {
    if (this.recoveryResumeTimer) clearTimeout(this.recoveryResumeTimer);
    this.recoveryResumeTimer = null;
    this.recoveryResumeFailures = 0;
  }

  /**
   * Persistence can become read-only asynchronously after the third failed
   * snapshot while agent processes are already running.  Entry-point guards do
   * not cover that transition, so this monitor freezes every service-owned
   * execution source promptly and lets the existing process-group termination
   * paths reap children and grandchildren.
   */
  private startPersistenceGateMonitor(): void {
    if (this.persistenceGateTimer) return;
    this.persistenceGateTimer = setInterval(() => {
      this.ensurePersistenceWritable();
    }, this.persistenceGatePollMs);
    this.persistenceGateTimer.unref?.();
  }

  private stopPersistenceGateMonitor(): void {
    if (!this.persistenceGateTimer) return;
    clearInterval(this.persistenceGateTimer);
    this.persistenceGateTimer = null;
  }

  private ensurePersistenceWritable(): boolean {
    if (!this.running) return false;
    if (this.engine.isPersistenceWritable()) return true;
    this.freezeForPersistence();
    return false;
  }

  private freezeForPersistence(): void {
    if (!this.running) return;
    // Flip the lifecycle flag first.  Exit/error callbacks and re-entrant engine
    // updates observe the frozen state before any signals are delivered.
    this.running = false;
    this.stopPersistenceGateMonitor();
    this.scripted.stop();
    this.watchdog.stop();
    for (const timer of this.timeoutTimers.values()) clearTimeout(timer);
    this.timeoutTimers.clear();
    // HeadlessProcessRegistry owns safe SIGTERM→SIGKILL process-group cleanup.
    // Do not update task/process records here: persistence is unavailable, so
    // restart reconciliation remains the truthful source of terminal status.
    this.registry.killAll();
    const recovery = this.engine.getPersistenceRecoveryStatus();
    console.error(
      `[persistence] task execution frozen while persistence is read-only: ${recovery.reason ?? recovery.last_persistence_error ?? recovery.outcome}`,
    );
  }

  /**
   * Auto-dispatch `cve_research` frontier items to headless web-research agents.
   * Gated on: an HTTP endpoint existing (daemon mode) AND cve_research enabled
   * (air-gapped engagements set `cve_research.enabled = false`). Bounded by the
   * shared headless concurrency cap; each item is dispatched at most once per
   * session (the agent stamps `cve_checked_at` via research_cve, which retires
   * the item permanently). This is what makes CVE research happen without the
   * primary having to remember to do it.
   */
  private drainCveResearch(): void {
    if (!this.running || !this.engine.isPersistenceWritable()) return;
    if (!this.endpoint) return;
    if (this.engine.getConfig().cve_research?.enabled === false) return;

    // Budget against all non-terminal target-facing headless work (launched or queued) — count
    // by the RESOLVED backend, NOT the persisted field. Normal dispatched agents
    // (recon/web/cred/…) never set task.backend yet still run headless, so the old
    // `t.backend === 'headless_mcp'` check counted 0 of them and over-registered
    // CVE tasks past the cap. Those extras couldn't launch (registry already full),
    // sat unspawned, got heartbeat-reaped, and — since they were marked attempted —
    // CVE research was silently abandoned for the session. resolveBackend matches
    // exactly what drainHeadless will launch, so the budget is now honest.
    const activeHeadless = this.engine.getAgentTasks().filter(
      t => (t.status === 'running' || t.status === 'pending')
        && t.role !== 'planner'
        && t.role !== 'orchestrator'
        && t.orchestrator !== true
        && this.resolveBackend(t) === 'headless_mcp',
    ).length;
    let budget = this.maxConcurrentHeadless - activeHeadless;
    if (budget <= 0) return;

    let frontier;
    try { frontier = this.engine.computeFrontier(); } catch { return; }
    for (const item of frontier) {
      if (item.type !== 'cve_research') continue;
      if (this.cveAttempted.has(item.id)) continue;
      if (budget <= 0) break;
      // Skip items already held by another task's frontier lease: that task is
      // working the item, so registering here only earns a lease-conflict refusal.
      // computeFrontier() returns the UNfiltered set (leased items included), so
      // without this guard a held lease would be re-registered — and refused,
      // logging a frontier_lease_conflict warning + a persist — on every drain for
      // the lease's whole lifetime. Skipping WITHOUT marking keeps the item
      // retryable: once the lease frees, a later drain dispatches it.
      if (this.engine.isFrontierItemHeldByOther(item.id)) continue;
      // Mark attempted BEFORE registering: registerAgent fires onUpdate
      // synchronously, which re-enters drainCveResearch — marking first stops the
      // re-entrant pass from double-dispatching the same item.
      this.cveAttempted.add(item.id);
      const taskId = uuidv4();
      const result = this.engine.registerAgent({
        id: taskId,
        agent_id: `cve-research-${taskId.slice(0, 8)}`,
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: item.id,
        subgraph_node_ids: item.node_id ? [item.node_id] : [],
        backend: 'headless_mcp',
        role: 'research',
        skill: 'cve-research',
      });
      // Only a real launch consumes one of our concurrency slots; a lease conflict
      // (another task already working the item) does not, so don't burn budget on
      // it. registerAgent fires onUpdate → drainHeadless launches the sub-agent.
      if (result.ok) {
        budget--;
      } else {
        // Refused despite the held-lease pre-check above — a lease was acquired in
        // the race between the check and here. Nothing launched, no slot consumed;
        // un-mark so the item is retried on a later drain rather than abandoned.
        this.cveAttempted.delete(item.id);
      }
    }
  }

  /**
   * Execute pending 'stop' directives for live headless agents. The engine
   * records the directive (decision); this service performs the process control
   * (kill + interrupt). pause/resume/steering are NOT acted on here — the agent
   * observes those via agent_heartbeat and honors them itself.
   */
  private drainDirectives(): void {
    for (const task of this.engine.getAgentTasks()) {
      if (task.status !== 'running') continue;
      if (!this.registry.has(task.id)) continue; // only live headless processes
      const pending = this.engine.getPendingAgentDirective(task.id);
      if (pending?.kind !== 'stop') continue;
      this.engine.acknowledgeAgentDirective(task.id, pending.id);
      // A stop directive (per-agent or fleet) is a deliberate operator stop —
      // mark it so the Phase 3.1 re-offer sweep doesn't auto-re-dispatch the work.
      this.engine.updateAgentSchedulerFlags(task.id, { no_retry: true });
      this.cancelHeadless(task.id, `stop directive (${pending.id})`);
    }
  }

  stop(): void {
    this.startRequested = false;
    this.clearRecoveryResumeRetry();
    this.running = false;
    this.stopPersistenceGateMonitor();
    this.scripted.stop();
    this.watchdog.stop();
    for (const t of this.timeoutTimers.values()) clearTimeout(t);
    this.timeoutTimers.clear();
    this.updateUnsubscribe?.();
    this.updateUnsubscribe = null;
    this.interruptHeadlessTasks('task execution service stopped');
    // Best-effort, fire-and-forget (sync callers). Daemon shutdown should use
    // shutdown() to actually AWAIT termination.
    this.registry.killAll();
  }

  /**
   * Async shutdown for the daemon: stops runners and AWAITS headless children
   * exiting (SIGTERM→SIGKILL escalation) so none outlive the process.
   */
  async shutdown(): Promise<void> {
    this.startRequested = false;
    this.clearRecoveryResumeRetry();
    this.running = false;
    this.stopPersistenceGateMonitor();
    this.scripted.stop();
    this.watchdog.stop();
    for (const t of this.timeoutTimers.values()) clearTimeout(t);
    this.timeoutTimers.clear();
    this.updateUnsubscribe?.();
    this.updateUnsubscribe = null;
    this.interruptHeadlessTasks('daemon shutdown');
    await this.registry.killAllAndWait();
  }

  /** Exposed for tests so a tick can be forced without waiting on the timer. */
  tickWatchdog(): number {
    if (!this.ensurePersistenceWritable()) return 0;
    return this.watchdog.tick();
  }

  /** Number of headless sub-agent processes currently tracked. */
  activeHeadlessCount(): number {
    return this.registry.size();
  }

  /**
   * Whether the headless backend can actually run (daemon mode with a bound
   * /mcp endpoint). The dashboard checks this before spawning a planner so a
   * free-form command in stdio mode fails fast instead of registering a task
   * that can only defer to manual.
   */
  isHeadlessAvailable(): boolean {
    return this.running
      && this.endpoint !== null
      && this.engine.isPersistenceWritable();
  }

  /**
   * Stop a running headless sub-agent: kill its OS process (SIGTERM→SIGKILL) and
   * mark the task interrupted (releases the frontier lease). No-op for tasks
   * with no live process. Returns whether a process was killed.
   *
   * The engine records the decision (status); this service performs the OS
   * process control — kept separate so the engine layer never touches processes.
   */
  cancelHeadless(task_id: string, reason = 'cancelled by operator'): boolean {
    const killed = this.registry.kill(task_id);
    const timer = this.timeoutTimers.get(task_id);
    if (timer) { clearTimeout(timer); this.timeoutTimers.delete(task_id); }
    const task = this.engine.getTask(task_id);
    if (task && (task.status === 'running' || task.status === 'pending')) {
      this.engine.updateAgentStatus(task_id, 'interrupted', reason);
    }
    if (task?.application_command_id) {
      const command = this.engine.getApplicationCommandById(task.application_command_id);
      if (
        command
        && command.status !== 'succeeded'
        && command.status !== 'failed'
        && command.status !== 'interrupted'
      ) {
        new ApplicationCommandService(this.engine).transition(
          task.application_command_id,
          {
            status: 'interrupted',
            error: {
              code: task.role === 'planner'
                ? 'PLANNER_INTERRUPTED'
                : 'AGENT_COMMAND_INTERRUPTED',
              message: reason,
            },
            entity_refs: { planner_task_id: task.task_id ?? task.id },
            result: {
              phase: 'interrupted',
              command_id: task.application_command_id,
              planner_task_id: task.task_id ?? task.id,
              reason,
            },
          },
        );
      }
    }
    // Abort any approval gate this agent was blocked on, so it can't auto-fire on
    // timeout and execute a command for an agent we just killed.
    this.engine.abortApprovalsForTask(task_id, reason);
    return killed;
  }

  private interruptHeadlessTasks(reason: string): void {
    for (const task of this.engine.getAgentTasks()) {
      if (task.status !== 'running' && task.status !== 'pending') continue;
      if (this.resolveBackend(task) !== 'headless_mcp') continue;
      try {
        this.cancelHeadless(task.id, reason);
      } catch {
        // Persistence may already be degraded during shutdown. Process cleanup
        // must still proceed; durable recovery owns the unfinished task/command.
        this.registry.kill(task.id);
      }
    }
  }

  /**
   * Reconcile tracked headless processes + wall-clock timers against engine task
   * state. The watchdog's heartbeat-reap (and any path that flips a task terminal
   * without going through cancelHeadless) marks the task 'interrupted' but does
   * NOT fire onUpdate, kill the OS process, or settle its pending approval — so a
   * reaped `claude -p` keeps running (double-execution risk) and its blocked
   * approval can auto-fire on timeout. Runs after every watchdog tick. Idempotent.
   */
  private reconcileTerminatedTasks(): void {
    // Orphaned processes: task no longer running but its process is still tracked.
    for (const entry of this.registry.listActive()) {
      const task = this.engine.getTask(entry.task_id);
      if (task && (task.status === 'running' || task.status === 'pending')) continue;
      this.cancelHeadless(entry.task_id, 'reaped: task no longer running');
    }
    // Leaked wall-clock timers: task finished by some path but its timer is still
    // armed and the process is gone (normal-exit case the timeout path misses).
    for (const [taskId, timer] of [...this.timeoutTimers]) {
      if (this.registry.has(taskId)) continue;
      const task = this.engine.getTask(taskId);
      if (task && (task.status === 'running' || task.status === 'pending')) continue;
      clearTimeout(timer);
      this.timeoutTimers.delete(taskId);
    }
  }

  /**
   * Phase 3.1 resilience. A headless agent that ends ABNORMALLY (wall-clock
   * timeout / heartbeat-reap / process death / boot reconcile) with unfinished
   * frontier work used to leave it silently stranded — "the log recovers but
   * nothing continues". This makes it LOUD: a one-time alert per dead task noting
   * the work is stranded and back on the frontier for pickup. The frontier lease
   * was already released on termination, so the item re-surfaces for the operator
   * — or (Phase 3.2) the persistent orchestrator that consumes this signal — to
   * redo. We deliberately do NOT auto-spawn a replacement: doing that correctly
   * over a mutable, id-reusing frontier + OPSEC/dispatch caps is the orchestrator's
   * job. Runs after every watchdog tick; each dead task is alerted at most once
   * (durable `reoffered` flag).
   */
  private reofferStrandedWork(): void {
    for (const task of this.engine.getAgentTasks()) {
      // Only abnormal terminations of headless work tied to a frontier item.
      if (task.status !== 'interrupted' && task.status !== 'failed') continue;
      if (task.no_retry) continue;                              // deliberate operator stop
      if (task.reoffered) continue;                             // alert once per dead task (durable)
      if (!task.frontier_item_id) continue;                     // planner/ad-hoc carry none
      // Use the STORED backend, not resolveBackend() — the latter re-derives via
      // scriptedCanHandle over live graph state and could flip a task that ran
      // headless to 'scripted' post-death, silently skipping a real strand.
      if (task.backend === 'scripted' || task.backend === 'manual') continue;
      // Wait until the OS process is confirmed gone (reconcileTerminatedTasks kills
      // it first each tick) so we don't alert on a task whose `claude -p` might yet
      // finish. Don't mark reoffered until then.
      if (this.registry.has(task.id)) continue;
      // A deliberately-aborted campaign is not "stranded" — record it handled.
      if (task.campaign_id && this.engine.getCampaign(task.campaign_id)?.status === 'aborted') {
        this.engine.updateAgentSchedulerFlags(task.id, { reoffered: true });
        continue;
      }

      // Is there still work? The frontier is the source of truth. getFrontierItem
      // runs computeFrontier(), which can throw on a concurrent graph mutation — a
      // throw must NOT commit the durable dedup flag (that would permanently
      // suppress a real strand), so we compute BEFORE marking and skip (retry next
      // tick) on error, mirroring drainCveResearch's guarded compute.
      let stillOpen: boolean;
      try {
        stillOpen = !!this.engine.getFrontierItem(task.frontier_item_id);
      } catch {
        continue; // transient — re-evaluate next tick, reoffered NOT set
      }

      // Now safe to commit the durable dedup flag.
      this.engine.updateAgentSchedulerFlags(task.id, { reoffered: true });
      if (!stillOpen) continue;                                 // item done/achieved/out-of-scope → nothing stranded
      // Already being worked by a live task (e.g. a fresh dispatch)? not stranded.
      const beingWorked = this.engine.getAgentTasks().some(t =>
        t.frontier_item_id === task.frontier_item_id && (t.status === 'running' || t.status === 'pending'));
      if (beingWorked) continue;

      // Make the strand LOUD. The frontier lease was released on termination, so
      // the item is already back on the frontier for pickup — by the operator, or
      // (Phase 3.2) the persistent orchestrator that consumes this signal. We do
      // NOT auto-spawn a replacement here: doing so correctly over a mutable,
      // id-reusing frontier + OPSEC/dispatch caps is the orchestrator's job.
      this.engine.logActionEvent({
        description: `Agent ${task.agent_id} ended (${task.status}) with unfinished work — ${task.frontier_item_id} is stranded and back on the frontier for pickup`,
        event_type: 'instrumentation_warning',
        category: 'agent',
        agent_id: task.agent_id,
        linked_agent_task_id: task.id,
        frontier_item_id: task.frontier_item_id,
        result_classification: 'failure',
        details: { reason: 'work_reoffered', frontier_item_id: task.frontier_item_id },
      });
    }

  }

  /**
   * Supervisor-owned liveness: keep the heartbeat (and thus the frontier lease) fresh
   * for tasks the supervisor is actively managing but that cannot beat for themselves
   * right now. `heartbeat_at` otherwise advances ONLY when the model calls
   * `agent_heartbeat`, so without this two things go wrong:
   *
   *  - The persistent orchestrator (a keepalive on a wall-clock schedule the model
   *    cannot perceive) emits no beat during a long synthesis turn / blocking approval
   *    / long tool call, and the watchdog reaps it mid-work — `reconcileTerminatedTasks`
   *    then kills the still-live process and `reconcileOrchestrator` respawns it,
   *    churning real work. Since WE hold the child process, WE own its liveness: refresh
   *    while its process is alive in the registry — UNLESS it's wedged (alive but making
   *    no genuine beat within the ceiling), in which case we kill it so a fresh primary
   *    is respawned instead of propping up a hung one forever.
   *  - A headless sub-agent QUEUED behind the concurrency cap is registered (and holds a
   *    frontier lease) but has no process yet, so it can neither beat nor renew its lease.
   *    Left alone it is reaped at its TTL before it ever launches, and its lease expires
   *    (freeing the item for a duplicate dispatch). Refresh it until a slot frees.
   *
   * Runs at the START of each watchdog tick, BEFORE reaping. Refreshes only once a beat
   * is older than half its TTL, so the event volume stays low and scales to each task's
   * own TTL. A throw is caught + logged by the watchdog's before-reap hook wrapper.
   */
  private refreshSupervisedLiveness(): void {
    const now = Date.now();
    const isStale = (task: AgentTask): boolean => {
      if (task.status !== 'running' || !task.heartbeat_at) return false;
      const ttlMs = (task.heartbeat_ttl_seconds ?? DEFAULT_HEARTBEAT_TTL_SECONDS) * 1000;
      const age = now - Date.parse(task.heartbeat_at);
      return Number.isFinite(age) && age > ttlMs / 2;
    };

    // The orchestrator — only while its process is genuinely alive.
    const orchId = this.orchestratorTaskId;
    if (orchId && this.registry.has(orchId)) {
      const t = this.engine.getTask(orchId);
      if (t && t.status === 'running') {
        // Wedged-primary guard: the silent keepalive stops a LIVE process from being
        // reaped, but a process that HANGS would then be propped up forever. Liveness =
        // process OUTPUT, not agent_heartbeat: a working `claude -p` streams stdout as it
        // thinks and calls tools; a hung one is silent. (agent_heartbeat is unreliable —
        // the orchestrator prompt doesn't force it, which is why the supervisor keepalive
        // exists at all.) If the process has produced NO output within the ceiling, kill
        // it — reconcileOrchestrator respawns a fresh primary. Falls back to assigned_at
        // before the first chunk, so a just-launched primary gets the full ceiling.
        const lastOutputAt = this.registry.get(orchId)?.last_output_at;
        const genuineAt = lastOutputAt ?? Date.parse(t.assigned_at);
        if (Number.isFinite(genuineAt) && now - genuineAt > this.orchestratorWedgedCeilingMs) {
          this.engine.logActionEvent({
            description: `Orchestrator ${t.agent_id} appears wedged — no process output in ${Math.round((now - genuineAt) / 60_000)}m; restarting`,
            event_type: 'instrumentation_warning', category: 'agent', result_classification: 'failure',
            linked_agent_task_id: orchId,
            details: { reason: 'orchestrator_wedged', last_output_at: lastOutputAt ?? null },
          });
          this.cancelHeadless(orchId, 'orchestrator wedged — no process output within the ceiling');
        } else if (isStale(t)) {
          // Silent keepalive: in-memory beat + lease renewal only, no event / disk write.
          this.engine.agentHeartbeat(orchId, undefined, { silent: true });
        }
      }
    }

    // Headless sub-agents: keep the frontier moving without reaping a busy agent.
    //  - QUEUED behind the concurrency cap (no process yet): it can neither beat nor
    //    renew its lease, so refresh it until a slot frees.
    //  - LAUNCHED with a live process: it must self-beat, but while it's blocked inside
    //    a single long tool child (a big nmap / subfinder / gowitness crawl) the model
    //    isn't looping, so no agent_heartbeat fires and the reaper would kill a healthy
    //    scanner mid-run. Use the SAME liveness signal as the orchestrator — process
    //    OUTPUT — and keep it fresh as long as it has produced output within the wedged
    //    ceiling. Past the ceiling with no output it's genuinely hung: stop propping it
    //    up and let the reaper (+ the 30-min wall-clock timeout) take it.
    if (!this.endpoint) return;
    for (const task of this.engine.getAgentTasks()) {
      if (task.status !== 'running') continue;                                  // cheap skip for terminal/historical
      if (task.orchestrator === true || task.role === 'orchestrator') continue; // handled above
      if (this.resolveBackend(task) !== 'headless_mcp') continue;

      const proc = this.registry.get(task.id);
      if (proc) {
        // Launched & process alive. Fall back to assigned_at before the first output
        // chunk so a just-launched agent gets the full ceiling, not an instant reap.
        const genuineAt = proc.last_output_at ?? Date.parse(proc.started_at);
        const withinCeiling = Number.isFinite(genuineAt) && now - genuineAt <= this.orchestratorWedgedCeilingMs;
        if (withinCeiling && isStale(task)) this.engine.agentHeartbeat(task.id, undefined, { silent: true });
        continue;
      }
      if (this.launched.has(task.id)) continue; // launched but process gone → reaper/reconcile owns it
      if (isStale(task)) this.engine.agentHeartbeat(task.id, undefined, { silent: true }); // queued behind cap
    }
  }

  /**
   * Phase 3.2. Keep exactly one persistent PRIMARY orchestrator alive while the
   * engagement opts in (`config.orchestrator.enabled`) and the headless runtime is
   * available. The orchestrator's autonomous frontier→dispatch→synthesize loop is
   * prompt-driven (the role:'orchestrator' primary bootstrap); this only owns its
   * LIFECYCLE — single-instance, and restart-on-crash with exponential backoff so a
   * broken orchestrator can't hot-loop. Runs at startup, when headless becomes
   * available, and after every watchdog tick.
   */
  private reconcileOrchestrator(): void {
    if (!this.running || !this.engine.isPersistenceWritable()) return;
    if (this.engine.getConfig().orchestrator?.enabled !== true) return; // opt-in
    if (!this.endpoint) return;                                          // needs headless runtime

    // Did the orchestrator we were tracking die? Update backoff before respawning.
    if (this.orchestratorTaskId) {
      const t = this.engine.getTask(this.orchestratorTaskId);
      const alive = !!t && (t.status === 'running' || t.status === 'pending');
      if (alive) return;                                                 // still up — nothing to do
      const ranMs = Date.now() - this.orchestratorSpawnedAt;
      if (ranMs >= this.orchestratorHealthyMs) {
        this.orchestratorFailures = 0;                                   // a healthy run resets backoff
      } else {
        this.orchestratorFailures = Math.min(this.orchestratorFailures + 1, 8);
        const backoff = Math.min(ORCHESTRATOR_BACKOFF_BASE_MS * (2 ** (this.orchestratorFailures - 1)), ORCHESTRATOR_BACKOFF_CAP_MS);
        this.orchestratorNextSpawnAt = Date.now() + backoff;
        this.engine.logActionEvent({
          description: `Orchestrator ${t?.agent_id ?? this.orchestratorTaskId} ended after ${Math.round(ranMs / 1000)}s — restarting in ${Math.round(backoff / 1000)}s (failure #${this.orchestratorFailures})`,
          event_type: 'instrumentation_warning', category: 'agent', result_classification: 'failure',
          linked_agent_task_id: this.orchestratorTaskId, details: { reason: 'orchestrator_restart_backoff', failures: this.orchestratorFailures, backoff_ms: backoff },
        });
      }
      this.orchestratorTaskId = null;
    }

    if (Date.now() < this.orchestratorNextSpawnAt) return;               // backing off after a fast death
    // Adopt an already-running orchestrator (e.g. one still live). Use its real
    // assigned_at as the spawn time, not now — otherwise a long-lived one that
    // dies shortly after adoption is misread as a fast crash and needlessly backed off.
    const existing = this.engine.getAgentTasks().find(t => t.role === 'orchestrator' && (t.status === 'running' || t.status === 'pending'));
    if (existing) {
      this.orchestratorTaskId = existing.id;
      this.orchestratorSpawnedAt = Date.parse(existing.assigned_at) || Date.now();
      return;
    }

    const id = uuidv4();
    const agentId = `orchestrator-${id.slice(0, 8)}`;
    const reg = this.engine.registerAgent({
      id,
      agent_id: agentId,
      assigned_at: new Date().toISOString(),
      status: 'running',
      subgraph_node_ids: [],   // no frontier item → no lease, no dispatch cap
      backend: 'headless_mcp',
      role: 'orchestrator',
      orchestrator: true,      // full tool surface + primary bootstrap
      // Generous heartbeat TTL: a busy orchestrator (dispatching + synthesizing)
      // shouldn't be reaped for infrequent beats; if it truly hangs, the watchdog
      // still reaps it here and reconcileOrchestrator restarts it.
      heartbeat_ttl_seconds: 600,
    });
    if (reg.ok) {
      this.orchestratorTaskId = id;
      this.orchestratorSpawnedAt = Date.now();
      this.engine.logActionEvent({
        description: `Persistent orchestrator ${agentId} started`,
        event_type: 'agent_registered', category: 'agent', result_classification: 'neutral',
        linked_agent_task_id: id, details: { reason: 'orchestrator_start' },
      });
      if (this.running) this.drainHeadless();
    }
  }

  /** Running target-facing workers in the registry. Persistent orchestration and
   *  operator planners use their own bounded control-plane lanes. */
  private activeWorkerCount(): number {
    let n = 0;
    for (const entry of this.registry.listActive()) {
      const t = this.engine.getTask(entry.task_id);
      if (
        t
        && t.role !== 'orchestrator'
        && t.orchestrator !== true
        && t.role !== 'planner'
      ) n++;
    }
    return n;
  }

  private activePlannerCount(): number {
    let n = 0;
    for (const entry of this.registry.listActive()) {
      if (this.engine.getTask(entry.task_id)?.role === 'planner') n++;
    }
    return n;
  }

  private drainHeadless(): void {
    if (!this.running || !this.engine.isPersistenceWritable()) return;
    for (const task of this.engine.getAgentTasks()) {
      const queuedPlanner = task.status === 'pending' && task.role === 'planner';
      if (task.status !== 'running' && !queuedPlanner) continue;
      const backend = this.resolveBackend(task);
      if (backend === 'scripted') continue; // handled by ScriptedAgentRunner

      if (backend === 'manual') { this.logDeferral(task, 'manual'); continue; }

      // headless_mcp
      if (this.launched.has(task.id) || this.registry.has(task.id)) continue;
      if (!this.endpoint) { this.logDeferral(task, 'headless_mcp'); continue; }
      // The persistent orchestrator runs OUTSIDE the concurrency pool — it is
      // long-lived and dispatches the sub-agents, so counting it against the cap
      // would starve them (a deadlock at maxConcurrentHeadless=1). Target workers
      // and planners each have bounded lanes; the orchestrator consumes neither.
      const isOrchestrator = task.orchestrator === true || task.role === 'orchestrator';
      const isPlanner = task.role === 'planner';
      if (isPlanner && this.activePlannerCount() >= this.maxConcurrentPlanners) {
        continue;
      }
      if (
        !isOrchestrator
        && !isPlanner
        && this.activeWorkerCount() >= this.maxConcurrentHeadless
      ) {
        // At capacity — a later drain (when a slot frees) will pick it up.
        continue;
      }
      this.launchHeadless(task);
    }
  }

  private launchHeadless(task: AgentTask): void {
    if (!this.running || !this.engine.isPersistenceWritable()) return;
    this.launched.add(task.id);
    let child;
    try {
      child = this.headlessRunner.launch(task, this.endpoint!);
    } catch (error) {
      this.launched.delete(task.id);
      throw error;
    }
    if (!child) {
      // Launch failed; runner already marked the task failed. Allow a future
      // retry only if it somehow returns to 'running'.
      this.launched.delete(task.id);
      return;
    }
    // The persistent orchestrator is long-lived — it is NOT bounded by the per-task
    // wall-clock timeout (that would churn it every 30 min). The heartbeat watchdog
    // still reaps it if it goes silent, and reconcileOrchestrator restarts it.
    if (task.orchestrator === true || task.role === 'orchestrator') return;
    // Arm a wall-clock timeout. If it fires while a process is still tracked,
    // kill it. A late timer (task already exited) finds nothing → harmless.
    const timer = setTimeout(() => {
      this.timeoutTimers.delete(task.id);
      if (!this.ensurePersistenceWritable()) return;
      if (this.registry.has(task.id)) {
        this.engine.logActionEvent({
          description: `Headless sub-agent timed out after ${Math.round(this.headlessTimeoutMs / 1000)}s`,
          event_type: 'instrumentation_warning',
          category: 'system',
          result_classification: 'failure',
          agent_id: task.agent_id,
          linked_agent_task_id: task.id,
          details: { reason: 'headless_timeout' },
        });
        this.cancelHeadless(task.id, 'headless wall-clock timeout');
      }
    }, this.headlessTimeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
    this.timeoutTimers.set(task.id, timer);
  }

  private logDeferral(task: AgentTask, backend: TaskBackend): void {
    if (this.deferredLogged.has(task.id)) return;
    this.deferredLogged.add(task.id);
    this.engine.logActionEvent({
      description: backend === 'headless_mcp'
        ? `Task ${task.id} requests headless_mcp but no HTTP endpoint is available (stdio mode) — left for manual/headless completion`
        : `Task ${task.id} assigned manual backend — awaiting operator completion`,
      event_type: 'instrumentation_warning',
      category: 'system',
      result_classification: 'neutral',
      agent_id: task.agent_id,
      linked_agent_task_id: task.id,
      details: { reason: 'no_automated_backend', backend },
    });
  }
}
