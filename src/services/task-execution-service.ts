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
import { HeadlessProcessRegistry } from './headless-process-registry.js';
import { HeadlessMcpRunner, type HeadlessEndpoint, type HeadlessMcpRunnerOptions } from './headless-mcp-runner.js';

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
const DEFAULT_HEADLESS_TIMEOUT_MS = 30 * 60_000; // 30 minutes

export interface TaskExecutionServiceOptions {
  /** Watchdog tick interval (ms). Defaults to the watchdog's own default (30s). */
  watchdogIntervalMs?: number;
  /** Max concurrently-running headless sub-agents. Default 3. */
  maxConcurrentHeadless?: number;
  /** Per-task wall-clock timeout for headless sub-agents (ms). Default 30 min. */
  headlessTimeoutMs?: number;
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

  private maxConcurrentHeadless: number;
  private headlessTimeoutMs: number;

  constructor(engine: GraphEngine, processTracker: ProcessTracker, options: TaskExecutionServiceOptions = {}) {
    this.engine = engine;
    this.scripted = new ScriptedAgentRunner(engine);
    this.watchdog = new AgentWatchdog(engine, {
      intervalMs: options.watchdogIntervalMs,
      // After each reap, kill any headless process whose task is now terminal
      // and abort its blocked approvals (heartbeat-reap doesn't do either).
      afterTick: () => this.reconcileTerminatedTasks(),
    });
    this.registry = new HeadlessProcessRegistry();
    this.headlessRunner = new HeadlessMcpRunner(engine, this.registry, processTracker, options.headless);
    this.maxConcurrentHeadless = options.maxConcurrentHeadless ?? DEFAULT_MAX_HEADLESS;
    this.headlessTimeoutMs = options.headlessTimeoutMs ?? DEFAULT_HEADLESS_TIMEOUT_MS;
  }

  /**
   * Provide the /mcp endpoint headless sub-agents should connect to. Called by
   * startHttpApp once the server is bound. Setting it enables the headless
   * backend and triggers a drain for any waiting headless tasks.
   */
  setHttpEndpoint(endpoint: HeadlessEndpoint): void {
    this.endpoint = endpoint;
    if (this.running) this.drainHeadless();
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
    if (this.running) return;
    this.running = true;
    // The scripted runner only picks up tasks our routing assigns to it.
    this.scripted.setShouldHandle((task) => this.resolveBackend(task) === 'scripted');
    this.scripted.start();
    this.watchdog.start();
    this.engine.onUpdate(() => {
      if (!this.running) return;
      this.drainDirectives();
      this.drainCveResearch();
      this.drainHeadless();
    });
    this.drainCveResearch();
    this.drainHeadless();
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
    if (!this.endpoint) return;
    if (this.engine.getConfig().cve_research?.enabled === false) return;

    // Budget against ALL non-terminal headless work (launched or queued) — count
    // by the RESOLVED backend, NOT the persisted field. Normal dispatched agents
    // (recon/web/cred/…) never set task.backend yet still run headless, so the old
    // `t.backend === 'headless_mcp'` check counted 0 of them and over-registered
    // CVE tasks past the cap. Those extras couldn't launch (registry already full),
    // sat unspawned, got heartbeat-reaped, and — since they were marked attempted —
    // CVE research was silently abandoned for the session. resolveBackend matches
    // exactly what drainHeadless will launch, so the budget is now honest.
    const activeHeadless = this.engine.getAgentTasks().filter(
      t => (t.status === 'running' || t.status === 'pending') && this.resolveBackend(t) === 'headless_mcp',
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
      this.cancelHeadless(task.id, `stop directive (${pending.id})`);
    }
  }

  stop(): void {
    this.running = false;
    this.scripted.stop();
    this.watchdog.stop();
    for (const t of this.timeoutTimers.values()) clearTimeout(t);
    this.timeoutTimers.clear();
    // Best-effort, fire-and-forget (sync callers). Daemon shutdown should use
    // shutdown() to actually AWAIT termination.
    this.registry.killAll();
  }

  /**
   * Async shutdown for the daemon: stops runners and AWAITS headless children
   * exiting (SIGTERM→SIGKILL escalation) so none outlive the process.
   */
  async shutdown(): Promise<void> {
    this.running = false;
    this.scripted.stop();
    this.watchdog.stop();
    for (const t of this.timeoutTimers.values()) clearTimeout(t);
    this.timeoutTimers.clear();
    await this.registry.killAllAndWait();
  }

  /** Exposed for tests so a tick can be forced without waiting on the timer. */
  tickWatchdog(): number {
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
    return this.endpoint !== null;
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
    // Abort any approval gate this agent was blocked on, so it can't auto-fire on
    // timeout and execute a command for an agent we just killed.
    this.engine.abortApprovalsForTask(task_id, reason);
    return killed;
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

  private drainHeadless(): void {
    for (const task of this.engine.getAgentTasks()) {
      if (task.status !== 'running') continue;
      const backend = this.resolveBackend(task);
      if (backend === 'scripted') continue; // handled by ScriptedAgentRunner

      if (backend === 'manual') { this.logDeferral(task, 'manual'); continue; }

      // headless_mcp
      if (this.launched.has(task.id) || this.registry.has(task.id)) continue;
      if (!this.endpoint) { this.logDeferral(task, 'headless_mcp'); continue; }
      if (this.registry.size() >= this.maxConcurrentHeadless) {
        // At capacity — a later drain (when a slot frees) will pick it up.
        continue;
      }
      this.launchHeadless(task);
    }
  }

  private launchHeadless(task: AgentTask): void {
    this.launched.add(task.id);
    const child = this.headlessRunner.launch(task, this.endpoint!);
    if (!child) {
      // Launch failed; runner already marked the task failed. Allow a future
      // retry only if it somehow returns to 'running'.
      this.launched.delete(task.id);
      return;
    }
    // Arm a wall-clock timeout. If it fires while a process is still tracked,
    // kill it. A late timer (task already exited) finds nothing → harmless.
    const timer = setTimeout(() => {
      this.timeoutTimers.delete(task.id);
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
