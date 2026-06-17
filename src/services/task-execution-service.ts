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

  private maxConcurrentHeadless: number;
  private headlessTimeoutMs: number;

  constructor(engine: GraphEngine, processTracker: ProcessTracker, options: TaskExecutionServiceOptions = {}) {
    this.engine = engine;
    this.scripted = new ScriptedAgentRunner(engine);
    this.watchdog = new AgentWatchdog(engine, { intervalMs: options.watchdogIntervalMs });
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
      this.drainHeadless();
    });
    this.drainHeadless();
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
    return killed;
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
