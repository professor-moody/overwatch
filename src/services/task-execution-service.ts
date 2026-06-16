// ============================================================
// Overwatch — Task Execution Service
//
// App-level owner of agent-task execution. Decouples execution from the
// dashboard (it must run whether or not the dashboard is open) and routes each
// registered AgentTask to its execution backend:
//
//   - 'scripted'     : in-process deterministic runner (credential_test, token
//                      validation). Handled by ScriptedAgentRunner.
//   - 'headless_mcp' : a headless `claude -p` reasoning sub-agent. NOT YET
//                      implemented — Phase 1B. In 1A these tasks are left for a
//                      manual/headless backend and a one-time deferral is logged.
//   - 'manual'       : a human operator drives it; no automated execution.
//
// Also owns the AgentWatchdog, which previously was never started in production.
// ============================================================

import type { GraphEngine } from './graph-engine.js';
import type { AgentTask, TaskBackend } from '../types.js';
import { ScriptedAgentRunner } from './scripted-agent-runner.js';
import { AgentWatchdog } from './agent-watchdog.js';

/**
 * Resolve which backend should execute a task. Explicit `task.backend` wins;
 * otherwise defaults to 'scripted' (preserves legacy behavior where the scripted
 * runner picked up every running task). Frontier-type-aware defaults can be
 * layered in here in 1B once headless execution exists.
 */
export function resolveTaskBackend(task: AgentTask): TaskBackend {
  return task.backend ?? 'scripted';
}

export interface TaskExecutionServiceOptions {
  /** Watchdog tick interval (ms). Defaults to the watchdog's own default (30s). */
  watchdogIntervalMs?: number;
}

export class TaskExecutionService {
  private engine: GraphEngine;
  private scripted: ScriptedAgentRunner;
  private watchdog: AgentWatchdog;
  private running = false;
  /** Tasks for which we've already logged a "no automated backend" deferral. */
  private deferredLogged = new Set<string>();

  constructor(engine: GraphEngine, options: TaskExecutionServiceOptions = {}) {
    this.engine = engine;
    this.scripted = new ScriptedAgentRunner(engine);
    this.watchdog = new AgentWatchdog(engine, { intervalMs: options.watchdogIntervalMs });
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    // The scripted runner self-subscribes to engine.onUpdate and only picks up
    // tasks whose resolved backend is 'scripted' (see ScriptedAgentRunner).
    this.scripted.start();
    this.watchdog.start();
    // Surface non-scripted tasks that have no runtime yet (1A), so they don't
    // look silently stuck. They are intentionally left 'running' for a
    // manual/headless backend to complete.
    this.engine.onUpdate(() => {
      if (!this.running) return;
      this.noteDeferredTasks();
    });
    this.noteDeferredTasks();
  }

  stop(): void {
    this.running = false;
    this.scripted.stop();
    this.watchdog.stop();
  }

  /** Exposed for tests so a tick can be forced without waiting on the timer. */
  tickWatchdog(): number {
    return this.watchdog.tick();
  }

  private noteDeferredTasks(): void {
    for (const task of this.engine.getAgentTasks()) {
      if (task.status !== 'running') continue;
      const backend = resolveTaskBackend(task);
      if (backend === 'scripted') continue;
      if (this.deferredLogged.has(task.id)) continue;
      this.deferredLogged.add(task.id);
      this.engine.logActionEvent({
        description: backend === 'headless_mcp'
          ? `Task ${task.id} requests headless_mcp backend — not available until Phase 1B; left for manual/headless completion`
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
}
