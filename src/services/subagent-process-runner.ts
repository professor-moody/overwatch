// ============================================================
// Overwatch — Sub-agent Process Runner (P4.2 — scaffold)
//
// Spawns a child Node process to host one sub-agent task in isolation,
// communicating over JSON-over-stdio per `subagent-ipc.ts`. The parent
// (this module) translates IPC messages into engine calls.
//
// Activation: only when `engagementConfigSchema.subagent_isolation`
// is set to `'process'`. Default `'in_process'` keeps existing behavior.
// Per scoping decision, this is scaffolding — the recon-scoping role is
// the one we prove end-to-end; other roles continue using the in-process
// path until follow-up work.
//
// Design notes:
//   * Uses a configurable child runner so tests can supply a fake/echo
//     handler without spawning a real process. The default is to spawn
//     `node <child_module>` via child_process.spawn.
//   * Parent owns engine state mutations. Child requests context;
//     parent fulfills via `engine.getAgentContext`-equivalent helpers.
//   * Findings, thoughts, heartbeats, and final result are forwarded
//     to the engine the same way the in-process path would call them.
// ============================================================

import { spawn, type ChildProcess } from 'child_process';
import { z } from 'zod';
import type { GraphEngine } from './graph-engine.js';
import { ApplicationCommandService } from './application-command-service.js';
import { AgentLifecycleCommandService } from './agent-lifecycle-command-service.js';
import type {
  SubAgentMessage,
  SubAgentAssign,
} from './subagent-ipc.js';
import { encodeMessage, decodeMessages } from './subagent-ipc.js';
import type { Finding, AgentTask } from '../types.js';

// ---- Public types ----

export interface SubAgentSpawnOptions {
  /** AgentTask to drive — caller has already registered it with the engine. */
  task: AgentTask;
  /** Path to the child's entry-point module. Tests stub via `runner`. */
  childModulePath?: string;
  /** Test/override: bypass spawn() with an in-process handler. */
  runner?: SubAgentRunner;
  /** Optional logger for debugging the IPC channel. */
  log?: (msg: string) => void;
  /** F2: hard timeout (seconds) past which we kill the child and mark
   *  the task interrupted. Defaults to 30 minutes. */
  timeout_seconds?: number;
}

/**
 * A SubAgentRunner abstracts spawn(). The default implementation uses
 * `node <childModulePath>` over real stdio. Tests can supply a runner
 * that wires the parent and child sides in-memory, exercising the IPC
 * contract without process boundaries.
 */
export interface SubAgentRunner {
  /** Send a message from parent to child. */
  send(msg: SubAgentMessage): void;
  /** Register a callback for child→parent messages. */
  onMessage(cb: (msg: SubAgentMessage) => void): void;
  /** Resolve when the child has fully exited (clean or crash). */
  exited: Promise<{ code: number | null }>;
  /** Force-terminate the child. */
  kill(): void;
}

export interface SubAgentRunResult {
  task_id: string;
  status: 'completed' | 'failed' | 'interrupted';
  result_summary?: string;
  findings_received: number;
  /** F2: set when the runner forced termination via the timeout path. */
  timed_out?: boolean;
}

/** F2: max wall-clock seconds to wait for transcript-or-exit. Past this we
 *  kill the child and mark the task interrupted. Configurable per-spawn via
 *  SubAgentSpawnOptions.timeout_seconds (defaults to 30 minutes). */
const DEFAULT_SUBAGENT_TIMEOUT_SECONDS = 30 * 60;

// ---- Public API ----

/**
 * Run one sub-agent task in process-isolated mode (or via a test runner).
 * Returns a promise that resolves when the child sends `submit_transcript`,
 * the child exits, OR the timeout elapses (F2: previously the timeout
 * branch was documented but never wired — a wedged child blocked forever).
 *
 * On timeout or early exit without transcript, we always update the
 * engine task status to `interrupted` so the graph doesn't leave the
 * task as `running` and the frontier lease gets released (F1).
 */
export async function runSubAgent(
  engine: GraphEngine,
  options: SubAgentSpawnOptions,
): Promise<SubAgentRunResult> {
  const { task, runner, log } = options;
  const channel: SubAgentRunner = runner ?? defaultSpawnRunner(options);
  const timeoutMs =
    Math.max(1, options.timeout_seconds ?? DEFAULT_SUBAGENT_TIMEOUT_SECONDS) * 1000;

  let findingsReceived = 0;
  let finalStatus: SubAgentRunResult['status'] = 'interrupted';
  let resultSummary: string | undefined;
  let messageSequence = 0;
  const commands = new ApplicationCommandService(engine);
  const lifecycle = new AgentLifecycleCommandService(engine, commands);
  const metadata = (kind: string) => {
    const sequence = messageSequence++;
    return {
      transport: 'system' as const,
      actor_task_id: task.task_id ?? task.id,
      command_id: `ipc-${task.id}-${kind}-${sequence}`,
      idempotency_key: `ipc:${task.id}:${kind}:${sequence}`,
    };
  };

  // Resolve when child sends submit_transcript OR exits.
  let resolveDone: (() => void) | undefined;
  const done = new Promise<void>((resolve) => { resolveDone = resolve; });

  channel.onMessage((msg) => {
    log?.(`[parent] received ${msg.kind} for task ${('task_id' in msg) ? msg.task_id : '?'}`);
    switch (msg.kind) {
      case 'register':
        // Acknowledged implicitly — the task is already registered with
        // the engine before spawn. The child's register tells us it's
        // ready to receive its assignment.
        return;

      case 'get_context': {
        // Parent fulfills the context request.
        const seedIds = task.subgraph_node_ids.length > 0
          ? task.subgraph_node_ids
          : task.frontier_item_id
            ? engine.computeSubgraphNodeIds(task.frontier_item_id, msg.hops ?? 2)
            : [];
        const context = {
          subgraph_node_ids: seedIds,
          // For now ship just the seed IDs; richer context (subgraph nodes,
          // edges, frontier items) is a follow-up. The recon-scoping handler
          // doesn't need much beyond seeds.
        };
        channel.send({
          kind: 'context_response',
          task_id: task.id,
          request_id: msg.request_id,
          context,
        });
        return;
      }

      case 'report_finding': {
        const commandMetadata = metadata('finding');
        const findingSchema = z.custom<Finding>(value =>
          Boolean(value && typeof value === 'object' && 'id' in value));
        try {
          const existing = commands.lookup<Finding, unknown>(
            'agent.ipc.report_finding',
            msg.finding,
            commandMetadata,
          );
          if (!existing) {
            engine.ingestFinding(msg.finding, {
              complete: result => {
                commands.recordSuccessInDomainTransaction({
                  command_kind: 'agent.ipc.report_finding',
                  input: msg.finding,
                  schema: findingSchema,
                  metadata: commandMetadata,
                  result,
                  record: finding => ({
                    entity_refs: {
                      finding_id: finding.id,
                      task_id: task.task_id ?? task.id,
                    },
                  }),
                });
              },
            });
          }
          // Durability: a sub-agent can be killed at any moment (reap / timeout /
          // crash). Flush the finding to disk synchronously so it survives even a
          // crash in the next instant, rather than riding the ≤500ms debounce.
          engine.flushNow();
          findingsReceived++;
        } catch (err) {
          try {
            commands.recordFailureSync({
              command_kind: 'agent.ipc.report_finding',
              input: msg.finding,
              schema: findingSchema,
              metadata: commandMetadata,
              error: err,
            });
          } catch { /* preserve the original ingestion failure */ }
          log?.(`[parent] ingestFinding error: ${err instanceof Error ? err.message : err}`);
        }
        return;
      }

      case 'log_thought': {
        commands.executeSync({
          command_kind: 'agent.ipc.log_thought',
          input: msg,
          schema: z.unknown(),
          metadata: metadata('thought'),
          state_keys: ['activity', 'frontier'],
          execute: () => engine.logActionEvent({
            description: msg.thought,
            event_type: 'thought',
            category: 'reasoning',
            agent_id: task.agent_id,
            linked_agent_task_id: task.id,
            frontier_item_id: task.frontier_item_id,
            result_classification: 'neutral',
            details: {
              kind: msg.thought_kind,
              considered_alternatives: msg.considered_alternatives,
              related_action_ids: msg.related_action_ids,
              confidence: msg.confidence,
            },
          }),
        });
        return;
      }

      case 'heartbeat': {
        lifecycle.heartbeat(
          { task_id: task.task_id ?? task.id },
          metadata('heartbeat'),
        );
        return;
      }

      case 'submit_transcript': {
        finalStatus = msg.status;
        resultSummary = msg.result_summary;
        lifecycle.updateStatus({
          task_id: task.task_id ?? task.id,
          status: msg.status,
          summary: msg.result_summary,
        }, metadata('status'));
        // Tell the child we accepted the transcript and to shut down.
        channel.send({ kind: 'shutdown', task_id: task.id, reason: 'transcript accepted' });
        resolveDone?.();
        return;
      }

      // Parent doesn't expect to receive these from the child:
      case 'assign':
      case 'shutdown':
      case 'context_response':
        return;
    }
  });

  // Send the assignment.
  const assign: SubAgentAssign = {
    kind: 'assign',
    task_id: task.id,
    agent_id: task.agent_id,
    engagement_nonce: engine.getConfig().engagement_nonce,
    frontier_item_id: task.frontier_item_id,
    subgraph_node_ids: task.subgraph_node_ids,
    skill: task.skill,
  };
  channel.send(assign);

  // F2: race transcript-submission against child exit AND a hard timeout.
  // Without the timeout branch a wedged child (alive but silent) used to
  // block the parent `await` indefinitely.
  let timedOut = false;
  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<void>((resolve) => {
    timeoutHandle = setTimeout(() => {
      timedOut = true;
      log?.(`[parent] task ${task.id} timed out after ${timeoutMs / 1000}s — killing child`);
      try { channel.kill(); } catch { /* best effort */ }
      resolve();
    }, timeoutMs);
    // Don't keep the event loop alive solely for this timer.
    if (typeof (timeoutHandle as { unref?: () => void }).unref === 'function') {
      (timeoutHandle as { unref?: () => void }).unref!();
    }
  });

  await Promise.race([done, channel.exited.then(() => {}), timeoutPromise]);
  if (timeoutHandle) clearTimeout(timeoutHandle);

  // F1 + F2: if we exit this race without a transcript-driven status
  // update, the task is still `running` in the engine. Update it now so
  // the frontier lease is released and the dashboard reflects reality.
  if (finalStatus === 'interrupted') {
    const reason = timedOut
      ? `subagent_timeout: no transcript within ${timeoutMs / 1000}s`
      : 'subagent_exited_without_transcript';
    resultSummary = resultSummary ?? reason;
    try {
      lifecycle.updateStatus({
        task_id: task.task_id ?? task.id,
        status: 'interrupted',
        summary: resultSummary,
      }, metadata('interrupted'));
    } catch (err) {
      log?.(`[parent] updateAgentStatus error: ${err instanceof Error ? err.message : err}`);
    }
  }

  return {
    task_id: task.id,
    status: finalStatus,
    result_summary: resultSummary,
    findings_received: findingsReceived,
    timed_out: timedOut || undefined,
  };
}

// ---- Default runner (real child process) ----

function defaultSpawnRunner(opts: SubAgentSpawnOptions): SubAgentRunner {
  const childPath = opts.childModulePath;
  if (!childPath) {
    throw new Error('subagent-process-runner: childModulePath required when no test runner provided');
  }
  const child: ChildProcess = spawn(process.execPath, [childPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let buffer = '';
  const cbs: Array<(msg: SubAgentMessage) => void> = [];

  child.stdout?.setEncoding('utf8');
  child.stdout?.on('data', (chunk: string) => {
    buffer += chunk;
    const { messages, remainder } = decodeMessages(buffer);
    buffer = remainder;
    for (const msg of messages) {
      for (const cb of cbs) cb(msg);
    }
  });
  child.stderr?.setEncoding('utf8');
  child.stderr?.on('data', (chunk: string) => {
    opts.log?.(`[child stderr] ${chunk}`);
  });

  const exited = new Promise<{ code: number | null }>((resolve) => {
    child.on('exit', (code) => resolve({ code }));
  });

  return {
    send(msg) {
      child.stdin?.write(encodeMessage(msg));
    },
    onMessage(cb) {
      cbs.push(cb);
    },
    exited,
    kill() {
      try { child.kill(); } catch { /* best effort */ }
    },
  };
}
