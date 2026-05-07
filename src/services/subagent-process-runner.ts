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
import type { GraphEngine } from './graph-engine.js';
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
}

// ---- Public API ----

/**
 * Run one sub-agent task in process-isolated mode (or via a test runner).
 * Returns a promise that resolves when the child exits or we time out
 * waiting for a `submit_transcript`.
 */
export async function runSubAgent(
  engine: GraphEngine,
  options: SubAgentSpawnOptions,
): Promise<SubAgentRunResult> {
  const { task, runner, log } = options;
  const channel: SubAgentRunner = runner ?? defaultSpawnRunner(options);

  let findingsReceived = 0;
  let finalStatus: SubAgentRunResult['status'] = 'interrupted';
  let resultSummary: string | undefined;

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
        try {
          engine.ingestFinding(msg.finding as Finding);
          findingsReceived++;
        } catch (err) {
          log?.(`[parent] ingestFinding error: ${err instanceof Error ? err.message : err}`);
        }
        return;
      }

      case 'log_thought': {
        engine.logActionEvent({
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
        });
        return;
      }

      case 'heartbeat': {
        engine.agentHeartbeat(task.id);
        return;
      }

      case 'submit_transcript': {
        finalStatus = msg.status;
        resultSummary = msg.result_summary;
        engine.updateAgentStatus(task.id, msg.status, msg.result_summary);
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

  // Race the transcript-submission promise against child exit. Whichever
  // resolves first wins — the child may exit cleanly without sending a
  // transcript (treated as 'interrupted'), and a transcript followed by
  // a clean exit lets `done` fire first.
  await Promise.race([done, channel.exited.then(() => {})]);

  return {
    task_id: task.id,
    status: finalStatus,
    result_summary: resultSummary,
    findings_received: findingsReceived,
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
