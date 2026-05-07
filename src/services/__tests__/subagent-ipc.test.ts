import { describe, it, expect, afterEach } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { encodeMessage, decodeMessages, type SubAgentMessage } from '../subagent-ipc.js';
import { runSubAgent, type SubAgentRunner } from '../subagent-process-runner.js';
import type { EngagementConfig, AgentTask, Finding } from '../../types.js';

const TEST_STATE = './state-test-subagent-ipc.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'subagent-test',
    name: 'subagent IPC test',
    created_at: '2026-01-01T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
    subagent_isolation: 'process',
  };
}

function cleanup(): void {
  for (const f of [TEST_STATE, TEST_STATE + '.journal.jsonl']) {
    try { if (existsSync(f)) unlinkSync(f); } catch {}
  }
}

/**
 * Build an in-memory runner that hosts both ends of the IPC channel.
 * The "child handler" is a function that receives parent→child messages
 * and can emit child→parent messages via `emitToParent`. This lets tests
 * exercise the full contract without spawning real processes.
 */
function makeInMemoryRunner(
  childHandler: (msg: SubAgentMessage, emitToParent: (out: SubAgentMessage) => void) => void,
): SubAgentRunner {
  const parentCallbacks: Array<(msg: SubAgentMessage) => void> = [];
  let exitResolve: ((v: { code: number | null }) => void) | undefined;
  const exited = new Promise<{ code: number | null }>((resolve) => { exitResolve = resolve; });

  const emitToParent = (msg: SubAgentMessage) => {
    // Round-trip through the wire format so we exercise the encoder/decoder
    // exactly as the real spawn runner would.
    const wire = encodeMessage(msg);
    const { messages } = decodeMessages(wire);
    for (const m of messages) {
      for (const cb of parentCallbacks) cb(m);
    }
  };

  return {
    send(msg) {
      // Same wire round-trip for parent→child.
      const wire = encodeMessage(msg);
      const { messages } = decodeMessages(wire);
      for (const m of messages) {
        try {
          childHandler(m, emitToParent);
        } catch (err) {
          // Surface as a fake exit so the test fails clearly.
          exitResolve?.({ code: 1 });
          throw err;
        }
      }
    },
    onMessage(cb) {
      parentCallbacks.push(cb);
    },
    exited,
    kill() {
      exitResolve?.({ code: 137 });
    },
  };
}

function makeTask(): AgentTask {
  return {
    id: 'task-recon-1',
    agent_id: 'sub-recon-1',
    assigned_at: '2026-01-01T00:00:01Z',
    status: 'running',
    frontier_item_id: 'fi-recon-1',
    subgraph_node_ids: ['host-10-10-10-5'],
    skill: 'recon-scoping',
  };
}

describe('Sub-agent IPC + process runner (P4.2)', () => {
  afterEach(() => cleanup());

  it('completes a register → heartbeat → report_finding → submit_transcript round-trip', async () => {
    cleanup();
    const engine = new GraphEngine(makeConfig(), TEST_STATE);
    const task = makeTask();
    engine.registerAgent(task);

    const finding: Finding = {
      id: 'finding-recon-1',
      agent_id: task.agent_id,
      timestamp: '2026-01-01T00:00:02Z',
      nodes: [
        { id: 'host-10-10-10-5', type: 'host', label: '10.10.10.5', ip: '10.10.10.5',
          discovered_at: '2026-01-01T00:00:02Z', confidence: 1 },
        { id: 'svc-10-10-10-5-22', type: 'service', label: 'ssh/22', port: 22,
          discovered_at: '2026-01-01T00:00:02Z', confidence: 1 },
      ],
      edges: [
        { source: 'host-10-10-10-5', target: 'svc-10-10-10-5-22',
          properties: { type: 'RUNS', confidence: 1, discovered_at: '2026-01-01T00:00:02Z' } },
      ],
    };

    // The "recon-scoping" sub-agent: registers, heartbeats, requests
    // context, reports a finding, submits result.
    const runner = makeInMemoryRunner((msg, emit) => {
      if (msg.kind === 'assign') {
        emit({ kind: 'register', task_id: msg.task_id, agent_id: msg.agent_id });
        emit({ kind: 'heartbeat', task_id: msg.task_id });
        emit({ kind: 'get_context', task_id: msg.task_id, request_id: 'r1', hops: 2 });
      } else if (msg.kind === 'context_response') {
        // Verify we got a coherent context payload back.
        expect(msg.context).toHaveProperty('subgraph_node_ids');
        emit({
          kind: 'log_thought',
          task_id: msg.task_id,
          thought: 'Identified an SSH service worth probing.',
          thought_kind: 'observation',
          confidence: 0.8,
        });
        emit({ kind: 'report_finding', task_id: msg.task_id, finding });
        emit({
          kind: 'submit_transcript',
          task_id: msg.task_id,
          status: 'completed',
          result_summary: 'Surveyed host; reported one service.',
        });
      } else if (msg.kind === 'shutdown') {
        // Simulate clean child exit.
        // (No-op in the in-memory runner; the test asserts via SubAgentRunResult.)
      }
    });

    const result = await runSubAgent(engine, { task, runner });

    expect(result.status).toBe('completed');
    expect(result.findings_received).toBe(1);
    expect(result.result_summary).toContain('Surveyed host');
    // Engine state reflects the ingested finding.
    expect(engine.getNode('host-10-10-10-5')).toBeDefined();
    expect(engine.getNode('svc-10-10-10-5-22')).toBeDefined();
    // Heartbeat made it through to the agent task.
    expect(engine.getTask(task.id)?.heartbeat_at).toBeDefined();
    // Task was marked completed.
    expect(engine.getTask(task.id)?.status).toBe('completed');
    // Thought was logged.
    const thoughts = engine.getFullHistory().filter(e => e.event_type === 'thought');
    expect(thoughts.some(t => t.description.includes('SSH service'))).toBe(true);
  });

  it('treats child exit without submit_transcript as interrupted', async () => {
    cleanup();
    const engine = new GraphEngine(makeConfig(), TEST_STATE);
    const task = { ...makeTask(), id: 'task-2', frontier_item_id: 'fi-2' };
    engine.registerAgent(task);

    // Child registers and immediately "exits" (kill the runner).
    let killer: (() => void) | undefined;
    const runner = makeInMemoryRunner((msg, emit) => {
      if (msg.kind === 'assign') {
        emit({ kind: 'register', task_id: msg.task_id, agent_id: msg.agent_id });
        // Schedule a kill on the next tick.
        setTimeout(() => { killer?.(); }, 0);
      }
    });
    killer = runner.kill;

    const result = await runSubAgent(engine, { task, runner });
    expect(result.status).toBe('interrupted');

    // F1: the engine must reflect the interrupted status (was previously
    // left as 'running' because runSubAgent never called updateAgentStatus
    // on the early-exit path). The frontier lease must also be released
    // so a follow-up dispatch on the same item can succeed.
    const persisted = engine.getTask('task-2');
    expect(persisted?.status).toBe('interrupted');
    const t2 = { ...makeTask(), id: 'task-2-followup', agent_id: 'sub-2', frontier_item_id: 'fi-2' };
    const reg = engine.registerAgent(t2);
    expect(reg.ok).toBe(true);
  });

  // F2 — process runner timeout: a wedged child that stays alive without
  // sending a transcript used to block the parent forever. We now kill it
  // after the configured timeout and mark the task interrupted.
  it('kills the child and marks the task interrupted when the timeout elapses (F2)', async () => {
    cleanup();
    const engine = new GraphEngine(makeConfig(), TEST_STATE);
    const task = { ...makeTask(), id: 'task-wedge', frontier_item_id: 'fi-wedge' };
    engine.registerAgent(task);

    // Wedged child: never sends submit_transcript, never exits on its own.
    let killCount = 0;
    const runner: SubAgentRunner = {
      send: () => { /* swallow */ },
      onMessage: () => { /* never emits */ },
      exited: new Promise(() => { /* never resolves on its own */ }),
      kill: () => { killCount++; },
    };

    const result = await runSubAgent(engine, { task, runner, timeout_seconds: 0.05 });
    expect(result.status).toBe('interrupted');
    expect(result.timed_out).toBe(true);
    expect(killCount).toBeGreaterThanOrEqual(1);
    expect(engine.getTask('task-wedge')?.status).toBe('interrupted');
  });

  it('encodeMessage/decodeMessages round-trip is identity', () => {
    const msgs: SubAgentMessage[] = [
      { kind: 'register', task_id: 't1', agent_id: 'a1' },
      { kind: 'heartbeat', task_id: 't1' },
      { kind: 'submit_transcript', task_id: 't1', status: 'completed', result_summary: 'done' },
    ];
    const wire = msgs.map(encodeMessage).join('');
    const { messages, remainder } = decodeMessages(wire);
    expect(remainder).toBe('');
    expect(messages).toEqual(msgs);
  });

  it('decodeMessages drops a malformed line and continues', () => {
    const wire = encodeMessage({ kind: 'heartbeat', task_id: 'a' })
      + 'not-json-at-all\n'
      + encodeMessage({ kind: 'heartbeat', task_id: 'b' });
    const { messages } = decodeMessages(wire);
    expect(messages.map(m => 'task_id' in m ? m.task_id : '')).toEqual(['a', 'b']);
  });

  it('decodeMessages returns trailing partial line as remainder', () => {
    const partial = encodeMessage({ kind: 'heartbeat', task_id: 'a' }) + '{"kind":"hea';
    const { messages, remainder } = decodeMessages(partial);
    expect(messages.length).toBe(1);
    expect(remainder).toBe('{"kind":"hea');
  });
});
