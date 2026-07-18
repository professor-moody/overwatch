import type { GraphEngine } from '../services/graph-engine.js';
import type { FrontierLeases } from '../services/frontier-leases.js';
import { computeAgentWorkSignature } from '../services/agent-work.js';
import type { AgentTask } from '../types.js';

const FIXTURE_TIME = '2026-07-17T00:00:00.000Z';

export interface AgentScaleFixture {
  source_task_id: string;
  target_task_id: string;
  target_frontier_item_id?: string;
}

interface AgentScaleContext {
  agents: Map<string, AgentTask>;
  frontierLeases: FrontierLeases;
}

/** Seed historical coordination state directly for scale measurement. This is
 * test/benchmark setup only; production writes remain transaction-only. */
export function seedAgentScaleFixture(
  engine: GraphEngine,
  taskCount: number,
  options: {
    running_leases?: boolean;
    lease_task_status?: 'running' | 'pending';
    successor_count?: number;
  } = {},
): AgentScaleFixture {
  if (!Number.isSafeInteger(taskCount) || taskCount < 1) {
    throw new Error('taskCount must be a positive safe integer');
  }
  const ctx = (engine as unknown as { ctx: AgentScaleContext }).ctx;
  const taskId = (index: number) => `scale-task-${String(index).padStart(6, '0')}`;
  for (let index = 0; index < taskCount; index++) {
    const id = taskId(index);
    const frontierItemId = options.running_leases ? `scale-frontier-${index}` : undefined;
    const task: AgentTask = {
      id,
      task_id: id,
      agent_id: `scale-agent-${index}`,
      agent_label: `scale-agent-${index}`,
      assigned_at: FIXTURE_TIME,
      heartbeat_at: options.running_leases ? FIXTURE_TIME : undefined,
      status: options.running_leases
        ? options.lease_task_status ?? 'running'
        : 'completed',
      subgraph_node_ids: [],
      objective: `Scale objective ${index}`,
      ...(frontierItemId ? { frontier_item_id: frontierItemId } : {}),
    };
    ctx.agents.set(id, task);
    if (frontierItemId) {
      ctx.frontierLeases.applySnapshot(frontierItemId, {
        frontier_item_id: frontierItemId,
        task_id: id,
        agent_id: task.agent_id,
        leased_at: FIXTURE_TIME,
        expires_at: '2026-07-17T01:00:00.000Z',
        ttl_seconds: 3_600,
      });
    }
  }

  const sourceTaskId = taskId(0);
  const successorCount = Math.min(options.successor_count ?? 0, taskCount - 1);
  for (let index = 1; index <= successorCount; index++) {
    const id = taskId(index);
    const task = ctx.agents.get(id)!;
    task.work = {
      version: 1,
      root_task_id: sourceTaskId,
      signature: computeAgentWorkSignature(task),
      relation: {
        kind: 'handoff',
        source_task_id: sourceTaskId,
        created_at: FIXTURE_TIME,
        summary: 'Deterministic scale successor',
      },
    };
  }

  const targetTaskId = taskId(taskCount - 1);
  return {
    source_task_id: sourceTaskId,
    target_task_id: targetTaskId,
    ...(options.running_leases
      ? { target_frontier_item_id: `scale-frontier-${taskCount - 1}` }
      : {}),
  };
}
