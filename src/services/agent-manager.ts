// ============================================================
// Overwatch — Agent Manager
// CRUD for agent task lifecycle.
// All state access goes through the shared EngineContext.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { AgentTask } from '../types.js';

export class AgentManager {
  private ctx: EngineContext;

  constructor(ctx: EngineContext) {
    this.ctx = ctx;
  }

  register(task: AgentTask): void {
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
  }

  getTask(taskId: string): AgentTask | null {
    return this.ctx.agents.get(taskId) || null;
  }

  updateStatus(taskId: string, status: AgentTask['status'], summary?: string): boolean {
    const task = this.ctx.agents.get(taskId);
    if (!task) return false;
    task.status = status;
    if (summary) task.result_summary = summary;
    if (status === 'completed' || status === 'failed') {
      task.completed_at = new Date().toISOString();
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
}
