import type { AgentTask } from '../types.js';

export function taskWireIdentity(task: AgentTask): {
  task_id: string;
  agent_label: string;
  id: string;
  agent_id: string;
} {
  const taskId = task.task_id ?? task.id;
  const agentLabel = task.agent_label ?? task.agent_id;
  return {
    task_id: taskId,
    agent_label: agentLabel,
    id: taskId,
    agent_id: agentLabel,
  };
}
