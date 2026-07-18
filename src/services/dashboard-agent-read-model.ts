import type { AgentDto, AgentListResponse } from '../contracts/dashboard-v1.js';
import { AgentListResponseSchema } from '../contracts/dashboard-v1.js';
import type { AgentTask, Campaign, GraphQueryResult } from '../types.js';
import type { ActivityLogEntry } from './engine-context.js';
import {
  buildAgentConsoleEvents,
  buildOperatorConsoleEvents,
  type AgentConsoleEvent,
} from './agent-console.js';
import { agentLabelOf, taskIdOf } from './agent-identity.js';
import { projectAgentDtos } from './dashboard-agent-projector.js';

export interface DashboardAgentContextRead {
  task: AgentDto;
  subgraph: GraphQueryResult;
}

export interface DashboardAgentHistoryRead {
  entries: ActivityLogEntry[];
  total: number;
}

export interface DashboardAgentConsoleRead {
  events: AgentConsoleEvent[];
  total: number;
}

export interface DashboardAgentConsoleQuery {
  limit?: number;
  after?: string;
}

export interface DashboardAgentReadModelOptions {
  now?: () => number;
}

/** Exact engine authority required to build dashboard agent read models. */
export interface DashboardAgentReadPort {
  getAllAgents(): AgentTask[];
  getAgentTasks(): AgentTask[];
  getTask(taskId: string): AgentTask | null;
  getFullHistory(): ActivityLogEntry[];
  listCampaigns(): Campaign[];
  getSubgraphForAgent(
    nodeIds: string[],
    options?: { hops?: number; includeCredentials?: boolean; includeServices?: boolean },
  ): GraphQueryResult;
}

/**
 * Transport-free read model for the dashboard's agent surfaces. HTTP handlers
 * retain URL parsing and status-code ownership; this class owns the canonical
 * task, attribution, context, and console/history projections shared by those
 * adapters.
 */
export class DashboardAgentReadModel {
  private readonly now: () => number;

  constructor(
    private readonly engine: DashboardAgentReadPort,
    options: DashboardAgentReadModelOptions = {},
  ) {
    this.now = options.now ?? (() => Date.now());
  }

  listAgents(): AgentListResponse {
    const agents = this.projectAgents(this.engine.getAllAgents());
    return AgentListResponseSchema.parse({ agents, total: agents.length });
  }

  getAgentContext(taskId: string): DashboardAgentContextRead | null {
    const task = this.engine.getTask(taskId);
    if (!task) return null;
    const canonicalTaskId = taskIdOf(task);
    const fleet = this.engine.getAllAgents();
    const projectionTasks = fleet.some(candidate => taskIdOf(candidate) === canonicalTaskId)
      ? fleet
      : [...fleet, task];
    const projectedTask = this.projectAgents(projectionTasks)
      .find(candidate => candidate.task_id === canonicalTaskId)!;
    return {
      task: projectedTask,
      subgraph: this.engine.getSubgraphForAgent(task.subgraph_node_ids, { hops: 2 }),
    };
  }

  getAgentHistory(taskId: string): DashboardAgentHistoryRead | null {
    const task = this.engine.getTask(taskId);
    if (!task) return null;
    const agentLabel = agentLabelOf(task);
    const uniqueLabel = this.engine.getAgentTasks()
      .filter(candidate => agentLabelOf(candidate) === agentLabel).length === 1;
    const entries = attributedEntries(
      this.engine.getFullHistory(),
      taskId,
      agentLabel,
      uniqueLabel,
    );
    return { entries, total: entries.length };
  }

  getAgentConsole(
    taskId: string,
    query: DashboardAgentConsoleQuery = {},
  ): DashboardAgentConsoleRead | null {
    const task = this.engine.getTask(taskId);
    if (!task) return null;
    const agentLabel = agentLabelOf(task);
    const allowLegacyLabel = this.engine.getAgentTasks()
      .filter(candidate => agentLabelOf(candidate) === agentLabel).length === 1;
    const entries = attributedEntries(
      this.engine.getFullHistory(),
      taskId,
      agentLabel,
      allowLegacyLabel,
    );
    const events = buildAgentConsoleEvents(entries, task, {
      limit: query.limit,
      after: query.after,
      allowLegacyLabel,
      preAttributed: true,
    });
    return { events, total: events.length };
  }

  getOperatorConsole(
    query: DashboardAgentConsoleQuery = {},
  ): DashboardAgentConsoleRead {
    const events = buildOperatorConsoleEvents(
      this.engine.getFullHistory(),
      this.engine.getAllAgents(),
      query,
    );
    return { events, total: events.length };
  }

  private projectAgents(tasks: AgentTask[]): AgentDto[] {
    return projectAgentDtos(
      tasks,
      this.engine.getFullHistory(),
      this.engine.listCampaigns(),
      this.now(),
    );
  }
}

function attributedEntries(
  entries: ActivityLogEntry[],
  taskId: string,
  agentLabel: string,
  allowLegacyLabel: boolean,
): ActivityLogEntry[] {
  const taskIdByAction = new Map<string, string>();
  for (const entry of entries) {
    const explicitTaskId = explicitTaskReference(entry)
      ?? (entry.agent_id === taskId ? taskId : undefined);
    if (entry.action_id && explicitTaskId) {
      taskIdByAction.set(entry.action_id, explicitTaskId);
    }
  }
  return entries.filter(entry => {
    const explicitTaskId = explicitTaskReference(entry)
      ?? (entry.agent_id === taskId ? taskId : undefined)
      ?? (entry.action_id ? taskIdByAction.get(entry.action_id) : undefined);
    if (explicitTaskId) return explicitTaskId === taskId;
    if (!allowLegacyLabel) return false;
    return entry.agent_id === agentLabel
      || stringDetail(entry.details?.agent_id) === agentLabel;
  });
}

function explicitTaskReference(entry: ActivityLogEntry): string | undefined {
  return entry.linked_agent_task_id
    ?? stringDetail(entry.details?.task_id)
    ?? stringDetail(entry.details?.linked_agent_task_id);
}

function stringDetail(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
