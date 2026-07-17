import type {
  AgentTask,
  Campaign,
  CampaignProgress,
  CampaignStatus,
  EngagementState,
  ExportedGraph,
  ExportedGraphSelection,
} from '../types.js';
import {
  normalizeLegacyAgentDispatchDescription,
  type AgentDto,
} from '../contracts/dashboard-v1.js';
import type { ActivityLogEntry, GraphUpdateDetail } from './engine-context.js';
import type { PersistedPlaybookRunV1 } from './persisted-state.js';
import type { DefensiveSignal, OpsecContext } from './opsec-tracker.js';
import { projectAgentDtos } from './dashboard-agent-projector.js';
import type { RuntimeBuildInfo } from './runtime-build-info.js';

export interface CampaignOpsecBudget {
  global_noise_spent: number;
  noise_budget_remaining: number;
  max_noise: number;
  recommended_approach: OpsecContext['recommended_approach'];
  defensive_signals: DefensiveSignal[];
  time_window_remaining_hours?: number;
  warning?: string;
}

export type DashboardCampaign = Campaign & {
  agent_count: number;
  running_agents: number;
  agents_total: number;
  agents_active: number;
  completion_pct: number;
  findings_count: number;
  child_count?: number;
  opsec: CampaignOpsecBudget;
};

export interface CampaignProjectionInput {
  campaigns: Campaign[];
  selected?: Campaign[];
  agents: AgentTask[];
  parent_progress: ReadonlyMap<string, CampaignProgress | null>;
  parent_status: ReadonlyMap<string, CampaignStatus | null>;
  campaign_noise: ReadonlyMap<string, number>;
  opsec: Pick<OpsecContext, 'noise_budget_remaining' | 'recommended_approach' | 'time_window_remaining_hours'>;
  max_noise: number;
}

/** Pure campaign projection. Engine reads and derived parent calculations are
 * deliberately completed by the caller before this compatibility DTO is built. */
export function projectCampaignDtos(input: CampaignProjectionInput): DashboardCampaign[] {
  const selected = input.selected ?? input.campaigns;
  return selected.map(campaign => {
    const children = input.campaigns.filter(candidate => candidate.parent_id === campaign.id);
    const aggregateProgress = input.parent_progress.get(campaign.id) ?? null;
    const derivedStatus = input.parent_status.get(campaign.id) ?? null;
    const projectedFindings = [...new Set([
      ...(campaign.findings ?? []),
      ...children.flatMap(child => child.findings ?? []),
    ])];
    const campaignIds = new Set([campaign.id, ...children.map(child => child.id)]);
    const agents = input.agents.filter(agent => agent.campaign_id && campaignIds.has(agent.campaign_id));
    const progress = aggregateProgress ?? campaign.progress;
    const completed = progress?.completed ?? 0;
    const total = progress?.total ?? campaign.items.length;
    const runningAgents = agents.filter(agent => agent.status === 'running').length;

    return {
      ...campaign,
      status: derivedStatus ?? campaign.status,
      progress,
      findings: projectedFindings,
      agent_count: agents.length,
      running_agents: runningAgents,
      agents_total: agents.length,
      agents_active: runningAgents,
      completion_pct: total > 0 ? Math.round((completed / total) * 100) : 0,
      findings_count: projectedFindings.length,
      child_count: children.length || undefined,
      opsec: {
        global_noise_spent: [...campaignIds]
          .reduce((totalNoise, id) => totalNoise + (input.campaign_noise.get(id) ?? 0), 0),
        noise_budget_remaining: input.opsec.noise_budget_remaining,
        max_noise: input.max_noise,
        recommended_approach: input.opsec.recommended_approach,
        defensive_signals: [],
        time_window_remaining_hours: input.opsec.time_window_remaining_hours,
      },
    };
  });
}

export type DashboardState<TSession = unknown, TPendingAction = unknown> =
  Omit<EngagementState, 'agents'> & {
    agents: AgentDto[];
    sessions: TSession[];
    pending_actions: TPendingAction[];
    campaigns: DashboardCampaign[];
    playbook_runs: PersistedPlaybookRunV1[];
  };

export function projectDashboardState<TSession, TPendingAction>(input: {
  state: EngagementState;
  sessions: TSession[];
  pending_actions: TPendingAction[];
  campaigns: DashboardCampaign[];
  history: ActivityLogEntry[];
  playbook_runs?: PersistedPlaybookRunV1[];
}): DashboardState<TSession, TPendingAction> {
  return {
    ...input.state,
    recent_activity: input.state.recent_activity.map(entry => ({
      ...entry,
      description: normalizeLegacyAgentDispatchDescription({
        event_type: entry.event_type,
        description: entry.description,
        details: (entry as ActivityLogEntry).details,
      }),
    })),
    agents: projectAgentDtos(input.state.agents, input.history, input.campaigns),
    sessions: structuredClone(input.sessions),
    pending_actions: structuredClone(input.pending_actions),
    campaigns: structuredClone(input.campaigns),
    playbook_runs: structuredClone(input.playbook_runs ?? []),
  };
}

export interface DashboardSnapshot<TState = DashboardState> {
  state: TState;
  graph: ExportedGraph;
  history_count: number;
  runtime_build: RuntimeBuildInfo;
}

export function projectDashboardSnapshot<TState>(
  state: TState,
  graph: ExportedGraph,
  historyCount: number,
  runtimeBuild: RuntimeBuildInfo,
): DashboardSnapshot<TState> {
  return {
    state: structuredClone(state),
    graph: structuredClone(graph),
    history_count: historyCount,
    runtime_build: structuredClone(runtimeBuild),
  };
}

export interface DashboardGraphDelta<TState = DashboardState> {
  state: TState;
  history_count: number;
  detail: GraphUpdateDetail;
  delta: {
    nodes: ExportedGraph['nodes'];
    edges: ExportedGraph['edges'];
    removed_nodes: string[];
    removed_edges: string[];
    cold_nodes?: NonNullable<ExportedGraph['cold_nodes']>;
  };
}

export function projectGraphDelta<TState>(
  state: TState,
  graph: ExportedGraphSelection,
  detail: GraphUpdateDetail,
  historyCount: number,
): DashboardGraphDelta<TState> {
  const removedNodes = [...new Set([
    ...(detail.removed_nodes || []),
    ...graph.hidden_node_ids,
  ])];
  const removedEdges = [...new Set([
    ...(detail.removed_edges || []),
    ...graph.hidden_edge_ids,
  ])];
  return {
    state: structuredClone(state),
    history_count: historyCount,
    detail: structuredClone(detail),
    delta: {
      nodes: graph.nodes.map(node => structuredClone(node)),
      edges: graph.edges.map(edge => structuredClone(edge)),
      removed_nodes: removedNodes,
      removed_edges: removedEdges,
      ...(graph.cold_nodes ? { cold_nodes: structuredClone(graph.cold_nodes) } : {}),
    },
  };
}
