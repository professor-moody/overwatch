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
  delta: DashboardGraphDeltaData['delta'];
}

export interface DashboardGraphDeltaData {
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

export interface IndexedCollectionMove {
  id: string;
  index: number;
}

export interface IndexedCollectionPatch<T> {
  upsert: T[];
  remove: string[];
  moves: IndexedCollectionMove[];
  total: number;
  replace?: T[];
}

export interface DashboardStatePatch<TState = DashboardState> {
  state?: Partial<Omit<TState, 'agents' | 'active_agents' | 'frontier'>>;
  /** Scalar/object keys that existed in the previous state but are absent from
   * the resulting state. JSON drops `undefined`, so removal must be explicit. */
  unset?: string[];
  agents?: IndexedCollectionPatch<TState extends { agents: Array<infer T> } ? T : never>;
  active_agents?: IndexedCollectionPatch<TState extends { active_agents: Array<infer T> } ? T : never>;
  frontier?: IndexedCollectionPatch<TState extends { frontier: Array<infer T> } ? T : never>;
}

const MAX_COLLECTION_MOVES = 2_048;

function collectionIds<T>(values: readonly T[], idOf: (value: T) => string, name: string): string[] {
  const ids = values.map(idOf);
  const seen = new Set<string>();
  for (const id of ids) {
    if (id.length === 0) throw new Error(`${name} contains an empty canonical id.`);
    if (seen.has(id)) throw new Error(`${name} contains duplicate canonical id ${id}.`);
    seen.add(id);
  }
  return ids;
}

/** IDs belonging to a longest increasing subsequence of prior positions can
 * remain in place while every other retained/new ID is expressed as one move.
 * This prevents one end-to-end reorder from becoming a full replacement. */
function retainedOrderIds(nextIds: readonly string[], previousIndex: ReadonlyMap<string, number>): Set<string> {
  const sequence = nextIds
    .map(id => ({ id, position: previousIndex.get(id) }))
    .filter((entry): entry is { id: string; position: number } => entry.position !== undefined);
  if (sequence.length === 0) return new Set();

  const tails: number[] = [];
  const tailSequenceIndices: number[] = [];
  const predecessor = new Array<number>(sequence.length).fill(-1);
  for (let index = 0; index < sequence.length; index++) {
    const position = sequence[index]!.position;
    let low = 0;
    let high = tails.length;
    while (low < high) {
      const middle = (low + high) >>> 1;
      if (tails[middle]! < position) low = middle + 1;
      else high = middle;
    }
    if (low > 0) predecessor[index] = tailSequenceIndices[low - 1]!;
    tails[low] = position;
    tailSequenceIndices[low] = index;
  }

  const retained = new Set<string>();
  let cursor = tailSequenceIndices[tails.length - 1] ?? -1;
  while (cursor >= 0) {
    retained.add(sequence[cursor]!.id);
    cursor = predecessor[cursor]!;
  }
  return retained;
}

function indexedCollectionPatch<T>(
  previous: readonly T[],
  next: readonly T[],
  idOf: (value: T) => string,
): IndexedCollectionPatch<T> | undefined {
  const previousIds = collectionIds(previous, idOf, 'Previous dashboard collection');
  const nextIds = collectionIds(next, idOf, 'Next dashboard collection');
  const previousById = new Map(previous.map(value => [idOf(value), value]));
  const nextById = new Map(next.map(value => [idOf(value), value]));
  const remove = previousIds
    .filter(id => !nextById.has(id));
  const upsert = next.filter(value => {
    const prior = previousById.get(idOf(value));
    return prior === undefined || JSON.stringify(prior) !== JSON.stringify(value);
  });

  const retainedPreviousIds = previousIds.filter(id => nextById.has(id));
  const previousIndex = new Map(retainedPreviousIds.map((id, index) => [id, index]));
  const retained = retainedOrderIds(nextIds, previousIndex);
  const moves = nextIds.flatMap((id, index) => retained.has(id) ? [] : [{ id, index }]);
  if (moves.length > MAX_COLLECTION_MOVES) {
    return { upsert: [], remove: [], moves: [], total: next.length, replace: structuredClone([...next]) };
  }
  if (remove.length === 0 && upsert.length === 0 && moves.length === 0) return undefined;
  return {
    upsert: structuredClone(upsert),
    remove,
    moves,
    total: next.length,
  };
}

/** Contract-v2 state delta. Large task/frontier collections are keyed patches;
 * the remaining bounded state fields are included only when their semantics
 * changed. Full state remains the reconnect baseline and v1 compatibility. */
export function projectDashboardStatePatch<TState extends {
  agents: unknown[];
  active_agents: unknown[];
  frontier: Array<{ id: string }>;
}>(
  previous: TState | undefined,
  next: TState,
): DashboardStatePatch<TState> {
  if (!previous) {
    const { agents, active_agents, frontier, ...state } = next;
    return {
      state: structuredClone(state) as DashboardStatePatch<TState>['state'],
      agents: { upsert: [], remove: [], moves: [], total: agents.length, replace: structuredClone(agents) } as DashboardStatePatch<TState>['agents'],
      active_agents: { upsert: [], remove: [], moves: [], total: active_agents.length, replace: structuredClone(active_agents) } as DashboardStatePatch<TState>['active_agents'],
      frontier: { upsert: [], remove: [], moves: [], total: frontier.length, replace: structuredClone(frontier) } as unknown as DashboardStatePatch<TState>['frontier'],
    };
  }
  const state: Record<string, unknown> = {};
  const unset: string[] = [];
  const nextRecord = next as Record<string, unknown>;
  const previousRecord = previous as Record<string, unknown>;
  const keys = new Set([...Object.keys(previousRecord), ...Object.keys(nextRecord)]);
  for (const key of keys) {
    if (key === 'agents' || key === 'active_agents' || key === 'frontier') continue;
    const value = nextRecord[key];
    if (!Object.prototype.hasOwnProperty.call(nextRecord, key) || value === undefined) {
      if (Object.prototype.hasOwnProperty.call(previousRecord, key) && previousRecord[key] !== undefined) {
        unset.push(key);
      }
      continue;
    }
    if (JSON.stringify(previousRecord[key]) !== JSON.stringify(value)) {
      state[key] = structuredClone(value);
    }
  }
  const agents = indexedCollectionPatch(
    previous.agents,
    next.agents,
    value => {
      const record = value as { task_id?: string; id?: string };
      return record.task_id ?? record.id ?? '';
    },
  );
  const activeAgents = indexedCollectionPatch(
    previous.active_agents,
    next.active_agents,
    value => {
      const record = value as { task_id?: string; id?: string; agent_id?: string };
      return record.task_id ?? record.id ?? record.agent_id ?? '';
    },
  );
  const frontier = indexedCollectionPatch(previous.frontier, next.frontier, value => value.id);
  return {
    ...(Object.keys(state).length > 0
      ? { state: state as DashboardStatePatch<TState>['state'] }
      : {}),
    ...(unset.length > 0 ? { unset } : {}),
    ...(agents ? { agents: agents as DashboardStatePatch<TState>['agents'] } : {}),
    ...(activeAgents
      ? { active_agents: activeAgents as DashboardStatePatch<TState>['active_agents'] }
      : {}),
    ...(frontier ? { frontier: frontier as DashboardStatePatch<TState>['frontier'] } : {}),
  };
}

export function projectGraphDelta<TState>(
  state: TState,
  graph: ExportedGraphSelection,
  detail: GraphUpdateDetail,
  historyCount: number,
): DashboardGraphDelta<TState> {
  return {
    state: structuredClone(state),
    ...projectGraphDeltaData(graph, detail, historyCount),
  };
}

export function projectGraphDeltaData(
  graph: ExportedGraphSelection,
  detail: GraphUpdateDetail,
  historyCount: number,
): DashboardGraphDeltaData {
  const removedNodes = [...new Set([
    ...(detail.removed_nodes || []),
    ...graph.hidden_node_ids,
  ])];
  const removedEdges = [...new Set([
    ...(detail.removed_edges || []),
    ...graph.hidden_edge_ids,
  ])];
  return {
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
