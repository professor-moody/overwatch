import { create } from 'zustand';
import { flattenNode, flattenEdge, projectRawGraph } from '../lib/graph-flatten';
import { GraphDeltaIndex } from '../lib/graph-delta-index';
import type {
  EngagementState,
  ExportedGraph,
  ExportedNode,
  ExportedEdge,
  FrontierItem,
  FrontierHiddenSummary,
  Objective,
  AgentInfo,
  Campaign,
  SessionInfo,
  PendingAction,
  ActivityEntry,
  EngagementPhase,
  FullStateData,
  GraphUpdateData,
  OpsecBudget,
  AccessSummary,
  PersistenceRecoveryStatus,
  PlaybookRun,
  StateRefreshData,
} from '../lib/types';

export interface EngagementStore {
  // Connection
  connected: boolean;
  initialized: boolean;
  setConnected: (v: boolean) => void;
  setInitialized: () => void;

  // Engagement state
  engagement: EngagementState['engagement'] | null;
  accessLevel: string;
  historyCount: number;

  // Graph
  graph: ExportedGraph;
  graphSummary: EngagementState['graph_summary'] | null;
  graphVersion: number;
  communityVersion: number;
  lastDelta: { nodes: ExportedNode[]; edges: ExportedEdge[]; removed_nodes: string[]; removed_edges: string[] } | null;
  lastCommunityDelta: ExportedNode[] | null;

  // Frontier
  frontier: FrontierItem[];
  frontierHidden: FrontierHiddenSummary | null;

  // Objectives
  objectives: Objective[];

  // Agents
  agents: AgentInfo[];

  // Campaigns
  campaigns: Campaign[];

  // Sessions
  sessions: SessionInfo[];

  // Pending Actions
  pendingActions: PendingAction[];

  // Durable credential-playbook coordination
  playbookRuns: PlaybookRun[];

  // Activity
  recentActivity: ActivityEntry[];

  // Phases
  phases: EngagementPhase[];

  // Readiness
  readiness: { status: string; issues: string[] } | null;

  // Durable recovery / configuration convergence
  persistenceRecovery: PersistenceRecoveryStatus | null;

  // OPSEC Budget
  opsecBudget: OpsecBudget | null;

  // Access Summary
  accessSummary: AccessSummary;

  // Actions
  loadFullState: (data: FullStateData) => void;
  applyGraphUpdate: (data: GraphUpdateData) => void;
  applyStateRefresh: (data: StateRefreshData) => void;
  updatePendingAction: (type: 'action_pending' | 'action_resolved', data: unknown) => void;
  setAgents: (agents: AgentInfo[]) => void;
  setCampaigns: (campaigns: Campaign[]) => void;
  setSessions: (sessions: SessionInfo[]) => void;
  setRecentActivity: (entries: ActivityEntry[]) => void;
  setOpsecBudget: (budget: OpsecBudget) => void;
  setPersistenceRecovery: (recovery: PersistenceRecoveryStatus | null) => void;
  setPlaybookRuns: (runs: PlaybookRun[]) => void;
}

const graphDeltaIndex = new GraphDeltaIndex();

export const useEngagementStore = create<EngagementStore>((set, get) => ({
  // Connection
  connected: false,
  initialized: false,
  setConnected: (v) => set({ connected: v }),
  setInitialized: () => set({ initialized: true }),

  // Engagement state
  engagement: null,
  accessLevel: 'none',
  historyCount: 0,

  // Graph
  graph: { nodes: [], edges: [], coldInventory: [] },
  graphSummary: null,
  graphVersion: 0,
  communityVersion: 0,
  lastDelta: null,
  lastCommunityDelta: null,

  // Frontier
  frontier: [],
  frontierHidden: null,

  // Objectives
  objectives: [],

  // Agents
  agents: [],

  // Campaigns
  campaigns: [],

  // Sessions
  sessions: [],

  // Pending Actions
  pendingActions: [],

  playbookRuns: [],

  // Activity
  recentActivity: [],

  // Phases
  phases: [],

  // Readiness
  readiness: null,

  persistenceRecovery: null,

  // OPSEC Budget
  opsecBudget: null,

  // Access Summary
  accessSummary: { compromised_hosts: [], valid_credentials: [], current_access_level: 'none' },

  // --- Actions ---

  loadFullState: (data: FullStateData) => {
    const s = data.state;
    // Backend exports `{ id, properties: {...} }`; the panel code reads
    // flat fields. Normalize once on load so every consumer sees the
    // same shape (fixes IdentityPanel + AttackPathsPanel rendering
    // empty against real engagements).
    const flatGraph = projectRawGraph(data.graph);
    graphDeltaIndex.reset(flatGraph);
    set({
      // The backend sends `config` + `access_summary`, NOT top-level `engagement`/
      // `access_level`. Derive the toolbar/layout view-model from the real fields —
      // reading the phantom fields left the toolbar blank, access at 'none', and the
      // graph-layout store keyed on 'default' (positions bleeding across engagements).
      engagement: s.config ? { id: s.config.id, name: s.config.name, profile: s.config.profile, created_at: s.config.created_at } : null,
      accessLevel: s.access_summary?.current_access_level || 'none',
      historyCount: data.history_count ?? 0,
      graph: flatGraph,
      graphSummary: s.graph_summary || null,
      graphVersion: get().graphVersion + 1,
      lastDelta: null,
      lastCommunityDelta: null,
      frontier: s.frontier || [],
      frontierHidden: s.frontier_hidden || null,
      objectives: s.objectives || [],
      agents: s.agents || [],
      campaigns: s.campaigns || [],
      sessions: s.sessions || [],
      pendingActions: s.pending_actions || [],
      playbookRuns: (s.playbook_runs || []).filter((run): run is PlaybookRun => run.schema_version === 1),
      phases: s.phases || [],
      initialized: true,
      readiness: s.lab_readiness ? { status: s.lab_readiness.status, issues: s.lab_readiness.top_issues } : null,
      persistenceRecovery: s.persistence_recovery ?? null,
      accessSummary: s.access_summary || get().accessSummary,
      recentActivity: (s as any).recent_activity || get().recentActivity,
    });
  },

  applyGraphUpdate: (data: GraphUpdateData) => {
    const s = data.state;
    const prev = get().graph;
    const graph = graphDeltaIndex.apply(prev, data);

    set({
      engagement: s.config ? { id: s.config.id, name: s.config.name, profile: s.config.profile, created_at: s.config.created_at } : get().engagement,
      accessLevel: s.access_summary?.current_access_level || get().accessLevel,
      historyCount: data.history_count ?? get().historyCount,
      graph,
      graphSummary: s.graph_summary || get().graphSummary,
      graphVersion: get().graphVersion + 1,
      lastDelta: {
        nodes: data.delta.nodes.map(flattenNode),
        edges: data.delta.edges.map(flattenEdge),
        removed_nodes: data.delta.removed_nodes,
        removed_edges: data.delta.removed_edges,
      },
      frontier: s.frontier || get().frontier,
      frontierHidden: s.frontier_hidden ?? get().frontierHidden,
      objectives: s.objectives || get().objectives,
      agents: s.agents || get().agents,
      campaigns: s.campaigns || get().campaigns,
      sessions: s.sessions || get().sessions,
      pendingActions: s.pending_actions || get().pendingActions,
      playbookRuns: s.playbook_runs
        ? s.playbook_runs.filter((run): run is PlaybookRun => run.schema_version === 1)
        : get().playbookRuns,
      phases: s.phases || get().phases,
      readiness: s.lab_readiness ? { status: s.lab_readiness.status, issues: s.lab_readiness.top_issues } : get().readiness,
      persistenceRecovery: s.persistence_recovery ?? get().persistenceRecovery,
      accessSummary: s.access_summary || get().accessSummary,
      recentActivity: (s as any).recent_activity || get().recentActivity,
    });
  },

  applyStateRefresh: ({ state: s, history_count, community_ids }) => {
    const graph = get().graph;
    const communityDelta = community_ids
      ? graphDeltaIndex.applyCommunityIds(graph, community_ids)
      : [];
    set({
      engagement: s.config ? { id: s.config.id, name: s.config.name, profile: s.config.profile, created_at: s.config.created_at } : get().engagement,
      accessLevel: s.access_summary?.current_access_level || get().accessLevel,
      historyCount: history_count ?? get().historyCount,
      ...(communityDelta.length > 0 ? {
        graph,
        communityVersion: get().communityVersion + 1,
        lastCommunityDelta: communityDelta,
      } : {}),
      graphSummary: s.graph_summary || get().graphSummary,
      frontier: s.frontier || get().frontier,
      frontierHidden: s.frontier_hidden ?? get().frontierHidden,
      objectives: s.objectives || get().objectives,
      agents: s.agents || get().agents,
      campaigns: s.campaigns || get().campaigns,
      sessions: s.sessions || get().sessions,
      pendingActions: s.pending_actions || get().pendingActions,
      playbookRuns: s.playbook_runs
        ? s.playbook_runs.filter((run): run is PlaybookRun => run.schema_version === 1)
        : get().playbookRuns,
      phases: s.phases || get().phases,
      readiness: s.lab_readiness ? { status: s.lab_readiness.status, issues: s.lab_readiness.top_issues } : get().readiness,
      persistenceRecovery: s.persistence_recovery ?? get().persistenceRecovery,
      accessSummary: s.access_summary || get().accessSummary,
      recentActivity: (s as any).recent_activity || get().recentActivity,
    });
  },

  updatePendingAction: (type, data) => {
    if (type === 'action_pending') {
      const action = data as PendingAction;
      set((s) => ({
        pendingActions: [...s.pendingActions.filter((a) => a.action_id !== action.action_id), action],
      }));
    } else if (type === 'action_resolved') {
      const resolved = data as { action_id: string };
      set((s) => ({
        pendingActions: s.pendingActions.filter((a) => a.action_id !== resolved.action_id),
      }));
    }
  },

  setAgents: (agents) => set({ agents }),
  setCampaigns: (campaigns) => set({ campaigns }),
  setSessions: (sessions) => set({ sessions }),
  setRecentActivity: (entries) => set({ recentActivity: entries }),
  setOpsecBudget: (budget) => set({ opsecBudget: budget }),
  setPersistenceRecovery: (persistenceRecovery) => set({ persistenceRecovery }),
  setPlaybookRuns: (playbookRuns) => set({ playbookRuns }),
}));
