import { create } from 'zustand';
import { flattenNode, flattenEdge, projectRawGraph } from '../lib/graph-flatten';
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
  lastDelta: { nodes: ExportedNode[]; edges: ExportedEdge[]; removed_nodes: string[]; removed_edges: string[] } | null;

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

  // Activity
  recentActivity: ActivityEntry[];

  // Phases
  phases: EngagementPhase[];

  // Readiness
  readiness: { status: string; issues: string[] } | null;

  // OPSEC Budget
  opsecBudget: OpsecBudget | null;

  // Access Summary
  accessSummary: AccessSummary;

  // Actions
  loadFullState: (data: FullStateData) => void;
  applyGraphUpdate: (data: GraphUpdateData) => void;
  updatePendingAction: (type: 'action_pending' | 'action_resolved', data: unknown) => void;
  setAgents: (agents: AgentInfo[]) => void;
  setCampaigns: (campaigns: Campaign[]) => void;
  setSessions: (sessions: SessionInfo[]) => void;
  setRecentActivity: (entries: ActivityEntry[]) => void;
  setOpsecBudget: (budget: OpsecBudget) => void;
}

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
  lastDelta: null,

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

  // Activity
  recentActivity: [],

  // Phases
  phases: [],

  // Readiness
  readiness: null,

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
      frontier: s.frontier || [],
      frontierHidden: s.frontier_hidden || null,
      objectives: s.objectives || [],
      agents: s.agents || [],
      campaigns: s.campaigns || [],
      sessions: s.sessions || [],
      pendingActions: s.pending_actions || [],
      phases: s.phases || [],
      initialized: true,
      readiness: s.lab_readiness ? { status: s.lab_readiness.status, issues: s.lab_readiness.top_issues } : null,
      accessSummary: s.access_summary || get().accessSummary,
      recentActivity: (s as any).recent_activity || get().recentActivity,
    });
  },

  applyGraphUpdate: (data: GraphUpdateData) => {
    const s = data.state;
    const prev = get().graph;

    // Merge delta into existing graph. Flatten incoming nodes/edges
    // so panel code can read flat fields consistently.
    const nodeMap = new Map<string, ExportedNode>();
    for (const n of prev.nodes) nodeMap.set(n.id, n);
    // Remove deleted nodes
    for (const id of data.delta.removed_nodes || []) nodeMap.delete(id);
    // Add/update nodes from delta (flattened)
    for (const n of data.delta.nodes) nodeMap.set(n.id, flattenNode(n));

    const edgeMap = new Map<string, ExportedEdge>();
    for (const e of prev.edges) {
      const key = e.id || `${e.source}-${e.type}-${e.target}`;
      edgeMap.set(key, e);
    }
    // Remove deleted edges
    for (const id of data.delta.removed_edges || []) edgeMap.delete(id);
    // Add/update edges from delta (flattened)
    for (const e of data.delta.edges) {
      const flat = flattenEdge(e);
      const key = flat.id || `${flat.source}-${flat.type}-${flat.target}`;
      edgeMap.set(key, flat);
    }

    set({
      engagement: s.config ? { id: s.config.id, name: s.config.name, profile: s.config.profile, created_at: s.config.created_at } : get().engagement,
      accessLevel: s.access_summary?.current_access_level || get().accessLevel,
      historyCount: data.history_count ?? get().historyCount,
      graph: {
        nodes: Array.from(nodeMap.values()),
        edges: Array.from(edgeMap.values()),
        coldInventory: data.delta.cold_nodes
          ? [...data.delta.cold_nodes]
          : prev.coldInventory,
      },
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
      phases: s.phases || get().phases,
      readiness: s.lab_readiness ? { status: s.lab_readiness.status, issues: s.lab_readiness.top_issues } : get().readiness,
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
}));
