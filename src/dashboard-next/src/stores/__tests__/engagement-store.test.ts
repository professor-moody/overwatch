import { beforeEach, describe, expect, it } from 'vitest';
import { useEngagementStore } from '../engagement-store';
import type { Campaign, FullStateData, GraphUpdateData, PendingAction, SessionInfo } from '../../lib/types';

const initialState = useEngagementStore.getState();

describe('engagement store hydration', () => {
  beforeEach(() => {
    useEngagementStore.setState({
      ...initialState,
      connected: false,
      initialized: false,
      graph: { nodes: [], edges: [], coldInventory: [] },
      graphVersion: 0,
      graphSummary: null,
      frontier: [],
      objectives: [],
      agents: [],
      campaigns: [],
      sessions: [],
      pendingActions: [],
      recentActivity: [],
      phases: [],
      readiness: null,
      accessSummary: { compromised_hosts: [], valid_credentials: [], current_access_level: 'none' },
    });
  });

  it('loads pending actions, sessions, and enriched campaigns from full state', () => {
    const pendingAction = {
      action_id: 'act-1',
      status: 'pending',
      submitted_at: '2026-05-15T10:00:00Z',
      description: 'Validate access',
      technique: 'credential_test',
      opsec_context: {},
      validation_result: 'valid',
    } as PendingAction;
    const campaign = {
      id: 'camp-1',
      name: 'Verify credential reachability',
      strategy: 'credential_spray',
      status: 'active',
      items: ['frontier-1', 'frontier-2'],
      created_at: '2026-05-15T10:00:00Z',
      completion_pct: 50,
      findings_count: 2,
      agents_active: 1,
      agents_total: 3,
      progress: { total: 2, completed: 1, succeeded: 1, failed: 0, consecutive_failures: 0 },
      abort_conditions: [],
      findings: ['finding-1', 'finding-2'],
    } as Campaign;
    const session = {
      id: 'sess-1',
      kind: 'pty',
      state: 'connected',
      title: 'ops shell',
    } as SessionInfo;

    const data: FullStateData = {
      state: {
        engagement: { id: 'eng-1', name: 'Demo Engagement' },
        pending_actions: [pendingAction],
        campaigns: [campaign],
        sessions: [session],
        agents: [],
        frontier: [],
        objectives: [],
        graph_summary: {
          total_nodes: 0,
          total_edges: 0,
          confirmed_edges: 0,
          inferred_edges: 0,
          nodes_by_type: {},
        },
      },
      graph: { nodes: [], edges: [] },
      history_count: 12,
    };

    useEngagementStore.getState().loadFullState(data);

    const hydrated = useEngagementStore.getState();
    expect(hydrated.initialized).toBe(true);
    expect(hydrated.pendingActions).toEqual([pendingAction]);
    expect(hydrated.sessions).toEqual([session]);
    expect(hydrated.campaigns[0]).toMatchObject({
      id: 'camp-1',
      status: 'active',
      completion_pct: 50,
      findings_count: 2,
      agents_active: 1,
      agents_total: 3,
    });
  });

  it('derives engagement + access level from config/access_summary (the real backend shape)', () => {
    // The backend sends `config` + `access_summary`, not top-level `engagement`/
    // `access_level`. Before the fix the store read the phantom fields, so the toolbar
    // was blank, access showed 'none', and the graph-layout key fell back to 'default'.
    const data: FullStateData = {
      state: {
        config: { id: 'eng-42', name: 'Prod Engagement', profile: 'goad_ad', created_at: '2026-05-15T10:00:00Z' },
        access_summary: { compromised_hosts: ['h1'], valid_credentials: ['c1'], current_access_level: 'domain_admin' },
        graph_summary: { total_nodes: 0, total_edges: 0, confirmed_edges: 0, inferred_edges: 0, nodes_by_type: {} },
      },
      graph: { nodes: [], edges: [] },
      history_count: 0,
    };
    useEngagementStore.getState().loadFullState(data);
    const s = useEngagementStore.getState();
    expect(s.engagement).toMatchObject({ id: 'eng-42', name: 'Prod Engagement', profile: 'goad_ad' });
    expect(s.engagement?.id).toBe('eng-42'); // the per-engagement graph-layout storage key
    expect(s.accessLevel).toBe('domain_admin');
  });

  it('replaces cold inventory only when a graph delta supplies a replacement snapshot', () => {
    const cold = {
      id: 'cold-1', type: 'host', label: 'cold', discovered_at: '2026-07-15T00:00:00Z',
      last_seen_at: '2026-07-15T00:00:00Z',
    };
    useEngagementStore.getState().loadFullState({
      state: {}, graph: { nodes: [], edges: [], cold_nodes: [cold] }, history_count: 0,
    } as FullStateData);

    const baseDelta = {
      state: {}, history_count: 0, detail: {},
      delta: { nodes: [], edges: [], removed_nodes: [], removed_edges: [] },
    } as GraphUpdateData;
    useEngagementStore.getState().applyGraphUpdate(baseDelta);
    expect(useEngagementStore.getState().graph.coldInventory.map(node => node.id)).toEqual(['cold-1']);

    useEngagementStore.getState().applyGraphUpdate({
      ...baseDelta, delta: { ...baseDelta.delta, cold_nodes: [] },
    });
    expect(useEngagementStore.getState().graph.coldInventory).toEqual([]);
  });

  it('projects cold-to-hot promotion and later hot removal without folding inventories together', () => {
    const cold = {
      id: 'host-1', type: 'host', label: 'candidate', discovered_at: '2026-07-15T00:00:00Z',
      last_seen_at: '2026-07-15T00:00:00Z',
    };
    useEngagementStore.getState().loadFullState({
      state: {}, graph: { nodes: [], edges: [], cold_nodes: [cold] }, history_count: 0,
    } as FullStateData);
    useEngagementStore.getState().applyGraphUpdate({
      state: {}, history_count: 0, detail: { new_nodes: ['host-1'] },
      delta: {
        nodes: [{ id: 'host-1', properties: { type: 'host', label: 'promoted' } }],
        edges: [], removed_nodes: [], removed_edges: [], cold_nodes: [],
      },
    } as GraphUpdateData);
    expect(useEngagementStore.getState().graph.nodes.map(node => node.id)).toEqual(['host-1']);
    expect(useEngagementStore.getState().graph.coldInventory).toEqual([]);

    useEngagementStore.getState().applyGraphUpdate({
      state: {}, history_count: 0, detail: { removed_nodes: ['host-1'] },
      delta: { nodes: [], edges: [], removed_nodes: ['host-1'], removed_edges: [], cold_nodes: [] },
    } as GraphUpdateData);
    expect(useEngagementStore.getState().graph.nodes).toEqual([]);
  });
});
