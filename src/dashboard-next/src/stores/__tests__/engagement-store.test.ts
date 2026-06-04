import { beforeEach, describe, expect, it } from 'vitest';
import { useEngagementStore } from '../engagement-store';
import type { Campaign, FullStateData, PendingAction, SessionInfo } from '../../lib/types';

const initialState = useEngagementStore.getState();

describe('engagement store hydration', () => {
  beforeEach(() => {
    useEngagementStore.setState({
      ...initialState,
      connected: false,
      initialized: false,
      graph: { nodes: [], edges: [] },
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
});
