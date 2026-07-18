import { afterEach, describe, expect, it, vi } from 'vitest';
import { getState } from '../api';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('dashboard state adapter', () => {
  it('accepts the real HTTP-v1 snapshot shape without a state revision', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      state: {
        config: { id: 'adapter-test', name: 'Adapter test' },
        access_summary: {
          compromised_hosts: [],
          valid_credentials: [],
          current_access_level: 'none',
        },
        graph_summary: {
          total_nodes: 0,
          total_edges: 0,
          confirmed_edges: 0,
          inferred_edges: 0,
          nodes_by_type: {},
        },
        objectives: [],
        frontier: [],
        frontier_hidden: {
          total: 0,
          by_reason: { lease: 0, opsec: 0, dead_host: 0, scope: 0 },
        },
        active_agents: [],
        agents: [],
        recent_activity: [],
        campaigns: [],
        sessions: [],
        pending_actions: [],
        warnings: {},
        scope_suggestions: [],
        phases: [],
        lab_readiness: { status: 'ready', top_issues: [] },
      },
      graph: { nodes: [], edges: [] },
      history_count: 17,
      runtime_build: {
        schema_version: 1,
        release_version: '0.2.0',
        input_sha256: 'd'.repeat(64),
        runtime_pid: 42,
        runtime_started_at: '2026-07-18T00:00:00.000Z',
      },
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })));

    await expect(getState()).resolves.toMatchObject({
      history_count: 17,
      state_revision: undefined,
      runtime_build: { release_version: '0.2.0' },
    });
  });
});
