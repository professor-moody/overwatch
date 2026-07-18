import { act, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { WsProvider, useWs } from '../ws-provider';
import { useEngagementStore } from '../../stores/engagement-store';
import { useToastStore } from '../../stores/toast-store';
import * as api from '../../lib/api';
import { createDashboardWebSocket } from '../../lib/dashboard-transport';

vi.mock('../../lib/api', () => ({
  getState: vi.fn(),
}));

vi.mock('../../lib/dashboard-transport', () => ({
  createDashboardWebSocket: vi.fn(),
}));

vi.mock('../../lib/dashboard-build-compatibility', () => ({
  compareDashboardBuilds: (serverBuild: string | undefined) => serverBuild === 'd'.repeat(64)
    ? {
        compatible: true,
        client_build: 'd'.repeat(64),
        server_build: serverBuild,
      }
    : {
        compatible: false,
        client_build: 'd'.repeat(64),
        message: 'Dashboard build does not match server build legacy/unknown.',
      },
}));

interface FakeSocket {
  readyState: number;
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  onerror: ((event: Event) => void) | null;
  close: ReturnType<typeof vi.fn>;
}

function fakeSocket(): FakeSocket {
  return {
    readyState: 0,
    onopen: null,
    onmessage: null,
    onclose: null,
    onerror: null,
    close: vi.fn(),
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(next => { resolve = next; });
  return { promise, resolve };
}

function dashboardState(overrides: Record<string, unknown> = {}) {
  return {
    config: { id: 'dom-engagement', name: 'DOM engagement' },
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
    ...overrides,
  };
}

function fullState(historyCount: number, state = dashboardState()) {
  return {
    state,
    graph: { nodes: [], edges: [] },
    history_count: historyCount,
    state_revision: 1,
    runtime_build: {
      schema_version: 1,
      input_sha256: 'd'.repeat(64),
      runtime_pid: 123,
      runtime_started_at: '2026-07-17T00:00:00.000Z',
    },
  };
}

function agent(taskId: string, status: 'pending' | 'running' | 'completed' = 'running') {
  return {
    task_id: taskId,
    agent_label: `agent-${taskId}`,
    id: taskId,
    agent_id: `agent-${taskId}`,
    status,
    assigned_at: '2026-07-18T00:00:00.000Z',
    queued: status === 'pending',
    lifecycle: status === 'completed' ? 'completed' : status === 'pending' ? 'queued' : 'live',
    live: status === 'running',
    subgraph_node_ids: [],
    findings_count: 0,
  };
}

function Probe() {
  const { connected } = useWs();
  return <div>{connected ? 'provider connected' : 'provider disconnected'}</div>;
}

describe('WsProvider effect ownership', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useEngagementStore.setState({
      connected: false,
      initialized: false,
      historyCount: 0,
      graph: { nodes: [], edges: [], coldInventory: [] },
      graphSummary: null,
      pendingActions: [],
      sessions: [],
      playbookRuns: [],
    });
    useToastStore.getState().clearAll();
  });

  it('waits for full_state, suppresses pre-base events, aborts stale polling, and cleans up', async () => {
    const fallback = deferred<ReturnType<typeof fullState>>();
    let fallbackSignal: AbortSignal | undefined;
    vi.mocked(api.getState).mockImplementation((signal?: AbortSignal) => {
      fallbackSignal = signal;
      return fallback.promise;
    });
    const socket = fakeSocket();
    vi.mocked(createDashboardWebSocket).mockReturnValue(socket as unknown as WebSocket);

    const rendered = render(
      <WsProvider>
        <Probe />
      </WsProvider>,
    );

    await waitFor(() => expect(createDashboardWebSocket).toHaveBeenCalledTimes(1));
    expect(screen.getByText('provider disconnected')).toBeInTheDocument();
    expect(api.getState).toHaveBeenCalledTimes(1);

    act(() => {
      socket.readyState = 1;
      socket.onopen?.(new Event('open'));
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'state_refresh',
          contract_version: 2,
          timestamp: '2026-07-17T00:00:00.000Z',
          data: {
            patch: {},
            base_revision: 0,
            state_revision: 1,
            history_count: 77,
          },
        }),
      } as MessageEvent);
    });
    expect(useEngagementStore.getState().historyCount).toBe(0);

    act(() => {
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'full_state',
          contract_version: 2,
          timestamp: '2026-07-17T00:00:01.000Z',
          data: fullState(1),
        }),
      } as MessageEvent);
    });
    await waitFor(() => expect(screen.getByText('provider connected')).toBeInTheDocument());
    expect(useEngagementStore.getState().historyCount).toBe(1);
    expect(fallbackSignal?.aborted).toBe(true);

    await act(async () => {
      fallback.resolve(fullState(999));
      await fallback.promise;
    });
    expect(useEngagementStore.getState().historyCount).toBe(1);

    rendered.unmount();
    expect(socket.close).toHaveBeenCalledTimes(1);
    expect(socket.onopen).toBeNull();
    expect(socket.onmessage).toBeNull();
    expect(socket.onclose).toBeNull();
    expect(socket.onerror).toBeNull();
    expect(useEngagementStore.getState().connected).toBe(false);
  });

  it('rejects a legacy full state without runtime identity instead of reconnecting generically', async () => {
    vi.mocked(api.getState).mockImplementation(() => new Promise(() => {}));
    const socket = fakeSocket();
    vi.mocked(createDashboardWebSocket).mockReturnValue(socket as unknown as WebSocket);

    render(
      <WsProvider>
        <Probe />
      </WsProvider>,
    );
    await waitFor(() => expect(createDashboardWebSocket).toHaveBeenCalledTimes(1));

    act(() => {
      socket.readyState = 1;
      socket.onopen?.(new Event('open'));
      const legacy: Record<string, unknown> = { ...fullState(1) };
      delete legacy.runtime_build;
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'full_state',
          contract_version: 2,
          timestamp: '2026-07-17T00:00:01.000Z',
          data: legacy,
        }),
      } as MessageEvent);
    });

    await waitFor(() => expect(screen.getByText(/legacy\/unknown/)).toBeInTheDocument());
    expect(screen.getByText('provider disconnected')).toBeInTheDocument();
    expect(socket.close).toHaveBeenCalledTimes(1);
  });

  it('rejects WebSocket v1 state envelopes on the bundled v2 client', async () => {
    vi.mocked(api.getState).mockImplementation(() => new Promise(() => {}));
    const socket = fakeSocket();
    vi.mocked(createDashboardWebSocket).mockReturnValue(socket as unknown as WebSocket);

    render(
      <WsProvider>
        <Probe />
      </WsProvider>,
    );
    await waitFor(() => expect(createDashboardWebSocket).toHaveBeenCalledWith('/ws?contract=2'));

    act(() => {
      socket.readyState = 1;
      socket.onopen?.(new Event('open'));
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'full_state',
          timestamp: '2026-07-18T00:00:01.000Z',
          data: fullState(1),
        }),
      } as MessageEvent);
    });

    await waitFor(() => expect(socket.close).toHaveBeenCalledTimes(1));
    expect(screen.getByText(/requires main WebSocket contract v2/)).toBeInTheDocument();
    expect(screen.getByText('provider disconnected')).toBeInTheDocument();
    expect(useEngagementStore.getState().initialized).toBe(false);
    expect(createDashboardWebSocket).toHaveBeenCalledTimes(1);
  });

  it('hydrates from an HTTP compatibility-v1 snapshot without a state revision', async () => {
    const { state_revision: _revision, ...snapshot } = fullState(41);
    vi.mocked(api.getState).mockResolvedValue(snapshot);
    const socket = fakeSocket();
    vi.mocked(createDashboardWebSocket).mockReturnValue(socket as unknown as WebSocket);

    render(
      <WsProvider>
        <Probe />
      </WsProvider>,
    );

    await waitFor(() => expect(useEngagementStore.getState().initialized).toBe(true));
    expect(useEngagementStore.getState().historyCount).toBe(41);
    expect(useEngagementStore.getState().stateRevision).toBeNull();
    expect(screen.getByText('provider disconnected')).toBeInTheDocument();
  });

  it('negotiates contract v2 and converges keyed agent patches exactly', async () => {
    vi.mocked(api.getState).mockImplementation(() => new Promise(() => {}));
    const socket = fakeSocket();
    vi.mocked(createDashboardWebSocket).mockReturnValue(socket as unknown as WebSocket);

    render(
      <WsProvider>
        <Probe />
      </WsProvider>,
    );
    await waitFor(() => expect(createDashboardWebSocket).toHaveBeenCalledWith('/ws?contract=2'));

    act(() => {
      socket.readyState = 1;
      socket.onopen?.(new Event('open'));
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'full_state',
          contract_version: 2,
          timestamp: '2026-07-18T00:00:01.000Z',
          data: fullState(1, dashboardState({
            agents: [agent('task-a'), agent('task-b')],
          })),
        }),
      } as MessageEvent);
    });
    await waitFor(() => expect(screen.getByText('provider connected')).toBeInTheDocument());

    act(() => {
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'graph_update',
          contract_version: 2,
          timestamp: '2026-07-18T00:00:01.500Z',
          data: {
            history_count: 1,
            detail: { updated_nodes: ['node-1'] },
            delta: { nodes: [], edges: [], removed_nodes: [], removed_edges: [] },
          },
        }),
      } as MessageEvent);
    });
    expect(useToastStore.getState().toasts).toHaveLength(0);

    act(() => {
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'state_refresh',
          contract_version: 2,
          timestamp: '2026-07-18T00:00:02.000Z',
          data: {
            history_count: 2,
            base_revision: 1,
            state_revision: 2,
            patch: {
              agents: {
                upsert: [agent('task-b', 'completed'), agent('task-c')],
                remove: ['task-a'],
                moves: [
                  { id: 'task-c', index: 0 },
                  { id: 'task-b', index: 1 },
                ],
                total: 2,
              },
            },
          },
        }),
      } as MessageEvent);
    });

    expect(useEngagementStore.getState().agents.map(candidate => ({
      task_id: candidate.task_id,
      status: candidate.status,
    }))).toEqual([
      { task_id: 'task-c', status: 'running' },
      { task_id: 'task-b', status: 'completed' },
    ]);
    expect(useEngagementStore.getState().historyCount).toBe(2);
    expect(useToastStore.getState().toasts).toEqual([
      expect.objectContaining({ title: 'Agent completed', linkItem: 'task-b' }),
    ]);
  });

  it('drops synchronization when a v2 patch targets the wrong full-state revision', async () => {
    vi.mocked(api.getState).mockImplementation(() => new Promise(() => {}));
    const socket = fakeSocket();
    vi.mocked(createDashboardWebSocket).mockReturnValue(socket as unknown as WebSocket);

    const rendered = render(
      <WsProvider>
        <Probe />
      </WsProvider>,
    );
    await waitFor(() => expect(createDashboardWebSocket).toHaveBeenCalledTimes(1));
    act(() => {
      socket.readyState = 1;
      socket.onopen?.(new Event('open'));
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'full_state',
          contract_version: 2,
          timestamp: '2026-07-18T00:00:01.000Z',
          data: fullState(1),
        }),
      } as MessageEvent);
    });
    await waitFor(() => expect(screen.getByText('provider connected')).toBeInTheDocument());

    act(() => {
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'state_refresh',
          contract_version: 2,
          timestamp: '2026-07-18T00:00:02.000Z',
          data: {
            history_count: 2,
            base_revision: 0,
            state_revision: 1,
            patch: { agents: { upsert: [], remove: [], moves: [], total: 0 } },
          },
        }),
      } as MessageEvent);
    });

    await waitFor(() => expect(screen.getByText('provider disconnected')).toBeInTheDocument());
    expect(socket.close).toHaveBeenCalledTimes(1);
    expect(useEngagementStore.getState().historyCount).toBe(1);
    expect(useEngagementStore.getState().stateRevision).toBe(1);
    rendered.unmount();
  });

  it('drops synchronization when a synchronized state-channel event is malformed', async () => {
    vi.mocked(api.getState).mockImplementation(() => new Promise(() => {}));
    const socket = fakeSocket();
    vi.mocked(createDashboardWebSocket).mockReturnValue(socket as unknown as WebSocket);

    render(
      <WsProvider>
        <Probe />
      </WsProvider>,
    );
    await waitFor(() => expect(createDashboardWebSocket).toHaveBeenCalledTimes(1));
    act(() => {
      socket.readyState = 1;
      socket.onopen?.(new Event('open'));
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'full_state',
          contract_version: 2,
          timestamp: '2026-07-18T00:00:01.000Z',
          data: fullState(7),
        }),
      } as MessageEvent);
    });
    await waitFor(() => expect(screen.getByText('provider connected')).toBeInTheDocument());

    act(() => {
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'graph_update',
          contract_version: 2,
          timestamp: '2026-07-18T00:00:02.000Z',
          data: { history_count: 8, detail: {} },
        }),
      } as MessageEvent);
    });

    await waitFor(() => expect(screen.getByText('provider disconnected')).toBeInTheDocument());
    expect(socket.close).toHaveBeenCalledTimes(1);
    expect(useEngagementStore.getState().historyCount).toBe(7);
  });

  it('drops synchronization when a valid graph delta cannot be applied', async () => {
    vi.mocked(api.getState).mockImplementation(() => new Promise(() => {}));
    const socket = fakeSocket();
    vi.mocked(createDashboardWebSocket).mockReturnValue(socket as unknown as WebSocket);

    render(
      <WsProvider>
        <Probe />
      </WsProvider>,
    );
    await waitFor(() => expect(createDashboardWebSocket).toHaveBeenCalledTimes(1));
    act(() => {
      socket.readyState = 1;
      socket.onopen?.(new Event('open'));
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'full_state',
          contract_version: 2,
          timestamp: '2026-07-18T00:00:01.000Z',
          data: fullState(11),
        }),
      } as MessageEvent);
    });
    await waitFor(() => expect(screen.getByText('provider connected')).toBeInTheDocument());
    const apply = vi.spyOn(useEngagementStore.getState(), 'applyGraphUpdate')
      .mockImplementationOnce(() => {
        throw new Error('synthetic graph projection failure');
      });

    act(() => {
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'graph_update',
          contract_version: 2,
          timestamp: '2026-07-18T00:00:02.000Z',
          data: {
            history_count: 12,
            detail: {},
            delta: { nodes: [], edges: [], removed_nodes: [], removed_edges: [] },
          },
        }),
      } as MessageEvent);
    });

    await waitFor(() => expect(screen.getByText('provider disconnected')).toBeInTheDocument());
    expect(socket.close).toHaveBeenCalledTimes(1);
    expect(useEngagementStore.getState().historyCount).toBe(11);
    apply.mockRestore();
  });
});
