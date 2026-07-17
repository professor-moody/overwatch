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

function dashboardState() {
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
  };
}

function fullState(historyCount: number) {
  return {
    state: dashboardState(),
    graph: { nodes: [], edges: [] },
    history_count: historyCount,
    runtime_build: {
      schema_version: 1,
      input_sha256: 'd'.repeat(64),
      runtime_pid: 123,
      runtime_started_at: '2026-07-17T00:00:00.000Z',
    },
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
          timestamp: '2026-07-17T00:00:00.000Z',
          data: { state: dashboardState(), history_count: 77 },
        }),
      } as MessageEvent);
    });
    expect(useEngagementStore.getState().historyCount).toBe(0);

    act(() => {
      socket.onmessage?.({
        data: JSON.stringify({
          type: 'full_state',
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
          timestamp: '2026-07-17T00:00:01.000Z',
          data: legacy,
        }),
      } as MessageEvent);
    });

    await waitFor(() => expect(screen.getByText(/legacy\/unknown/)).toBeInTheDocument());
    expect(screen.getByText('provider disconnected')).toBeInTheDocument();
    expect(socket.close).toHaveBeenCalledTimes(1);
  });
});
