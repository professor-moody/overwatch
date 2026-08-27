import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as api from '../../../lib/api';
import { createDashboardWebSocket } from '../../../lib/dashboard-transport';
import type { AgentConsoleEvent } from '../../../lib/types';
import { useEngagementStore } from '../../../stores/engagement-store';
import { ActivityDrawer } from '../ActivityDrawer';
import { ExecutionOutputView } from '../ExecutionOutputView';

vi.mock('../../../lib/api', () => ({
  getOperatorConsole: vi.fn(),
  getActionOutput: vi.fn(),
  getEvidenceRaw: vi.fn(),
  explainAction: vi.fn(),
  reparseAction: vi.fn(),
}));

vi.mock('../../../lib/dashboard-transport', () => ({
  createDashboardWebSocket: vi.fn(),
}));

function consoleEvent(id: string, title: string, timestamp: string): AgentConsoleEvent {
  return {
    id,
    timestamp,
    agent_id: 'browser-agent',
    source_kind: 'system',
    source_label: 'Runtime',
    kind: 'system',
    severity: 'info',
    title,
    summary: `${title} summary`,
  } as AgentConsoleEvent;
}

function ActivityHarness() {
  const [selected, setSelected] = useState<string | undefined>();
  return (
    <ActivityDrawer
      selectedItem={selected}
      onSelect={item => setSelected(item ?? undefined)}
      onOpenRun={() => {}}
    />
  );
}

describe('native execution console', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useEngagementStore.setState({ connected: true });
  });

  it('accepts paused events and counts replayed IDs only once without moving selection', async () => {
    const first = consoleEvent('event-1', 'Initial event', '2026-08-27T10:00:00.000Z');
    vi.mocked(api.getOperatorConsole).mockResolvedValue({ events: [first], total: 1 });

    render(<MemoryRouter><ActivityHarness /></MemoryRouter>);
    await screen.findByText('Initial event');
    fireEvent.click(screen.getByRole('button', { name: /Pause/ }));

    const next = consoleEvent('event-2', 'New while paused', '2026-08-27T10:00:01.000Z');
    act(() => {
      window.dispatchEvent(new CustomEvent('overwatch-agent-console-update', {
        detail: { events: [next, next] },
      }));
    });

    expect(screen.getByText('New while paused')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /1 new event/ })).toBeInTheDocument();
    expect(screen.getAllByText('Initial event summary').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('button', { name: /Resume/ }));
    await waitFor(() => expect(screen.queryByRole('button', { name: /new event/ })).toBeNull());
  });

  it('pages durable output from the server byte cursor and exposes its evidence link', async () => {
    vi.mocked(api.getActionOutput).mockResolvedValue({
      action_id: 'act-paged',
      status: 'success',
      max_bytes: 65_536,
      command_repr: 'printf unicode-output',
      stdout: {
        evidence_id: 'evidence-paged',
        text: '🙂 head\n',
        total_bytes: 65_540,
        truncated: false,
        head_truncated: true,
        dropped_bytes: 0,
      },
      stderr: null,
    });
    vi.mocked(api.getEvidenceRaw).mockResolvedValue({
      evidence_id: 'evidence-paged',
      text: 'tail',
      total_bytes: 65_540,
      offset: 65_536,
      bytes_read: 4,
      eof: true,
    });

    render(<MemoryRouter><ExecutionOutputView actionId="act-paged" showOpenInRuns={false} /></MemoryRouter>);
    await screen.findByText('🙂 head', { exact: false });
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));

    await waitFor(() => expect(api.getEvidenceRaw).toHaveBeenCalledWith('evidence-paged', {
      offset: 65_536,
      maxBytes: 256 * 1024,
    }));
    expect(await screen.findByText('tail', { exact: false })).toBeInTheDocument();
    expect(screen.getByTitle('Open evidence evidence-paged')).toBeInTheDocument();
  });

  it('keeps the last-good live buffer visible when transport disconnects', async () => {
    const socket = {
      onmessage: null as ((event: MessageEvent) => void) | null,
      close: vi.fn(),
    };
    vi.mocked(createDashboardWebSocket).mockReturnValue(socket as unknown as WebSocket);
    vi.mocked(api.getActionOutput).mockResolvedValue({
      action_id: 'act-live',
      status: 'running',
      max_bytes: 65_536,
      command_repr: 'long-running-command',
      stdout: null,
      stderr: null,
    });

    render(<MemoryRouter><ExecutionOutputView actionId="act-live" showOpenInRuns={false} /></MemoryRouter>);
    await waitFor(() => expect(createDashboardWebSocket).toHaveBeenCalled());
    act(() => {
      socket.onmessage?.({
        data: JSON.stringify({ type: 'output', stream: 'stdout', text: 'last good live bytes\n', end_pos: 21, dropped: false }),
      } as MessageEvent);
    });
    expect(screen.getByText('last good live bytes', { exact: false })).toBeInTheDocument();

    act(() => useEngagementStore.setState({ connected: false }));
    expect(screen.getByText('Last captured output remains visible.', { exact: false })).toBeInTheDocument();
    expect(screen.getByText('last good live bytes', { exact: false })).toBeInTheDocument();
    expect(screen.getByText('Stale buffer')).toBeInTheDocument();
  });
});
