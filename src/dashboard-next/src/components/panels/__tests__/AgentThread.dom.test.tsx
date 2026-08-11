import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AgentThread } from '../AgentThread';
import { buildAgentThread } from '../../../lib/agent-thread';
import type { AgentConsoleEvent } from '../../../lib/types';

function ev(o: Partial<AgentConsoleEvent> & { id: string; timestamp: string }): AgentConsoleEvent {
  return { agent_id: 'recon-1', kind: 'action', severity: 'info', title: 'Event', summary: '', ...o } as AgentConsoleEvent;
}

function renderThread(events: AgentConsoleEvent[]) {
  const entries = buildAgentThread(events, [], { agentId: 'task-1', agentLabel: 'recon-1' });
  render(
    <AgentThread
      agentLabel="recon-1"
      entries={entries}
      totalEntries={entries.length}
      paused={false}
      following
      scrollRef={{ current: null }}
      onTogglePaused={vi.fn()}
      onScroll={vi.fn()}
      onJumpLatest={vi.fn()}
      onRefresh={vi.fn()}
      onAnswered={vi.fn()}
      onNavigateGraph={vi.fn()}
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      onNavigatePanel={vi.fn() as any}
    />,
  );
}

describe('AgentThread — agent reasoning', () => {
  it('renders a thought as a reasoning card: kind, confidence, body, and considered options', () => {
    renderThread([
      ev({
        id: 't', timestamp: '2026-06-17T12:00:05Z', kind: 'thought',
        summary: 'Spray is quieter than a full kerberoast',
        raw: { details: { kind: 'decision', considered_alternatives: ['kerberoast all SPNs', 'targeted spray'], confidence: 0.7 } },
      }),
    ]);
    expect(screen.getByText('💭 Decision')).toBeTruthy();          // the thought kind
    expect(screen.getByText('70% sure')).toBeTruthy();             // confidence
    expect(screen.getByText(/Spray is quieter than a full kerberoast/)).toBeTruthy();
    expect(screen.getByText('Considered')).toBeTruthy();
    expect(screen.getByText('kerberoast all SPNs')).toBeTruthy();  // an alternative it weighed
  });

  it('falls back to a plain "Thinking" card when the thought carries no reasoning fields', () => {
    renderThread([
      ev({ id: 't', timestamp: '2026-06-17T12:00:05Z', kind: 'thought', summary: 'looks like SMB signing is off' }),
    ]);
    expect(screen.getByText('💭 Thinking')).toBeTruthy();
    expect(screen.getByText(/SMB signing is off/)).toBeTruthy();
    expect(screen.queryByText('Considered')).toBeNull();
  });
});
