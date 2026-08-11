import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AttentionQueue } from '../AttentionQueue';
import { useEngagementStore } from '../../../stores/engagement-store';
import type { AgentInfo } from '../../../lib/types';

// A minimal failed agent surfaces as a top-priority 'failed' AttentionItem
// (buildAttentionQueue: recentlyFailed → failedItem). No completed_at ⇒ always recent.
function failedAgent(id = 'task-1'): AgentInfo {
  return { id, agent_id: `agent-${id}`, status: 'failed' } as unknown as AgentInfo;
}

function renderQueue(onForceRemove = vi.fn()) {
  useEngagementStore.setState({ agents: [failedAgent()], pendingActions: [] });
  render(
    <AttentionQueue
      agentQueries={[]}
      proposedPlans={[]}
      onAnswered={() => {}}
      onPlanResolved={() => {}}
      onSelectAgent={() => {}}
      onForceRemove={onForceRemove}
      onTriageAll={() => {}}
    />,
  );
  return onForceRemove;
}

describe('AttentionQueue — inline force-remove for a wedged/failed agent', () => {
  afterEach(() => {
    useEngagementStore.setState({ agents: [], pendingActions: [] });
  });

  it('offers Force remove on a failed agent and calls onForceRemove with its taskId', () => {
    const onForceRemove = renderQueue();
    // The queue keeps its top item expanded by default, so the action is one click away.
    fireEvent.click(screen.getByRole('button', { name: /Force remove/i }));
    expect(onForceRemove).toHaveBeenCalledWith('task-1');
  });

  it('keeps View agent → alongside Force remove for inspection', () => {
    renderQueue();
    expect(screen.getByRole('button', { name: /View agent/i })).toBeTruthy();
    expect(screen.getByRole('button', { name: /Force remove/i })).toBeTruthy();
  });

  it('disables the button while the removal is in flight (no double-fire)', async () => {
    let resolve!: () => void;
    const onForceRemove = vi.fn(() => new Promise<void>(r => { resolve = r; }));
    renderQueue(onForceRemove);
    const btn = screen.getByRole('button', { name: /Force remove/i });
    fireEvent.click(btn);
    // Second click is a no-op while the first is pending.
    fireEvent.click(btn);
    expect(onForceRemove).toHaveBeenCalledTimes(1);
    expect((btn as HTMLButtonElement).disabled).toBe(true);
    resolve();
  });
});
