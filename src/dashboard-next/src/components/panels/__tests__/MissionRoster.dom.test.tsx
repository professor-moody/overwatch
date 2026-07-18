import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { MissionCard } from '../../../lib/agent-mission';
import { MissionRoster } from '../AgentsPanel';

function card(index: number): MissionCard {
  return {
    id: `task-${index}`,
    label: `agent-${index}`,
    status: 'completed',
    freshness: 'none',
    ownedSessionIds: [],
    findingsCount: 0,
    pendingApproval: false,
    awaitingAnswer: false,
    tone: 'done',
    scopeNodeCount: 0,
  };
}

describe('MissionRoster scale guard', () => {
  it('renders a bounded initial fleet and expands only on operator request', () => {
    const cards = Array.from({ length: 1_000 }, (_, index) => card(index));
    render(<MissionRoster
      groups={[{ key: 'fleet', name: 'Fleet', cards }]}
      agentCount={cards.length}
      activeAgentId="all"
      selectedIds={new Set()}
      collapsedGroups={new Set()}
      batchMode={false}
      elapsedById={new Map()}
      onToggleBatch={() => {}}
      onSelectAllOutput={() => {}}
      onSelectAgent={() => {}}
      onToggleSelect={() => {}}
      onToggleGroup={() => {}}
      onCancelAgent={() => {}}
      onDismissAgent={() => {}}
      onForceRemoveAgent={() => {}}
      onClearFinished={() => {}}
    />);

    expect(screen.getAllByTestId('mission-card')).toHaveLength(200);
    fireEvent.click(screen.getByRole('button', { name: /Show 200 more/ }));
    expect(screen.getAllByTestId('mission-card')).toHaveLength(400);
  });
});
