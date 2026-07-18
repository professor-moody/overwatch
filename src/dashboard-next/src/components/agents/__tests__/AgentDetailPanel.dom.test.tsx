import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { AgentInfo } from '../../../lib/types';
import { AgentDetailPanel } from '../AgentDetailPanel';

const agent: AgentInfo = {
  task_id: 'task-canonical-42',
  agent_label: 'planner-42',
  id: 'legacy-task-42',
  agent_id: 'legacy-planner-42',
  status: 'running',
  assigned_at: '2026-07-17T12:00:00.000Z',
  elapsed_ms: 2_000,
  queued: false,
  lifecycle: 'live',
  live: true,
  subgraph_node_ids: ['node-1'],
  current_action: 'Map the selected scope',
  findings_count: 0,
};

describe('AgentDetailPanel', () => {
  it('renders canonical identity and sends steering actions to the canonical task ID', async () => {
    const issueDirective = vi.fn().mockResolvedValue(undefined);
    const rendered = render(
      <AgentDetailPanel
        agent={agent}
        context={{ subgraph: { nodes: [{ id: 'node-1', properties: { label: 'Target node' } }] } }}
        ownedSessions={[]}
        onCancel={vi.fn()}
        onForceRemove={vi.fn()}
        onNavigateGraph={vi.fn()}
        onNavigateCampaign={vi.fn()}
        onNavigateSession={vi.fn()}
        onIssueDirective={issueDirective}
      />,
    );

    expect(screen.getByText('planner-42')).toBeInTheDocument();
    expect(screen.getByText('task-canonical-42')).toBeInTheDocument();
    expect(rendered.container.textContent).not.toContain('undefined');

    fireEvent.click(screen.getByRole('button', { name: 'Pause' }));
    await waitFor(() => {
      expect(issueDirective).toHaveBeenCalledWith('task-canonical-42', 'pause');
    });
  });
});
