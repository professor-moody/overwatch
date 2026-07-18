import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { AgentInfo } from '../../../lib/types';
import { ContextualCommandBar } from '../ContextualCommandBar';
import * as api from '../../../lib/api';

vi.mock('../../../lib/api', () => ({
  issueDirective: vi.fn(),
  fleetInstruct: vi.fn(),
}));

const focusedAgent: AgentInfo = {
  task_id: 'task-canonical',
  agent_label: 'planner-canonical',
  id: 'legacy-task',
  agent_id: 'legacy-planner',
  status: 'running',
  assigned_at: '2026-07-17T12:00:00.000Z',
  queued: false,
  lifecycle: 'live',
  live: true,
  subgraph_node_ids: [],
  findings_count: 0,
};

describe('ContextualCommandBar canonical agent routing', () => {
  it('sends a focused instruction to task_id while showing agent_label', async () => {
    vi.mocked(api.issueDirective).mockResolvedValue({ ok: true, results: [] });

    render(
      <ContextualCommandBar
        focusedAgent={focusedAgent}
        agents={[focusedAgent]}
      />,
    );

    expect(screen.getByRole('button', { name: 'planner-canonical' })).toBeInTheDocument();
    const input = screen.getByPlaceholderText(/Command planner-canonical/);
    fireEvent.change(input, { target: { value: 'return your current status' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));

    await waitFor(() => {
      expect(api.issueDirective).toHaveBeenCalledWith(
        'task-canonical',
        'instruct',
        { note: 'return your current status' },
      );
    });
    expect(document.body.textContent).not.toContain('undefined');
  });
});
