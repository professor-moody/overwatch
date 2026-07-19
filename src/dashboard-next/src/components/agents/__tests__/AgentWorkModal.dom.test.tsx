import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AgentInfo } from '../../../lib/types';
import * as api from '../../../lib/api';
import { AgentWorkModal } from '../AgentWorkModal';

vi.mock('../../../lib/api', async importOriginal => {
  const actual = await importOriginal<typeof import('../../../lib/api')>();
  return {
    ...actual,
    getAgentDuplicates: vi.fn(),
    handoffAgentWork: vi.fn(),
    splitAgentWork: vi.fn(),
    mergeAgentWork: vi.fn(),
  };
});

const terminalAgent: AgentInfo = {
  task_id: 'task-source',
  agent_label: 'source-agent',
  id: 'task-source',
  agent_id: 'source-agent',
  status: 'completed',
  assigned_at: '2026-07-18T01:00:00.000Z',
  completed_at: '2026-07-18T01:10:00.000Z',
  queued: false,
  lifecycle: 'completed',
  live: false,
  subgraph_node_ids: ['node-a', 'node-b', 'node-c', 'node-d'],
  archetype: 'web_tester',
  objective: 'Assess the application.',
  findings_count: 0,
};

describe('AgentWorkModal', () => {
  beforeEach(() => vi.clearAllMocks());

  it('hands terminal work to one successor without changing historical ownership', async () => {
    vi.mocked(api.handoffAgentWork).mockResolvedValue({
      operation: 'handoff',
      source_task_id: 'task-source',
      created_tasks: [{
        task_id: 'task-next',
        agent_label: 'next-agent',
        id: 'task-next',
        agent_id: 'next-agent',
        assigned_at: '2026-07-18T02:00:00.000Z',
        status: 'pending',
        subgraph_node_ids: terminalAgent.subgraph_node_ids,
        work: { version: 1, root_task_id: 'task-source', signature: 'a'.repeat(64) },
      }],
      warnings: [],
      reused_existing: false,
      command_id: 'cmd-handoff',
      idempotency_key: 'idem-handoff',
      replayed: false,
    });
    const completed = vi.fn();

    render(
      <AgentWorkModal
        agent={terminalAgent}
        mode="handoff"
        onClose={vi.fn()}
        onCompleted={completed}
      />,
    );
    fireEvent.change(screen.getByLabelText('Key finding IDs'), {
      target: { value: 'finding-one, finding-two finding-one' },
    });
    fireEvent.change(screen.getByLabelText('Key evidence IDs'), {
      target: { value: 'evidence-one' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create successor' }));

    await waitFor(() => {
      expect(api.handoffAgentWork).toHaveBeenCalledWith(
        'task-source',
        expect.objectContaining({
          archetype: 'web_tester',
          objective: 'Assess the application.',
          key_finding_ids: ['finding-one', 'finding-two'],
          key_evidence_ids: ['evidence-one'],
        }),
      );
      expect(completed).toHaveBeenCalledTimes(1);
    });
  });

  it('builds a deterministic disjoint split that covers every source node', async () => {
    const childTask = (id: string, nodes: string[]) => ({
      id,
      task_id: id,
      agent_id: id,
      agent_label: id,
      assigned_at: '2026-07-18T02:00:00.000Z',
      status: 'pending' as const,
      subgraph_node_ids: nodes,
      work: { version: 1 as const, root_task_id: 'task-source', signature: 'c'.repeat(64) },
    });
    vi.mocked(api.splitAgentWork).mockResolvedValue({
      operation: 'split',
      source_task_id: 'task-source',
      created_tasks: [childTask('child-1', ['node-a', 'node-c']), childTask('child-2', ['node-b', 'node-d'])],
      warnings: [],
      reused_existing: false,
      command_id: 'cmd-split',
      idempotency_key: 'idem-split',
      replayed: false,
    });

    render(
      <AgentWorkModal
        agent={terminalAgent}
        mode="split"
        onClose={vi.fn()}
        onCompleted={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Create children' }));

    await waitFor(() => expect(api.splitAgentWork).toHaveBeenCalledTimes(1));
    const request = vi.mocked(api.splitAgentWork).mock.calls[0]![1];
    expect(request.children.map(child => child.target_node_ids)).toEqual([
      ['node-a', 'node-c'],
      ['node-b', 'node-d'],
    ]);
    expect(new Set(request.children.flatMap(child => child.target_node_ids))).toEqual(
      new Set(terminalAgent.subgraph_node_ids),
    );
  });

  it('disables split submission when the child count is empty or invalid', () => {
    render(
      <AgentWorkModal
        agent={terminalAgent}
        mode="split"
        onClose={vi.fn()}
        onCompleted={vi.fn()}
      />,
    );
    const input = screen.getByLabelText('Child tasks');
    fireEvent.change(input, { target: { value: '' } });
    expect(screen.getByRole('button', { name: 'Create children' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Create children' }));
    expect(api.splitAgentWork).not.toHaveBeenCalled();
  });

  it('loads exact duplicates and merges only terminal non-canonical tasks', async () => {
    vi.mocked(api.getAgentDuplicates).mockResolvedValue({
      total: 1,
      groups: [{
        signature: 'b'.repeat(64),
        canonical_task_id: 'task-live',
        candidate_task_ids: ['task-live', 'task-source', 'task-other'],
        tasks: [
          { ...terminalAgent, task_id: 'task-live', id: 'task-live', status: 'running', lifecycle: 'live', live: true, work: { version: 1, root_task_id: 'task-live', signature: 'b'.repeat(64) } },
          { ...terminalAgent, work: { version: 1, root_task_id: 'task-source', signature: 'b'.repeat(64) } },
          { ...terminalAgent, task_id: 'task-other', id: 'task-other', work: { version: 1, root_task_id: 'task-other', signature: 'b'.repeat(64) } },
        ],
      }],
    });
    vi.mocked(api.mergeAgentWork).mockResolvedValue({
      operation: 'merge',
      canonical_task_id: 'task-live',
      updated_tasks: [
        { ...terminalAgent, task_id: 'task-live', id: 'task-live', status: 'running', work: { version: 1, root_task_id: 'task-live', signature: 'b'.repeat(64) } },
        { ...terminalAgent, work: { version: 1, root_task_id: 'task-source', signature: 'b'.repeat(64), merged_into_task_id: 'task-live' } },
        { ...terminalAgent, task_id: 'task-other', id: 'task-other', work: { version: 1, root_task_id: 'task-other', signature: 'b'.repeat(64), merged_into_task_id: 'task-live' } },
      ],
      warnings: [],
      reused_existing: false,
      command_id: 'cmd-merge',
      idempotency_key: 'idem-merge',
      replayed: false,
    });

    render(
      <AgentWorkModal
        agent={terminalAgent}
        mode="merge"
        onClose={vi.fn()}
        onCompleted={vi.fn()}
      />,
    );
    await screen.findByText('Terminal merge candidates:');
    fireEvent.click(screen.getByLabelText('task-other'));
    await waitFor(() => {
      expect(screen.getByLabelText('task-other')).not.toBeChecked();
    });
    fireEvent.click(screen.getByRole('button', { name: 'Merge duplicates' }));

    await waitFor(() => {
      expect(api.mergeAgentWork).toHaveBeenCalledWith('task-live', expect.objectContaining({
        duplicate_task_ids: ['task-source'],
      }));
    });
    expect(api.getAgentDuplicates).toHaveBeenCalledTimes(2);
  });

  it('fails closed when duplicate canonical membership changes during confirmation', async () => {
    const initial = {
      total: 1,
      groups: [{
        signature: 'd'.repeat(64),
        canonical_task_id: 'task-live',
        candidate_task_ids: ['task-live', 'task-source'],
        tasks: [
          { ...terminalAgent, task_id: 'task-live', id: 'task-live', status: 'running' as const, lifecycle: 'live' as const, live: true, work: { version: 1 as const, root_task_id: 'task-live', signature: 'd'.repeat(64) } },
          { ...terminalAgent, work: { version: 1 as const, root_task_id: 'task-source', signature: 'd'.repeat(64) } },
        ],
      }],
    };
    const changed = {
      ...initial,
      groups: [{
        ...initial.groups[0]!,
        canonical_task_id: 'task-source',
        candidate_task_ids: ['task-source', 'task-live'],
      }],
    };
    vi.mocked(api.getAgentDuplicates)
      .mockResolvedValueOnce(initial)
      .mockResolvedValueOnce(changed);

    render(
      <AgentWorkModal
        agent={terminalAgent}
        mode="merge"
        onClose={vi.fn()}
        onCompleted={vi.fn()}
      />,
    );
    await screen.findByText('Terminal merge candidates:');
    const mergeButton = screen.getByRole('button', { name: 'Merge duplicates' });
    // The eligible selection is derived in an effect after duplicate discovery.
    // Wait for that state transition instead of racing a click against a disabled
    // button on slower/supported Node runtimes.
    await waitFor(() => expect(mergeButton).toBeEnabled());
    fireEvent.click(mergeButton);
    await waitFor(() => expect(api.getAgentDuplicates).toHaveBeenCalledTimes(2));
    expect(api.mergeAgentWork).not.toHaveBeenCalled();
    expect(await screen.findByText('task-source')).toBeInTheDocument();
  });

  it('is a labelled keyboard dialog and restores focus when it closes', () => {
    const trigger = document.createElement('button');
    trigger.textContent = 'Open work';
    document.body.append(trigger);
    trigger.focus();
    const close = vi.fn();
    const rendered = render(
      <AgentWorkModal
        agent={terminalAgent}
        mode="handoff"
        onClose={close}
        onCompleted={vi.fn()}
      />,
    );
    const dialog = screen.getByRole('dialog', { name: 'Hand off work' });
    expect(screen.getByLabelText('Operator summary')).toHaveFocus();
    fireEvent.keyDown(dialog, { key: 'Escape' });
    expect(close).toHaveBeenCalledTimes(1);
    rendered.unmount();
    expect(trigger).toHaveFocus();
    trigger.remove();
  });
});
