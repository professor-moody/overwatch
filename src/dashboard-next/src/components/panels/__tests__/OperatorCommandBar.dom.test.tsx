import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { OperatorCommandBar } from '../OperatorCommandBar';
import { POLL } from '../../../lib/polling';
import * as api from '../../../lib/api';

vi.mock('../../../lib/api', () => ({
  getActiveApplicationCommands: vi.fn(),
  getApplicationCommand: vi.fn(),
  previewCommand: vi.fn(),
  confirmCommand: vi.fn(),
  denyCommandPlan: vi.fn(),
  getProposedPlans: vi.fn(),
  cancelAgent: vi.fn(),
  DashboardApiError: class DashboardApiError extends Error {
    status = 500;
  },
}));

const accepted = {
  command_id: 'planner-command-dom',
  idempotency_key: 'planner-command-dom',
  input_sha256: 'a'.repeat(64),
  command_kind: 'operator.plan',
  validated_input: { command: 'inspect the unusual host' },
  transport: 'dashboard',
  actor_task_id: null,
  status: 'accepted',
  created_at: '2000-01-01T00:00:00.000Z',
  entity_refs: { planner_task_id: 'planner-task-dom' },
} as api.ApplicationCommandRecord;

const plan: api.ProposedPlan = {
  plan_id: 'planner-plan-dom',
  command: 'inspect the unusual host',
  summary: 'Inspect the unusual host safely',
  ops: [{ op: 'scope', add_cidrs: ['10.44.0.0/24'] }],
  created_at: 1,
  expires_at: 999_999_999,
  status: 'open',
};

describe('OperatorCommandBar durable planner rendering', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    sessionStorage.clear();
    vi.mocked(api.getActiveApplicationCommands).mockResolvedValue({ commands: [accepted] });
    vi.mocked(api.getApplicationCommand).mockResolvedValue({ command: accepted });
    vi.mocked(api.getProposedPlans).mockResolvedValue({ plans: [plan] });
  });

  afterEach(() => vi.useRealTimers());

  it('renders a durable planner identity without undefined or a browser deadline', async () => {
    render(<OperatorCommandBar />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(screen.getByText(/planner lane is available/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('undefined');
    expect(document.body.textContent?.toLowerCase()).not.toContain('did not return a plan in time');

    vi.mocked(api.getApplicationCommand).mockResolvedValue({
      command: {
        ...accepted,
        status: 'succeeded',
        result: { phase: 'plan_ready', plan },
      },
    });
    await act(async () => {
      vi.advanceTimersByTime(POLL.PLAN_POLL_MS);
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByText(/Planner proposed:/)).toHaveTextContent(plan.summary);
    expect(screen.getByRole('button', { name: 'Confirm & run' })).toBeInTheDocument();
  });

  it('does not let late active-command discovery replace a newly submitted planner', async () => {
    let resolveDiscovery!: (value: { commands: api.ApplicationCommandRecord[] }) => void;
    vi.mocked(api.getActiveApplicationCommands).mockReturnValue(new Promise(resolve => {
      resolveDiscovery = resolve;
    }));
    const newCommand: api.ApplicationCommandRecord = {
      ...accepted,
      command_id: 'planner-command-new',
      entity_refs: { planner_task_id: 'planner-task-new' },
    };
    vi.mocked(api.previewCommand).mockResolvedValue({
      plan_id: undefined,
      ops: [],
      summary: 'Planner requested',
      unresolved: [{ text: 'investigate the new target', reason: 'planner needed' }],
      needs_planner: true,
      planner_task_id: 'planner-task-new',
      command_id: 'planner-command-new',
      planner_status: 'accepted',
      planner_available: true,
    });
    vi.mocked(api.getApplicationCommand).mockResolvedValue({ command: newCommand });

    render(<OperatorCommandBar />);
    fireEvent.change(screen.getByRole('textbox'), {
      target: { value: 'investigate the new target' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Send' }));
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(api.getApplicationCommand).toHaveBeenCalledWith(
      'planner-command-new',
      expect.any(AbortSignal),
    );

    await act(async () => {
      resolveDiscovery({ commands: [accepted] });
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(vi.mocked(api.getApplicationCommand).mock.calls
      .some(([commandId]) => commandId === accepted.command_id)).toBe(false);
    expect(screen.getByText(/Planner is queued/)).toBeInTheDocument();
  });

  it('polls arbitrarily long without a browser deadline and clears every timer on unmount', async () => {
    const view = render(<OperatorCommandBar />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });

    for (let index = 0; index < 40; index++) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(POLL.PLAN_POLL_MS);
      });
    }
    expect(api.getApplicationCommand).toHaveBeenCalledTimes(41);
    expect(screen.getByText(/Planner is queued/)).toBeInTheDocument();
    expect(document.body.textContent?.toLowerCase()).not.toContain('time out');

    view.unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('cancels an in-flight planner poll and ignores its stale response', async () => {
    let signal: AbortSignal | undefined;
    let resolveStatus!: (value: { command: api.ApplicationCommandRecord }) => void;
    let calls = 0;
    vi.mocked(api.getApplicationCommand).mockImplementation((_commandId, requestSignal) => {
      calls += 1;
      if (calls === 1) return Promise.resolve({ command: accepted });
      signal = requestSignal;
      return new Promise(resolve => { resolveStatus = resolve; });
    });
    vi.mocked(api.cancelAgent).mockResolvedValue({ ok: true });

    render(<OperatorCommandBar />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(POLL.PLAN_POLL_MS);
    });
    expect(signal?.aborted).toBe(false);
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
      await Promise.resolve();
    });
    expect(signal?.aborted).toBe(true);
    expect(screen.queryByText(/Planner is queued/)).not.toBeInTheDocument();

    await act(async () => {
      resolveStatus({
        command: {
          ...accepted,
          status: 'succeeded',
          result: { phase: 'plan_ready', plan },
        },
      });
      await Promise.resolve();
    });
    expect(screen.queryByText(/Planner proposed:/)).not.toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('shows canonical task identity after a confirmed dispatch', async () => {
    vi.mocked(api.getActiveApplicationCommands).mockResolvedValue({ commands: [] });
    vi.mocked(api.previewCommand).mockResolvedValue({
      plan_id: 'dispatch-plan',
      ops: [{ op: 'dispatch', target_node_ids: ['host-1'] }],
      summary: 'Deploy recon',
      unresolved: [],
      needs_planner: false,
    });
    vi.mocked(api.confirmCommand).mockResolvedValue({
      executed: true,
      results: [{
        op: { op: 'dispatch', target_node_ids: ['host-1'] },
        ok: true,
        task: {
          task_id: 'task-canonical',
          agent_label: 'recon-canonical',
          id: 'task-canonical',
          agent_id: 'recon-canonical',
        },
      }],
    });

    render(<OperatorCommandBar />);
    fireEvent.change(screen.getByRole('textbox'), {
      target: { value: 'deploy recon' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Send' }));
      await Promise.resolve();
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Confirm & run' }));
      await Promise.resolve();
    });
    expect(screen.getByText(/recon-canonical \(task-canonical\)/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('undefined');
  });

  it('summarizes every committed op when a dispatch and scope update succeed', async () => {
    vi.mocked(api.getActiveApplicationCommands).mockResolvedValue({ commands: [] });
    vi.mocked(api.previewCommand).mockResolvedValue({
      plan_id: 'mixed-success-plan',
      ops: [
        { op: 'scope', add_cidrs: ['10.55.0.0/24'] },
        { op: 'dispatch', target_node_ids: ['host-55'] },
      ],
      summary: 'Scope and deploy',
      unresolved: [],
      needs_planner: false,
    });
    vi.mocked(api.confirmCommand).mockResolvedValue({
      executed: true,
      results: [
        {
          op: { op: 'scope', add_cidrs: ['10.55.0.0/24'] },
          ok: true,
          detail: 'Scope updated with 10.55.0.0/24',
        },
        {
          op: { op: 'dispatch', target_node_ids: ['host-55'] },
          ok: true,
          task: {
            task_id: 'task-55', agent_label: 'recon-55', id: 'task-55', agent_id: 'recon-55',
          },
        },
      ],
    });

    render(<OperatorCommandBar />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'scope and deploy' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Send' }));
      await Promise.resolve();
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Confirm & run' }));
      await Promise.resolve();
    });
    expect(screen.getByText(/Executed 2\/2 op\(s\)/)).toHaveTextContent('deployed recon-55 (task-55)');
    expect(screen.getByText(/Executed 2\/2 op\(s\)/)).toHaveTextContent('Scope updated with 10.55.0.0/24');
  });

  it('reports committed successes alongside failures so the operator does not reissue them', async () => {
    vi.mocked(api.getActiveApplicationCommands).mockResolvedValue({ commands: [] });
    vi.mocked(api.previewCommand).mockResolvedValue({
      plan_id: 'partial-plan',
      ops: [
        { op: 'dispatch', target_node_ids: ['host-ok'] },
        { op: 'dispatch', target_node_ids: ['host-stale'] },
      ],
      summary: 'Deploy both',
      unresolved: [],
      needs_planner: false,
    });
    vi.mocked(api.confirmCommand).mockResolvedValue({
      executed: true,
      results: [
        {
          op: { op: 'dispatch', target_node_ids: ['host-ok'] },
          ok: true,
          task: {
            task_id: 'task-ok', agent_label: 'recon-ok', id: 'task-ok', agent_id: 'recon-ok',
          },
        },
        {
          op: { op: 'dispatch', target_node_ids: ['host-stale'] },
          ok: false,
          error: 'host-stale is no longer actionable',
        },
      ],
    });

    render(<OperatorCommandBar />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'deploy both' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Send' }));
      await Promise.resolve();
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Confirm & run' }));
      await Promise.resolve();
    });
    const result = screen.getByText(/Executed 1\/2 op\(s\)/);
    expect(result).toHaveTextContent('deployed recon-ok (task-ok)');
    expect(result).toHaveTextContent('failures: host-stale is no longer actionable');
  });

  it('aborts an unresolved proposed-plan reconciliation request on unmount', async () => {
    vi.mocked(api.getActiveApplicationCommands).mockResolvedValue({ commands: [] });
    vi.mocked(api.previewCommand).mockResolvedValue({
      plan_id: undefined,
      ops: [],
      summary: 'Planner returned a proposal',
      unresolved: [],
      needs_planner: true,
      planner_plan: plan,
      planner_available: true,
    });
    let signal: AbortSignal | undefined;
    vi.mocked(api.getProposedPlans).mockImplementation(requestSignal => {
      signal = requestSignal;
      return new Promise(() => {});
    });

    const view = render(<OperatorCommandBar />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'inspect target' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Send' }));
      await Promise.resolve();
    });
    expect(screen.getByText(/Planner proposed:/)).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(POLL.AGENTS_MS);
    });
    expect(signal?.aborted).toBe(false);
    view.unmount();
    expect(signal?.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('times out a hung proposed-plan reconciliation and retries it', async () => {
    vi.mocked(api.getActiveApplicationCommands).mockResolvedValue({ commands: [] });
    vi.mocked(api.previewCommand).mockResolvedValue({
      plan_id: undefined,
      ops: [],
      summary: 'Planner returned a proposal',
      unresolved: [],
      needs_planner: true,
      planner_plan: plan,
      planner_available: true,
    });
    const signals: AbortSignal[] = [];
    vi.mocked(api.getProposedPlans).mockImplementation(signal => new Promise((_resolve, reject) => {
      if (!signal) return;
      signals.push(signal);
      signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
    }));

    const view = render(<OperatorCommandBar />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'inspect target' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Send' }));
      await Promise.resolve();
    });
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL.AGENTS_MS); });
    expect(signals).toHaveLength(1);
    expect(signals[0].aborted).toBe(false);
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(signals[0].aborted).toBe(true);
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL.AGENTS_MS); });
    expect(signals).toHaveLength(2);
    view.unmount();
    expect(signals[1].aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
});
