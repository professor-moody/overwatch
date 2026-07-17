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
    expect(screen.getByText(/Planner is queued/)).toBeInTheDocument();
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
});
