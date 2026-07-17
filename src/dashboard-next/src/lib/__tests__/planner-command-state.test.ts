import { describe, expect, it } from 'vitest';
import type {
  ApplicationCommandRecord,
  ProposedPlan,
} from '../api';
import { projectPlannerCommand } from '../planner-command-state';

function command(
  overrides: Partial<ApplicationCommandRecord> = {},
): ApplicationCommandRecord {
  return {
    command_id: 'command-1',
    idempotency_key: 'plan-command-1',
    input_sha256: 'a'.repeat(64),
    command_kind: 'operator.plan',
    validated_input: { command: 'inspect the strange host' },
    transport: 'dashboard',
    actor_task_id: null,
    status: 'accepted',
    created_at: '2000-01-01T00:00:00.000Z',
    ...overrides,
  };
}

const plan: ProposedPlan = {
  plan_id: 'plan-1',
  command: 'inspect the strange host',
  ops: [{ op: 'scope', add_cidrs: ['10.20.30.0/24'] }],
  summary: 'Inspect the strange host',
  created_at: 1,
  expires_at: 600_001,
  status: 'open',
};

describe('projectPlannerCommand', () => {
  it('keeps an arbitrarily old accepted planner queued instead of timing it out', () => {
    expect(projectPlannerCommand(command({
      entity_refs: { planner_task_id: 'planner-task-1' },
    }))).toEqual({
      kind: 'planning',
      plannerTaskId: 'planner-task-1',
      phase: 'planning_queued',
    });
  });

  it('keeps a durable running planner active', () => {
    expect(projectPlannerCommand(command({
      status: 'running',
      result: {
        phase: 'planning_running',
        planner_task_id: 'planner-task-2',
      },
    }))).toEqual({
      kind: 'planning',
      plannerTaskId: 'planner-task-2',
      phase: 'planning_running',
    });
  });

  it('returns the exact proposed plan from the successful command', () => {
    expect(projectPlannerCommand(command({
      status: 'succeeded',
      result: { phase: 'plan_ready', plan },
    }))).toEqual({ kind: 'proposed', plan });
  });

  it('renders durable terminal failure details', () => {
    expect(projectPlannerCommand(command({
      status: 'failed',
      error: {
        code: 'PLANNER_NO_PLAN',
        message: 'Planner completed without returning a plan.',
      },
    }))).toEqual({
      kind: 'error',
      text: 'Planner completed without returning a plan.',
    });
  });

  it('does not render an expired embedded plan as confirmable', () => {
    expect(projectPlannerCommand(command({
      status: 'succeeded',
      result: { phase: 'plan_expired', plan_id: 'plan-1' },
    }))).toEqual({
      kind: 'error',
      text: 'The proposed plan expired before confirmation. Send the command again.',
    });
  });
});
