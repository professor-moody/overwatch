import type {
  ApplicationCommandRecord,
  ProposedPlan,
} from './api';

export type PlannerCommandView =
  | {
      kind: 'planning';
      plannerTaskId?: string;
      phase: 'planning_queued' | 'planning_running';
    }
  | { kind: 'proposed'; plan: ProposedPlan }
  | { kind: 'error'; text: string };

function commandResult(
  command: ApplicationCommandRecord,
): Record<string, unknown> | undefined {
  return command.result && typeof command.result === 'object'
    ? command.result as Record<string, unknown>
    : undefined;
}

function plannerTaskId(
  command: ApplicationCommandRecord,
  fallback?: string,
): string | undefined {
  const result = commandResult(command);
  if (typeof result?.planner_task_id === 'string') {
    return result.planner_task_id;
  }
  const referenced = command.entity_refs?.planner_task_id;
  if (typeof referenced === 'string') return referenced;
  return fallback;
}

/**
 * Project durable planner-command truth into the command-bar state.
 *
 * Deliberately contains no wall-clock deadline: an accepted planner can remain
 * queued behind the agent cap, and a running planner can reason for as long as
 * its supervised process remains live. Only a durable terminal command status
 * is rendered as success or failure.
 */
export function projectPlannerCommand(
  command: ApplicationCommandRecord,
  fallbackTaskId?: string,
): PlannerCommandView {
  const resolvedTaskId = plannerTaskId(command, fallbackTaskId);
  if (command.status === 'accepted') {
    return {
      kind: 'planning',
      plannerTaskId: resolvedTaskId,
      phase: 'planning_queued',
    };
  }
  if (command.status === 'running') {
    return {
      kind: 'planning',
      plannerTaskId: resolvedTaskId,
      phase: 'planning_running',
    };
  }

  const result = commandResult(command);
  if (command.status === 'succeeded') {
    const plan = result?.plan;
    if (
      plan
      && typeof plan === 'object'
      && typeof (plan as ProposedPlan).plan_id === 'string'
    ) {
      return { kind: 'proposed', plan: plan as ProposedPlan };
    }
    return {
      kind: 'error',
      text: 'Planner completed, but its proposed plan is unavailable.',
    };
  }

  return {
    kind: 'error',
    text: command.error?.message
      ?? (command.status === 'interrupted'
        ? 'The planner was interrupted before returning a plan.'
        : 'The planner could not return a plan.'),
  };
}
