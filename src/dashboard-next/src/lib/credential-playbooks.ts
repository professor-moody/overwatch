import type { PlaybookRun } from './types';

export interface PreparedExecution {
  run_id: string;
  step_id: string;
  attempt_id: string;
  execution: Record<string, unknown>;
}

export function groupPlaybookRunsByCredential(runs: PlaybookRun[]): Map<string, PlaybookRun[]> {
  const grouped = new Map<string, PlaybookRun[]>();
  for (const run of [...runs].sort((left, right) => right.updated_at.localeCompare(left.updated_at))) {
    grouped.set(run.credential_id, [...(grouped.get(run.credential_id) || []), run]);
  }
  return grouped;
}

export function preparedExecutionIsClaimed(prepared: PreparedExecution, runs: PlaybookRun[]): boolean {
  const step = runs.find(run => run.run_id === prepared.run_id)
    ?.steps.find(candidate => candidate.step_id === prepared.step_id);
  return step?.attempts.some(attempt =>
    attempt.attempt_id === prepared.attempt_id && attempt.status === 'claimed') === true;
}
