import { describe, expect, it } from 'vitest';
import type { PlaybookRun } from '../../../lib/types';
import {
  groupPlaybookRunsByCredential,
  preparedExecutionIsClaimed,
  type PreparedExecution,
} from '../CredentialsPanel';

function run(runId: string, credentialId: string, updatedAt: string): PlaybookRun {
  return {
    schema_version: 1,
    run_id: runId,
    definition: {
      definition_id: 'test', definition_version: 1, provider: 'aws', title: 'Test',
    },
    credential_id: credentialId,
    input_hash: 'a'.repeat(64),
    normalized_inputs: {},
    bindings: {},
    plan_revisions: [{ revision: 1, created_at: updatedAt, plan_hash: 'b'.repeat(64), steps: [] }],
    current_plan_revision: 1,
    steps: [],
    status: 'pending',
    report_status: 'generated',
    created_at: updatedAt,
    updated_at: updatedAt,
    resume_count: 0,
  };
}

describe('Credentials playbook grouping', () => {
  it('retains every run for a credential in newest-first order without cross-credential leakage', () => {
    const grouped = groupPlaybookRunsByCredential([
      run('older', 'cred-a', '2026-07-16T00:00:00Z'),
      run('other', 'cred-b', '2026-07-16T00:02:00Z'),
      run('newer', 'cred-a', '2026-07-16T00:01:00Z'),
    ]);
    expect(grouped.get('cred-a')?.map(candidate => candidate.run_id)).toEqual(['newer', 'older']);
    expect(grouped.get('cred-b')?.map(candidate => candidate.run_id)).toEqual(['other']);
  });

  it('shows a prepared descriptor only while its exact attempt remains claimed', () => {
    const prepared: PreparedExecution = {
      run_id: 'run-claim', step_id: 'step-claim', attempt_id: 'attempt-claim',
      execution: { command: 'echo claimed' },
    };
    const claimed = run('run-claim', 'cred-a', '2026-07-16T00:00:00Z');
    claimed.steps = [{
      step_id: 'step-claim', ordinal: 1, description: 'Claimed', status: 'pending',
      depends_on: [], required_bindings: [], produces_bindings: [], resolved_bindings: {},
      attempts: [{
        attempt_id: 'attempt-claim', attempt_number: 1, status: 'claimed',
        started_at: '2026-07-16T00:00:00Z', claimed_via: 'dashboard',
        execution_command_id: 'command-1', execution_idempotency_key: 'idem-1',
        execution_action_id: 'action-1', plan_revision: 1,
        execution_template_hash: 'c'.repeat(64), evidence_ids: [], finding_ids: [],
      }],
      updated_at: '2026-07-16T00:00:00Z',
    }];
    expect(preparedExecutionIsClaimed(prepared, [claimed])).toBe(true);
    claimed.steps[0].attempts[0].status = 'succeeded';
    expect(preparedExecutionIsClaimed(prepared, [claimed])).toBe(false);
    expect(preparedExecutionIsClaimed(prepared, [run('other', 'cred-a', '2026-07-16T00:00:00Z')])).toBe(false);
  });
});
