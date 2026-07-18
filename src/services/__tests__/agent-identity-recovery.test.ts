import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig } from '../../types.js';

function config(): EngagementConfig {
  return {
    id: 'agent-identity-recovery',
    name: 'Agent identity recovery',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'test', max_noise: 1 },
  };
}

describe('agent identity recovery', () => {
  let directory: string | undefined;

  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = undefined;
  });

  it('normalizes task aliases and preserves ambiguous legacy relationships as warnings', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-agent-identity-'));
    const stateFile = join(directory, 'state.json');
    const first = new GraphEngine(config(), stateFile);
    for (const id of ['task-a', 'task-b']) {
      first.registerAgent({
        id,
        agent_id: 'shared-label',
        assigned_at: '2026-07-16T01:00:00.000Z',
        status: 'completed',
        subgraph_node_ids: [],
      });
    }
    first.persistImmediate();
    first.dispose();

    const state = JSON.parse(readFileSync(stateFile, 'utf8'));
    const now = Date.now();
    state.agentDirectives = [[
      'shared-label',
      [{
        id: 'directive-legacy',
        task_id: 'shared-label',
        kind: 'pause',
        issued_by: 'operator',
        issued_at: '2026-07-16T01:05:00.000Z',
        status: 'pending',
      }],
    ]];
    state.approvalRequests = [[
      'approval-legacy',
      {
        action_id: 'approval-legacy',
        submitted_at: '2026-07-16T01:06:00.000Z',
        timeout_at: '2026-07-16T01:11:00.000Z',
        description: 'legacy approval',
        opsec_context: {},
        validation_result: 'valid',
        status: 'pending',
        agent_id: 'shared-label',
      },
    ]];
    state.runtimeRuns = [{
      run_id: 'run-legacy',
      kind: 'headless_agent',
      agent_id: 'shared-label',
      started_at: '2026-07-16T01:07:00.000Z',
      lifecycle: 'unknown',
    }];
    state.sessionDescriptors = [{
      session_id: 'session-legacy',
      kind: 'socket',
      transport: 'tcp',
      lifecycle: 'closed',
      title: 'legacy session',
      owner_task_id: 'shared-label',
      started_at: '2026-07-16T01:08:00.000Z',
      last_activity_at: '2026-07-16T01:09:00.000Z',
      closed_at: '2026-07-16T01:09:00.000Z',
      capabilities: {
        has_stdin: false,
        has_stdout: true,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'none',
      },
      resume_intent: {
        policy: 'none',
        requested: false,
        recorded_at: '2026-07-16T01:09:00.000Z',
      },
    }];
    state.proposedPlans = {
      plans: [{
        plan_id: 'plan-legacy',
        command: 'pause task-a',
        ops: [{ op: 'directive', task_id: 'task-a', agent_label: 'shared-label', kind: 'pause' }],
        summary: 'legacy plan',
        source_task_id: 'shared-label',
        source_agent_id: 'shared-label',
        created_at: now,
        expires_at: now + 60_000,
        status: 'open',
      }],
      tombstones: [],
    };
    state.agentQueries = {
      queries: [
        {
          query_id: 'query-legacy',
          task_id: 'shared-label',
          agent_id: 'shared-label',
          question: 'continue?',
          status: 'open',
          created_at: now,
          expires_at: now + 60_000,
        },
        {
          query_id: 'query-orphan',
          agent_id: 'orphan-label',
          question: 'is anyone there?',
          status: 'open',
          created_at: now,
          expires_at: now + 60_000,
        },
      ],
    };
    delete state.walCompactionAuthority;
    writeFileSync(stateFile, JSON.stringify(state));

    const recovered = new GraphEngine(config(), stateFile);
    expect(recovered.getAgentTasks()).toEqual(expect.arrayContaining([
      expect.objectContaining({
        task_id: 'task-a',
        agent_label: 'shared-label',
        id: 'task-a',
        agent_id: 'shared-label',
      }),
      expect.objectContaining({
        task_id: 'task-b',
        agent_label: 'shared-label',
      }),
    ]));
    expect(recovered.getProposedPlanStore().get('plan-legacy')).toMatchObject({
      source_agent_id: 'shared-label',
      recovery_warning: expect.stringContaining('ambiguous'),
    });
    expect(recovered.getProposedPlanStore().get('plan-legacy')?.owner_task_id).toBeUndefined();
    expect(recovered.getAgentQueryStore().get('query-legacy')).toMatchObject({
      agent_id: 'shared-label',
      recovery_warning: expect.stringContaining('ambiguous'),
    });
    expect(recovered.getAgentQueryStore().get('query-legacy')?.owner_task_id).toBeUndefined();
    expect(recovered.getAgentQueryStore().get('query-orphan')).toMatchObject({
      agent_id: 'orphan-label',
      recovery_warning: expect.stringContaining('could not be resolved'),
    });
    expect(recovered.getAgentQueryStore().get('query-orphan')?.owner_task_id).toBeUndefined();
    expect(recovered.getSessionDescriptors()[0]).toMatchObject({
      recovery_warning: expect.stringContaining('ambiguous'),
    });
    expect(recovered.getSessionDescriptors()[0].owner_task_id).toBeUndefined();
    expect(recovered.getRuntimeRuns()[0]).toMatchObject({
      recovery_warning: expect.stringContaining('ambiguous'),
    });
    expect(recovered.getRuntimeRuns()[0].task_id).toBeUndefined();
    expect(recovered.getPendingAgentDirective('task-a')).toBeNull();
    expect(recovered.getPendingAgentDirective('task-b')).toBeNull();

    const warnings = recovered.getPersistenceRecoveryStatus().coordination_warnings ?? [];
    expect(warnings.map(warning => warning.relationship)).toEqual(expect.arrayContaining([
      'directive:directive-legacy',
      'approval:approval-legacy',
      'runtime_run:run-legacy',
      'session:session-legacy',
      'plan:plan-legacy',
      'agent_query:query-legacy',
      'agent_query:query-orphan',
    ]));
    for (const warning of warnings.filter(warning => warning.reference === 'shared-label')) {
      expect(warning.candidate_task_ids).toEqual(['task-a', 'task-b']);
    }
    const orphanWarning = warnings.find(warning => warning.reference === 'orphan-label');
    expect(orphanWarning).toMatchObject({
      relationship: 'agent_query:query-orphan',
    });
    expect(orphanWarning?.candidate_task_ids).toBeUndefined();

    recovered.persistImmediate();
    recovered.dispose();
    const secondRestart = new GraphEngine(config(), stateFile);
    expect(secondRestart.getPersistenceRecoveryStatus().coordination_warnings?.length)
      .toBe(warnings.length);
    secondRestart.dispose();
  });

  it('migrates a unique legacy label to the canonical task id', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-agent-identity-unique-'));
    const stateFile = join(directory, 'state.json');
    const first = new GraphEngine(config(), stateFile);
    first.registerAgent({
      id: 'task-only',
      agent_id: 'legacy-only',
      assigned_at: '2026-07-16T01:00:00.000Z',
      status: 'completed',
      subgraph_node_ids: [],
    });
    first.persistImmediate();
    first.dispose();

    const state = JSON.parse(readFileSync(stateFile, 'utf8'));
    const now = Date.now();
    state.agentQueries = {
      queries: [{
        query_id: 'query-unique',
        task_id: 'legacy-only',
        agent_id: 'legacy-only',
        question: 'continue?',
        status: 'open',
        created_at: now,
        expires_at: now + 60_000,
      }],
    };
    delete state.walCompactionAuthority;
    writeFileSync(stateFile, JSON.stringify(state));

    const recovered = new GraphEngine(config(), stateFile);
    expect(recovered.getAgentQueryStore().get('query-unique')).toMatchObject({
      owner_task_id: 'task-only',
      owner_agent_label: 'legacy-only',
      task_id: 'task-only',
      agent_id: 'legacy-only',
    });
    expect(recovered.getPersistenceRecoveryStatus().coordination_warnings).toBeUndefined();
    recovered.dispose();
  });

  it('clears a runtime ambiguity marker when a later restart resolves one unique owner', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-agent-identity-runtime-resolution-'));
    const stateFile = join(directory, 'state.json');
    const first = new GraphEngine(config(), stateFile);
    for (const id of ['task-a', 'task-b']) {
      first.registerAgent({
        id,
        agent_id: 'shared-runtime-label',
        assigned_at: '2026-07-16T01:00:00.000Z',
        status: 'completed',
        subgraph_node_ids: [],
      });
    }
    first.persistImmediate();
    first.dispose();

    const state = JSON.parse(readFileSync(stateFile, 'utf8'));
    state.runtimeRuns = [{
      run_id: 'run-resolves-later',
      kind: 'headless_agent',
      agent_id: 'shared-runtime-label',
      started_at: '2026-07-16T01:07:00.000Z',
      lifecycle: 'unknown',
    }];
    delete state.walCompactionAuthority;
    writeFileSync(stateFile, JSON.stringify(state));

    const ambiguous = new GraphEngine(config(), stateFile);
    expect(ambiguous.getRuntimeRuns()[0]).toMatchObject({
      recovery_warning: expect.stringContaining('ambiguous'),
    });
    expect(ambiguous.getRuntimeRuns()[0]?.task_id).toBeUndefined();
    expect(ambiguous.getAgentWorkTransferBlockers('task-a')).toContain('unresolved_ownership');
    expect(ambiguous.getAgentWorkTransferBlockers('task-b')).toContain('unresolved_ownership');
    expect(ambiguous.dismissAgent('task-b')).toBe(true);
    ambiguous.persistImmediate();
    ambiguous.dispose();

    const resolved = new GraphEngine(config(), stateFile);
    expect(resolved.getRuntimeRuns()[0]).toMatchObject({
      task_id: 'task-a',
      agent_id: 'shared-runtime-label',
    });
    expect(resolved.getRuntimeRuns()[0]?.recovery_warning).toBeUndefined();
    expect(resolved.getAgentWorkTransferBlockers('task-a')).toContain('runtime_run');
    expect(resolved.getAgentWorkTransferBlockers('task-a')).not.toContain('unresolved_ownership');
    expect(resolved.getAgentWorkTransferBlockers('task-b')).not.toContain('unresolved_ownership');
    // The original warning remains available as recovery audit history; it no
    // longer acts as a live ownership lock after exact resolution.
    expect(resolved.getPersistenceRecoveryStatus().coordination_warnings)
      .toEqual(expect.arrayContaining([
        expect.objectContaining({ relationship: 'runtime_run:run-resolves-later' }),
      ]));
    resolved.dispose();
  });
});
