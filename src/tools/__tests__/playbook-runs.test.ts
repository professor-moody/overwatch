import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { withApplicationCommandInvocation } from '../../services/application-command-service.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { PlaybookRunService } from '../../services/playbook-run-service.js';
import { registerPlaybookRunTools } from '../playbook-runs.js';

function parse(result: any): any {
  return JSON.parse(result.content[0].text);
}

describe('playbook run MCP tools', () => {
  let directory: string;
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-playbook-tools-'));
    engine = new GraphEngine({
      id: 'playbook-tools', name: 'Playbook tools', created_at: '2026-07-16T00:00:00.000Z',
      scope: { cidrs: [], domains: [], exclusions: [] }, objectives: [],
      opsec: { name: 'pentest', max_noise: 0.7 },
    }, join(directory, 'state.json'));
    handlers = {};
    registerPlaybookRunTools({
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer, engine);
  });

  afterEach(() => {
    engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  it('completes an executed attempt with strict public parameters and replays it', async () => {
    const runs = new PlaybookRunService(engine);
    const opened = runs.open({
      definition: {
        definition_id: 'public-completion', definition_version: 1,
        provider: 'aws', title: 'Public completion',
      },
      credential_id: 'cred-public', normalized_inputs: {},
      steps: [{
        step_id: 'identity', description: 'Resolve identity', runner: 'run_bash',
        command: 'identity-command', ready: true, status: 'ready',
      }],
    });
    const claim = runs.startStep(opened.run.run_id, 'identity');
    runs.beginAttemptExecution(claim.execution);
    const evidenceId = engine.getEvidenceStore().store({
      action_id: claim.attempt.execution_action_id,
      evidence_type: 'command_output',
      raw_output: 'durable public completion evidence',
    });
    engine.logActionEvent({
      action_id: claim.attempt.execution_action_id,
      event_type: 'action_completed',
      description: 'Public completion action reached terminal state',
      category: 'frontier',
      result_classification: 'success',
    });
    engine.logActionEvent({
      action_id: claim.attempt.execution_action_id,
      event_type: 'finding_ingested',
      description: 'Public completion finding landed',
      category: 'finding',
      linked_finding_ids: ['finding-public'],
      result_classification: 'success',
    });
    const request = {
      run_id: opened.run.run_id,
      step_id: 'identity',
      attempt_id: claim.attempt.attempt_id,
      task_id: 'task-public',
      execution_outcome: 'succeeded',
      parse_outcome: 'ok',
      action_id: claim.attempt.execution_action_id,
      evidence_ids: [evidenceId],
      finding_ids: ['finding-public'],
    };

    const first = await handlers.complete_playbook_attempt(request);
    expect(first.isError).toBeFalsy();
    expect(parse(first).run.steps[0].attempts[0]).toMatchObject({
      status: 'succeeded', evidence_ids: [evidenceId], finding_ids: ['finding-public'],
    });
    const replay = await handlers.complete_playbook_attempt(request);
    expect(parse(replay)).toEqual(parse(first));
    expect(runs.getDurable(opened.run.run_id).steps[0].attempts).toHaveLength(1);
  });

  it('rejects unowned proof references and premature success without changing the attempt', async () => {
    const runs = new PlaybookRunService(engine);
    const opened = runs.open({
      definition: {
        definition_id: 'public-proof-validation', definition_version: 1,
        provider: 'aws', title: 'Public proof validation',
      },
      credential_id: 'cred-proof', normalized_inputs: {},
      steps: [{
        step_id: 'identity', description: 'Resolve identity', runner: 'run_bash',
        command: 'identity-command', ready: true, status: 'ready',
      }],
    });
    const claim = runs.startStep(opened.run.run_id, 'identity');
    runs.markAttemptExecutionState(claim.execution, 'awaiting_approval');
    const premature = await handlers.complete_playbook_attempt({
      run_id: opened.run.run_id,
      step_id: 'identity',
      attempt_id: claim.attempt.attempt_id,
      execution_outcome: 'succeeded',
      action_id: claim.attempt.execution_action_id,
      evidence_ids: [],
      finding_ids: [],
    });
    expect(premature.isError).toBe(true);
    expect(parse(premature).error).toContain('success requires a running attempt');
    expect(runs.getDurable(opened.run.run_id).steps[0].attempts[0].status).toBe('awaiting_approval');

    runs.markAttemptExecutionState(claim.execution, 'running');
    const noTerminal = await handlers.complete_playbook_attempt({
      run_id: opened.run.run_id,
      step_id: 'identity',
      attempt_id: claim.attempt.attempt_id,
      execution_outcome: 'succeeded',
      action_id: claim.attempt.execution_action_id,
      evidence_ids: [],
      finding_ids: [],
    });
    expect(noTerminal.isError).toBe(true);
    expect(parse(noTerminal).error).toContain('durable terminal event');

    engine.logActionEvent({
      action_id: claim.attempt.execution_action_id,
      event_type: 'action_completed',
      description: 'Proof validation action completed',
      category: 'frontier',
      result_classification: 'success',
    });
    const foreignEvidence = engine.getEvidenceStore().store({
      action_id: 'another-action', evidence_type: 'command_output', raw_output: 'foreign',
    });
    const foreign = await handlers.complete_playbook_attempt({
      run_id: opened.run.run_id,
      step_id: 'identity',
      attempt_id: claim.attempt.attempt_id,
      execution_outcome: 'succeeded',
      action_id: claim.attempt.execution_action_id,
      evidence_ids: [foreignEvidence],
      finding_ids: ['missing-finding'],
    });
    expect(foreign.isError).toBe(true);
    expect(parse(foreign).error).toContain('is not a durable artifact');
    const ownedEvidence = engine.getEvidenceStore().store({
      action_id: claim.attempt.execution_action_id,
      evidence_type: 'command_output',
      raw_output: 'owned evidence with no matching finding',
    });
    const missingFinding = await handlers.complete_playbook_attempt({
      run_id: opened.run.run_id,
      step_id: 'identity',
      attempt_id: claim.attempt.attempt_id,
      execution_outcome: 'succeeded',
      action_id: claim.attempt.execution_action_id,
      evidence_ids: [ownedEvidence],
      finding_ids: ['missing-finding'],
    });
    expect(missingFinding.isError).toBe(true);
    expect(parse(missingFinding).error).toContain('is not durably attributed');
    expect(runs.getDurable(opened.run.run_id).steps[0].attempts[0]).toMatchObject({
      status: 'running', evidence_ids: [], finding_ids: [],
    });
  });

  it('surfaces cross-surface ownership instead of letting MCP steal a dashboard claim', async () => {
    const runs = new PlaybookRunService(engine);
    const opened = runs.open({
      definition: {
        definition_id: 'surface-ownership', definition_version: 1,
        provider: 'github', title: 'Surface ownership',
      },
      credential_id: 'cred-shared', normalized_inputs: {},
      steps: [{
        step_id: 'repositories', description: 'List repositories', runner: 'run_bash',
        command: 'gh api /user/repos', ready: true, status: 'ready',
      }],
    });
    withApplicationCommandInvocation({
      transport: 'dashboard', actor_task_id: 'task-dashboard', request_id: 'dashboard-claim',
    }, () => runs.startStep(opened.run.run_id, 'repositories'));

    const conflict = await withApplicationCommandInvocation({
      transport: 'mcp', actor_task_id: 'task-claude', request_id: 'mcp-claim',
    }, () => handlers.start_playbook_step({
      run_id: opened.run.run_id, step_id: 'repositories', task_id: 'task-claude',
    }));
    expect(conflict.isError).toBe(true);
    expect(parse(conflict)).toMatchObject({ code: 'PLAYBOOK_CONFLICT' });
    expect(parse(conflict).error).toContain('task-dashboard via dashboard');

    const released = await handlers.interrupt_playbook_attempt({
      run_id: opened.run.run_id, step_id: 'repositories', reason: 'Dashboard abandoned the prepared descriptor.',
    });
    expect(parse(released).run.status).toBe('interrupted');
    const retry = await withApplicationCommandInvocation({
      transport: 'mcp', actor_task_id: 'task-claude', request_id: 'mcp-retry',
    }, () => handlers.retry_playbook_step({
      run_id: opened.run.run_id, step_id: 'repositories', task_id: 'task-claude',
    }));
    expect(parse(retry).attempt).toMatchObject({
      attempt_number: 2, claimed_via: 'mcp', claimed_by_task_id: 'task-claude',
    });
  });
});
