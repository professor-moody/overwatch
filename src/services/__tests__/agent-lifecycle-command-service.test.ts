import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AgentTask, EngagementConfig } from '../../types.js';
import {
  AgentLifecycleCommandError,
  AgentLifecycleCommandService,
} from '../agent-lifecycle-command-service.js';
import { GraphEngine } from '../graph-engine.js';

function config(): EngagementConfig {
  return {
    id: 'agent-command-test',
    name: 'agent command test',
    created_at: new Date().toISOString(),
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'test', enabled: false, max_noise: 1 },
  } as EngagementConfig;
}

function task(overrides: Partial<AgentTask> = {}): AgentTask {
  return {
    id: 'task-1',
    task_id: 'task-1',
    agent_id: 'agent-1',
    agent_label: 'agent-1',
    assigned_at: new Date().toISOString(),
    status: 'running',
    subgraph_node_ids: [],
    ...overrides,
  };
}

describe('AgentLifecycleCommandService', () => {
  let dir: string;
  let stateFile: string;
  let engine: GraphEngine;
  let service: AgentLifecycleCommandService;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-agent-command-'));
    stateFile = join(dir, 'state.json');
    engine = new GraphEngine(config(), stateFile);
    expect(engine.registerAgent(task()).ok).toBe(true);
    service = new AgentLifecycleCommandService(engine);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('records and replays a transcript without putting raw JSONL in command state', () => {
    const metadata = {
      transport: 'mcp' as const,
      command_id: 'transcript-command',
      idempotency_key: 'transcript-attempt',
    };
    const first = service.submitTranscript({
      task_reference: 'task-1',
      summary: 'Found the useful path.',
      transcript_jsonl: '{"secret":"only-in-evidence"}\n',
    }, metadata);
    const replay = service.submitTranscript({
      task_reference: 'task-1',
      summary: 'Found the useful path.',
      transcript_jsonl: '{"secret":"only-in-evidence"}\n',
    }, metadata);

    expect(replay.replayed).toBe(true);
    expect(replay.result).toEqual(first.result);
    expect(JSON.stringify(engine.getApplicationCommandById('transcript-command')))
      .not.toContain('only-in-evidence');
    expect(engine.getEvidenceStore().getContent(first.result?.evidence_id ?? ''))
      .toContain('only-in-evidence');
  });

  it('records transcript bytes as UTF-8 bytes rather than characters', () => {
    const transcript = '{"note":"résumé 🛰️"}\n';
    const execution = service.submitTranscript({
      task_reference: 'task-1',
      summary: 'Unicode transcript.',
      transcript_jsonl: transcript,
    }, {
      command_id: 'unicode-transcript-command',
      idempotency_key: 'unicode-transcript-attempt',
    });

    expect(execution.result?.transcript_bytes)
      .toBe(Buffer.byteLength(transcript, 'utf8'));
  });

  it('replays a canonical transcript after the task has been dismissed', () => {
    const metadata = {
      command_id: 'dismissed-transcript-command',
      idempotency_key: 'dismissed-transcript-attempt',
    };
    const input = {
      task_reference: 'task-1',
      summary: 'Final handoff.',
      transcript_jsonl: '{"done":true}\n',
    };
    const first = service.submitTranscript(input, metadata);
    engine.updateAgentStatus('task-1', 'completed', 'done');
    expect(engine.dismissAgent('task-1')).toBe(true);

    const replay = service.submitTranscript(input, metadata);
    expect(replay).toMatchObject({
      replayed: true,
      result: first.result,
    });
  });

  it('updates lifecycle and emits the missing-transcript warning exactly once on replay', () => {
    const metadata = {
      transport: 'mcp' as const,
      command_id: 'complete-command',
      idempotency_key: 'complete-attempt',
    };
    const first = service.updateStatus({
      task_id: 'task-1',
      status: 'completed',
      summary: 'done',
    }, metadata);
    const replay = service.updateStatus({
      task_id: 'task-1',
      status: 'completed',
      summary: 'done',
    }, metadata);

    expect(first.result?.transcript_warning).toBeTruthy();
    expect(replay.replayed).toBe(true);
    expect(engine.getFullHistory().filter(entry =>
      (entry.details as { warning?: string } | undefined)?.warning
        === 'missing_agent_transcript')).toHaveLength(1);
  });

  it('delivers and acknowledges question answers through durable heartbeats', () => {
    const asked = service.askQuestion({
      task_id: 'task-1',
      question: 'Proceed?',
    }, {
      transport: 'mcp',
      command_id: 'ask-command',
      idempotency_key: 'ask-attempt',
    });
    const queryId = asked.result!.query.query_id;
    service.answerQuestions({
      query_ids: [queryId],
      answer: 'Proceed carefully.',
    }, {
      transport: 'dashboard',
      command_id: 'answer-command',
      idempotency_key: 'answer-attempt',
    });
    const delivered = service.heartbeat({ task_id: 'task-1' }, {
      transport: 'mcp',
      command_id: 'heartbeat-command',
      idempotency_key: 'heartbeat-attempt',
    });
    expect(delivered.result?.pending_answer).toMatchObject({
      query_id: queryId,
      answer: 'Proceed carefully.',
    });
    service.heartbeat({
      task_id: 'task-1',
      acknowledged_query_id: queryId,
    }, {
      transport: 'mcp',
      command_id: 'heartbeat-ack-command',
      idempotency_key: 'heartbeat-ack-attempt',
    });
    expect(engine.getAgentQueryStore().get(queryId)?.acknowledged_at).toBeDefined();
  });

  it('issues and acknowledges one directive with durable replay', () => {
    const issued = service.issueDirective({
      task_id: 'task-1',
      kind: 'instruct',
      note: 'Focus on SMB.',
    }, {
      transport: 'dashboard',
      command_id: 'directive-command',
      idempotency_key: 'directive-attempt',
    });
    const directiveId = issued.result!.directive.id;
    const acknowledged = service.acknowledgeDirective({
      task_id: 'task-1',
      directive_id: directiveId,
    }, {
      transport: 'mcp',
      command_id: 'directive-ack-command',
      idempotency_key: 'directive-ack-attempt',
    });
    expect(acknowledged.result?.directive.status).toBe('acknowledged');
    engine.updateAgentStatus('task-1', 'completed', 'done');
    expect(service.issueDirective({
      task_id: 'task-1',
      kind: 'instruct',
      note: 'Focus on SMB.',
    }, {
      transport: 'dashboard',
      command_id: 'directive-command',
      idempotency_key: 'directive-attempt',
    }).replayed).toBe(true);
  });

  it('rejects an answer after the asking agent is terminal', () => {
    const asked = service.askQuestion({
      task_id: 'task-1',
      question: 'Proceed?',
    }, {
      transport: 'mcp',
      command_id: 'ask-terminal-command',
      idempotency_key: 'ask-terminal-attempt',
    });
    engine.updateAgentStatus('task-1', 'interrupted', 'stopped');
    expect(() => service.answerQuestions({
      query_ids: [asked.result!.query.query_id],
      answer: 'Too late.',
    }, {
      transport: 'dashboard',
      command_id: 'answer-terminal-command',
      idempotency_key: 'answer-terminal-attempt',
    })).toThrowError(AgentLifecycleCommandError);
  });

  it('cancels a process once per idempotency key and permits a new cleanup attempt', () => {
    let kills = 0;
    service.setRuntimeController({
      cancelHeadless: () => {
        kills++;
        return true;
      },
    });
    const metadata = {
      transport: 'dashboard' as const,
      command_id: 'cancel-command',
      idempotency_key: 'cancel-attempt',
    };
    const first = service.cancel('task-1', 'operator cancel', metadata);
    const replay = service.cancel('task-1', 'operator cancel', metadata);
    expect(first.result).toMatchObject({
      cancelled: true,
      already_terminal: false,
      process_killed: true,
    });
    expect(replay.replayed).toBe(true);
    expect(kills).toBe(1);

    const cleanup = service.cancel('task-1', 'retry zombie cleanup', {
      transport: 'dashboard',
      command_id: 'cancel-command-2',
      idempotency_key: 'cancel-attempt-2',
    });
    expect(cleanup.result?.already_terminal).toBe(true);
    expect(kills).toBe(2);
  });

  it('keeps durable terminal truth when process cancellation fails', () => {
    service.setRuntimeController({
      cancelHeadless: () => {
        throw new Error('kill denied');
      },
    });
    expect(() => service.cancel('task-1', 'operator cancel', {
      transport: 'dashboard',
      command_id: 'cancel-failed-command',
      idempotency_key: 'cancel-failed-attempt',
    })).toThrowError(AgentLifecycleCommandError);
    expect(engine.getTask('task-1')?.status).toBe('interrupted');
    expect(engine.getApplicationCommandById('cancel-failed-command')).toMatchObject({
      status: 'failed',
      error: { code: 'AGENT_PROCESS_CANCEL_FAILED' },
    });
  });

  it('force-dismiss cancels before removing the roster entry', () => {
    const observed: Array<'cancel' | 'dismissed'> = [];
    service.setRuntimeController({
      cancelHeadless: taskId => {
        expect(engine.getTask(taskId)).toBeTruthy();
        observed.push('cancel');
        return true;
      },
    });
    const result = service.dismiss('task-1', true, {
      transport: 'dashboard',
      command_id: 'force-dismiss-command',
      idempotency_key: 'force-dismiss-attempt',
    });
    if (!engine.getTask('task-1')) observed.push('dismissed');
    expect(result.result).toMatchObject({
      dismissed: true,
      task_id: 'task-1',
      forced: true,
    });
    expect(observed).toEqual(['cancel', 'dismissed']);
  });

  it('replays fleet directives and fleet dismissals without duplicate mutations', () => {
    expect(engine.registerAgent(task({
      id: 'task-2',
      task_id: 'task-2',
      agent_id: 'agent-2',
      agent_label: 'agent-2',
    })).ok).toBe(true);
    const directiveMetadata = {
      transport: 'dashboard' as const,
      command_id: 'fleet-directive-command',
      idempotency_key: 'fleet-directive-attempt',
    };
    const first = service.issueDirectiveBatch({
      kind: 'pause',
    }, directiveMetadata);
    const replay = service.issueDirectiveBatch({
      kind: 'pause',
    }, directiveMetadata);
    expect(first.result?.applied).toBe(2);
    expect(replay.replayed).toBe(true);
    expect(engine.getAgentDirectives('task-1')).toHaveLength(1);
    expect(engine.getAgentDirectives('task-2')).toHaveLength(1);

    engine.updateAgentStatus('task-1', 'completed');
    engine.updateAgentStatus('task-2', 'failed');
    const dismissMetadata = {
      transport: 'dashboard' as const,
      command_id: 'fleet-dismiss-command',
      idempotency_key: 'fleet-dismiss-attempt',
    };
    expect(service.dismissBatch({}, dismissMetadata).result).toMatchObject({
      dismissed: 2,
      total: 2,
    });
    expect(service.dismissBatch({}, dismissMetadata).replayed).toBe(true);
    expect(engine.getAgentTasks()).toHaveLength(0);
  });
});
