import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import {
  SESSION_COMMAND_TERMINAL,
  SessionCommandService,
  buildSessionRequestFingerprint,
} from '../session-command-service.js';

function config(): EngagementConfig {
  return {
    id: 'session-command-test',
    name: 'Session command boundary',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

describe('SessionCommandService', () => {
  let directory: string | undefined;
  let engine: GraphEngine | undefined;

  afterEach(() => {
    engine?.dispose();
    if (directory) rmSync(directory, { recursive: true, force: true });
  });

  it('replays captured output after restart without sending again', async () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-session-command-'));
    const statePath = join(directory, 'state.json');
    engine = new GraphEngine(config(), statePath);
    let sends = 0;
    const descriptor = {
      session_id: 'session-1',
      action_id: 'action-session-command',
      command_length: 6,
      request_fingerprint: buildSessionRequestFingerprint({
        session_id: 'session-1',
        command_length: 6,
        timeout_ms: 10_000,
        idle_ms: 500,
      }),
      timeout_ms: 10_000,
      idle_ms: 500,
      has_wait_for: false,
      force: false,
      has_target_url: false,
      allow_unverified_scope: false,
    };
    const metadata = {
      command_id: 'session-command-1',
      idempotency_key: 'session-command-retry-1',
      actor_task_id: 'operator-task',
      action_id: 'action-session-command',
    };
    const execute = async () => {
      sends += 1;
      const evidenceId = engine!.getEvidenceStore().store({
        action_id: 'action-session-command',
        evidence_type: 'command_output',
        filename: 'session_output',
        raw_output: 'uid=1000(operator)',
      });
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            session_id: 'session-1',
            start_pos: 0,
            end_pos: 18,
            text: 'uid=1000(operator)',
            truncated: false,
            completion_reason: 'idle',
            timed_out: false,
            action_id: 'action-session-command',
            evidence_id: evidenceId,
            validation_result: 'valid',
          }, null, 2),
        }],
      };
    };
    const first = await new SessionCommandService(engine).execute(
      descriptor,
      execute,
      metadata,
    );
    expect(sends).toBe(1);
    expect(JSON.parse(first.content[0]!.text).text).toBe('uid=1000(operator)');

    engine.dispose();
    engine = new GraphEngine(config(), statePath);
    const replay = await new SessionCommandService(engine).execute(
      descriptor,
      execute,
      metadata,
    );
    const replayPayload = JSON.parse(replay.content[0]!.text);

    expect(sends).toBe(1);
    expect(replayPayload).toMatchObject({
      session_id: 'session-1',
      text: 'uid=1000(operator)',
      action_id: 'action-session-command',
      validation_result: 'valid',
    });
    expect(JSON.stringify(engine.listApplicationCommands()))
      .not.toContain('uid=1000(operator)');
  });

  it('replays an explicitly empty session result byte-for-byte', async () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-session-empty-'));
    const statePath = join(directory, 'state.json');
    engine = new GraphEngine(config(), statePath);
    let sends = 0;
    const descriptor = {
      session_id: 'session-empty',
      action_id: 'action-session-empty',
      command_length: 4,
      request_fingerprint: buildSessionRequestFingerprint({
        session_id: 'session-empty',
        command: 'true',
      }),
      timeout_ms: 10_000,
      idle_ms: 500,
      has_wait_for: false,
      force: false,
      has_target_url: false,
      allow_unverified_scope: false,
    };
    const metadata = {
      command_id: 'session-empty-command',
      idempotency_key: 'session-empty-retry',
      action_id: 'action-session-empty',
    };
    const operation = async () => {
      sends++;
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            session_id: 'session-empty',
            text: '',
            action_id: 'action-session-empty',
          }),
        }],
      };
    };
    const first = await new SessionCommandService(engine).execute(
      descriptor,
      operation,
      metadata,
    );
    engine.dispose();
    engine = new GraphEngine(config(), statePath);
    const replay = await new SessionCommandService(engine).execute(
      descriptor,
      operation,
      metadata,
    );

    expect(replay).toEqual(first);
    expect(JSON.parse(replay.content[0]!.text)).toHaveProperty('text', '');
    expect(sends).toBe(1);
  });

  it('rejects a retry key reused for a different same-length session command', async () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-session-conflict-'));
    engine = new GraphEngine(config(), join(directory, 'state.json'));
    const service = new SessionCommandService(engine);
    const base = {
      session_id: 'session-conflict',
      action_id: 'action-session-conflict',
      command_length: 3,
      timeout_ms: 10_000,
      idle_ms: 500,
      has_wait_for: false,
      force: false,
      has_target_url: false,
      allow_unverified_scope: false,
    };
    const metadata = {
      command_id: 'session-conflict-command',
      idempotency_key: 'session-conflict-retry',
      action_id: 'action-session-conflict',
    };
    const operation = async () => ({
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          session_id: 'session-conflict',
          text: '',
          action_id: 'action-session-conflict',
        }),
      }],
    });

    await service.execute({
      ...base,
      request_fingerprint: buildSessionRequestFingerprint({
        session_id: base.session_id,
        command: 'foo',
      }),
    }, operation, metadata);
    await expect(service.execute({
      ...base,
      request_fingerprint: buildSessionRequestFingerprint({
        session_id: base.session_id,
        command: 'bar',
      }),
    }, operation, metadata)).rejects.toMatchObject({
      code: 'IDEMPOTENCY_CONFLICT',
    });
  });

  it('replays one committed terminal event and receipt after an apply-boundary crash', async () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-session-terminal-'));
    const statePath = join(directory, 'state.json');
    engine = new GraphEngine(config(), statePath);
    const descriptor = {
      session_id: 'session-terminal',
      action_id: 'action-session-terminal',
      command_length: 2,
      request_fingerprint: buildSessionRequestFingerprint({
        session_id: 'session-terminal',
        command: 'id',
      }),
      timeout_ms: 10_000,
      idle_ms: 500,
      has_wait_for: false,
      force: false,
      has_target_url: false,
      allow_unverified_scope: false,
    };
    const metadata = {
      command_id: 'session-terminal-command',
      idempotency_key: 'session-terminal-retry',
      action_id: 'action-session-terminal',
    };
    const journal = (engine as any).ctx.mutationJournal;
    const originalAppend = journal.appendTransaction.bind(journal);
    let sends = 0;

    await expect(new SessionCommandService(engine).execute(
      descriptor,
      async () => {
        sends++;
        vi.spyOn(journal, 'appendTransaction').mockImplementationOnce((draft: unknown) => {
          originalAppend(draft);
          throw new Error('synthetic terminal apply-boundary crash');
        });
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              session_id: 'session-terminal',
              text: '',
              action_id: 'action-session-terminal',
            }),
          }],
          [SESSION_COMMAND_TERMINAL]: {
            description: 'session command completed',
            action_id: 'action-session-terminal',
            event_type: 'action_completed' as const,
            category: 'frontier' as const,
            result_classification: 'success' as const,
          },
        };
      },
      metadata,
    )).rejects.toThrow('synthetic terminal apply-boundary crash');

    vi.restoreAllMocks();
    engine.dispose();
    engine = new GraphEngine(config(), statePath);
    const replay = await new SessionCommandService(engine).execute(
      descriptor,
      async () => {
        sends++;
        throw new Error('must not resend');
      },
      metadata,
    );

    expect(sends).toBe(1);
    expect(JSON.parse(replay.content[0]!.text)).toHaveProperty('text', '');
    expect(engine.getApplicationCommandById(metadata.command_id)).toMatchObject({
      status: 'succeeded',
      action_id: 'action-session-terminal',
    });
    expect(engine.getFullHistory().filter(event =>
      event.event_type === 'action_completed'
      && event.action_id === 'action-session-terminal')).toHaveLength(1);
  });
});
