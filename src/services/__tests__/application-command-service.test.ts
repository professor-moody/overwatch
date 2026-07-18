import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import type { EngagementConfig } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal } from '../mutation-journal.js';
import {
  ApplicationCommandActorMismatchError,
  ApplicationCommandConflictError,
  ApplicationCommandPayloadError,
  ApplicationCommandRetryTokenError,
  ApplicationCommandService,
  ApplicationCommandTransitionError,
  MAX_APPLICATION_COMMAND_RESULT_BYTES,
  withApplicationCommandInvocation,
} from '../application-command-service.js';
import { validatePersistedApplicationCommandV1 } from '../persisted-state.js';

function config(id: string): EngagementConfig {
  return {
    id,
    name: id,
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.20.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

const dispatchSchema = z.object({
  node_ids: z.array(z.string()).min(1),
  label: z.string(),
}).strict();

describe('ApplicationCommandService', () => {
  let directory: string;
  let statePath: string;
  let engines: GraphEngine[];

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-command-service-'));
    statePath = join(directory, 'state.json');
    engines = [];
  });

  afterEach(() => {
    for (const engine of engines) engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  function open(): GraphEngine {
    const engine = new GraphEngine(config('application-command-test'), statePath);
    engines.push(engine);
    return engine;
  }

  function close(engine: GraphEngine): void {
    engine.dispose();
    engines.splice(engines.indexOf(engine), 1);
  }

  it('returns the original dispatch result after restart without creating another task', () => {
    const first = open();
    const commands = new ApplicationCommandService(first);
    const input = { node_ids: ['node-1'], label: 'shared-recon' };
    const metadata = {
      transport: 'dashboard' as const,
      actor_task_id: null,
      command_id: 'command-first',
      idempotency_key: 'operator-click-1',
    };
    const original = commands.executeSync({
      command_kind: 'agent.dispatch',
      input,
      schema: dispatchSchema,
      metadata,
      state_keys: ['agents'],
      execute: parsed => {
        const task = {
          id: 'task-command-1',
          agent_id: parsed.label,
          assigned_at: first.now(),
          status: 'running' as const,
          subgraph_node_ids: parsed.node_ids,
          archetype: 'recon_scanner',
        };
        expect(first.registerAgent(task).ok).toBe(true);
        return { dispatched: true, task };
      },
    });
    expect(original).toMatchObject({
      command_id: 'command-first',
      replayed: false,
      status: 'succeeded',
      result: { dispatched: true, task: { id: 'task-command-1' } },
    });
    close(first);

    const second = open();
    const replay = new ApplicationCommandService(second).executeSync({
      command_kind: 'agent.dispatch',
      input,
      schema: dispatchSchema,
      metadata: { ...metadata, command_id: 'ignored-retry-command-id' },
      state_keys: ['agents'],
      execute: () => {
        throw new Error('duplicate handler must not execute');
      },
    });
    expect(replay).toEqual({
      ...original,
      replayed: true,
      record: replay.record,
    });
    expect(replay.command_id).toBe('command-first');
    expect(second.getAgentTasks().map(task => task.id)).toEqual(['task-command-1']);
  });

  it('rebuilds command-id lookup and duplicate rejection from a checkpointed base', () => {
    const first = open();
    const commands = new ApplicationCommandService(first);
    const original = commands.executeSync({
      command_kind: 'test.snapshot_index',
      input: { value: 'original' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: {
        command_id: 'checkpointed-command-id',
        idempotency_key: 'checkpointed-command-key',
      },
      execute: input => input,
    });
    first.flushNow();
    close(first);

    const restarted = open();
    expect(restarted.getApplicationCommandById('checkpointed-command-id'))
      .toEqual(original.record);
    expect(() => new ApplicationCommandService(restarted).executeSync({
      command_kind: 'test.snapshot_index.other',
      input: { value: 'different' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: {
        command_id: 'checkpointed-command-id',
        idempotency_key: 'different-command-key',
      },
      execute: input => input,
    })).toThrow(/command_id|already bound/i);
  });

  it('rejects reuse of one idempotency key with different validated input', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const metadata = {
      transport: 'mcp' as const,
      actor_task_id: 'primary-task',
      idempotency_key: 'same-request',
    };
    commands.executeSync({
      command_kind: 'agent.dispatch',
      input: { node_ids: ['node-a'], label: 'a' },
      schema: dispatchSchema,
      metadata,
      state_keys: ['agents'],
      execute: input => input,
    });

    expect(() => commands.executeSync({
      command_kind: 'agent.dispatch',
      input: { node_ids: ['node-b'], label: 'b' },
      schema: dispatchSchema,
      metadata,
      state_keys: ['agents'],
      execute: input => input,
    })).toThrow(ApplicationCommandConflictError);
  });

  it('commits domain effects and the response-ready outcome in one transaction', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const execution = commands.executeSync({
      command_kind: 'agent.dispatch',
      input: { node_ids: ['node-atomic'], label: 'atomic' },
      schema: dispatchSchema,
      metadata: {
        transport: 'dashboard',
        idempotency_key: 'atomic-command',
      },
      state_keys: ['agents'],
      execute: parsed => {
        const task = {
          id: 'task-atomic',
          agent_id: parsed.label,
          assigned_at: engine.now(),
          status: 'running' as const,
          subgraph_node_ids: parsed.node_ids,
          archetype: 'recon_scanner',
        };
        expect(engine.registerAgent(task).ok).toBe(true);
        return { task_id: task.id };
      },
    });

    expect(engine.getTask('task-atomic')).not.toBeNull();
    expect(engine.getApplicationCommand(execution.idempotency_key)).toMatchObject({
      command_id: execution.command_id,
      status: 'succeeded',
      result: { task_id: 'task-atomic' },
    });
  });

  it('commits async completion effects and the terminal command together', async () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const execution = await commands.executeAsync({
      command_kind: 'process.execute',
      input: { value: 'complete' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: {
        command_id: 'async-effects-command',
        idempotency_key: 'async-effects-command',
      },
      completion_state_keys: ['agents'],
      execute: async () => ({
        status: 'succeeded',
        result: { completed: true },
      }),
      completion_effects: () => {
        expect(engine.registerAgent({
          id: 'task-async-effect',
          agent_id: 'async-effect',
          assigned_at: engine.now(),
          status: 'running',
          subgraph_node_ids: [],
          archetype: 'default',
        }).ok).toBe(true);
      },
    });

    expect(execution.status).toBe('succeeded');
    expect(engine.getTask('task-async-effect')).not.toBeNull();
    expect(engine.getApplicationCommandById('async-effects-command'))
      .toMatchObject({ status: 'succeeded', result: { completed: true } });
  });

  it('rolls back async completion effects and leaves the command recoverable', async () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    await expect(commands.executeAsync({
      command_kind: 'process.execute',
      input: { value: 'rollback' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: {
        command_id: 'async-effects-rollback',
        idempotency_key: 'async-effects-rollback',
      },
      completion_state_keys: ['agents'],
      execute: async () => ({
        status: 'succeeded',
        result: { completed: true },
      }),
      completion_effects: () => {
        expect(engine.registerAgent({
          id: 'task-async-effect-rollback',
          agent_id: 'async-effect-rollback',
          assigned_at: engine.now(),
          status: 'running',
          subgraph_node_ids: [],
          archetype: 'default',
        }).ok).toBe(true);
        throw new Error('terminal side effect failed');
      },
    })).rejects.toThrow('terminal side effect failed');

    expect(engine.getTask('task-async-effect-rollback')).toBeNull();
    expect(engine.getApplicationCommandById('async-effects-rollback'))
      .toMatchObject({ status: 'running' });
  });

  it('rolls back domain effects before recording a failed synchronous command', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const execution = commands.executeSync({
      command_kind: 'agent.dispatch',
      input: { node_ids: ['node-rollback'], label: 'rollback' },
      schema: dispatchSchema,
      metadata: {
        command_id: 'command-rollback',
        idempotency_key: 'rollback-command',
      },
      state_keys: ['agents'],
      execute: parsed => {
        expect(engine.registerAgent({
          id: 'task-rollback',
          agent_id: parsed.label,
          assigned_at: engine.now(),
          status: 'running',
          subgraph_node_ids: parsed.node_ids,
          archetype: 'recon_scanner',
        }).ok).toBe(true);
        throw Object.assign(new Error('dispatch preparation failed'), {
          code: 'DISPATCH_PREPARATION_FAILED',
        });
      },
    });

    expect(execution).toMatchObject({
      status: 'failed',
      error: {
        code: 'DISPATCH_PREPARATION_FAILED',
        message: 'dispatch preparation failed',
      },
    });
    expect(engine.getTask('task-rollback')).toBeNull();
    expect(engine.getApplicationCommand(execution.idempotency_key)).toMatchObject({
      status: 'failed',
    });
  });

  it('rolls back reservation effects before recording a failed accepted command', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const execution = commands.reserveSync({
      command_kind: 'operator.plan',
      input: { command: 'plan a rollback' },
      schema: z.object({ command: z.string() }).strict(),
      metadata: {
        command_id: 'reservation-rollback',
        idempotency_key: 'reservation-rollback',
      },
      state_keys: ['agents'],
      reserve: () => {
        expect(engine.registerAgent({
          id: 'planner-rollback',
          agent_id: 'planner-rollback',
          assigned_at: engine.now(),
          status: 'running',
          subgraph_node_ids: [],
          role: 'planner',
        }).ok).toBe(true);
        throw new Error('planner reservation failed');
      },
    });

    expect(execution).toMatchObject({
      status: 'failed',
      error: { message: 'planner reservation failed' },
    });
    expect(engine.getTask('planner-rollback')).toBeNull();
  });

  it('rejects one command_id bound to two idempotency identities', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    commands.executeSync({
      command_kind: 'test.first',
      input: { value: 1 },
      schema: z.object({ value: z.number() }).strict(),
      metadata: {
        command_id: 'same-command-id',
        idempotency_key: 'first-key',
      },
      execute: input => input,
    });

    expect(() => commands.executeSync({
      command_kind: 'test.second',
      input: { value: 2 },
      schema: z.object({ value: z.number() }).strict(),
      metadata: {
        command_id: 'same-command-id',
        idempotency_key: 'second-key',
      },
      execute: input => input,
    })).toThrow(ApplicationCommandConflictError);
  });

  it('namespaces implicit MCP request ids by session', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const schema = z.object({ value: z.string() }).strict();
    const first = withApplicationCommandInvocation({
      transport: 'mcp',
      session_id: 'mcp-session-a',
      request_id: '1',
    }, () => commands.executeSync({
      command_kind: 'test.mcp_request',
      input: { value: 'a' },
      schema,
      execute: input => input,
    }));
    const second = withApplicationCommandInvocation({
      transport: 'mcp',
      session_id: 'mcp-session-b',
      request_id: '1',
    }, () => commands.executeSync({
      command_kind: 'test.mcp_request',
      input: { value: 'b' },
      schema,
      execute: input => input,
    }));

    expect(first.idempotency_key).not.toBe(second.idempotency_key);
    expect(first.result).toEqual({ value: 'a' });
    expect(second.result).toEqual({ value: 'b' });
  });

  it('keeps authenticated task identity authoritative when an adapter omits its alias', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const execution = withApplicationCommandInvocation({
      transport: 'mcp',
      actor_task_id: 'authenticated-task',
      session_id: 'authenticated-session',
      request_id: 'actor-omitted',
    }, () => commands.executeSync({
      command_kind: 'test.authenticated_actor',
      input: { value: 'same-task' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: { actor_task_id: null },
      execute: input => input,
    }));

    expect(execution.record.actor_task_id).toBe('authenticated-task');
  });

  it('rejects a body alias that conflicts with authenticated task identity', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    expect(() => withApplicationCommandInvocation({
      transport: 'mcp',
      actor_task_id: 'authenticated-task',
      session_id: 'authenticated-session',
      request_id: 'actor-conflict',
    }, () => commands.executeSync({
      command_kind: 'test.authenticated_actor',
      input: { value: 'other-task' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: { actor_task_id: 'claimed-other-task' },
      execute: input => input,
    }))).toThrow(ApplicationCommandActorMismatchError);
    expect(engine.listApplicationCommands()).toHaveLength(0);
  });

  it('namespaces a stdio request id by server lifetime', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const schema = z.object({ value: z.string() }).strict();
    const first = withApplicationCommandInvocation({
      transport: 'mcp',
      session_id: 'stdio-runtime-a',
      request_id: '1',
    }, () => commands.executeSync({
      command_kind: 'test.stdio_request',
      input: { value: 'first-process' },
      schema,
      execute: input => input,
    }));
    const retry = withApplicationCommandInvocation({
      transport: 'mcp',
      session_id: 'stdio-runtime-a',
      request_id: '1',
    }, () => commands.executeSync({
      command_kind: 'test.stdio_request',
      input: { value: 'first-process' },
      schema,
      execute: input => input,
    }));
    const laterRuntime = withApplicationCommandInvocation({
      transport: 'mcp',
      session_id: 'stdio-runtime-b',
      request_id: '1',
    }, () => commands.executeSync({
      command_kind: 'test.stdio_request',
      input: { value: 'second-process' },
      schema,
      execute: input => input,
    }));

    expect(retry.idempotency_key).toBe(first.idempotency_key);
    expect(retry.replayed).toBe(true);
    expect(laterRuntime.idempotency_key).not.toBe(first.idempotency_key);
    expect(laterRuntime.result).toEqual({ value: 'second-process' });
  });

  it('marks unfinished accepted/running commands interrupted during startup recovery', () => {
    const first = open();
    const commands = new ApplicationCommandService(first);
    const reserved = commands.reserveSync({
      command_kind: 'operator.plan',
      input: { command: 'map the domain' },
      schema: z.object({ command: z.string() }).strict(),
      metadata: {
        command_id: 'planner-command',
        idempotency_key: 'planner-command-key',
        transport: 'dashboard',
      },
      reserve: () => ({
        status: 'accepted',
        result: { phase: 'planning_queued', planner_task_id: 'planner-task' },
      }),
    });
    expect(reserved.status).toBe('accepted');
    close(first);

    const second = open();
    expect(new ApplicationCommandService(second).recoverInterruptedCommands()).toBe(1);
    expect(second.getApplicationCommandById('planner-command')).toMatchObject({
      status: 'interrupted',
      error: {
        code: 'COMMAND_INTERRUPTED',
        message: 'daemon restarted before command completion',
      },
    });
  });

  it('keeps raw idempotency keys opaque and replays through the explicit retry token', () => {
    const first = open();
    const commands = new ApplicationCommandService(first);
    const rawKey = `idem_${'a'.repeat(64)}`;
    const original = withApplicationCommandInvocation({
      transport: 'mcp',
      actor_task_id: 'retry-owner',
    }, () => commands.executeSync({
      command_kind: 'test.retry_token',
      input: { value: 'stable' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: { idempotency_key: rawKey, command_id: 'retry-original' },
      execute: input => ({ ...input, executions: 1 }),
    }));
    expect(original.idempotency_key).not.toBe(rawKey);
    expect(original.retry_token).toBe(original.idempotency_key);
    close(first);

    const second = open();
    const replay = withApplicationCommandInvocation({
      transport: 'mcp',
      actor_task_id: 'retry-owner',
    }, () => new ApplicationCommandService(second).executeSync({
      command_kind: 'test.retry_token',
      input: { value: 'stable' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: {
        retry_token: original.retry_token,
        command_id: 'retry-after-restart',
      },
      execute: () => {
        throw new Error('retry token must not execute twice');
      },
    }));
    expect(replay).toMatchObject({
      command_id: 'retry-original',
      retry_token: original.retry_token,
      replayed: true,
      result: { value: 'stable', executions: 1 },
    });
  });

  it('fails closed for unknown or actor-mismatched retry tokens', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    expect(() => commands.executeSync({
      command_kind: 'test.retry_token',
      input: { value: 'stable' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: { retry_token: `idem_${'b'.repeat(64)}` },
      execute: input => input,
    })).toThrow(ApplicationCommandRetryTokenError);

    const original = withApplicationCommandInvocation({
      transport: 'mcp',
      actor_task_id: 'task-a',
    }, () => commands.executeSync({
      command_kind: 'test.retry_token',
      input: { value: 'stable' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: { idempotency_key: 'actor-bound-token' },
      execute: input => input,
    }));
    expect(() => withApplicationCommandInvocation({
      transport: 'mcp',
      actor_task_id: 'task-b',
    }, () => commands.executeSync({
      command_kind: 'test.retry_token',
      input: { value: 'stable' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: { retry_token: original.retry_token },
      execute: input => input,
    }))).toThrow(ApplicationCommandConflictError);
  });

  it('rejects non-JSON command input before executing an effect', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    let executions = 0;
    for (const value of [1n, Number.NaN, () => undefined]) {
      expect(() => commands.executeSync({
        command_kind: 'test.invalid_input',
        input: { value },
        schema: z.object({ value: z.any() }).strict(),
        execute: input => {
          executions += 1;
          return input;
        },
      })).toThrow(ApplicationCommandPayloadError);
    }
    const cyclic: { self?: unknown } = {};
    cyclic.self = cyclic;
    expect(() => commands.executeSync({
      command_kind: 'test.invalid_input',
      input: { value: cyclic },
      schema: z.object({ value: z.any() }).strict(),
      execute: input => {
        executions += 1;
        return input;
      },
    })).toThrow(ApplicationCommandPayloadError);
    expect(executions).toBe(0);
    expect(engine.listApplicationCommands()).toHaveLength(0);
  });

  it('rolls back an oversized synchronous result and records one bounded failure', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const execution = commands.executeSync({
      command_kind: 'test.oversized_result',
      input: { task_id: 'oversized-result-task' },
      schema: z.object({ task_id: z.string() }).strict(),
      state_keys: ['agents'],
      execute: input => {
        expect(engine.registerAgent({
          id: input.task_id,
          agent_id: input.task_id,
          assigned_at: engine.now(),
          status: 'running',
          subgraph_node_ids: [],
        }).ok).toBe(true);
        return { output: 'x'.repeat(MAX_APPLICATION_COMMAND_RESULT_BYTES + 1) };
      },
    });
    expect(execution).toMatchObject({
      status: 'failed',
      error: { code: 'COMMAND_PAYLOAD_INVALID' },
    });
    expect(engine.getTask('oversized-result-task')).toBeNull();
    expect(JSON.stringify(execution.record).length).toBeLessThan(32_000);
  });

  it('turns an unsafe async result into a terminal failure without completion effects', async () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const cyclic: { self?: unknown } = {};
    cyclic.self = cyclic;
    let completionEffects = 0;
    const execution = await commands.executeAsync({
      command_kind: 'test.async_invalid_result',
      input: { value: 'safe' },
      schema: z.object({ value: z.string() }).strict(),
      execute: async () => ({ status: 'succeeded', result: cyclic }),
      completion_effects: () => { completionEffects += 1; },
    });
    expect(execution).toMatchObject({
      status: 'failed',
      error: { code: 'COMMAND_PAYLOAD_INVALID' },
    });
    expect(completionEffects).toBe(0);
  });

  it('enforces forward-only command lifecycle transitions', async () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const accepted = commands.reserveSync({
      command_kind: 'test.lifecycle',
      input: { value: 'lifecycle' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: { command_id: 'lifecycle-command' },
      reserve: () => ({ result: { phase: 'accepted' } }),
    });
    expect(accepted.status).toBe('accepted');
    commands.transition('lifecycle-command', {
      status: 'running',
      result: { phase: 'running' },
    });
    const enriched = commands.transition('lifecycle-command', {
      status: 'running',
      action_id: 'late-action',
    });
    expect(enriched.record).toMatchObject({ status: 'running', action_id: 'late-action' });
    expect(() => commands.transition('lifecycle-command', {
      status: 'accepted',
    })).toThrow(ApplicationCommandTransitionError);
    expect(engine.getApplicationCommandById('lifecycle-command')).toMatchObject({ status: 'running' });

    const succeeded = commands.transition('lifecycle-command', {
      status: 'succeeded',
      result: { phase: 'done' },
    });
    const terminalReplay = commands.transition('lifecycle-command', {
      status: 'failed',
      error: { message: 'must not replace terminal truth' },
    });
    expect(terminalReplay).toMatchObject({
      replayed: true,
      status: 'succeeded',
      result: { phase: 'done' },
    });
    expect(terminalReplay.record.completed_at).toBe(succeeded.record.completed_at);

    const invalidAsync = await commands.executeAsync({
      command_kind: 'test.lifecycle_async',
      input: { value: 'bad-terminal' },
      schema: z.object({ value: z.string() }).strict(),
      execute: async () => ({ status: 'running', result: { phase: 'still-running' } }),
    });
    expect(invalidAsync).toMatchObject({
      status: 'failed',
      error: { code: 'COMMAND_TRANSITION_INVALID' },
    });
  });

  it('journals one bounded command delta instead of the complete command map', () => {
    const engine = open();
    engine.flushNow();
    const snapshot = JSON.parse(readFileSync(statePath, 'utf8')) as {
      journalSnapshotSeq: number;
    };
    const commands = new ApplicationCommandService(engine);
    for (let index = 0; index < 32; index += 1) {
      commands.executeSync({
        command_kind: 'test.delta_history',
        input: { index },
        schema: z.object({ index: z.number().int() }).strict(),
        metadata: { idempotency_key: `delta-history-${index}` },
        execute: input => input,
      });
    }
    const transactions = new MutationJournal(statePath)
      .readTransactionsSince(snapshot.journalSnapshotSeq);
    expect(transactions).toHaveLength(32);
    for (const transaction of transactions) {
      expect(transaction.operations.map(operation => operation.type)).toContain(
        'application_command_change',
      );
      const commandPatches = transaction.operations
        .filter(operation => operation.type === 'state_patch')
        .map(operation => (
          operation.payload as { slices?: { command_state?: Record<string, unknown> } }
        ).slices?.command_state)
        .filter(Boolean);
      expect(commandPatches.every(patch =>
        !Object.prototype.hasOwnProperty.call(patch, 'applicationCommands'))).toBe(true);
    }
    const serializedSizes = transactions.map(transaction =>
      Buffer.byteLength(JSON.stringify(transaction.operations)));
    expect(Math.max(...serializedSizes) - Math.min(...serializedSizes)).toBeLessThan(256);
  });

  it('keeps command WAL payloads independent of retained activity history', () => {
    const engine = open();
    const historicalMarker = `historical-${'x'.repeat(4 * 1024)}`;
    for (let index = 0; index < 32; index += 1) {
      engine.logActionEvent({
        description: `${historicalMarker}-${index}`,
        event_type: 'system',
        category: 'system',
      });
    }
    engine.flushNow();
    const context = (engine as unknown as {
      ctx: { captureDurableStateSlices(keys: readonly string[]): unknown };
    }).ctx;
    const capturedKeys: string[][] = [];
    const originalCapture = context.captureDurableStateSlices.bind(context);
    vi.spyOn(context, 'captureDurableStateSlices').mockImplementation(keys => {
      capturedKeys.push([...keys]);
      return originalCapture(keys);
    });
    const checkpoint = (JSON.parse(readFileSync(statePath, 'utf8')) as {
      journalSnapshotSeq: number;
    }).journalSnapshotSeq;

    new ApplicationCommandService(engine).executeSync({
      command_kind: 'test.bounded_activity',
      input: { value: 'small' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: { idempotency_key: 'bounded-activity-command' },
      execute: input => {
        engine.logActionEvent({
          description: 'bounded command activity',
          event_type: 'system',
          category: 'system',
        });
        return input;
      },
    });

    const transaction = new MutationJournal(statePath)
      .readTransactionsSince(checkpoint)[0]!;
    expect(transaction.operations.map(operation => operation.type)).toEqual([
      'activity_append',
      'application_command_change',
    ]);
    const serialized = JSON.stringify(transaction.operations);
    expect(serialized).not.toContain(historicalMarker);
    expect(Buffer.byteLength(serialized)).toBeLessThan(16 * 1024);
    expect(capturedKeys.length).toBeGreaterThan(0);
    expect(capturedKeys.every(keys =>
      !keys.includes('activity') && !keys.includes('frontier'))).toBe(true);
  });

  it('retains a frontier-weight mutation that has no activity delta', () => {
    const first = open();
    const commands = new ApplicationCommandService(first);
    const execution = commands.executeSync({
      command_kind: 'test.frontier-weights',
      input: { host: 91 },
      schema: z.object({ host: z.number() }).strict(),
      metadata: {
        command_id: 'frontier-weight-command',
        idempotency_key: 'frontier-weight-retry',
      },
      state_keys: ['frontier'],
      execute: input => {
        first.setFrontierWeights({ fan_out: { host: input.host } });
        return { host: input.host };
      },
    });
    expect(execution.status).toBe('succeeded');
    expect(first.getFrontierWeights().fan_out.host).toBe(91);
    close(first);

    const second = open();
    expect(second.getFrontierWeights().fan_out.host).toBe(91);
  });

  it('commits a bounded command without exporting the full hot or cold graph', () => {
    const engine = open();
    const internals = engine as unknown as {
      ctx: {
        graph: { export(): unknown };
        coldStore: { export(): unknown };
      };
    };
    const graphExport = vi.spyOn(internals.ctx.graph, 'export');
    const coldExport = vi.spyOn(internals.ctx.coldStore, 'export');

    const execution = new ApplicationCommandService(engine).executeSync({
      command_kind: 'test.bounded-command-footprint',
      input: { value: 'bounded' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: {
        command_id: 'bounded-command-footprint',
        idempotency_key: 'bounded-command-footprint',
      },
      execute: input => input,
    });

    expect(execution.status).toBe('succeeded');
    expect(graphExport).not.toHaveBeenCalled();
    expect(coldExport).not.toHaveBeenCalled();
  });

  it('bounds high-frequency replay receipts by generation and globally', () => {
    const first = open();
    const commands = new ApplicationCommandService(first);
    const schema = z.object({ sequence: z.number().int() }).strict();
    const execute = (sequence: number, group: string) => commands.executeSync({
      command_kind: 'external.ws.session.input',
      input: { sequence },
      schema,
      metadata: {
        command_id: `session-command-${sequence}`,
        idempotency_key: `session-command-${sequence}`,
      },
      retention: {
        retention_class: 'dashboard.session_ws',
        retention_group: group,
        max_group_records: 2,
        max_class_records: 3,
      },
      execute: input => input,
    });

    execute(1, 'session-a:generation-1');
    execute(2, 'session-a:generation-1');
    execute(3, 'session-a:generation-1');
    execute(4, 'session-b:generation-1');
    execute(5, 'session-b:generation-1');

    const retained = first.listApplicationCommands()
      .filter(command => command.retention_class === 'dashboard.session_ws');
    expect(retained.map(command => command.command_id).sort()).toEqual([
      'session-command-3',
      'session-command-4',
      'session-command-5',
    ]);
    expect(first.getApplicationCommandById('session-command-1')).toMatchObject({
      error: { code: 'COMMAND_RECEIPT_EXPIRED' },
    });
    expect(first.getApplicationCommandById('session-command-2')).toMatchObject({
      error: { code: 'COMMAND_RECEIPT_EXPIRED' },
    });
    close(first);

    const second = open();
    expect(second.listApplicationCommands()
      .filter(command => command.retention_class === 'dashboard.session_ws')
      .map(command => command.command_id)
      .sort()).toEqual([
      'session-command-3',
      'session-command-4',
      'session-command-5',
    ]);
  });

  it('preserves the receipt being finalized when completion clocks tie or move backwards', () => {
    const engine = open();
    vi.spyOn(engine, 'now').mockReturnValue('2026-07-16T00:00:00.000Z');
    const commands = new ApplicationCommandService(engine);
    const execute = (commandId: string, sequence: number) => commands.executeSync({
      command_kind: 'external.ws.session.input',
      input: { sequence },
      schema: z.object({ sequence: z.number().int() }).strict(),
      metadata: { command_id: commandId, idempotency_key: commandId },
      retention: {
        retention_class: 'dashboard.session_ws',
        retention_group: 'session:pinned-clock',
        max_group_records: 1,
        max_class_records: 1,
      },
      execute: input => input,
    });

    execute('zzzz-older-command', 1);
    const newest = execute('aaaa-current-command', 2);
    expect(newest.status).toBe('succeeded');
    expect(engine.getApplicationCommand(newest.retry_token)).toMatchObject({
      command_id: 'aaaa-current-command',
      status: 'succeeded',
    });
    expect(engine.getApplicationCommandById('zzzz-older-command')).toMatchObject({
      error: { code: 'COMMAND_RECEIPT_EXPIRED' },
    });
  });

  it('prunes a high-frequency class through its bounded index without listing the ledger', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const listSpy = vi.spyOn(engine, 'listApplicationCommands')
      .mockImplementation(() => { throw new Error('full command-ledger scan'); });
    for (let sequence = 0; sequence < 4; sequence += 1) {
      expect(commands.executeSync({
        command_kind: 'external.ws.session.input',
        input: { sequence },
        schema: z.object({ sequence: z.number().int() }).strict(),
        metadata: {
          command_id: `indexed-session-${sequence}`,
          idempotency_key: `indexed-session-${sequence}`,
        },
        retention: {
          retention_class: 'dashboard.session_ws',
          retention_group: 'session:indexed',
          max_group_records: 2,
          max_class_records: 2,
        },
        execute: input => input,
      }).status).toBe('succeeded');
    }
    expect(listSpy).not.toHaveBeenCalled();
    expect(engine.getApplicationCommandById('indexed-session-3')).toBeDefined();
    expect(engine.getApplicationCommandById('indexed-session-0')).toMatchObject({
      status: 'failed',
      receipt_terminal_status: 'succeeded',
      error: { code: 'COMMAND_RECEIPT_EXPIRED' },
    });
  });

  it('fails closed through a compact tombstone after a full receipt is retired', () => {
    const first = open();
    const commands = new ApplicationCommandService(first);
    const schema = z.object({ sequence: z.number().int() }).strict();
    let executions = 0;
    const execute = (sequence: number) => commands.executeSync({
      command_kind: 'external.ws.session.input',
      input: { sequence },
      schema,
      metadata: {
        command_id: `retired-command-${sequence}`,
        idempotency_key: `retired-key-${sequence}`,
      },
      retention: {
        retention_class: 'dashboard.session_ws',
        retention_group: 'session:retired',
        max_group_records: 1,
        max_class_records: 1,
      },
      execute: input => {
        executions++;
        return input;
      },
    });

    expect(execute(1).status).toBe('succeeded');
    expect(execute(2).status).toBe('succeeded');
    expect(executions).toBe(2);
    const retired = execute(1);
    expect(executions).toBe(2);
    expect(retired).toMatchObject({
      replayed: true,
      status: 'failed',
      error: { code: 'COMMAND_RECEIPT_EXPIRED' },
      record: {
        validated_input: null,
        receipt_terminal_status: 'succeeded',
      },
    });

    close(first);
    const second = open();
    let restartedExecutions = 0;
    const replay = new ApplicationCommandService(second).executeSync({
      command_kind: 'external.ws.session.input',
      input: { sequence: 1 },
      schema,
      metadata: {
        command_id: 'retired-command-1',
        idempotency_key: 'retired-key-1',
      },
      execute: input => {
        restartedExecutions++;
        return input;
      },
    });
    expect(restartedExecutions).toBe(0);
    expect(replay).toMatchObject({
      replayed: true,
      status: 'failed',
      error: { code: 'COMMAND_RECEIPT_EXPIRED' },
    });
  });

  it('uses durable completion sequence for eviction when clocks move backwards', () => {
    const first = open();
    const retention = {
      retention_class: 'dashboard.session_ws',
      retention_group: 'session:completion-order',
      retention_max_group_records: 2,
      retention_max_class_records: 2,
    };
    const base = (commandId: string, idempotencyKey: string) => ({
      command_id: commandId,
      idempotency_key: idempotencyKey,
      input_sha256: commandId === 'accepted-first' ? 'a'.repeat(64) : 'b'.repeat(64),
      validated_input: { commandId },
      command_kind: 'external.ws.session.input',
      transport: 'dashboard' as const,
      actor_task_id: null,
      created_at: '2026-07-16T00:00:00.000Z',
      ...retention,
    });
    first.recordApplicationCommand({ ...base('accepted-first', 'completion-key-a'), status: 'accepted' });
    first.recordApplicationCommand({ ...base('accepted-second', 'completion-key-b'), status: 'accepted' });
    first.recordApplicationCommand({
      ...base('accepted-second', 'completion-key-b'),
      status: 'succeeded',
      started_at: '2026-07-16T00:00:00.500Z',
      completed_at: '2026-07-16T00:00:02.000Z',
      result: { completed: 'first' },
    });
    first.recordApplicationCommand({
      ...base('accepted-first', 'completion-key-a'),
      status: 'succeeded',
      started_at: '2026-07-16T00:00:00.500Z',
      completed_at: '2026-07-16T00:00:01.000Z',
      result: { completed: 'second' },
    });
    close(first);

    const second = open();
    second.pruneApplicationCommandReceipts({
      retention_class: retention.retention_class,
      retention_group: retention.retention_group,
      max_group_records: 1,
      max_class_records: 1,
    });
    expect(second.getApplicationCommand('completion-key-b')).toMatchObject({
      receipt_terminal_status: 'succeeded',
      error: { code: 'COMMAND_RECEIPT_EXPIRED' },
    });
    expect(second.getApplicationCommand('completion-key-a')).toMatchObject({
      status: 'succeeded',
      result: { completed: 'second' },
    });
  });

  it('assigns ordinary commands a documented count, byte, and age replay window', () => {
    const engine = open();
    const command = new ApplicationCommandService(engine).executeSync({
      command_kind: 'test.default-retention',
      input: { value: 1 },
      schema: z.object({ value: z.number() }).strict(),
      execute: input => input,
    }).record;
    expect(command).toMatchObject({
      retention_class: 'application.command',
      retention_max_group_records: 10_000,
      retention_max_class_records: 10_000,
      retention_max_class_bytes: 256 * 1024 * 1024,
      retention_max_age_ms: 30 * 24 * 60 * 60 * 1_000,
    });
  });

  it('limits one pruning transaction to 1,024 receipt retirements', () => {
    const engine = open();
    const createdAt = '2026-01-01T00:00:00.000Z';
    engine.runApplicationCommandTransaction(
      'seed bounded receipt retirement fixture',
      undefined,
      () => {
        for (let index = 0; index < 1_050; index += 1) {
          engine.recordApplicationCommand({
            command_id: `bounded-retirement-${index}`,
            idempotency_key: `bounded-retirement-${index}`,
            input_sha256: index.toString(16).padStart(64, '0'),
            validated_input: { index },
            command_kind: 'test.bounded-retirement',
            transport: 'system',
            actor_task_id: null,
            status: 'succeeded',
            created_at: createdAt,
            started_at: createdAt,
            completed_at: createdAt,
            result: { index },
            retention_class: 'test.bounded-retirement',
            retention_group: 'all',
            retention_max_group_records: 2_000,
            retention_max_class_records: 2_000,
          });
        }
      },
    );
    engine.flushNow();
    const base = (JSON.parse(readFileSync(statePath, 'utf8')) as {
      journalSnapshotSeq: number;
    }).journalSnapshotSeq;

    expect(engine.pruneApplicationCommandReceipts({
      retention_class: 'test.bounded-retirement',
      retention_group: 'all',
      max_group_records: 1,
      max_class_records: 1,
    })).toBe(1_024);
    expect(engine.listApplicationCommands().filter(command =>
      command.retention_class === 'test.bounded-retirement')).toHaveLength(26);
    const [transaction] = new MutationJournal(statePath).readTransactionsSince(base);
    expect(transaction.operations).toHaveLength(1_024);
    expect(transaction.operations.every(operation =>
      operation.type === 'application_command_change')).toBe(true);
  });

  it('charges full receipt preimages against the pruning byte budget', () => {
    const engine = open();
    const createdAt = '2026-01-01T00:00:00.000Z';
    const blob = 'x'.repeat(3 * 1024 * 1024);
    engine.runApplicationCommandTransaction(
      'seed byte-bounded receipt retirement fixture',
      undefined,
      () => {
        for (let index = 0; index < 4; index += 1) {
          engine.recordApplicationCommand({
            command_id: `byte-retirement-${index}`,
            idempotency_key: `byte-retirement-${index}`,
            input_sha256: (index + 1).toString(16).padStart(64, '0'),
            validated_input: { index },
            command_kind: 'test.byte-retirement',
            transport: 'system',
            actor_task_id: null,
            status: 'succeeded',
            created_at: createdAt,
            started_at: createdAt,
            completed_at: createdAt,
            result: { blob },
            retention_class: 'test.byte-retirement',
            retention_group: 'all',
            retention_max_group_records: 10,
            retention_max_class_records: 10,
          });
        }
      },
    );
    engine.flushNow();
    const base = (JSON.parse(readFileSync(statePath, 'utf8')) as {
      journalSnapshotSeq: number;
    }).journalSnapshotSeq;

    expect(engine.pruneApplicationCommandReceipts({
      retention_class: 'test.byte-retirement',
      retention_group: 'all',
      max_group_records: 1,
      max_class_records: 1,
    })).toBe(3);
    expect(engine.listApplicationCommands().filter(command =>
      command.retention_class === 'test.byte-retirement')).toHaveLength(1);
    const [transaction] = new MutationJournal(statePath).readTransactionsSince(base);
    expect(transaction.operations).toHaveLength(3);
    expect(Buffer.byteLength(JSON.stringify(transaction.operations)))
      .toBeLessThan(12 * 1024 * 1024);
  });

  it('validates persisted retention metadata with the same limits as runtime commands', () => {
    const engine = open();
    const command = new ApplicationCommandService(engine).executeSync({
      command_kind: 'test.retention-validation',
      input: { value: 1 },
      schema: z.object({ value: z.number() }).strict(),
      execute: input => input,
    }).record;
    expect(() => validatePersistedApplicationCommandV1(command, 'command')).not.toThrow();
    expect(() => validatePersistedApplicationCommandV1({
      ...command,
      retention_group: undefined,
    }, 'command')).toThrow(/complete or absent/);
    expect(() => validatePersistedApplicationCommandV1({
      ...command,
      retention_class: 'x'.repeat(257),
    }, 'command')).toThrow(/exceeds/);
    expect(() => validatePersistedApplicationCommandV1({
      ...command,
      retention_max_group_records: 100_001,
    }, 'command')).toThrow(/1 through 100000/);
  });

  it('journals plans, outcomes, deletes, and pruning as bounded per-key deltas', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    commands.executeSync({
      command_kind: 'test.coordination_seed',
      input: { index: 0 },
      schema: z.object({ index: z.number().int() }).strict(),
      execute: input => input,
    });
    engine.flushNow();
    let checkpoint = (JSON.parse(readFileSync(statePath, 'utf8')) as {
      journalSnapshotSeq: number;
    }).journalSnapshotSeq;
    const firstPlan = engine.createCommandPlan({
      command: 'bounded coordination',
      ops: [],
      now: 1_000,
      ttlMs: 10_000,
    });
    const firstTransaction = new MutationJournal(statePath)
      .readTransactionsSince(checkpoint)[0]!;
    const firstSize = Buffer.byteLength(JSON.stringify(firstTransaction.operations));
    expect(firstTransaction.operations.map(operation => operation.type))
      .toEqual(['command_coordination_change']);

    engine.deleteCommandPlan(firstPlan);
    for (let index = 1; index <= 64; index += 1) {
      commands.executeSync({
        command_kind: 'test.coordination_seed',
        input: { index },
        schema: z.object({ index: z.number().int() }).strict(),
        execute: input => input,
      });
    }
    engine.flushNow();
    checkpoint = (JSON.parse(readFileSync(statePath, 'utf8')) as {
      journalSnapshotSeq: number;
    }).journalSnapshotSeq;
    const secondPlan = engine.createCommandPlan({
      command: 'bounded coordination',
      ops: [],
      now: 2_000,
      ttlMs: 10_000,
    });
    engine.recordCommandOutcome(secondPlan, [{ ok: true }], 2_100, 10_000);
    const expiredPlan = engine.createCommandPlan({
      command: 'expire me',
      ops: [],
      now: 100,
      ttlMs: 1,
    });
    expect(engine.getCommandPlan(expiredPlan, 200)).toBeUndefined();
    engine.deleteCommandPlan(secondPlan);

    const transactions = new MutationJournal(statePath)
      .readTransactionsSince(checkpoint);
    expect(transactions.length).toBeGreaterThanOrEqual(5);
    for (const transaction of transactions) {
      expect(transaction.operations.every(operation =>
        operation.type === 'command_coordination_change')).toBe(true);
      expect(JSON.stringify(transaction.operations)).not.toContain('applicationCommands');
      expect(JSON.stringify(transaction.operations)).not.toContain('commandPlans');
      expect(JSON.stringify(transaction.operations)).not.toContain('commandOutcomes');
    }
    const secondCreate = transactions.find(transaction =>
      (transaction.operations[0]?.payload as { key?: string }).key === secondPlan)!;
    const secondSize = Buffer.byteLength(JSON.stringify(secondCreate.operations));
    expect(Math.abs(secondSize - firstSize)).toBeLessThan(256);
  });

  it('compare-and-applies command deltas and preserves commands across partial command-state patches', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const accepted = commands.reserveSync({
      command_kind: 'test.delta_compare',
      input: { value: 'compare' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: { command_id: 'delta-compare-command' },
      reserve: () => ({ result: { phase: 'accepted' } }),
    });
    const reserveTransaction = new MutationJournal(statePath)
      .readTransactionsSince(0)
      .find(transaction => transaction.operations.some(operation =>
        operation.type === 'application_command_change'))!;
    const reserveChange = reserveTransaction.operations.find(operation =>
      operation.type === 'application_command_change');
    expect(reserveChange).toBeDefined();
    expect(engine.applyApplicationCommandChangeMutation(
      reserveChange!.payload as never,
    )).toEqual({ status: 'applied' });

    commands.transition('delta-compare-command', {
      status: 'running',
      result: { phase: 'running' },
    });
    expect(engine.applyApplicationCommandChangeMutation(
      reserveChange!.payload as never,
    )).toMatchObject({ status: 'skipped' });

    expect(engine.applyStatePatchMutation({
      payload_version: 1,
      operation_id: 'partial-command-state',
      occurred_at: engine.now(),
      reason: 'replace only legacy plan caches',
      slices: {
        command_state: {
          commandPlans: [],
          commandOutcomes: [],
        },
      },
    })).toEqual({ status: 'applied' });
    expect(engine.getApplicationCommand(accepted.idempotency_key)).toMatchObject({
      command_id: 'delta-compare-command',
      status: 'running',
    });
    expect(engine.getApplicationCommandById('delta-compare-command')).toMatchObject({
      idempotency_key: accepted.idempotency_key,
      status: 'running',
    });
  });

  it('rolls back only a command delta that actually changed during a rejected bounded transaction', () => {
    const engine = open();
    const commands = new ApplicationCommandService(engine);
    const accepted = commands.executeSync({
      command_kind: 'test.rollback_delta',
      input: { value: 'kept' },
      schema: z.object({ value: z.string() }).strict(),
      metadata: { command_id: 'rollback-delta-command' },
      execute: input => input,
    });
    const addOperation = new MutationJournal(statePath)
      .readTransactionsSince(0)
      .flatMap(transaction => transaction.operations)
      .find(operation =>
        operation.type === 'application_command_change'
        && (operation.payload as { after?: { command_id?: string } }).after?.command_id
          === accepted.command_id)!;
    const rejectedOperation = {
      type: 'command_coordination_change' as const,
      payload: {
        payload_version: 1,
        operation_id: 'reject-after-command',
        occurred_at: engine.now(),
        record_kind: 'plan',
        key: 'malformed-plan',
        before: null,
        after: { command: 42 },
      },
    };
    const persistence = (engine as unknown as {
      persistence: {
        applyTransactionDraft(
          draft: { operations: typeof addOperation[] },
          mutators: GraphEngine,
        ): { status: 'applied' | 'skipped'; reason?: string };
      };
    }).persistence;

    const idempotent = persistence.applyTransactionDraft({
      operations: [addOperation, rejectedOperation as typeof addOperation],
    }, engine);
    expect(idempotent.status).toBe('skipped');
    expect(engine.getApplicationCommandById(accepted.command_id)).toEqual(accepted.record);

    expect(engine.deleteApplicationCommand(accepted.retry_token)).toBe(true);
    const changed = persistence.applyTransactionDraft({
      operations: [addOperation, rejectedOperation as typeof addOperation],
    }, engine);
    expect(changed.status).toBe('skipped');
    expect(engine.getApplicationCommand(accepted.retry_token)).toBeUndefined();
    expect(engine.getApplicationCommandById(accepted.command_id)).toBeUndefined();
  });

  it('proves a transaction against the terminal delta for a repeatedly changed command', () => {
    const engine = open();
    const createdAt = engine.now();
    const base = {
      command_id: 'multi-delta-command',
      idempotency_key: 'multi-delta-key',
      input_sha256: 'a'.repeat(64),
      command_kind: 'test.multi_delta',
      validated_input: { value: true },
      transport: 'dashboard' as const,
      actor_task_id: null,
      created_at: createdAt,
    };
    engine.runApplicationCommandTransaction(
      'multiple deltas for one command',
      undefined,
      () => {
        engine.recordApplicationCommand({
          ...base,
          status: 'accepted',
        });
        engine.recordApplicationCommand({
          ...base,
          status: 'succeeded',
          started_at: createdAt,
          completed_at: createdAt,
          result: { ok: true },
        });
      },
    );
    expect(engine.getApplicationCommandById(base.command_id)).toMatchObject({
      status: 'succeeded',
      result: { ok: true },
    });
  });
});
