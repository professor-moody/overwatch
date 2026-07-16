import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';
import type { EngagementConfig } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import {
  ApplicationCommandConflictError,
  ApplicationCommandService,
  withApplicationCommandInvocation,
} from '../application-command-service.js';

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
});
