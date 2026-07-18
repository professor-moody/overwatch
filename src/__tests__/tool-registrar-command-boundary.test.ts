import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { ToolRegistrar } from '../app.js';
import { ApplicationCommandService } from '../services/application-command-service.js';
import { GraphEngine } from '../services/graph-engine.js';
import type { EngagementConfig } from '../types.js';

type Handler = (
  input: Record<string, unknown>,
  extra?: { requestId?: string | number; sessionId?: string },
) => Promise<unknown>;

const readAnnotations: ToolAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

const writeAnnotations: ToolAnnotations = {
  ...readAnnotations,
  readOnlyHint: false,
};

function config(id: string): EngagementConfig {
  return {
    id,
    name: id,
    created_at: '2026-07-17T00:00:00.000Z',
    scope: { cidrs: ['10.31.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

describe('ToolRegistrar application-command boundary', () => {
  let directory: string;
  let engine: GraphEngine;
  let handlers: Map<string, Handler>;
  let configs: Map<string, { inputSchema?: Record<string, unknown> }>;
  let registrar: ToolRegistrar;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-tool-boundary-'));
    engine = new GraphEngine(
      config('tool-registrar-command-boundary'),
      join(directory, 'state.json'),
    );
    handlers = new Map();
    configs = new Map();
    const server = {
      registerTool(
        name: string,
        registeredConfig: { inputSchema?: Record<string, unknown> },
        callback: Handler,
      ) {
        configs.set(name, registeredConfig);
        handlers.set(name, callback);
        return { enable() {}, disable() {}, enabled: true };
      },
    };
    registrar = new ToolRegistrar(server as never, engine, 'task-authenticated');
  });

  afterEach(() => {
    engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  function registerMutation(
    callback: Handler,
    name = 'add_objective',
    inputSchema: Record<string, unknown> = { description: z.string() },
  ): void {
    registrar.registerTool(name, {
      description: 'Test mutation boundary.',
      inputSchema: inputSchema as never,
      annotations: writeAnnotations,
    }, callback as never);
  }

  it('adds common command fields only to mutation-capable schemas', () => {
    registerMutation(async () => ({ content: [{ type: 'text', text: 'mutated' }] }));
    registrar.registerTool('get_history', {
      description: 'Test read boundary.',
      inputSchema: { limit: z.number().optional() },
      annotations: readAnnotations,
    }, async () => ({ content: [{ type: 'text' as const, text: 'read' }] }));

    expect(configs.get('add_objective')?.inputSchema).toMatchObject({
      description: expect.anything(),
      command_id: expect.anything(),
      idempotency_key: expect.anything(),
      retry_token: expect.anything(),
    });
    expect(configs.get('get_history')?.inputSchema).toEqual({
      limit: expect.anything(),
    });
    expect(registrar.getEntries().find(entry => entry.name === 'add_objective')
      ?.input_schema).toMatchObject({
      properties: {
        command_id: expect.anything(),
        idempotency_key: expect.anything(),
        retry_token: expect.anything(),
      },
    });
    expect(registrar.getEntries().find(entry => entry.name === 'get_history')
      ?.input_schema).not.toMatchObject({
      properties: { retry_token: expect.anything() },
    });
  });

  it('replays one exact mutation response with its opaque retry token', async () => {
    let executions = 0;
    registerMutation(async input => {
      executions += 1;
      expect(input).toEqual({ description: 'first objective' });
      return {
        content: [{ type: 'text', text: JSON.stringify({ executions }) }],
        structuredContent: { executions },
      };
    });
    const handler = handlers.get('add_objective')!;
    const first = await handler({
      description: 'first objective',
      command_id: 'client-command-1',
      idempotency_key: 'client-retry-1',
    }, { requestId: 11, sessionId: 'session-1' }) as {
      content: Array<{ text: string }>;
      structuredContent: { executions: number };
      _meta: Record<string, Record<string, unknown>>;
    };
    const receipt = first._meta['overwatch/application-command'];
    expect(first.structuredContent).toEqual({ executions: 1 });
    expect(receipt).toMatchObject({
      boundary_command_id: expect.stringMatching(/^boundary_/),
      retry_token: expect.stringMatching(/^idem_[a-f0-9]{64}$/),
      status: 'succeeded',
      replayed: false,
    });

    const replay = await handler({
      description: 'first objective',
      command_id: 'client-command-1',
      idempotency_key: 'client-retry-1',
      retry_token: receipt.retry_token,
    }, { requestId: 12, sessionId: 'session-1' }) as typeof first;
    expect(replay.content).toEqual(first.content);
    expect(replay.structuredContent).toEqual(first.structuredContent);
    expect(replay._meta['overwatch/application-command']).toMatchObject({
      retry_token: receipt.retry_token,
      status: 'succeeded',
      replayed: true,
    });
    expect(executions).toBe(1);

    const command = engine.listApplicationCommands()
      .find(record => record.command_kind === 'external.mcp.add_objective');
    expect(command).toMatchObject({
      actor_task_id: 'task-authenticated',
      command_id: receipt.boundary_command_id,
      status: 'succeeded',
    });
  });

  it('wraps only the mutating form of a conditional tool', async () => {
    let executions = 0;
    registerMutation(async () => {
      executions += 1;
      return { content: [{ type: 'text', text: `scope-${executions}` }] };
    }, 'update_scope', { confirm: z.boolean().optional() });
    const handler = handlers.get('update_scope')!;

    const preview = await handler({ confirm: false }) as { _meta?: unknown };
    expect(preview._meta).toBeUndefined();
    expect(engine.listApplicationCommands()).toHaveLength(0);

    const mutation = await handler({
      confirm: true,
      idempotency_key: 'scope-confirmation',
    }) as { _meta: Record<string, unknown> };
    expect(mutation._meta).toHaveProperty('overwatch/application-command');
    expect(engine.listApplicationCommands()).toHaveLength(1);
    expect(executions).toBe(2);
  });

  it('keeps nested domain commands distinct from their external receipt', async () => {
    const commands = new ApplicationCommandService(engine);
    registerMutation(async input => {
      const nested = commands.executeSync({
        command_kind: 'test.nested-domain-command',
        input: { description: input.description },
        schema: z.object({ description: z.string() }).strict(),
        execute: parsed => ({ accepted: parsed.description }),
      });
      return {
        content: [{ type: 'text', text: JSON.stringify(nested.result) }],
      };
    });

    await handlers.get('add_objective')!({
      description: 'nested objective',
      idempotency_key: 'shared-public-identity',
    }, { requestId: 20, sessionId: 'nested-session' });

    const persisted = engine.listApplicationCommands();
    expect(persisted.map(record => record.command_kind).sort()).toEqual([
      'external.mcp.add_objective',
      'test.nested-domain-command',
    ]);
    expect(new Set(persisted.map(record => record.idempotency_key)).size).toBe(2);
    expect(persisted).toEqual(expect.arrayContaining([
      expect.objectContaining({ actor_task_id: 'task-authenticated' }),
    ]));
  });

  it('does not conflate identical request ids and inputs from independent MCP sessions', async () => {
    let executions = 0;
    registerMutation(async () => ({
      content: [{ type: 'text', text: String(++executions) }],
      structuredContent: { executions },
    }));
    const handler = handlers.get('add_objective')!;

    const first = await handler(
      { description: 'same semantic input' },
      { requestId: 44, sessionId: 'independent-session-a' },
    ) as { structuredContent: { executions: number }; _meta: Record<string, Record<string, unknown>> };
    const second = await handler(
      { description: 'same semantic input' },
      { requestId: 44, sessionId: 'independent-session-b' },
    ) as typeof first;

    expect(first.structuredContent.executions).toBe(1);
    expect(second.structuredContent.executions).toBe(2);
    expect(second._meta['overwatch/application-command']).toMatchObject({ replayed: false });
    expect(second._meta['overwatch/application-command'].boundary_command_id)
      .not.toBe(first._meta['overwatch/application-command'].boundary_command_id);
  });

  it('replays an explicitly identified MCP request after session and daemon restart', async () => {
    let executions = 0;
    const callback: Handler = async input => {
      executions += 1;
      return {
        content: [{ type: 'text', text: JSON.stringify({ input, executions }) }],
        structuredContent: { executions },
      };
    };
    registerMutation(callback);
    const first = await handlers.get('add_objective')!(
      {
        description: 'survive reconnect',
        idempotency_key: 'cross-restart-explicit-retry',
      },
      { requestId: 44, sessionId: 'session-before-restart' },
    ) as { structuredContent: { executions: number }; _meta: Record<string, Record<string, unknown>> };
    expect(first.structuredContent.executions).toBe(1);
    engine.flushNow();
    engine.dispose();

    engine = new GraphEngine(
      config('tool-registrar-command-boundary'),
      join(directory, 'state.json'),
    );
    const restartedHandlers = new Map<string, Handler>();
    const restartedServer = {
      registerTool(
        name: string,
        _registeredConfig: { inputSchema?: Record<string, unknown> },
        registeredCallback: Handler,
      ) {
        restartedHandlers.set(name, registeredCallback);
        return { enable() {}, disable() {}, enabled: true };
      },
    };
    registrar = new ToolRegistrar(restartedServer as never, engine, 'task-authenticated');
    registerMutation(callback);

    const replay = await restartedHandlers.get('add_objective')!(
      {
        description: 'survive reconnect',
        idempotency_key: 'cross-restart-explicit-retry',
      },
      { requestId: 44, sessionId: 'session-after-restart' },
    ) as typeof first;
    expect(replay.structuredContent.executions).toBe(1);
    expect(replay._meta['overwatch/application-command']).toMatchObject({
      replayed: true,
      boundary_command_id: first._meta['overwatch/application-command'].boundary_command_id,
    });
    expect(executions).toBe(1);
  });
});
