import { describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentWorkCommandService } from '../../services/agent-work-command-service.js';
import { registerAgentWorkTools } from '../agent-work-tools.js';

function register(commands: Pick<
  AgentWorkCommandService,
  'findDuplicates' | 'handoff' | 'split' | 'merge'
>) {
  const handlers: Record<string, (input: any) => Promise<any>> = {};
  const definitions: Record<string, any> = {};
  const server = {
    registerTool(name: string, definition: unknown, handler: (input: any) => Promise<any>) {
      definitions[name] = definition;
      handlers[name] = handler;
    },
  } as unknown as McpServer;
  registerAgentWorkTools(server, commands);
  return { definitions, handlers };
}

function successful<T>(result: T) {
  return {
    command_id: 'cmd-work-1',
    idempotency_key: 'idem-work-1',
    retry_token: 'idem-work-1',
    replayed: false,
    status: 'succeeded' as const,
    result,
    record: {} as never,
  };
}

function fakeCommands() {
  return {
    findDuplicates: vi.fn(() => ({ groups: [], total: 0 })),
    handoff: vi.fn(() => successful({
      operation: 'handoff' as const,
      source_task_id: 'source-1',
      created_tasks: [],
      warnings: [],
      reused_existing: false,
    })),
    split: vi.fn(() => successful({
      operation: 'split' as const,
      source_task_id: 'source-1',
      created_tasks: [],
      warnings: [],
      reused_existing: false,
    })),
    merge: vi.fn(() => successful({
      operation: 'merge' as const,
      canonical_task_id: 'canonical-1',
      updated_tasks: [],
      warnings: [],
      reused_existing: false,
    })),
  };
}

describe('agent work MCP tools', () => {
  it('registers one read adapter and three idempotent mutation adapters', () => {
    const { definitions } = register(fakeCommands() as never);
    expect(Object.keys(definitions)).toEqual([
      'find_duplicate_agent_work',
      'handoff_agent_work',
      'split_agent_work',
      'merge_duplicate_agent_work',
    ]);
    expect(definitions.find_duplicate_agent_work.annotations).toEqual({
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    });
    for (const name of [
      'handoff_agent_work',
      'split_agent_work',
      'merge_duplicate_agent_work',
    ]) {
      expect(definitions[name].annotations).toEqual({
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      });
      expect(definitions[name].inputSchema).toMatchObject({
        command_id: expect.anything(),
        idempotency_key: expect.anything(),
        retry_token: expect.anything(),
      });
    }
  });

  it('returns exact duplicate groups without crossing the mutation service', async () => {
    const commands: any = fakeCommands();
    commands.findDuplicates.mockReturnValue({
      groups: [{
        signature: 'sig-1',
        canonical_task_id: 'task-1',
        candidate_task_ids: ['task-1', 'task-2'],
        tasks: [],
      }],
      total: 1,
    });
    const { handlers } = register(commands as never);
    const payload = JSON.parse((await handlers.find_duplicate_agent_work({})).content[0].text);
    expect(payload.total).toBe(1);
    expect(payload.groups[0].candidate_task_ids).toEqual(['task-1', 'task-2']);
    expect(commands.handoff).not.toHaveBeenCalled();
    expect(commands.split).not.toHaveBeenCalled();
    expect(commands.merge).not.toHaveBeenCalled();
  });

  it('delegates handoff body and application-command metadata unchanged', async () => {
    const commands = fakeCommands();
    const { handlers } = register(commands as never);
    const result = await handlers.handoff_agent_work({
      source_task_id: 'source-1',
      archetype: 'recon_scanner',
      objective: 'continue mapping',
      summary: 'Retain the useful context',
      key_finding_ids: ['finding-1'],
      command_id: 'public-command-1',
      idempotency_key: 'public-retry-1',
      retry_token: 'durable-retry-1',
    });
    expect(commands.handoff).toHaveBeenCalledWith('source-1', {
      archetype: 'recon_scanner',
      objective: 'continue mapping',
      summary: 'Retain the useful context',
      key_finding_ids: ['finding-1'],
    }, {
      transport: 'mcp',
      command_id: 'public-command-1',
      idempotency_key: 'public-retry-1',
      retry_token: 'durable-retry-1',
    });
    expect(JSON.parse(result.content[0].text)).toMatchObject({
      operation: 'handoff',
      command_id: 'cmd-work-1',
      idempotency_key: 'idem-work-1',
      retry_token: 'idem-work-1',
      replayed: false,
    });
  });

  it('delegates exact split partitions through the shared service', async () => {
    const commands = fakeCommands();
    const { handlers } = register(commands as never);
    await handlers.split_agent_work({
      source_task_id: 'source-1',
      summary: 'Partition by host',
      children: [
        { archetype: 'recon_scanner', objective: 'map host one', target_node_ids: ['node-1'] },
        { archetype: 'web_tester', objective: 'test host two', target_node_ids: ['node-2'] },
      ],
      idempotency_key: 'split-retry-1',
    });
    expect(commands.split).toHaveBeenCalledWith('source-1', {
      summary: 'Partition by host',
      children: [
        { archetype: 'recon_scanner', objective: 'map host one', target_node_ids: ['node-1'] },
        { archetype: 'web_tester', objective: 'test host two', target_node_ids: ['node-2'] },
      ],
    }, {
      transport: 'mcp',
      command_id: undefined,
      idempotency_key: 'split-retry-1',
      retry_token: undefined,
    });
  });

  it('delegates merge without moving canonical identity into the request body', async () => {
    const commands = fakeCommands();
    const { handlers } = register(commands as never);
    await handlers.merge_duplicate_agent_work({
      canonical_task_id: 'canonical-1',
      duplicate_task_ids: ['duplicate-1'],
      summary: 'Exact duplicate confirmed',
      command_id: 'merge-command-1',
    });
    expect(commands.merge).toHaveBeenCalledWith('canonical-1', {
      duplicate_task_ids: ['duplicate-1'],
      summary: 'Exact duplicate confirmed',
    }, {
      transport: 'mcp',
      command_id: 'merge-command-1',
      idempotency_key: undefined,
      retry_token: undefined,
    });
  });

  it('converts shared service failures into structured MCP errors', async () => {
    const commands = fakeCommands();
    const error = Object.assign(new Error('Agent task must be terminal before handoff.'), {
      code: 'AGENT_HANDOFF_REQUIRES_TERMINAL',
      details: { task_id: 'source-1', status: 'running' },
    });
    commands.handoff.mockImplementation(() => { throw error; });
    const { handlers } = register(commands as never);
    const result = await handlers.handoff_agent_work({
      source_task_id: 'source-1',
      archetype: 'recon_scanner',
      objective: 'continue mapping',
      summary: 'Preserve context',
    });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text)).toMatchObject({
      success: false,
      code: 'AGENT_HANDOFF_REQUIRES_TERMINAL',
      task_id: 'source-1',
      status: 'running',
      tool: 'handoff_agent_work',
    });
  });
});
