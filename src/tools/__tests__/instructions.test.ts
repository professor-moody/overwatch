import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

vi.mock('../../services/prompt-generator.js', () => ({
  generateSystemPrompt: vi.fn((_engine, _tools, options) => {
    if (options.role === 'sub_agent') {
      return '# Sub-Agent Instructions\n\nYou are a scoped sub-agent worker.';
    }
    return '# Primary Orchestrator\n\nYou are the primary operator. Core loop follows.';
  }),
}));

import { registerInstructionTools } from '../instructions.js';
import { generateSystemPrompt } from '../../services/prompt-generator.js';

function buildHandlers() {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const fakeServer = {
    registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
      handlers[name] = handler;
    },
  } as unknown as McpServer;

  const engine = {} as any;

  const tools = [
    { name: 'get_state', description: 'Get engagement state' },
    { name: 'report_finding', description: 'Report a finding' },
  ];
  const getRegisteredTools = vi.fn(() => tools);

  registerInstructionTools(fakeServer, engine, getRegisteredTools);
  return { handlers, engine, getRegisteredTools };
}

describe('get_system_prompt tool', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns primary orchestrator instructions for role=primary', async () => {
    const { handlers } = buildHandlers();

    const result = await handlers.get_system_prompt({
      role: 'primary',
      include_state: true,
      include_tools: true,
    });

    expect(result.isError).toBeUndefined();
    const text = result.content[0].text;
    expect(text).toContain('Primary Orchestrator');
    expect(text).toContain('primary operator');
    expect(generateSystemPrompt).toHaveBeenCalledWith(
      expect.anything(),
      expect.any(Array),
      expect.objectContaining({ role: 'primary' }),
    );
  });

  it('returns sub-agent instructions for role=sub_agent', async () => {
    const { handlers } = buildHandlers();

    const result = await handlers.get_system_prompt({
      role: 'sub_agent',
      agent_id: 'agent-42',
      include_state: true,
      include_tools: true,
    });

    expect(result.isError).toBeUndefined();
    const text = result.content[0].text;
    expect(text).toContain('Sub-Agent Instructions');
    expect(text).toContain('scoped sub-agent');
    expect(generateSystemPrompt).toHaveBeenCalledWith(
      expect.anything(),
      expect.any(Array),
      expect.objectContaining({ role: 'sub_agent', agent_id: 'agent-42' }),
    );
  });

  it('passes registered tools from getRegisteredTools callback', async () => {
    const { handlers, getRegisteredTools } = buildHandlers();

    await handlers.get_system_prompt({
      role: 'primary',
      include_state: true,
      include_tools: true,
    });

    expect(getRegisteredTools).toHaveBeenCalledTimes(1);
    const passedTools = vi.mocked(generateSystemPrompt).mock.calls[0][1];
    expect(passedTools).toHaveLength(2);
    expect(passedTools[0].name).toBe('get_state');
  });
});
