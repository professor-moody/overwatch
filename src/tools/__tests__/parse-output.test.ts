import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

vi.mock('../../services/parsers/index.js', () => ({
  parseOutput: vi.fn(),
  getSupportedParsers: vi.fn(() => ['mocked-tool']),
}));

vi.mock('../../services/finding-validation.js', () => ({
  prepareFindingForIngest: vi.fn(),
}));

import { registerParseOutputTools } from '../parse-output.js';
import { parseOutput } from '../../services/parsers/index.js';
import { prepareFindingForIngest } from '../../services/finding-validation.js';

function buildHandlers() {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const fakeServer = {
    registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
      handlers[name] = handler;
    },
  } as unknown as McpServer;

  const engine = {
    getNodesByType: vi.fn(() => []),
    getNode: vi.fn(() => null),
    getFrontierItem: vi.fn(() => null),
    logActionEvent: vi.fn(),
    persist: vi.fn(),
    ingestFinding: vi.fn(),
  };

  registerParseOutputTools(fakeServer, engine as any);
  return { handlers, engine };
}

describe('parse_output tool', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns validation_errors with generated action context when ingestion validation fails', async () => {
    const finding = {
      id: 'finding-1',
      agent_id: 'mock-agent',
      timestamp: new Date().toISOString(),
      nodes: [{ id: 'cred-bad', type: 'credential' as const, label: 'bad credential', privileged: true }],
      edges: [],
    };
    vi.mocked(parseOutput).mockReturnValue(finding as any);
    vi.mocked(prepareFindingForIngest).mockReturnValue({
      finding,
      errors: [{
        code: 'credential_material_missing',
        message: 'Credential claims reusable access without normalized material',
        node_id: 'cred-bad',
      }],
    });

    const { handlers, engine } = buildHandlers();
    const result = await handlers.parse_output({
      tool_name: 'mocked-tool',
      output: 'raw parser output',
      ingest: true,
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.parsed).toBe(true);
    expect(payload.action_id).toBeDefined();
    expect(payload.validation_errors[0].code).toBe('credential_material_missing');
    expect(payload.warnings[0]).toContain('without prior action context');
    expect(engine.ingestFinding).not.toHaveBeenCalled();
    expect(engine.persist).toHaveBeenCalled();
    expect(engine.logActionEvent).toHaveBeenCalled();
  });
});
