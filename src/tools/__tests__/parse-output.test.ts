import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

vi.mock('../../services/parsers/index.js', () => ({
  parseOutput: vi.fn(),
  getSupportedParsers: vi.fn(() => ['mocked-tool']),
  isParserError: vi.fn(() => false),
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

  registerParseOutputTools(fakeServer, engine as any, {
    execute: async (_descriptor: unknown, operation: () => unknown) => operation(),
    resolveActorTaskId: () => null,
  } as any);
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

  it('treats zero-artifact parses as explicit no_data errors', async () => {
    const finding = {
      id: 'finding-empty',
      agent_id: 'mock-agent',
      timestamp: new Date().toISOString(),
      nodes: [],
      edges: [],
    };
    vi.mocked(parseOutput).mockReturnValue(finding as any);

    const { handlers, engine } = buildHandlers();
    const result = await handlers.parse_output({
      tool_name: 'mocked-tool',
      output: 'valid tool banner but no recognized records',
      action_id: 'act-empty-parse',
      ingest: true,
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.parsed).toBe(false);
    expect(payload.ingested).toBe(false);
    expect(payload.parse_status).toBe('no_data');
    expect(payload.nodes_parsed).toBe(0);
    expect(payload.edges_parsed).toBe(0);
    expect(engine.ingestFinding).not.toHaveBeenCalled();
    expect(engine.logActionEvent).toHaveBeenCalledWith(expect.objectContaining({
      action_id: 'act-empty-parse',
      event_type: 'parse_output',
      result_classification: 'failure',
      details: expect.objectContaining({ parse_status: 'no_data' }),
    }));
  });
});
