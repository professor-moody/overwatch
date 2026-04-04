import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerRemediationTools } from '../remediation.js';

function buildHandlers() {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const fakeServer = {
    registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
      handlers[name] = handler;
    },
  } as unknown as McpServer;

  const engine = {
    correctGraph: vi.fn(),
  };

  registerRemediationTools(fakeServer, engine as any);
  return { handlers, engine };
}

describe('correct_graph tool', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('applies drop_edge operations and returns result', async () => {
    const { handlers, engine } = buildHandlers();
    engine.correctGraph.mockReturnValue({
      dropped_edges: ['edge-1'],
      replaced_edges: [],
      patched_nodes: [],
    });

    const result = await handlers.correct_graph({
      reason: 'Stale edge cleanup',
      operations: [{
        kind: 'drop_edge',
        source_id: 'host-1',
        edge_type: 'RUNS',
        target_id: 'svc-1',
      }],
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.reason).toBe('Stale edge cleanup');
    expect(payload.dropped_edges).toEqual(['edge-1']);
    expect(payload.replaced_edges).toEqual([]);
    expect(payload.patched_nodes).toEqual([]);
    expect(engine.correctGraph).toHaveBeenCalledWith(
      'Stale edge cleanup',
      [{ kind: 'drop_edge', source_id: 'host-1', edge_type: 'RUNS', target_id: 'svc-1' }],
      undefined,
    );
  });

  it('applies patch_node operations and returns result', async () => {
    const { handlers, engine } = buildHandlers();
    engine.correctGraph.mockReturnValue({
      dropped_edges: [],
      replaced_edges: [],
      patched_nodes: ['host-1'],
    });

    const result = await handlers.correct_graph({
      reason: 'Fix hostname typo',
      action_id: 'action-fix-1',
      operations: [{
        kind: 'patch_node',
        node_id: 'host-1',
        set_properties: { hostname: 'dc01.test.local' },
        unset_properties: ['old_hostname'],
      }],
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.action_id).toBe('action-fix-1');
    expect(payload.patched_nodes).toEqual(['host-1']);
    expect(engine.correctGraph).toHaveBeenCalledWith(
      'Fix hostname typo',
      [{
        kind: 'patch_node',
        node_id: 'host-1',
        set_properties: { hostname: 'dc01.test.local' },
        unset_properties: ['old_hostname'],
      }],
      'action-fix-1',
    );
  });

  it('propagates engine errors via the error boundary', async () => {
    const { handlers, engine } = buildHandlers();
    engine.correctGraph.mockImplementation(() => {
      throw new Error('Edge does not exist in graph: host-1 --[RUNS]--> svc-missing');
    });

    const result = await handlers.correct_graph({
      reason: 'Drop nonexistent edge',
      operations: [{
        kind: 'drop_edge',
        source_id: 'host-1',
        edge_type: 'RUNS',
        target_id: 'svc-missing',
      }],
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.error).toContain('Edge does not exist');
  });
});
