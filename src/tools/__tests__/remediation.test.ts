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
    promoteClaim: vi.fn(),
  };

  registerRemediationTools(fakeServer, engine as any, {
    correct(input: any) {
      return {
        command_id: 'test-graph-correction-command',
        idempotency_key: 'test-graph-correction-idempotency',
        replayed: false,
        result: engine.correctGraph(
          input.reason,
          input.operations,
          input.action_id,
        ),
      };
    },
  } as any);
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

describe('promote_claim tool', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('promotes an edge and attributes an operator by default', async () => {
    const { handlers, engine } = buildHandlers();
    engine.promoteClaim.mockReturnValue({ target_kind: 'edge', target_id: 'edge-1', claim_state: 'refuted' });

    const result = await handlers.promote_claim({ edge_id: 'edge-1', state: 'refuted', reason: 'disproved' });

    expect(engine.promoteClaim).toHaveBeenCalledWith(expect.objectContaining({
      edge_id: 'edge-1', state: 'refuted', reason: 'disproved', by_kind: 'operator', by: undefined,
    }));
    expect(JSON.parse(result.content[0].text).claim_state).toBe('refuted');
  });

  it('attributes an agent when agent_id is provided', async () => {
    const { handlers, engine } = buildHandlers();
    engine.promoteClaim.mockReturnValue({ target_kind: 'node', target_id: 'n1', claim_state: 'validated' });

    await handlers.promote_claim({ node_id: 'n1', state: 'validated', reason: 'tested', agent_id: 'agent-7' });

    expect(engine.promoteClaim).toHaveBeenCalledWith(expect.objectContaining({
      node_id: 'n1', by_kind: 'agent', by: 'agent-7',
    }));
  });

  it('requires exactly one of node_id / edge_id', async () => {
    const { handlers, engine } = buildHandlers();

    const neither = await handlers.promote_claim({ state: 'validated', reason: 'r' });
    expect(neither.isError).toBe(true);
    expect(JSON.parse(neither.content[0].text).error).toContain('exactly one');

    const both = await handlers.promote_claim({ node_id: 'n', edge_id: 'e', state: 'validated', reason: 'r' });
    expect(both.isError).toBe(true);

    expect(engine.promoteClaim).not.toHaveBeenCalled();
  });
});
