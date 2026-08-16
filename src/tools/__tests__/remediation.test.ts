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
  const promote = vi.fn();
  const withdraw = vi.fn();

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
  } as any, { promote, withdraw } as any);
  return { handlers, engine, promote, withdraw };
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

  it('routes an edge promotion through the command service and surfaces the receipt', async () => {
    const { handlers, promote } = buildHandlers();
    promote.mockReturnValue({
      result: { target_kind: 'edge', target_id: 'edge-1', claim_state: 'refuted' },
      command_id: 'cmd-1', idempotency_key: 'idem-1', replayed: false,
    });

    const result = await handlers.promote_claim({ edge_id: 'edge-1', state: 'refuted', reason: 'disproved' });

    expect(promote).toHaveBeenCalledWith(
      expect.objectContaining({ edge_id: 'edge-1', state: 'refuted', reason: 'disproved' }),
      expect.objectContaining({ transport: 'mcp' }),
    );
    const payload = JSON.parse(result.content[0].text);
    expect(payload).toMatchObject({ claim_state: 'refuted', command_id: 'cmd-1', idempotency_key: 'idem-1', replayed: false });
  });

  it('passes agent_id through (the service maps it to agent attribution)', async () => {
    const { handlers, promote } = buildHandlers();
    promote.mockReturnValue({
      result: { target_kind: 'node', target_id: 'n1', claim_state: 'validated' },
      command_id: 'c', idempotency_key: 'i', replayed: false,
    });

    await handlers.promote_claim({ node_id: 'n1', state: 'validated', reason: 'tested', agent_id: 'agent-7' });

    expect(promote).toHaveBeenCalledWith(
      expect.objectContaining({ node_id: 'n1', agent_id: 'agent-7' }),
      expect.anything(),
    );
  });

  it('requires exactly one of node_id / edge_id before calling the command service', async () => {
    const { handlers, promote } = buildHandlers();

    const neither = await handlers.promote_claim({ state: 'validated', reason: 'r' });
    expect(neither.isError).toBe(true);
    expect(JSON.parse(neither.content[0].text).error).toContain('exactly one');

    const both = await handlers.promote_claim({ node_id: 'n', edge_id: 'e', state: 'validated', reason: 'r' });
    expect(both.isError).toBe(true);

    expect(promote).not.toHaveBeenCalled();
  });
});

describe('withdraw_claim tool', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('routes a withdrawal through the command service and surfaces the receipt', async () => {
    const { handlers, withdraw } = buildHandlers();
    withdraw.mockReturnValue({
      result: { target_kind: 'edge', target_id: 'edge-1', claim_state: 'observed', withdrew: 'refuted' },
      command_id: 'cmd-w', idempotency_key: 'idem-w', replayed: false,
    });

    const result = await handlers.withdraw_claim({ edge_id: 'edge-1', reason: 'undo it' });

    expect(withdraw).toHaveBeenCalledWith(
      expect.objectContaining({ edge_id: 'edge-1', reason: 'undo it' }),
      expect.objectContaining({ transport: 'mcp' }),
    );
    const payload = JSON.parse(result.content[0].text);
    expect(payload).toMatchObject({ claim_state: 'observed', withdrew: 'refuted', command_id: 'cmd-w', replayed: false });
  });

  it('requires exactly one of node_id / edge_id before calling the command service', async () => {
    const { handlers, withdraw } = buildHandlers();

    const neither = await handlers.withdraw_claim({ reason: 'r' });
    expect(neither.isError).toBe(true);
    expect(JSON.parse(neither.content[0].text).error).toContain('exactly one');

    const both = await handlers.withdraw_claim({ node_id: 'n', edge_id: 'e', reason: 'r' });
    expect(both.isError).toBe(true);

    expect(withdraw).not.toHaveBeenCalled();
  });
});
