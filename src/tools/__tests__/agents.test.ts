import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerAgentTools } from '../agents.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-agents.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-agents',
    name: 'Agents Test Engagement',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}
}

describe('agent tools', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    handlers = {};

    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;

    registerAgentTools(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('register_agent returns agent_id, task_id, and status', async () => {
    engine.addNode({
      id: 'host-10-10-10-1',
      type: 'host',
      label: '10.10.10.1',
      ip: '10.10.10.1',
      discovered_at: new Date().toISOString(),
      discovered_by: 'test',
      confidence: 1.0,
    });

    const result = await handlers.register_agent({
      agent_id: 'agent-test-1',
      frontier_item_id: 'frontier-node-host-10-10-10-1',
      subgraph_node_ids: ['host-10-10-10-1'],
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.task_id).toBeDefined();
    expect(payload.agent_id).toBe('agent-test-1');
    expect(payload.status).toBe('running');
    expect(payload.message).toContain('frontier-node-host-10-10-10-1');
  });

  it('get_agent_context returns subgraph data for a registered agent', async () => {
    engine.addNode({
      id: 'host-10-10-10-1',
      type: 'host',
      label: '10.10.10.1',
      ip: '10.10.10.1',
      discovered_at: new Date().toISOString(),
      discovered_by: 'test',
      confidence: 1.0,
    });

    const reg = await handlers.register_agent({
      agent_id: 'agent-ctx',
      frontier_item_id: 'frontier-node-host-10-10-10-1',
      subgraph_node_ids: ['host-10-10-10-1'],
    });
    const taskId = JSON.parse(reg.content[0].text).task_id;

    const result = await handlers.get_agent_context({
      task_id: taskId,
      hops: 1,
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.task_id).toBe(taskId);
    expect(payload.agent_id).toBe('agent-ctx');
    expect(payload.subgraph).toBeDefined();
    expect(payload.subgraph.nodes).toBeInstanceOf(Array);
    expect(payload.subgraph.edges).toBeInstanceOf(Array);
    expect(payload.subgraph.nodes.some((n: { id: string }) => n.id === 'host-10-10-10-1')).toBe(true);
  });

  it('update_agent changes status to completed', async () => {
    const reg = await handlers.register_agent({
      agent_id: 'agent-update',
      frontier_item_id: 'frontier-node-host-10-10-10-2',
      subgraph_node_ids: ['host-10-10-10-2'],
    });
    const taskId = JSON.parse(reg.content[0].text).task_id;

    const result = await handlers.update_agent({
      task_id: taskId,
      status: 'completed',
      summary: 'Done with enumeration',
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.task_id).toBe(taskId);
    expect(payload.status).toBe('completed');
    expect(payload.updated).toBe(true);
  });

  it('update_agent returns error for unknown task', async () => {
    const result = await handlers.update_agent({
      task_id: 'nonexistent-task-id',
      status: 'failed',
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.error).toContain('nonexistent-task-id');
  });

  it('get_agent_context returns error for unknown task', async () => {
    const result = await handlers.get_agent_context({
      task_id: 'nonexistent-task-id',
      hops: 1,
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.error).toContain('nonexistent-task-id');
  });
});
