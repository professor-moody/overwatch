import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerScopeTools } from '../scope.js';
import { registerExplorationTools } from '../exploration.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-tool-handlers.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-tool-handlers',
    name: 'Tool Handler Test',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [{
      id: 'obj-1',
      description: 'Get DA',
      target_node_type: 'user',
      target_criteria: { privileged: true },
      achieved: false,
    }],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}
}

function buildHandlers(engine: GraphEngine) {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const fakeServer = {
    registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
      handlers[name] = handler;
    },
  } as unknown as McpServer;

  registerScopeTools(fakeServer, engine);
  registerExplorationTools(fakeServer, engine);
  return handlers;
}

describe('scope tool handler', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    handlers = buildHandlers(engine);
  });

  afterEach(cleanup);

  it('dry-run preview returns mode: preview', async () => {
    const result = await handlers['update_scope']({
      add_cidrs: ['172.16.1.0/24'],
      reason: 'Pivot discovered',
      confirm: false,
    });

    const data = JSON.parse(result.content[0].text);
    expect(data.mode).toBe('preview');
    expect(data.reason).toBe('Pivot discovered');
    expect(data.message).toContain('Dry-run');
  });

  it('dry-run with new scope entries includes expansion warning', async () => {
    const result = await handlers['update_scope']({
      add_cidrs: ['172.16.1.0/24'],
      reason: 'Pivot',
      confirm: false,
    });

    const data = JSON.parse(result.content[0].text);
    expect(data.scope_expansion_warning).toBeDefined();
    expect(data.scope_expansion_warning.some((w: string) => w.includes('172.16.1.0/24'))).toBe(true);
  });

  it('confirm: true applies scope change', async () => {
    const result = await handlers['update_scope']({
      add_domains: ['child.test.local'],
      reason: 'Child domain found',
      confirm: true,
    });

    const data = JSON.parse(result.content[0].text);
    expect(data.mode).toBe('applied');
    expect(data.after.domains).toContain('child.test.local');
  });

  it('invalid domain format returns error', async () => {
    const result = await handlers['update_scope']({
      add_domains: ['nodot'],
      reason: 'Bad domain',
      confirm: true,
    });

    const data = JSON.parse(result.content[0].text);
    expect(data.mode).toBe('error');
    expect(data.errors.length).toBeGreaterThan(0);
  });
});

describe('exploration tool handler', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    handlers = buildHandlers(engine);

    engine.ingestFinding({
      id: 'f-1', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', ip: '10.10.10.1', label: 'h1', discovered_at: new Date().toISOString(), confidence: 1.0, alive: true },
        { id: 'svc-10-10-10-1-445', type: 'service', port: 445, service_name: 'smb', label: 'smb', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [
        { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
      ],
    });
  });

  afterEach(cleanup);

  it('rejects deprecated free-text query parameter', async () => {
    const result = await handlers['query_graph']({
      query: 'credential',
      direction: 'both',
      max_depth: 2,
      limit: 100,
    });

    expect(result.isError).toBe(true);
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain('Free-text');
  });

  it('returns nodes by type', async () => {
    const result = await handlers['query_graph']({
      node_type: 'host',
      direction: 'both',
      max_depth: 2,
      limit: 100,
    });

    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.nodes.length).toBeGreaterThanOrEqual(1);
    expect(data.nodes.some((n: any) => n.id === 'host-10-10-10-1')).toBe(true);
  });

  it('traverses from a specific node', async () => {
    const result = await handlers['query_graph']({
      from_node: 'host-10-10-10-1',
      direction: 'both',
      max_depth: 1,
      limit: 100,
    });

    const data = JSON.parse(result.content[0].text);
    expect(data.nodes.length).toBeGreaterThanOrEqual(1);
  });

  it('filters edges by type', async () => {
    const result = await handlers['query_graph']({
      edge_type: 'RUNS',
      direction: 'both',
      max_depth: 2,
      limit: 100,
    });

    const data = JSON.parse(result.content[0].text);
    expect(data.edges.length).toBeGreaterThanOrEqual(1);
    expect(data.edges.some((e: any) => e.type === 'RUNS' || e.properties?.type === 'RUNS')).toBe(true);
  });
});
