import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerStateTools } from '../state.js';
import { registerScopeTools } from '../scope.js';
import { registerLoggingTools } from '../logging.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-state-tools.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-state-tools',
    name: 'State Tools Test Engagement',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [
      { id: 'obj-1', description: 'Compromise host', achieved: false },
    ],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}
}

describe('state tools', () => {
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

    registerStateTools(fakeServer, engine);
    registerScopeTools(fakeServer, engine);
    registerLoggingTools(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('get_state returns graph_summary, objectives, and scope', async () => {
    const result = await handlers.get_state({
      include_full_frontier: true,
      activity_count: 20,
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.graph_summary).toBeDefined();
    expect(payload.objectives).toBeDefined();
    expect(payload.config.scope).toBeDefined();
    expect(payload.config.scope.cidrs).toContain('10.10.10.0/24');
    expect(payload.frontier).toBeInstanceOf(Array);
  });

  it('get_history returns cursor and has_more fields for pagination', async () => {
    // Seed some activity entries
    for (let i = 0; i < 5; i++) {
      await handlers.log_action_event({
        action_id: `act-pagination-${i}`,
        event_type: 'action_started',
        description: `Test action ${i}`,
        target_node_ids: [],
      });
    }

    const result = await handlers.get_history({
      limit: 2,
      direction: 'oldest_first',
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.returned).toBe(2);
    expect(payload.has_more).toBe(true);
    expect(payload.next_cursor).toBeDefined();
    expect(payload.total_entries).toBeGreaterThanOrEqual(5);

    // Verify next page works
    const page2 = await handlers.get_history({
      limit: 2,
      cursor: payload.next_cursor,
      direction: 'oldest_first',
    });
    const page2Payload = JSON.parse(page2.content[0].text);
    expect(page2Payload.returned).toBe(2);
  });

  it('update_scope adds a CIDR to scope in preview mode', async () => {
    const result = await handlers.update_scope({
      add_cidrs: ['172.16.0.0/24'],
      reason: 'Pivot network discovered',
      confirm: false,
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.mode).toBe('preview');
    expect(payload.after.cidrs).toContain('172.16.0.0/24');
    expect(payload.before.cidrs).not.toContain('172.16.0.0/24');
  });

  it('update_scope applies a CIDR change when confirmed', async () => {
    const result = await handlers.update_scope({
      add_cidrs: ['172.16.1.0/24'],
      reason: 'Confirmed pivot network',
      confirm: true,
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.mode).toBe('applied');
    expect(payload.after.cidrs).toContain('172.16.1.0/24');

    // Verify the scope is actually updated in engine state
    const stateResult = await handlers.get_state({
      include_full_frontier: false,
      activity_count: 1,
    });
    const state = JSON.parse(stateResult.content[0].text);
    expect(state.config.scope.cidrs).toContain('172.16.1.0/24');
  });
});
