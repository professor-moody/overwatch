import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerScoringTools } from '../scoring.js';
import { registerInferenceTools } from '../inference.js';
import { registerStateTools } from '../state.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-scoring.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-scoring',
    name: 'Scoring Test Engagement',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [
      { id: 'obj-da', description: 'Achieve Domain Admin', achieved: false },
    ],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}
}

describe('scoring and inference tools', () => {
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
    registerScoringTools(fakeServer, engine);
    registerInferenceTools(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('recompute_objectives returns before and after objective status', async () => {
    const result = await handlers.recompute_objectives({});

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.before).toBeInstanceOf(Array);
    expect(payload.after).toBeInstanceOf(Array);
    expect(payload.before.length).toBe(1);
    expect(payload.after.length).toBe(1);
    expect(payload.before[0].id).toBe('obj-da');
    expect(payload.after[0].id).toBe('obj-da');
  });

  it('suggest_inference_rule returns rule_id and confirmation', async () => {
    const result = await handlers.suggest_inference_rule({
      name: 'RDP access from creds',
      description: 'If a host has RDP open, create CAN_RDPINTO from users with valid creds',
      trigger_node_type: 'service',
      trigger_properties: { service_name: 'rdp' },
      produces: [
        {
          edge_type: 'CAN_RDPINTO',
          source_selector: 'domain_users',
          target_selector: 'parent_host',
          confidence: 0.6,
        },
      ],
      backfill: false,
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.rule_id).toBeDefined();
    expect(payload.added).toBe(true);
    expect(payload.name).toBe('RDP access from creds');
  });

  it('suggest_inference_rule rejects invalid selectors', async () => {
    const result = await handlers.suggest_inference_rule({
      name: 'Bad rule',
      description: 'Uses invalid selectors',
      trigger_node_type: 'service',
      produces: [
        {
          edge_type: 'RUNS',
          source_selector: 'nonexistent_selector',
          target_selector: 'trigger_node',
          confidence: 0.5,
        },
      ],
      backfill: false,
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.valid).toBe(false);
    expect(payload.errors.length).toBeGreaterThan(0);
  });
});
