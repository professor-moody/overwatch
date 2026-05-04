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

  describe('next_task frontier linkage tracking', () => {
    it('returns a linkage_status_summary on every call', async () => {
      const r = await handlers.next_task({ max_items: 5, include_filtered: false, group_by: 'individual' });
      expect(r.isError).toBeUndefined();
      const payload = JSON.parse(r.content[0].text);
      expect(payload.linkage_status_summary).toMatchObject({
        total: expect.any(Number),
        open: expect.any(Number),
        validated: expect.any(Number),
        pursued: expect.any(Number),
        rejected_explicit: expect.any(Number),
        dropped: expect.any(Number),
      });
    });

    it('observes action_completed on a frontier_item_id and tallies as pursued', async () => {
      // Manually emit a frontier item id through the tracker, then log an
      // action_completed event with that id; the next next_task summary
      // should reflect it as pursued.
      const tracker = engine.getFrontierLinkage();
      tracker.recordEmitted(['fi-fake-1']);
      engine.logActionEvent({
        description: 'simulated completion',
        event_type: 'action_completed',
        category: 'frontier',
        frontier_item_id: 'fi-fake-1',
        agent_id: 'primary',
      });
      const r = await handlers.next_task({ max_items: 5, include_filtered: false, group_by: 'individual' });
      const payload = JSON.parse(r.content[0].text);
      expect(payload.linkage_status_summary.pursued).toBeGreaterThanOrEqual(1);
    });

    it('emits a frontier_item_dropped system event after the threshold', async () => {
      const tracker = engine.getFrontierLinkage();
      tracker.recordEmitted(['fi-stale']);
      // Burn through threshold next_task calls without the item reappearing.
      for (let i = 0; i < 6; i++) {
        await handlers.next_task({ max_items: 5, include_filtered: false, group_by: 'individual' });
      }
      const dropEvents = engine.getFullHistory().filter(
        (e) => e.event_type === 'frontier_item_dropped' && e.frontier_item_id === 'fi-stale',
      );
      expect(dropEvents.length).toBe(1);
      expect(dropEvents[0].provenance).toBe('system');
      expect(dropEvents[0].category).toBe('frontier');
    });
  });
});
