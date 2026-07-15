import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import type { AgentTask, EngagementConfig } from '../../types.js';

// B3 — per-campaign OPSEC meter: noise recorded during the action lifecycle must
// be attributed to the owning campaign so the dashboard can show a per-campaign
// gauge. The lifecycle carries an agent_id and/or frontier_item_id (not the
// campaign directly), so GraphEngine.recordOpsecNoise resolves the campaign via
// the agent's task. These tests pin that resolution.

function makeConfig(): EngagementConfig {
  return {
    id: 'test-per-campaign-opsec',
    name: 'Per-Campaign OPSEC Test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1.0 },
  } as EngagementConfig;
}

function runningTask(overrides: Partial<AgentTask>): AgentTask {
  return {
    id: overrides.id ?? 'task-1',
    agent_id: overrides.agent_id ?? 'agent-1',
    assigned_at: new Date().toISOString(),
    status: 'running',
    subgraph_node_ids: [],
    ...overrides,
  };
}

describe('GraphEngine.recordOpsecNoise — per-campaign attribution', () => {
  let engine: GraphEngine;
  let testDir: string;

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-campaign-opsec-'));
    engine = new GraphEngine(makeConfig(), join(testDir, 'state.json'));
  });
  afterEach(() => {
    engine.dispose();
    rmSync(testDir, { recursive: true, force: true });
  });

  it('attributes noise to the campaign via frontier_item_id (running task lookup)', () => {
    engine.registerAgent(runningTask({ id: 't1', agent_id: 'a1', frontier_item_id: 'fi-1', campaign_id: 'camp-1' }));
    engine.recordOpsecNoise({ frontier_item_id: 'fi-1', noise_estimate: 0.3 });
    expect(engine.getOpsecTracker().getCampaignNoise('camp-1')).toBeCloseTo(0.3, 4);
  });

  it('attributes noise to the campaign via agent_id when no frontier item is given', () => {
    engine.registerAgent(runningTask({ id: 't2', agent_id: 'a2', campaign_id: 'camp-2' }));
    engine.recordOpsecNoise({ agent_id: 'a2', noise_estimate: 0.25 });
    // agent_id may also arrive as the task id — both resolve to the campaign.
    engine.recordOpsecNoise({ agent_id: 't2', noise_estimate: 0.1 });
    expect(engine.getOpsecTracker().getCampaignNoise('camp-2')).toBeCloseTo(0.35, 4);
  });

  it('prefers an explicit campaign_id over resolution', () => {
    engine.registerAgent(runningTask({ id: 't3', agent_id: 'a3', frontier_item_id: 'fi-3', campaign_id: 'camp-resolved' }));
    engine.recordOpsecNoise({ frontier_item_id: 'fi-3', campaign_id: 'camp-explicit', noise_estimate: 0.4 });
    expect(engine.getOpsecTracker().getCampaignNoise('camp-explicit')).toBeCloseTo(0.4, 4);
    expect(engine.getOpsecTracker().getCampaignNoise('camp-resolved')).toBe(0);
  });

  it('prefers the running task when an agent_id reused across campaigns has a finished task in the map', () => {
    // agent "shared" finished t-old (camp-old) and is now running t-new (camp-new).
    // Live noise must land on the running campaign, not the stale completed one.
    engine.registerAgent(runningTask({ id: 't-old', agent_id: 'shared', campaign_id: 'camp-old', status: 'completed' }));
    engine.registerAgent(runningTask({ id: 't-new', agent_id: 'shared', campaign_id: 'camp-new', status: 'running' }));
    engine.recordOpsecNoise({ agent_id: 'shared', noise_estimate: 0.3 });
    expect(engine.getOpsecTracker().getCampaignNoise('camp-new')).toBeCloseTo(0.3, 4);
    expect(engine.getOpsecTracker().getCampaignNoise('camp-old')).toBe(0);
  });

  it('records globally but against no campaign for ad-hoc actions', () => {
    engine.recordOpsecNoise({ host_id: 'h-adhoc', noise_estimate: 0.2 });
    expect(engine.getOpsecTracker().getGlobalNoise()).toBeCloseTo(0.2, 4);
    expect(engine.getOpsecTracker().getCampaignNoise('camp-1')).toBe(0);
  });
});
