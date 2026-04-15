import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../graph-engine.js';
import { registerAgentTools } from '../../tools/agents.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-campaign-orch.json';

function makeConfig(overrides?: Partial<EngagementConfig>): EngagementConfig {
  return {
    id: 'test-campaign-orch',
    name: 'Campaign Orchestration Test',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  } as EngagementConfig;
}

function cleanup(): void {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}
}

const now = new Date().toISOString();

function addHost(engine: GraphEngine, id: string, ip: string) {
  engine.addNode({
    id, type: 'host', label: ip, ip,
    discovered_at: now, discovered_by: 'test', confidence: 1.0,
  });
}

function addService(engine: GraphEngine, id: string, hostId: string, name: string, port: number) {
  engine.addNode({
    id, type: 'service', label: `${name}:${port}`, service_name: name, port,
    discovered_at: now, discovered_by: 'test', confidence: 1.0,
  });
  engine.addEdge(hostId, id, {
    type: 'RUNS', confidence: 1.0, discovered_at: now, discovered_by: 'test',
  } as any);
}

// @ts-expect-error - helper available for future tests
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function _addCredential(engine: GraphEngine, id: string, hostId: string) {
  engine.addNode({
    id, type: 'credential', label: id, cred_type: 'plaintext', cred_value: 'pass123',
    discovered_at: now, discovered_by: 'test', confidence: 1.0,
  });
  engine.addEdge(hostId, id, {
    type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: 'test',
  } as any);
}

describe('dispatch_campaign_agents', () => {
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

  it('rejects dispatch for nonexistent campaign', async () => {
    const result = await handlers.dispatch_campaign_agents({
      campaign_id: 'nonexistent',
      max_agents: 3,
      hops: 2,
    });
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.error).toContain('not found');
  });

  it('rejects dispatch for paused campaign', async () => {
    addHost(engine, 'host-1', '10.10.10.1');
    addService(engine, 'svc-1', 'host-1', 'smb', 445);
    addService(engine, 'svc-2', 'host-1', 'ssh', 22);

    const campaigns = engine.getCampaigns();
    if (campaigns.length === 0) return;

    const cid = campaigns[0].id;
    // Campaign is draft — activate it first, then pause
    engine.activateCampaign(cid);
    engine.pauseCampaign(cid);

    const result = await handlers.dispatch_campaign_agents({
      campaign_id: cid,
      max_agents: 3,
      hops: 2,
    });
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.error).toContain('paused');
  });

  it('dispatches agents with campaign_id set on tasks', async () => {
    // Build graph with nodes that will generate frontier items
    addHost(engine, 'host-1', '10.10.10.1');
    addHost(engine, 'host-2', '10.10.10.2');
    addService(engine, 'svc-1', 'host-1', 'smb', 445);
    addService(engine, 'svc-2', 'host-2', 'ssh', 22);

    const campaigns = engine.getCampaigns();
    if (campaigns.length === 0) return; // No auto-generated campaigns

    const cid = campaigns[0].id;
    const campaign = engine.getCampaign(cid)!;

    const result = await handlers.dispatch_campaign_agents({
      campaign_id: cid,
      max_agents: 8,
      hops: 2,
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.campaign_id).toBe(cid);
    expect(payload.strategy).toBe(campaign.strategy);
    expect(payload.dispatched).toBeInstanceOf(Array);

    // Verify tasks have campaign_id
    const state = engine.getState();
    for (const dispatched of payload.dispatched) {
      const task = state.active_agents.find((a: any) => a.id === dispatched.task_id);
      expect(task).toBeDefined();
      expect(task!.campaign_id).toBe(cid);
    }
  });

  it('respects max_agents limit', async () => {
    addHost(engine, 'host-1', '10.10.10.1');
    addHost(engine, 'host-2', '10.10.10.2');
    addHost(engine, 'host-3', '10.10.10.3');
    addService(engine, 'svc-1', 'host-1', 'smb', 445);
    addService(engine, 'svc-2', 'host-2', 'ssh', 22);
    addService(engine, 'svc-3', 'host-3', 'rdp', 3389);

    const campaigns = engine.getCampaigns();
    if (campaigns.length === 0) return;

    const cid = campaigns[0].id;
    const result = await handlers.dispatch_campaign_agents({
      campaign_id: cid,
      max_agents: 1,
      hops: 2,
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.dispatched.length).toBeLessThanOrEqual(1);
  });

  it('skips items with existing running agents', async () => {
    addHost(engine, 'host-1', '10.10.10.1');
    addService(engine, 'svc-1', 'host-1', 'smb', 445);

    const campaigns = engine.getCampaigns();
    if (campaigns.length === 0) return;

    const cid = campaigns[0].id;
    const campaign = engine.getCampaign(cid)!;

    // Pre-register an agent for the first item
    if (campaign.items.length > 0) {
      engine.registerAgent({
        id: 'existing-task-1',
        agent_id: 'existing-agent-1',
        assigned_at: now,
        status: 'running',
        frontier_item_id: campaign.items[0],
        subgraph_node_ids: [],
      });
    }

    const result = await handlers.dispatch_campaign_agents({
      campaign_id: cid,
      max_agents: 8,
      hops: 2,
    });

    const payload = JSON.parse(result.content[0].text);
    const skippedIds = payload.skipped.map((s: any) => s.frontier_item_id);
    if (campaign.items.length > 0) {
      expect(skippedIds).toContain(campaign.items[0]);
    }
  });

  it('activates draft campaign on dispatch', async () => {
    addHost(engine, 'host-1', '10.10.10.1');
    addService(engine, 'svc-1', 'host-1', 'smb', 445);

    const campaigns = engine.getCampaigns();
    if (campaigns.length === 0) return;

    const cid = campaigns[0].id;
    // Campaign should start as draft
    const before = engine.getCampaign(cid)!;
    expect(before.status).toBe('draft');

    await handlers.dispatch_campaign_agents({
      campaign_id: cid,
      max_agents: 3,
      hops: 2,
    });

    const after = engine.getCampaign(cid)!;
    expect(after.status).toBe('active');
  });
});

describe('campaign agent completion aggregation', () => {
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

  it('agent completion updates campaign progress', async () => {
    addHost(engine, 'host-1', '10.10.10.1');
    addService(engine, 'svc-1', 'host-1', 'smb', 445);

    const campaigns = engine.getCampaigns();
    if (campaigns.length === 0) return;

    const cid = campaigns[0].id;

    // Dispatch agents
    const dispResult = await handlers.dispatch_campaign_agents({
      campaign_id: cid,
      max_agents: 8,
      hops: 2,
    });
    const payload = JSON.parse(dispResult.content[0].text);
    if (payload.dispatched.length === 0) return;

    const taskId = payload.dispatched[0].task_id;

    // Complete the agent
    await handlers.update_agent({
      task_id: taskId,
      status: 'completed',
      summary: 'Found new services',
    });

    // Check campaign progress was updated
    const campaign = engine.getCampaign(cid)!;
    expect(campaign.progress.completed).toBeGreaterThanOrEqual(1);
    expect(campaign.progress.succeeded).toBeGreaterThanOrEqual(1);
  });

  it('agent failure updates campaign progress', async () => {
    addHost(engine, 'host-1', '10.10.10.1');
    addService(engine, 'svc-1', 'host-1', 'smb', 445);

    const campaigns = engine.getCampaigns();
    if (campaigns.length === 0) return;

    const cid = campaigns[0].id;

    const dispResult = await handlers.dispatch_campaign_agents({
      campaign_id: cid,
      max_agents: 8,
      hops: 2,
    });
    const payload = JSON.parse(dispResult.content[0].text);
    if (payload.dispatched.length === 0) return;

    const taskId = payload.dispatched[0].task_id;

    // Fail the agent
    await handlers.update_agent({
      task_id: taskId,
      status: 'failed',
      summary: 'Connection refused',
    });

    const campaign = engine.getCampaign(cid)!;
    expect(campaign.progress.completed).toBeGreaterThanOrEqual(1);
    expect(campaign.progress.failed).toBeGreaterThanOrEqual(1);
  });

  it('abort condition cascades to remaining agents', async () => {
    // Build enough nodes to generate multiple frontier items
    for (let i = 1; i <= 8; i++) {
      addHost(engine, `host-${i}`, `10.10.10.${i}`);
      addService(engine, `svc-${i}`, `host-${i}`, 'smb', 445);
    }

    const campaigns = engine.getCampaigns();
    if (campaigns.length === 0) return;

    // Find a campaign with abort conditions and enough items to exceed the threshold
    const campaign = campaigns.find(c => {
      const abortCond = c.abort_conditions.find(
        (ac: any) => ac.type === 'consecutive_failures'
      );
      return abortCond && c.items.length > abortCond.threshold;
    });
    if (!campaign) return;

    const cid = campaign.id;
    const abortThreshold = campaign.abort_conditions.find(
      (ac: any) => ac.type === 'consecutive_failures'
    )!.threshold;

    const dispResult = await handlers.dispatch_campaign_agents({
      campaign_id: cid,
      max_agents: 20,
      hops: 2,
    });
    const payload = JSON.parse(dispResult.content[0].text);
    if (payload.dispatched.length <= abortThreshold) return;

    // Fail agents consecutively up to the abort threshold
    for (let i = 0; i < abortThreshold; i++) {
      await handlers.update_agent({
        task_id: payload.dispatched[i].task_id,
        status: 'failed',
        summary: `Failure ${i + 1}`,
      });
    }

    // Campaign should be aborted
    const finalCampaign = engine.getCampaign(cid)!;
    expect(finalCampaign.status).toBe('aborted');

    // Any remaining running agents should be interrupted
    const state = engine.getState();
    const campaignAgents = state.active_agents.filter(
      (a: any) => a.campaign_id === cid
    );
    for (const agent of campaignAgents) {
      expect(agent.status).not.toBe('running');
    }
  });
});
