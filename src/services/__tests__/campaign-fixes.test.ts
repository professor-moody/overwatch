import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../graph-engine.js';
import { registerAgentTools, dispatchCampaignAgents } from '../../tools/agents.js';
import { registerFindingTools } from '../../tools/findings.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-campaign-fixes.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-campaign-fixes',
    name: 'Campaign fixes test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.0.0.0/24'], domains: ['lab.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup() {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
}

function parse(result: any): any {
  return JSON.parse(result.content[0].text);
}

function buildEngineWithCampaign(itemIds: string[]): { engine: GraphEngine; campaignId: string } {
  cleanup();
  const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
  const c = engine.createCampaign({
    name: 'test-campaign',
    strategy: 'enumeration',
    item_ids: itemIds,
    abort_conditions: [],
  });
  engine.activateCampaign(c.id);
  return { engine, campaignId: c.id };
}

describe('Campaign fixes — P1: persistence of CRUD/lifecycle', () => {
  afterEach(cleanup);

  it('createCampaign survives engine restart', () => {
    cleanup();
    const e1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const c = e1.createCampaign({ name: 'persist-me', strategy: 'enumeration', item_ids: ['fi-1'], abort_conditions: [] });
    expect(c).toBeTruthy();
    e1.flushNow();

    const e2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    expect(e2.listCampaigns().some((x) => x.id === c.id)).toBe(true);
  });

  it('pause / resume / abort persist across reloads', () => {
    cleanup();
    const e1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const c = e1.createCampaign({ name: 't', strategy: 'enumeration', item_ids: ['fi-1', 'fi-2'], abort_conditions: [] });
    e1.activateCampaign(c.id);
    e1.pauseCampaign(c.id);
    e1.flushNow();

    const e2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    expect(e2.getCampaign(c.id)?.status).toBe('paused');

    e2.abortCampaign(c.id);
    e2.flushNow();
    const e3 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    expect(e3.getCampaign(c.id)?.status).toBe('aborted');
  });

  it('deleteCampaign persists across reload', () => {
    cleanup();
    const e1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const c = e1.createCampaign({ name: 't', strategy: 'enumeration', item_ids: ['fi-1'], abort_conditions: [] });
    e1.deleteCampaign(c.id);
    e1.flushNow();
    const e2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    expect(e2.getCampaign(c.id)).toBeNull();
  });
});

describe('Campaign fixes — P1: dispatch skips completed items', () => {
  afterEach(cleanup);

  it('does not redispatch frontier items already marked succeeded', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1', 'fi-2']);

    // Simulate fi-1 completing successfully
    engine.updateCampaignProgress(campaignId, 'fi-1', 'success', 'fnd-1');

    const result = dispatchCampaignAgents(engine, campaignId, { max_agents: 8 });
    const dispatchedIds = result.dispatched.map((d) => d.frontier_item_id);
    const skippedIds = result.skipped.map((s) => s.frontier_item_id);

    expect(dispatchedIds).not.toContain('fi-1');
    expect(skippedIds).toContain('fi-1');
    expect(dispatchedIds).toContain('fi-2');
  });

  it('does not redispatch items already marked failed', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1', 'fi-2']);
    engine.updateCampaignProgress(campaignId, 'fi-1', 'failure');

    const result = dispatchCampaignAgents(engine, campaignId, { max_agents: 8 });
    expect(result.dispatched.map((d) => d.frontier_item_id)).not.toContain('fi-1');
    expect(result.skipped.find((s) => s.frontier_item_id === 'fi-1')?.reason).toMatch(/already_failed/);
  });
});

describe('Campaign fixes — P2: idempotent terminal updates', () => {
  afterEach(cleanup);

  it('updateCampaignProgress does not double-count repeated terminal calls', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1']);

    engine.updateCampaignProgress(campaignId, 'fi-1', 'success', 'fnd-1');
    engine.updateCampaignProgress(campaignId, 'fi-1', 'success', 'fnd-1');
    engine.updateCampaignProgress(campaignId, 'fi-1', 'success', 'fnd-1');

    const c = engine.getCampaign(campaignId)!;
    expect(c.progress.completed).toBe(1);
    expect(c.progress.succeeded).toBe(1);
    expect(c.progress.failed).toBe(0);
    expect(c.progress.completed).toBeLessThanOrEqual(c.progress.total);
  });

  it('updateAgentStatus replays do not double-count campaign progress', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1']);
    engine.registerAgent({
      id: 'task-1',
      agent_id: 'agent-X',
      assigned_at: new Date().toISOString(),
      status: 'running',
      frontier_item_id: 'fi-1',
      campaign_id: campaignId,
      subgraph_node_ids: [],
    });

    engine.updateAgentStatus('task-1', 'completed', 'done');
    engine.updateAgentStatus('task-1', 'completed', 'done again');

    const c = engine.getCampaign(campaignId)!;
    expect(c.progress.completed).toBe(1);
    expect(c.progress.succeeded).toBe(1);
  });
});

describe('Campaign fixes — P2: report_finding links finding to campaign', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;
  let campaignId: string;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const c = engine.createCampaign({
      name: 't', strategy: 'enumeration', item_ids: ['frontier-node-host-10-0-0-1'], abort_conditions: [],
    });
    engine.activateCampaign(c.id);
    campaignId = c.id;

    handlers = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;
    registerAgentTools(fakeServer, engine);
    registerFindingTools(fakeServer, engine);

    engine.addNode({
      id: 'host-10-0-0-1',
      type: 'host',
      label: '10.0.0.1',
      ip: '10.0.0.1',
      discovered_at: new Date().toISOString(),
      discovered_by: 'test',
      confidence: 1.0,
    });
  });

  afterEach(cleanup);

  it('report_finding appends the new finding to campaign.findings when frontier_item_id matches', async () => {
    const result = await handlers.report_finding({
      agent_id: 'agent-X',
      tool_name: 'manual',
      frontier_item_id: 'frontier-node-host-10-0-0-1',
      target_node_ids: ['host-10-0-0-1'],
      nodes: [{
        id: 'svc-22',
        type: 'service',
        label: 'ssh',
        properties: { port: 22, protocol: 'tcp' },
      }],
      edges: [],
    });
    const payload = parse(result);
    expect(payload.finding_id).toBeTruthy();
    expect(payload.campaign_id).toBe(campaignId);

    const c = engine.getCampaign(campaignId)!;
    expect(c.findings).toContain(payload.finding_id);
  });
});

describe('Campaign fixes — P3: submit_agent_transcript accepts task_id and falls back on agent_id', () => {
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

    engine.addNode({
      id: 'host-10-0-0-1', type: 'host', label: '10.0.0.1', ip: '10.0.0.1',
      discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0,
    });
  });

  afterEach(cleanup);

  it('accepts task_id parameter', async () => {
    const reg = await handlers.register_agent({
      agent_id: 'agent-T1',
      frontier_item_id: 'frontier-node-host-10-0-0-1',
      subgraph_node_ids: ['host-10-0-0-1'],
    });
    const { task_id } = parse(reg);

    const r = await handlers.submit_agent_transcript({
      task_id,
      summary: 'ok',
    });
    const payload = parse(r);
    expect(payload.submitted).toBe(true);
    expect(payload.task_id).toBe(task_id);
    expect(payload.agent_id).toBe('agent-T1');
  });

  it('falls back to agent_id lookup when caller passes the human-readable name', async () => {
    const reg = await handlers.register_agent({
      agent_id: 'agent-T2',
      frontier_item_id: 'frontier-node-host-10-0-0-1',
      subgraph_node_ids: ['host-10-0-0-1'],
    });
    const { task_id } = parse(reg);

    const r = await handlers.submit_agent_transcript({
      agent_id: 'agent-T2', // not the task UUID
      summary: 'ok',
    });
    const payload = parse(r);
    expect(payload.submitted).toBe(true);
    expect(payload.task_id).toBe(task_id);
    expect(payload.agent_id).toBe('agent-T2');
  });
});
