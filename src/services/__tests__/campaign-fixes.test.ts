import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../graph-engine.js';
import { registerAgentTools, dispatchCampaignAgents } from '../../tools/agents.js';
import { registerFindingTools } from '../../tools/findings.js';
import type { EngagementConfig } from '../../types.js';
import { cleanupTestPersistence } from '../../__tests__/helpers/cleanup-test-persistence.js';

const TEST_STATE_FILE = './state-test-campaign-fixes.json';
const engines = new Set<GraphEngine>();

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
  for (const engine of engines) engine.dispose();
  engines.clear();
  cleanupTestPersistence(TEST_STATE_FILE);
}

function openEngine(): GraphEngine {
  const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
  engines.add(engine);
  return engine;
}

function parse(result: any): any {
  return JSON.parse(result.content[0].text);
}

function buildEngineWithCampaign(itemIds: string[]): { engine: GraphEngine; campaignId: string } {
  cleanup();
  const engine = openEngine();
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
    const e1 = openEngine();
    const c = e1.createCampaign({ name: 'persist-me', strategy: 'enumeration', item_ids: ['fi-1'], abort_conditions: [] });
    expect(c).toBeTruthy();
    e1.flushNow();

    const e2 = openEngine();
    expect(e2.listCampaigns().some((x) => x.id === c.id)).toBe(true);
  });

  it('findCampaignForItem resolves by item id after a restart (reverse index rebuilt on load)', () => {
    cleanup();
    const e1 = openEngine();
    const c = e1.createCampaign({ name: 'reindex-me', strategy: 'enumeration', item_ids: ['fi-reindex'], abort_conditions: [] });
    e1.flushNow();

    const e2 = openEngine();
    // The reverse index was built in the planner's constructor from the still-empty
    // campaigns map, then loadState replaced the map — so before the reindex-on-load
    // fix this returned null and the campaign was regenerated as a duplicate.
    expect(e2.findCampaignForItem('fi-reindex')?.id).toBe(c.id);
  });

  it('pause / resume / abort persist across reloads', () => {
    cleanup();
    const e1 = openEngine();
    const c = e1.createCampaign({ name: 't', strategy: 'enumeration', item_ids: ['fi-1', 'fi-2'], abort_conditions: [] });
    e1.activateCampaign(c.id);
    e1.pauseCampaign(c.id);
    e1.flushNow();

    const e2 = openEngine();
    expect(e2.getCampaign(c.id)?.status).toBe('paused');

    e2.abortCampaign(c.id);
    e2.flushNow();
    const e3 = openEngine();
    expect(e3.getCampaign(c.id)?.status).toBe('aborted');
  });

  it('deleteCampaign persists across reload', () => {
    cleanup();
    const e1 = openEngine();
    const c = e1.createCampaign({ name: 't', strategy: 'enumeration', item_ids: ['fi-1'], abort_conditions: [] });
    e1.deleteCampaign(c.id);
    e1.flushNow();
    const e2 = openEngine();
    expect(e2.getCampaign(c.id)).toBeNull();
  });
});

describe('Campaign fixes — manual abort stops in-flight agents', () => {
  afterEach(cleanup);

  it('abortCampaign interrupts the campaign\'s running agents (no_retry) and leaves others alone', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1']);
    engine.registerAgent({
      id: 'task-camp', agent_id: 'a-camp', assigned_at: new Date().toISOString(),
      status: 'running', subgraph_node_ids: [], campaign_id: campaignId,
    } as never);
    engine.registerAgent({
      id: 'task-other', agent_id: 'a-other', assigned_at: new Date().toISOString(),
      status: 'running', subgraph_node_ids: [],   // no campaign_id → unrelated
    } as never);

    const c = engine.abortCampaign(campaignId);
    expect(c?.status).toBe('aborted');

    // A deliberate abort must actually STOP the campaign's work.
    const camp = engine.getTask('task-camp');
    expect(camp?.status).toBe('interrupted');
    expect(camp?.no_retry).toBe(true);            // re-offer sweep must not re-dispatch it

    // An unrelated running agent is untouched.
    expect(engine.getTask('task-other')?.status).toBe('running');
  });

  it('aborting a parent campaign also stops agents of cascaded child campaigns', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1', 'fi-2']);
    const children = engine.splitCampaign(campaignId, 2);
    expect(children && children.length).toBeGreaterThan(0);
    const childId = children![0].id;
    engine.registerAgent({
      id: 'task-child', agent_id: 'a-child', assigned_at: new Date().toISOString(),
      status: 'running', subgraph_node_ids: [], campaign_id: childId,
    } as never);

    engine.abortCampaign(campaignId);                      // cascades → child aborted

    expect(engine.getCampaign(childId)?.status).toBe('aborted');
    const child = engine.getTask('task-child');
    expect(child?.status).toBe('interrupted');             // cascaded child's agent stopped too
    expect(child?.no_retry).toBe(true);
  });
});

describe('Campaign fixes — P1: dispatch skips completed items', () => {
  afterEach(cleanup);

  it('does not redispatch frontier items already marked succeeded', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1', 'fi-2']);
    vi.spyOn(engine, 'getActionableFrontierItem').mockImplementation(itemId => ({
      id: itemId,
      type: 'network_discovery',
      description: `Discover ${itemId}`,
      target_cidr: '10.0.0.0/24',
      graph_metrics: { hops_to_objective: null, fan_out_estimate: 1, node_degree: 0, confidence: 1 },
      opsec_noise: 0.1,
      staleness_seconds: 0,
    }));

    // Simulate fi-1 completing successfully
    engine.updateCampaignProgress(campaignId, 'fi-1', 'success', 'fnd-1');

    const result = dispatchCampaignAgents(engine, campaignId, { max_agents: 8 });
    const dispatchedIds = result.dispatched.map((d) => d.frontier_item_id);
    const skippedIds = result.skipped.map((s) => s.frontier_item_id);

    expect(dispatchedIds).not.toContain('fi-1');
    expect(skippedIds).toContain('fi-1');
    expect(dispatchedIds).toContain('fi-2');
  });

  it('does not dispatch a stored item that is no longer actionable', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-stale']);
    const result = dispatchCampaignAgents(engine, campaignId, { max_agents: 1 });
    expect(result.dispatched).toEqual([]);
    expect(result.skipped).toEqual([{ frontier_item_id: 'fi-stale', reason: 'frontier_not_actionable' }]);
  });

  it('does not redispatch items already marked failed', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1', 'fi-2']);
    engine.updateCampaignProgress(campaignId, 'fi-1', 'failure');

    const result = dispatchCampaignAgents(engine, campaignId, { max_agents: 8 });
    expect(result.dispatched.map((d) => d.frontier_item_id)).not.toContain('fi-1');
    expect(result.skipped.find((s) => s.frontier_item_id === 'fi-1')?.reason).toMatch(/already_failed/);
  });
});

describe('Campaign fixes — split ownership preserves active work', () => {
  afterEach(cleanup);

  it('moves progress, item membership, and in-flight tasks into child campaigns', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1', 'fi-2']);
    engine.activateCampaign(campaignId);
    engine.updateCampaignProgress(campaignId, 'fi-1', 'success', 'finding-before-split');
    engine.registerAgent({
      id: 'task-before-split', agent_id: 'agent-before-split', assigned_at: new Date().toISOString(),
      status: 'running', frontier_item_id: 'fi-2', campaign_id: campaignId, subgraph_node_ids: [],
    });

    const children = engine.splitCampaign(campaignId, 2)!;
    const completedChild = children.find(child => child.items.includes('fi-1'))!;
    const activeChild = children.find(child => child.items.includes('fi-2'))!;

    expect(completedChild).toMatchObject({
      status: 'completed',
      progress: { total: 1, completed: 1, succeeded: 1, failed: 0 },
      item_status: { 'fi-1': 'succeeded' },
    });
    expect(engine.findCampaignForItem('fi-1')?.id).toBe(completedChild.id);
    expect(engine.findCampaignForItem('fi-2')?.id).toBe(activeChild.id);
    expect(engine.getTask('task-before-split')?.campaign_id).toBe(activeChild.id);
  });

  it('does not abort a parent whose children are already terminal', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1', 'fi-2']);
    const children = engine.splitCampaign(campaignId, 2)!;
    engine.activateCampaign(campaignId);
    for (const child of children) {
      engine.updateCampaignProgress(child.id, child.items[0], 'success');
    }
    expect(engine.deriveCampaignParentStatus(campaignId)).toBe('completed');
    expect(engine.abortCampaign(campaignId)).toBeNull();
  });

  it('rejects item edits on a split parent instead of desynchronizing children', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1', 'fi-2']);
    engine.pauseCampaign(campaignId);
    engine.splitCampaign(campaignId, 2);
    expect(() => engine.updateCampaign(campaignId, { add_items: ['fi-3'] })).toThrow('child campaigns');
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

  it('a late completion after an interrupt does not resurrect a campaign item as success', () => {
    const { engine, campaignId } = buildEngineWithCampaign(['fi-1']);
    engine.registerAgent({
      id: 'task-int', agent_id: 'agent-Y', assigned_at: new Date().toISOString(),
      status: 'running', frontier_item_id: 'fi-1', campaign_id: campaignId, subgraph_node_ids: [],
    });

    // Operator cancel → interrupted. (Campaign progress for interrupts is intentionally
    // NOT advanced here — see the deferred completion-semantics note; the point of this
    // test is that a LATE completed must not overwrite the interrupt into a false success.)
    engine.updateAgentStatus('task-int', 'interrupted', 'cancelled');
    engine.updateAgentStatus('task-int', 'completed', 'late done');

    expect(engine.getTask('task-int')?.status).toBe('interrupted'); // monotonic — not a false success
    const c = engine.getCampaign(campaignId)!;
    expect(c.progress.succeeded).toBe(0);
  });
});

describe('Campaign fixes — P2: report_finding links finding to campaign', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;
  let campaignId: string;

  beforeEach(() => {
    cleanup();
    engine = openEngine();
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
    engine = openEngine();
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
