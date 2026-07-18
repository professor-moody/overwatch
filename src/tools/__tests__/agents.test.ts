import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { AgentWorkCommandService } from '../../services/agent-work-command-service.js';
import { registerAgentTools, dispatchCampaignAgents } from '../agents.js';
import type { EngagementConfig } from '../../types.js';
import { cleanupTestPersistence } from '../../__tests__/helpers/cleanup-test-persistence.js';
import { createTestSandbox } from '../../test-support/test-sandbox.js';

const sandbox = createTestSandbox('agents');
const TEST_STATE_FILE = sandbox.path('state-test-agents.json');

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
  cleanupTestPersistence(TEST_STATE_FILE);
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
    engine.dispose();
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

  it('get_agent_context gives a successor its durable handoff summary and key references', async () => {
    const sourceId = 'context-handoff-source';
    engine.registerAgent({
      id: sourceId,
      task_id: sourceId,
      agent_id: 'context-source',
      agent_label: 'context-source',
      assigned_at: new Date().toISOString(),
      status: 'completed',
      subgraph_node_ids: [],
      archetype: 'recon_scanner',
      objective: 'Map the source context',
    });
    const handedOff = new AgentWorkCommandService(engine).handoff(sourceId, {
      archetype: 'web_tester',
      objective: 'Continue with application validation',
      summary: 'The login endpoint and tenant boundary are confirmed.',
      key_finding_ids: ['finding-context'],
      key_evidence_ids: ['evidence-context'],
      key_event_ids: ['event-context'],
    });
    const successorId = handedOff.result!.created_tasks[0]!.id;
    const payload = JSON.parse((await handlers.get_agent_context({
      task_id: successorId,
      hops: 1,
    })).content[0].text);

    expect(payload.work.relation).toMatchObject({
      kind: 'handoff',
      source_task_id: sourceId,
      summary: 'The login endpoint and tenant boundary are confirmed.',
      key_finding_ids: ['finding-context'],
      key_evidence_ids: ['evidence-context'],
      key_event_ids: ['event-context'],
    });
  });

  it('get_agent_context surfaces prior_actions_on_scope (already-run actions on the agent\'s targets)', async () => {
    engine.addNode({
      id: 'host-10-10-10-9', type: 'host', label: '10.10.10.9', ip: '10.10.10.9',
      discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0,
    });
    // A completed action already ran against this host...
    engine.logActionEvent({
      description: 'nmap -sV on 10.10.10.9', event_type: 'action_completed', category: 'agent',
      action_id: 'act-nmap', result_classification: 'success', technique: 'service_enumeration',
      tool_name: 'nmap', target_node_ids: ['host-10-10-10-9'],
    });
    // ...logged a SECOND time with the same action_id — must be deduped to one row.
    engine.logActionEvent({
      description: 'nmap -sV on 10.10.10.9 (dup)', event_type: 'action_completed', category: 'agent',
      action_id: 'act-nmap', result_classification: 'success', technique: 'service_enumeration',
      tool_name: 'nmap', target_node_ids: ['host-10-10-10-9'],
    });
    // ...and one on an UNRELATED node, which must NOT appear in this agent's scope.
    engine.logActionEvent({
      description: 'elsewhere', event_type: 'action_completed', category: 'agent',
      result_classification: 'success', target_node_ids: ['host-10-10-10-1'],
    });

    const reg = await handlers.register_agent({
      agent_id: 'agent-prior', frontier_item_id: 'frontier-node-host-10-10-10-9',
      subgraph_node_ids: ['host-10-10-10-9'],
    });
    const taskId = JSON.parse(reg.content[0].text).task_id;

    const payload = JSON.parse((await handlers.get_agent_context({ task_id: taskId, hops: 1 })).content[0].text);
    expect(payload.prior_actions_on_scope).toHaveLength(1);
    expect(payload.prior_actions_on_scope[0].tool).toBe('nmap');
    expect(payload.prior_actions_on_scope[0].technique).toBe('service_enumeration');
    expect(payload.prior_actions_on_scope[0].result).toBe('success');
    expect(payload.prior_actions_on_scope[0].targets).toContain('host-10-10-10-9');
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

  // H1 — archetype-on-dispatch: every dispatch path now stamps the task with a
  // resolved archetype so the sub-agent gets the right tool surface, instead of
  // silently defaulting to the full `default` surface.
  describe('archetype on dispatch', () => {
    function seedHost(): void {
      engine.addNode({
        id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1',
        discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0,
      });
    }

    it('register_agent honors an explicit archetype override', async () => {
      seedHost();
      const result = await handlers.register_agent({
        agent_id: 'agent-ovr', frontier_item_id: 'frontier-node-host-10-10-10-1',
        subgraph_node_ids: ['host-10-10-10-1'], archetype: 'cve_researcher',
      });
      const payload = JSON.parse(result.content[0].text);
      expect(payload.archetype).toBe('cve_researcher');
      expect(engine.getTask(payload.task_id)?.archetype).toBe('cve_researcher');
    });

    it('register_agent ignores an unknown archetype and auto-resolves instead', async () => {
      seedHost();
      const result = await handlers.register_agent({
        agent_id: 'agent-bad', frontier_item_id: 'frontier-node-host-10-10-10-1',
        subgraph_node_ids: ['host-10-10-10-1'], archetype: 'not_a_real_archetype',
      });
      const payload = JSON.parse(result.content[0].text);
      // Falls through to recommendArchetype (host node → recon_scanner), never the bogus id.
      expect(payload.archetype).not.toBe('not_a_real_archetype');
      expect(payload.archetype).toBe('recon_scanner');
    });

    it('dispatch_agents stamps each agent with a frontier-derived archetype (host → recon_scanner)', async () => {
      seedHost();
      const result = await handlers.dispatch_agents({
        count: 5, strategy: 'top_priority', hops: 2, types: ['incomplete_node'],
      });
      const payload = JSON.parse(result.content[0].text);
      expect(payload.dispatched.length).toBeGreaterThan(0);
      for (const d of payload.dispatched) {
        expect(d.archetype).toBe('recon_scanner');
        expect(engine.getTask(d.task_id)?.archetype).toBe('recon_scanner');
      }
    });

    it('dispatch_campaign_agents derives the archetype from the campaign strategy', async () => {
      seedHost();
      const fid = engine.computeFrontier()[0]?.id;
      expect(fid).toBeDefined();
      const campaign = engine.createCampaign({ name: 'spray', strategy: 'credential_spray', item_ids: [fid!] });
      const result = dispatchCampaignAgents(engine, campaign.id, {});
      expect(result.dispatched.length).toBeGreaterThan(0);
      expect(result.dispatched[0].archetype).toBe('credential_operator');
      expect(engine.getTask(result.dispatched[0].task_id)?.archetype).toBe('credential_operator');
    });

    it('dispatch_campaign_agents lets an explicit archetype override the strategy default', async () => {
      seedHost();
      const fid = engine.computeFrontier()[0]?.id;
      const campaign = engine.createCampaign({ name: 'spray2', strategy: 'credential_spray', item_ids: [fid!] });
      const result = dispatchCampaignAgents(engine, campaign.id, { archetype: 'post_exploit' });
      expect(result.dispatched[0].archetype).toBe('post_exploit');
    });
  });
});
