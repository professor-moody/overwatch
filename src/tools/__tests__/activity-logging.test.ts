import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerLoggingTools } from '../logging.js';
import { registerScoringTools } from '../scoring.js';
import { registerFindingTools } from '../findings.js';
import { registerParseOutputTools } from '../parse-output.js';
import { registerAgentTools } from '../agents.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-activity-log.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-activity-log',
    name: 'Activity Log Test Engagement',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/30'],
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

describe('structured activity logging tools', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;
  let toolConfigs: Record<string, any>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    handlers = {};
    toolConfigs = {};

    const fakeServer = {
      registerTool(name: string, config: unknown, handler: (args: any) => Promise<any>) {
        toolConfigs[name] = config;
        handlers[name] = handler;
      },
    } as unknown as McpServer;

    registerLoggingTools(fakeServer, engine);
    registerScoringTools(fakeServer, engine);
    registerFindingTools(fakeServer, engine);
    registerParseOutputTools(fakeServer, engine);
    registerAgentTools(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('log_action_event generates event_id and action_id for planned actions', async () => {
    const result = await handlers.log_action_event({
      event_type: 'action_planned',
      description: 'Plan Nmap sweep',
      tool_name: 'nmap',
      target_node_ids: ['host-10-10-10-1'],
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.event_id).toBeDefined();
    expect(payload.action_id).toBeDefined();

    const reloaded = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const history = reloaded.getFullHistory();
    const entry = history.find(candidate => candidate.action_id === payload.action_id);
    expect(entry?.event_type).toBe('action_planned');
    expect(entry?.tool_name).toBe('nmap');
  });

  it('validate_action logs a structured validation event and returns action_id', async () => {
    const result = await handlers.validate_action({
      target_node: 'host-10-10-10-1',
      technique: 'portscan',
      tool_name: 'nmap',
      description: 'Validate an nmap scan',
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.action_id).toBeDefined();
    expect(payload.validation_result).toBeDefined();

    const history = engine.getFullHistory();
    const validationEvent = history.find(candidate => candidate.action_id === payload.action_id && candidate.event_type === 'action_validated');
    expect(validationEvent).toBeDefined();
    expect(validationEvent?.tool_name).toBe('nmap');
  });

  it('validate_action is marked non-read-only and non-idempotent because it logs', () => {
    expect(toolConfigs.validate_action.annotations.readOnlyHint).toBe(false);
    expect(toolConfigs.validate_action.annotations.idempotentHint).toBe(false);
  });

  it('report_finding links finding_reported and finding_ingested to the same action_id', async () => {
    const actionId = 'action-find-1';
    await handlers.report_finding({
      agent_id: 'agent-1',
      action_id: actionId,
      tool_name: 'nxc',
      target_node_ids: ['host-10-10-10-1'],
      nodes: [
        { id: 'svc-log-test', type: 'service', label: 'SMB test', properties: { port: 445, service_name: 'smb' } },
      ],
      edges: [
        { source: 'host-10-10-10-1', target: 'svc-log-test', type: 'RUNS', confidence: 1.0 },
      ],
    });

    const history = engine.getFullHistory().filter(candidate => candidate.action_id === actionId);
    expect(history.some(candidate => candidate.event_type === 'finding_reported')).toBe(true);
    expect(history.some(candidate => candidate.event_type === 'finding_ingested')).toBe(true);
    expect(history.find(candidate => candidate.event_type === 'finding_ingested')?.linked_finding_ids?.length).toBe(1);
  });

  it('report_finding generates and returns action_id when omitted', async () => {
    const result = await handlers.report_finding({
      agent_id: 'agent-implicit',
      tool_name: 'manual',
      nodes: [
        { id: 'host-manual-observation', type: 'host', label: 'manual host', properties: { ip: '10.10.10.3' } },
      ],
      edges: [],
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.action_id).toBeDefined();

    const history = engine.getFullHistory().filter(candidate => candidate.action_id === payload.action_id);
    expect(history.some(candidate => candidate.event_type === 'finding_reported')).toBe(true);
    expect(history.some(candidate => candidate.event_type === 'finding_ingested')).toBe(true);
  });

  it('parse_output logs parse metadata with the supplied action_id', async () => {
    const actionId = 'action-parse-1';
    await handlers.parse_output({
      tool_name: 'nxc',
      output: 'SMB  10.10.10.2  445  ACME\\\\scanner  [+]  Windows Server 2019',
      action_id: actionId,
      ingest: true,
    });

    const parseEvent = engine.getFullHistory().find(candidate => candidate.action_id === actionId && candidate.event_type === 'parse_output');
    expect(parseEvent).toBeDefined();
    expect(parseEvent?.tool_name).toBe('nxc');
    expect(parseEvent?.details?.ingested).toBe(true);
  });

  it('parse_output generates and returns action_id when omitted', async () => {
    const result = await handlers.parse_output({
      tool_name: 'nxc',
      output: 'SMB  10.10.10.2  445  ACME\\\\scanner  [+]  Windows Server 2019',
      ingest: true,
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.action_id).toBeDefined();

    const history = engine.getFullHistory().filter(candidate => candidate.action_id === payload.action_id);
    expect(history.some(candidate => candidate.event_type === 'parse_output')).toBe(true);
    expect(history.some(candidate => candidate.event_type === 'finding_ingested')).toBe(true);
  });

  it('register_agent and update_agent create structured agent lifecycle events', async () => {
    const registration = await handlers.register_agent({
      agent_id: 'agent-ops',
      frontier_item_id: 'frontier-node-host-10-10-10-1',
      subgraph_node_ids: ['host-10-10-10-1'],
    });
    const taskId = JSON.parse(registration.content[0].text).task_id;

    await handlers.update_agent({
      task_id: taskId,
      status: 'completed',
      summary: 'Completed host enumeration',
    });

    const history = engine.getFullHistory();
    expect(history.some(candidate => candidate.event_type === 'agent_registered' && candidate.linked_agent_task_id === taskId)).toBe(true);
    expect(history.some(candidate => candidate.event_type === 'agent_updated' && candidate.linked_agent_task_id === taskId)).toBe(true);
  });

  it('update_agent is marked non-idempotent because it appends lifecycle history', () => {
    expect(toolConfigs.update_agent.annotations.readOnlyHint).toBe(false);
    expect(toolConfigs.update_agent.annotations.idempotentHint).toBe(false);
  });

  it('register_agent can omit subgraph_node_ids and get_agent_context auto-computes scope', async () => {
    const registration = await handlers.register_agent({
      agent_id: 'agent-auto-scope',
      frontier_item_id: 'frontier-node-host-10-10-10-1',
    });
    const taskId = JSON.parse(registration.content[0].text).task_id;

    const contextResult = await handlers.get_agent_context({
      task_id: taskId,
      hops: 1,
    });
    const payload = JSON.parse(contextResult.content[0].text);

    expect(payload.subgraph.nodes.some((node: { id: string }) => node.id === 'host-10-10-10-1')).toBe(true);
  });
});
