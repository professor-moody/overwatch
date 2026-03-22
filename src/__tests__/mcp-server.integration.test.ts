import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { unlinkSync, existsSync } from 'fs';
import { resolve } from 'path';

const STATE_FILE = resolve('./state-eng-001.json');
const ENGAGEMENT_JSON = resolve('./engagement.json');
const SKILLS_DIR = resolve('./skills');

let client: Client;
let transport: StdioClientTransport;

function cleanup() {
  if (existsSync(STATE_FILE)) unlinkSync(STATE_FILE);
}

describe('MCP Server Integration', () => {
  beforeAll(async () => {
    cleanup();
    transport = new StdioClientTransport({
      command: 'node',
      args: [resolve('./dist/index.js')],
      env: {
        ...process.env as Record<string, string>,
        OVERWATCH_CONFIG: ENGAGEMENT_JSON,
        OVERWATCH_SKILLS: SKILLS_DIR,
      },
      stderr: 'pipe',
    });

    client = new Client({ name: 'test-client', version: '0.1.0' });
    await client.connect(transport);
  }, 10000);

  afterAll(async () => {
    await client.close();
    cleanup();
  });

  it('lists all 22 tools', async () => {
    const result = await client.listTools();
    expect(result.tools.length).toBe(22);
    const toolNames = result.tools.map(t => t.name).sort();
    expect(toolNames).toContain('get_state');
    expect(toolNames).toContain('report_finding');
    expect(toolNames).toContain('next_task');
    expect(toolNames).toContain('validate_action');
    expect(toolNames).toContain('query_graph');
    expect(toolNames).toContain('find_paths');
    expect(toolNames).toContain('register_agent');
    expect(toolNames).toContain('get_agent_context');
    expect(toolNames).toContain('update_agent');
    expect(toolNames).toContain('get_history');
    expect(toolNames).toContain('get_skill');
    expect(toolNames).toContain('export_graph');
    expect(toolNames).toContain('run_lab_preflight');
    expect(toolNames).toContain('run_graph_health');
    expect(toolNames).toContain('ingest_bloodhound');
    expect(toolNames).toContain('check_tools');
    expect(toolNames).toContain('track_process');
    expect(toolNames).toContain('check_processes');
    expect(toolNames).toContain('suggest_inference_rule');
    expect(toolNames).toContain('parse_output');
    expect(toolNames).toContain('log_action_event');
    expect(toolNames).toContain('run_retrospective');
  });

  it('get_state returns engagement state', async () => {
    const result = await client.callTool({ name: 'get_state', arguments: {} });
    expect(result.content).toBeDefined();
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content.length).toBeGreaterThan(0);

    const state = JSON.parse(content[0].text);
    expect(state.config).toBeDefined();
    expect(state.graph_summary).toBeDefined();
    expect(state.frontier).toBeDefined();
    expect(state.objectives).toBeDefined();
    expect(state.access_summary).toBeDefined();
    expect(state.warnings).toBeDefined();
    expect(state.lab_readiness).toBeDefined();
  });

  it('run_lab_preflight returns a readiness report', async () => {
    const result = await client.callTool({
      name: 'run_lab_preflight',
      arguments: { profile: 'single_host' },
    });
    const content = result.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0].text);
    expect(body.status).toBeDefined();
    expect(body.checks).toBeInstanceOf(Array);
    expect(body.recommended_next_steps).toBeInstanceOf(Array);
  });

  it('run_graph_health returns a health report', async () => {
    const result = await client.callTool({ name: 'run_graph_health', arguments: {} });
    const content = result.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0].text);
    expect(body.status).toBeDefined();
    expect(body.counts_by_severity).toBeDefined();
    expect(body.issues).toBeInstanceOf(Array);
  });

  it('report_finding ingests a node and returns results', async () => {
    const uniqueId = `svc-integ-${Date.now()}`;
    const result = await client.callTool({
      name: 'report_finding',
      arguments: {
        agent_id: 'test-agent',
        nodes: [
          { id: uniqueId, type: 'service', label: 'SMB integration test', properties: { port: 445, service_name: 'smb' } },
        ],
        edges: [],
      },
    });

    const content = result.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0].text);
    expect(body.new_nodes).toContain(uniqueId);
  });

  it('next_task returns frontier items after findings', async () => {
    const result = await client.callTool({ name: 'next_task', arguments: {} });
    const content = result.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0].text);
    expect(body.candidates).toBeDefined();
    expect(body.candidates.length).toBeGreaterThan(0);
  });

  it('validate_action rejects bad input', async () => {
    const result = await client.callTool({
      name: 'validate_action',
      arguments: {
        target_node: 'nonexistent-node-xyz',
        description: 'Test validation of nonexistent node',
      },
    });
    const content = result.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0].text);
    expect(body.valid).toBe(false);
    expect(body.errors.length).toBeGreaterThan(0);
    expect(body.action_id).toBeDefined();
  });

  it('links validate_action and report_finding via action_id in get_history', async () => {
    const validation = await client.callTool({
      name: 'validate_action',
      arguments: {
        target_node: 'host-10-10-10-1',
        tool_name: 'nmap',
        technique: 'portscan',
        description: 'Validate an nmap scan against host-10-10-10-1',
      },
    });
    const validationBody = JSON.parse((validation.content as Array<{ type: string; text: string }>)[0].text);
    const actionId = validationBody.action_id;

    await client.callTool({
      name: 'report_finding',
      arguments: {
        agent_id: 'test-agent',
        action_id: actionId,
        tool_name: 'nmap',
        target_node_ids: ['host-10-10-10-1'],
        nodes: [
          { id: `svc-http-${Date.now()}`, type: 'service', label: 'HTTP integration test', properties: { port: 80, service_name: 'http' } },
        ],
        edges: [],
      },
    });

    const historyResult = await client.callTool({ name: 'get_history', arguments: { limit: 50 } });
    const historyBody = JSON.parse((historyResult.content as Array<{ type: string; text: string }>)[0].text);
    const linkedEntries = historyBody.entries.filter((entry: any) => entry.action_id === actionId);
    expect(linkedEntries.some((entry: any) => entry.event_type === 'action_validated')).toBe(true);
    expect(linkedEntries.some((entry: any) => entry.event_type === 'finding_reported')).toBe(true);
    expect(linkedEntries.some((entry: any) => entry.event_type === 'finding_ingested')).toBe(true);
  });

  it('supports validate_action to log_action_event to report_finding as one coherent action lifecycle', async () => {
    const validation = await client.callTool({
      name: 'validate_action',
      arguments: {
        target_node: 'host-10-10-10-2',
        tool_name: 'nxc',
        technique: 'smb-enum',
        description: 'Validate SMB enumeration against host-10-10-10-2',
      },
    });
    const validationBody = JSON.parse((validation.content as Array<{ type: string; text: string }>)[0].text);
    const actionId = validationBody.action_id;

    await client.callTool({
      name: 'log_action_event',
      arguments: {
        action_id: actionId,
        event_type: 'action_started',
        description: 'Started SMB enumeration on host-10-10-10-2',
        tool_name: 'nxc',
        target_node_ids: ['host-10-10-10-2'],
      },
    });

    await client.callTool({
      name: 'report_finding',
      arguments: {
        agent_id: 'test-agent',
        action_id: actionId,
        tool_name: 'nxc',
        target_node_ids: ['host-10-10-10-2'],
        nodes: [
          { id: `svc-smb-${Date.now()}`, type: 'service', label: 'SMB integration lifecycle', properties: { port: 445, service_name: 'smb' } },
        ],
        edges: [],
      },
    });

    await client.callTool({
      name: 'log_action_event',
      arguments: {
        action_id: actionId,
        event_type: 'action_completed',
        description: 'Completed SMB enumeration on host-10-10-10-2',
        tool_name: 'nxc',
        target_node_ids: ['host-10-10-10-2'],
        result_classification: 'success',
      },
    });

    const historyResult = await client.callTool({ name: 'get_history', arguments: { limit: 100 } });
    const historyBody = JSON.parse((historyResult.content as Array<{ type: string; text: string }>)[0].text);
    const linkedEntries = historyBody.entries.filter((entry: any) => entry.action_id === actionId);
    expect(linkedEntries.some((entry: any) => entry.event_type === 'action_validated')).toBe(true);
    expect(linkedEntries.some((entry: any) => entry.event_type === 'action_started')).toBe(true);
    expect(linkedEntries.some((entry: any) => entry.event_type === 'finding_ingested')).toBe(true);
    expect(linkedEntries.some((entry: any) => entry.event_type === 'action_completed')).toBe(true);
  });

  it('direct report_finding without prior validation still generates linked structured events', async () => {
    const result = await client.callTool({
      name: 'report_finding',
      arguments: {
        agent_id: 'test-agent',
        tool_name: 'manual',
        nodes: [
          { id: `host-direct-${Date.now()}`, type: 'host', label: 'direct manual host', properties: { ip: '10.10.10.77' } },
        ],
        edges: [],
      },
    });

    const body = JSON.parse((result.content as Array<{ type: string; text: string }>)[0].text);
    expect(body.action_id).toBeDefined();

    const historyResult = await client.callTool({ name: 'get_history', arguments: { limit: 100 } });
    const historyBody = JSON.parse((historyResult.content as Array<{ type: string; text: string }>)[0].text);
    const linkedEntries = historyBody.entries.filter((entry: any) => entry.action_id === body.action_id);
    expect(linkedEntries.some((entry: any) => entry.event_type === 'finding_reported')).toBe(true);
    expect(linkedEntries.some((entry: any) => entry.event_type === 'finding_ingested')).toBe(true);
  });

  it('get_skill returns skill content', async () => {
    const result = await client.callTool({
      name: 'get_skill',
      arguments: { query: 'nmap network recon' },
    });
    const content = result.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0].text);
    expect(body.top_match).toBeDefined();
    expect(body.top_match.content).toBeTruthy();
  });

  it('get_agent_context returns error for unknown task', async () => {
    const result = await client.callTool({
      name: 'get_agent_context',
      arguments: { task_id: 'nonexistent-task' },
    });
    expect(result.isError).toBe(true);
  });

  it('update_agent returns error for unknown task', async () => {
    const result = await client.callTool({
      name: 'update_agent',
      arguments: { task_id: 'nonexistent-task', status: 'failed' },
    });
    expect(result.isError).toBe(true);
  });

  it('export_graph returns full graph', async () => {
    const result = await client.callTool({ name: 'export_graph', arguments: {} });
    const content = result.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0].text);
    expect(body.nodes).toBeDefined();
    expect(body.edges).toBeDefined();
    expect(body.nodes.length).toBeGreaterThan(0);
  });

  it('run_retrospective returns context improvements and trace quality', async () => {
    const result = await client.callTool({ name: 'run_retrospective', arguments: {} });
    const content = result.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0].text);
    expect(body.context_improvements).toBeDefined();
    expect(body.context_improvements.recommendations).toBeInstanceOf(Array);
    expect(body.trace_quality).toBeDefined();
    expect(body.scoring).toBeUndefined();
  });
});
