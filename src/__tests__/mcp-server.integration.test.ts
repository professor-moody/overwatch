import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { unlinkSync, existsSync, readFileSync, readdirSync } from 'fs';
import { resolve, basename } from 'path';
import { createConnection, createServer, type Socket } from 'net';
import { setTimeout as delay } from 'timers/promises';
import * as pty from 'node-pty';

const ENGAGEMENT_JSON = resolve('./engagement.json');
const SKILLS_DIR = resolve('./skills');
const engagementId = JSON.parse(readFileSync(ENGAGEMENT_JSON, 'utf-8')).id;
const STATE_FILE = resolve(`./state-${engagementId}.json`);

let client: Client;
let transport: StdioClientTransport;

const supportsLocalPty = (() => {
  try {
    const proc = pty.spawn('/bin/sh', [], {
      name: 'xterm-256color',
      cols: 80,
      rows: 24,
      cwd: process.cwd(),
      env: { ...process.env as Record<string, string> },
    });
    proc.kill();
    return true;
  } catch {
    return false;
  }
})();

const supportsLocalListen = await new Promise<boolean>((resolve) => {
  const srv = createServer();
  srv.on('error', () => {
    srv.close();
    resolve(false);
  });
  srv.listen(0, '127.0.0.1', () => {
    srv.close();
    resolve(true);
  });
});

function cleanup() {
  if (existsSync(STATE_FILE)) unlinkSync(STATE_FILE);
  // Clean up snapshot files for this engagement
  const prefix = `state-${engagementId}.snap-`;
  const dir = resolve('.');
  try {
    for (const file of readdirSync(dir)) {
      if (file.startsWith(prefix) && file.endsWith('.json')) {
        unlinkSync(resolve(dir, file));
      }
    }
  } catch {}
}

function parseToolBody(result: Awaited<ReturnType<Client['callTool']>>) {
  return JSON.parse((result.content as Array<{ type: string; text: string }>)[0].text);
}

async function callToolJson(name: string, args: Record<string, unknown> = {}) {
  return parseToolBody(await client.callTool({ name, arguments: args }));
}

async function getFreePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close();
        reject(new Error('Failed to obtain ephemeral port'));
        return;
      }
      const { port } = address;
      server.close((err) => {
        if (err) reject(err);
        else resolvePort(port);
      });
    });
  });
}

async function waitForSessionState(sessionId: string, expectedState: string, timeoutMs: number = 2000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const body = await callToolJson('list_sessions', { session_id: sessionId });
    if (body.state === expectedState) return body;
    await delay(50);
  }
  throw new Error(`Timed out waiting for session ${sessionId} to reach state ${expectedState}`);
}

async function readUntilContains(sessionId: string, fromPos: number, needle: string, timeoutMs: number = 2000) {
  const start = Date.now();
  let cursor = fromPos;
  let combined = '';

  while (Date.now() - start < timeoutMs) {
    const body = await callToolJson('read_session', { session_id: sessionId, from_pos: cursor });
    cursor = body.end_pos;
    combined += body.text || '';
    if (combined.includes(needle)) {
      return { body, combined, endPos: cursor };
    }
    await delay(50);
  }

  throw new Error(`Timed out waiting for session output containing "${needle}"`);
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
        OVERWATCH_DASHBOARD_PORT: '0',
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

  it('lists all 36 tools including the session toolset', async () => {
    const result = await client.listTools();
    expect(result.tools.length).toBe(36);
    const toolNames = result.tools.map(t => t.name).sort();
    expect(toolNames).toContain('get_state');
    expect(toolNames).toContain('report_finding');
    expect(toolNames).toContain('next_task');
    expect(toolNames).toContain('validate_action');
    expect(toolNames).toContain('query_graph');
    expect(toolNames).toContain('find_paths');
    expect(toolNames).toContain('register_agent');
    expect(toolNames).toContain('dispatch_agents');
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
    expect(toolNames).toContain('correct_graph');
    expect(toolNames).toContain('recompute_objectives');
    expect(toolNames).toContain('open_session');
    expect(toolNames).toContain('write_session');
    expect(toolNames).toContain('read_session');
    expect(toolNames).toContain('send_to_session');
    expect(toolNames).toContain('list_sessions');
    expect(toolNames).toContain('update_session');
    expect(toolNames).toContain('resize_session');
    expect(toolNames).toContain('signal_session');
    expect(toolNames).toContain('close_session');
    expect(toolNames).toContain('update_scope');
    expect(toolNames).toContain('get_system_prompt');
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

  it('validate_action accepts in-scope target_ip without a graph node', async () => {
    const result = await client.callTool({
      name: 'validate_action',
      arguments: {
        target_ip: '10.10.110.5',
        tool_name: 'nmap',
        technique: 'portscan',
        description: 'Pre-discovery scan of in-scope IP',
      },
    });
    const content = result.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0].text);
    expect(body.valid).toBe(true);
    expect(body.action_id).toBeDefined();
  });

  it('validate_action rejects excluded target_ip', async () => {
    const result = await client.callTool({
      name: 'validate_action',
      arguments: {
        target_ip: '10.10.110.2',
        description: 'Scan excluded IP',
      },
    });
    const content = result.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0].text);
    expect(body.valid).toBe(false);
    expect(body.errors.some((e: string) => e.includes('out of scope'))).toBe(true);
  });

  it('next_task includes network_discovery frontier items', async () => {
    const result = await client.callTool({ name: 'next_task', arguments: {} });
    const content = result.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0].text);
    const discovery = body.candidates.filter((c: any) => c.type === 'network_discovery');
    expect(discovery.length).toBeGreaterThan(0);
    expect(discovery[0].target_cidr).toBe('10.10.110.0/24');
  });

  it('query_graph rejects deprecated free-text query payloads', async () => {
    const result = await client.callTool({
      name: 'query_graph',
      arguments: { query: 'credential' },
    });
    expect(result.isError).toBe(true);
    const body = JSON.parse((result.content as Array<{ type: string; text: string }>)[0].text);
    expect(body.error).toContain('Free-text query payloads are not supported');
  });

  it.skipIf(!supportsLocalPty)('supports a full local_pty session lifecycle through MCP', async () => {
    const opened = await callToolJson('open_session', {
      kind: 'local_pty',
      title: 'integration-local-shell',
      shell: '/bin/sh',
      cwd: resolve('.'),
      agent_id: 'owner-agent',
      cols: 100,
      rows: 30,
    });

    expect(opened.session.state).toBe('connected');
    expect(opened.session.claimed_by).toBe('owner-agent');

    const listed = await callToolJson('list_sessions', { session_id: opened.session.id });
    expect(listed.id).toBe(opened.session.id);
    expect(listed.title).toBe('integration-local-shell');

    const sent = await callToolJson('send_to_session', {
      session_id: opened.session.id,
      command: 'printf session-ready',
      agent_id: 'owner-agent',
      wait_for: 'session-ready',
      timeout_ms: 4000,
      idle_ms: 100,
    });
    expect(sent.text).toContain('session-ready');

    const write = await callToolJson('write_session', {
      session_id: opened.session.id,
      data: 'printf cursor-check',
      append_newline: true,
      agent_id: 'owner-agent',
    });
    const cursorRead = await readUntilContains(opened.session.id, write.end_pos, 'cursor-check');
    expect(cursorRead.combined).toContain('cursor-check');

    const updated = await callToolJson('update_session', {
      session_id: opened.session.id,
      title: 'integration-local-shell-upgraded',
      tty_quality: 'full',
      supports_resize: true,
      supports_signals: true,
      notes: 'session lifecycle check',
      agent_id: 'owner-agent',
    });
    expect(updated.title).toBe('integration-local-shell-upgraded');
    expect(updated.notes).toBe('session lifecycle check');
    expect(updated.capabilities.tty_quality).toBe('full');

    const resized = await callToolJson('resize_session', {
      session_id: opened.session.id,
      cols: 120,
      rows: 40,
      agent_id: 'owner-agent',
    });
    expect(resized.resized).toBe(true);

    const signaled = await callToolJson('signal_session', {
      session_id: opened.session.id,
      signal: 'SIGINT',
      agent_id: 'owner-agent',
    });
    expect(signaled.sent).toBe(true);

    const closed = await callToolJson('close_session', {
      session_id: opened.session.id,
      agent_id: 'owner-agent',
    });
    expect(closed.session.state).toBe('closed');
    expect(closed.final_output.session_id).toBe(opened.session.id);

    const activeSessions = await callToolJson('list_sessions', { active_only: true });
    expect(activeSessions.sessions.some((s: any) => s.id === opened.session.id)).toBe(false);
  });

  it.skipIf(!supportsLocalPty)('enforces ownership for claimed session control paths and allows force override', async () => {
    const opened = await callToolJson('open_session', {
      kind: 'local_pty',
      title: 'ownership-shell',
      shell: '/bin/sh',
      agent_id: 'owner-agent',
    });

    const omittedAgent = await client.callTool({
      name: 'write_session',
      arguments: {
        session_id: opened.session.id,
        data: 'printf denied',
        append_newline: true,
      },
    });
    expect(omittedAgent.isError).toBe(true);
    expect(parseToolBody(omittedAgent).error).toContain('claimed by "owner-agent"');

    const wrongAgent = await client.callTool({
      name: 'signal_session',
      arguments: {
        session_id: opened.session.id,
        signal: 'SIGINT',
        agent_id: 'other-agent',
      },
    });
    expect(wrongAgent.isError).toBe(true);
    expect(parseToolBody(wrongAgent).error).toContain('claimed by "owner-agent"');

    const forced = await callToolJson('send_to_session', {
      session_id: opened.session.id,
      command: 'printf forced-ok',
      agent_id: 'other-agent',
      force: true,
      wait_for: 'forced-ok',
      timeout_ms: 4000,
      idle_ms: 100,
    });
    expect(forced.text).toContain('forced-ok');

    const forceClosed = await callToolJson('close_session', {
      session_id: opened.session.id,
      agent_id: 'other-agent',
      force: true,
    });
    expect(forceClosed.session.state).toBe('closed');
  });

  it.skipIf(!supportsLocalListen)('supports a deterministic socket pending-to-connected lifecycle through MCP', async () => {
    const port = await getFreePort();
    const opened = await callToolJson('open_session', {
      kind: 'socket',
      title: 'integration-socket-listener',
      mode: 'listen',
      port,
      agent_id: 'socket-owner',
    });

    expect(opened.session.state).toBe('pending');

    const socketClient = await new Promise<Socket>((resolveSocket, reject) => {
      const sock = createConnection({ host: '127.0.0.1', port }, () => resolveSocket(sock));
      sock.once('error', reject);
    });

    const connected = await waitForSessionState(opened.session.id, 'connected');
    expect(connected.state).toBe('connected');

    socketClient.write('client-hello\n');
    const serverRead = await readUntilContains(opened.session.id, opened.initial_output.end_pos, 'client-hello');
    expect(serverRead.combined).toContain('client-hello');

    const clientData = new Promise<string>((resolveData, reject) => {
      const timeout = setTimeout(() => reject(new Error('Timed out waiting for socket data')), 2000);
      socketClient.once('data', (chunk) => {
        clearTimeout(timeout);
        resolveData(chunk.toString());
      });
      socketClient.once('error', reject);
    });

    await callToolJson('write_session', {
      session_id: opened.session.id,
      data: 'server-hello',
      append_newline: true,
      agent_id: 'socket-owner',
    });
    expect(await clientData).toContain('server-hello');

    const closed = await callToolJson('close_session', {
      session_id: opened.session.id,
      agent_id: 'socket-owner',
    });
    expect(closed.session.state).toBe('closed');

    socketClient.destroy();
  });

  it.skipIf(!supportsLocalPty)('session activity does not distort inline lab readiness', async () => {
    const before = await callToolJson('get_state', {});
    const baseline = JSON.stringify(before.lab_readiness);

    const opened = await callToolJson('open_session', {
      kind: 'local_pty',
      title: 'readiness-session-check',
      shell: '/bin/sh',
      agent_id: 'readiness-owner',
    });

    await callToolJson('send_to_session', {
      session_id: opened.session.id,
      command: 'printf readiness-ok',
      agent_id: 'readiness-owner',
      wait_for: 'readiness-ok',
      timeout_ms: 4000,
      idle_ms: 100,
    });

    const after = await callToolJson('get_state', {});
    expect(JSON.stringify(after.lab_readiness)).toBe(baseline);

    await callToolJson('close_session', {
      session_id: opened.session.id,
      agent_id: 'readiness-owner',
    });
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

  it.skipIf(!supportsLocalPty)('run_retrospective handles structured session lifecycle events sanely', async () => {
    const opened = await callToolJson('open_session', {
      kind: 'local_pty',
      title: 'retro-session-check',
      shell: '/bin/sh',
      agent_id: 'retro-owner',
    });

    await callToolJson('signal_session', {
      session_id: opened.session.id,
      signal: 'SIGINT',
      agent_id: 'retro-owner',
    });

    await callToolJson('close_session', {
      session_id: opened.session.id,
      agent_id: 'retro-owner',
    });

    const retro = await callToolJson('run_retrospective', {});
    expect(retro.training_traces).toBeInstanceOf(Array);
    expect(retro.training_traces.some((trace: any) =>
      ['session_opened', 'session_signaled', 'session_closed'].includes(trace.action?.type))).toBe(true);
  });
});
