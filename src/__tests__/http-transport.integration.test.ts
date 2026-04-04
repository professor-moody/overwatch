import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { resolve } from 'path';
import { readFileSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createServer } from 'net';
import { createOverwatchApp, startHttpApp, shutdownOverwatchApp, type OverwatchApp } from '../app.js';
import { parseEngagementConfig } from '../config.js';

const supportsLocalListen = await new Promise<boolean>((resolve) => {
  const srv = createServer();
  srv.on('error', () => { srv.close(); resolve(false); });
  srv.listen(0, '127.0.0.1', () => { srv.close(); resolve(true); });
});

const ENGAGEMENT_JSON = resolve('./engagement.json');
const rawConfig = readFileSync(ENGAGEMENT_JSON, 'utf-8');
const config = parseEngagementConfig(rawConfig);
const tempDir = mkdtempSync(join(tmpdir(), 'overwatch-http-test-'));

let app: OverwatchApp;
let client: Client;
let transport: StreamableHTTPClientTransport;
let baseUrl: string;

function cleanup() {
  try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
}

describe.skipIf(!supportsLocalListen)('MCP HTTP Transport Integration', () => {
  beforeAll(async () => {
    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath: join(tempDir, `state-${config.id}.json`),
    });

    await startHttpApp(app, { port: 0, host: '127.0.0.1' });

    // Read the actual bound port
    const addr = app.httpServer?.address();
    if (!addr || typeof addr === 'string') throw new Error('Failed to get HTTP server address');
    baseUrl = `http://127.0.0.1:${addr.port}`;

    transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`));
    client = new Client({ name: 'http-test-client', version: '0.1.0' });
    await client.connect(transport);
  }, 15000);

  afterAll(async () => {
    try { await client?.close(); } catch {}
    if (app) await shutdownOverwatchApp(app);
    cleanup();
  });

  it('lists all tools over HTTP transport', async () => {
    const result = await client.listTools();
    expect(result.tools.length).toBeGreaterThanOrEqual(1);
    const toolNames = result.tools.map(t => t.name).sort();
    expect(toolNames).toContain('get_state');
    expect(toolNames).toContain('update_scope');
    expect(toolNames).toContain('open_session');
    expect(toolNames).toContain('get_system_prompt');
  });

  it('get_state returns engagement state over HTTP', async () => {
    const result = await client.callTool({ name: 'get_state', arguments: {} });
    expect(result.content).toBeDefined();
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content.length).toBeGreaterThan(0);

    const state = JSON.parse(content[0].text);
    expect(state.config).toBeDefined();
    expect(state.config.id).toBe(config.id);
  });

  it('report_finding and query_graph work over HTTP', async () => {
    const finding = await client.callTool({
      name: 'report_finding',
      arguments: {
        agent_id: 'http-test-agent',
        nodes: [
          { id: 'http-host-1', type: 'host', label: '10.99.99.1' },
        ],
        edges: [],
      },
    });
    const findingContent = finding.content as Array<{ type: string; text: string }>;
    expect(findingContent.length).toBeGreaterThan(0);
    const findingBody = JSON.parse(findingContent[0].text);
    expect(findingBody.new_nodes.length).toBe(1);

    const query = await client.callTool({
      name: 'query_graph',
      arguments: { node_type: 'host' },
    });
    const queryBody = JSON.parse((query.content as Array<{ type: string; text: string }>)[0].text);
    expect(queryBody.nodes.some((n: any) => n.id === 'http-host-1')).toBe(true);
  });

  it('supports a second concurrent client session', async () => {
    const transport2 = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`));
    const client2 = new Client({ name: 'http-test-client-2', version: '0.1.0' });
    await client2.connect(transport2);

    const result = await client2.listTools();
    expect(result.tools.length).toBeGreaterThanOrEqual(1);

    // Second client sees the same graph state (shared engine)
    const query = await client2.callTool({
      name: 'query_graph',
      arguments: { node_type: 'host' },
    });
    const queryBody = JSON.parse((query.content as Array<{ type: string; text: string }>)[0].text);
    expect(queryBody.nodes.some((n: any) => n.id === 'http-host-1')).toBe(true);

    await client2.close();
  });

  it('rejects POST without session ID or initialize request', async () => {
    const resp = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }),
    });
    expect(resp.status).toBe(400);
  });

  it('rejects GET without valid session ID', async () => {
    const resp = await fetch(`${baseUrl}/mcp`, {
      method: 'GET',
      headers: { 'mcp-session-id': 'nonexistent-session-id' },
    });
    expect(resp.status).toBe(400);
  });
});
