import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { resolve, join } from 'path';
import { readFileSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { createServer } from 'net';
import { createOverwatchApp, startHttpApp, shutdownOverwatchApp, type OverwatchApp } from '../app.js';
import { parseEngagementConfig } from '../config.js';

const supportsLocalListen = await new Promise<boolean>((resolve) => {
  const srv = createServer();
  srv.on('error', () => { srv.close(); resolve(false); });
  srv.listen(0, '127.0.0.1', () => { srv.close(); resolve(true); });
});

const ENGAGEMENT_JSON = resolve('./engagement.example.json');
const rawConfig = readFileSync(ENGAGEMENT_JSON, 'utf-8');

function waitFor(pred: () => boolean, timeoutMs = 4000): Promise<void> {
  return new Promise((resolveP, reject) => {
    const start = Date.now();
    const tick = () => {
      if (pred()) return resolveP();
      if (Date.now() - start > timeoutMs) return reject(new Error('waitFor timed out'));
      setTimeout(tick, 20);
    };
    tick();
  });
}

describe.skipIf(!supportsLocalListen)('Approval over HTTP — abort + timeout (1A)', () => {
  let app: OverwatchApp;
  let client: Client;
  let baseUrl: string;
  let tempDir: string;
  const APPROVAL_TIMEOUT_MS = 300_000;
  const prevRequireToken = process.env.OVERWATCH_MCP_REQUIRE_TOKEN;

  beforeAll(async () => {
    // Exercises the approval/abort flow, not auth — open loopback for the test.
    process.env.OVERWATCH_MCP_REQUIRE_TOKEN = '0';
    tempDir = mkdtempSync(join(tmpdir(), 'overwatch-approval-http-'));
    const config = parseEngagementConfig(rawConfig);
    // Force the approval gate so validate_action blocks.
    config.opsec = { ...config.opsec, approval_mode: 'approve-all', approval_timeout_ms: APPROVAL_TIMEOUT_MS };

    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath: join(tempDir, `state-${config.id}.json`),
    });
    await startHttpApp(app, { port: 0, host: '127.0.0.1' });
    const addr = app.httpServer?.address();
    if (!addr || typeof addr === 'string') throw new Error('no server address');
    baseUrl = `http://127.0.0.1:${addr.port}`;

    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`));
    client = new Client({ name: 'approval-test-client', version: '0.1.0' });
    await client.connect(transport);
  }, 15000);

  afterAll(async () => {
    try { await client?.close(); } catch { /* ignore */ }
    if (app) await shutdownOverwatchApp(app);
    if (prevRequireToken === undefined) delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN; else process.env.OVERWATCH_MCP_REQUIRE_TOKEN = prevRequireToken;
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('sets a finite HTTP requestTimeout that outlives the approval window', () => {
    // The fix: socket must not die before the approval can resolve. requestTimeout
    // is approval_timeout_ms + margin (NOT 0/unbounded, NOT Node's ~5min default
    // which would race the approval timeout).
    expect(app.httpServer?.requestTimeout).toBe(APPROVAL_TIMEOUT_MS + 60_000);
    expect(app.httpServer?.requestTimeout).toBeGreaterThan(APPROVAL_TIMEOUT_MS);
  });

  it('resolves a blocked approval as aborted when the client cancels, reclaiming the slot', async () => {
    const queue = app.engine.getPendingActionQueue();
    expect(queue.getPendingCount()).toBe(0);

    const controller = new AbortController();
    const call = client.callTool(
      {
        name: 'validate_action',
        arguments: {
          action_id: 'http-abort-1',
          target_ip: '10.10.10.50',
          description: 'blocking action to be aborted',
          allow_unverified_scope: true,
        },
      },
      undefined,
      { signal: controller.signal },
    ).then(() => 'resolved').catch(() => 'rejected');

    // Wait until the server has queued the pending approval, then cancel.
    await waitFor(() => queue.getPendingCount() === 1);
    controller.abort();

    // Client request unwinds (cancelled).
    expect(await call).toBe('rejected');

    // Server-side: the pending approval is resolved as 'aborted' (not orphaned
    // until the 5-minute timeout), and the durable record reflects it.
    await waitFor(() => queue.getPendingCount() === 0);
    const resolution = queue.getResolution('http-abort-1');
    expect(resolution?.status).toBe('aborted');
  }, 15000);
});

describe.skipIf(!supportsLocalListen)('/mcp auth wiring (1A)', () => {
  let app: OverwatchApp;
  let baseUrl: string;
  let tempDir: string;
  const prevToken = process.env.OVERWATCH_MCP_TOKEN;
  const prevRequire = process.env.OVERWATCH_MCP_REQUIRE_TOKEN;

  beforeAll(async () => {
    process.env.OVERWATCH_MCP_TOKEN = 'integration-secret';
    process.env.OVERWATCH_MCP_REQUIRE_TOKEN = '1';
    tempDir = mkdtempSync(join(tmpdir(), 'overwatch-mcpauth-'));
    const config = parseEngagementConfig(rawConfig);
    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath: join(tempDir, `state-${config.id}.json`),
    });
    await startHttpApp(app, { port: 0, host: '127.0.0.1' });
    const addr = app.httpServer?.address();
    if (!addr || typeof addr === 'string') throw new Error('no server address');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  }, 15000);

  afterAll(async () => {
    if (app) await shutdownOverwatchApp(app);
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
    if (prevToken === undefined) delete process.env.OVERWATCH_MCP_TOKEN; else process.env.OVERWATCH_MCP_TOKEN = prevToken;
    if (prevRequire === undefined) delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN; else process.env.OVERWATCH_MCP_REQUIRE_TOKEN = prevRequire;
  });

  const initBody = JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'c', version: '0' } },
  });

  it('rejects /mcp without a bearer token (401)', async () => {
    const resp = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
      body: initBody,
    });
    expect(resp.status).toBe(401);
  });

  it('rejects /mcp with a wrong token (401)', async () => {
    const resp = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: 'Bearer wrong' },
      body: initBody,
    });
    expect(resp.status).toBe(401);
  });

  it('admits /mcp with the correct token (not 401/403)', async () => {
    const resp = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: 'Bearer integration-secret' },
      body: initBody,
    });
    expect(resp.status).not.toBe(401);
    expect(resp.status).not.toBe(403);
  });
});

// Fail-closed DEFAULT: with no token configured and no opt-out, the daemon must
// generate a token and require it — /mcp is never open on loopback by default.
describe.skipIf(!supportsLocalListen)('/mcp auth fail-closed default (generated token)', () => {
  let app: OverwatchApp;
  let baseUrl: string;
  let tempDir: string;
  let generatedToken: string | undefined;
  const prevToken = process.env.OVERWATCH_MCP_TOKEN;
  const prevRequire = process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
  const prevTokenFile = process.env.OVERWATCH_MCP_TOKEN_FILE;

  beforeAll(async () => {
    delete process.env.OVERWATCH_MCP_TOKEN;       // no token configured
    delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN; // default (require)
    tempDir = mkdtempSync(join(tmpdir(), 'overwatch-mcpauth-default-'));
    process.env.OVERWATCH_MCP_TOKEN_FILE = join(tempDir, '.overwatch-mcp-token');
    const config = parseEngagementConfig(rawConfig);
    app = createOverwatchApp({ config, skillDir: resolve('./skills'), dashboardPort: 0, stateFilePath: join(tempDir, `state-${config.id}.json`) });
    await startHttpApp(app, { port: 0, host: '127.0.0.1' });
    generatedToken = process.env.OVERWATCH_MCP_TOKEN; // startHttpApp generates it
    const addr = app.httpServer?.address();
    if (!addr || typeof addr === 'string') throw new Error('no server address');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  }, 15000);

  afterAll(async () => {
    if (app) await shutdownOverwatchApp(app);
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
    if (prevToken === undefined) delete process.env.OVERWATCH_MCP_TOKEN; else process.env.OVERWATCH_MCP_TOKEN = prevToken;
    if (prevRequire === undefined) delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN; else process.env.OVERWATCH_MCP_REQUIRE_TOKEN = prevRequire;
    if (prevTokenFile === undefined) delete process.env.OVERWATCH_MCP_TOKEN_FILE; else process.env.OVERWATCH_MCP_TOKEN_FILE = prevTokenFile;
  });

  const initBody = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'c', version: '0' } } });

  it('generates a token when none is configured', () => {
    expect(typeof generatedToken).toBe('string');
    expect((generatedToken ?? '').length).toBeGreaterThanOrEqual(16);
  });

  it('rejects loopback /mcp without the generated token (401) — not open by default', async () => {
    const resp = await fetch(`${baseUrl}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: initBody });
    expect(resp.status).toBe(401);
  });

  it('admits /mcp with the generated token', async () => {
    const resp = await fetch(`${baseUrl}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: `Bearer ${generatedToken}` }, body: initBody });
    expect(resp.status).not.toBe(401);
    expect(resp.status).not.toBe(403);
  });
});
