import { describe, it, expect, beforeAll, afterAll } from 'vitest';
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

const ENGAGEMENT_JSON = resolve('./engagement.example.json');
const rawConfig = readFileSync(ENGAGEMENT_JSON, 'utf-8');
const config = parseEngagementConfig(rawConfig);
const tempDir = mkdtempSync(join(tmpdir(), 'overwatch-session-limit-test-'));

let app: OverwatchApp;
let baseUrl: string;

function cleanup() {
  try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
}

describe.skipIf(!supportsLocalListen)('HTTP session limit', () => {
  const prevRequireToken = process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
  beforeAll(async () => {
    process.env.OVERWATCH_MCP_REQUIRE_TOKEN = '0'; // exercises session limits, not auth
    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath: join(tempDir, `state-${config.id}.json`),
    });

    // Start with maxSessions=2 for fast testing
    await startHttpApp(app, {
      port: 0,
      host: '127.0.0.1',
      maxSessions: 2,
      sessionIdleMs: 1_000,
    });

    const addr = app.httpServer?.address();
    if (!addr || typeof addr === 'string') throw new Error('Failed to get HTTP server address');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  }, 15000);

  afterAll(async () => {
    if (app) await shutdownOverwatchApp(app);
    if (prevRequireToken === undefined) delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN; else process.env.OVERWATCH_MCP_REQUIRE_TOKEN = prevRequireToken;
    cleanup();
  });

  it('returns 503 when max sessions exceeded', async () => {
    const initBody = {
      jsonrpc: '2.0',
      method: 'initialize',
      params: {
        protocolVersion: '2025-03-26',
        capabilities: {},
        clientInfo: { name: 'test', version: '0.1.0' },
      },
      id: 1,
    };

    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
    };

    // Open 2 sessions (the limit)
    const res1 = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers,
      body: JSON.stringify(initBody),
    });
    expect(res1.status).toBe(200);

    const sessionId = res1.headers.get('mcp-session-id');
    expect(sessionId).toBeTruthy();
    const sseAbort = new AbortController();
    const sse = await fetch(`${baseUrl}/mcp`, {
      headers: {
        Accept: 'text/event-stream',
        'mcp-session-id': sessionId!,
      },
      signal: sseAbort.signal,
    });
    expect(sse.status).toBe(200);

    // Pin the first session before opening the deliberately abandoned second
    // session. With a very short idle window, a loaded CI runner can otherwise
    // reap session one between initialize and this SSE request.
    const res2 = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers,
      body: JSON.stringify(initBody),
    });
    expect(res2.status).toBe(200);

    // Third session should be rejected
    const res3 = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers,
      body: JSON.stringify(initBody),
    });
    expect(res3.status).toBe(503);

    const body = await res3.json();
    expect(body.error.message).toContain('Too many active sessions');

    // Abandoned clients no longer consume the daemon's hard session capacity
    // forever. The reaper only closes records with no active response/SSE.
    const reaperDeadline = Date.now() + 5_000;
    let res4: globalThis.Response;
    do {
      await new Promise(resolveWait => setTimeout(resolveWait, 100));
      res4 = await fetch(`${baseUrl}/mcp`, {
        method: 'POST',
        headers,
        body: JSON.stringify(initBody),
      });
    } while (res4.status === 503 && Date.now() < reaperDeadline);
    expect(res4.status).toBe(200);

    const replacementSessionId = res4.headers.get('mcp-session-id');
    expect(replacementSessionId).toBeTruthy();
    const replacementSseAbort = new AbortController();
    const replacementSse = await fetch(`${baseUrl}/mcp`, {
      headers: {
        Accept: 'text/event-stream',
        'mcp-session-id': replacementSessionId!,
      },
      signal: replacementSseAbort.signal,
    });
    expect(replacementSse.status).toBe(200);

    const res5 = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers,
      body: JSON.stringify(initBody),
    });
    expect(res5.status).toBe(503);
    replacementSseAbort.abort();
    sseAbort.abort();
  });
});
