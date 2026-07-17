import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import {
  createOverwatchApp,
  getAutoTapeStartDecision,
  maybeAutoEnableTape,
  shutdownOverwatchApp,
  startHttpApp,
  type OverwatchApp,
} from '../app.js';
import type { EngagementConfig } from '../types.js';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: `test-tape-startup-${Math.random().toString(16).slice(2)}`,
    name: 'Tape Startup Test',
    created_at: '2026-05-26T00:00:00Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  };
}

describe('tape startup attribution', () => {
  let tmpDir: string;
  let app: OverwatchApp | null;
  let originalTapeEnv: string | undefined;
  let originalRequireToken: string | undefined;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'overwatch-tape-startup-'));
    app = null;
    originalTapeEnv = process.env.OVERWATCH_TAPE;
    delete process.env.OVERWATCH_TAPE;
    originalRequireToken = process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
    process.env.OVERWATCH_MCP_REQUIRE_TOKEN = '0'; // tape-recording test, not auth
  });

  afterEach(async () => {
    if (app) await shutdownOverwatchApp(app).catch(() => {});
    if (originalTapeEnv === undefined) delete process.env.OVERWATCH_TAPE;
    else process.env.OVERWATCH_TAPE = originalTapeEnv;
    if (originalRequireToken === undefined) delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
    else process.env.OVERWATCH_MCP_REQUIRE_TOKEN = originalRequireToken;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('attributes env-forced startup to env', () => {
    process.env.OVERWATCH_TAPE = '1';
    const config = makeConfig({ tape: { dir: tmpDir } });
    expect(getAutoTapeStartDecision(config)).toEqual({ enabled: true, startedBy: 'env' });

    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath: join(tmpDir, 'state-env.json'),
    });
    maybeAutoEnableTape(app);

    expect(app.tape.getStatus().enabled).toBe(true);
    expect(app.tape.getStatus().started_by).toBe('env');
  });

  it('attributes config startup to config', () => {
    const config = makeConfig({ tape: { enabled: true, dir: tmpDir } });
    expect(getAutoTapeStartDecision(config)).toEqual({ enabled: true, startedBy: 'config' });

    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath: join(tmpDir, 'state-config.json'),
    });
    maybeAutoEnableTape(app);

    expect(app.tape.getStatus().enabled).toBe(true);
    expect(app.tape.getStatus().started_by).toBe('config');
  });

  it('lets env false override config startup', () => {
    process.env.OVERWATCH_TAPE = '0';
    const config = makeConfig({ tape: { enabled: true, dir: tmpDir } });
    expect(getAutoTapeStartDecision(config)).toEqual({ enabled: false });

    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath: join(tmpDir, 'state-disabled.json'),
    });
    maybeAutoEnableTape(app);

    expect(app.tape.getStatus().enabled).toBe(false);
  });

  it('does not create an auto-tape artifact during degraded recovery', async () => {
    const tapeDir = join(tmpDir, 'degraded-tapes');
    const stateFilePath = join(tmpDir, 'state-degraded.json');
    const config = makeConfig({ tape: { enabled: true, dir: tapeDir } });
    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath,
    });
    app.engine.persistImmediate();
    await shutdownOverwatchApp(app);
    app = null;

    const future = JSON.parse(readFileSync(stateFilePath, 'utf8')) as Record<string, unknown>;
    future.state_version = 2;
    writeFileSync(stateFilePath, JSON.stringify(future));
    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath,
    });

    expect(app.engine.isPersistenceWritable()).toBe(false);
    expect(() => app!.tape.enable({ defaultDir: tapeDir })).toThrow(/durable mutations are disabled/i);
    maybeAutoEnableTape(app);
    expect(app.tape.getStatus().enabled).toBe(false);
    expect(existsSync(tapeDir)).toBe(false);
  });

  it('auto-enables tape for HTTP startup and records HTTP frames', async () => {
    const config = makeConfig({ tape: { enabled: true, dir: tmpDir } });
    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
      stateFilePath: join(tmpDir, 'state-http.json'),
    });
    await startHttpApp(app, { port: 0, host: '127.0.0.1' });

    const addr = app.httpServer?.address();
    if (!addr || typeof addr === 'string') throw new Error('Failed to get HTTP server address');

    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${addr.port}/mcp`));
    const client = new Client({ name: 'tape-startup-test', version: '0.1.0' });
    try {
      await client.connect(transport);
      await client.listTools();
      expect(app.tape.getStatus().enabled).toBe(true);
      expect(app.tape.getStatus().started_by).toBe('config');
      expect(app.tape.getStatus().frame_count).toBeGreaterThan(0);
    } finally {
      await client.close().catch(() => {});
    }
  }, 15000);
});
