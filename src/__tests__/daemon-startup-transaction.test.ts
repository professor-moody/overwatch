import { createServer, type Server } from 'node:net';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createOverwatchApp,
  shutdownOverwatchApp,
  startHttpApp,
  type OverwatchApp,
} from '../app.js';
import { readDaemonInstanceOwner } from '../services/daemon-instance-lease.js';
import type { EngagementConfig } from '../types.js';

const roots: string[] = [];
const servers: Server[] = [];
const apps: OverwatchApp[] = [];

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', () => resolveListen());
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('missing test listener address');
  return address.port;
}

async function freePort(): Promise<number> {
  const reservation = createServer();
  const port = await listen(reservation);
  await new Promise<void>(resolveClose => reservation.close(() => resolveClose()));
  return port;
}

function createTestApp(
  root: string,
  mcpPort: number,
  dashboardPort: number,
  name: string,
): { app: OverwatchApp; statePath: string } {
  const config: EngagementConfig = {
    id: `${name}-${Date.now()}`,
    name,
    created_at: '2026-07-17T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'test', max_noise: 1 },
  };
  const configPath = join(root, 'engagement.json');
  const statePath = join(root, 'state.json');
  writeFileSync(configPath, JSON.stringify(config));
  const app = createOverwatchApp({
    config,
    configPath,
    stateFilePath: statePath,
    skillDir: resolve('skills'),
    dashboardPort,
    runtimeOwnership: {
      transport: 'http',
      dashboard_url: `http://127.0.0.1:${dashboardPort}`,
      mcp_url: `http://127.0.0.1:${mcpPort}/mcp`,
    },
  });
  apps.push(app);
  return { app, statePath };
}

afterEach(async () => {
  for (const app of apps.splice(0)) {
    try { await shutdownOverwatchApp(app); } catch {}
  }
  for (const server of servers.splice(0)) {
    await new Promise<void>(resolveClose => server.close(() => resolveClose()));
  }
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('daemon startup transaction', () => {
  it('accepts managed shutdown only with MCP auth and the exact management nonce', async () => {
    const root = mkdtempSync(join(tmpdir(), 'overwatch-managed-shutdown-'));
    roots.push(root);
    const mcpPort = await freePort();
    const dashboardPort = await freePort();
    const { app } = createTestApp(root, mcpPort, dashboardPort, 'Managed shutdown control');
    const token = 'managed-shutdown-test-token';
    const nonce = 'managed-shutdown-test-nonce';
    const previous = {
      token: process.env.OVERWATCH_MCP_TOKEN,
      managed: process.env.OVERWATCH_DAEMON_MANAGED,
      nonce: process.env.OVERWATCH_DAEMON_MANAGEMENT_NONCE,
    };
    process.env.OVERWATCH_MCP_TOKEN = token;
    try {
      await startHttpApp(app, { port: mcpPort, host: '127.0.0.1' });
      const requestShutdown = vi.fn();
      app.requestManagedShutdown = requestShutdown;
      process.env.OVERWATCH_DAEMON_MANAGED = '1';
      process.env.OVERWATCH_DAEMON_MANAGEMENT_NONCE = nonce;

      const workerToken = (app.taskExecution as any).endpoint.tokenForTask('managed-shutdown-worker');
      const workerRejected = await fetch(`http://127.0.0.1:${mcpPort}/api/runtime/shutdown`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${workerToken}`,
          'x-overwatch-management-nonce': nonce,
        },
      });
      expect(workerRejected.status).toBe(403);
      expect(requestShutdown).not.toHaveBeenCalled();

      const rejected = await fetch(`http://127.0.0.1:${mcpPort}/api/runtime/shutdown`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'x-overwatch-management-nonce': 'wrong-nonce',
        },
      });
      expect(rejected.status).toBe(403);
      expect(requestShutdown).not.toHaveBeenCalled();

      const accepted = await fetch(`http://127.0.0.1:${mcpPort}/api/runtime/shutdown`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'x-overwatch-management-nonce': nonce,
        },
      });
      expect(accepted.status).toBe(202);
      await new Promise(resolveImmediate => setImmediate(resolveImmediate));
      expect(requestShutdown).toHaveBeenCalledTimes(1);
    } finally {
      if (previous.token === undefined) delete process.env.OVERWATCH_MCP_TOKEN;
      else process.env.OVERWATCH_MCP_TOKEN = previous.token;
      if (previous.managed === undefined) delete process.env.OVERWATCH_DAEMON_MANAGED;
      else process.env.OVERWATCH_DAEMON_MANAGED = previous.managed;
      if (previous.nonce === undefined) delete process.env.OVERWATCH_DAEMON_MANAGEMENT_NONCE;
      else process.env.OVERWATCH_DAEMON_MANAGEMENT_NONCE = previous.nonce;
    }
  });

  it('does not expose dashboard/workers when the MCP listener cannot bind', async () => {
    const root = mkdtempSync(join(tmpdir(), 'overwatch-daemon-startup-'));
    roots.push(root);
    const occupied = createServer();
    servers.push(occupied);
    const occupiedPort = await listen(occupied);
    const dashboardReservation = createServer();
    const dashboardPort = await listen(dashboardReservation);
    await new Promise<void>(resolveClose => dashboardReservation.close(() => resolveClose()));

    const config: EngagementConfig = {
      id: `daemon-startup-${Date.now()}`,
      name: 'Daemon startup transaction',
      created_at: '2026-07-17T00:00:00.000Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'test', max_noise: 1 },
    };
    const configPath = join(root, 'engagement.json');
    const statePath = join(root, 'state.json');
    writeFileSync(configPath, JSON.stringify(config));
    const app = createOverwatchApp({
      config,
      configPath,
      stateFilePath: statePath,
      skillDir: resolve('skills'),
      dashboardPort,
      runtimeOwnership: {
        transport: 'http',
        dashboard_url: `http://127.0.0.1:${dashboardPort}`,
        mcp_url: `http://127.0.0.1:${occupiedPort}/mcp`,
      },
    });
    apps.push(app);

    const priorRequireToken = process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
    process.env.OVERWATCH_MCP_REQUIRE_TOKEN = '0';
    try {
      await expect(startHttpApp(app, { port: occupiedPort, host: '127.0.0.1' }))
        .rejects.toMatchObject({ code: 'EADDRINUSE' });
    } finally {
      if (priorRequireToken === undefined) delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
      else process.env.OVERWATCH_MCP_REQUIRE_TOKEN = priorRequireToken;
    }
    expect(app.dashboard?.running).toBe(false);
    expect(app.taskExecution.isHeadlessAvailable()).toBe(false);
    expect(app.tape.isEnabled()).toBe(false);
    expect(readDaemonInstanceOwner(statePath)).toBeUndefined();
    apps.splice(apps.indexOf(app), 1);
    expect(readDaemonInstanceOwner(statePath)).toBeUndefined();
  });

  it('rolls back the MCP listener and ownership when the dashboard cannot bind', async () => {
    const root = mkdtempSync(join(tmpdir(), 'overwatch-daemon-dashboard-bind-'));
    roots.push(root);
    const mcpPort = await freePort();
    const occupiedDashboard = createServer();
    servers.push(occupiedDashboard);
    const dashboardPort = await listen(occupiedDashboard);
    const { app, statePath } = createTestApp(root, mcpPort, dashboardPort, 'Dashboard bind rollback');

    const priorRequireToken = process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
    process.env.OVERWATCH_MCP_REQUIRE_TOKEN = '0';
    try {
      await expect(startHttpApp(app, { port: mcpPort, host: '127.0.0.1' }))
        .rejects.toThrow('Dashboard ownership could not be acquired');
    } finally {
      if (priorRequireToken === undefined) delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
      else process.env.OVERWATCH_MCP_REQUIRE_TOKEN = priorRequireToken;
    }
    expect(app.dashboard?.running).toBe(false);
    expect(app.httpServer?.listening).toBe(false);
    expect(app.taskExecution.isHeadlessAvailable()).toBe(false);
    expect(app.tape.isEnabled()).toBe(false);
    expect(readDaemonInstanceOwner(statePath)).toBeUndefined();
  });

  it('rolls back a bound MCP listener when lease endpoint publication throws', async () => {
    const root = mkdtempSync(join(tmpdir(), 'overwatch-daemon-lease-bind-'));
    roots.push(root);
    const mcpPort = await freePort();
    const dashboardPort = await freePort();
    const { app, statePath } = createTestApp(root, mcpPort, dashboardPort, 'Lease endpoint rollback');
    vi.spyOn(app.runtimeLease!, 'update').mockImplementationOnce(() => {
      throw new Error('lease endpoint publication failed');
    });

    const priorRequireToken = process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
    process.env.OVERWATCH_MCP_REQUIRE_TOKEN = '0';
    try {
      await expect(startHttpApp(app, { port: mcpPort, host: '127.0.0.1' }))
        .rejects.toThrow('lease endpoint publication failed');
    } finally {
      if (priorRequireToken === undefined) delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
      else process.env.OVERWATCH_MCP_REQUIRE_TOKEN = priorRequireToken;
    }
    expect(app.dashboard?.running).toBe(false);
    expect(app.httpServer?.listening).toBe(false);
    expect(app.taskExecution.isHeadlessAvailable()).toBe(false);
    expect(readDaemonInstanceOwner(statePath)).toBeUndefined();
  });

  it('rolls back both listeners and state ownership when task execution preparation fails', async () => {
    const root = mkdtempSync(join(tmpdir(), 'overwatch-daemon-late-startup-'));
    roots.push(root);
    const mcpPort = await freePort();
    const dashboardPort = await freePort();
    const config: EngagementConfig = {
      id: `daemon-late-startup-${Date.now()}`,
      name: 'Daemon late startup transaction',
      created_at: '2026-07-17T00:00:00.000Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'test', max_noise: 1 },
    };
    const configPath = join(root, 'engagement.json');
    const statePath = join(root, 'state.json');
    writeFileSync(configPath, JSON.stringify(config));
    const app = createOverwatchApp({
      config,
      configPath,
      stateFilePath: statePath,
      skillDir: resolve('skills'),
      dashboardPort,
      runtimeOwnership: {
        transport: 'http',
        dashboard_url: `http://127.0.0.1:${dashboardPort}`,
        mcp_url: `http://127.0.0.1:${mcpPort}/mcp`,
      },
    });
    apps.push(app);
    vi.spyOn(app.taskExecution, 'start').mockImplementation(() => {
      throw new Error('task preparation failed');
    });
    const activate = vi.spyOn(app.taskExecution, 'activateAfterRuntimeReady');
    const priorRequireToken = process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
    process.env.OVERWATCH_MCP_REQUIRE_TOKEN = '0';
    try {
      await expect(startHttpApp(app, { port: mcpPort, host: '127.0.0.1' }))
        .rejects.toThrow('task preparation failed');
    } finally {
      if (priorRequireToken === undefined) delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
      else process.env.OVERWATCH_MCP_REQUIRE_TOKEN = priorRequireToken;
    }
    expect(activate).not.toHaveBeenCalled();
    expect(app.dashboard?.running).toBe(false);
    expect(app.httpServer?.listening).toBe(false);
    expect(app.runtimeLifecycle.phase).not.toMatch(/^ready/);
    expect(readDaemonInstanceOwner(statePath)).toBeUndefined();
  });

  it('rolls back READY when the final managed-record publication fails', async () => {
    const root = mkdtempSync(join(tmpdir(), 'overwatch-daemon-publish-failure-'));
    roots.push(root);
    const mcpPort = await freePort();
    const dashboardPort = await freePort();
    const config: EngagementConfig = {
      id: `daemon-publish-failure-${Date.now()}`,
      name: 'Daemon publication transaction',
      created_at: '2026-07-17T00:00:00.000Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'test', max_noise: 1 },
    };
    const configPath = join(root, 'engagement.json');
    const statePath = join(root, 'state.json');
    writeFileSync(configPath, JSON.stringify(config));
    const app = createOverwatchApp({
      config,
      configPath,
      stateFilePath: statePath,
      skillDir: resolve('skills'),
      dashboardPort,
      runtimeOwnership: {
        transport: 'http',
        dashboard_url: `http://127.0.0.1:${dashboardPort}`,
        mcp_url: `http://127.0.0.1:${mcpPort}/mcp`,
      },
    });
    apps.push(app);
    const activate = vi.spyOn(app.taskExecution, 'activateAfterRuntimeReady');
    const priorEnvironment = {
      requireToken: process.env.OVERWATCH_MCP_REQUIRE_TOKEN,
      managed: process.env.OVERWATCH_DAEMON_MANAGED,
      record: process.env.OVERWATCH_DAEMON_RECORD,
      nonce: process.env.OVERWATCH_DAEMON_MANAGEMENT_NONCE,
    };
    process.env.OVERWATCH_MCP_REQUIRE_TOKEN = '0';
    process.env.OVERWATCH_DAEMON_MANAGED = '1';
    process.env.OVERWATCH_DAEMON_RECORD = '/dev/null/overwatch-daemon.json';
    process.env.OVERWATCH_DAEMON_MANAGEMENT_NONCE = 'publication-failure-test';
    try {
      await expect(startHttpApp(app, { port: mcpPort, host: '127.0.0.1' }))
        .rejects.toThrow();
    } finally {
      const restore = (key: string, value: string | undefined) => {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      };
      restore('OVERWATCH_MCP_REQUIRE_TOKEN', priorEnvironment.requireToken);
      restore('OVERWATCH_DAEMON_MANAGED', priorEnvironment.managed);
      restore('OVERWATCH_DAEMON_RECORD', priorEnvironment.record);
      restore('OVERWATCH_DAEMON_MANAGEMENT_NONCE', priorEnvironment.nonce);
    }
    expect(activate).not.toHaveBeenCalled();
    expect(app.dashboard?.running).toBe(false);
    expect(app.httpServer?.listening).toBe(false);
    expect(app.runtimeLifecycle.phase).not.toMatch(/^ready/);
    expect(readDaemonInstanceOwner(statePath)).toBeUndefined();
  });

  it('continues later cleanup after synchronous shutdown hooks throw', async () => {
    const root = mkdtempSync(join(tmpdir(), 'overwatch-daemon-shutdown-errors-'));
    roots.push(root);
    const mcpPort = await freePort();
    const dashboardPort = await freePort();
    const { app } = createTestApp(root, mcpPort, dashboardPort, 'Shutdown error isolation');
    const priorRequireToken = process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
    process.env.OVERWATCH_MCP_REQUIRE_TOKEN = '0';
    try {
      await startHttpApp(app, { port: mcpPort, host: '127.0.0.1' });
    } finally {
      if (priorRequireToken === undefined) delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
      else process.env.OVERWATCH_MCP_REQUIRE_TOKEN = priorRequireToken;
    }

    const taskShutdown = vi.spyOn(app.taskExecution, 'shutdown');
    const sessionShutdown = vi.spyOn(app.sessionManager, 'shutdown').mockImplementation(() => {
      throw new Error('session shutdown failed synchronously');
    });
    const dashboardStop = vi.spyOn(app.dashboard!, 'stop');
    const tapeDisable = vi.spyOn(app.tape, 'disable');
    const engineDispose = vi.spyOn(app.engine, 'dispose');
    vi.spyOn(app.dashboard!, 'beginRuntimeShutdown').mockImplementation(() => {
      throw new Error('dashboard shutdown preparation failed');
    });
    Object.defineProperty(app.httpServer!, 'closeAllConnections', {
      configurable: true,
      value: vi.fn(() => { throw new Error('connection shutdown failed synchronously'); }),
    });

    await expect(shutdownOverwatchApp(app)).rejects.toThrow('dashboard shutdown preparation failed');
    expect(taskShutdown).toHaveBeenCalledOnce();
    expect(sessionShutdown).toHaveBeenCalledOnce();
    expect(dashboardStop).toHaveBeenCalledOnce();
    expect(tapeDisable).toHaveBeenCalledOnce();
    expect(engineDispose).toHaveBeenCalledOnce();
    expect(app.httpServer?.listening).toBe(false);
  });
});
