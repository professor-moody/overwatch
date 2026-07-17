#!/usr/bin/env npx tsx
// Isolated browser-journey fixture. Every run owns a temporary engagement
// directory and two dashboard daemons: one writable operator workspace and one
// intentionally diverged recovery workspace. Nothing here reads or writes an
// operator's engagement files.

import { createServer } from 'node:http';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseEngagementConfig } from '../src/config.js';
import { DashboardServer } from '../src/services/dashboard-server.js';
import { withConfigMetadata } from '../src/services/engagement-config-service.js';
import { GraphEngine } from '../src/services/graph-engine.js';
import { PlaybookRunService } from '../src/services/playbook-run-service.js';
import type { SessionManager } from '../src/services/session-manager.js';
import type { EngagementConfig, NodeProperties } from '../src/types.js';

const dashboardPort = Number.parseInt(process.env.OVERWATCH_BROWSER_PORT ?? '18484', 10);
const recoveryPort = Number.parseInt(process.env.OVERWATCH_BROWSER_RECOVERY_PORT ?? '18485', 10);
const controlPort = Number.parseInt(process.env.OVERWATCH_BROWSER_CONTROL_PORT ?? '18486', 10);
let activeDashboardPort = dashboardPort;
let activeRecoveryPort = recoveryPort;
const token = process.env.OVERWATCH_BROWSER_TOKEN ?? 'browser-ci-token / encoded';
process.env.OVERWATCH_DASHBOARD_TOKEN = token;

const fixtureRoot = mkdtempSync(join(tmpdir(), 'overwatch-browser-journey-'));
const root = join(fixtureRoot, 'engagement');
const dashboardStaticRoot = join(fixtureRoot, 'dashboard-next');
mkdirSync(root, { recursive: true });
cpSync(resolve('dist', 'dashboard-next'), dashboardStaticRoot, { recursive: true });
const now = '2026-07-17T00:00:00.000Z';
const browserSessionId = '00000000-0000-4000-8000-000000000014';
const browserSessionConnectionId = `${browserSessionId}:g1`;
const browserActionId = 'browser-live-action';
const browserSessionOutput = 'Browser journey session is ready.\r\n';

function baseConfig(id: string, name: string): EngagementConfig {
  return {
    id,
    name,
    created_at: now,
    scope: { cidrs: ['10.44.0.0/24'], domains: ['browser.test'], exclusions: [] },
    objectives: [{
      id: 'objective:browser-ci',
      description: 'Reach the browser journey objective',
      target_node_type: 'host',
      target_criteria: { id: 'browser-objective-host' },
      achievement_edge_types: ['ADMIN_TO'],
      achieved: false,
    }],
    opsec: { name: 'pentest', enabled: false, max_noise: 1 },
  } as EngagementConfig;
}

function seedWritableEngine(): GraphEngine {
  const engine = new GraphEngine(
    baseConfig('browser-journey', 'Browser Journey Engagement'),
    join(root, 'browser-state.json'),
  );
  const hosts: NodeProperties[] = Array.from({ length: 5 }, (_, index) => ({
    id: index === 0 ? 'browser-objective-host' : `browser-host-${index}`,
    type: 'host',
    label: index === 0 ? 'Browser Objective Host' : `Browser Host ${index}`,
    ip: `10.44.0.${10 + index}`,
    alive: true,
    confidence: 1,
    discovered_at: now,
  }));
  const credential: NodeProperties = {
    id: 'browser-credential',
    type: 'credential',
    label: 'Browser CI credential',
    cred_type: 'token',
    cred_material_kind: 'pat',
    credential_status: 'active',
    cred_user: 'browser-ci',
    cred_audience: 'browser.test',
    cred_value: 'browser-ci-redacted',
    confidence: 1,
    discovered_at: now,
  };
  for (const host of hosts) engine.addNode(host);
  engine.ingestFinding({
    id: 'browser-seed-finding',
    agent_id: 'browser-seed',
    action_id: 'browser-seed-action',
    tool_name: 'browser-fixture',
    timestamp: now,
    // Hosts are already present above. Keep the seed finding scoped to the
    // credential so the graph deep-link target has an intentionally empty
    // evidence chain (the empty response is itself part of that journey).
    target_node_ids: [credential.id],
    nodes: [credential],
    edges: [],
  });

  const computedFrontierIds = engine.getState().frontier
    .filter(item => item.type === 'incomplete_node')
    .map(item => item.id)
    .slice(0, 5);
  // Campaign storage intentionally preserves frontier IDs even when a candidate
  // later leaves the live frontier. Fill the deterministic browser fixture with
  // stale IDs when inference does not yield enough actionable candidates so the
  // campaign journeys also exercise that compatibility path.
  const frontierIds = Array.from({ length: 5 }, (_, index) => (
    computedFrontierIds[index] ?? `browser-stale-frontier-${index + 1}`
  ));
  engine.createCampaign({
    name: 'Browser draft campaign',
    strategy: 'custom',
    item_ids: frontierIds.slice(0, 2),
  });
  engine.createCampaign({
    name: 'Browser split parent',
    strategy: 'enumeration',
    item_ids: frontierIds.slice(1, 5),
  });

  const playbooks = new PlaybookRunService(engine);
  const opened = playbooks.open({
    definition: {
      definition_id: 'browser-playbook',
      definition_version: 1,
      provider: 'github',
      title: 'Browser credential validation',
    },
    credential_id: credential.id,
    normalized_inputs: { repository: 'overwatch/browser-ci' },
    steps: [{
      step_id: 'validate',
      step: 1,
      description: 'Validate browser credential',
      runner: 'run_tool',
      binary: 'printf',
      args: ['browser-ci'],
      parser: 'github_user',
      context: { credential_id: credential.id, repository: 'overwatch/browser-ci' },
      ready: true,
      status: 'ready',
    }],
  });
  const claim = playbooks.startStep(opened.run.run_id, 'validate');
  playbooks.finishAttempt(opened.run.run_id, 'validate', claim.attempt.attempt_id, {
    execution_outcome: 'failed',
    parse_outcome: 'no_data',
    error: 'Deterministic browser fixture failure',
  });

  // Keep one action genuinely in flight so the Analysis panel opens its
  // component-owned action-output WebSocket instead of relying on a direct
  // protocol probe. The buffer is intentionally left open until fixture stop.
  engine.logActionEvent({
    action_id: browserActionId,
    event_type: 'action_started',
    category: 'agent',
    agent_id: 'browser-seed',
    tool_name: 'browser-fixture',
    command_repr: 'browser-fixture --stream',
    description: 'Browser fixture action started',
    target_node_ids: [hosts[1].id],
    details: {
      command: 'browser-fixture --stream',
      binary: 'browser-fixture',
      invoking_tool: 'run_tool',
    },
  });
  engine.getActionOutputBuffer().open(browserActionId);
  engine.getActionOutputBuffer().append(
    browserActionId,
    'stdout',
    'Browser journey live output.\n',
  );
  engine.persistImmediate();
  return engine;
}

/** A deterministic connected generation used by the real Sessions panel. */
function createFixtureSessionManager(): SessionManager {
  const metadata = {
    id: browserSessionId,
    kind: 'pty' as const,
    adapter: 'browser-fixture',
    transport: 'pty',
    state: 'connected' as const,
    title: 'Browser journey terminal',
    connection_id: browserSessionConnectionId,
    connection_generation: 1,
    connection_started_at: now,
    started_at: now,
    last_activity_at: now,
    capabilities: {
      has_stdin: true,
      has_stdout: true,
      supports_resize: true,
      supports_signals: false,
      tty_quality: 'full',
    },
    buffer_end_pos: browserSessionOutput.length,
  };
  const read = (
    sessionId: string,
    fromPos?: number,
    tailBytes?: number,
  ) => {
    if (sessionId !== browserSessionId) throw new Error(`Session not found: ${sessionId}`);
    const end = browserSessionOutput.length;
    const start = fromPos !== undefined
      ? Math.min(Math.max(fromPos, 0), end)
      : Math.max(0, end - (tailBytes || 4096));
    return {
      session_id: browserSessionId,
      connection_id: browserSessionConnectionId,
      connection_generation: 1,
      start_pos: start,
      end_pos: end,
      text: browserSessionOutput.slice(start),
      truncated: false,
    };
  };
  return {
    list: () => [metadata],
    getSession: (sessionId: string) => sessionId === browserSessionId ? metadata : null,
    read,
    write: () => ({
      session_id: browserSessionId,
      connection_id: browserSessionConnectionId,
      connection_generation: 1,
      end_pos: browserSessionOutput.length,
    }),
    resize: () => metadata,
    onEvent: () => () => {},
  } as unknown as SessionManager;
}

function seedRecoveryEngine(): GraphEngine {
  const configPath = join(root, 'recovery-engagement.json');
  const statePath = join(root, 'recovery-state.json');
  const legacy = baseConfig('browser-recovery', 'Browser Recovery Engagement');
  writeFileSync(configPath, JSON.stringify(legacy));
  const first = new GraphEngine(legacy, statePath, configPath);
  first.persistImmediate();
  first.dispose();

  const durable = parseEngagementConfig(readFileSync(configPath, 'utf8'));
  const external = withConfigMetadata({
    ...durable,
    name: 'Externally edited browser recovery engagement',
  }, (durable.config_revision ?? 1) + 1);
  writeFileSync(configPath, JSON.stringify(external));
  return new GraphEngine(external, statePath, configPath);
}

let writableEngine: GraphEngine | undefined;
let recoveryEngine: GraphEngine | undefined;
let writableDashboard: DashboardServer | undefined;
let recoveryDashboard: DashboardServer | undefined;
let writableListening = false;
let recoveryListening = false;
let control: ReturnType<typeof createServer> | undefined;
let stopping = false;

function boundPort(address: string): number {
  return Number.parseInt(new URL(address).port, 10);
}

async function stopDashboards(): Promise<void> {
  const pending: Promise<unknown>[] = [];
  if (writableListening && writableDashboard) pending.push(writableDashboard.stop());
  if (recoveryListening && recoveryDashboard) pending.push(recoveryDashboard.stop());
  await Promise.allSettled(pending);
  writableEngine?.dispose();
  recoveryEngine?.dispose();
  writableEngine = undefined;
  recoveryEngine = undefined;
  writableDashboard = undefined;
  recoveryDashboard = undefined;
  writableListening = false;
  recoveryListening = false;
}

async function stop(): Promise<void> {
  if (stopping) return;
  stopping = true;
  if (control?.listening) {
    await new Promise<void>(resolve => control!.close(() => resolve()));
  }
  await stopDashboards();
  rmSync(fixtureRoot, { recursive: true, force: true });
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    void stop().finally(() => process.exit(0));
  });
}

async function startDashboards(): Promise<void> {
  writableEngine = seedWritableEngine();
  recoveryEngine = seedRecoveryEngine();
  writableDashboard = new DashboardServer(
    writableEngine,
    activeDashboardPort,
    '0.0.0.0',
    createFixtureSessionManager(),
    undefined,
    undefined,
    dashboardStaticRoot,
  );
  recoveryDashboard = new DashboardServer(
    recoveryEngine,
    activeRecoveryPort,
    '0.0.0.0',
    undefined,
    join(root, 'recovery-engagement.json'),
    undefined,
    dashboardStaticRoot,
  );

  const writableStarted = await writableDashboard.start();
  writableListening = writableStarted.started;
  if (!writableStarted.started) {
    throw new Error(`browser fixture failed to start writable dashboard: ${writableStarted.error ?? 'unknown error'}`);
  }
  const recoveryStarted = await recoveryDashboard.start();
  recoveryListening = recoveryStarted.started;
  if (!recoveryStarted.started) {
    throw new Error(`browser fixture failed to start recovery dashboard: ${recoveryStarted.error ?? 'unknown error'}`);
  }
  activeDashboardPort = boundPort(writableDashboard.address);
  activeRecoveryPort = boundPort(recoveryDashboard.address);
}

async function resetDashboards(): Promise<void> {
  await stopDashboards();
  rmSync(root, { recursive: true, force: true });
  mkdirSync(root, { recursive: true });
  await startDashboards();
}

async function startFixture(): Promise<void> {
  await startDashboards();

  let mutationCounter = 0;
  control = createServer((request, response) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    const json = (status: number, body: Record<string, unknown>) => {
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    if (url.pathname === '/health') {
      json(200, {
        ready: true,
        dashboard_port: boundPort(writableDashboard!.address),
        recovery_port: boundPort(recoveryDashboard!.address),
        token,
        session_id: browserSessionId,
        action_id: browserActionId,
      });
      return;
    }
    if (url.pathname === '/reset' && request.method === 'POST') {
      void resetDashboards().then(() => {
        mutationCounter = 0;
        json(200, {
          reset: true,
          dashboard_port: boundPort(writableDashboard!.address),
          recovery_port: boundPort(recoveryDashboard!.address),
        });
      }).catch((error) => {
        json(500, { error: error instanceof Error ? error.message : String(error) });
      });
      return;
    }
    if (url.pathname === '/drop-main-ws' && request.method === 'POST') {
      const clients = (writableDashboard as unknown as {
        clients: Set<{ terminate(): void }>;
      }).clients;
      for (const client of clients) client.terminate();
      mutationCounter += 1;
      const nodeId = `browser-resync-host-${mutationCounter}`;
      writableEngine!.addNode({
        id: nodeId,
        type: 'host',
        label: `Browser Resync Host ${mutationCounter}`,
        ip: `10.44.0.${100 + mutationCounter}`,
        alive: false,
        confidence: 1,
        discovered_at: now,
      });
      json(200, {
        node_id: nodeId,
        total_nodes: writableEngine!.getState().graph_summary.total_nodes,
      });
      return;
    }
    json(404, { error: 'not found' });
  });
  await new Promise<void>((resolve, reject) => {
    control!.once('error', reject);
    control!.listen(controlPort, '127.0.0.1', () => resolve());
  });

  const controlAddress = control.address();
  if (!controlAddress || typeof controlAddress === 'string') {
    throw new Error('browser fixture control server did not publish a TCP address');
  }

  console.log(JSON.stringify({
    ready: true,
    dashboard: `http://127.0.0.1:${boundPort(writableDashboard.address)}`,
    recovery: `http://127.0.0.1:${boundPort(recoveryDashboard.address)}`,
    control: `http://127.0.0.1:${controlAddress.port}`,
  }));
}

try {
  await startFixture();
} catch (error) {
  await stop();
  throw error;
}
