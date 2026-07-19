#!/usr/bin/env npx tsx

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { chromium, type Browser } from '@playwright/test';
import {
  assertArtifactSnapshotUnchanged,
  snapshotSensitiveArtifacts,
} from '../src/test-support/artifact-hygiene.js';

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixtureRoot = mkdtempSync(join(tmpdir(), 'overwatch-dogfood-local-'));
const setupScript = join(workspaceRoot, 'scripts', 'setup.mjs');
const lifecycleScript = join(workspaceRoot, 'scripts', 'daemon-lifecycle.mjs');
const doctorScript = join(workspaceRoot, 'scripts', 'doctor.mjs');
const fakeClaude = join(workspaceRoot, 'src', 'test-support', 'fake-claude.mjs');
const protectedBefore = snapshotSensitiveArtifacts(workspaceRoot);
const sanitizedEnvironment = Object.fromEntries(
  Object.entries(process.env).filter(([name]) => !name.startsWith('OVERWATCH_')),
);

type Json = Record<string, any>;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function runNode(
  script: string,
  args: string[],
  environment: NodeJS.ProcessEnv,
  timeoutMs = 120_000,
): string {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: workspaceRoot,
    env: environment,
    encoding: 'utf8',
    timeout: timeoutMs,
  });
  if (result.status !== 0) {
    throw new Error([
      `${basename(script)} ${args.join(' ')} failed with ${result.status ?? result.signal ?? 'unknown status'}`,
      result.stdout,
      result.stderr,
    ].filter(Boolean).join('\n'));
  }
  return result.stdout;
}

async function reservePorts(count: number): Promise<number[]> {
  const servers = [];
  try {
    for (let index = 0; index < count; index++) {
      const server = createServer();
      await new Promise<void>((resolveListen, rejectListen) => {
        server.once('error', rejectListen);
        server.listen(0, '127.0.0.1', () => resolveListen());
      });
      servers.push(server);
    }
    return servers.map(server => {
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('could not reserve a dogfood port');
      return address.port;
    });
  } finally {
    await Promise.all(servers.map(server => new Promise<void>(resolveClose => server.close(() => resolveClose()))));
  }
}

async function waitFor<T>(
  label: string,
  check: () => Promise<T | undefined | false>,
  timeoutMs = 30_000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const value = await check();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await new Promise(resolveWait => setTimeout(resolveWait, 100));
  }
  throw new Error(`Timed out waiting for ${label}${lastError ? `: ${String(lastError)}` : ''}`);
}

function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function collectFiles(path: string): string[] {
  if (!existsSync(path)) return [];
  if (statSync(path).isFile()) return [path];
  return readdirSync(path, { withFileTypes: true })
    .flatMap(entry => collectFiles(join(path, entry.name)))
    .sort();
}

function parseToolResult(result: any, name: string): Json {
  const text = result?.content?.find((item: any) => item?.type === 'text')?.text;
  if (result?.isError) throw new Error(`${name} failed: ${text ?? 'unknown MCP error'}`);
  assert(typeof text === 'string', `${name} returned no text result`);
  try {
    return JSON.parse(text) as Json;
  } catch {
    throw new Error(`${name} returned non-JSON text: ${text.slice(0, 500)}`);
  }
}

async function connectMcp(mcpUrl: string, token: string, name: string): Promise<Client> {
  const client = new Client({ name, version: '0.0.0-dogfood' });
  const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  await client.connect(transport);
  return client;
}

async function mcpCall(client: Client, name: string, args: Json = {}): Promise<Json> {
  return parseToolResult(await client.callTool({ name, arguments: args }), name);
}

async function assertPortClosed(port: number): Promise<void> {
  await new Promise<void>((resolveCheck, rejectCheck) => {
    const socket = createServer();
    socket.once('error', error => rejectCheck(new Error(`port ${port} remains occupied`, { cause: error })));
    socket.listen(port, '127.0.0.1', () => socket.close(() => resolveCheck()));
  });
}

const [dashboardPort, mcpPort] = await reservePorts(2);
const dashboardBase = `http://127.0.0.1:${dashboardPort}`;
const mcpUrl = `http://127.0.0.1:${mcpPort}/mcp`;
const dashboardToken = 'dogfood dashboard token / encoded';
const environment: NodeJS.ProcessEnv = {
  ...sanitizedEnvironment,
  OVERWATCH_SETUP_ROOT: fixtureRoot,
  OVERWATCH_DOCTOR_RUNTIME_ROOT: fixtureRoot,
  OVERWATCH_RUNTIME_PROFILE: join(fixtureRoot, '.overwatch-runtime', 'profile.json'),
  OVERWATCH_DAEMON_RECORD: join(fixtureRoot, 'daemon.json'),
  OVERWATCH_DAEMON_LOG: join(fixtureRoot, 'daemon.log'),
  OVERWATCH_HTTP_HOST: '127.0.0.1',
  OVERWATCH_HTTP_PORT: String(mcpPort),
  OVERWATCH_DASHBOARD_HOST: '127.0.0.1',
  OVERWATCH_DASHBOARD_PORT: String(dashboardPort),
  OVERWATCH_DASHBOARD_TOKEN: dashboardToken,
  OVERWATCH_CLAUDE_BINARY: fakeClaude,
  OVERWATCH_FAKE_MODE: 'dogfood',
  OVERWATCH_AGENT_LOG_DIR: join(fixtureRoot, 'logs', 'agents'),
};
const dashboardHeaders = {
  Authorization: `Bearer ${dashboardToken}`,
  'Content-Type': 'application/json',
  Connection: 'close',
};

let terminalClient: Client | undefined;
let observerClient: Client | undefined;
let browser: Browser | undefined;
let daemonStarted = false;
let journeyError: unknown;

async function dashboardRequest(path: string, init: RequestInit = {}): Promise<Json> {
  const response = await fetch(`${dashboardBase}${path}`, {
    ...init,
    headers: { ...dashboardHeaders, ...(init.headers ?? {}) },
  });
  const text = await response.text();
  let body: Json = {};
  if (text) {
    try { body = JSON.parse(text) as Json; }
    catch { body = { text }; }
  }
  if (!response.ok) throw new Error(`${init.method ?? 'GET'} ${path} returned ${response.status}: ${text.slice(0, 1_000)}`);
  return body;
}

try {
  console.log('dogfood 1/12: setup creates one isolated managed engagement');
  const setupArgs = [
    '--template', join(workspaceRoot, 'engagement-templates', 'ctf.json'),
    '--name', 'Local dogfood qualification',
    '--id', 'dogfood-local',
    '--cidr', '10.77.0.0/24',
  ];
  const setupOutput = runNode(setupScript, setupArgs, environment);
  assert(setupOutput.includes('npm run daemon:start'), 'setup omitted the managed daemon start command');
  const configPath = join(fixtureRoot, 'engagement.json');
  const firstConfig = readFileSync(configPath);
  runNode(setupScript, [
    '--template', join(workspaceRoot, 'engagement-templates', 'ctf.json'),
    '--name', 'Must not replace dogfood',
    '--id', 'must-not-replace',
    '--cidr', '192.0.2.0/24',
  ], environment);
  assert(readFileSync(configPath).equals(firstConfig), 'repeated setup replaced the established engagement');

  const config = JSON.parse(firstConfig.toString('utf8')) as Json;
  config.opsec = {
    ...(config.opsec ?? {}),
    enabled: true,
    max_noise: 1,
    approval_mode: 'approve-all',
    approval_timeout_ms: 60_000,
  };
  config.cve_research = { enabled: false };
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });

  console.log('dogfood 2/12: one managed daemon starts and doctor passes');
  runNode(lifecycleScript, ['start'], environment);
  daemonStarted = true;
  const initialDaemonPid = (JSON.parse(readFileSync(environment.OVERWATCH_DAEMON_RECORD!, 'utf8')) as Json).pid as number;
  assert(Number.isSafeInteger(initialDaemonPid), 'managed start did not publish a daemon PID');
  await waitFor('writable daemon', async () => {
    const runtime = await dashboardRequest('/api/runtime');
    return runtime.runtime_status?.phase === 'ready'
      && runtime.runtime_status?.persistence_writable === true
      ? runtime
      : undefined;
  });
  const doctorBin = join(fixtureRoot, 'doctor-bin');
  mkdirSync(doctorBin, { recursive: true, mode: 0o700 });
  const doctorClaude = join(doctorBin, 'claude');
  writeFileSync(doctorClaude, `#!/bin/sh\ncase "$1" in\n  --version) echo "Claude Code dogfood" ;;\n  --help) echo "--strict-mcp-config --setting-sources --no-session-persistence --max-budget-usd" ;;\n  *) exit 0 ;;\nesac\n`, { mode: 0o700 });
  chmodSync(doctorClaude, 0o700);
  const doctor = runNode(doctorScript, [], {
    ...environment,
    PATH: `${doctorBin}:${environment.PATH ?? ''}`,
  });
  assert(doctor.includes('PASS Shared daemon'), 'doctor did not validate the shared daemon');

  console.log('dogfood 3/12: terminal-style and dashboard clients share the daemon');
  const mcpToken = readFileSync(join(fixtureRoot, '.overwatch-mcp-token'), 'utf8').trim();
  terminalClient = await connectMcp(mcpUrl, mcpToken, 'dogfood-terminal');
  observerClient = await connectMcp(mcpUrl, mcpToken, 'dogfood-observer');
  const terminalInitial = await mcpCall(terminalClient, 'get_state', { compact: true });
  const dashboardInitial = await dashboardRequest('/api/state');
  assert(JSON.stringify(terminalInitial).includes('dogfood-local'), 'terminal client loaded the wrong engagement');
  assert(JSON.stringify(dashboardInitial).includes('dogfood-local'), 'dashboard client loaded the wrong engagement');

  console.log('dogfood 4/12: live scope converges across both client surfaces');
  await mcpCall(terminalClient, 'update_scope', {
    add_domains: ['app.dogfood.test'],
    reason: 'isolated operator journey',
    confirm: true,
  });
  const configFromDashboard = await dashboardRequest('/api/config');
  assert(configFromDashboard.scope?.domains?.includes('app.dogfood.test'), 'dashboard did not observe terminal scope change');
  await dashboardRequest('/api/config', {
    method: 'PATCH',
    body: JSON.stringify({
      scope: {
        ...configFromDashboard.scope,
        cidrs: [...new Set([...(configFromDashboard.scope?.cidrs ?? []), '10.78.0.0/24'])],
      },
    }),
  });
  const scopeFromObserver = await mcpCall(observerClient, 'get_state', { compact: true });
  assert(JSON.stringify(scopeFromObserver).includes('10.78.0.0/24'), 'MCP observer did not see dashboard scope change');

  console.log('dogfood 5/12: planner command has durable identity and a terminal plan');
  const submittedCommand = await dashboardRequest('/api/commands', {
    method: 'POST',
    body: JSON.stringify({ command: 'work out how to investigate the isolated dogfood target' }),
  });
  assert(typeof submittedCommand.command_id === 'string', 'planner command did not return command_id');
  assert(typeof submittedCommand.planner_task_id === 'string', 'planner command did not return planner_task_id');
  const plannerCommand = await waitFor('terminal planner command', async () => {
    const body = await dashboardRequest(`/api/commands/${encodeURIComponent(submittedCommand.command_id)}`);
    return body.command?.status === 'succeeded' ? body.command : undefined;
  });
  assert(plannerCommand.result?.phase === 'plan_ready', 'planner command did not retain a terminal plan result');
  assert(typeof plannerCommand.plan_id === 'string', 'planner command did not persist its plan_id');

  console.log('dogfood 6/12: two clients dispatch distinct typed headless agents');
  const terminalDispatch = await mcpCall(terminalClient, 'register_agent', {
    agent_label: 'dogfood-terminal-recon',
    archetype: 'recon_scanner',
    skill: 'network-enumeration',
  });
  const terminalTaskId = terminalDispatch.task_id as string;
  assert(typeof terminalTaskId === 'string', 'terminal dispatch did not return task_id');
  const dashboardDispatch = await dashboardRequest('/api/agents/quick-deploy', {
    method: 'POST',
    body: JSON.stringify({ target: 'app.dogfood.test', archetype: 'web_tester' }),
  });
  const dashboardTaskId = (dashboardDispatch.task?.task_id ?? dashboardDispatch.task?.id) as string;
  assert(typeof dashboardTaskId === 'string', 'dashboard dispatch did not return task_id');
  assert(terminalTaskId !== dashboardTaskId, 'two clients received the same task identity');

  console.log('dogfood 7/12: an approval is queued and resolved through the dashboard');
  const approvalRun = terminalClient.callTool({
    name: 'run_tool',
    arguments: {
      binary: process.execPath,
      args: ['-e', 'process.stdout.write("dogfood-approved\\n")'],
      technique: 'local_fixture',
      description: 'Execute the isolated approval fixture',
      operator_infra: true,
      timeout_ms: 10_000,
    },
  });
  const pendingAction = await waitFor('pending approval', async () => {
    const body = await dashboardRequest('/api/actions/pending');
    return body.pending?.find((action: Json) => action.description === 'Execute the isolated approval fixture');
  });
  await dashboardRequest(`/api/actions/${encodeURIComponent(pendingAction.action_id)}/approve`, {
    method: 'POST',
    body: JSON.stringify({ notes: 'approved by isolated dogfood journey' }),
  });
  const approvedResult = parseToolResult(await approvalRun, 'run_tool');
  assert(approvedResult.executed === true, 'approved fixture did not execute');
  assert(String(approvedResult.stdout).includes('dogfood-approved'), 'approved fixture output was not captured');

  console.log('dogfood 8/12: agent question reaches the dashboard and receives an answer');
  const openQuery = await waitFor('open agent question', async () => {
    const body = await dashboardRequest('/api/agent-queries');
    return body.queries?.find((query: Json) => query.task_id === dashboardTaskId && query.status === 'open');
  });
  await dashboardRequest(`/api/agent-queries/${encodeURIComponent(openQuery.query_id)}/answer`, {
    method: 'POST',
    body: JSON.stringify({ answer: 'yes' }),
  });

  const completedAgents = await waitFor('both typed agents to complete', async () => {
    const body = await dashboardRequest('/api/agents');
    const selected = body.agents?.filter((agent: Json) => [terminalTaskId, dashboardTaskId].includes(agent.task_id));
    return selected?.length === 2 && selected.every((agent: Json) => agent.status === 'completed') ? selected : undefined;
  }, 45_000);
  assert(new Set(completedAgents.map((agent: Json) => agent.archetype)).size === 2, 'typed agents lost their distinct archetypes');
  const leasedFrontiers = completedAgents.map((agent: Json) => agent.frontier_item_id).filter(Boolean);
  assert(new Set(leasedFrontiers).size === leasedFrontiers.length, 'typed agents held a duplicate frontier lease');
  const answeredHistory = await dashboardRequest(`/api/agents/${encodeURIComponent(dashboardTaskId)}/history`);
  assert(JSON.stringify(answeredHistory).includes('operator answer: yes'), 'agent answer was not preserved in its durable transcript');

  console.log('dogfood 9/12: finding, evidence, and report land durably');
  const finding = await mcpCall(observerClient, 'report_finding', {
    agent_id: 'dogfood-terminal-operator',
    action_id: 'dogfood-manual-finding-action',
    tool_name: 'dogfood-fixture',
    nodes: [{
      id: 'dogfood-host-10-78-0-20',
      type: 'host',
      label: 'dogfood-host',
      properties: { ip: '10.78.0.20', alive: true },
    }],
    edges: [],
    evidence: {
      type: 'command_output',
      content: 'Synthetic fixture confirmed 10.78.0.20 is alive.',
      filename: 'dogfood-fixture.txt',
    },
    raw_output: '10.78.0.20 alive (synthetic; no network activity)',
  });
  assert(typeof finding.finding_id === 'string', 'report_finding returned no finding_id');
  assert(typeof finding.evidence_id === 'string', 'report_finding returned no evidence_id');
  const evidence = await mcpCall(terminalClient, 'get_evidence', { evidence_id: finding.evidence_id });
  assert(String(evidence.content).includes('Synthetic fixture'), 'evidence content was not retrievable');
  const report = await dashboardRequest('/api/reports/render', {
    method: 'POST',
    body: JSON.stringify({ format: 'markdown', client_safe: true }),
  });
  assert(typeof report.report?.id === 'string', 'report render returned no report id');
  const reportDownload = await fetch(`${dashboardBase}/api/reports/${encodeURIComponent(report.report.id)}`, {
    headers: { Authorization: `Bearer ${dashboardToken}`, Connection: 'close' },
  });
  assert(reportDownload.ok && (await reportDownload.arrayBuffer()).byteLength > 0, 'report download was empty');

  console.log('dogfood 10/12: every principal dashboard route renders while synchronized');
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const pageErrors: string[] = [];
  page.on('pageerror', error => pageErrors.push(error.message));
  await page.goto(`${dashboardBase}/agents?token=${encodeURIComponent(dashboardToken)}`, { waitUntil: 'domcontentloaded' });
  await page.getByText('Live', { exact: true }).waitFor({ timeout: 10_000 });
  const routes = [
    'agents', 'frontier', 'actions', 'campaigns', 'graph', 'findings', 'paths',
    'evidence', 'analysis', 'identity', 'credentials', 'recon', 'activity',
    'overview', 'sessions', 'engagements', 'settings', 'smoke',
  ];
  for (const route of routes) {
    console.log(`  dashboard route: /${route}`);
    await page.goto(`${dashboardBase}/${route}`, { waitUntil: 'domcontentloaded' });
    if (route === 'graph') {
      await page.getByRole('link', { name: 'Console' }).waitFor({ timeout: 10_000 });
      await page.locator('canvas').first().waitFor({ state: 'visible', timeout: 10_000 });
    } else {
      await page.locator('main').waitFor({ state: 'visible', timeout: 10_000 });
      await page.getByText('Live', { exact: true }).waitFor({ timeout: 10_000 });
      assert(!await page.getByText('Disconnected — reconnecting…', { exact: true }).isVisible(), `${route} rendered disconnected`);
    }
  }
  assert(pageErrors.length === 0, `dashboard emitted page errors: ${pageErrors.join('; ')}`);
  await browser.close();
  browser = undefined;

  console.log('dogfood 11/12: restart preserves scope, tasks, transcripts, findings, and evidence');
  await terminalClient.close();
  terminalClient = undefined;
  await observerClient.close();
  observerClient = undefined;
  runNode(lifecycleScript, ['restart'], environment);
  const restartedDaemonPid = (JSON.parse(readFileSync(environment.OVERWATCH_DAEMON_RECORD!, 'utf8')) as Json).pid as number;
  assert(Number.isSafeInteger(restartedDaemonPid), 'managed restart did not publish a daemon PID');
  assert(restartedDaemonPid !== initialDaemonPid, 'managed restart retained the original process identity');
  await waitFor('original daemon process exit', async () => !processIsAlive(initialDaemonPid));
  await waitFor('restarted writable daemon', async () => {
    const runtime = await dashboardRequest('/api/runtime');
    return runtime.runtime_status?.phase === 'ready'
      && runtime.runtime_status?.persistence_writable === true
      ? runtime
      : undefined;
  });
  terminalClient = await connectMcp(mcpUrl, mcpToken, 'dogfood-terminal-after-restart');
  const recoveredState = await dashboardRequest('/api/state');
  const recoveredText = JSON.stringify(recoveredState);
  for (const expected of [
    'app.dogfood.test', '10.78.0.0/24', terminalTaskId, dashboardTaskId,
    finding.finding_id, 'dogfood-host-10-78-0-20',
  ]) {
    assert(recoveredText.includes(expected), `restart lost ${expected}`);
  }
  const recoveredAgents = await dashboardRequest('/api/agents');
  for (const taskId of [submittedCommand.planner_task_id, terminalTaskId, dashboardTaskId]) {
    const agent = recoveredAgents.agents?.find((candidate: Json) => candidate.task_id === taskId);
    assert(agent?.status === 'completed', `restart did not truthfully restore completed task ${taskId}`);
    const history = await dashboardRequest(`/api/agents/${encodeURIComponent(taskId)}/history`);
    assert(JSON.stringify(history).includes('transcript'), `restart lost transcript history for ${taskId}`);
  }
  const recoveredEvidence = await mcpCall(terminalClient, 'get_evidence', { evidence_id: finding.evidence_id });
  assert(String(recoveredEvidence.content).includes('Synthetic fixture'), 'restart lost evidence content');
  const recoveredReports = await dashboardRequest('/api/reports');
  assert(recoveredReports.reports?.some((candidate: Json) => candidate.id === report.report.id), 'restart lost report manifest');
  const activeProcesses = await mcpCall(terminalClient, 'check_processes', { active_only: true });
  assert(activeProcesses.active === 0 && activeProcesses.processes?.length === 0, 'completed journey retained an active supervised process');

  const statePath = join(fixtureRoot, 'state-dogfood-local.json');
  const artifactFiles = [
    configPath,
    statePath,
    ...collectFiles(join(fixtureRoot, 'evidence')),
    ...collectFiles(join(fixtureRoot, 'reports')),
  ].filter(path => existsSync(path));
  const checksums = artifactFiles.map(path => ({
    path: path.slice(fixtureRoot.length + 1),
    sha256: sha256File(path),
  }));
  assert(checksums.some(entry => entry.path === basename(statePath)), 'journey did not produce durable state');

  console.log('dogfood 12/12: managed shutdown leaves no runtime or temporary artifacts');
  await terminalClient.close();
  terminalClient = undefined;
  runNode(lifecycleScript, ['stop'], environment);
  daemonStarted = false;
  assert(!existsSync(environment.OVERWATCH_DAEMON_RECORD!), 'daemon record remained after stop');
  assert(!existsSync(`${statePath}.migration-lock`), 'state migration lock remained after stop');
  await waitFor('restarted daemon process exit', async () => !processIsAlive(restartedDaemonPid));
  await assertPortClosed(dashboardPort);
  await assertPortClosed(mcpPort);

  console.log(JSON.stringify({
    ok: true,
    engagement_id: 'dogfood-local',
    planner_task_id: submittedCommand.planner_task_id,
    agent_task_ids: [terminalTaskId, dashboardTaskId],
    finding_id: finding.finding_id,
    evidence_id: finding.evidence_id,
    report_id: report.report.id,
    checked_dashboard_routes: routes.length,
    artifact_checksums: checksums,
  }, null, 2));
} catch (error) {
  journeyError = error;
  throw error;
} finally {
  const cleanupErrors: unknown[] = [];
  if (browser) await browser.close().catch(error => cleanupErrors.push(error));
  if (terminalClient) await terminalClient.close().catch(error => cleanupErrors.push(error));
  if (observerClient) await observerClient.close().catch(error => cleanupErrors.push(error));
  if (daemonStarted) {
    try { runNode(lifecycleScript, ['stop'], environment); }
    catch (error) { cleanupErrors.push(error); }
  }
  if (cleanupErrors.length === 0) rmSync(fixtureRoot, { recursive: true, force: true });
  assertArtifactSnapshotUnchanged(protectedBefore, snapshotSensitiveArtifacts(workspaceRoot));
  if (cleanupErrors.length === 0) {
    // Removal is part of the acceptance contract, not merely best-effort cleanup.
    assert(!existsSync(fixtureRoot), 'temporary runtime root remained after dogfood');
  }
  if (cleanupErrors.length > 0) {
    console.error(`Dogfood cleanup failed; preserved ${fixtureRoot}`);
    if (!journeyError) throw cleanupErrors[0];
  }
}
