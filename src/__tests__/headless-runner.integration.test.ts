import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { resolve, join } from 'path';
import { existsSync, readFileSync, mkdtempSync, rmSync, chmodSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { createServer } from 'net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createOverwatchApp, startHttpApp, shutdownOverwatchApp, type OverwatchApp } from '../app.js';
import { parseEngagementConfig } from '../config.js';
import { withConfigMetadata } from '../services/engagement-config-service.js';
import { GraphEngine } from '../services/graph-engine.js';
import type { AgentTask } from '../types.js';

const supportsLocalListen = await new Promise<boolean>((resolveP) => {
  const srv = createServer();
  srv.on('error', () => { srv.close(); resolveP(false); });
  srv.listen(0, '127.0.0.1', () => { srv.close(); resolveP(true); });
});

const FAKE_CLAUDE = resolve('./src/test-support/fake-claude.mjs');
const rawConfig = readFileSync(resolve('./engagement.example.json'), 'utf-8');

async function freeLoopbackPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const address = server.address();
  const port = address && typeof address === 'object' ? address.port : 0;
  await new Promise<void>((resolveClose, reject) => {
    server.close(error => error ? reject(error) : resolveClose());
  });
  return port;
}

function waitFor(pred: () => boolean, timeoutMs = 12000): Promise<void> {
  return new Promise((res, rej) => {
    const start = Date.now();
    const tick = () => {
      if (pred()) return res();
      if (Date.now() - start > timeoutMs) return rej(new Error('waitFor timed out'));
      setTimeout(tick, 50);
    };
    tick();
  });
}

function headlessTask(id: string): AgentTask {
  return {
    id,
    agent_id: `agent-${id}`,
    assigned_at: new Date().toISOString(),
    status: 'running',
    subgraph_node_ids: [],
    backend: 'headless_mcp',
  };
}

describe.skipIf(!supportsLocalListen)('Headless runner end-to-end (fake claude) — 1B', () => {
  let app: OverwatchApp;
  let tempDir: string;
  const prevBinary = process.env.OVERWATCH_CLAUDE_BINARY;
  const prevMode = process.env.OVERWATCH_FAKE_MODE;
  const prevPlannerGate = process.env.OVERWATCH_FAKE_PLANNER_GATE;

  beforeAll(() => {
    chmodSync(FAKE_CLAUDE, 0o755);
  });

  beforeEach(async () => {
    process.env.OVERWATCH_CLAUDE_BINARY = FAKE_CLAUDE;
    tempDir = mkdtempSync(join(tmpdir(), 'ow-headless-int-'));
    const config = parseEngagementConfig(rawConfig);
    app = createOverwatchApp({
      config,
      skillDir: resolve('./skills'),
      dashboardPort: await freeLoopbackPort(),
      stateFilePath: join(tempDir, `state-${config.id}.json`),
    });
    await startHttpApp(app, { port: 0, host: '127.0.0.1' });
  });

  afterEach(async () => {
    delete process.env.OVERWATCH_FAKE_PLANNER_GATE;
    if (app) await shutdownOverwatchApp(app);
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  afterAll(() => {
    if (prevBinary === undefined) delete process.env.OVERWATCH_CLAUDE_BINARY; else process.env.OVERWATCH_CLAUDE_BINARY = prevBinary;
    if (prevMode === undefined) delete process.env.OVERWATCH_FAKE_MODE; else process.env.OVERWATCH_FAKE_MODE = prevMode;
    if (prevPlannerGate === undefined) delete process.env.OVERWATCH_FAKE_PLANNER_GATE; else process.env.OVERWATCH_FAKE_PLANNER_GATE = prevPlannerGate;
  });

  it('launches a headless sub-agent that connects, reports a finding, and completes its task', async () => {
    process.env.OVERWATCH_FAKE_MODE = 'complete';
    app.engine.registerAgent(headlessTask('e2e-complete'));

    // The fake connects back over HTTP, writes a finding, and calls update_agent.
    await waitFor(() => app.engine.getTask('e2e-complete')?.status === 'completed');

    // The sub-agent's write landed in the shared graph. report_finding derives
    // the host node id from its IP, so match on the IP rather than a literal id.
    const graph = app.engine.exportGraph();
    const wrote = graph.nodes.some((n: any) => JSON.stringify(n).includes('10.10.10.77'));
    expect(wrote).toBe(true);
    // Process cleaned up.
    await waitFor(() => app.taskExecution.activeHeadlessCount() === 0);
  }, 20000);

  it('cancel kills a hung headless sub-agent and marks the task interrupted', async () => {
    process.env.OVERWATCH_FAKE_MODE = 'hang';
    app.engine.registerAgent(headlessTask('e2e-hang'));

    // Wait until the process is live (it connected and is idling).
    await waitFor(() => app.taskExecution.activeHeadlessCount() === 1);

    const killed = app.taskExecution.cancelHeadless('e2e-hang', 'test cancel');
    expect(killed).toBe(true);

    await waitFor(() => app.engine.getTask('e2e-hang')?.status === 'interrupted');
    await waitFor(() => app.taskExecution.activeHeadlessCount() === 0);
  }, 20000);

  it('revokes a managed worker credential and closes its actor session after termination', async () => {
    process.env.OVERWATCH_FAKE_MODE = 'hang';
    app.engine.registerAgent(headlessTask('e2e-revoke-token'));
    const configPath = join(tmpdir(), 'overwatch-mcp-e2e-revoke-token.json');
    await waitFor(() => existsSync(configPath) && app.taskExecution.activeHeadlessCount() === 1);
    const config = JSON.parse(readFileSync(configPath, 'utf8')) as {
      mcpServers: { overwatch: { headers: { Authorization: string } } };
    };
    const capturedAuthorization = config.mcpServers.overwatch.headers.Authorization;
    expect(capturedAuthorization).toMatch(/^Bearer /);

    expect(app.taskExecution.cancelHeadless('e2e-revoke-token', 'credential revocation test'))
      .toBe(true);
    await waitFor(() => app.engine.getTask('e2e-revoke-token')?.status === 'interrupted');
    await waitFor(() => app.taskExecution.activeHeadlessCount() === 0);
    await new Promise(resolve => setTimeout(resolve, 25));

    const address = app.httpServer?.address();
    if (!address || typeof address === 'string') throw new Error('HTTP server is not bound');
    const response = await fetch(`http://127.0.0.1:${address.port}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: capturedAuthorization,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'stale-worker', version: '0.0.0' },
        },
      }),
    });
    expect(response.status).toBe(401);
  }, 20000);

  it('rejects reuse of an initialized MCP session under a different valid worker identity', async () => {
    process.env.OVERWATCH_FAKE_MODE = 'hang';
    app.engine.registerAgent(headlessTask('e2e-session-owner-a'));
    app.engine.registerAgent(headlessTask('e2e-session-owner-b'));
    const configA = join(tmpdir(), 'overwatch-mcp-e2e-session-owner-a.json');
    const configB = join(tmpdir(), 'overwatch-mcp-e2e-session-owner-b.json');
    await waitFor(() => existsSync(configA) && existsSync(configB)
      && app.taskExecution.activeHeadlessCount() === 2);
    const authorization = (path: string) => (JSON.parse(readFileSync(path, 'utf8')) as {
      mcpServers: { overwatch: { headers: { Authorization: string } } };
    }).mcpServers.overwatch.headers.Authorization;
    const tokenA = authorization(configA);
    const tokenB = authorization(configB);
    expect(tokenA).not.toBe(tokenB);
    const address = app.httpServer?.address();
    if (!address || typeof address === 'string') throw new Error('HTTP server is not bound');
    const endpoint = `http://127.0.0.1:${address.port}/mcp`;
    const baseHeaders = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    };
    const initialized = await fetch(endpoint, {
      method: 'POST',
      headers: { ...baseHeaders, Authorization: tokenA },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'initialize',
        params: {
          protocolVersion: '2025-06-18', capabilities: {},
          clientInfo: { name: 'owner-a-probe', version: '0.0.0' },
        },
      }),
    });
    expect(initialized.status).toBe(200);
    const sessionId = initialized.headers.get('mcp-session-id');
    expect(sessionId).toBeTruthy();

    const swapped = await fetch(endpoint, {
      method: 'POST',
      headers: {
        ...baseHeaders,
        Authorization: tokenB,
        'mcp-session-id': sessionId!,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
    });
    expect(swapped.status).toBe(401);

    await fetch(endpoint, {
      method: 'DELETE',
      headers: { ...baseHeaders, Authorization: tokenA, 'mcp-session-id': sessionId! },
    });
    expect(app.taskExecution.cancelHeadless('e2e-session-owner-a', 'session binding test')).toBe(true);
    expect(app.taskExecution.cancelHeadless('e2e-session-owner-b', 'session binding test')).toBe(true);
    await waitFor(() => app.taskExecution.activeHeadlessCount() === 0);
  }, 20000);

  it('a dashboard planner command stays durable through worker proposal and exit', async () => {
    process.env.OVERWATCH_FAKE_MODE = 'planner';
    const plannerGate = join(tempDir, 'planner-concurrency-gate');
    process.env.OVERWATCH_FAKE_PLANNER_GATE = plannerGate;
    // A running target the operator wants to steer (manual backend → the daemon
    // won't spawn a process for it; it just stays a steerable running task).
    app.engine.registerAgent({
      id: 'plan-target', agent_id: 'scanner-x', assigned_at: new Date().toISOString(),
      status: 'running', backend: 'manual', subgraph_node_ids: [],
    } as AgentTask);

    // Enter through the real dashboard command boundary so the planner task,
    // durable application command, proposal, and worker exit all share the
    // production ownership chain.
    const response = await fetch(`${app.dashboard!.address}/api/commands`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: 'go deal with that noisy scanner somehow' }),
    });
    expect(response.status).toBe(200);
    const queued = await response.json() as {
      command_id: string;
      planner_task_id: string;
      planner_status: string;
    };
    expect(queued).toMatchObject({
      command_id: expect.any(String),
      planner_task_id: expect.any(String),
      planner_status: 'accepted',
    });
    await waitFor(() => existsSync(`${plannerGate}.ready`), 18_000);
    expect(app.engine.getTask(queued.planner_task_id)?.status).toBe('running');
    expect(app.taskExecution.activeHeadlessCount()).toBe(1);
    expect(app.engine.getApplicationCommandById(queued.command_id)).toMatchObject({
      status: 'running',
      entity_refs: { planner_task_id: queued.planner_task_id },
    });

    // A terminal Claude/MCP client remains an independent sibling on the same
    // daemon while the dashboard-owned planner is running. Its read and write
    // must land in the same engine rather than starting a conflicting stdio
    // writer or inheriting the worker's task identity.
    const address = app.httpServer?.address();
    if (!address || typeof address === 'string') throw new Error('HTTP server is not bound');
    const terminalTransport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${address.port}/mcp`),
      {
        requestInit: process.env.OVERWATCH_MCP_TOKEN
          ? { headers: { Authorization: `Bearer ${process.env.OVERWATCH_MCP_TOKEN}` } }
          : undefined,
      },
    );
    const terminalClient = new Client({ name: 'terminal-claude', version: '0.1.0' });
    await terminalClient.connect(terminalTransport);
    try {
      const [stateRead, thoughtWrite] = await Promise.all([
        terminalClient.callTool({ name: 'get_state', arguments: {} }),
        terminalClient.callTool({
          name: 'log_thought',
          arguments: {
            kind: 'note',
            thought: 'terminal operator remains active during dashboard planning',
          },
        }),
      ]);
      expect(stateRead.content).toBeDefined();
      expect(thoughtWrite.content).toBeDefined();
      const spoofedLifecycle = await terminalClient.callTool({
        name: 'update_agent',
        arguments: {
          task_id: queued.planner_task_id,
          status: 'failed',
          summary: 'terminal must not close the dashboard planner',
        },
      });
      const lifecyclePayload = JSON.parse((spoofedLifecycle as {
        content: Array<{ text: string }>;
      }).content[0].text) as { code?: string; error?: string };
      expect(lifecyclePayload.code).toBe('AGENT_ACTOR_REQUIRED');
      expect(app.engine.getTask(queued.planner_task_id)?.status).toBe('running');
      expect(app.engine.getApplicationCommandById(queued.command_id)?.status).toBe('running');
      const spoofedProposal = await terminalClient.callTool({
        name: 'propose_plan',
        arguments: {
          task_id: queued.planner_task_id,
          agent_id: app.engine.getTask(queued.planner_task_id)?.agent_id,
          summary: 'terminal must not own this planner',
          ops: [{ op: 'scope', add_cidrs: ['10.77.77.0/24'] }],
        },
      });
      const spoofedPayload = JSON.parse((spoofedProposal as {
        content: Array<{ text: string }>;
      }).content[0].text) as {
        ok?: boolean;
        error?: string;
      };
      expect(spoofedPayload.ok).toBe(false);
      expect(spoofedPayload.error).toMatch(/authenticated planner task|owning planner/i);
      expect(app.engine.getProposedPlanStore().getOpen()).toHaveLength(0);
    } finally {
      await terminalClient.close();
    }

    // The planner was demonstrably live throughout the terminal calls. Release
    // it only after the actor-isolation assertions above have completed.
    writeFileSync(`${plannerGate}.release`, 'go');

    await waitFor(() => app.engine.getApplicationCommandById(queued.command_id)?.status === 'succeeded', 18000);
    const command = app.engine.getApplicationCommandById(queued.command_id)!;
    expect(command).toMatchObject({
      status: 'succeeded',
      plan_id: expect.any(String),
      entity_refs: {
        planner_task_id: queued.planner_task_id,
        plan_id: expect.any(String),
      },
    });
    const plan = app.engine.getProposedPlanStore().get(command.plan_id!);
    if (!plan) throw new Error('planner command succeeded without its linked plan');
    expect(plan.ops[0]).toMatchObject({ op: 'directive', task_id: 'plan-target', kind: 'pause' });

    // Operator confirm path: execute through the real HTTP application-command
    // boundary, not the retired test-only interpreter mutation helper.
    const confirmResponse = await fetch(`${app.dashboard!.address}/api/commands`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: true, plan_id: plan.plan_id }),
    });
    expect(confirmResponse.status).toBe(200);
    const confirmed = await confirmResponse.json() as {
      results: Array<{ ok: boolean; task?: { task_id: string; agent_label: string } }>;
    };
    expect(confirmed.results.every(result => result.ok)).toBe(true);
    expect(app.engine.getPendingAgentDirective('plan-target')?.kind).toBe('pause');

    // Planner closed itself out and the process is gone.
    await waitFor(() => app.engine.getTask(queued.planner_task_id)?.status === 'completed');
    await waitFor(() => app.taskExecution.activeHeadlessCount() === 0);
    expect(app.engine.getApplicationCommandById(queued.command_id)?.status).toBe('succeeded');
    expect(app.engine.getFullHistory().some(event =>
      event.description.includes('terminal operator remains active'))).toBe(true);
  }, 30000);

  it('restarts deferred planner execution after config reconciliation', async () => {
    process.env.OVERWATCH_FAKE_MODE = 'planner';
    await shutdownOverwatchApp(app);

    const configPath = join(tempDir, 'engagement.json');
    const statePath = join(tempDir, 'state-recovery.json');
    const durable = withConfigMetadata(parseEngagementConfig(rawConfig), 1);
    writeFileSync(configPath, JSON.stringify(durable));
    const seed = new GraphEngine(durable, statePath, configPath);
    seed.persistImmediate();
    seed.dispose();
    writeFileSync(configPath, JSON.stringify(withConfigMetadata({
      ...durable,
      name: 'Externally edited while stopped',
    }, 2)));

    app = createOverwatchApp({
      configPath,
      skillDir: resolve('./skills'),
      dashboardPort: await freeLoopbackPort(),
      stateFilePath: statePath,
    });
    await startHttpApp(app, { port: 0, host: '127.0.0.1' });
    expect(app.taskExecution.isHeadlessAvailable()).toBe(false);
    const blocked = app.engine.getPersistenceRecoveryStatus().config_recovery!;

    const resolved = await fetch(`${app.dashboard!.address}/api/recovery/config/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resolution: 'use_state',
        expected_file_hash: blocked.file_hash,
        expected_state_hash: blocked.state_hash,
      }),
    });
    expect(resolved.status).toBe(200);
    expect(app.engine.isPersistenceWritable()).toBe(true);
    expect(app.taskExecution.isHeadlessAvailable()).toBe(true);
    app.engine.registerAgent({
      id: 'plan-target',
      task_id: 'plan-target',
      agent_id: 'scanner-x',
      agent_label: 'scanner-x',
      assigned_at: new Date().toISOString(),
      status: 'running',
      backend: 'manual',
      subgraph_node_ids: [],
    });

    const response = await fetch(`${app.dashboard!.address}/api/commands`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: 'go deal with the noisy scanner somehow' }),
    });
    expect(response.status).toBe(200);
    const queued = await response.json() as {
      command_id: string;
      planner_task_id: string;
    };
    await waitFor(() =>
      app.engine.getApplicationCommandById(queued.command_id)?.status === 'succeeded',
    18_000);
    await waitFor(() =>
      app.engine.getTask(queued.planner_task_id)?.status === 'completed',
    18_000);
    expect(app.engine.getTask(queued.planner_task_id)?.status).toBe('completed');
  }, 30000);

  it('keeps managed planner identity when loopback global MCP auth is disabled', async () => {
    process.env.OVERWATCH_FAKE_MODE = 'planner';
    await shutdownOverwatchApp(app);
    const previousRequireToken = process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
    const previousToken = process.env.OVERWATCH_MCP_TOKEN;
    process.env.OVERWATCH_MCP_REQUIRE_TOKEN = '0';
    delete process.env.OVERWATCH_MCP_TOKEN;
    try {
      const config = parseEngagementConfig(rawConfig);
      app = createOverwatchApp({
        config,
        skillDir: resolve('./skills'),
        dashboardPort: await freeLoopbackPort(),
        stateFilePath: join(tempDir, 'state-open-loopback.json'),
      });
      await startHttpApp(app, { port: 0, host: '127.0.0.1' });
      expect(process.env.OVERWATCH_MCP_TOKEN).toBeUndefined();
      app.engine.registerAgent({
        id: 'open-loopback-target',
        task_id: 'open-loopback-target',
        agent_id: 'open-loopback-target',
        agent_label: 'open-loopback-target',
        assigned_at: new Date().toISOString(),
        status: 'running',
        backend: 'manual',
        subgraph_node_ids: [],
      });

      const response = await fetch(`${app.dashboard!.address}/api/commands`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'pause the open loopback target' }),
      });
      expect(response.status).toBe(200);
      const queued = await response.json() as { command_id: string; planner_task_id: string };
      await waitFor(() =>
        app.engine.getApplicationCommandById(queued.command_id)?.status === 'succeeded',
      18_000);
      expect(app.engine.getProposedPlanStore().getOpen()).toHaveLength(1);
      expect(app.engine.getTask(queued.planner_task_id)?.status).toBe('completed');
    } finally {
      if (previousRequireToken === undefined) delete process.env.OVERWATCH_MCP_REQUIRE_TOKEN;
      else process.env.OVERWATCH_MCP_REQUIRE_TOKEN = previousRequireToken;
      if (previousToken === undefined) delete process.env.OVERWATCH_MCP_TOKEN;
      else process.env.OVERWATCH_MCP_TOKEN = previousToken;
    }
  }, 30000);

  it('a headless agent escalates via ask_operator, waits, and proceeds on the operator answer (3D)', async () => {
    process.env.OVERWATCH_FAKE_MODE = 'ask';
    app.engine.registerAgent({
      id: 'e2e-ask', agent_id: 'agent-ask', assigned_at: new Date().toISOString(),
      status: 'running', backend: 'headless_mcp', subgraph_node_ids: [],
    } as AgentTask);

    // The fake agent connects, calls ask_operator, and starts heartbeating.
    await waitFor(() => app.engine.getAgentQueryStore().getOpen().length > 0, 18000);
    const q = app.engine.getAgentQueryStore().getOpen()[0];
    expect(q.task_id).toBe('e2e-ask');
    expect(q.question).toContain('loud');

    // Operator answers; the agent receives it on its next heartbeat and completes.
    app.engine.getAgentQueryStore().answer(q.query_id, 'stay quiet');
    await waitFor(() => app.engine.getTask('e2e-ask')?.status === 'completed', 18000);
    expect(app.engine.getTask('e2e-ask')?.result_summary).toContain('stay quiet');
    await waitFor(() => app.taskExecution.activeHeadlessCount() === 0);
  }, 30000);

  it('auto-dispatches a versioned service to a research agent that records a candidate CVE', async () => {
    process.env.OVERWATCH_FAKE_MODE = 'research';
    // Discovering a versioned service generates a cve_research frontier item,
    // which the daemon auto-dispatches to a headless research agent (the fake).
    app.engine.ingestFinding({
      id: 'seed-research', agent_id: 't', timestamp: new Date().toISOString(),
      nodes: [{ id: 'svc-research-e2e', type: 'service', label: 'http/8080', service_name: 'apache', version: '2.4.49' }],
      edges: [],
    } as any);

    // The fake research agent calls research_cve → service stamped + candidate ingested.
    await waitFor(() => app.engine.getNode('svc-research-e2e')?.cve_checked_at !== undefined, 18000);
    const vulns = app.engine.getNodesByType('vulnerability');
    expect(vulns.some((v: any) => v.cve === 'CVE-2021-41773')).toBe(true);
    // The cve_research frontier item is retired (no longer regenerated).
    const stillQueued = app.engine.computeFrontier().some(f => f.type === 'cve_research' && f.node_id === 'svc-research-e2e');
    expect(stillQueued).toBe(false);
    await waitFor(() => app.taskExecution.activeHeadlessCount() === 0);
  }, 30000);
});
