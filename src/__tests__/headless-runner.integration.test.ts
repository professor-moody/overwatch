import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { resolve, join } from 'path';
import { readFileSync, mkdtempSync, rmSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { createServer } from 'net';
import { createOverwatchApp, startHttpApp, shutdownOverwatchApp, type OverwatchApp } from '../app.js';
import { parseEngagementConfig } from '../config.js';
import { buildPlannerObjective, executeOps } from '../services/command-interpreter.js';
import type { AgentTask } from '../types.js';

const supportsLocalListen = await new Promise<boolean>((resolveP) => {
  const srv = createServer();
  srv.on('error', () => { srv.close(); resolveP(false); });
  srv.listen(0, '127.0.0.1', () => { srv.close(); resolveP(true); });
});

const FAKE_CLAUDE = resolve('./src/test-support/fake-claude.mjs');
const rawConfig = readFileSync(resolve('./engagement.example.json'), 'utf-8');

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
      dashboardPort: 0,
      stateFilePath: join(tempDir, `state-${config.id}.json`),
    });
    await startHttpApp(app, { port: 0, host: '127.0.0.1' });
  });

  afterEach(async () => {
    if (app) await shutdownOverwatchApp(app);
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  afterAll(() => {
    if (prevBinary === undefined) delete process.env.OVERWATCH_CLAUDE_BINARY; else process.env.OVERWATCH_CLAUDE_BINARY = prevBinary;
    if (prevMode === undefined) delete process.env.OVERWATCH_FAKE_MODE; else process.env.OVERWATCH_FAKE_MODE = prevMode;
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

  it('a headless PLANNER agent reads its objective, proposes a plan via propose_plan, and the plan is executable', async () => {
    process.env.OVERWATCH_FAKE_MODE = 'planner';
    // A running target the operator wants to steer (manual backend → the daemon
    // won't spawn a process for it; it just stays a steerable running task).
    app.engine.registerAgent({
      id: 'plan-target', agent_id: 'scanner-x', assigned_at: new Date().toISOString(),
      status: 'running', backend: 'manual', subgraph_node_ids: [],
    } as AgentTask);

    // Dispatch a planner exactly as the dashboard would: role 'planner', the
    // free-form command + steerable-state snapshot carried as the objective.
    const objective = buildPlannerObjective('please pause that noisy scanner', {
      tasks: [{ id: 'plan-target', agent_id: 'scanner-x', status: 'running' }],
      pendingActionIds: [],
    });
    app.engine.registerAgent({
      id: 'plan-er', agent_id: 'planner-1', assigned_at: new Date().toISOString(),
      status: 'running', backend: 'headless_mcp', role: 'planner', subgraph_node_ids: [], objective,
    } as AgentTask);

    // The fake planner connects over /mcp, reads the objective from its prompt,
    // and submits a directive(pause) on plan-target via propose_plan.
    await waitFor(() => app.engine.getProposedPlanStore().getOpen().length > 0, 18000);
    const plan = app.engine.getProposedPlanStore().getOpen()[0];
    expect(plan.ops[0]).toMatchObject({ op: 'directive', task_id: 'plan-target', kind: 'pause' });

    // Operator confirm path: the proposed ops execute through the validated
    // executeOps, issuing the directive the target will see on its next heartbeat.
    app.engine.getProposedPlanStore().resolve(plan.plan_id, 'confirmed');
    const results = executeOps(app.engine, plan.ops, 'operator');
    expect(results.every(r => r.ok)).toBe(true);
    expect(app.engine.getPendingAgentDirective('plan-target')?.kind).toBe('pause');

    // Planner closed itself out and the process is gone.
    await waitFor(() => app.engine.getTask('plan-er')?.status === 'completed');
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
