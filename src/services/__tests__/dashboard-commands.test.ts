// ============================================================
// Dashboard /api/commands + /api/plans (Phase 3A NL cockpit)
//
// Boots a loopback DashboardServer (mutations need no token on loopback) and
// exercises: the grammar fast-path (preview + confirm), the headless-planner
// fallback (needs_planner → planner task spawned), the planner-proposed-plan
// confirm path (shared ProposedPlanStore), and deny.
// ============================================================

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig, AgentTask } from '../../types.js';

let dashboard: DashboardServer;
let engine: GraphEngine;
let baseUrl: string;
let tempDir: string;
let headlessAvail = true;

function makeConfig(): EngagementConfig {
  return {
    id: 'cmd-api', name: 'cmd api', created_at: new Date().toISOString(),
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [], opsec: { name: 'pentest', max_noise: 0.7, enabled: true },
  } as EngagementConfig;
}

const post = (body: unknown) => fetch(`${baseUrl}/api/commands`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});

beforeAll(async () => {
  tempDir = mkdtempSync(join(tmpdir(), 'overwatch-cmd-'));
  engine = new GraphEngine(makeConfig(), join(tempDir, 'state.json'));
  engine.registerAgent({
    id: 'target-1', agent_id: 'scanner-1', assigned_at: new Date().toISOString(),
    status: 'running', subgraph_node_ids: [],
  } as AgentTask);
  dashboard = new DashboardServer(engine, 0, '127.0.0.1', undefined, undefined);
  dashboard.attachTaskExecution({ cancelHeadless: () => false, isHeadlessAvailable: () => headlessAvail });
  const result = await dashboard.start();
  if (!result.started) throw new Error(`dashboard failed to start: ${result.error}`);
  baseUrl = dashboard.address;
});

afterAll(async () => {
  await dashboard?.stop().catch(() => {});
  try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

describe('/api/commands — grammar fast-path', () => {
  it('previews a recognized command without mutating, then confirms it', async () => {
    const preview = await (await post({ command: 'pause scanner-1' })).json();
    expect(preview.plan_id).toBeTruthy();
    expect(preview.ops).toHaveLength(1);
    expect(preview.needs_planner).toBe(false);
    // not yet executed — no directive pending
    expect(engine.getPendingAgentDirective('target-1')).toBeNull();

    const confirm = await (await post({ confirm: true, plan_id: preview.plan_id })).json();
    expect(confirm.executed).toBe(true);
    expect(confirm.results[0].ok).toBe(true);
    expect(engine.getPendingAgentDirective('target-1')?.kind).toBe('pause');
  });

  it('a stale/unknown plan_id returns 404', async () => {
    const res = await post({ confirm: true, plan_id: 'does-not-exist' });
    expect(res.status).toBe(404);
  });
});

describe('/api/commands — headless planner fallback', () => {
  it('a free-form command spawns a read-only planner task (daemon available)', async () => {
    headlessAvail = true;
    const r = await (await post({ command: 'go take care of the noisy box somehow' })).json();
    expect(r.needs_planner).toBe(true);
    expect(r.planner_available).toBe(true);
    expect(r.planner_task_id).toBeTruthy();
    const task = engine.getTask(r.planner_task_id);
    expect(task?.role).toBe('planner');
    expect(task?.backend).toBe('headless_mcp');
    expect(task?.objective).toContain('go take care of the noisy box somehow');
  });

  it('reports planner_available:false in stdio mode (no daemon)', async () => {
    headlessAvail = false;
    const r = await (await post({ command: 'please do the thing with the stuff' })).json();
    expect(r.needs_planner).toBe(true);
    expect(r.planner_available).toBe(false);
    expect(r.planner_task_id).toBeUndefined();
    headlessAvail = true;
  });
});

describe('/api/commands — planner-proposed plan confirm + deny + GET /api/plans', () => {
  it('confirms a plan from the shared ProposedPlanStore via the same path', async () => {
    const plan = engine.getProposedPlanStore().add({
      command: 'pause the scanner',
      ops: [{ op: 'directive', task_id: 'target-1', agent_label: 'scanner-1', kind: 'pause' }],
      summary: 'pause target-1', source_task_id: 'planner-task', source_agent_id: 'planner-x',
    });

    const list = await (await fetch(`${baseUrl}/api/plans`)).json();
    expect(list.plans.some((p: { plan_id: string }) => p.plan_id === plan.plan_id)).toBe(true);

    const confirm = await (await post({ confirm: true, plan_id: plan.plan_id })).json();
    expect(confirm.executed).toBe(true);
    expect(confirm.results[0].ok).toBe(true);
    // consumed — no longer open
    expect(engine.getProposedPlanStore().getOpen().some(p => p.plan_id === plan.plan_id)).toBe(false);
  });

  it('deny dismisses a proposed plan without executing it', async () => {
    const plan = engine.getProposedPlanStore().add({
      command: 'do a risky thing',
      ops: [{ op: 'scope', add_cidrs: ['10.9.9.0/24'] }],
      summary: 'widen scope',
    });
    const r = await (await post({ deny: true, plan_id: plan.plan_id })).json();
    expect(r.denied).toBe(true);
    expect(engine.getProposedPlanStore().getOpen().some(p => p.plan_id === plan.plan_id)).toBe(false);
    // scope was NOT widened
    expect(engine.getConfig().scope.cidrs).not.toContain('10.9.9.0/24');
  });
});
