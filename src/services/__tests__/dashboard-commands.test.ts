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
import { recordProposedPlan } from '../../tools/propose-plan.js';
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
  engine?.dispose();
  try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

describe('/api/agents/dispatch — contract (regression for the node_ids vs target_node_ids bug)', () => {
  const dispatch = (body: unknown) => fetch(`${baseUrl}/api/agents/dispatch`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });

  it('rejects the OLD client shape { node_ids } with 400', async () => {
    const res = await dispatch({ node_ids: ['n1', 'n2'] });
    expect(res.status).toBe(400);
  });

  it('accepts { target_node_ids } and registers the agent (201)', async () => {
    const res = await dispatch({ target_node_ids: ['n1', 'n2'], skill: 'enumeration' });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.dispatched).toBe(true);
    expect(body.task?.subgraph_node_ids).toEqual(['n1', 'n2']);
  });
});

describe('/api/agents/:id/directive — per-agent steering (Phase 3B)', () => {
  const directive = (taskId: string, body: unknown) => fetch(`${baseUrl}/api/agents/${taskId}/directive`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  // Use a dedicated agent so issuing directives here doesn't pollute target-1
  // (the grammar tests below assert it has no pending directive pre-confirm).
  beforeAll(() => {
    engine.registerAgent({
      id: 'steer-1', agent_id: 'steerable', assigned_at: new Date().toISOString(),
      status: 'running', subgraph_node_ids: [],
    } as AgentTask);
  });

  it('issues a pause directive to a running agent (200) and records it', async () => {
    const res = await directive('steer-1', { kind: 'pause' });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(engine.getPendingAgentDirective('steer-1')?.kind).toBe('pause');
  });

  it('rejects an unknown directive kind (400)', async () => {
    const res = await directive('steer-1', { kind: 'detonate' });
    expect(res.status).toBe(400);
  });

  it('409s when the agent is not running', async () => {
    engine.registerAgent({
      id: 'done-1', agent_id: 'done-agent', assigned_at: new Date().toISOString(),
      status: 'completed', subgraph_node_ids: [],
    } as AgentTask);
    const res = await directive('done-1', { kind: 'pause' });
    expect(res.status).toBe(409);
  });

  it('404s for an unknown task', async () => {
    const res = await directive('ghost', { kind: 'stop' });
    expect(res.status).toBe(404);
  });

  it('accepts a free-text instruct directive (Phase 3C)', async () => {
    const res = await directive('steer-1', { kind: 'instruct', note: 'focus on SMB' });
    expect(res.status).toBe(200);
    const dir = engine.getPendingAgentDirective('steer-1');
    expect(dir?.kind).toBe('instruct');
    expect(dir?.note).toBe('focus on SMB');
  });
});

describe('/api/fleet/directive — fleet-level steering (Phase 3C)', () => {
  const fleet = (body: unknown) => fetch(`${baseUrl}/api/fleet/directive`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });

  it('applies pause to all running agents in a campaign (scoped so other agents are untouched)', async () => {
    engine.registerAgent({ id: 'fleet-a', agent_id: 'fa', assigned_at: new Date().toISOString(), status: 'running', subgraph_node_ids: [], campaign_id: 'fleet-camp' } as AgentTask);
    engine.registerAgent({ id: 'fleet-b', agent_id: 'fb', assigned_at: new Date().toISOString(), status: 'running', subgraph_node_ids: [], campaign_id: 'fleet-camp' } as AgentTask);
    const res = await fleet({ kind: 'pause', campaign_id: 'fleet-camp' });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.applied).toBe(2);
    expect(body.total).toBe(2);
    expect(engine.getPendingAgentDirective('fleet-a')?.kind).toBe('pause');
    expect(engine.getPendingAgentDirective('fleet-b')?.kind).toBe('pause');
    // target-1 (no campaign) untouched — the grammar tests below depend on it.
    expect(engine.getPendingAgentDirective('target-1')).toBeNull();
  });

  it('rejects a non-lifecycle fleet kind (400)', async () => {
    const res = await fleet({ kind: 'instruct' });
    expect(res.status).toBe(400);
  });
});

describe('/api/agents current_action (Phase 3C — "see everything")', () => {
  const ts = () => new Date().toISOString();

  it('attributes a unique-agent_id running task but NOT a shared agent_id (no cross-bleed)', async () => {
    engine.registerAgent({ id: 'ca-uniq', agent_id: 'ca-uniq-label', assigned_at: ts(), status: 'running', subgraph_node_ids: [] } as AgentTask);
    engine.logActionEvent({ description: 'running nmap on host', event_type: 'action_started', agent_id: 'ca-uniq-label', category: 'frontier' });
    // two running tasks share one agent_id → ambiguous, must not attribute either
    engine.registerAgent({ id: 'ca-dup-a', agent_id: 'ca-dup-label', assigned_at: ts(), status: 'running', subgraph_node_ids: [] } as AgentTask);
    engine.registerAgent({ id: 'ca-dup-b', agent_id: 'ca-dup-label', assigned_at: ts(), status: 'running', subgraph_node_ids: [] } as AgentTask);
    engine.logActionEvent({ description: 'shared work', event_type: 'action_started', agent_id: 'ca-dup-label', category: 'frontier' });

    const { agents } = await (await fetch(`${baseUrl}/api/agents`)).json();
    const byId = (id: string) => agents.find((a: { id: string }) => a.id === id);
    expect(byId('ca-uniq').current_action).toBe('running nmap on host');
    expect(byId('ca-dup-a').current_action).toBeUndefined();
    expect(byId('ca-dup-b').current_action).toBeUndefined();
  });

  it('does not surface operator/system bookkeeping as current_action', async () => {
    engine.registerAgent({ id: 'ca-bk', agent_id: 'ca-bk-label', assigned_at: ts(), status: 'running', subgraph_node_ids: [] } as AgentTask);
    engine.logActionEvent({ description: 'real agent work', event_type: 'action_started', agent_id: 'ca-bk-label', category: 'frontier' });
    engine.logActionEvent({ description: 'Operator directive: pause', event_type: 'operator_command', category: 'system', linked_agent_task_id: 'ca-bk' });

    const { agents } = await (await fetch(`${baseUrl}/api/agents`)).json();
    expect(agents.find((a: { id: string }) => a.id === 'ca-bk').current_action).toBe('real agent work');
  });
});

describe('/api/agent-queries — agent→operator escalation (Phase 3D)', () => {
  it('lists open questions, answers one, and removes it from the inbox', async () => {
    const q = engine.getAgentQueryStore().add({ task_id: 'target-1', agent_id: 'scanner-1', question: 'go loud?' });

    const list = await (await fetch(`${baseUrl}/api/agent-queries`)).json();
    expect(list.queries.some((x: { query_id: string }) => x.query_id === q.query_id)).toBe(true);

    const ans = await fetch(`${baseUrl}/api/agent-queries/${q.query_id}/answer`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ answer: 'stay quiet' }),
    });
    expect(ans.status).toBe(200);

    // delivered to the agent on its next heartbeat (peek), and gone from the open inbox
    const taken = engine.getAgentQueryStore().getAnswerForTask('target-1');
    expect(taken?.answer).toBe('stay quiet');
    const after = await (await fetch(`${baseUrl}/api/agent-queries`)).json();
    expect(after.queries.some((x: { query_id: string }) => x.query_id === q.query_id)).toBe(false);
  });

  it('rejects an empty answer (400) and an unknown query (404)', async () => {
    const q = engine.getAgentQueryStore().add({ task_id: 'target-1', question: 'x?' });
    const empty = await fetch(`${baseUrl}/api/agent-queries/${q.query_id}/answer`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ answer: '  ' }),
    });
    expect(empty.status).toBe(400);
    const unknown = await fetch(`${baseUrl}/api/agent-queries/nope/answer`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ answer: 'hi' }),
    });
    expect(unknown.status).toBe(404);
  });

  it('answer-batch fans one answer out to a cluster of identical questions', async () => {
    // Two running agents asked the same question; the operator answers once.
    engine.registerAgent({
      id: 'target-2', agent_id: 'scanner-2', assigned_at: new Date().toISOString(),
      status: 'running', subgraph_node_ids: [],
    } as AgentTask);
    const q1 = engine.getAgentQueryStore().add({ task_id: 'target-1', agent_id: 'scanner-1', question: 'go loud everywhere?' });
    const q2 = engine.getAgentQueryStore().add({ task_id: 'target-2', agent_id: 'scanner-2', question: 'go loud everywhere?' });

    const res = await fetch(`${baseUrl}/api/agent-queries/answer-batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query_ids: [q1.query_id, q2.query_id], answer: 'no, stay quiet' }),
    });
    expect(res.status).toBe(200);
    expect((await res.json()).answered).toBe(2);

    // Both agents receive the answer on their next heartbeat.
    expect(engine.getAgentQueryStore().getAnswerForTask('target-1')?.answer).toBe('no, stay quiet');
    expect(engine.getAgentQueryStore().getAnswerForTask('target-2')?.answer).toBe('no, stay quiet');
  });

  it('answer-batch rejects an empty answer (400) and empty query_ids (400)', async () => {
    const q = engine.getAgentQueryStore().add({ task_id: 'target-1', question: 'x?' });
    const emptyAnswer = await fetch(`${baseUrl}/api/agent-queries/answer-batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query_ids: [q.query_id], answer: '  ' }),
    });
    expect(emptyAnswer.status).toBe(400);
    const noIds = await fetch(`${baseUrl}/api/agent-queries/answer-batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query_ids: [], answer: 'hi' }),
    });
    expect(noIds.status).toBe(400);
  });
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

  it('a duplicate confirm of an already-executed plan is idempotent (not a 404 that re-prompts)', async () => {
    const preview = await (await post({ command: 'pause scanner-1' })).json();
    const first = await post({ confirm: true, plan_id: preview.plan_id });
    expect(first.status).toBe(200);
    expect((await first.json()).executed).toBe(true);

    // Second confirm of the SAME plan_id (double-click / retry). The plan was
    // consumed by the first, but instead of a 404 "re-issue the command" — which the
    // operator hit AFTER agents had already deployed — it returns the prior result.
    const second = await post({ confirm: true, plan_id: preview.plan_id });
    expect(second.status).toBe(200);
    const body = await second.json();
    expect(body.executed).toBe(true);
    expect(body.already_executed).toBe(true);
  });
});

describe('/api/commands — headless planner fallback', () => {
  it('a free-form command spawns a read-only planner task (daemon available)', async () => {
    headlessAvail = true;
    const r = await (await post({ command: 'go take care of the noisy box somehow' })).json();
    expect(r.needs_planner).toBe(true);
    expect(r.planner_available).toBe(true);
    expect(r.command_id).toBeTruthy();
    expect(r.planner_status).toBe('accepted');
    expect(r.planner_task_id).toBeTruthy();
    const task = engine.getTask(r.planner_task_id);
    expect(task?.role).toBe('planner');
    expect(task?.archetype).toBe('planner');
    expect(task?.skill).toBe('operator-planner');
    expect(task?.backend).toBe('headless_mcp');
    expect(task?.objective).toContain('go take care of the noisy box somehow');
    expect(task?.application_command_id).toBe(r.command_id);
    const dispatchEvent = engine.getFullHistory()
      .find(event => event.linked_agent_task_id === r.planner_task_id
        && event.event_type === 'agent_registered');
    expect(dispatchEvent?.description).toContain('as operator planner');
    expect(dispatchEvent?.description).not.toContain('undefined');
    const durable = await (
      await fetch(`${baseUrl}/api/commands/${encodeURIComponent(r.command_id)}`)
    ).json();
    expect(durable.command).toMatchObject({
      command_id: r.command_id,
      status: 'accepted',
      entity_refs: { planner_task_id: r.planner_task_id },
    });
    const active = await (
      await fetch(`${baseUrl}/api/commands/active`)
    ).json();
    expect(active.commands).toEqual([
      expect.objectContaining({
        command_id: r.command_id,
        status: 'accepted',
        entity_refs: expect.objectContaining({
          planner_task_id: r.planner_task_id,
          planner_request_key: expect.stringMatching(/^planner_[a-f0-9]{64}$/),
        }),
      }),
    ]);
  });

  it('re-issuing the same free-form command reuses the in-flight planner (no duplicate)', async () => {
    headlessAvail = true;
    const cmd = 'go rummage through the weird share  and report back';
    const first = await (await post({ command: cmd })).json();
    expect(first.planner_task_id).toBeTruthy();
    // Re-issue verbatim (and with cosmetic whitespace/case differences) while the first
    // planner is still running → same task id back, and only ONE planner exists.
    const second = await (await post({ command: cmd })).json();
    expect(second.planner_task_id).toBe(first.planner_task_id);
    const third = await (await post({ command: '  GO Rummage through the weird share and report back ' })).json();
    expect(third.planner_task_id).toBe(first.planner_task_id);
    const planners = engine.getAgentTasks().filter(t => t.role === 'planner' && t.objective?.includes('rummage through the weird share'));
    expect(planners).toHaveLength(1);
  });

  it('coalesces concurrent semantically-identical HTTP planner requests', async () => {
    headlessAvail = true;
    const before = engine.getAgentTasks().filter(task => task.role === 'planner').length;
    const responses = await Promise.all([
      post({ command: 'investigate the concurrent mystery host' }),
      post({ command: '  INVESTIGATE   the concurrent mystery host ' }),
      post({ command: 'Investigate the concurrent mystery host' }),
    ]);
    expect(responses.every(response => response.status === 200)).toBe(true);
    const bodies = await Promise.all(responses.map(response => response.json()));
    expect(new Set(bodies.map(body => body.command_id)).size).toBe(1);
    expect(new Set(bodies.map(body => body.planner_task_id)).size).toBe(1);
    expect(engine.getAgentTasks().filter(task => task.role === 'planner'))
      .toHaveLength(before + 1);
  });

  it('returns a conflict when one idempotency key is reused for different text', async () => {
    headlessAvail = true;
    const request = (command: string, commandId: string) => fetch(`${baseUrl}/api/commands`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': 'planner-http-conflict',
        'X-Overwatch-Command-Id': commandId,
      },
      body: JSON.stringify({ command }),
    });
    const first = await request('inspect idempotency alpha', 'planner-http-alpha');
    expect(first.status).toBe(200);
    const before = engine.getAgentTasks().filter(task => task.role === 'planner').length;
    const second = await request('inspect idempotency beta', 'planner-http-beta');
    expect(second.status).toBe(409);
    expect(await second.json()).toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' });
    expect(engine.getAgentTasks().filter(task => task.role === 'planner'))
      .toHaveLength(before);
  });

  it('correlates the planner proposal to the durable command without a timeout window', async () => {
    headlessAvail = true;
    const command = 'work out how to investigate the correlation target';
    const queued = await (await post({ command })).json();
    expect(queued).toMatchObject({
      needs_planner: true,
      planner_status: 'accepted',
      command_id: expect.any(String),
      planner_task_id: expect.any(String),
    });

    engine.addNode({
      id: 'planner-correlation-target',
      type: 'host',
      label: '10.0.0.77',
      ip: '10.0.0.77',
      discovered_at: new Date().toISOString(),
      discovered_by: 'test',
      confidence: 1,
    });
    const proposed = recordProposedPlan(engine, {
      task_id: queued.planner_task_id,
      command,
      summary: 'dispatch a recon agent',
      ops: [{
        op: 'dispatch',
        target_node_ids: ['planner-correlation-target'],
        archetype: 'recon_scanner',
      }],
    });
    expect(proposed.ok).toBe(true);

    const durable = await (
      await fetch(`${baseUrl}/api/commands/${encodeURIComponent(queued.command_id)}`)
    ).json();
    expect(durable.command).toMatchObject({
      command_id: queued.command_id,
      status: 'succeeded',
      plan_id: proposed.ok ? proposed.plan_id : undefined,
      entity_refs: {
        planner_task_id: queued.planner_task_id,
        plan_id: proposed.ok ? proposed.plan_id : undefined,
      },
      result: {
        phase: 'plan_ready',
        command_id: queued.command_id,
        planner_task_id: queued.planner_task_id,
        plan: {
          plan_id: proposed.ok ? proposed.plan_id : undefined,
          owner_task_id: queued.planner_task_id,
        },
      },
    });
  });

  it('surfaces an already-open plan for the command instead of spawning a duplicate planner', async () => {
    headlessAvail = true;
    // A prior planner proposed a plan for this command and has since terminated; the
    // plan is still open in the store. Re-issuing the command must NOT spawn a new
    // planner — it returns the open plan's source task so the UI shows that plan.
    engine.getProposedPlanStore().add({
      command: 'deal with the leftover box',
      ops: [{ op: 'directive', task_id: 'target-1', agent_label: 'scanner-1', kind: 'pause' }],
      summary: 's', source_task_id: 'planner-prior', source_agent_id: 'planner-prior-a',
    });
    const before = engine.getAgentTasks().filter(t => t.role === 'planner').length;
    const r = await (await post({ command: 'Deal with the leftover box' })).json(); // case-insensitive match
    expect(r.planner_task_id).toBe('planner-prior');
    expect(r.planner_available).toBe(true);
    expect(r.planner_plan).toMatchObject({
      command: 'deal with the leftover box',
      owner_task_id: 'planner-prior',
      owner_agent_label: 'planner-prior-a',
    });
    expect(engine.getAgentTasks().filter(t => t.role === 'planner').length).toBe(before); // no new planner
  });

  it('hydrates a legacy succeeded command from its linked open plan', async () => {
    const plan = engine.getProposedPlanStore().add({
      command: 'hydrate the legacy plan',
      ops: [{
        op: 'directive',
        task_id: 'target-1',
        agent_label: 'scanner-1',
        kind: 'pause',
      }],
      summary: 'pause the scanner',
      source_task_id: 'legacy-planner-task',
      source_agent_id: 'legacy-planner',
    });
    engine.recordApplicationCommand({
      command_id: 'legacy-planner-command',
      idempotency_key: 'legacy-planner-idempotency',
      input_sha256: 'a'.repeat(64),
      command_kind: 'operator.plan',
      validated_input: { command: plan.command },
      transport: 'dashboard',
      actor_task_id: null,
      status: 'succeeded',
      created_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      plan_id: plan.plan_id,
      entity_refs: {
        planner_task_id: 'legacy-planner-task',
        plan_id: plan.plan_id,
      },
      result: {
        phase: 'plan_ready',
        command_id: 'legacy-planner-command',
        plan_id: plan.plan_id,
      },
    });

    const response = await fetch(
      `${baseUrl}/api/commands/legacy-planner-command`,
    );
    expect(response.status).toBe(200);
    expect((await response.json()).command).toMatchObject({
      status: 'succeeded',
      result: {
        planner_task_id: 'legacy-planner-task',
        plan_id: plan.plan_id,
        plan: { plan_id: plan.plan_id },
      },
    });
  });

  it('never projects an expired embedded plan as confirmable', async () => {
    const plan = engine.getProposedPlanStore().add({
      command: 'expired planner command',
      ops: [{ op: 'scope', add_cidrs: ['10.88.0.0/24'] }],
      summary: 'expired plan',
      now: Date.now() - 11 * 60_000,
    });
    engine.recordApplicationCommand({
      command_id: 'expired-planner-command',
      idempotency_key: 'expired-planner-idempotency',
      input_sha256: 'b'.repeat(64),
      command_kind: 'operator.plan',
      validated_input: { command: plan.command },
      transport: 'dashboard',
      actor_task_id: null,
      status: 'succeeded',
      created_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      plan_id: plan.plan_id,
      result: {
        phase: 'plan_ready',
        plan_id: plan.plan_id,
        plan,
      },
    });

    const response = await fetch(`${baseUrl}/api/commands/expired-planner-command`);
    expect(response.status).toBe(200);
    const projected = (await response.json()).command;
    expect(projected.result).toMatchObject({
      phase: 'plan_expired',
      plan_id: plan.plan_id,
    });
    expect(projected.result.plan).toBeUndefined();
  });

  it('reports planner_available:false in stdio mode (no daemon)', async () => {
    headlessAvail = false;
    const r = await (await post({ command: 'please do the thing with the stuff' })).json();
    expect(r.needs_planner).toBe(true);
    expect(r.planner_available).toBe(false);
    expect(r.planner_task_id).toBeUndefined();
    expect(r.command_id).toBeTruthy();
    expect(r.planner_status).toBe('failed');
    const durable = await (
      await fetch(`${baseUrl}/api/commands/${encodeURIComponent(r.command_id)}`)
    ).json();
    expect(durable.command).toMatchObject({
      command_id: r.command_id,
      status: 'failed',
      error: { code: 'PLANNER_UNAVAILABLE' },
    });
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
    expect(engine.getProposedPlanStore().get(plan.plan_id)).toMatchObject({
      status: 'confirmed',
      confirmed_at: expect.any(Number),
      acknowledged_at: expect.any(Number),
      execution_outcome: {
        status: 'succeeded',
        completed_at: expect.any(Number),
        results: [expect.objectContaining({ ok: true })],
      },
    });
  });

  it('reports planner_available:false when NO task-execution service is attached (dashboard-only)', async () => {
    const eng = new GraphEngine(makeConfig(), join(tempDir, 'state-noexec.json'));
    const dash = new DashboardServer(eng, 0, '127.0.0.1', undefined, undefined);
    // deliberately do NOT attachTaskExecution
    const started = await dash.start();
    if (!started.started) throw new Error('dashboard failed to start');
    try {
      const r = await (await fetch(`${dash.address}/api/commands`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'go do something clever and free-form' }),
      })).json();
      expect(r.needs_planner).toBe(true);
      expect(r.planner_available).toBe(false);
      expect(r.planner_task_id).toBeUndefined();
      expect(eng.getAgentTasks().some(t => t.role === 'planner')).toBe(false);
    } finally {
      await dash.stop().catch(() => {});
      eng.dispose();
    }
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

  it('confirming a plan DENIED from the other surface returns 409 "do not re-issue", not a re-issue 404', async () => {
    // The "Needs you" queue dismissed this plan; the OperatorCommandBar then tries to
    // confirm the same (now-stale) plan_id. A blanket 404 "re-issue the command" here
    // is what spawned a duplicate planner + duplicate dispatch — the reported bug.
    const plan = engine.getProposedPlanStore().add({
      command: 'go poke around', ops: [{ op: 'directive', task_id: 'target-1', agent_label: 'scanner-1', kind: 'pause' }], summary: 's',
    });
    engine.getProposedPlanStore().resolve(plan.plan_id, 'denied'); // dismissed elsewhere
    const res = await post({ confirm: true, plan_id: plan.plan_id });
    expect(res.status).toBe(409);
    const body = await res.json();
    expect(body.already_handled).toBe(true);
    expect(body.resolution).toBe('denied');
    expect(body.error).toContain('do not re-issue');
  });

  it('confirming a plan already confirmed elsewhere returns 409 "check the fleet", not a re-issue 404', async () => {
    const plan = engine.getProposedPlanStore().add({
      command: 'go poke around', ops: [{ op: 'directive', task_id: 'target-1', agent_label: 'scanner-1', kind: 'pause' }], summary: 's',
    });
    engine.getProposedPlanStore().resolve(plan.plan_id, 'confirmed'); // consumed by another surface (not via executedPlanIds)
    const res = await post({ confirm: true, plan_id: plan.plan_id });
    expect(res.status).toBe(409);
    const body = await res.json();
    expect(body.resolution).toBe('confirmed');
    expect(body.error).toContain('check the fleet');
  });

  it('a genuinely unknown/expired plan_id still gets the re-issue 404', async () => {
    const res = await post({ confirm: true, plan_id: 'never-proposed' });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.already_handled).toBeFalsy();
    expect(body.error).toContain('re-issue');
  });
});
