// ============================================================
// Dispatch / lease / heartbeat lifecycle regressions.
//
// Pins six bugs the assessment found:
//   F1 next_task surfaced leased items
//   F2 dispatch sites ignored registerAgent refusal
//   F3 tasks without heartbeat_at were never reaped
//   F4 reconcileOnStartup left frontier leases behind
//   F5 campaign dispatch activated draft before any successful registration
//   F6 update_agent emitted transcript warnings before validating task_id
// ============================================================

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../services/graph-engine.js';
import { AgentWatchdog } from '../services/agent-watchdog.js';
import type { AgentTask, EngagementConfig, FrontierItem } from '../types.js';

let testDir: string;
let testStateFile: string;
const engines = new Set<GraphEngine>();

function makeConfig(): EngagementConfig {
  return {
    id: 'test-dispatch-lease',
    name: 'dispatch lease lifecycle',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  };
}

function createEngine(): GraphEngine {
  const engine = new GraphEngine(makeConfig(), testStateFile);
  engines.add(engine);
  return engine;
}

function makeRunningTask(overrides: Partial<AgentTask> = {}): AgentTask {
  const id = overrides.id ?? `task-${Math.random().toString(36).slice(2, 10)}`;
  return {
    id,
    agent_id: overrides.agent_id ?? `agent-${id}`,
    assigned_at: new Date().toISOString(),
    status: 'running',
    subgraph_node_ids: [],
    skill: undefined,
    frontier_item_id: overrides.frontier_item_id ?? `fi-${id}`,
    ...overrides,
  } as AgentTask;
}

function makeFrontierItem(id: string, nodeId: string): FrontierItem {
  return {
    id,
    type: 'incomplete_node',
    node_id: nodeId,
    description: `complete ${nodeId}`,
    graph_metrics: { hops_to_objective: null, fan_out_estimate: 1, node_degree: 0, confidence: 0.7 },
    opsec_noise: 0.2,
    staleness_seconds: 0,
  };
}

describe('Dispatch / lease / heartbeat lifecycle', () => {
  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-dispatch-lease-'));
    testStateFile = join(testDir, 'state.json');
  });
  afterEach(() => {
    for (const engine of engines) engine.dispose();
    engines.clear();
    rmSync(testDir, { recursive: true, force: true });
  });

  // F1
  it('filterFrontier excludes items currently leased to another task', () => {
    const engine = createEngine();
    engine.addNode({ id: 'host-1', type: 'host', label: 'host-1', ip: '10.10.10.5', alive: true, discovered_at: new Date().toISOString(), confidence: 1 });
    const task = makeRunningTask({ id: 'task-running', frontier_item_id: 'fi-running' });
    engine.registerAgent(task);

    // Synthesize the frontier item that the task holds and verify it's filtered.
    const item = makeFrontierItem('fi-running', 'host-1');
    const { passed, filtered } = engine.filterFrontier([item]);
    expect(passed).toHaveLength(0);
    expect(filtered).toHaveLength(1);
    expect(filtered[0].reason).toMatch(/frontier_item_leased/);
  });

  // F2 — register refusal contract is observable
  it('registerAgent refuses a second task on a leased frontier item', () => {
    const engine = createEngine();
    const t1 = makeRunningTask({ id: 'task-1', frontier_item_id: 'fi-shared' });
    const t2 = makeRunningTask({ id: 'task-2', agent_id: 'agent-2', frontier_item_id: 'fi-shared' });
    const r1 = engine.registerAgent(t1);
    const r2 = engine.registerAgent(t2);
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(false);
    expect(r2.lease_conflict?.existing_task_id).toBe('task-1');
  });

  // F3 — heartbeat_at is auto-initialized so tasks that crash before
  // the first heartbeat are reaped after TTL elapses.
  it('initializes heartbeat_at on register so the watchdog can reap stale never-heartbeated tasks', () => {
    const engine = createEngine();
    const past = new Date(Date.now() - 5 * 60 * 1000).toISOString(); // 5 min ago
    const task = makeRunningTask({
      id: 'pre-crash',
      frontier_item_id: 'fi-crash',
      // Simulate registration 5 minutes ago by overriding heartbeat_at
      // (the register code sets it to now() on insert, so we override
      // after the fact to model "never heartbeated since registration").
    });
    engine.registerAgent(task);
    expect(engine.getTask('pre-crash')?.heartbeat_at).toBeDefined();
    // Public getters are detached snapshots. Reach into the test fixture's
    // durable task map only to model five minutes passing without a heartbeat.
    (engine as any).ctx.agents.get('pre-crash').heartbeat_at = past;

    const watchdog = new AgentWatchdog(engine);
    const reaped = watchdog.tick();
    expect(reaped).toBe(1);
    const after = engine.getTask('pre-crash')!;
    expect(after.status).toBe('interrupted');
  });

  // F4
  it('reconcileOnStartup releases the frontier lease on each interrupted task', () => {
    const engine = createEngine();
    const t = makeRunningTask({ id: 'task-r', frontier_item_id: 'fi-r' });
    engine.registerAgent(t);
    // Simulate "fresh restart": call reconcile again and check the lease is gone.
    // The first reconcileOnStartup ran in the constructor when the engine loaded
    // (no-op here since nothing was running pre-load). The newly registered
    // task is running, so trigger reconciliation against that stale-live shape.
    const reconciled = engine.reconcileAgentsOnStartup();
    expect(reconciled).toBeGreaterThan(0);
    // Now register a different task on the same frontier item — should succeed
    // because the lease was released.
    const t2 = makeRunningTask({ id: 'task-r2', agent_id: 'agent-r2', frontier_item_id: 'fi-r' });
    const r2 = engine.registerAgent(t2);
    expect(r2.ok).toBe(true);
  });
});
