import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { ProcessTracker } from '../process-tracker.js';
import { TaskExecutionService, resolveTaskBackend } from '../task-execution-service.js';
import type { EngagementConfig, AgentTask } from '../../types.js';

const TEST_STATE_FILE = './state-test-task-execution.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-task-exec',
    name: 'task exec test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch { /* ignore */ }
}

function runningTask(overrides: Partial<AgentTask> = {}): AgentTask {
  return {
    id: overrides.id ?? `task-${Math.random().toString(36).slice(2, 10)}`,
    agent_id: overrides.agent_id ?? 'agent-x',
    assigned_at: new Date().toISOString(),
    status: 'running',
    subgraph_node_ids: [],
    frontier_item_id: overrides.frontier_item_id,
    backend: overrides.backend,
    heartbeat_at: overrides.heartbeat_at,
    heartbeat_ttl_seconds: overrides.heartbeat_ttl_seconds,
  };
}

const settle = () => new Promise(r => setTimeout(r, 10));

describe('resolveTaskBackend', () => {
  it('defaults to scripted when unset', () => {
    expect(resolveTaskBackend(runningTask())).toBe('scripted');
  });
  it('honors an explicit backend', () => {
    expect(resolveTaskBackend(runningTask({ backend: 'headless_mcp' }))).toBe('headless_mcp');
    expect(resolveTaskBackend(runningTask({ backend: 'manual' }))).toBe('manual');
  });
});

describe('TaskExecutionService', () => {
  let engine: GraphEngine;
  let svc: TaskExecutionService;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    svc = new TaskExecutionService(engine, new ProcessTracker());
  });

  afterEach(() => {
    svc.stop();
    cleanup();
  });

  it('runs scripted-backend tasks WITHOUT a dashboard (decoupled execution)', async () => {
    svc.start();
    // Default backend (scripted) + a frontier item that does not exist → the
    // scripted runner picks it up and marks it completed ("not found; skipped").
    engine.registerAgent(runningTask({ id: 'scripted-1', frontier_item_id: 'frontier-nonexistent' }));
    await settle();
    expect(engine.getTask('scripted-1')?.status).toBe('completed');
  });

  it('does NOT execute headless_mcp tasks (no runtime until 1B) and logs a deferral', async () => {
    svc.start();
    engine.registerAgent(runningTask({
      id: 'headless-1',
      backend: 'headless_mcp',
      frontier_item_id: 'frontier-nonexistent',
    }));
    await settle();

    // Left running for a future headless/manual backend — not auto-completed.
    expect(engine.getTask('headless-1')?.status).toBe('running');
    const deferral = engine.getFullHistory().find(e =>
      e.event_type === 'instrumentation_warning'
      && (e.details as any)?.reason === 'no_automated_backend'
      && e.linked_agent_task_id === 'headless-1');
    expect(deferral).toBeDefined();
    expect((deferral!.details as any).backend).toBe('headless_mcp');
  });

  it('fails loudly (not falsely "completed") when scripted is forced on an unhandleable frontier item', async () => {
    svc.start();
    // The seeded CIDR (no hosts) yields a network_discovery frontier item — a
    // type the scripted runner has no handler for. Forcing backend:'scripted'
    // must end 'failed' with a clear reason, never a silent 'completed'.
    const item = engine.computeFrontier().find(f => f.type !== 'credential_test');
    expect(item, 'expected a non-credential frontier item from the seeded CIDR').toBeDefined();
    engine.registerAgent(runningTask({ id: 'forced-scripted-1', backend: 'scripted', frontier_item_id: item!.id }));
    await settle();
    const t = engine.getTask('forced-scripted-1');
    expect(t?.status).toBe('failed');
    expect(t?.result_summary ?? '').toContain('no_scripted_handler');
  });

  it('leaves manual tasks running for the operator', async () => {
    svc.start();
    engine.registerAgent(runningTask({ id: 'manual-1', backend: 'manual', frontier_item_id: 'frontier-nonexistent' }));
    await settle();
    expect(engine.getTask('manual-1')?.status).toBe('running');
  });

  it('starts the watchdog so stale agents are reaped in production', () => {
    svc.start();
    // Stale heartbeat, no frontier item (so the scripted runner ignores it),
    // older than its TTL → the service-owned watchdog reaps it on tick.
    engine.registerAgent(runningTask({
      id: 'stale-1',
      heartbeat_at: new Date(Date.now() - 5 * 60_000).toISOString(),
      heartbeat_ttl_seconds: 60,
    }));
    const reaped = svc.tickWatchdog();
    expect(reaped).toBe(1);
    expect(engine.getTask('stale-1')?.status).toBe('interrupted');
  });
});
