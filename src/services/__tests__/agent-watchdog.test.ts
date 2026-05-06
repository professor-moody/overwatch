import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { AgentWatchdog } from '../agent-watchdog.js';
import type { EngagementConfig, AgentTask } from '../../types.js';

const TEST_STATE_FILE = './state-test-agent-watchdog.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-watchdog',
    name: 'watchdog test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
}

function makeRunningTask(overrides: Partial<AgentTask> = {}): AgentTask {
  return {
    id: overrides.id ?? `task-${Math.random().toString(36).slice(2, 10)}`,
    agent_id: overrides.agent_id ?? 'sub-agent-1',
    assigned_at: overrides.assigned_at ?? new Date().toISOString(),
    status: 'running',
    subgraph_node_ids: overrides.subgraph_node_ids ?? [],
    skill: overrides.skill,
    frontier_item_id: overrides.frontier_item_id,
    heartbeat_at: overrides.heartbeat_at,
    heartbeat_ttl_seconds: overrides.heartbeat_ttl_seconds,
  };
}

describe('AgentWatchdog (P0.3)', () => {
  let engine: GraphEngine;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
  });

  afterEach(() => {
    cleanup();
  });

  it('reaps tasks whose heartbeat is older than TTL', () => {
    // 5 minutes ago heartbeat, 60s TTL → stale.
    const stale = makeRunningTask({
      id: 'stale-1',
      heartbeat_at: new Date(Date.now() - 5 * 60_000).toISOString(),
      heartbeat_ttl_seconds: 60,
    });
    engine.registerAgent(stale);
    const watchdog = new AgentWatchdog(engine);
    const reaped = watchdog.tick();
    expect(reaped).toBe(1);
    const task = engine.getTask('stale-1');
    expect(task?.status).toBe('interrupted');
    expect(task?.completed_at).toBeDefined();
  });

  it('does NOT reap tasks that never heartbeated (backward-compat)', () => {
    // Task without heartbeat_at — exempt from watchdog.
    const noHeartbeat = makeRunningTask({ id: 'no-beat-1' });
    engine.registerAgent(noHeartbeat);
    const watchdog = new AgentWatchdog(engine);
    const reaped = watchdog.tick();
    expect(reaped).toBe(0);
    const task = engine.getTask('no-beat-1');
    expect(task?.status).toBe('running');
  });

  it('does NOT reap tasks whose heartbeat is fresh', () => {
    const fresh = makeRunningTask({
      id: 'fresh-1',
      heartbeat_at: new Date(Date.now() - 5_000).toISOString(),
      heartbeat_ttl_seconds: 120,
    });
    engine.registerAgent(fresh);
    const watchdog = new AgentWatchdog(engine);
    const reaped = watchdog.tick();
    expect(reaped).toBe(0);
    expect(engine.getTask('fresh-1')?.status).toBe('running');
  });

  it('emits an instrumentation_warning when reaping', () => {
    const stale = makeRunningTask({
      id: 'stale-2',
      heartbeat_at: new Date(Date.now() - 10 * 60_000).toISOString(),
      heartbeat_ttl_seconds: 30,
    });
    engine.registerAgent(stale);
    const before = engine.getFullHistory().length;
    new AgentWatchdog(engine).tick();
    const after = engine.getFullHistory().slice(before);
    const warning = after.find(e => e.event_type === 'instrumentation_warning'
      && (e.details as any)?.reason === 'heartbeat_timeout');
    expect(warning).toBeDefined();
    expect(warning!.linked_agent_task_id).toBe('stale-2');
  });

  it('engine.agentHeartbeat updates heartbeat_at and emits a heartbeat event', () => {
    const task = makeRunningTask({ id: 'hb-1' });
    engine.registerAgent(task);
    const before = engine.getFullHistory().length;
    const ok = engine.agentHeartbeat('hb-1');
    expect(ok).toBe(true);
    expect(engine.getTask('hb-1')?.heartbeat_at).toBeDefined();
    const after = engine.getFullHistory().slice(before);
    expect(after.some(e => e.event_type === 'heartbeat')).toBe(true);
  });

  it('agentHeartbeat refuses tasks that are already in a terminal state', () => {
    const task = makeRunningTask({ id: 'done-1' });
    engine.registerAgent(task);
    engine.updateAgentStatus('done-1', 'completed');
    const ok = engine.agentHeartbeat('done-1');
    expect(ok).toBe(false);
  });

  it('heartbeat events are NOT chained when hash chain is on', () => {
    cleanup();
    const cfg = { ...makeConfig(), hash_chain_enabled: true };
    const eng = new GraphEngine(cfg, TEST_STATE_FILE);
    const task = makeRunningTask({ id: 'chain-1' });
    eng.registerAgent(task);
    eng.agentHeartbeat('chain-1');
    const heartbeats = eng.getFullHistory().filter(e => e.event_type === 'heartbeat');
    expect(heartbeats.length).toBeGreaterThan(0);
    for (const hb of heartbeats) {
      expect(hb.event_hash).toBeUndefined();
      expect(hb.chain_excluded).toBe(true);
    }
  });
});
