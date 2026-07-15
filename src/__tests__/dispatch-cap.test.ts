import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../services/graph-engine.js';
import type { AgentTask, EngagementConfig, OperatorPolicy } from '../types.js';

// T3 — per-subnet/target dispatch cap. registerAgent refuses (without registering
// or logging) a target-facing agent that would exceed the operator-policy limit.

let testDir: string;
let testStateFile: string;

function makeConfig(operator_policy?: OperatorPolicy): EngagementConfig {
  return {
    id: 'test-dispatch-cap',
    name: 'Dispatch Cap Test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1.0 },
    operator_policy,
  } as EngagementConfig;
}

function host(engine: GraphEngine, id: string, ip: string) {
  engine.addNode({ id, type: 'host', label: ip, ip, discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1 } as never);
}

function task(overrides: Partial<AgentTask>): AgentTask {
  return {
    id: overrides.id ?? `t-${Math.random().toString(36).slice(2, 8)}`,
    agent_id: overrides.agent_id ?? 'a',
    assigned_at: new Date().toISOString(),
    status: 'running',
    subgraph_node_ids: [],
    archetype: 'recon_scanner', // target-facing by default
    ...overrides,
  };
}

describe('GraphEngine.registerAgent — operator-policy dispatch cap', () => {
  let engine: GraphEngine;
  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-dispatch-cap-'));
    testStateFile = join(testDir, 'state.json');
  });
  afterEach(() => {
    engine?.dispose();
    rmSync(testDir, { recursive: true, force: true });
  });

  it('refuses an N+1 target-facing agent on a /24 that is at the per-subnet cap', () => {
    engine = new GraphEngine(makeConfig({ version: 1, dispatch_limits: { max_per_subnet: 1 } }), testStateFile);
    host(engine, 'h1', '10.10.10.1');
    host(engine, 'h2', '10.10.10.2');
    expect(engine.registerAgent(task({ id: 't1', subgraph_node_ids: ['h1'] })).ok).toBe(true);
    const second = engine.registerAgent(task({ id: 't2', subgraph_node_ids: ['h2'] }));
    expect(second.ok).toBe(false);
    expect(second.cap_exceeded).toMatchObject({ scope: 'subnet', key: '10.10.10.0/24', limit: 1, current: 1 });
    // The refused task was NOT registered.
    expect(engine.getTask('t2')).toBeNull();
  });

  it('exempts read-only archetypes from the cap', () => {
    engine = new GraphEngine(makeConfig({ version: 1, dispatch_limits: { max_per_subnet: 1 } }), testStateFile);
    host(engine, 'h1', '10.10.10.1');
    host(engine, 'h2', '10.10.10.2');
    expect(engine.registerAgent(task({ id: 't1', subgraph_node_ids: ['h1'] })).ok).toBe(true);
    // pathfinder is read-only → not counted, not capped.
    expect(engine.registerAgent(task({ id: 't2', archetype: 'pathfinder', subgraph_node_ids: ['h2'] })).ok).toBe(true);
  });

  it('frees a slot when an agent completes', () => {
    engine = new GraphEngine(makeConfig({ version: 1, dispatch_limits: { max_per_subnet: 1 } }), testStateFile);
    host(engine, 'h1', '10.10.10.1');
    host(engine, 'h2', '10.10.10.2');
    expect(engine.registerAgent(task({ id: 't1', subgraph_node_ids: ['h1'] })).ok).toBe(true);
    engine.updateAgentStatus('t1', 'completed', 'done');
    // t1 no longer running → the subnet slot is free.
    expect(engine.registerAgent(task({ id: 't2', subgraph_node_ids: ['h2'] })).ok).toBe(true);
  });

  it('a no-IP target bypasses the subnet cap', () => {
    engine = new GraphEngine(makeConfig({ version: 1, dispatch_limits: { max_per_subnet: 1 } }), testStateFile);
    host(engine, 'h1', '10.10.10.1');
    expect(engine.registerAgent(task({ id: 't1', subgraph_node_ids: ['h1'] })).ok).toBe(true);
    // a credential/no-IP-resolvable seed → exempt.
    engine.addNode({ id: 'cred1', type: 'credential', label: 'c', discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1 } as never);
    expect(engine.registerAgent(task({ id: 't2', subgraph_node_ids: ['cred1'] })).ok).toBe(true);
  });

  it('max_per_target is independent of max_per_subnet', () => {
    engine = new GraphEngine(makeConfig({ version: 1, dispatch_limits: { max_per_target: 1 } }), testStateFile);
    host(engine, 'h1', '10.10.10.1');
    host(engine, 'h2', '10.10.10.2');
    expect(engine.registerAgent(task({ id: 't1', subgraph_node_ids: ['h1'] })).ok).toBe(true);
    // different host in the same /24 → allowed (no subnet cap), only per-target binds.
    expect(engine.registerAgent(task({ id: 't2', subgraph_node_ids: ['h2'] })).ok).toBe(true);
    // same host as t1 → per-target cap hits.
    const third = engine.registerAgent(task({ id: 't3', subgraph_node_ids: ['h1'] }));
    expect(third.ok).toBe(false);
    expect(third.cap_exceeded).toMatchObject({ scope: 'target', key: '10.10.10.1', limit: 1 });
  });

  it('no policy → no cap', () => {
    engine = new GraphEngine(makeConfig(), testStateFile);
    host(engine, 'h1', '10.10.10.1');
    host(engine, 'h2', '10.10.10.2');
    expect(engine.registerAgent(task({ id: 't1', subgraph_node_ids: ['h1'] })).ok).toBe(true);
    expect(engine.registerAgent(task({ id: 't2', subgraph_node_ids: ['h2'] })).ok).toBe(true);
  });
});
