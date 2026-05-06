import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { FrontierLeases } from '../frontier-leases.js';
import type { EngagementConfig, AgentTask } from '../../types.js';

const TEST_STATE_FILE = './state-test-frontier-leases.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'lease-test',
    name: 'lease test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function makeTask(id: string, frontier_item_id: string, agent_id = 'a'): AgentTask {
  return {
    id,
    agent_id,
    assigned_at: new Date().toISOString(),
    status: 'running',
    frontier_item_id,
    subgraph_node_ids: [],
  };
}

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
}

describe('FrontierLeases (P1.4)', () => {
  describe('unit', () => {
    it('first acquire wins; second acquire refused', () => {
      const leases = new FrontierLeases();
      const r1 = leases.acquire({
        frontier_item_id: 'fi-1', agent_id: 'a', task_id: 't1',
        now: '2026-01-01T00:00:00.000Z',
      });
      expect(r1.ok).toBe(true);

      const r2 = leases.acquire({
        frontier_item_id: 'fi-1', agent_id: 'b', task_id: 't2',
        now: '2026-01-01T00:00:00.000Z',
      });
      expect(r2.ok).toBe(false);
      expect(r2.existing?.task_id).toBe('t1');
    });

    it('same task re-acquiring renews the TTL', () => {
      const leases = new FrontierLeases();
      const r1 = leases.acquire({
        frontier_item_id: 'fi-1', agent_id: 'a', task_id: 't1',
        now: '2026-01-01T00:00:00.000Z', ttl_seconds: 60,
      });
      const r2 = leases.acquire({
        frontier_item_id: 'fi-1', agent_id: 'a', task_id: 't1',
        now: '2026-01-01T00:00:30.000Z', ttl_seconds: 60,
      });
      expect(r1.ok).toBe(true);
      expect(r2.ok).toBe(true);
      expect(Date.parse(r2.lease!.expires_at)).toBeGreaterThan(Date.parse(r1.lease!.expires_at));
    });

    it('expired lease lets a different task acquire', () => {
      const leases = new FrontierLeases();
      leases.acquire({
        frontier_item_id: 'fi-1', agent_id: 'a', task_id: 't1',
        now: '2026-01-01T00:00:00.000Z', ttl_seconds: 60,
      });
      const r2 = leases.acquire({
        frontier_item_id: 'fi-1', agent_id: 'b', task_id: 't2',
        now: '2026-01-01T00:02:00.000Z', // 2 minutes later, TTL was 60s
      });
      expect(r2.ok).toBe(true);
    });

    it('isHeldByOther returns true only when a DIFFERENT task holds an active lease', () => {
      const leases = new FrontierLeases();
      leases.acquire({
        frontier_item_id: 'fi-1', agent_id: 'a', task_id: 't1',
        now: '2026-01-01T00:00:00.000Z',
      });
      expect(leases.isHeldByOther('fi-1', 't1', '2026-01-01T00:00:01.000Z')).toBe(false);
      expect(leases.isHeldByOther('fi-1', 't2', '2026-01-01T00:00:01.000Z')).toBe(true);
      // After expiry — no longer held.
      expect(leases.isHeldByOther('fi-1', 't2', '2026-01-01T01:00:00.000Z')).toBe(false);
    });

    it('renew extends TTL by the same seconds the lease was originally taken with', () => {
      const leases = new FrontierLeases();
      leases.acquire({
        frontier_item_id: 'fi-1', agent_id: 'a', task_id: 't1',
        now: '2026-01-01T00:00:00.000Z', ttl_seconds: 30,
      });
      expect(leases.renew('t1', '2026-01-01T00:00:20.000Z')).toBe(true);
      const lease = leases.get('fi-1', '2026-01-01T00:00:25.000Z')!;
      expect(Date.parse(lease.expires_at)).toBe(Date.parse('2026-01-01T00:00:50.000Z'));
    });

    it('releaseByTask drops every lease the task held', () => {
      const leases = new FrontierLeases();
      leases.acquire({ frontier_item_id: 'fi-1', agent_id: 'a', task_id: 't1', now: '2026-01-01T00:00:00.000Z' });
      leases.acquire({ frontier_item_id: 'fi-2', agent_id: 'a', task_id: 't1', now: '2026-01-01T00:00:00.000Z' });
      const released = leases.releaseByTask('t1');
      expect(released).toBe(2);
      expect(leases.list('2026-01-01T00:00:01.000Z')).toEqual([]);
    });

    it('reapExpired returns dropped item ids', () => {
      const leases = new FrontierLeases();
      leases.acquire({ frontier_item_id: 'fi-1', agent_id: 'a', task_id: 't1', now: '2026-01-01T00:00:00.000Z', ttl_seconds: 60 });
      leases.acquire({ frontier_item_id: 'fi-2', agent_id: 'a', task_id: 't2', now: '2026-01-01T00:00:00.000Z', ttl_seconds: 60 });
      const dropped = leases.reapExpired('2026-01-01T01:00:00.000Z');
      expect(dropped.sort()).toEqual(['fi-1', 'fi-2']);
      expect(leases.list('2026-01-01T01:00:01.000Z')).toEqual([]);
    });
  });

  describe('integrated with engine', () => {
    let engine: GraphEngine;

    beforeEach(() => {
      cleanup();
      engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    });

    afterEach(() => {
      cleanup();
    });

    it('registerAgent rejects when another task holds the lease', () => {
      const r1 = engine.registerAgent(makeTask('t1', 'fi-1', 'agent-A'));
      const r2 = engine.registerAgent(makeTask('t2', 'fi-1', 'agent-B'));
      expect(r1.ok).toBe(true);
      expect(r2.ok).toBe(false);
      expect(r2.lease_conflict?.existing_task_id).toBe('t1');
      // Only the winner is registered.
      expect(engine.getAgentTasks().filter(t => t.frontier_item_id === 'fi-1')).toHaveLength(1);
    });

    it('lease releases on completed status; lets another agent claim afterward', () => {
      engine.registerAgent(makeTask('t1', 'fi-1', 'agent-A'));
      engine.updateAgentStatus('t1', 'completed', 'done');
      // A different agent can now claim the same item.
      const r = engine.registerAgent(makeTask('t2', 'fi-1', 'agent-B'));
      expect(r.ok).toBe(true);
    });

    it('heartbeat extends the lease', () => {
      engine.registerAgent(makeTask('t1', 'fi-1'));
      const before = engine.getActiveFrontierLeases().find(l => l.frontier_item_id === 'fi-1')!;
      // Advance ~5s and heartbeat
      engine.agentHeartbeat('t1', new Date(Date.parse(before.leased_at) + 5_000).toISOString());
      const after = engine.getActiveFrontierLeases().find(l => l.frontier_item_id === 'fi-1')!;
      expect(Date.parse(after.expires_at)).toBeGreaterThan(Date.parse(before.expires_at));
    });

    it('isFrontierItemHeldByOther distinguishes self from others', () => {
      engine.registerAgent(makeTask('t1', 'fi-1'));
      expect(engine.isFrontierItemHeldByOther('fi-1', 't1')).toBe(false);
      expect(engine.isFrontierItemHeldByOther('fi-1', 't-other')).toBe(true);
    });
  });
});
