import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { existsSync, readFileSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { FrontierLeases } from '../frontier-leases.js';
import type { EngagementConfig, AgentTask } from '../../types.js';
import { cleanupTestPersistence } from '../../__tests__/helpers/cleanup-test-persistence.js';
import { createTestSandbox } from '../../test-support/test-sandbox.js';
import { MutationJournal } from '../mutation-journal.js';

const sandbox = createTestSandbox('frontier-leases');
const TEST_STATE_FILE = sandbox.path('state-test-frontier-leases.json');

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
  cleanupTestPersistence(TEST_STATE_FILE);
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
}

function journalOperations(raw: string): Array<{ type: string; payload: Record<string, unknown> }> {
  const frames = raw.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
  const byTransaction = new Map<string, Array<{ chunk_index: number; data: string }>>();
  for (const frame of frames) {
    if (frame.record_type !== 'tx_chunk') continue;
    const chunks = byTransaction.get(frame.tx_id) ?? [];
    chunks.push(frame);
    byTransaction.set(frame.tx_id, chunks);
  }
  return [...byTransaction.values()].flatMap(chunks => {
    const bytes = Buffer.concat(chunks
      .sort((left, right) => left.chunk_index - right.chunk_index)
      .map(chunk => Buffer.from(chunk.data, 'base64')));
    return JSON.parse(bytes.toString('utf8')).operations;
  });
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

    it('keeps the task ownership index coherent across replacement, snapshots, and restore', () => {
      const leases = new FrontierLeases();
      leases.applySnapshot('fi-1', {
        frontier_item_id: 'fi-1', agent_id: 'a', task_id: 't1',
        leased_at: '2026-01-01T00:00:00.000Z',
        expires_at: '2026-01-01T00:01:00.000Z', ttl_seconds: 60,
      });
      expect(leases.getSnapshotsByTask('t1').map(lease => lease.frontier_item_id))
        .toEqual(['fi-1']);

      leases.acquire({
        frontier_item_id: 'fi-1', agent_id: 'b', task_id: 't2',
        now: '2026-01-01T00:02:00.000Z', ttl_seconds: 60,
      });
      expect(leases.getSnapshotsByTask('t1')).toEqual([]);
      expect(leases.getSnapshotsByTask('t2')).toHaveLength(1);

      const restored = FrontierLeases.deserialize(leases.serialize());
      expect(restored.getSnapshotsByTask('t2')).toMatchObject([{
        frontier_item_id: 'fi-1', task_id: 't2',
      }]);
      restored.applySnapshot('fi-1', null);
      expect(restored.getSnapshotsByTask('t2')).toEqual([]);
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
      engine.dispose();
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

    it('leaves the task, lease, and audit tail untouched when heartbeat WAL append fails', () => {
      engine.registerAgent(makeTask('t1', 'fi-append-failure'));
      const ctx = (engine as unknown as { ctx: any }).ctx;
      const taskBefore = structuredClone(engine.getTask('t1'));
      const leaseBefore = ctx.frontierLeases.getSnapshot('fi-append-failure');
      const historyBefore = structuredClone(engine.getFullHistory());
      const journal = ctx.mutationJournal as MutationJournal;
      vi.spyOn(journal, 'appendTransaction').mockImplementationOnce(() => {
        throw new Error('synthetic heartbeat WAL append failure');
      });

      expect(() => engine.agentHeartbeat(
        't1',
        '2026-07-18T12:00:00.000Z',
      )).toThrow('synthetic heartbeat WAL append failure');
      expect(engine.getTask('t1')).toEqual(taskBefore);
      expect(ctx.frontierLeases.getSnapshot('fi-append-failure')).toEqual(leaseBefore);
      expect(engine.getFullHistory()).toEqual(historyBefore);
      expect(engine.getPersistenceRecoveryStatus()).toMatchObject({ writable: true });
    });

    it('rolls back a committed heartbeat apply failure and replays it exactly once', () => {
      engine.registerAgent({ ...makeTask('t1', 'fi-apply-failure'), status: 'pending' });
      engine.flushNow();
      const heartbeatAt = '2026-07-18T12:00:00.000Z';
      const taskBefore = structuredClone(engine.getTask('t1'));
      const leaseBefore = structuredClone(
        engine.getActiveFrontierLeases('2026-07-18T11:59:59.000Z')
          .find(lease => lease.frontier_item_id === 'fi-apply-failure'),
      );
      const historyBefore = structuredClone(engine.getFullHistory());
      const apply = engine.applyAgentCoordinationChangeMutation.bind(engine);
      vi.spyOn(engine, 'applyAgentCoordinationChangeMutation')
        .mockImplementationOnce((payload, recovery) => {
          apply(payload, recovery);
          throw new Error('synthetic heartbeat post-commit apply failure');
        });

      expect(() => engine.agentHeartbeat('t1', heartbeatAt)).toThrow(
        'synthetic heartbeat post-commit apply failure',
      );
      expect(engine.getTask('t1')).toEqual(taskBefore);
      expect(engine.getActiveFrontierLeases('2026-07-18T11:59:59.000Z')
        .find(lease => lease.frontier_item_id === 'fi-apply-failure')).toEqual(leaseBefore);
      expect(engine.getFullHistory()).toEqual(historyBefore);
      expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
        complete: false,
        writable: false,
        reason: expect.stringContaining('failed during in-memory application'),
      });

      engine.dispose();
      vi.restoreAllMocks();
      engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      expect(engine.getTask('t1')).toMatchObject({ heartbeat_at: heartbeatAt });
      expect(engine.getActiveFrontierLeases('2026-07-18T12:00:01.000Z'))
        .toEqual([expect.objectContaining({
          frontier_item_id: 'fi-apply-failure',
          leased_at: heartbeatAt,
        })]);
      expect(engine.getFullHistory().filter(event =>
        event.event_type === 'heartbeat' && event.linked_agent_task_id === 't1'))
        .toHaveLength(1);
      expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
        complete: true,
        writable: true,
      });
    });

    it('journals expired-lease cleanup as a bounded taskless delta and replays it', () => {
      engine.registerAgent({ ...makeTask('t1', 'fi-expired'), status: 'pending' });
      const journalPath = MutationJournal.pathForState(TEST_STATE_FILE);
      const beforeBytes = existsSync(journalPath) ? readFileSync(journalPath).length : 0;
      const dropped = engine.reapExpiredFrontierLeases('2030-01-01T00:00:00.000Z');
      expect(dropped).toEqual(['fi-expired']);

      const tail = readFileSync(journalPath).subarray(beforeBytes).toString('utf8');
      expect(journalOperations(tail).map(operation => operation.type))
        .toEqual(['agent_coordination_change']);

      engine.dispose();
      engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      expect(engine.getTask('t1')).toMatchObject({ status: 'pending' });
      expect(engine.getActiveFrontierLeases('2030-01-01T00:00:01.000Z')).toEqual([]);
      expect(engine.getPersistenceRecoveryStatus()).toMatchObject({
        complete: true,
        writable: true,
      });
    });

    it('leaves an expired lease installed when its taskless WAL append fails', () => {
      engine.registerAgent({ ...makeTask('t1', 'fi-expired-append'), status: 'pending' });
      const ctx = (engine as unknown as { ctx: any }).ctx;
      const before = ctx.frontierLeases.getSnapshot('fi-expired-append');
      vi.spyOn(ctx.mutationJournal as MutationJournal, 'appendTransaction')
        .mockImplementationOnce(() => {
          throw new Error('synthetic lease-reap WAL append failure');
        });

      expect(() => engine.reapExpiredFrontierLeases(
        '2030-01-01T00:00:00.000Z',
      )).toThrow('synthetic lease-reap WAL append failure');
      expect(ctx.frontierLeases.getSnapshot('fi-expired-append')).toEqual(before);
      expect(engine.getPersistenceRecoveryStatus()).toMatchObject({ writable: true });
    });

    it('splits a large expired-lease cleanup into bounded journal transactions', () => {
      for (let index = 0; index < 33; index++) {
        engine.registerAgent({
          ...makeTask(`task-${index}`, `fi-${index}`, `agent-${index}`),
          status: 'pending',
        });
      }
      const journalPath = MutationJournal.pathForState(TEST_STATE_FILE);
      const beforeBytes = readFileSync(journalPath).length;

      expect(engine.reapExpiredFrontierLeases('2030-01-01T00:00:00.000Z')).toHaveLength(33);
      const tail = readFileSync(journalPath).subarray(beforeBytes).toString('utf8');
      const operations = journalOperations(tail);
      expect(operations).toHaveLength(3);
      expect(operations.every(operation => operation.type === 'agent_coordination_change')).toBe(true);
      expect(operations.map(operation =>
        (operation.payload.lease_changes as unknown[]).length)).toEqual([16, 16, 1]);
      expect(engine.getActiveFrontierLeases('2030-01-01T00:00:01.000Z')).toEqual([]);
    });

    it('isFrontierItemHeldByOther distinguishes self from others', () => {
      engine.registerAgent(makeTask('t1', 'fi-1'));
      expect(engine.isFrontierItemHeldByOther('fi-1', 't1')).toBe(false);
      expect(engine.isFrontierItemHeldByOther('fi-1', 't-other')).toBe(true);
    });
  });
});
