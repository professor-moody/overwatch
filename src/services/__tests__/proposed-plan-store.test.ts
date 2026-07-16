import { describe, it, expect } from 'vitest';
import { ProposedPlanStore } from '../proposed-plan-store.js';
import type { OperatorOp } from '../command-interpreter.js';

const ops: OperatorOp[] = [{ op: 'directive', task_id: 't1', agent_label: 'a1', kind: 'pause' }];

describe('ProposedPlanStore', () => {
  it('add mints a plan_id and stores an open plan', () => {
    const store = new ProposedPlanStore();
    const plan = store.add({ command: 'pause it', ops, summary: 'pause t1', now: 1000 });
    expect(plan.plan_id).toMatch(/[0-9a-f-]{36}/);
    expect(plan.status).toBe('open');
    expect(store.get(plan.plan_id)?.summary).toBe('pause t1');
    expect(store.getOpen(1000)).toHaveLength(1);
  });

  it('resolve marks a plan confirmed and prevents a second resolve', () => {
    const store = new ProposedPlanStore();
    const plan = store.add({ command: 'x', ops, summary: 's', now: 1000 });
    expect(store.resolve(plan.plan_id, 'confirmed', 1000)?.status).toBe('confirmed');
    // second resolve returns null (already resolved) — guards double-confirm
    expect(store.resolve(plan.plan_id, 'confirmed', 1000)).toBeNull();
    expect(store.getOpen(1000)).toHaveLength(0);
  });

  it('resolve of an unknown id returns null', () => {
    const store = new ProposedPlanStore();
    expect(store.resolve('nope', 'denied')).toBeNull();
  });

  it('resolve prunes first — a plan past its TTL can NOT be confirmed (no stale execution)', () => {
    const store = new ProposedPlanStore(60_000); // 1 min TTL
    const plan = store.add({ command: 'x', ops, summary: 's', now: 1000 });
    // Confirm 61s later, with no intervening getOpen()/add() to sweep it.
    expect(store.resolve(plan.plan_id, 'confirmed', 1000 + 61_000)).toBeNull();
    // and its expired state remains durable for recovery/audit
    expect(store.get(plan.plan_id)).toMatchObject({
      status: 'expired',
      expires_at: 61_000,
      expired_at: 61_000,
    });
  });

  it('prune marks plans expired without discarding their body', () => {
    const store = new ProposedPlanStore(60_000); // 1 min TTL
    const plan = store.add({ command: 'x', ops, summary: 's', now: 1000 });
    expect(store.get(plan.plan_id)).toBeDefined();
    store.prune(1000 + 61_000);
    expect(store.get(plan.plan_id)).toMatchObject({
      status: 'expired',
      command: 'x',
      ops,
    });
    expect(store.size()).toBe(1);
  });

  it('describeResolution distinguishes confirmed / denied / expired / unknown after the plan is gone', () => {
    const store = new ProposedPlanStore(60_000); // 1 min TTL
    // open plan → 'open'
    const openPlan = store.add({ command: 'a', ops, summary: 'a', now: 1000 });
    expect(store.describeResolution(openPlan.plan_id, 1000)).toBe('open');

    // confirmed → tombstone survives pruning
    const confirmed = store.add({ command: 'b', ops, summary: 'b', now: 1000 });
    store.resolve(confirmed.plan_id, 'confirmed', 1000);
    expect(store.describeResolution(confirmed.plan_id, 1000)).toBe('confirmed');
    expect(store.describeResolution(confirmed.plan_id, 1000 + 61_000)).toBe('confirmed'); // pruned from live map, tombstone remains

    // denied → tombstone survives pruning
    const denied = store.add({ command: 'c', ops, summary: 'c', now: 1000 });
    store.resolve(denied.plan_id, 'denied', 1000);
    expect(store.describeResolution(denied.plan_id, 1000 + 61_000)).toBe('denied');

    // open-but-timed-out → 'expired' (tombstoned by prune, not confirmed/denied)
    const stale = store.add({ command: 'd', ops, summary: 'd', now: 1000 });
    expect(store.describeResolution(stale.plan_id, 1000 + 61_000)).toBe('expired');

    // never seen → 'unknown'
    expect(store.describeResolution('never-existed')).toBe('unknown');
  });

  it('onChange fires on add and resolve', () => {
    const store = new ProposedPlanStore();
    let calls = 0;
    store.onChange(() => { calls++; });
    const plan = store.add({ command: 'x', ops, summary: 's', now: 1000 });
    store.resolve(plan.plan_id, 'denied', 1000);
    expect(calls).toBe(2);
  });

  it('getOpen returns newest first', () => {
    const store = new ProposedPlanStore();
    const a = store.add({ command: 'a', ops, summary: 'a', now: 1000 });
    const b = store.add({ command: 'b', ops, summary: 'b', now: 2000 });
    const open = store.getOpen(2000);
    expect(open.map(p => p.plan_id)).toEqual([b.plan_id, a.plan_id]);
  });

  it('round-trips the original absolute expiry without extending it on restart', () => {
    const store = new ProposedPlanStore(60_000);
    const plan = store.add({ command: 'x', ops, summary: 's', now: 1_000 });
    const restored = ProposedPlanStore.deserialize(store.serialize(), 60_000, 30_000);

    expect(restored.get(plan.plan_id)?.expires_at).toBe(61_000);
    expect(restored.getOpen(60_999).map(p => p.plan_id)).toEqual([plan.plan_id]);
    expect(restored.getOpen(61_000)).toEqual([]);
    expect(restored.describeResolution(plan.plan_id, 61_000)).toBe('expired');
    expect(restored.get(plan.plan_id)).toMatchObject({
      status: 'expired',
      expires_at: 61_000,
      expired_at: 61_000,
    });
  });

  it('persists canonical ownership, confirmation, acknowledgement, and execution outcome', () => {
    const store = new ProposedPlanStore();
    const plan = store.add({
      command: 'pause it',
      ops,
      summary: 'pause t1',
      owner_task_id: 't1',
      owner_agent_label: 'a1',
      now: 1_000,
    });
    store.resolve(plan.plan_id, 'confirmed', 1_100);
    store.recordExecutionOutcome(plan.plan_id, [{ ok: true }], 1_200);

    expect(store.get(plan.plan_id)).toMatchObject({
      owner_task_id: 't1',
      owner_agent_label: 'a1',
      source_task_id: 't1',
      source_agent_id: 'a1',
      status: 'confirmed',
      confirmed_at: 1_100,
      acknowledged_at: 1_100,
      execution_outcome: {
        status: 'succeeded',
        completed_at: 1_200,
        results: [{ ok: true }],
      },
    });
    const restored = ProposedPlanStore.deserialize(store.serialize(), undefined, 2_000);
    expect(restored.get(plan.plan_id)?.execution_outcome?.status).toBe('succeeded');
  });

  it('restores terminal tombstones and keeps existing listeners attached', () => {
    const source = new ProposedPlanStore();
    const confirmed = source.add({ command: 'x', ops, summary: 's', now: 1_000 });
    source.resolve(confirmed.plan_id, 'confirmed', 1_001);

    const store = new ProposedPlanStore();
    let calls = 0;
    store.onChange(() => { calls++; });
    store.restore(source.serialize(), 2_000);

    expect(calls).toBe(0);
    expect(store.describeResolution(confirmed.plan_id, 2_000)).toBe('confirmed');
    store.add({ command: 'y', ops, summary: 't', now: 2_001 });
    expect(calls).toBe(1);
  });

  it('blocks durable mutations while degraded but leaves filtered reads available', () => {
    const store = new ProposedPlanStore(60_000);
    const plan = store.add({ command: 'x', ops, summary: 's', now: 1_000 });
    store.setMutationGuard(() => { throw new Error('read-only'); });

    expect(() => store.add({ command: 'y', ops, summary: 't', now: 2_000 })).toThrow('read-only');
    expect(() => store.resolve(plan.plan_id, 'confirmed', 2_000)).toThrow('read-only');
    expect(() => store.prune(61_000)).toThrow('read-only');
    expect(store.getOpen(61_000)).toEqual([]);
    expect(store.get(plan.plan_id)).toBeDefined();
  });
});
