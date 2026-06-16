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
    // and it's gone from the store
    expect(store.get(plan.plan_id)).toBeUndefined();
  });

  it('prune drops plans older than the TTL', () => {
    const store = new ProposedPlanStore(60_000); // 1 min TTL
    const plan = store.add({ command: 'x', ops, summary: 's', now: 1000 });
    expect(store.get(plan.plan_id)).toBeDefined();
    store.prune(1000 + 61_000);
    expect(store.get(plan.plan_id)).toBeUndefined();
    expect(store.size()).toBe(0);
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
});
