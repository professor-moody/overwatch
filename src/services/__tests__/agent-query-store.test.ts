import { describe, it, expect } from 'vitest';
import { AgentQueryStore } from '../agent-query-store.js';

describe('AgentQueryStore (Phase 3D)', () => {
  it('add mints a query_id and stores an open question', () => {
    const store = new AgentQueryStore();
    const q = store.add({ task_id: 't1', agent_id: 'a1', question: 'which path?', now: 1000 });
    expect(q.query_id).toMatch(/[0-9a-f-]{36}/);
    expect(q.status).toBe('open');
    expect(store.getOpen(1000).map(x => x.query_id)).toEqual([q.query_id]);
  });

  it('answer marks the question answered and removes it from the open inbox', () => {
    const store = new AgentQueryStore();
    const q = store.add({ task_id: 't1', question: 'x?', now: 1000 });
    const answered = store.answer(q.query_id, 'do A', 1001);
    expect(answered?.status).toBe('answered');
    expect(answered?.answer).toBe('do A');
    expect(store.getOpen(1001)).toHaveLength(0);
    // a second answer is a no-op
    expect(store.answer(q.query_id, 'do B', 1002)).toBeNull();
  });

  it('getAnswerForTask PEEKS (at-least-once): returns the answer on every call until cleared', () => {
    const store = new AgentQueryStore();
    const q = store.add({ task_id: 't1', question: 'x?', now: 1000 });
    expect(store.getAnswerForTask('t1', 1_000)).toBeNull(); // not answered yet
    store.answer(q.query_id, 'go left', 1001);
    // redelivered on every heartbeat (a dropped heartbeat self-heals)
    expect(store.getAnswerForTask('t1', 1_001)?.answer).toBe('go left');
    expect(store.getAnswerForTask('t1', 1_001)?.answer).toBe('go left');
  });

  it('stops delivering an answered question at its original absolute expiry', () => {
    const store = new AgentQueryStore(60_000);
    const q = store.add({ task_id: 't1', question: 'x?', now: 1_000 });
    store.answer(q.query_id, 'go left', 2_000);

    expect(store.getAnswerForTask('t1', 60_999)?.answer).toBe('go left');
    expect(store.getAnswerForTask('t1', 61_000)).toBeNull();
    expect(store.get(q.query_id)).toMatchObject({
      status: 'expired',
      answer: 'go left',
      expires_at: 61_000,
      expired_at: 61_000,
    });
  });

  it('scopes delivery to the asking task', () => {
    const store = new AgentQueryStore();
    const q = store.add({ task_id: 't1', question: 'x?', now: 1000 });
    store.answer(q.query_id, 'ans', 1001);
    expect(store.getAnswerForTask('other', 1_001)).toBeNull();
    expect(store.getAnswerForTask('t1', 1_001)?.answer).toBe('ans');
  });

  it('expireForTask retains but closes a terminated task\'s questions', () => {
    const store = new AgentQueryStore();
    const open = store.add({ task_id: 't1', question: 'open?', now: 1000 });
    const ans = store.add({ task_id: 't1', question: 'answered?', now: 1000 });
    store.answer(ans.query_id, 'a', 1001);
    store.add({ task_id: 't2', question: 'other task', now: 1000 });
    store.expireForTask('t1', 1_002);
    expect(store.get(open.query_id)).toMatchObject({ status: 'expired', expired_at: 1_002 });
    expect(store.get(ans.query_id)).toMatchObject({
      status: 'expired',
      answer: 'a',
      expired_at: 1_002,
    });
    expect(store.getAnswerForTask('t1', 1_001)).toBeNull();
    expect(store.getOpen(1001).map(q => q.task_id)).toEqual(['t2']); // t2 untouched
  });

  it('prune marks questions expired without discarding their body', () => {
    const store = new AgentQueryStore(60_000);
    const q = store.add({ task_id: 't1', question: 'x?', now: 1000 });
    expect(store.get(q.query_id)).toBeDefined();
    store.prune(1000 + 61_000);
    expect(store.get(q.query_id)).toMatchObject({
      status: 'expired',
      question: 'x?',
      expired_at: 61_000,
    });
  });

  it('onChange fires on add and answer', () => {
    const store = new AgentQueryStore();
    let calls = 0;
    store.onChange(() => { calls++; });
    const q = store.add({ task_id: 't1', question: 'x?', now: 1000 });
    store.answer(q.query_id, 'a', 1001);
    expect(calls).toBe(2);
  });

  it('getOpen returns oldest-first (FIFO)', () => {
    const store = new AgentQueryStore();
    const a = store.add({ task_id: 't1', question: 'first', now: 1000 });
    const b = store.add({ task_id: 't2', question: 'second', now: 2000 });
    expect(store.getOpen(2000).map(q => q.query_id)).toEqual([a.query_id, b.query_id]);
  });

  it('answerMany fans one answer out to every open member (answer-once)', () => {
    const store = new AgentQueryStore();
    const a = store.add({ task_id: 't1', agent_id: 'recon-1', question: 'scan hard?', now: 1000 });
    const b = store.add({ task_id: 't2', agent_id: 'recon-2', question: 'scan hard?', now: 1000 });
    const resolved = store.answerMany([a.query_id, b.query_id], 'yes', 1001);
    expect(resolved.map(r => r.query_id).sort()).toEqual([a.query_id, b.query_id].sort());
    expect(store.getAnswerForTask('t1', 1_001)?.answer).toBe('yes');
    expect(store.getAnswerForTask('t2', 1_001)?.answer).toBe('yes');
    expect(store.getOpen(1001)).toHaveLength(0);
  });

  it('answerMany skips unknown / already-answered ids and fires onChange once', () => {
    const store = new AgentQueryStore();
    let calls = 0;
    const a = store.add({ task_id: 't1', question: 'q?', now: 1000 });
    const b = store.add({ task_id: 't2', question: 'q?', now: 1000 });
    store.answer(a.query_id, 'early', 1001);
    store.onChange(() => { calls++; });
    const resolved = store.answerMany([a.query_id, b.query_id, 'nope'], 'late', 1002);
    // a is already answered (keeps its first answer), nope is unknown → only b.
    expect(resolved.map(r => r.query_id)).toEqual([b.query_id]);
    expect(store.getAnswerForTask('t1', 1_002)?.answer).toBe('early');
    expect(store.getAnswerForTask('t2', 1_002)?.answer).toBe('late');
    expect(calls).toBe(1);
  });

  it('answerMany with no answerable ids does not fire onChange', () => {
    const store = new AgentQueryStore();
    let calls = 0;
    store.onChange(() => { calls++; });
    expect(store.answerMany(['x', 'y'], 'ans', 1000)).toEqual([]);
    expect(calls).toBe(0);
  });

  it('round-trips the original absolute expiry without extending it on restart', () => {
    const store = new AgentQueryStore(60_000);
    const query = store.add({ task_id: 't1', question: 'x?', now: 1_000 });
    const restored = AgentQueryStore.deserialize(store.serialize(), 60_000, 30_000);

    expect(restored.get(query.query_id)?.expires_at).toBe(61_000);
    expect(restored.getOpen(60_999).map(q => q.query_id)).toEqual([query.query_id]);
    expect(restored.getOpen(61_000)).toEqual([]);
    expect(restored.get(query.query_id)).toMatchObject({
      status: 'expired',
      expires_at: 61_000,
      expired_at: 61_000,
    });
  });

  it('tracks delivery and explicit acknowledgement without redelivering', () => {
    const store = new AgentQueryStore();
    const query = store.add({
      owner_task_id: 't1',
      owner_agent_label: 'a1',
      question: 'which path?',
      now: 1_000,
    });
    store.answer(query.query_id, 'left', 1_100);
    store.markDelivered(query.query_id, 't1', 1_200);
    expect(store.getAnswerForTask('t1', 1_200)).toMatchObject({
      delivered_at: 1_200,
      answer: 'left',
    });
    store.acknowledge(query.query_id, 't1', 1_300);
    expect(store.getAnswerForTask('t1', 1_300)).toBeNull();
    expect(store.get(query.query_id)).toMatchObject({
      owner_task_id: 't1',
      owner_agent_label: 'a1',
      task_id: 't1',
      agent_id: 'a1',
      answered_at: 1_100,
      delivered_at: 1_200,
      acknowledged_at: 1_300,
    });
  });

  it('restores answered questions and keeps existing listeners attached', () => {
    const source = new AgentQueryStore();
    const query = source.add({ task_id: 't1', question: 'x?', now: 1_000 });
    source.answer(query.query_id, 'go left', 1_001);

    const store = new AgentQueryStore();
    let calls = 0;
    store.onChange(() => { calls++; });
    store.restore(source.serialize(), 2_000);

    expect(calls).toBe(0);
    expect(store.getAnswerForTask('t1', 2_000)?.answer).toBe('go left');
    store.add({ task_id: 't2', question: 'y?', now: 2_001 });
    expect(calls).toBe(1);
  });

  it('blocks durable mutations while degraded but leaves filtered reads available', () => {
    const store = new AgentQueryStore(60_000);
    const query = store.add({ task_id: 't1', question: 'x?', now: 1_000 });
    store.setMutationGuard(() => { throw new Error('read-only'); });

    expect(() => store.add({ task_id: 't2', question: 'y?', now: 2_000 })).toThrow('read-only');
    expect(() => store.answer(query.query_id, 'answer', 2_000)).toThrow('read-only');
    expect(() => store.answerMany([query.query_id], 'answer', 2_000)).toThrow('read-only');
    expect(() => store.expireForTask('t1')).toThrow('read-only');
    expect(() => store.prune(61_000)).toThrow('read-only');
    expect(store.getOpen(61_000)).toEqual([]);
    expect(store.get(query.query_id)).toBeDefined();
  });
});
