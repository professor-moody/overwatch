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
    expect(store.getAnswerForTask('t1')).toBeNull(); // not answered yet
    store.answer(q.query_id, 'go left', 1001);
    // redelivered on every heartbeat (a dropped heartbeat self-heals)
    expect(store.getAnswerForTask('t1')?.answer).toBe('go left');
    expect(store.getAnswerForTask('t1')?.answer).toBe('go left');
  });

  it('scopes delivery to the asking task', () => {
    const store = new AgentQueryStore();
    const q = store.add({ task_id: 't1', question: 'x?', now: 1000 });
    store.answer(q.query_id, 'ans', 1001);
    expect(store.getAnswerForTask('other')).toBeNull();
    expect(store.getAnswerForTask('t1')?.answer).toBe('ans');
  });

  it('expireForTask drops a terminated task\'s questions (no answering into the void)', () => {
    const store = new AgentQueryStore();
    const open = store.add({ task_id: 't1', question: 'open?', now: 1000 });
    const ans = store.add({ task_id: 't1', question: 'answered?', now: 1000 });
    store.answer(ans.query_id, 'a', 1001);
    store.add({ task_id: 't2', question: 'other task', now: 1000 });
    store.expireForTask('t1');
    expect(store.get(open.query_id)).toBeUndefined();
    expect(store.get(ans.query_id)).toBeUndefined();
    expect(store.getAnswerForTask('t1')).toBeNull();
    expect(store.getOpen(1001).map(q => q.task_id)).toEqual(['t2']); // t2 untouched
  });

  it('prune drops questions past the TTL', () => {
    const store = new AgentQueryStore(60_000);
    const q = store.add({ task_id: 't1', question: 'x?', now: 1000 });
    expect(store.get(q.query_id)).toBeDefined();
    store.prune(1000 + 61_000);
    expect(store.get(q.query_id)).toBeUndefined();
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
    expect(store.getAnswerForTask('t1')?.answer).toBe('yes');
    expect(store.getAnswerForTask('t2')?.answer).toBe('yes');
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
    expect(store.getAnswerForTask('t1')?.answer).toBe('early');
    expect(store.getAnswerForTask('t2')?.answer).toBe('late');
    expect(calls).toBe(1);
  });

  it('answerMany with no answerable ids does not fire onChange', () => {
    const store = new AgentQueryStore();
    let calls = 0;
    store.onChange(() => { calls++; });
    expect(store.answerMany(['x', 'y'], 'ans', 1000)).toEqual([]);
    expect(calls).toBe(0);
  });
});
