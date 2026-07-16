import { describe, it, expect } from 'vitest';
import { buildAttentionQueue } from '../attention-queue';
import type { AgentInfo, PendingAction } from '../types';
import type { AgentQuery } from '../api';

const NOW = Date.UTC(2026, 5, 17, 12, 0, 0);

function action(o: Partial<PendingAction> = {}): PendingAction {
  return { action_id: 'act-1', technique: 'ssh', description: 'spray', submitted_at: new Date(NOW).toISOString(), ...o };
}
function query(o: Partial<AgentQuery> = {}): AgentQuery {
  return { query_id: 'q1', agent_id: 'recon-1', question: 'increase intensity?', status: 'open', created_at: NOW, ...o };
}
function agent(o: Partial<AgentInfo> = {}): AgentInfo {
  return { task_id: 't1', agent_label: 'recon-1', id: 't1', agent_id: 'recon-1', status: 'running', assigned_at: new Date(NOW - 10_000).toISOString(), queued: false, lifecycle: 'live', live: true, subgraph_node_ids: [], findings_count: 0, ...o };
}

describe('buildAttentionQueue', () => {
  it('returns an empty queue when nothing needs the operator', () => {
    const v = buildAttentionQueue({ now: NOW });
    expect(v.total).toBe(0);
    expect(v.items).toEqual([]);
    expect(v.counts).toEqual({ approval: 0, question: 0, plan: 0, failed: 0, stuck: 0 });
  });

  it('merges approvals, questions, and failed agents into one queue with counts', () => {
    const v = buildAttentionQueue({
      now: NOW,
      pendingActions: [action()],
      agentQueries: [query()],
      agents: [agent({ id: 'tf', status: 'failed', result_summary: 'crashed' })],
      // a running agent should NOT appear:
    }, );
    expect(v.total).toBe(3);
    expect(v.counts).toEqual({ approval: 1, question: 1, plan: 0, failed: 1, stuck: 0 });
  });

  it('surfaces only OPEN proposed plans (confirm handle + TTL countdown), ranked approval > plan > stuck', () => {
    const plan = (o: Partial<import('../api').ProposedPlan> = {}): import('../api').ProposedPlan => ({
      plan_id: 'p1', command: 'what next?', ops: [{ op: 'directive' } as never], summary: 'Prioritize app01 recon',
      source_agent_id: 'planner-1', created_at: NOW - 60_000, status: 'open', ...o,
    });
    // a heartbeating-but-idle running agent (stuck) — same construction as the stuck suite
    const stuck = agent({
      id: 'ts', agent_id: 'recon-9', status: 'running',
      assigned_at: new Date(NOW - 20 * 60_000).toISOString(),
      current_action_at: new Date(NOW - 20 * 60_000).toISOString(),
    });
    const v = buildAttentionQueue({
      now: NOW,
      pendingActions: [action()],
      proposedPlans: [plan(), plan({ plan_id: 'p-expired', status: 'expired' })], // expired must be dropped
      agents: [stuck],
    });
    const planItem = v.items.find(i => i.kind === 'plan');
    expect(v.counts.plan).toBe(1); // only the open one, not the expired
    expect(planItem?.id).toBe('plan:p1');
    expect(planItem?.planId).toBe('p1'); // confirm handle
    expect(planItem?.detail).toContain('Prioritize app01 recon');
    expect(planItem?.detail).toContain('1 op');
    // TTL countdown: ceil((600000 − 60000) / 60000) = 9 minutes left
    expect(planItem?.detail).toContain('expires in ~9m');
    // full ordering: approval (80) > plan (70) > stuck (60)
    const order = v.items.map(i => i.kind);
    expect(v.counts.stuck).toBe(1);
    expect(order.indexOf('approval')).toBeLessThan(order.indexOf('plan'));
    expect(order.indexOf('plan')).toBeLessThan(order.indexOf('stuck'));
  });

  it('orders timeout-soon approval > question > high-risk approval > normal approval > failed', () => {
    const v = buildAttentionQueue({
      now: NOW,
      pendingActions: [
        action({ action_id: 'normal', opsec_context: { noise_level: 0 } }),
        action({ action_id: 'highrisk', opsec_context: { noise_level: 3.5 } }),
        action({ action_id: 'expiring', timeout_at: new Date(NOW + 30_000).toISOString() }),
      ],
      agentQueries: [query()],
      agents: [agent({ id: 'tf', status: 'failed' })],
    });
    expect(v.items.map(i => i.id)).toEqual([
      'approval:expiring',
      'question:q1',
      'approval:highrisk',
      'approval:normal',
      'failed:tf',
    ]);
  });

  it('drops failed agents older than the recency window, keeps recent + uncompleted ones', () => {
    const v = buildAttentionQueue({
      now: NOW,
      agents: [
        agent({ id: 'old', status: 'failed', completed_at: new Date(NOW - 60 * 60_000).toISOString() }),
        agent({ id: 'recent', status: 'failed', completed_at: new Date(NOW - 60_000).toISOString() }),
        agent({ id: 'nostamp', status: 'interrupted' }),
      ],
    });
    expect(v.items.map(i => i.taskId).sort()).toEqual(['nostamp', 'recent']);
  });

  it('excludes answered questions and non-terminal agents', () => {
    const v = buildAttentionQueue({
      now: NOW,
      agentQueries: [query({ status: 'answered' })],
      agents: [agent(), agent({ id: 'done', status: 'completed' }), agent({ id: 'pend', status: 'pending' })],
    });
    expect(v.total).toBe(0);
  });

  it('gives each item a stable kind-prefixed id and carries action handles', () => {
    const v = buildAttentionQueue({ now: NOW, pendingActions: [action({ action_id: 'a9', agent_id: 'web-2' })] });
    expect(v.items[0]).toMatchObject({ id: 'approval:a9', kind: 'approval', actionId: 'a9', agentLabel: 'web-2' });
    expect(v.items[0].risk?.label).toBeDefined();
  });

  it('carries question options for quick-answers', () => {
    const v = buildAttentionQueue({ now: NOW, agentQueries: [query({ options: ['yes', 'no'] })] });
    expect(v.items[0].options).toEqual(['yes', 'no']);
    expect(v.items[0].queryId).toBe('q1');
    // An un-clustered question still carries its single member for the fan-out path.
    expect(v.items[0].queryIds).toEqual(['q1']);
  });

  it('clusters identical questions from different agents into one item (answer-once)', () => {
    const v = buildAttentionQueue({
      now: NOW,
      agentQueries: [
        query({ query_id: 'q1', agent_id: 'recon-1', question: 'Increase intensity?' }),
        query({ query_id: 'q2', agent_id: 'recon-2', question: '  increase   INTENSITY? ' }), // same after normalize
        query({ query_id: 'q3', agent_id: 'recon-3', question: 'Increase intensity?' }),
      ],
    });
    expect(v.counts.question).toBe(1);
    const item = v.items[0];
    expect(item.queryIds).toEqual(['q1', 'q2', 'q3']);
    expect(item.queryId).toBe('q1'); // representative = oldest/first
    expect(item.title).toBe('Agent question · 3 agents');
    expect(item.clusterAgentLabels).toEqual(['recon-1', 'recon-2', 'recon-3']);
  });

  it('keeps questions with different text or different options as separate items', () => {
    const v = buildAttentionQueue({
      now: NOW,
      agentQueries: [
        query({ query_id: 'q1', question: 'scan hard?', options: ['yes', 'no'] }),
        query({ query_id: 'q2', question: 'scan hard?', options: ['yes'] }), // different option set
        query({ query_id: 'q3', question: 'pivot now?' }),                   // different text
      ],
    });
    expect(v.counts.question).toBe(3);
    expect(v.items.every(i => i.queryIds?.length === 1)).toBe(true);
  });
});

describe('buildAttentionQueue — stuck agents', () => {
  const idle = (o: Partial<AgentInfo> = {}) => agent({
    status: 'running',
    assigned_at: new Date(NOW - 20 * 60_000).toISOString(),
    current_action_at: new Date(NOW - 20 * 60_000).toISOString(),
    ...o,
  });

  it('flags a heartbeating-but-idle running agent as a stuck item', () => {
    const v = buildAttentionQueue({ now: NOW, agents: [idle({ id: 'tstuck', agent_id: 'recon-9' })] });
    expect(v.counts.stuck).toBe(1);
    const it = v.items.find(i => i.kind === 'stuck');
    expect(it?.taskId).toBe('tstuck');
    expect(it?.detail).toContain('idle');
  });

  it('does NOT flag a just-started agent (assigned_at recent)', () => {
    const v = buildAttentionQueue({ now: NOW, agents: [idle({ assigned_at: new Date(NOW - 60_000).toISOString(), current_action_at: new Date(NOW - 60_000).toISOString() })] });
    expect(v.counts.stuck).toBe(0);
  });

  it('does NOT flag an idle agent that is blocked (pending approval) — no double-count', () => {
    const v = buildAttentionQueue({
      now: NOW,
      agents: [idle({ task_id: 'tb', id: 'tb', agent_label: 'web-2', agent_id: 'web-2' })],
      pendingActions: [action({ action_id: 'a1', task_id: 'tb', agent_id: 'web-2' })],
    });
    expect(v.counts.stuck).toBe(0);
    expect(v.counts.approval).toBe(1);
  });

  it('does NOT flag when assigned_at is missing (legacy non-heartbeating task)', () => {
    const v = buildAttentionQueue({ now: NOW, agents: [agent({ status: 'running', current_action_at: new Date(NOW - 20 * 60_000).toISOString() })] });
    expect(v.counts.stuck).toBe(0);
  });

  it('does NOT flag when current_action_at is absent (unattributable activity)', () => {
    const v = buildAttentionQueue({ now: NOW, agents: [agent({ status: 'running', assigned_at: new Date(NOW - 20 * 60_000).toISOString() })] });
    expect(v.counts.stuck).toBe(0);
  });

  it('a bad last_finding_at does not leak NaN into the stuck detail', () => {
    const v = buildAttentionQueue({ now: NOW, agents: [idle({ id: 'tn', last_finding_at: 'not-a-date' })] });
    expect(v.items.find(i => i.kind === 'stuck')?.detail).not.toContain('NaN');
  });

  it('orders stuck below approvals/questions, above failed', () => {
    const v = buildAttentionQueue({
      now: NOW,
      pendingActions: [action({ action_id: 'a1' })],
      agents: [idle({ id: 'tstuck' }), agent({ id: 'tf', status: 'failed' })],
    });
    const kinds = v.items.map(i => i.kind);
    expect(kinds.indexOf('approval')).toBeLessThan(kinds.indexOf('stuck'));
    expect(kinds.indexOf('stuck')).toBeLessThan(kinds.indexOf('failed'));
  });
});
