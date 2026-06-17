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
  return { id: 't1', agent_id: 'recon-1', status: 'running', task: 'recon', ...o };
}

describe('buildAttentionQueue', () => {
  it('returns an empty queue when nothing needs the operator', () => {
    const v = buildAttentionQueue({ now: NOW });
    expect(v.total).toBe(0);
    expect(v.items).toEqual([]);
    expect(v.counts).toEqual({ approval: 0, question: 0, failed: 0 });
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
    expect(v.counts).toEqual({ approval: 1, question: 1, failed: 1 });
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
  });
});
