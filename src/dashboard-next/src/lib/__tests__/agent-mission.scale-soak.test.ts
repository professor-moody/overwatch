import { performance } from 'node:perf_hooks';
import { describe, expect, it } from 'vitest';
import type { AgentInfo } from '../types';
import { buildMissionCards } from '../agent-mission';

describe('agent mission scale gate', () => {
  it('projects mission cards linearly for a 50k-task fleet', () => {
    const agents: AgentInfo[] = Array.from({ length: 50_000 }, (_, index) => ({
      id: `scale-task-${index}`,
      task_id: `scale-task-${index}`,
      agent_id: `scale-agent-${index}`,
      agent_label: `scale-agent-${index}`,
      assigned_at: '2026-07-17T00:00:00.000Z',
      status: 'completed',
      queued: false,
      lifecycle: 'completed',
      live: false,
      subgraph_node_ids: [],
      findings_count: index % 3,
    }));
    const started = performance.now();
    const cards = buildMissionCards(agents, {
      now: Date.parse('2026-07-17T00:02:00.000Z'),
      sessions: [],
      pendingActions: [],
      agentQueries: [],
    });
    const elapsed = performance.now() - started;

    expect(cards).toHaveLength(50_000);
    expect(elapsed).toBeLessThan(750);
  });
});
