import { performance } from 'node:perf_hooks';
import { describe, expect, it } from 'vitest';
import { projectDashboardStatePatch } from '../dashboard-projectors.js';
import { applyIndexedCollectionPatch } from '../../contracts/indexed-collection-patch.js';

function agent(index: number, revision = 0) {
  return {
    task_id: `scale-task-${index}`,
    id: `scale-task-${index}`,
    agent_label: `scale-agent-${index}`,
    status: revision === 0 ? 'running' : 'completed',
    revision,
  };
}

function frontier(index: number, revision = 0) {
  return {
    id: `scale-frontier-${index}`,
    type: 'incomplete_node',
    node_id: `node-${index}`,
    score: index + revision,
  };
}

describe('dashboard websocket state-patch scale gate', () => {
  it('keeps ten 50k-collection changes bounded in time and wire size', () => {
    const previous = {
      agents: Array.from({ length: 50_000 }, (_, index) => agent(index)),
      active_agents: [],
      frontier: Array.from({ length: 50_000 }, (_, index) => frontier(index)),
      graph_summary: { total_nodes: 50_000 },
    };
    const next = {
      ...previous,
      agents: previous.agents.slice(),
      frontier: previous.frontier.slice(),
    };
    for (let index = 0; index < 10; index++) {
      const position = index * 4_999;
      next.agents[position] = agent(position, 1);
      next.frontier[position] = frontier(position, 1);
    }

    const started = performance.now();
    const patch = projectDashboardStatePatch(previous, next);
    const wire = JSON.stringify(patch);
    const projectedElapsed = performance.now() - started;
    const applyStarted = performance.now();
    const appliedAgents = applyIndexedCollectionPatch(
      previous.agents,
      patch.agents!,
      value => value.task_id,
    );
    const appliedFrontier = applyIndexedCollectionPatch(
      previous.frontier,
      patch.frontier!,
      value => value.id,
    );
    const applyElapsed = performance.now() - applyStarted;

    expect(patch.agents?.upsert).toHaveLength(10);
    expect(patch.frontier?.upsert).toHaveLength(10);
    expect(patch.agents?.replace).toBeUndefined();
    expect(patch.frontier?.replace).toBeUndefined();
    expect(Buffer.byteLength(wire)).toBeLessThan(512 * 1_024);
    expect(appliedAgents).toEqual(next.agents);
    expect(appliedFrontier).toEqual(next.frontier);
    expect(projectedElapsed).toBeLessThan(2_000);
    expect(applyElapsed).toBeLessThan(1_000);
  }, 30_000);

  it('encodes a 50k end-to-end reorder as one move instead of a replacement', () => {
    const frontierItems = Array.from({ length: 50_000 }, (_, index) => frontier(index));
    const previous = { agents: [], active_agents: [], frontier: frontierItems };
    const next = {
      ...previous,
      frontier: [frontierItems[frontierItems.length - 1]!, ...frontierItems.slice(0, -1)],
    };

    const started = performance.now();
    const patch = projectDashboardStatePatch(previous, next);
    const elapsed = performance.now() - started;

    expect(patch.frontier?.replace).toBeUndefined();
    expect(patch.frontier?.moves).toEqual([{ id: 'scale-frontier-49999', index: 0 }]);
    expect(Buffer.byteLength(JSON.stringify(patch))).toBeLessThan(2_048);
    expect(elapsed).toBeLessThan(1_000);
  }, 30_000);
});
