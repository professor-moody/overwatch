import { describe, expect, it } from 'vitest';
import type { AgentTask, Campaign, ExportedGraph } from '../../types.js';
import {
  projectCampaignDtos,
  projectDashboardState,
  projectDashboardSnapshot,
  projectDashboardStatePatch,
  projectGraphDelta,
} from '../dashboard-projectors.js';
import { applyIndexedCollectionPatch } from '../../contracts/indexed-collection-patch.js';

const progress = (total: number, completed: number) => ({
  total,
  completed,
  succeeded: completed,
  failed: 0,
  consecutive_failures: 0,
});

const campaign = (overrides: Partial<Campaign> = {}): Campaign => ({
  id: 'campaign-parent',
  name: 'Parent',
  strategy: 'custom',
  status: 'active',
  items: ['fi-1', 'fi-2'],
  abort_conditions: [],
  progress: progress(2, 0),
  created_at: '2026-07-16T00:00:00.000Z',
  findings: ['finding-shared'],
  ...overrides,
});

const agent = (overrides: Partial<AgentTask> = {}): AgentTask => ({
  id: 'task-1',
  agent_id: 'agent-1',
  assigned_at: '2026-07-16T00:00:00.000Z',
  status: 'running',
  subgraph_node_ids: [],
  campaign_id: 'campaign-parent',
  ...overrides,
});

const graph = (): ExportedGraph => ({
  nodes: [
    { id: 'node-new', properties: { id: 'node-new', type: 'host', label: 'New host', confidence: 1, discovered_at: 'now' } },
    { id: 'node-stable', properties: { id: 'node-stable', type: 'host', label: 'Stable host', confidence: 1, discovered_at: 'now' } },
  ],
  edges: [
    { id: 'edge-new', source: 'node-new', target: 'node-stable', properties: { type: 'REACHABLE', confidence: 1, discovered_at: 'now' } },
    { id: 'edge-stable', source: 'node-stable', target: 'node-new', properties: { type: 'REACHABLE', confidence: 1, discovered_at: 'now' } },
  ],
  cold_nodes: [{
    id: 'cold-1',
    type: 'host',
    label: 'Cold host',
    discovered_at: 'now',
    last_seen_at: 'now',
  }],
});

function permutations<T>(values: readonly T[]): T[][] {
  if (values.length <= 1) return [[...values]];
  return values.flatMap((value, index) =>
    permutations([...values.slice(0, index), ...values.slice(index + 1)])
      .map(rest => [value, ...rest]));
}

describe('dashboard pure projectors', () => {
  it('projects agent and frontier collections as keyed upsert/remove/move patches', () => {
    const previous = {
      agents: [
        { task_id: 'task-a', value: 1 },
        { task_id: 'task-b', value: 1 },
      ],
      active_agents: [{ task_id: 'task-a' }],
      frontier: [{ id: 'fi-a', value: 1 }, { id: 'fi-b', value: 1 }],
      warnings: { marker: 'old' },
    };
    const next = {
      agents: [
        { task_id: 'task-c', value: 1 },
        { task_id: 'task-b', value: 2 },
      ],
      active_agents: [{ task_id: 'task-c' }],
      frontier: [{ id: 'fi-b', value: 2 }, { id: 'fi-c', value: 1 }],
      warnings: { marker: 'new' },
    };

    expect(projectDashboardStatePatch(previous, next)).toEqual({
      state: { warnings: { marker: 'new' } },
      agents: {
        upsert: [
          { task_id: 'task-c', value: 1 },
          { task_id: 'task-b', value: 2 },
        ],
        remove: ['task-a'],
        moves: [{ id: 'task-c', index: 0 }],
        total: 2,
      },
      // active_agents is intentionally NOT emitted (the client reads agents/frontier only).
      frontier: {
        upsert: [{ id: 'fi-b', value: 2 }, { id: 'fi-c', value: 1 }],
        remove: ['fi-a'],
        moves: [{ id: 'fi-c', index: 1 }],
        total: 2,
      },
    });
  });

  it('expresses removed scalar state explicitly across JSON transport', () => {
    const patch = projectDashboardStatePatch(
      {
        agents: [], active_agents: [], frontier: [],
        current_phase: 'recon', persistence_recovery: { writable: false },
      },
      {
        agents: [], active_agents: [], frontier: [],
        current_phase: undefined,
      },
    );

    expect(JSON.parse(JSON.stringify(patch))).toEqual({
      unset: ['current_phase', 'persistence_recovery'],
    });
  });

  it('converges every five-record producer permutation through the shared client applier', () => {
    const previousAgents = ['a', 'b', 'c', 'd', 'e']
      .map((id, index) => ({ task_id: id, value: index }));
    for (const order of permutations(previousAgents)) {
      const nextAgents = order.map((item, index) => ({
        ...item,
        value: item.task_id === 'c' ? 100 + index : item.value,
      }));
      const patch = projectDashboardStatePatch(
        { agents: previousAgents, active_agents: [], frontier: [] },
        { agents: nextAgents, active_agents: [], frontier: [] },
      ).agents!;
      expect(applyIndexedCollectionPatch(previousAgents, patch, item => item.task_id))
        .toEqual(nextAgents);
    }
  });

  it('atomically converges mixed insertion, removal, value, and order changes', () => {
    const previous = [
      { task_id: 'a', value: 1 },
      { task_id: 'b', value: 1 },
      { task_id: 'c', value: 1 },
      { task_id: 'd', value: 1 },
      { task_id: 'e', value: 1 },
    ];
    const next = [
      { task_id: 'a', value: 2 },
      { task_id: 'c', value: 1 },
      { task_id: 'new', value: 1 },
      { task_id: 'e', value: 2 },
      { task_id: 'd', value: 1 },
    ];
    const patch = projectDashboardStatePatch(
      { agents: previous, active_agents: [], frontier: [] },
      { agents: next, active_agents: [], frontier: [] },
    ).agents!;
    expect(applyIndexedCollectionPatch(previous, patch, item => item.task_id)).toEqual(next);
  });

  it('aggregates parent progress and deduplicates child findings and agents', () => {
    const parent = campaign();
    const child = campaign({
      id: 'campaign-child',
      name: 'Child',
      parent_id: parent.id,
      items: ['fi-1'],
      progress: progress(1, 1),
      findings: ['finding-shared', 'finding-child'],
    });
    const projected = projectCampaignDtos({
      campaigns: [parent, child],
      selected: [parent],
      agents: [agent(), agent({ id: 'task-2', agent_id: 'agent-2', campaign_id: child.id, status: 'completed' })],
      parent_progress: new Map([[parent.id, progress(2, 1)]]),
      parent_status: new Map([[parent.id, 'active']]),
      campaign_noise: new Map([[parent.id, 0.1], [child.id, 0.2]]),
      opsec: { noise_budget_remaining: 0.7, recommended_approach: 'normal' },
      max_noise: 1,
    })[0];

    expect(projected.findings).toEqual(['finding-shared', 'finding-child']);
    expect(projected.findings_count).toBe(2);
    expect(projected.completion_pct).toBe(50);
    expect(projected.agent_count).toBe(2);
    expect(projected.running_agents).toBe(1);
    expect(projected.child_count).toBe(1);
    expect(projected.opsec.global_noise_spent).toBeCloseTo(0.3);
    expect(parent.findings).toEqual(['finding-shared']);
  });

  it('projects only changed IDs while retaining removals and replacing cold inventory', () => {
    const inputGraph = graph();
    const selection = {
      nodes: [inputGraph.nodes[0]],
      edges: [inputGraph.edges[0]],
      cold_nodes: inputGraph.cold_nodes,
      hidden_node_ids: [],
      hidden_edge_ids: [],
    };
    const projected = projectGraphDelta(
      { marker: 'state' },
      selection,
      {
        new_nodes: ['node-new'],
        updated_edges: ['edge-new'],
        removed_nodes: ['node-removed'],
        removed_edges: ['edge-removed'],
      },
      12,
    );

    expect(projected.delta.nodes.map(node => node.id)).toEqual(['node-new']);
    expect(projected.delta.edges.map(edge => edge.id)).toEqual(['edge-new']);
    expect(projected.delta.removed_nodes).toEqual(['node-removed']);
    expect(projected.delta.removed_edges).toEqual(['edge-removed']);
    expect(projected.delta.cold_nodes).toEqual(selection.cold_nodes);
    expect(projected.delta.cold_nodes).not.toBe(selection.cold_nodes);
  });

  it('turns final-state hidden graph records into removals', () => {
    const projected = projectGraphDelta(
      { marker: 'state' },
      {
        nodes: [],
        edges: [],
        hidden_node_ids: ['node-superseded'],
        hidden_edge_ids: ['edge-hidden'],
      },
      { updated_nodes: ['node-superseded'], updated_edges: ['edge-hidden'] },
      13,
    );

    expect(projected.delta).toMatchObject({
      nodes: [],
      edges: [],
      removed_nodes: ['node-superseded'],
      removed_edges: ['edge-hidden'],
    });
  });

  it('clones full snapshots so consumers cannot mutate engine-owned inputs', () => {
    const inputState = { nested: { value: 1 } };
    const inputGraph = graph();
    const runtimeBuild = {
      schema_version: 1,
      input_sha256: 'a'.repeat(64),
      runtime_pid: 123,
      runtime_started_at: '2026-07-17T00:00:00.000Z',
      runtime_instance_id: '11111111-1111-4111-8111-111111111111',
    };
    const snapshot = projectDashboardSnapshot(inputState, inputGraph, 3, runtimeBuild);

    snapshot.state.nested.value = 99;
    snapshot.graph.nodes[0].properties.label = 'Changed in UI';
    snapshot.graph.cold_nodes![0].label = 'Changed cold node';
    snapshot.runtime_build.input_sha256 = 'b'.repeat(64);

    expect(inputState.nested.value).toBe(1);
    expect(inputGraph.nodes[0].properties.label).toBe('New host');
    expect(inputGraph.cold_nodes![0].label).toBe('Cold host');
    expect(runtimeBuild.input_sha256).toBe('a'.repeat(64));
  });

  it('repairs untyped legacy planner dispatches in full-state recent activity', () => {
    const state = {
      agents: [],
      recent_activity: [{
        timestamp: '2026-07-16T00:00:00.000Z',
        description: 'Agent dispatched: planner-old for undefined',
      }],
    } as any;
    const projected = projectDashboardState({
      state,
      sessions: [],
      pending_actions: [],
      campaigns: [],
      history: [],
    });

    expect(projected.recent_activity[0].description)
      .toBe('Agent dispatched: planner-old as operator planner');
  });
});
