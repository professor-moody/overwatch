import type { GraphUpdateDetail, OverwatchGraph } from '../services/engine-context.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { EdgeProperties, NodeProperties } from '../types.js';

const FIXTURE_TIME = '2026-07-16T00:00:00.000Z';

export interface DashboardScaleFixture {
  detail: GraphUpdateDetail;
  node_ids: string[];
  edge_ids: string[];
}

/** Seed a deterministic scale graph without invoking durable mutation paths.
 * This is test/benchmark setup only; production writes remain transaction-only. */
export function seedDashboardScaleFixture(
  engine: GraphEngine,
  nodeCount: number,
  changedCount = 5,
): DashboardScaleFixture {
  const graph = (engine as unknown as { ctx: { graph: OverwatchGraph } }).ctx.graph;
  for (let index = 0; index < nodeCount; index++) {
    const id = `scale-node-${index}`;
    graph.addNode(id, {
      id,
      type: 'host',
      label: `Scale host ${index}`,
      ip: `10.${Math.floor(index / 65_536) % 256}.${Math.floor(index / 256) % 256}.${index % 256}`,
      alive: index % 3 === 0,
      confidence: 1,
      discovered_at: FIXTURE_TIME,
      last_seen_at: FIXTURE_TIME,
    } satisfies NodeProperties);
  }
  for (let index = 0; index < nodeCount; index++) {
    const id = `scale-edge-${index}`;
    graph.addEdgeWithKey(
      id,
      `scale-node-${index}`,
      `scale-node-${(index + 1) % nodeCount}`,
      {
        type: 'REACHABLE',
        confidence: 1,
        discovered_at: FIXTURE_TIME,
      } satisfies EdgeProperties,
    );
  }
  const boundedChangedCount = Math.min(changedCount, nodeCount);
  const nodeIds = Array.from({ length: boundedChangedCount }, (_, index) => `scale-node-${index * 2}`);
  const edgeIds = Array.from({ length: boundedChangedCount }, (_, index) => `scale-edge-${index * 2}`);
  return {
    node_ids: nodeIds,
    edge_ids: edgeIds,
    detail: {
      updated_nodes: nodeIds,
      updated_edges: edgeIds,
    },
  };
}
