import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { GraphDeltaDtoSchema, RawGraphDtoSchema } from '../../contracts/dashboard-v1.js';
import { seedDashboardScaleFixture } from '../../test-support/dashboard-scale-fixture.js';
import type { EngagementConfig } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import { projectGraphDelta } from '../dashboard-projectors.js';

const roots: string[] = [];
const engines: GraphEngine[] = [];

function openScaleEngine(size: number): GraphEngine {
  const root = mkdtempSync(join(tmpdir(), `overwatch-dashboard-scale-${size}-`));
  roots.push(root);
  const config: EngagementConfig = {
    id: `dashboard-scale-${size}`,
    name: `Dashboard scale ${size}`,
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  };
  const engine = new GraphEngine(config, join(root, 'state.json'));
  engines.push(engine);
  return engine;
}

function median(values: number[]): number {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)];
}

afterEach(() => {
  for (const engine of engines.splice(0)) engine.dispose();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe.sequential('dashboard projection performance', () => {
  it('keeps an ordinary ten-item delta proportional to changed IDs at 1k, 10k, and 50k nodes', () => {
    const medians: Record<number, number> = {};
    for (const size of [1_000, 10_000, 50_000]) {
      const engine = openScaleEngine(size);
      const fixture = seedDashboardScaleFixture(engine, size);
      const fullExport = vi.spyOn(engine, 'exportGraph');
      const samples: number[] = [];
      for (let iteration = 0; iteration < 9; iteration++) {
        const started = performance.now();
        const selection = engine.exportGraphSelection({
          node_ids: fixture.node_ids,
          edge_ids: fixture.edge_ids,
          includeIncidentEdges: false,
          includeDerivedCommunities: false,
        });
        const projected = projectGraphDelta({}, selection, fixture.detail, 0);
        GraphDeltaDtoSchema.parse(projected.delta);
        JSON.stringify(projected.delta);
        const elapsed = performance.now() - started;
        if (iteration >= 2) samples.push(elapsed);
      }
      medians[size] = median(samples);
      expect(fullExport).not.toHaveBeenCalled();
    }

    expect(medians[50_000]).toBeLessThan(100);
    expect(medians[50_000]).toBeLessThan(medians[1_000] * 20 + 20);
  }, 30_000);

  it('projects, validates, and serializes an initial 50k-node graph within five seconds', () => {
    const engine = openScaleEngine(50_000);
    seedDashboardScaleFixture(engine, 50_000);

    const started = performance.now();
    const state = engine.getState();
    const graph = engine.exportGraph({ includeDerivedCommunities: false });
    RawGraphDtoSchema.parse(graph);
    JSON.stringify({ state, graph });
    const elapsed = performance.now() - started;

    expect(graph.nodes).toHaveLength(50_000);
    expect(graph.edges).toHaveLength(50_000);
    expect(state.graph_summary.total_nodes).toBe(50_000);
    expect(elapsed).toBeLessThan(5_000);
  }, 30_000);

  it('keeps the changed-ID projector free of full graph traversals', () => {
    const source = readFileSync(new URL('../graph-engine.ts', import.meta.url), 'utf8');
    const start = source.indexOf('  exportGraphSelection(options:');
    const end = source.indexOf('\n  getColdInventoryRevision()', start);
    const method = source.slice(start, end);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    expect(method).not.toContain('exportGraph(');
    expect(method).not.toContain('forEachNode(');
    expect(method).not.toContain('forEachEdge(');
  });
});
