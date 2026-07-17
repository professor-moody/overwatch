import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { GraphDeltaDtoSchema, RawGraphDtoSchema } from '../src/contracts/dashboard-v1.js';
import { GraphEngine } from '../src/services/graph-engine.js';
import { projectGraphDelta } from '../src/services/dashboard-projectors.js';
import { seedDashboardScaleFixture } from '../src/test-support/dashboard-scale-fixture.js';
import type { EngagementConfig } from '../src/types.js';

function median(values: number[]): number {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)];
}

const results: Array<Record<string, number>> = [];
for (const size of [1_000, 10_000, 50_000]) {
  const root = mkdtempSync(join(tmpdir(), `overwatch-dashboard-benchmark-${size}-`));
  const config: EngagementConfig = {
    id: `dashboard-benchmark-${size}`,
    name: `Dashboard benchmark ${size}`,
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  };
  const engine = new GraphEngine(config, join(root, 'state.json'));
  try {
    const fixture = seedDashboardScaleFixture(engine, size);
    const fullStarted = performance.now();
    const full = engine.exportGraph({ includeDerivedCommunities: false });
    RawGraphDtoSchema.parse(full);
    JSON.stringify(full);
    const fullMs = performance.now() - fullStarted;

    const deltaSamples: number[] = [];
    for (let iteration = 0; iteration < 9; iteration++) {
      const started = performance.now();
      const selection = engine.exportGraphSelection({
        node_ids: fixture.node_ids,
        edge_ids: fixture.edge_ids,
        includeDerivedCommunities: false,
      });
      const delta = projectGraphDelta({}, selection, fixture.detail, 0).delta;
      GraphDeltaDtoSchema.parse(delta);
      JSON.stringify(delta);
      if (iteration >= 2) deltaSamples.push(performance.now() - started);
    }
    results.push({
      nodes: size,
      edges: size,
      full_projection_ms: Number(fullMs.toFixed(2)),
      ten_item_delta_median_ms: Number(median(deltaSamples).toFixed(2)),
    });
  } finally {
    engine.dispose();
    rmSync(root, { recursive: true, force: true });
  }
}

console.log(JSON.stringify({ results }, null, 2));
