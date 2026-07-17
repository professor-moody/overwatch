import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EngagementConfig } from '../../types.js';
import { DashboardProjectionService } from '../dashboard-projection-service.js';
import { GraphEngine } from '../graph-engine.js';

const engines: GraphEngine[] = [];
const tempDirs: string[] = [];

function engineFixture(): GraphEngine {
  const dir = mkdtempSync(join(tmpdir(), 'overwatch-dashboard-projection-'));
  tempDirs.push(dir);
  const config: EngagementConfig = {
    id: 'projection-cache',
    name: 'Projection cache',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'test', max_noise: 1, enabled: false },
  };
  const engine = new GraphEngine(config, join(dir, 'state.json'));
  engines.push(engine);
  return engine;
}

afterEach(() => {
  for (const engine of engines.splice(0)) engine.dispose();
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('DashboardProjectionService', () => {
  it('reuses one full graph projection within a publication revision', () => {
    const engine = engineFixture();
    const service = new DashboardProjectionService(engine);
    const exportSpy = vi.spyOn(engine, 'exportGraph');

    expect(service.getFullGraph()).toBe(service.getFullGraph());
    expect(exportSpy).toHaveBeenCalledTimes(1);
  });

  it('invalidates for graph, state-derived projection, and cold inventory changes', () => {
    const engine = engineFixture();
    const service = new DashboardProjectionService(engine);
    const exportSpy = vi.spyOn(engine, 'exportGraph');
    let previous = service.getFullGraph();

    engine.logActionEvent({ description: 'state-only update', category: 'system' });
    engine.persist();
    let current = service.getFullGraph();
    expect(current).not.toBe(previous);
    previous = current;

    engine.addNode({
      id: 'host-1',
      type: 'host',
      label: '10.0.0.1',
      ip: '10.0.0.1',
      discovered_at: '2026-07-16T00:00:00.000Z',
      confidence: 1,
    });
    engine.persist({ new_nodes: ['host-1'] });
    current = service.getFullGraph();
    expect(current).not.toBe(previous);
    previous = current;

    (engine as any).ctx.coldStore.add({
      id: 'cold-1',
      type: 'host',
      label: '10.0.0.2',
      discovered_at: '2026-07-16T00:00:00.000Z',
      last_seen_at: '2026-07-16T00:00:00.000Z',
    });
    current = service.getFullGraph();
    expect(current).not.toBe(previous);
    expect(current.cold_nodes).toHaveLength(1);
    expect(exportSpy).toHaveBeenCalledTimes(4);
  });
});
