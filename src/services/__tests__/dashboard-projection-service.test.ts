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
  it('caches the base topology within a revision (one export) but re-labels trust fresh per call', () => {
    const engine = engineFixture();
    const service = new DashboardProjectionService(engine);
    const exportSpy = vi.spyOn(engine, 'exportGraph');

    const a = service.getFullGraph();
    const b = service.getFullGraph();
    // The expensive base export runs once per revision (cached)…
    expect(exportSpy).toHaveBeenCalledTimes(1);
    // …but each call returns a freshly trust-labelled graph (a new object), so time-sensitive
    // claim_state is never frozen. Same content within a revision (no time passed).
    expect(b).not.toBe(a);
    expect(b).toEqual(a);
  });

  it('re-derives claim_state against the clock on each read — an expired promotion converges without a revision change', () => {
    const engine = engineFixture();
    const service = new DashboardProjectionService(engine);
    engine.ingestFinding({
      id: 'f', agent_id: 'nxc', action_id: 'a', timestamp: '2026-07-16T00:00:00.000Z',
      target_node_ids: ['u', 'h'],
      nodes: [
        { id: 'u', type: 'user', label: 'u' },
        { id: 'h', type: 'host', label: '10.0.0.1', ip: '10.0.0.1' },
      ],
      edges: [{ source: 'u', target: 'h', properties: { type: 'ADMIN_TO', confidence: 1.0, discovered_at: '2026-07-16T00:00:00.000Z' } }],
    } as never);
    const edgeId = engine.exportGraph().edges.find(e => e.properties.type === 'ADMIN_TO')!.id!;
    // Validated, but only until a fixed instant.
    engine.promoteClaim({ edge_id: edgeId, state: 'validated', reason: 'valid for now', by_kind: 'operator', valid_until: '2026-07-16T01:00:00.000Z' });

    const claimStateAt = (nowIso: string): string | undefined =>
      (engine as any).ctx.withClock(nowIso, () => service.getFullGraph())
        .edges.find((e: any) => e.id === edgeId)?.properties.claim_state;

    // Before the window elapses — validated. This ALSO primes the cache.
    expect(claimStateAt('2026-07-16T00:30:00.000Z')).toBe('validated');
    // After it elapses, with NO revision change — the projection must now read stale (the old
    // revision-cached sourceTrust export would have frozen 'validated').
    expect(claimStateAt('2026-07-16T09:00:00.000Z')).toBe('stale');
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
