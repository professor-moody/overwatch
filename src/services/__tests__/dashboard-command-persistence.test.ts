import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';

function config(): EngagementConfig {
  return {
    id: 'durable-dashboard-command',
    name: 'Durable dashboard command',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, enabled: true },
  };
}

describe('dashboard command coordination persistence', () => {
  const dashboards: DashboardServer[] = [];
  const engines: GraphEngine[] = [];
  let directory = '';

  afterEach(async () => {
    for (const dashboard of dashboards.splice(0)) {
      await dashboard.stop().catch(() => {});
    }
    for (const engine of engines.splice(0)) engine.dispose();
    if (directory) rmSync(directory, { recursive: true, force: true });
  });

  async function open(statePath: string): Promise<{
    engine: GraphEngine;
    dashboard: DashboardServer;
    baseUrl: string;
  }> {
    const engine = new GraphEngine(config(), statePath);
    engines.push(engine);
    const dashboard = new DashboardServer(engine, 0, '127.0.0.1');
    dashboards.push(dashboard);
    const start = await dashboard.start();
    if (!start.started) throw new Error(start.error);
    return { engine, dashboard, baseUrl: dashboard.address };
  }

  async function close(engine: GraphEngine, dashboard: DashboardServer): Promise<void> {
    await dashboard.stop();
    dashboards.splice(dashboards.indexOf(dashboard), 1);
    engine.flushNow();
    engine.dispose();
    engines.splice(engines.indexOf(engine), 1);
  }

  it('confirms a preview after restart and returns the original outcome after another restart', async () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-dashboard-command-state-'));
    const statePath = join(directory, 'state.json');
    const first = await open(statePath);
    const previewResponse = await fetch(`${first.baseUrl}/api/commands`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: 'add scope 10.0.1.0/24' }),
    });
    expect(previewResponse.status).toBe(200);
    const preview = await previewResponse.json() as { plan_id?: string };
    expect(preview.plan_id).toBeDefined();
    await close(first.engine, first.dashboard);

    const second = await open(statePath);
    const confirmationResponse = await fetch(`${second.baseUrl}/api/commands`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: true, plan_id: preview.plan_id }),
    });
    expect(confirmationResponse.status).toBe(200);
    const confirmation = await confirmationResponse.json() as {
      executed: boolean;
      already_executed?: boolean;
      results: unknown[];
    };
    expect(confirmation).toMatchObject({
      executed: true,
      results: [expect.objectContaining({ ok: true })],
    });
    expect(second.engine.getConfig().scope.cidrs).toContain('10.0.1.0/24');
    await close(second.engine, second.dashboard);

    const third = await open(statePath);
    const duplicateResponse = await fetch(`${third.baseUrl}/api/commands`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: true, plan_id: preview.plan_id }),
    });
    expect(duplicateResponse.status).toBe(200);
    expect(await duplicateResponse.json()).toEqual({
      executed: true,
      already_executed: true,
      results: confirmation.results,
    });
  });
});
