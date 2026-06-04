import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createServer } from 'net';
import { DashboardServer } from '../services/dashboard-server.js';
import { GraphEngine } from '../services/graph-engine.js';
import type { SessionManager } from '../services/session-manager.js';
import type { EngagementConfig } from '../types.js';

const supportsLocalListen = await new Promise<boolean>((resolve) => {
  const srv = createServer();
  srv.on('error', () => { srv.close(); resolve(false); });
  srv.listen(0, '127.0.0.1', () => { srv.close(); resolve(true); });
});

const tempDirs: string[] = [];

function makeConfig(id: string): EngagementConfig {
  return {
    id,
    name: 'dashboard state test',
    created_at: '2026-05-15T10:00:00Z',
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1, approval_timeout_ms: 300_000 },
  };
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe.skipIf(!supportsLocalListen)('dashboard state API', () => {
  it('hydrates pending actions, sessions, and enriched campaigns through /api/state', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'overwatch-dashboard-state-'));
    tempDirs.push(tempDir);
    const engine = new GraphEngine(makeConfig('test-dashboard-state'), join(tempDir, 'state.json'));
    const sessionManager = {
      list: () => [{
        id: '11111111-1111-4111-8111-111111111111',
        kind: 'pty',
        transport: 'pty',
        state: 'connected',
        title: 'operator shell',
        started_at: '2026-05-15T10:00:00Z',
        last_activity_at: '2026-05-15T10:00:00Z',
      }],
    } as unknown as SessionManager;
    const campaign = engine.createCampaign({
      name: 'Verify reachable credentials',
      strategy: 'credential_spray',
      item_ids: ['frontier-1', 'frontier-2'],
    });
    engine.updateCampaignProgress(campaign.id, 'frontier-1', 'success', 'finding-1');
    engine.registerAgent({
      id: 'task-1',
      agent_id: 'agent-1',
      assigned_at: '2026-05-15T10:01:00Z',
      status: 'running',
      campaign_id: campaign.id,
      frontier_item_id: 'frontier-2',
      subgraph_node_ids: [],
    });
    const queue = engine.getPendingActionQueue();
    queue.submit({
      action_id: 'act-dashboard-state',
      technique: 'credential_test',
      description: 'Validate captured token',
      opsec_context: {
        noise_budget_remaining: 1,
        global_noise_spent: 0,
        recommended_approach: 'normal',
        defensive_signals: [],
      },
      validation_result: 'valid',
      frontier_item_id: 'frontier-2',
    });

    const dashboard = new DashboardServer(engine, 0, '127.0.0.1', sessionManager);
    let startedDashboard = false;
    try {
      const started = await dashboard.start();
      expect(started.started).toBe(true);
      startedDashboard = true;
      const port = (dashboard as unknown as { port: number }).port;
      const response = await fetch(`http://127.0.0.1:${port}/api/state`);
      expect(response.status).toBe(200);
      const body = await response.json();

      expect(body.state.pending_actions).toHaveLength(1);
      expect(body.state.pending_actions[0]).toMatchObject({
        action_id: 'act-dashboard-state',
        status: 'pending',
        frontier_item_id: 'frontier-2',
      });
      expect(body.state.sessions).toHaveLength(1);
      expect(body.state.sessions[0]).toMatchObject({ id: '11111111-1111-4111-8111-111111111111', state: 'connected' });
      const hydratedCampaign = body.state.campaigns.find((candidate: { id?: string }) => candidate.id === campaign.id);
      expect(hydratedCampaign).toBeDefined();
      expect(hydratedCampaign).toMatchObject({
        id: campaign.id,
        agent_count: 1,
        agents_total: 1,
        findings_count: 1,
      });
      expect(hydratedCampaign.running_agents).toBe(hydratedCampaign.agents_active);
      const progress = hydratedCampaign.progress;
      const total = progress?.total ?? hydratedCampaign.items?.length ?? 0;
      const completed = progress?.completed ?? 0;
      expect(hydratedCampaign.completion_pct).toBe(total > 0 ? Math.round((completed / total) * 100) : 0);
    } finally {
      queue.deny('act-dashboard-state', 'test cleanup');
      queue.dispose();
      if (startedDashboard) await dashboard.stop();
    }
  });
});
