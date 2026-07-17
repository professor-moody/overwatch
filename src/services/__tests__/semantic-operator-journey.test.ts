import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AgentTask, EngagementConfig } from '../../types.js';
import { DashboardServer } from '../dashboard-server.js';
import { DispatchCommandService } from '../dispatch-command-service.js';
import { GraphEngine } from '../graph-engine.js';

function config(): EngagementConfig {
  return {
    id: 'semantic-operator-journey',
    name: 'Semantic operator journey',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.77.0.0/24'], domains: [], exclusions: [] },
    objectives: [{
      id: 'objective-admin-host',
      description: 'Gain administrative access to the objective host',
      target_node_type: 'host',
      target_criteria: { ip: '10.77.0.20' },
      achievement_edge_types: ['ADMIN_TO'],
      achieved: false,
    }],
    opsec: { name: 'pentest', enabled: false, max_noise: 1 },
  };
}

describe('semantic operator delivery journey', () => {
  let directory: string | undefined;
  let engine: GraphEngine | undefined;
  let dashboard: DashboardServer | undefined;

  afterEach(async () => {
    await dashboard?.stop().catch(() => undefined);
    engine?.dispose();
    if (directory) rmSync(directory, { recursive: true, force: true });
    dashboard = undefined;
    engine = undefined;
    directory = undefined;
  });

  it('carries dispatch attribution through finding, objective, report, and dashboard projections', async () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-semantic-journey-'));
    engine = new GraphEngine(config(), join(directory, 'state.json'));
    engine.addNode({
      id: 'journey-operator',
      type: 'user',
      label: 'Journey Operator',
      username: 'operator',
      discovered_at: '2026-07-16T00:00:01.000Z',
      confidence: 1,
    });
    engine.addNode({
      id: 'journey-objective-host',
      type: 'host',
      label: 'Journey Objective Host',
      ip: '10.77.0.20',
      alive: true,
      discovered_at: '2026-07-16T00:00:01.000Z',
      confidence: 1,
    });

    const candidate = engine.getState().frontier.find(item =>
      item.node_id === 'journey-objective-host');
    expect(candidate).toBeDefined();
    const dispatched = new DispatchCommandService(engine).dispatch({
      agent_label: 'journey-agent',
      frontier_item_id: candidate!.id,
      target_node_ids: ['journey-objective-host'],
      objective: 'Confirm administrative access',
    }, {
      command_id: 'journey-dispatch-command',
      idempotency_key: 'journey-dispatch-key',
      transport: 'dashboard',
    });
    const task = dispatched.result?.body.task as AgentTask | undefined;
    expect(task).toMatchObject({
      task_id: expect.any(String),
      agent_label: 'journey-agent',
      frontier_item_id: candidate!.id,
    });

    engine.ingestFinding({
      id: 'journey-admin-finding',
      agent_id: 'journey-agent',
      action_id: 'journey-admin-action',
      frontier_item_id: candidate!.id,
      tool_name: 'semantic-journey',
      timestamp: '2026-07-16T00:00:02.000Z',
      target_node_ids: ['journey-objective-host'],
      nodes: [],
      edges: [{
        source: 'journey-operator',
        target: 'journey-objective-host',
        properties: {
          type: 'ADMIN_TO',
          confidence: 1,
          discovered_at: '2026-07-16T00:00:02.000Z',
        },
      }],
      raw_output: 'Confirmed administrative access to Journey Objective Host.',
    });

    expect(engine.getConfig().objectives[0]).toMatchObject({
      id: 'objective-admin-host',
      achieved: true,
    });
    expect(engine.getFullHistory()).toContainEqual(expect.objectContaining({
      event_type: 'objective_achieved',
    }));

    dashboard = new DashboardServer(engine, 0, '127.0.0.1');
    const started = await dashboard.start();
    expect(started.started).toBe(true);
    const base = dashboard.address;

    const stateResponse = await fetch(`${base}/api/state`);
    expect(stateResponse.status).toBe(200);
    const projected = await stateResponse.json() as {
      state: { agents: Array<{ task_id: string; agent_label: string; findings_count: number }> };
    };
    expect(projected.state.agents).toContainEqual(expect.objectContaining({
      task_id: task!.task_id,
      agent_label: 'journey-agent',
      findings_count: 1,
    }));

    const findingsResponse = await fetch(`${base}/api/findings`);
    expect(findingsResponse.status).toBe(200);
    const findings = await findingsResponse.json() as { findings: Array<{ affected_assets: string[] }> };
    expect(findings.findings.length).toBeGreaterThan(0);
    expect(findings.findings.some(finding => finding.affected_assets.some(asset =>
      asset === 'journey-objective-host'
      || asset === '10.77.0.20'
      || asset === 'Journey Objective Host'))).toBe(true);

    const reportResponse = await fetch(`${base}/api/reports/render`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format: 'markdown', include_attack_paths: true }),
    });
    expect(reportResponse.status).toBe(201);
    const report = await reportResponse.json() as { report: { id: string } };
    const download = await fetch(`${base}/api/reports/${report.report.id}`);
    expect(download.status).toBe(200);
    const markdown = await download.text();
    expect(markdown).toContain('# Penetration Test Report');
    expect(markdown).toContain('Gain administrative access to the objective host');
    expect(markdown).toContain('Journey Objective Host');
  });
});
