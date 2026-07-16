import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import { DispatchCommandService } from '../dispatch-command-service.js';
import { GraphEngine } from '../graph-engine.js';

function config(): EngagementConfig {
  return {
    id: 'dispatch-command-test',
    name: 'Dispatch command test',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

describe('DispatchCommandService canonical identity', () => {
  let directory: string;
  let engine: GraphEngine;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-dispatch-command-'));
    engine = new GraphEngine(config(), join(directory, 'state.json'));
    engine.addNode({
      id: 'host-dispatch',
      type: 'host',
      label: 'dispatch host',
      ip: '10.0.0.12',
      discovered_at: '2026-07-16T00:00:00.000Z',
      confidence: 1,
    });
  });

  afterEach(() => {
    engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  it('returns and replays task_id and agent_label with legacy aliases', () => {
    const service = new DispatchCommandService(engine);
    const metadata = {
      command_id: 'dispatch-canonical-command',
      idempotency_key: 'dispatch-canonical-retry',
      transport: 'dashboard' as const,
    };
    const input = {
      agent_label: 'planner-helper',
      target_node_ids: ['host-dispatch'],
      objective: 'Inspect the target',
    };
    const first = service.dispatch(input, metadata);
    const replay = service.dispatch(input, metadata);
    const task = first.result?.body.task as Record<string, unknown>;

    expect(task).toMatchObject({
      task_id: expect.any(String),
      agent_label: 'planner-helper',
      id: expect.any(String),
      agent_id: 'planner-helper',
    });
    expect(task.task_id).toBe(task.id);
    expect(replay).toMatchObject({
      replayed: true,
      result: first.result,
    });
    expect(engine.getTask(String(task.task_id))).toMatchObject(task);
  });

  it('returns and replays canonical identity for quick deploy', () => {
    const service = new DispatchCommandService(engine);
    const metadata = {
      command_id: 'quick-deploy-canonical-command',
      idempotency_key: 'quick-deploy-canonical-retry',
      transport: 'dashboard' as const,
    };
    const input = { target: '10.0.0.22' };
    const first = service.quickDeploy(input, metadata);
    const replay = service.quickDeploy(input, metadata);
    const task = first.result?.task as Record<string, unknown>;

    expect(task).toMatchObject({
      task_id: expect.any(String),
      agent_label: expect.stringMatching(/^quick-/),
      id: expect.any(String),
      agent_id: expect.stringMatching(/^quick-/),
    });
    expect(task.task_id).toBe(task.id);
    expect(task.agent_label).toBe(task.agent_id);
    expect(replay).toMatchObject({
      replayed: true,
      result: first.result,
    });
    expect(engine.getTask(String(task.task_id))).toMatchObject(task);
  });
});
