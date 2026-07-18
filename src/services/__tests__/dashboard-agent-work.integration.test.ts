import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AgentDuplicatesResponseSchema,
  AgentHandoffResponseSchema,
  AgentMergeResponseSchema,
  AgentSplitResponseSchema,
} from '../../contracts/dashboard-v1.js';
import type { AgentTask, EngagementConfig } from '../../types.js';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';

function config(): EngagementConfig {
  return {
    id: 'agent-work-http',
    name: 'Agent work HTTP integration',
    created_at: '2026-07-18T00:00:00.000Z',
    scope: { cidrs: ['10.88.0.0/16'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'test', max_noise: 1 },
  };
}

function completedTask(
  id: string,
  nodes: string[],
  overrides: Partial<AgentTask> = {},
): AgentTask {
  return {
    id,
    task_id: id,
    agent_id: `agent-${id}`,
    agent_label: `agent-${id}`,
    assigned_at: '2026-07-18T00:00:00.000Z',
    completed_at: '2026-07-18T00:05:00.000Z',
    status: 'completed',
    subgraph_node_ids: nodes,
    archetype: 'default',
    role: 'default',
    backend: 'headless_mcp',
    objective: 'Assess the assigned scope.',
    ...overrides,
  };
}

describe('dashboard agent-work HTTP boundary', () => {
  let directory: string;
  let engine: GraphEngine;
  let dashboard: DashboardServer;

  beforeEach(async () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-agent-work-http-'));
    engine = new GraphEngine(config(), join(directory, 'state.json'));
    dashboard = new DashboardServer(engine, 0);
    const started = await dashboard.start();
    expect(started.started).toBe(true);
  });

  afterEach(async () => {
    await dashboard.stop();
    engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  async function post(path: string, body: unknown, key = `test-${path}`): Promise<Response> {
    return fetch(`${dashboard.address}${path}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': key,
      },
      body: JSON.stringify(body),
    });
  }

  it('serves handoff, split, duplicate discovery, and exact merge through one contract registry', async () => {
    expect(engine.registerAgent(completedTask('handoff-source', ['handoff-a'])).ok).toBe(true);
    const handoffResponse = await post('/api/agents/handoff-source/handoff', {
      summary: 'Continue the source assessment.',
      archetype: 'default',
      objective: 'Continue the assigned assessment.',
    });
    expect(handoffResponse.status).toBe(200);
    const handoff = AgentHandoffResponseSchema.parse(await handoffResponse.json());
    expect(handoff.created_tasks).toHaveLength(1);
    expect(handoff.created_tasks[0]?.work.relation).toMatchObject({
      kind: 'handoff',
      source_task_id: 'handoff-source',
    });

    expect(engine.registerAgent(completedTask('split-source', ['split-a', 'split-b'])).ok).toBe(true);
    const splitResponse = await post('/api/agents/split-source/split', {
      summary: 'Partition the remaining node work.',
      children: [
        { archetype: 'default', objective: 'Assess split A.', target_node_ids: ['split-a'] },
        { archetype: 'default', objective: 'Assess split B.', target_node_ids: ['split-b'] },
      ],
    });
    expect(splitResponse.status).toBe(200);
    const split = AgentSplitResponseSchema.parse(await splitResponse.json());
    expect(split.created_tasks).toHaveLength(2);
    expect(split.created_tasks.flatMap(task => task.subgraph_node_ids).sort()).toEqual(['split-a', 'split-b']);

    const duplicateA = completedTask('duplicate-a', ['duplicate-node']);
    const duplicateB = completedTask('duplicate-b', ['duplicate-node']);
    expect(engine.registerAgent(duplicateA).ok).toBe(true);
    expect(engine.registerAgent(duplicateB).ok).toBe(true);
    const duplicatesResponse = await fetch(`${dashboard.address}/api/agents/duplicates`);
    expect(duplicatesResponse.status).toBe(200);
    const duplicates = AgentDuplicatesResponseSchema.parse(await duplicatesResponse.json());
    const group = duplicates.groups.find(item =>
      item.candidate_task_ids.includes('duplicate-a')
      && item.candidate_task_ids.includes('duplicate-b'));
    expect(group).toBeDefined();

    const canonical = group!.canonical_task_id;
    const duplicate = group!.candidate_task_ids.find(taskId => taskId !== canonical)!;
    const mergeResponse = await post(`/api/agents/${canonical}/merge`, {
      summary: 'Consolidate the exact duplicate tasks.',
      duplicate_task_ids: [duplicate],
    });
    expect(mergeResponse.status).toBe(200);
    const merge = AgentMergeResponseSchema.parse(await mergeResponse.json());
    expect(merge.canonical_task_id).toBe(canonical);
    expect(engine.getTask(duplicate)?.work?.merged_into_task_id).toBe(canonical);
  });

  it('enforces strict input, lifecycle, persistence, replay, and command-conflict boundaries', async () => {
    const body = {
      summary: 'Continue the source assessment.',
      archetype: 'default',
      objective: 'Continue the assigned assessment.',
    };
    expect((await post('/api/agents/missing/handoff', body, 'missing-task')).status).toBe(404);

    expect(engine.registerAgent(completedTask('strict-source', [])).ok).toBe(true);
    expect((await post('/api/agents/strict-source/handoff', {
      ...body,
      unexpected: true,
    }, 'strict-invalid')).status).toBe(400);

    expect(engine.registerAgent(completedTask('live-source', [], {
      status: 'running',
      completed_at: undefined,
    })).ok).toBe(true);
    expect((await post('/api/agents/live-source/handoff', body, 'live-conflict')).status).toBe(409);

    expect(engine.registerAgent(completedTask('replay-source', [])).ok).toBe(true);
    const first = await post('/api/agents/replay-source/handoff', body, 'stable-replay-key');
    const replay = await post('/api/agents/replay-source/handoff', body, 'stable-replay-key');
    expect(first.status).toBe(200);
    expect(replay.status).toBe(200);
    expect(replay.headers.get('x-overwatch-command-replayed')).toBe('true');
    expect(engine.getAgentWorkSuccessors('replay-source', 'handoff')).toHaveLength(1);

    const conflict = await post('/api/agents/replay-source/handoff', {
      ...body,
      summary: 'A different command body under the same identity.',
    }, 'stable-replay-key');
    expect(conflict.status).toBe(409);
    expect(await conflict.json()).toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' });

    expect(engine.registerAgent(completedTask('read-only-source', [])).ok).toBe(true);
    const writable = vi.spyOn(engine, 'isPersistenceWritable').mockReturnValue(false);
    try {
      const readOnly = await post('/api/agents/read-only-source/handoff', body, 'read-only-key');
      expect(readOnly.status).toBe(503);
      expect(await readOnly.json()).toMatchObject({ code: 'PERSISTENCE_READ_ONLY' });
    } finally {
      writable.mockRestore();
    }
  });

  it('maps a bounded dispatch-cap refusal to the contracted 429 response', async () => {
    engine.addNode({
      id: 'host-cap',
      type: 'host',
      label: '10.88.0.10',
      ip: '10.88.0.10',
      discovered_at: '2026-07-18T00:00:00.000Z',
      confidence: 1,
    });
    expect(engine.registerAgent(completedTask('cap-source', ['host-cap'])).ok).toBe(true);
    engine.updateConfig({
      operator_policy: { version: 1, dispatch_limits: { max_per_target: 1 } },
    });
    expect(engine.registerAgent(completedTask('cap-live', ['host-cap'], {
      status: 'running',
      completed_at: undefined,
      archetype: 'web_tester',
      objective: 'Existing application work.',
    })).ok).toBe(true);
    const response = await post('/api/agents/cap-source/handoff', {
      summary: 'Continue the application work.',
      archetype: 'web_tester',
      objective: 'Continue the application work.',
    }, 'dispatch-cap-key');
    expect(response.status).toBe(429);
    expect(await response.json()).toMatchObject({ code: 'DISPATCH_CAP_EXCEEDED' });
    expect(engine.getAgentWorkSuccessors('cap-source', 'handoff')).toHaveLength(0);
  });
});
