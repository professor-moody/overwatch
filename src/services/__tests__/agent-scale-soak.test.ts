import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { afterEach, describe, expect, it } from 'vitest';
import { seedAgentScaleFixture } from '../../test-support/agent-scale-fixture.js';
import type { EngagementConfig } from '../../types.js';
import { AgentWorkCommandService } from '../agent-work-command-service.js';
import { projectAgentDtos } from '../dashboard-agent-projector.js';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal } from '../mutation-journal.js';

const roots: string[] = [];
const engines: GraphEngine[] = [];

function openScaleEngine(size: number): {
  engine: GraphEngine;
  stateFile: string;
  config: EngagementConfig;
} {
  const root = mkdtempSync(join(tmpdir(), `overwatch-agent-scale-${size}-`));
  roots.push(root);
  const config: EngagementConfig = {
    id: `agent-scale-${size}`,
    name: `Agent scale ${size}`,
    created_at: '2026-07-17T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  };
  const stateFile = join(root, 'state.json');
  const engine = new GraphEngine(config, stateFile);
  engines.push(engine);
  return { engine, stateFile, config };
}

function disposeTracked(engine: GraphEngine): void {
  engine.dispose();
  const index = engines.indexOf(engine);
  if (index >= 0) engines.splice(index, 1);
}

function journalBytes(stateFile: string): number {
  const path = MutationJournal.pathForState(stateFile);
  return existsSync(path) ? readFileSync(path).length : 0;
}

function median(samples: number[]): number {
  return [...samples].sort((left, right) => left - right)[Math.floor(samples.length / 2)]!;
}

function measured(operation: () => void): number {
  operation();
  const samples: number[] = [];
  for (let iteration = 0; iteration < 5; iteration++) {
    const started = performance.now();
    operation();
    samples.push(performance.now() - started);
  }
  return median(samples);
}

afterEach(() => {
  for (const engine of engines.splice(0)) engine.dispose();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe.sequential('agent coordination scale and soak gates', () => {
  it('keeps one durable heartbeat independent of a 1k, 10k, or 50k roster', () => {
    const elapsed: Record<number, number> = {};
    for (const size of [1_000, 10_000, 50_000]) {
      const { engine, stateFile, config } = openScaleEngine(size);
      const fixture = seedAgentScaleFixture(engine, size, {
        running_leases: true,
        lease_task_status: 'pending',
      });
      // Direct seeding is benchmark setup, but the operation under test must
      // have a real trusted base so its WAL tail is restart-replayable.
      engine.persistImmediate();
      const beforeBytes = journalBytes(stateFile);
      const started = performance.now();
      expect(engine.agentHeartbeat(
        fixture.target_task_id,
        '2026-07-17T00:01:00.000Z',
        { silent: true },
      )).toBe(true);
      elapsed[size] = performance.now() - started;
      const walGrowth = journalBytes(stateFile) - beforeBytes;

      expect(walGrowth).toBeLessThan(64 * 1_024);
      expect(engine.getTask(fixture.target_task_id)?.heartbeat_at)
        .toBe('2026-07-17T00:01:00.000Z');
      expect(engine.getActiveFrontierLeases('2026-07-17T00:01:01.000Z')
        .find(lease => lease.frontier_item_id === fixture.target_frontier_item_id))
        .toMatchObject({ task_id: fixture.target_task_id });

      disposeTracked(engine);
      const reopened = new GraphEngine(config, stateFile);
      engines.push(reopened);
      expect(reopened.getTask(fixture.target_task_id)).toMatchObject({
        status: 'pending',
        heartbeat_at: '2026-07-17T00:01:00.000Z',
      });
      expect(reopened.getActiveFrontierLeases('2026-07-17T00:01:01.000Z')
        .find(lease => lease.frontier_item_id === fixture.target_frontier_item_id))
        .toMatchObject({ task_id: fixture.target_task_id });
      expect(reopened.getPersistenceRecoveryStatus()).toMatchObject({
        complete: true,
        writable: true,
      });
    }
    expect(elapsed[50_000]).toBeLessThan(250);
    expect(elapsed[50_000]).toBeLessThan(elapsed[1_000] * 5 + 100);
  }, 60_000);

  it('keeps a no-op 50k-task watchdog cycle read-only and below its budget', () => {
    const { engine, stateFile } = openScaleEngine(50_000);
    seedAgentScaleFixture(engine, 50_000, { running_leases: true });
    const beforeBytes = journalBytes(stateFile);
    const started = performance.now();
    expect(engine.reapStaleAgents('2026-07-17T00:01:00.000Z')).toBe(0);
    expect(engine.reapExpiredFrontierLeases('2026-07-17T00:01:00.000Z')).toEqual([]);
    const elapsed = performance.now() - started;

    expect(elapsed).toBeLessThan(250);
    expect(journalBytes(stateFile)).toBe(beforeBytes);
  }, 30_000);

  it('bounds lineage, duplicate inspection, and DTO projection at 50k tasks', () => {
    const { engine } = openScaleEngine(50_000);
    const fixture = seedAgentScaleFixture(engine, 50_000, { successor_count: 10 });
    const tasks = engine.getAgentTasks();

    const successorsMs = measured(() => {
      expect(engine.getAgentWorkSuccessors(fixture.source_task_id, 'handoff')).toHaveLength(10);
    });
    const dismissalMs = measured(() => {
      expect(engine.getAgentWorkDismissalBlocker(fixture.target_task_id)).toBeNull();
    });
    const duplicatesMs = measured(() => {
      expect(new AgentWorkCommandService(engine).findDuplicates().total).toBe(0);
    });
    const projectionMs = measured(() => {
      expect(projectAgentDtos(tasks, [], [], Date.parse('2026-07-17T00:02:00.000Z')))
        .toHaveLength(50_000);
    });

    expect(successorsMs).toBeLessThan(250);
    expect(dismissalMs).toBeLessThan(250);
    expect(duplicatesMs).toBeLessThan(1_000);
    expect(projectionMs).toBeLessThan(2_000);
  }, 30_000);

});
