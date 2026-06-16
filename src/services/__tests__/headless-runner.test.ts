import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import { existsSync, rmSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import { ProcessTracker } from '../process-tracker.js';
import { TaskExecutionService } from '../task-execution-service.js';
import type { EngagementConfig, AgentTask } from '../../types.js';

const TEST_STATE_FILE = './state-test-headless-runner.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-headless',
    name: 'headless test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

// Minimal stand-in for a spawned ChildProcess.
class FakeChild extends EventEmitter {
  pid: number;
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  signals: string[] = [];
  constructor(pid: number) { super(); this.pid = pid; }
  kill(sig: NodeJS.Signals = 'SIGTERM'): boolean { this.signals.push(sig); return true; }
  simulateExit(code: number | null, signal: NodeJS.Signals | null = null): void {
    this.emit('exit', code, signal);
  }
}

function headlessTask(overrides: Partial<AgentTask> = {}): AgentTask {
  return {
    id: overrides.id ?? `task-${Math.random().toString(36).slice(2, 10)}`,
    agent_id: overrides.agent_id ?? 'sub-agent',
    assigned_at: new Date().toISOString(),
    status: 'running',
    subgraph_node_ids: [],
    backend: 'headless_mcp',
    frontier_item_id: overrides.frontier_item_id,
  };
}

const settle = () => new Promise(r => setTimeout(r, 5));

describe('Headless runner mechanics (injected spawn)', () => {
  let engine: GraphEngine;
  let svc: TaskExecutionService;
  let spawned: FakeChild[];
  let logDir: string;
  let nextPid: number;

  function makeService(opts: { maxConcurrentHeadless?: number } = {}) {
    return new TaskExecutionService(engine, new ProcessTracker(), {
      maxConcurrentHeadless: opts.maxConcurrentHeadless,
      headless: {
        logDir,
        spawnFn: () => {
          const child = new FakeChild(4_000_000_000 + (nextPid++));
          spawned.push(child);
          return child as any;
        },
      },
    });
  }

  beforeEach(() => {
    try { if (existsSync(TEST_STATE_FILE)) rmSync(TEST_STATE_FILE); } catch { /* ignore */ }
    logDir = mkdtempSync(join(tmpdir(), 'ow-headless-log-'));
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    spawned = [];
    nextPid = 1;
  });

  afterEach(() => {
    svc?.stop();
    try { if (existsSync(TEST_STATE_FILE)) rmSync(TEST_STATE_FILE); } catch { /* ignore */ }
    try { rmSync(logDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('does NOT launch headless tasks until an HTTP endpoint is set', async () => {
    svc = makeService();
    svc.start();
    engine.registerAgent(headlessTask({ id: 'h-noendpoint' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(0);
    expect(engine.getTask('h-noendpoint')?.status).toBe('running'); // deferred
  });

  it('launches a headless process once an endpoint is available', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-launch' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);
    expect(spawned).toHaveLength(1);
  });

  it('reconciles to interrupted when the child exits without closing the task', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-exit' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);

    spawned[0].simulateExit(0);
    await settle();
    // Process gone, and the still-running task is marked interrupted (lease released).
    expect(svc.activeHeadlessCount()).toBe(0);
    expect(engine.getTask('h-exit')?.status).toBe('interrupted');
  });

  it('cancelHeadless kills the process (SIGTERM) and marks the task interrupted', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-cancel' }));
    await settle();

    const killed = svc.cancelHeadless('h-cancel', 'operator cancel');
    expect(killed).toBe(true);
    expect(spawned[0].signals).toContain('SIGTERM');
    expect(engine.getTask('h-cancel')?.status).toBe('interrupted');
  });

  it('enforces the max-concurrent-headless cap and launches the next when a slot frees', async () => {
    svc = makeService({ maxConcurrentHeadless: 1 });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });

    engine.registerAgent(headlessTask({ id: 'h-cap-1' }));
    engine.registerAgent(headlessTask({ id: 'h-cap-2' }));
    await settle();

    // Only one launched (cap = 1).
    expect(svc.activeHeadlessCount()).toBe(1);
    expect(spawned).toHaveLength(1);

    // First finishes → its exit cascades a drain that launches the second.
    spawned[0].simulateExit(0);
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);
    expect(spawned).toHaveLength(2);
  });

  it('marks the task failed when spawn throws', async () => {
    svc = new TaskExecutionService(engine, new ProcessTracker(), {
      headless: {
        logDir,
        spawnFn: () => { throw new Error('ENOENT: claude not found'); },
      },
    });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-spawnfail' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(0);
    expect(engine.getTask('h-spawnfail')?.status).toBe('failed');
  });

  it('killAll on stop() terminates live headless children', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-shutdown' }));
    await settle();
    const child = spawned[0];
    svc.stop();
    expect(child.signals).toContain('SIGTERM');
  });
});
