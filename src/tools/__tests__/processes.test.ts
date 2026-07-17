import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, readdirSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine as BaseGraphEngine } from '../../services/graph-engine.js';
import { ProcessTracker } from '../../services/process-tracker.js';
import { registerProcessTools } from '../processes.js';
import type { EngagementConfig } from '../../types.js';
import { cleanupTestPersistence } from '../../__tests__/helpers/cleanup-test-persistence.js';
import { createTestSandbox } from '../../test-support/test-sandbox.js';

const sandbox = createTestSandbox('process-tools');
const TEST_STATE_FILE = sandbox.path('state-test-process-tools.json');
const engines = new Set<BaseGraphEngine>();

class GraphEngine extends BaseGraphEngine {
  constructor(config: EngagementConfig, stateFilePath?: string, configFilePath?: string) {
    super(config, stateFilePath, configFilePath);
    engines.add(this);
  }
}

function makeConfig(): EngagementConfig {
  return {
    id: 'test-process-tools',
    name: 'Process Tool Test Engagement',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/30'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  for (const engine of engines) engine.dispose();
  engines.clear();
  cleanupTestPersistence(TEST_STATE_FILE);
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}

  try {
    for (const entry of readdirSync('.')) {
      if (entry.startsWith('state-test-process-tools.snap-')) {
        try { unlinkSync(entry); } catch {}
      }
    }
  } catch {}
}

describe('registerProcessTools', () => {
  let engine: GraphEngine;
  let tracker: ProcessTracker;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    tracker = new ProcessTracker();
    handlers = {};

    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;

    registerProcessTools(fakeServer, tracker, engine);
  });

  afterEach(() => {
    engine.dispose();
    cleanup();
  });

  it('track_process persists immediately without a later graph mutation', async () => {
    await handlers.track_process({
      pid: 1234,
      command: 'nmap -sV 10.10.10.1',
      description: 'Version scan',
    });
    engine.flushNow();

    const reloaded = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    expect(reloaded.getTrackedProcesses()).toHaveLength(1);
    expect(reloaded.getTrackedProcesses()[0].command).toContain('nmap');
    expect(reloaded.getTrackedProcesses()[0]).toMatchObject({
      ownership_mode: 'external_adopted',
      signal_scope: 'none',
      command_fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    expect(reloaded.getRuntimeRuns()).toContainEqual(expect.objectContaining({
      kind: 'tracked_process',
      ownership_mode: 'external_adopted',
      signal_scope: 'none',
      command_fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/),
    }));
  });

  it('check_processes persists status transitions caused by refreshStatuses()', async () => {
    const result = await handlers.track_process({
      pid: 999999999,
      command: 'bloodhound-python -c All',
      description: 'BloodHound collection',
    });
    expect(JSON.parse(result.content[0].text)).toMatchObject({ status: 'unknown' });
    expect(tracker.listAll()[0]).toMatchObject({
      status: 'unknown',
      recovery_warning: expect.stringContaining('no longer running'),
    });

    await handlers.check_processes({ active_only: false });
    engine.flushNow();

    const reloaded = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    expect(reloaded.getTrackedProcesses()).toHaveLength(1);
    // P4.1: dead PID with no lifecycle visibility resolves to "unknown,"
    // not "completed."
    expect(reloaded.getTrackedProcesses()[0].status).toBe('unknown');
    expect(reloaded.getTrackedProcesses()[0].completed_at).toBeDefined();
  });

  it('rejects a non-positive pid before creating any durable ownership state', async () => {
    const result = await handlers.track_process({
      pid: 0,
      command: 'nmap',
      description: 'invalid process',
    });

    expect(result.isError).toBe(true);
    expect(tracker.listAll()).toEqual([]);
    expect(engine.getRuntimeRuns()).toEqual([]);
  });

  it('does not guess when a legacy agent label matches multiple tasks', async () => {
    for (const taskId of ['task-a', 'task-b']) {
      engine.registerAgent({
        id: taskId,
        task_id: taskId,
        agent_id: 'duplicate-label',
        agent_label: 'duplicate-label',
        assigned_at: new Date().toISOString(),
        status: 'running',
        subgraph_node_ids: [],
      });
    }

    const result = await handlers.track_process({
      pid: process.pid,
      command: 'nmap',
      description: 'ambiguous owner',
      agent_id: 'duplicate-label',
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text)).toMatchObject({
      candidate_task_ids: expect.arrayContaining(['task-a', 'task-b']),
    });
    expect(tracker.listAll()).toEqual([]);
    expect(engine.getRuntimeRuns()).toEqual([]);
  });
});
