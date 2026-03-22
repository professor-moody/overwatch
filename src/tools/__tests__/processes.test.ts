import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, readdirSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { ProcessTracker } from '../../services/process-tracker.js';
import { registerProcessTools } from '../processes.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-process-tools.json';

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
    cleanup();
  });

  it('track_process persists immediately without a later graph mutation', async () => {
    await handlers.track_process({
      pid: 1234,
      command: 'nmap -sV 10.10.10.1',
      description: 'Version scan',
    });

    const reloaded = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    expect(reloaded.getTrackedProcesses()).toHaveLength(1);
    expect(reloaded.getTrackedProcesses()[0].command).toContain('nmap');
  });

  it('check_processes persists status transitions caused by refreshStatuses()', async () => {
    await handlers.track_process({
      pid: 999999999,
      command: 'bloodhound-python -c All',
      description: 'BloodHound collection',
    });

    await handlers.check_processes({ active_only: false });

    const reloaded = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    expect(reloaded.getTrackedProcesses()).toHaveLength(1);
    expect(reloaded.getTrackedProcesses()[0].status).toBe('completed');
    expect(reloaded.getTrackedProcesses()[0].completed_at).toBeDefined();
  });
});
