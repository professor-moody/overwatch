import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync, rmSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerRunBashTool } from '../run-bash.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-run-bash.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-run-bash',
    name: 'run_bash test engagement',
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
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
  try { rmSync('./evidence-test-run-bash', { recursive: true, force: true }); } catch {}
}

function parseTextResult(result: any): any {
  return JSON.parse(result.content[0].text);
}

describe('run_bash tool', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    handlers = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;
    registerRunBashTool(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('executes a simple command and logs the full lifecycle', async () => {
    const result = await handlers.run_bash({
      command: 'echo hello-from-bash',
      validate: false,
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBeFalsy();
    expect(payload.executed).toBe(true);
    expect(payload.exit_code).toBe(0);
    expect(payload.stdout).toContain('hello-from-bash');
    expect(payload.action_id).toBeTruthy();
    expect(payload.stdout_evidence_id).toBeTruthy();

    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const types = events.map(e => e.event_type);
    expect(types).toContain('action_started');
    expect(types).toContain('action_completed');
    expect(types).not.toContain('action_failed');

    // Evidence store has the stdout
    const stored = engine.getEvidenceStore().getRawOutput(payload.stdout_evidence_id);
    expect(stored).toContain('hello-from-bash');
  });

  it('logs action_failed on non-zero exit', async () => {
    const result = await handlers.run_bash({
      command: 'exit 7',
      validate: false,
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.exit_code).toBe(7);
    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const terminal = events.find(e => e.event_type === 'action_failed' || e.event_type === 'action_completed');
    expect(terminal?.event_type).toBe('action_failed');
    expect((terminal?.details as any).reason).toBe('nonzero_exit');
  });

  it('times out long-running commands and reports timeout', async () => {
    const result = await handlers.run_bash({
      command: 'sleep 5',
      timeout_ms: 200,
      validate: false,
    });
    const payload = parseTextResult(result);

    expect(payload.timed_out).toBe(true);
    expect(result.isError).toBe(true);
    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const failed = events.find(e => e.event_type === 'action_failed');
    expect(failed).toBeTruthy();
    expect((failed!.details as any).reason).toBe('timeout');
  }, 10_000);

  it('blocks execution when target_ip is out of scope', async () => {
    const result = await handlers.run_bash({
      command: 'echo would-not-run',
      target_ip: '8.8.8.8',
      technique: 'portscan',
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(false);
    expect(payload.validation_result).toBe('invalid');
    expect(payload.errors.join(' ')).toContain('out of scope');

    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    expect(events.find(e => e.event_type === 'action_started')).toBeUndefined();
    expect(events.find(e => e.event_type === 'action_failed')).toBeTruthy();
  });

  it('blocks when any target_ips entry is out of scope (no singular target_ip)', async () => {
    // Regression: previously target_ips was logged but never validated, so a
    // multi-target invocation could ride out-of-scope IPs through.
    const result = await handlers.run_bash({
      command: 'echo would-not-run',
      target_ips: ['8.8.8.8'],
      technique: 'portscan',
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(false);
    expect(payload.validation_result).toBe('invalid');
    expect(payload.errors.join(' ')).toContain('8.8.8.8');
    expect(payload.errors.join(' ')).toContain('out of scope');
  });

  it('blocks when one of multiple target_ips is out of scope', async () => {
    const result = await handlers.run_bash({
      command: 'echo would-not-run',
      target_ips: ['10.10.10.1', '8.8.8.8'],
      technique: 'portscan',
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(false);
    expect(payload.errors.join(' ')).toContain('8.8.8.8');
  });

  it('threads frontier_item_id through events', async () => {
    const result = await handlers.run_bash({
      command: 'true',
      validate: false,
      frontier_item_id: 'fake-frontier-1',
    });
    const payload = parseTextResult(result);
    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    for (const e of events) {
      expect(e.frontier_item_id).toBe('fake-frontier-1');
    }
  });

  it('returns a parse error if parse_with names an unknown parser', async () => {
    const result = await handlers.run_bash({
      command: 'echo x',
      validate: false,
      parse_with: 'definitely-not-a-real-parser',
    });
    const payload = parseTextResult(result);
    expect(payload.parse_summary).toBeTruthy();
    expect(String(payload.parse_summary.error)).toContain('No parser found');
  });
});
