import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync, rmSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerRunToolTool } from '../run-tool.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-run-tool.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-run-tool',
    name: 'run_tool test engagement',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/30'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
  try { rmSync('./evidence-test-run-tool', { recursive: true, force: true }); } catch {}
}

function parseTextResult(result: any): any {
  return JSON.parse(result.content[0].text);
}

describe('run_tool', () => {
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
    registerRunToolTool(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('executes a binary with argv and logs the full lifecycle', async () => {
    const result = await handlers.run_tool({
      binary: 'echo',
      args: ['hello-from-tool', 'arg-2'],
      validate: false,
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBeFalsy();
    expect(payload.executed).toBe(true);
    expect(payload.binary).toBe('echo');
    expect(payload.args).toEqual(['hello-from-tool', 'arg-2']);
    expect(payload.exit_code).toBe(0);
    expect(payload.stdout).toContain('hello-from-tool');
    expect(payload.stdout).toContain('arg-2');
    expect(payload.action_id).toBeTruthy();

    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const types = events.map(e => e.event_type);
    expect(types).toContain('action_started');
    expect(types).toContain('action_completed');

    // tool_name should default to the binary basename
    const started = events.find(e => e.event_type === 'action_started');
    expect(started?.tool_name).toBe('echo');
    // Started event records invoking_tool=run_tool for retrospective discrimination
    expect((started?.details as any)?.invoking_tool).toBe('run_tool');
    expect((started?.details as any)?.binary).toBe('echo');
    expect((started?.details as any)?.args).toEqual(['hello-from-tool', 'arg-2']);
  });

  it('logs action_failed on non-zero exit', async () => {
    const result = await handlers.run_tool({
      binary: 'bash',
      args: ['-c', 'exit 7'],
      validate: false,
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(true);
    expect(payload.exit_code).toBe(7);

    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const types = events.map(e => e.event_type);
    expect(types).toContain('action_failed');
    expect(types).not.toContain('action_completed');
  });

  it('reports signal-only exits without losing terminal lifecycle metadata', async () => {
    const result = await handlers.run_tool({
      binary: process.execPath,
      args: ['-e', "process.kill(process.pid, 'SIGTERM')"],
      validate: false,
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(true);
    expect(payload.exit_code).toBeNull();
    expect(payload.signal).toBe('SIGTERM');

    const failed = engine.getFullHistory().find(e => e.action_id === payload.action_id && e.event_type === 'action_failed');
    expect(failed).toBeDefined();
    expect(failed?.details?.signal).toBe('SIGTERM');
  });

  it('does not invoke the shell — special characters are literal', async () => {
    // Using `;` and `$()` as a literal arg must NOT execute additional commands.
    const result = await handlers.run_tool({
      binary: 'echo',
      args: ['x; rm -rf /tmp/should-never-happen', '$(whoami)'],
      validate: false,
    });
    const payload = parseTextResult(result);
    expect(result.isError).toBeFalsy();
    expect(payload.stdout).toContain('x; rm -rf /tmp/should-never-happen');
    expect(payload.stdout).toContain('$(whoami)');
  });

  it('honours timeout_ms', async () => {
    const start = Date.now();
    const result = await handlers.run_tool({
      binary: 'sleep',
      args: ['10'],
      timeout_ms: 200,
      validate: false,
    });
    const elapsed = Date.now() - start;
    const payload = parseTextResult(result);
    expect(payload.executed).toBe(true);
    expect(payload.timed_out).toBe(true);
    expect(elapsed).toBeLessThan(7000);
  });

  it('marks oversized stdout as truncated while preserving evidence linkage', async () => {
    const result = await handlers.run_tool({
      binary: process.execPath,
      args: ['-e', "process.stdout.write('A'.repeat(300 * 1024))"],
      validate: false,
    });
    const payload = parseTextResult(result);

    expect(payload.executed).toBe(true);
    expect(payload.stdout_truncated).toBe(true);
    expect(payload.stdout_total_bytes).toBe(300 * 1024);
    expect(payload.stdout_evidence_id).toBeTruthy();

    const completed = engine.getFullHistory().find(e => e.action_id === payload.action_id && e.event_type === 'action_completed');
    expect(completed?.details?.stdout_truncated).toBe(true);
    expect(completed?.details?.stdout_evidence_id).toBe(payload.stdout_evidence_id);
  });

  it('blocks execution when validation fails', async () => {
    // Out-of-scope IP triggers validation failure
    const result = await handlers.run_tool({
      binary: 'echo',
      args: ['hi'],
      target_ip: '8.8.8.8',
      validate: true,
    });
    const payload = parseTextResult(result);
    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(false);
    expect(payload.validation_result).toBe('invalid');
  });
});
