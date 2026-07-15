import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerRunToolTool } from '../run-tool.js';
import type { EngagementConfig } from '../../types.js';

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

function parseTextResult(result: any): any {
  return JSON.parse(result.content[0].text);
}

describe('run_tool', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;
  let testDir: string;

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-run-tool-'));
    engine = new GraphEngine(makeConfig(), join(testDir, 'state.json'));
    handlers = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;
    registerRunToolTool(fakeServer, engine);
  });

  afterEach(() => {
    engine.dispose();
    rmSync(testDir, { recursive: true, force: true });
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

  it('preserves GitHub repository and branch context through inline run_tool parsing', async () => {
    const output = JSON.stringify({ use_default: false, include_claim_keys: ['repo', 'context'] });
    const result = await handlers.run_tool({
      binary: process.execPath,
      args: ['-e', `process.stdout.write(${JSON.stringify(output)})`],
      validate: false,
      parse_with: 'github-actions-oidc',
      parser_context: {
        repo_full_name: 'acme/widgets', branch_name: 'release',
        provider_extension: { retained: true },
      },
    });
    const payload = parseTextResult(result);
    expect(result.isError).toBeFalsy();
    expect(payload.parse_summary.parse_outcome).toBe('ok');
    expect(engine.getNodesByType('idp_application')[0]).toMatchObject({
      repo_full_name: 'acme/widgets', branch_name: 'release',
      oidc_use_default: false, oidc_include_claim_keys: ['repo', 'context'],
    });
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

  it('kills an in-flight process and skips terminal ingest when persistence becomes read-only', async () => {
    let writable = true;
    const gate = vi.spyOn(engine, 'isPersistenceWritable').mockImplementation(() => writable);
    const startedAt = Date.now();

    try {
      const pending = handlers.run_tool({
        binary: process.execPath,
        args: ['-e', "setInterval(() => process.stdout.write('still-running\\n'), 25)"],
        timeout_ms: 30_000,
        validate: false,
        parse_with: 'nmap',
      });

      // Wait until action_started has landed so this exercises the live
      // writable→read-only transition, not the entry-point rejection path.
      for (let i = 0; i < 100 && !engine.getFullHistory().some(event => event.event_type === 'action_started'); i++) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      expect(engine.getFullHistory().some(event => event.event_type === 'action_started')).toBe(true);

      writable = false;
      const result = await pending;
      const payload = parseTextResult(result);

      expect(Date.now() - startedAt).toBeLessThan(4_000);
      expect(result.isError).toBe(true);
      expect(payload).toMatchObject({
        executed: true,
        interrupted: true,
        code: 'PERSISTENCE_READ_ONLY',
        reason: 'persistence_degraded',
      });
      expect(payload.signal).toBeTruthy();

      const actionEvents = engine.getFullHistory().filter(event => event.action_id === payload.action_id);
      expect(actionEvents.map(event => event.event_type)).toContain('action_started');
      expect(actionEvents.map(event => event.event_type)).not.toContain('action_completed');
      expect(actionEvents.map(event => event.event_type)).not.toContain('action_failed');
      expect(actionEvents.map(event => event.event_type)).not.toContain('parse_output');
    } finally {
      gate.mockRestore();
    }
  }, 10_000);

  it('aborts a pending approval when persistence becomes read-only before spawn', async () => {
    engine.updateConfig({ opsec: { ...engine.getConfig().opsec, approval_mode: 'approve-all' } });
    let writable = true;
    const gate = vi.spyOn(engine, 'isPersistenceWritable').mockImplementation(() => writable);

    try {
      const pending = handlers.run_tool({
        binary: 'echo',
        args: ['must-not-spawn'],
        target_ip: '10.10.10.1',
        technique: 'enum_smb',
      });

      for (let i = 0; i < 100 && engine.getPendingActionQueue().getPending().length === 0; i++) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      expect(engine.getPendingActionQueue().getPending()).toHaveLength(1);

      writable = false;
      const result = await pending;
      const payload = parseTextResult(result);

      expect(result.isError).toBe(true);
      expect(payload).toMatchObject({
        executed: false,
        interrupted: true,
        code: 'PERSISTENCE_READ_ONLY',
        reason: 'persistence_degraded',
        approval_status: 'aborted',
      });
      expect(engine.getPendingActionQueue().getPending()).toHaveLength(0);
      expect(engine.getFullHistory().some(event => event.event_type === 'action_started')).toBe(false);
    } finally {
      gate.mockRestore();
    }
  }, 10_000);

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
