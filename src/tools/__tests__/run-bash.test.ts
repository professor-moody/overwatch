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

  it('extracts implicit targets from a known target-facing binary even without technique (regression: scope-bypass P0)', async () => {
    // Caller omits both target_ip(s) and technique. Previously this slipped
    // through scope because implicit-target extraction was gated on
    // TARGET_FACING_TECHNIQUES. Now extraction also fires when the binary is
    // a known scanner (nmap), so the out-of-scope IP is rejected.
    const result = await handlers.run_bash({
      command: 'nmap 8.8.8.8',
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(false);
    expect(payload.validation_result).toBe('invalid');
    expect(payload.errors.join(' ')).toContain('8.8.8.8');
    expect(payload.errors.join(' ')).toContain('out of scope');
  });

  it('does not over-extract on non-target-facing commands that mention out-of-scope hosts', async () => {
    // A non-scanner command that happens to mention an out-of-scope IP/URL
    // must still run — neither the binary (echo) nor the technique are
    // target-facing, so we deliberately don't sniff argv. This guards against
    // the fix for the P0 scope-bypass over-rejecting innocuous commands.
    const result = await handlers.run_bash({
      command: 'echo connecting-to-https://example.com/and/8.8.8.8-mention',
    });
    const payload = parseTextResult(result);
    expect(payload.executed).toBe(true);
  });

  it('rejects direct actions whose noise_estimate exceeds the OPSEC ceiling (P1 max_noise)', async () => {
    // Build a fresh engine with OPSEC enforcement enabled and a tight ceiling.
    cleanup();
    const tightEngine = new GraphEngine({
      ...makeConfig(),
      opsec: { name: 'tight', max_noise: 0.2, enabled: true } as any,
    }, TEST_STATE_FILE);
    const tightHandlers: Record<string, (a: any) => Promise<any>> = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (a: any) => Promise<any>) {
        tightHandlers[name] = handler;
      },
    } as unknown as McpServer;
    registerRunBashTool(fakeServer, tightEngine);

    const result = await tightHandlers.run_bash({
      command: 'echo would-be-noisy',
      target_ip: '10.10.10.1',
      technique: 'portscan',
      noise_estimate: 0.9, // way over headroom
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(false);
    expect(payload.validation_result).toBe('invalid');
    expect(payload.errors.join(' ')).toContain('OPSEC noise ceiling');
  });

  it('OPSEC stays inert with opsec.enabled=false — no noise recorded, no defaults substituted', async () => {
    // OPSEC is opt-in. With enforcement disabled, missing noise_estimate must
    // NOT be silently filled in by the runner (neither the old buggy
    // cumulative-spend substitution nor the new per-technique defaults), and
    // no noise should be recorded against the OpsecTracker. The whole
    // pipeline stays out of the way unless the operator turns it on.
    const r1 = await handlers.run_bash({
      command: 'echo first',
      target_ip: '10.10.10.1',
      technique: 'enum_smb',
    });
    const payload = parseTextResult(r1);
    expect(payload.executed).toBe(true);
    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const started = events.find(e => e.event_type === 'action_started');
    expect(started?.noise_estimate).toBeUndefined();
    // OpsecTracker should still report zero global noise.
    expect(engine.getOpsecContext().global_noise_spent).toBe(0);
  });

  it('respects an explicit noise_estimate even when OPSEC is disabled (records, does not enforce)', async () => {
    // If the caller explicitly passes noise_estimate, we honor it (record it
    // on the event and the tracker) but do NOT enforce a ceiling — that
    // requires opsec.enabled.
    const r1 = await handlers.run_bash({
      command: 'echo explicit',
      target_ip: '10.10.10.1',
      technique: 'enum_smb',
      noise_estimate: 0.5,
    });
    const payload = parseTextResult(r1);
    expect(payload.executed).toBe(true);
    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const started = events.find(e => e.event_type === 'action_started');
    expect(started?.noise_estimate).toBe(0.5);
    expect(engine.getOpsecContext().global_noise_spent).toBe(0.5);
  });

  it('substitutes per-technique noise default only when OPSEC is enabled (no double-count)', async () => {
    // Regression: previously, when noise_estimate was undefined, the runner
    // substituted v.opsec_context.global_noise_spent, recording cumulative
    // spend back onto each subsequent action. With OPSEC enabled, the runner
    // now uses a per-technique default (enum_smb → 0.15), not the accumulated
    // total. With OPSEC disabled this whole branch is skipped (covered above).
    cleanup();
    const opsecEngine = new GraphEngine({
      ...makeConfig(),
      opsec: { name: 'pentest', max_noise: 1.0, enabled: true } as any,
    }, TEST_STATE_FILE);
    const opsecHandlers: Record<string, (a: any) => Promise<any>> = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (a: any) => Promise<any>) {
        opsecHandlers[name] = handler;
      },
    } as unknown as McpServer;
    registerRunBashTool(fakeServer, opsecEngine);

    await opsecHandlers.run_bash({ command: 'echo first', target_ip: '10.10.10.1', technique: 'enum_smb' });
    const r2 = await opsecHandlers.run_bash({ command: 'echo second', target_ip: '10.10.10.1', technique: 'enum_smb' });
    const payload2 = parseTextResult(r2);
    expect(payload2.executed).toBe(true);
    const events = opsecEngine.getFullHistory().filter(e => e.action_id === payload2.action_id);
    const started = events.find(e => e.event_type === 'action_started');
    // Per-action default for enum_smb is 0.15, not the cumulative sum (~0.3).
    expect(started?.noise_estimate).toBe(0.15);
  });

  it('approval gate sees the worst per-target OPSEC context, not the last (regression)', async () => {
    // Two in-scope targets; only the first carries a defensive signal. The
    // logged opsec_context for the action must reflect that signal — earlier
    // versions overwrote opsec_context with the last validated target.
    const now = new Date().toISOString();
    engine.addNode({ id: 'host-1', type: 'host', label: '10.10.10.1', discovered_at: now, confidence: 1 });
    engine.addNode({ id: 'host-2', type: 'host', label: '10.10.10.2', discovered_at: now, confidence: 1 });
    engine.recordDefensiveSignal({
      type: 'rate_limit',
      host_id: 'host-1',
      detected_at: now,
      description: 'WAF rate limited /admin',
    });

    const result = await handlers.run_bash({
      command: 'echo multi',
      target_node_ids: ['host-1', 'host-2'],
      technique: 'portscan',
    });
    const payload = parseTextResult(result);
    expect(payload.executed).toBe(true);

    const validated = engine.getFullHistory().find(
      e => e.action_id === payload.action_id && e.event_type === 'action_validated',
    );
    const opsec = (validated?.details as any)?.opsec_context;
    expect(opsec).toBeTruthy();
    const signals = opsec.defensive_signals as Array<{ host_id?: string }>;
    expect(signals.some(s => s.host_id === 'host-1')).toBe(true);
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

  // -----------------------------------------------------------------
  // Phase I: parse output even on non-zero exit; tag findings partial
  // -----------------------------------------------------------------
  it('parses output on non-zero exit and tags the finding partial', async () => {
    // emit a single line that the nuclei text parser will accept, then exit 7
    const cmd = `echo '[CVE-2099-9999] [http] [high] http://10.10.10.1/x'; exit 7`;
    const result = await handlers.run_bash({
      command: cmd,
      validate: false,
      parse_with: 'nuclei',
    });
    const payload = parseTextResult(result);
    expect(payload.parse_summary).toBeTruthy();
    expect(payload.parse_summary.parsed).toBe(true);
    expect(payload.parse_summary.partial).toBe(true);
    expect(payload.parse_summary.exit_code).toBe(7);

    const findingId = payload.parse_summary.finding_id as string;
    const vuln = engine.getNodesByType('vulnerability').find(
      v => (v as Record<string, unknown>).cve === 'CVE-2099-9999',
    );
    expect(vuln).toBeTruthy();
    expect((vuln as Record<string, unknown>).partial).toBe(true);
    expect(findingId).toBeTruthy();
  });

  it('treats an acceptable_exit_code (nuclei exit 1 = no match) as non-partial', async () => {
    // nuclei exits 1 when no template matched. Output is empty so the
    // parser will produce no nodes — but partial must NOT be true because
    // exit 1 is whitelisted for nuclei.
    const result = await handlers.run_bash({
      command: 'exit 1',
      validate: false,
      parse_with: 'nuclei',
    });
    const payload = parseTextResult(result);
    // No bytes produced → parser path is skipped entirely; no parse_summary.
    // We only assert that the runner did not crash and reported the exit.
    expect(payload.executed).toBe(true);
    expect(payload.exit_code).toBe(1);
  });
});
