// ============================================================
// Phase D: target-token argv guard.
//
// _process-runner already extracts implicit targets when the technique
// or binary is target-facing. This test pins down the new fail-closed
// behavior when the caller uses a non-target-facing technique label
// (e.g. 'note', 'research') but argv embeds a URL/IP/hostname.
// ============================================================

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, rmSync, unlinkSync } from 'fs';
import { GraphEngine } from '../services/graph-engine.js';
import { runInstrumentedProcess } from '../tools/_process-runner.js';
import type { EngagementConfig } from '../types.js';

const TEST_STATE_FILE = './state-test-target-guard.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-target-guard',
    name: 'target-guard',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24', '10.10.110.0/24'], domains: ['lab.local'], exclusions: ['10.10.110.2'] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  };
}

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
  try { rmSync('./evidence-test-target-guard', { recursive: true, force: true }); } catch {}
}

describe('Phase D — target-token argv guard', () => {
  beforeEach(() => { cleanup(); });
  afterEach(() => { cleanup(); });

  it('refuses execution when argv contains a URL but no scope metadata', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'curl',
      args: ['https://target.example.com/admin'],
      command_repr: 'curl https://target.example.com/admin',
      technique: 'note', // not in TARGET_FACING_TECHNIQUES
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    const payload = JSON.parse(res.content[0].text);
    expect(payload.executed).toBe(false);
    expect(payload.errors[0]).toMatch(/target_tokens_in_argv_without_scope/);
    expect(payload.argv_tokens_found).toContain('https://target.example.com/admin');
  });

  it('refuses execution when a network-capable binary has an IP in argv but no scope', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'nc',
      args: ['9.9.9.9', '443'],
      command_repr: 'nc 9.9.9.9 443',
      technique: 'research',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    const payload = JSON.parse(res.content[0].text);
    expect(payload.argv_tokens_found).toContain('9.9.9.9');
  });

  it('does not fire on shell-only binaries that mention IPs/URLs in argv (echo, cat, etc.)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'echo',
      args: ['note: target was 9.9.9.9'],
      command_repr: 'echo "note: target was 9.9.9.9"',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBeFalsy();
    const payload = JSON.parse(res.content[0].text);
    expect(payload.argv_tokens_found).toBeUndefined();
    expect(payload.executed).not.toBe(false);
  });

  it('lets target-facing techniques continue through implicit extraction', async () => {
    // 'recon' IS target-facing, so the existing F3 path runs and the
    // implicit IP gets re-validated against scope. With 9.9.9.9 out of
    // scope this still fails, but with the OUT_OF_SCOPE error rather
    // than the new argv-guard error.
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'echo',
      args: ['9.9.9.9'],
      command_repr: 'echo 9.9.9.9',
      technique: 'recon',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    const payload = JSON.parse(res.content[0].text);
    expect(payload.errors.join(' ')).toMatch(/out of scope/);
    expect(payload.errors.join(' ')).not.toMatch(/target_tokens_in_argv_without_scope/);
  });

  it('honors allow_unverified_scope as the explicit operator escape hatch', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'echo',
      args: ['hello https://anywhere.example/'],
      command_repr: 'echo hello https://anywhere.example/',
      technique: 'note',
      allow_unverified_scope: true,
      invoking_tool: 'run_bash',
    });
    // echo exits 0 — should succeed, not be blocked by the new guard.
    expect(res.isError).toBeFalsy();
    const payload = JSON.parse(res.content[0].text);
    expect(payload.argv_tokens_found).toBeUndefined();
    expect(payload.executed).not.toBe(false);
  });

  it('validates nmap CIDR targets without treating the network address or --exclude values as host targets', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'nmap',
      args: ['-oX', '-', '10.10.110.0/24', '--exclude', '10.10.110.2'],
      command_repr: 'nmap -oX - 10.10.110.0/24 --exclude 10.10.110.2',
      technique: 'host_discovery',
      invoking_tool: 'run_tool',
      timeout_ms: 100,
    });
    const validation = engine.getFullHistory().find(e => e.event_type === 'action_validated');
    expect(validation?.target_cidrs).toEqual(['10.10.110.0/24']);
    const payload = JSON.parse(res.content[0].text);
    expect((payload.errors || []).join(' ')).not.toMatch(/10\.10\.110\.0\/24|10\.10\.110\.2/);
  });

  it('allows local operator infrastructure commands without broad unverified-scope override', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'bash',
      args: ['-c', 'echo bridge 10.10.14.22:4444 to 127.0.0.1:4445'],
      command_repr: 'echo bridge 10.10.14.22:4444 to 127.0.0.1:4445',
      technique: 'note',
      operator_infra: true,
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBeFalsy();
    const started = engine.getFullHistory().find(e => e.event_type === 'action_started');
    expect(started?.details).toMatchObject({ operator_infra: true });
  });
});
