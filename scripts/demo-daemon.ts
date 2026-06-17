#!/usr/bin/env npx tsx
// Full-daemon demo: starts the /mcp HTTP server + dashboard + TaskExecutionService
// (headless runner) wired to the FAKE claude planner, with a small seeded
// engagement. This lets you watch the NL cockpit's free-form path end to end:
// a command the grammar can't parse → a headless 'planner' sub-agent connects
// back over /mcp → proposes a plan via propose_plan → you confirm it in the
// command bar → it executes through the validated engine path.
//
//   npm run demo:daemon
//
// Then open the dashboard URL it prints, go to Operator Console, and type a
// free-form command like "wrap up the noisy recon agent".

import { resolve, join } from 'path';
import { chmodSync, existsSync, unlinkSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';

// The headless runner reads OVERWATCH_CLAUDE_BINARY at construction, so set the
// fake-claude (planner mode) BEFORE createOverwatchApp builds the service.
const FAKE_CLAUDE = resolve('./src/test-support/fake-claude.mjs');
chmodSync(FAKE_CLAUDE, 0o755);
process.env.OVERWATCH_CLAUDE_BINARY = FAKE_CLAUDE;
process.env.OVERWATCH_FAKE_MODE = 'planner';
process.env.OVERWATCH_OPERATOR_NAME = process.env.OVERWATCH_OPERATOR_NAME || 'Demo Operator';
process.env.OVERWATCH_OPERATOR_MODEL = process.env.OVERWATCH_OPERATOR_MODEL || 'claude-opus-4-8';

const { createOverwatchApp, startHttpApp, shutdownOverwatchApp } = await import('../src/app.js');
import type { EngagementConfig, AgentTask } from '../src/types.js';

const DASHBOARD_PORT = Number.parseInt(process.env.OVERWATCH_DEMO_DASHBOARD_PORT || '8385', 10);
const MCP_PORT = Number.parseInt(process.env.OVERWATCH_DEMO_MCP_PORT || '8386', 10);
const tempDir = mkdtempSync(join(tmpdir(), 'overwatch-demo-daemon-'));
const STATE_FILE = join(tempDir, 'state.json');
if (existsSync(STATE_FILE)) unlinkSync(STATE_FILE);
const iso = (minutesAgo = 0) => new Date(Date.now() - minutesAgo * 60_000).toISOString();

const config: EngagementConfig = {
  id: 'demo-daemon',
  name: 'NL Cockpit Daemon Demo',
  created_at: iso(120),
  profile: 'network',
  scope: { cidrs: ['10.20.0.0/24'], domains: ['lab.local'], exclusions: [] },
  // Keep the ONLY headless spawn the operator's planner: disable CVE auto-research.
  cve_research: { enabled: false },
  opsec: { name: 'pentest', enabled: true, max_noise: 1.0, approval_mode: 'approve-all', approval_timeout_ms: 3_600_000 },
  objectives: [],
} as EngagementConfig;

const app = createOverwatchApp({
  config,
  skillDir: resolve('./skills'),
  dashboardPort: DASHBOARD_PORT,
  stateFilePath: STATE_FILE,
});

// --- seed a small, steerable engagement ---
app.engine.ingestFinding({
  id: 'seed-hosts', agent_id: 'nmap', action_id: 'seed-a1', timestamp: iso(60), tool_name: 'nmap',
  target_node_ids: ['h-gw', 'h-app'],
  nodes: [
    { id: 'h-gw', type: 'host', label: 'gw.lab.local', ip: '10.20.0.1', hostname: 'gw', alive: true },
    { id: 'h-app', type: 'host', label: 'app01.lab.local', ip: '10.20.0.20', hostname: 'app01', alive: true },
    { id: 'svc-ssh', type: 'service', label: 'SSH (22)', port: 22, protocol: 'tcp', service_name: 'ssh' },
  ],
  edges: [{ source: 'h-app', target: 'svc-ssh', properties: { type: 'RUNS', confidence: 1, discovered_at: iso(60) } }],
} as never);

// Running agents the operator can steer. backend:'manual' so the daemon does
// NOT auto-launch headless processes for them — they stay steer targets, and the
// only headless spawn is the planner the operator triggers via a command.
// A large heartbeat_ttl keeps the watchdog from reaping these demo agents (they
// never heartbeat on their own), so the cockpit stays populated.
const DEMO_TTL = 86_400; // 24h — exempt from the 120s heartbeat watchdog
app.engine.registerAgent({
  id: 'task-recon-1', agent_id: 'agent-recon-1', assigned_at: iso(15), status: 'running',
  subgraph_node_ids: ['h-app', 'svc-ssh'], skill: 'network_enumeration', backend: 'manual',
  heartbeat_ttl_seconds: DEMO_TTL,
} as AgentTask);
app.engine.registerAgent({
  id: 'task-web-1', agent_id: 'agent-web-1', assigned_at: iso(8), status: 'running',
  subgraph_node_ids: ['h-app'], skill: 'webapp_testing', backend: 'manual',
  heartbeat_ttl_seconds: DEMO_TTL,
} as AgentTask);

const queue = app.engine.getPendingActionQueue();
void queue.submit({
  action_id: 'demo-act-1', technique: 'ssh_bruteforce', target_node: 'h-app', target_ip: '10.20.0.20',
  description: 'Spray a small credential list against app01 SSH.', validation_result: 'warning_only',
  agent_id: 'agent-recon-1',
  opsec_context: { global_noise_spent: 0.2, noise_budget_remaining: 0.5, recommended_approach: 'normal', defensive_signals: [] },
} as never);

app.engine.logActionEvent({
  description: 'Primary: prioritizing app01 — SSH is the only exposed service and recon is mid-flight.',
  event_type: 'thought', category: 'reasoning', target_node_ids: ['h-app'],
  details: { kind: 'selection' },
});

// Seed a full command→result→question loop for agent-recon-1 so the focused
// agent's CONVERSATION view shows the whole arc on load (logged in order so it
// reads top→bottom): operator command → action started → result → finding →
// the agent asks the operator. agent-web-1 stays mid-flight.
app.engine.logActionEvent({
  description: 'instruct → agent-recon-1: enumerate SSH auth methods on app01 and report back',
  event_type: 'operator_command', category: 'reasoning', agent_id: 'agent-recon-1',
  details: { source: 'dashboard', kind: 'instruct' },
});
app.engine.logActionEvent({
  description: 'Enumerating SSH auth methods on app01 (10.20.0.20:22)',
  event_type: 'action_started', category: 'frontier', agent_id: 'agent-recon-1',
  target_node_ids: ['h-app', 'svc-ssh'],
});
app.engine.logActionEvent({
  description: 'app01 SSH (10.20.0.20:22): password auth ENABLED; users enumerated — svc-deploy, admin',
  event_type: 'action_completed', category: 'frontier', agent_id: 'agent-recon-1',
  target_node_ids: ['h-app', 'svc-ssh'], result_classification: 'success',
});
app.engine.logActionEvent({
  description: 'Finding: app01 exposes SSH password auth (10.20.0.20) — credential-spray candidate',
  event_type: 'finding_reported', category: 'finding', agent_id: 'agent-recon-1',
  target_node_ids: ['h-app', 'svc-ssh'], result_classification: 'success',
});
app.engine.logActionEvent({
  description: 'Fuzzing app01 web root for hidden endpoints (ffuf)',
  event_type: 'action_started', category: 'frontier', agent_id: 'agent-web-1',
  target_node_ids: ['h-app'],
});
app.engine.getAgentQueryStore().add({
  task_id: 'task-recon-1', agent_id: 'agent-recon-1',
  question: 'app01 SSH allows password auth — spray a small list, or stay quiet and pivot?',
  options: ['spray (noisy)', 'stay quiet'],
});

// --- seed real tool runs (action_id + captured output) so the ANALYSIS
// workspace shows raw stdout/stderr the operator can assess. Each run stores
// its output in the evidence store and references it from the completed event,
// exactly as runInstrumentedProcess does. ---
const store = app.engine.getEvidenceStore();
const seedRun = (opts: {
  actionId: string; agent: string; tool: string; command: string; targets: string[];
  status: 'success' | 'failure'; exitCode: number; durationMs: number;
  stdout?: string; stderr?: string; findingIds?: string[];
}) => {
  const stdoutId = opts.stdout ? store.store({ evidence_type: 'command_output', raw_output: opts.stdout, action_id: opts.actionId, agent_id: opts.agent }) : undefined;
  const stderrId = opts.stderr ? store.store({ evidence_type: 'command_output', raw_output: opts.stderr, action_id: opts.actionId, agent_id: opts.agent }) : undefined;
  app.engine.logActionEvent({
    action_id: opts.actionId, event_type: 'action_started', category: 'frontier', agent_id: opts.agent,
    tool_name: opts.tool, command_repr: opts.command, target_node_ids: opts.targets,
    description: `${opts.tool}: ${opts.command}`,
    details: { command: opts.command, binary: opts.tool, invoking_tool: 'run_tool' },
  });
  app.engine.logActionEvent({
    action_id: opts.actionId,
    event_type: opts.status === 'success' ? 'action_completed' : 'action_failed',
    category: 'frontier', agent_id: opts.agent, tool_name: opts.tool, command_repr: opts.command,
    target_node_ids: opts.targets, result_classification: opts.status,
    linked_finding_ids: opts.findingIds,
    description: `${opts.tool} ${opts.status === 'success' ? 'completed' : 'failed'}: ${opts.command}`,
    details: {
      exit_code: opts.exitCode, duration_ms: opts.durationMs, binary: opts.tool, invoking_tool: 'run_tool',
      command: opts.command,
      stdout_evidence_id: stdoutId, stderr_evidence_id: stderrId,
      stdout_total_bytes: opts.stdout ? Buffer.byteLength(opts.stdout) : 0,
      stderr_total_bytes: opts.stderr ? Buffer.byteLength(opts.stderr) : 0,
    },
  });
};

seedRun({
  actionId: 'act_nmap_app01', agent: 'agent-recon-1', tool: 'nmap',
  command: 'nmap -sV -p- 10.20.0.20', targets: ['h-app', 'svc-ssh'], status: 'success',
  exitCode: 0, durationMs: 8420, findingIds: ['find-ssh-passwordauth'],
  stdout: [
    'Starting Nmap 7.94 ( https://nmap.org ) at 2026-06-17 12:01 UTC',
    'Nmap scan report for app01.lab.local (10.20.0.20)',
    'Host is up (0.00031s latency).',
    'Not shown: 65532 closed tcp ports (reset)',
    'PORT     STATE SERVICE     VERSION',
    '22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)',
    '80/tcp   open  http        nginx 1.18.0 (Ubuntu)',
    '8080/tcp open  http-proxy  Werkzeug/2.0.3 Python/3.10.6',
    'Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel',
    '',
    'Service detection performed. Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds',
  ].join('\n') + '\n',
});

seedRun({
  actionId: 'act_nxc_smb', agent: 'agent-recon-1', tool: 'nxc',
  command: 'nxc smb 10.20.0.20 -u svc-deploy -p winter2026', targets: ['h-app'], status: 'failure',
  exitCode: 1, durationMs: 1180,
  stderr: [
    'SMB         10.20.0.20      445    APP01            [*] Windows 10 / Server 2019 Build 17763 x64',
    'SMB         10.20.0.20      445    APP01            [-] lab.local\\svc-deploy:winter2026 STATUS_LOGON_FAILURE',
  ].join('\n') + '\n',
});

// A run still in flight: action_started with an id, no terminal event yet.
app.engine.logActionEvent({
  action_id: 'act_ffuf_app01', event_type: 'action_started', category: 'frontier', agent_id: 'agent-web-1',
  tool_name: 'ffuf', command_repr: 'ffuf -u http://10.20.0.20/FUZZ -w common.txt', target_node_ids: ['h-app'],
  description: 'ffuf: fuzzing app01 web root for hidden endpoints',
  details: { command: 'ffuf -u http://10.20.0.20/FUZZ -w common.txt', binary: 'ffuf', invoking_tool: 'run_tool' },
});

const result = await startHttpApp(app, { port: MCP_PORT, host: '127.0.0.1' });
void result;

console.log(`\nNL Cockpit DAEMON demo`);
console.log(`   Dashboard:   ${app.dashboard?.address ?? `http://127.0.0.1:${DASHBOARD_PORT}`}`);
console.log(`   MCP /mcp:    http://127.0.0.1:${MCP_PORT}/mcp  (headless planner connects here)`);
console.log(`   Headless:    fake-claude planner mode (${FAKE_CLAUDE})`);
console.log(`   Seeded:      2 hosts, 1 running agent (agent-recon-1), 1 pending action (demo-act-1)\n`);
console.log(`   Try in the Operator Console command bar:`);
console.log(`     • Grammar:   "pause recon"   |   "approve demo-act-1"   |   "scan 10.30.0.0/24"`);
console.log(`     • Free-form: "wrap up the noisy recon agent"  → a planner is dispatched, proposes a plan, you Confirm\n`);

process.on('SIGINT', async () => {
  console.log('\nShutting down daemon demo...');
  await shutdownOverwatchApp(app);
  try { unlinkSync(STATE_FILE); } catch { /* ignore */ }
  process.exit(0);
});
