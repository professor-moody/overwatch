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

// A running agent the operator can steer. backend:'manual' so the daemon does
// NOT auto-launch a headless process for it — it stays a steer target, and the
// only headless spawn is the planner the operator triggers via a command.
app.engine.registerAgent({
  id: 'task-recon-1', agent_id: 'agent-recon-1', assigned_at: iso(15), status: 'running',
  subgraph_node_ids: ['h-app', 'svc-ssh'], skill: 'network_enumeration', backend: 'manual',
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
