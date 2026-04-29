#!/usr/bin/env npx tsx
// Lightweight demo: starts GraphEngine + DashboardServer with synthetic data
// so the dashboard-next UI can be previewed with real content.

import { GraphEngine } from '../src/services/graph-engine.js';
import { DashboardServer } from '../src/services/dashboard-server.js';
import { setTelemetry } from '../src/tools/error-boundary.js';
import { ToolTelemetry } from '../src/services/tool-telemetry.js';
import type { EngagementConfig } from '../src/types.js';
import { unlinkSync, existsSync } from 'fs';

const STATE_FILE = './state-demo-dashboard.json';

// Clean slate
if (existsSync(STATE_FILE)) unlinkSync(STATE_FILE);

const config: EngagementConfig = {
  id: 'demo-engagement',
  name: 'Demo Engagement',
  created_at: new Date().toISOString(),
  profile: 'network',
  scope: {
    cidrs: ['10.10.10.0/24'],
    domains: ['corp.local'],
    exclusions: [],
    url_patterns: ['*.corp.local'],
  },
  opsec: {
    name: 'pentest',
    max_noise: 0.7,
    approval_mode: 'auto-approve',
  },
  objectives: [
    { id: 'obj-1', description: 'Compromise domain controller', achieved: false },
    { id: 'obj-2', description: 'Exfiltrate sensitive data', achieved: false },
    { id: 'obj-3', description: 'Establish persistence', achieved: true, achieved_at: new Date().toISOString() },
  ],
  phases: [
    {
      id: 'recon', name: 'Reconnaissance', order: 0,
      strategies: ['enumeration', 'network_discovery'],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'node_count', node_type: 'host', min: 5 }],
    },
    {
      id: 'exploit', name: 'Exploitation', order: 1,
      strategies: ['credential_spray', 'post_exploitation'],
      entry_criteria: [{ type: 'phase_completed', phase_id: 'recon' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'obj-1' }],
    },
  ],
};

const engine = new GraphEngine(config, STATE_FILE);

// Seed synthetic graph data
const hosts = [
  { id: 'dc01', type: 'host' as const, label: 'DC01.corp.local', ip: '10.10.10.10', os: 'Windows Server 2019', hostname: 'DC01' },
  { id: 'web01', type: 'host' as const, label: 'WEB01.corp.local', ip: '10.10.10.20', os: 'Ubuntu 22.04', hostname: 'WEB01' },
  { id: 'db01', type: 'host' as const, label: 'DB01.corp.local', ip: '10.10.10.30', os: 'Windows Server 2022', hostname: 'DB01' },
  { id: 'fs01', type: 'host' as const, label: 'FS01.corp.local', ip: '10.10.10.40', os: 'Windows Server 2019', hostname: 'FS01' },
  { id: 'ws01', type: 'host' as const, label: 'WS01.corp.local', ip: '10.10.10.50', os: 'Windows 11', hostname: 'WS01' },
  { id: 'ws02', type: 'host' as const, label: 'WS02.corp.local', ip: '10.10.10.51', os: 'Windows 11', hostname: 'WS02' },
];

const users = [
  { id: 'user-admin', type: 'user' as const, label: 'Administrator', username: 'Administrator', domain: 'corp.local' },
  { id: 'user-jdoe', type: 'user' as const, label: 'jdoe', username: 'jdoe', domain: 'corp.local' },
  { id: 'user-svc', type: 'user' as const, label: 'svc_backup', username: 'svc_backup', domain: 'corp.local' },
];

const creds = [
  { id: 'cred-jdoe-ntlm', type: 'credential' as const, label: 'jdoe:NTLM', cred_type: 'ntlm' as const, hash: 'aad3b435b51404ee:5d41402abc4b2a76' },
  { id: 'cred-svc-pass', type: 'credential' as const, label: 'svc_backup:password', cred_type: 'plaintext' as const, plaintext: 'Backup2024!' },
];

const services = [
  { id: 'svc-smb-dc01', type: 'service' as const, label: 'SMB (445)', port: 445, protocol: 'tcp', service_name: 'smb' },
  { id: 'svc-http-web01', type: 'service' as const, label: 'HTTP (80)', port: 80, protocol: 'tcp', service_name: 'http' },
  { id: 'svc-https-web01', type: 'service' as const, label: 'HTTPS (443)', port: 443, protocol: 'tcp', service_name: 'https' },
  { id: 'svc-mssql-db01', type: 'service' as const, label: 'MSSQL (1433)', port: 1433, protocol: 'tcp', service_name: 'mssql' },
  { id: 'svc-rdp-ws01', type: 'service' as const, label: 'RDP (3389)', port: 3389, protocol: 'tcp', service_name: 'rdp' },
];

engine.ingestFinding({
  id: 'f-hosts', agent_id: 'nmap-agent', tool_name: 'nmap',
  timestamp: new Date(Date.now() - 3600000).toISOString(),
  nodes: [...hosts, ...services],
  edges: [
    { source: 'dc01', target: 'svc-smb-dc01', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
    { source: 'web01', target: 'svc-http-web01', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
    { source: 'web01', target: 'svc-https-web01', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
    { source: 'db01', target: 'svc-mssql-db01', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
    { source: 'ws01', target: 'svc-rdp-ws01', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
  ],
});

engine.ingestFinding({
  id: 'f-users', agent_id: 'enum-agent', tool_name: 'enum4linux',
  timestamp: new Date(Date.now() - 1800000).toISOString(),
  nodes: [...users, ...creds],
  edges: [
    { source: 'user-jdoe', target: 'cred-jdoe-ntlm', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
    { source: 'user-svc', target: 'cred-svc-pass', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: new Date().toISOString() } },
    { source: 'user-admin', target: 'dc01', properties: { type: 'ADMIN_TO', confidence: 0.8, discovered_at: new Date().toISOString(), inferred: true } },
    { source: 'user-jdoe', target: 'ws01', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString() } },
    { source: 'user-svc', target: 'db01', properties: { type: 'HAS_SESSION', confidence: 0.9, discovered_at: new Date().toISOString() } },
  ],
});

// Seed tool telemetry
const telemetry = new ToolTelemetry();
setTelemetry(telemetry);

const tools = ['get_state', 'next_task', 'validate_action', 'report_finding', 'parse_output', 'query_graph', 'log_action_event', 'register_agent'];
// Simulate realistic tool call patterns
for (let i = 0; i < 80; i++) {
  const tool = tools[Math.floor(Math.random() * tools.length)];
  const duration = Math.floor(Math.random() * 200) + 10;
  const error = Math.random() < 0.05;
  telemetry.record(tool, duration, error);
}
// Add some sequential patterns
for (let i = 0; i < 20; i++) {
  telemetry.record('get_state', 50, false);
  telemetry.record('next_task', 30, false);
  telemetry.record('validate_action', 20, false);
}

// Register some agents
engine.registerAgent({
  id: 'task-smb-1',
  agent_id: 'agent-smb-1',
  assigned_at: new Date().toISOString(),
  status: 'running',
  subgraph_node_ids: ['dc01'],
  skill: 'smb_enumeration',
});

engine.registerAgent({
  id: 'task-spray-1',
  agent_id: 'agent-spray-1',
  assigned_at: new Date().toISOString(),
  status: 'running',
  subgraph_node_ids: ['ws01', 'ws02'],
  skill: 'credential_spray',
});

// Log some activity
engine.logActionEvent({ description: 'Nmap scan completed: 6 hosts discovered', event_type: 'action_completed', agent_id: 'nmap-agent', category: 'finding' });
engine.logActionEvent({ description: 'Enum4linux: 3 users, 2 credentials extracted', event_type: 'action_completed', agent_id: 'enum-agent', category: 'finding' });
engine.logActionEvent({ description: 'SMB share enumeration started on DC01', event_type: 'action_started', agent_id: 'agent-smb-1', category: 'frontier' });
engine.logActionEvent({ description: 'Credential spray: testing jdoe against RDP', event_type: 'action_started', agent_id: 'agent-spray-1', category: 'frontier' });

// Start dashboard
const dashboard = new DashboardServer(engine, 8384);

// Wire graph updates to dashboard
engine.onUpdate((detail) => dashboard.onGraphUpdate(detail));

const result = await dashboard.start();
if (result.started) {
  console.log('\n✅ Demo dashboard running at http://localhost:8384');
  console.log('   Vite dev server (with HMR) at http://localhost:5173');
  console.log(`   Graph: ${hosts.length} hosts, ${users.length} users, ${creds.length} creds, ${services.length} services`);
  console.log('   Press Ctrl+C to stop\n');
} else {
  console.error('Failed to start dashboard:', result.error);
  process.exit(1);
}

// Keep alive
process.on('SIGINT', async () => {
  console.log('\nShutting down...');
  await dashboard.stop();
  if (existsSync(STATE_FILE)) unlinkSync(STATE_FILE);
  process.exit(0);
});
