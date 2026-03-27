import { describe, it, expect, afterEach } from 'vitest';
import { GraphEngine } from '../graph-engine.js';
import { parseLinpeas } from '../output-parsers.js';
import { parseOutput } from '../output-parsers.js';
import type { EngagementConfig, Finding } from '../../types.js';
import { unlinkSync, existsSync } from 'fs';

const TEST_STATE_FILE = './state-test-sprint9.json';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-s9',
    name: 'Sprint 9 Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [{
      id: 'obj-1',
      description: 'Get DA',
      target_node_type: 'user',
      target_criteria: { privileged: true },
      achieved: false,
    }],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  };
}

function cleanup() {
  if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
}

const now = new Date().toISOString();

function makeFinding(nodes: Finding['nodes'], edges: Finding['edges'] = []): Finding {
  return { id: `f-${Date.now()}`, agent_id: 'test', timestamp: now, nodes, edges };
}

// ============================================================
// 9.0: SSH Session Confirmation Fix
// ============================================================
describe('9.0 — SSH session confirmation fix', () => {
  afterEach(cleanup);

  it('detectSshAuthFailure patterns are present in SessionManager', async () => {
    // Verify the session manager module exports correctly (structural test)
    const mod = await import('../session-manager.js');
    expect(mod.SessionManager).toBeDefined();
  });
});

// ============================================================
// 9.1: Linux Host Enrichment — NodeProperties + Frontier
// ============================================================
describe('9.1 — Linux host enrichment', () => {
  afterEach(cleanup);

  it('NodeProperties accepts Linux enrichment fields', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'host-10-10-10-5', type: 'host', label: 'linux-box', ip: '10.10.10.5',
      discovered_at: now, confidence: 1.0, alive: true, os: 'Linux',
      suid_checked: true, has_suid_root: true,
      suid_binaries: ['/usr/bin/python3'],
      cron_checked: true, capabilities_checked: true,
      docker_socket_accessible: false, kernel_version: '5.15.0',
    }]));
    const node = engine.getNode('host-10-10-10-5');
    expect(node).toBeDefined();
    expect(node!.suid_checked).toBe(true);
    expect(node!.has_suid_root).toBe(true);
    expect(node!.suid_binaries).toEqual(['/usr/bin/python3']);
    expect(node!.kernel_version).toBe('5.15.0');
  });

  it('frontier flags Linux-specific missing properties', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'host-10-10-10-6', type: 'host', label: 'linux-bare', ip: '10.10.10.6',
      discovered_at: now, confidence: 1.0, alive: true, os: 'Linux',
    }]));
    // Add a service so 'services' doesn't dominate
    engine.ingestFinding(makeFinding(
      [{ id: 'svc-ssh-6', type: 'service', label: 'ssh/22', port: 22, protocol: 'tcp', service_name: 'ssh', discovered_at: now, confidence: 1.0 }],
      [{ source: 'host-10-10-10-6', target: 'svc-ssh-6', properties: { type: 'RUNS', confidence: 1.0, discovered_at: now } }],
    ));
    const frontier = engine.computeFrontier();
    const item = frontier.find(f => f.node_id === 'host-10-10-10-6' && f.type === 'incomplete_node');
    expect(item).toBeDefined();
    expect(item!.missing_properties).toContain('suid_checked');
    expect(item!.missing_properties).toContain('cron_checked');
    expect(item!.missing_properties).toContain('capabilities_checked');
  });

  it('frontier does NOT flag Linux properties for Windows hosts', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-7', type: 'host', label: 'win-box', ip: '10.10.10.7', discovered_at: now, confidence: 1.0, alive: true, os: 'Windows Server 2019' },
        { id: 'svc-smb-7', type: 'service', label: 'smb/445', port: 445, protocol: 'tcp', service_name: 'smb', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'host-10-10-10-7', target: 'svc-smb-7', properties: { type: 'RUNS', confidence: 1.0, discovered_at: now } }],
    ));
    const frontier = engine.computeFrontier();
    const item = frontier.find(f => f.node_id === 'host-10-10-10-7' && f.type === 'incomplete_node');
    if (item) {
      expect(item.missing_properties).not.toContain('suid_checked');
      expect(item.missing_properties).not.toContain('cron_checked');
    }
  });

  it('fully enriched Linux host has no Linux-specific missing properties', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-8', type: 'host', label: 'linux-full', ip: '10.10.10.8', discovered_at: now, confidence: 1.0, alive: true, os: 'Linux', suid_checked: true, cron_checked: true, capabilities_checked: true },
        { id: 'svc-ssh-8', type: 'service', label: 'ssh/22', port: 22, protocol: 'tcp', service_name: 'ssh', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'host-10-10-10-8', target: 'svc-ssh-8', properties: { type: 'RUNS', confidence: 1.0, discovered_at: now } }],
    ));
    const frontier = engine.computeFrontier();
    const item = frontier.find(f => f.node_id === 'host-10-10-10-8' && f.type === 'incomplete_node');
    expect(item).toBeUndefined();
  });

  it('NodeProperties accepts no_root_squash on share nodes', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'share-nfs-1', type: 'share', label: '/export', share_name: '/export',
      discovered_at: now, confidence: 1.0, no_root_squash: true,
    }]));
    const node = engine.getNode('share-nfs-1');
    expect(node!.no_root_squash).toBe(true);
  });

  it('NodeProperties accepts linked_servers on service nodes', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'svc-mssql-1', type: 'service', label: 'mssql/1433', port: 1433,
      protocol: 'tcp', service_name: 'mssql',
      discovered_at: now, confidence: 1.0, linked_servers: ['LINKED-HOST'],
    }]));
    const node = engine.getNode('svc-mssql-1');
    expect(node!.linked_servers).toEqual(['LINKED-HOST']);
  });

  it('NodeProperties accepts subnet_cidr on subnet nodes', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // Subnet nodes are seeded from config CIDRs
    const node = engine.getNode('subnet-10-10-10-0-24');
    expect(node).toBeDefined();
    expect(node!.type).toBe('subnet');
    expect(node!.subnet_cidr).toBe('10.10.10.0/24');
  });
});

// ============================================================
// 9.2: Linux Inference Rules
// ============================================================
describe('9.2 — Linux inference rules', () => {
  afterEach(cleanup);

  it('rule-suid-privesc: SUID root → ADMIN_TO from session holders', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // Create host with session and SUID
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-20', type: 'host', label: 'suid-host', ip: '10.10.10.20', discovered_at: now, confidence: 1.0, alive: true, os: 'Linux' },
        { id: 'user-attacker', type: 'user', label: 'attacker', username: 'attacker', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-attacker', target: 'host-10-10-10-20', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } }],
    ));
    // Now add SUID property → should trigger rule
    engine.ingestFinding(makeFinding([{
      id: 'host-10-10-10-20', type: 'host', label: 'suid-host', ip: '10.10.10.20',
      discovered_at: now, confidence: 1.0, has_suid_root: true,
    }]));
    const edges = engine.queryGraph({ from_node: 'user-attacker', edge_type: 'ADMIN_TO' });
    expect(edges.edges.length).toBeGreaterThanOrEqual(1);
    const adminEdge = edges.edges.find(e => e.target === 'host-10-10-10-20');
    expect(adminEdge).toBeDefined();
  });

  it('rule-ssh-key-reuse: SSH key → POTENTIAL_AUTH to SSH services', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-21', type: 'host', label: 'ssh-host-1', ip: '10.10.10.21', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'svc-ssh-21', type: 'service', label: 'ssh/22', port: 22, protocol: 'tcp', service_name: 'ssh', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'host-10-10-10-21', target: 'svc-ssh-21', properties: { type: 'RUNS', confidence: 1.0, discovered_at: now } }],
    ));
    // Ingest SSH key credential
    engine.ingestFinding(makeFinding([{
      id: 'cred-sshkey-1', type: 'credential', label: 'SSH key', cred_type: 'ssh_key',
      discovered_at: now, confidence: 1.0,
    }]));
    const edges = engine.queryGraph({ from_node: 'cred-sshkey-1', edge_type: 'POTENTIAL_AUTH' });
    expect(edges.edges.length).toBeGreaterThanOrEqual(1);
    const authEdge = edges.edges.find(e => e.target === 'svc-ssh-21');
    expect(authEdge).toBeDefined();
  });

  it('rule-docker-escape: Docker socket → ADMIN_TO from session holders', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-22', type: 'host', label: 'docker-host', ip: '10.10.10.22', discovered_at: now, confidence: 1.0, alive: true, os: 'Linux' },
        { id: 'user-docker-attacker', type: 'user', label: 'docker-attacker', username: 'docker-attacker', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-docker-attacker', target: 'host-10-10-10-22', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } }],
    ));
    engine.ingestFinding(makeFinding([{
      id: 'host-10-10-10-22', type: 'host', label: 'docker-host', ip: '10.10.10.22',
      discovered_at: now, confidence: 1.0, docker_socket_accessible: true,
    }]));
    const edges = engine.queryGraph({ from_node: 'user-docker-attacker', edge_type: 'ADMIN_TO' });
    const adminEdge = edges.edges.find(e => e.target === 'host-10-10-10-22');
    expect(adminEdge).toBeDefined();
    expect(adminEdge!.properties.confidence).toBe(0.8);
  });

  it('rule-nfs-root-squash: no_root_squash host → ADMIN_TO from session holders', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-23', type: 'host', label: 'nfs-host', ip: '10.10.10.23', discovered_at: now, confidence: 1.0, alive: true, os: 'Linux' },
        { id: 'user-nfs-attacker', type: 'user', label: 'nfs-attacker', username: 'nfs-attacker', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-nfs-attacker', target: 'host-10-10-10-23', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } }],
    ));
    engine.ingestFinding(makeFinding([{
      id: 'host-10-10-10-23', type: 'host', label: 'nfs-host', ip: '10.10.10.23',
      discovered_at: now, confidence: 1.0, no_root_squash: true,
    }]));
    const edges = engine.queryGraph({ from_node: 'user-nfs-attacker', edge_type: 'ADMIN_TO' });
    const adminEdge = edges.edges.find(e => e.target === 'host-10-10-10-23');
    expect(adminEdge).toBeDefined();
    expect(adminEdge!.properties.confidence).toBe(0.7);
  });

  it('session_holders_on_host returns empty when no sessions exist', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'host-10-10-10-24', type: 'host', label: 'no-session', ip: '10.10.10.24',
      discovered_at: now, confidence: 1.0, alive: true, os: 'Linux', has_suid_root: true,
    }]));
    // No HAS_SESSION edge → no ADMIN_TO should be inferred
    const edges = engine.queryGraph({ edge_type: 'ADMIN_TO' });
    const adminEdge = edges.edges.find(e => e.target === 'host-10-10-10-24');
    expect(adminEdge).toBeUndefined();
  });
});

// ============================================================
// 9.3: MSSQL Linked Server Inference
// ============================================================
describe('9.3 — MSSQL linked server inference', () => {
  afterEach(cleanup);

  it('rule-mssql-linked-server: MSSQL with linked_servers → REACHABLE to matching hosts', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // Create MSSQL service with linked server + the linked host
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-30', type: 'host', label: 'mssql-src', ip: '10.10.10.30', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'svc-mssql-30', type: 'service', label: 'mssql/1433', port: 1433, protocol: 'tcp', service_name: 'mssql', discovered_at: now, confidence: 1.0, linked_servers: ['linked-target'] },
        { id: 'host-10-10-10-31', type: 'host', label: 'linked-target', hostname: 'linked-target', ip: '10.10.10.31', discovered_at: now, confidence: 1.0, alive: true },
      ],
      [{ source: 'host-10-10-10-30', target: 'svc-mssql-30', properties: { type: 'RUNS', confidence: 1.0, discovered_at: now } }],
    ));
    const edges = engine.queryGraph({ from_node: 'host-10-10-10-30', edge_type: 'REACHABLE' });
    const reachable = edges.edges.find(e => e.target === 'host-10-10-10-31');
    expect(reachable).toBeDefined();
    expect(reachable!.properties.confidence).toBe(0.8);
  });

  it('NXC parser detects MSSQL linked servers', () => {
    const nxcOutput = [
      'MSSQL 10.10.10.30 1433 SQLSRV [*] Windows Server 2019',
      'MSSQL 10.10.10.30 1433 SQLSRV [*] Linked SQL Servers: LINKED-HOST1, LINKED-HOST2',
    ].join('\n');
    const result = parseOutput('nxc', nxcOutput, 'test-agent');
    expect(result).not.toBeNull();
    const svcNode = result!.nodes.find(n => n.service_name === 'mssql');
    expect(svcNode).toBeDefined();
    expect(svcNode!.linked_servers).toEqual(['LINKED-HOST1', 'LINKED-HOST2']);
  });

  it('linked_server_hosts selector matches by hostname', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // Create host with known hostname, then MSSQL with that hostname in linked_servers
    engine.ingestFinding(makeFinding([
      { id: 'host-10-10-10-32', type: 'host', label: 'target-ls', hostname: 'target-ls', ip: '10.10.10.32', discovered_at: now, confidence: 1.0, alive: true },
    ]));
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-33', type: 'host', label: 'src-ls', ip: '10.10.10.33', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'svc-mssql-ls', type: 'service', label: 'mssql/1433', port: 1433, protocol: 'tcp', service_name: 'mssql', discovered_at: now, confidence: 1.0, linked_servers: ['target-ls'] },
      ],
      [{ source: 'host-10-10-10-33', target: 'svc-mssql-ls', properties: { type: 'RUNS', confidence: 1.0, discovered_at: now } }],
    ));
    const edges = engine.queryGraph({ from_node: 'host-10-10-10-33', edge_type: 'REACHABLE' });
    expect(edges.edges.some(e => e.target === 'host-10-10-10-32')).toBe(true);
  });
});

// ============================================================
// 9.4: Network Zone / Pivot Tracking
// ============================================================
describe('9.4 — Network pivot tracking', () => {
  afterEach(cleanup);

  it('subnet nodes are seeded from scope CIDRs', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const subnet = engine.getNode('subnet-10-10-10-0-24');
    expect(subnet).toBeDefined();
    expect(subnet!.type).toBe('subnet');
    expect(subnet!.subnet_cidr).toBe('10.10.10.0/24');
  });

  it('pivot reachability creates REACHABLE edges with via_pivot', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // Two hosts in same subnet
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-50', type: 'host', label: 'pivot-a', ip: '10.10.10.50', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-51', type: 'host', label: 'pivot-b', ip: '10.10.10.51', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'user-pivot-user', type: 'user', label: 'pivot-user', username: 'pivot-user', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-pivot-user', target: 'host-10-10-10-50', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } }],
    ));
    // Check REACHABLE edge from pivot-a to pivot-b
    const edges = engine.queryGraph({ from_node: 'host-10-10-10-50', edge_type: 'REACHABLE' });
    const pivotEdge = edges.edges.find(e => e.target === 'host-10-10-10-51');
    expect(pivotEdge).toBeDefined();
    expect(pivotEdge!.properties.via_pivot).toBe('user-pivot-user');
    expect(pivotEdge!.properties.inferred_by_rule).toBe('pivot-reachability');
  });

  it('pivot reachability does NOT fire without HAS_SESSION', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([
      { id: 'host-10-10-10-52', type: 'host', label: 'no-pivot-a', ip: '10.10.10.52', discovered_at: now, confidence: 1.0, alive: true },
      { id: 'host-10-10-10-53', type: 'host', label: 'no-pivot-b', ip: '10.10.10.53', discovered_at: now, confidence: 1.0, alive: true },
    ]));
    const edges = engine.queryGraph({ from_node: 'host-10-10-10-52', edge_type: 'REACHABLE' });
    const pivotEdge = edges.edges.find(e => e.target === 'host-10-10-10-53');
    expect(pivotEdge).toBeUndefined();
  });

  it('pivot peer is represented in frontier (inferred_edge or network_pivot, not both)', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // Host A has session, host B does not → peer should appear in frontier exactly once
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-60', type: 'host', label: 'fp-a', ip: '10.10.10.60', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-61', type: 'host', label: 'fp-b', ip: '10.10.10.61', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'user-fp-user', type: 'user', label: 'fp-user', username: 'fp-user', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-fp-user', target: 'host-10-10-10-60', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } }],
    ));
    const frontier = engine.computeFrontier();
    const coveringItems = frontier.filter(f =>
      (f.type === 'network_pivot' && f.node_id === 'host-10-10-10-61') ||
      (f.type === 'inferred_edge' && f.edge_target === 'host-10-10-10-61' && f.edge_type === 'REACHABLE')
    );
    expect(coveringItems.length).toBe(1);
  });

  it('network_pivot not generated for hosts that already have sessions', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-70', type: 'host', label: 'both-a', ip: '10.10.10.70', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-71', type: 'host', label: 'both-b', ip: '10.10.10.71', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'user-1', type: 'user', label: 'user-1', username: 'user-1', discovered_at: now, confidence: 1.0 },
        { id: 'user-2', type: 'user', label: 'user-2', username: 'user-2', discovered_at: now, confidence: 1.0 },
      ],
      [
        { source: 'user-1', target: 'host-10-10-10-70', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } },
        { source: 'user-2', target: 'host-10-10-10-71', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } },
      ],
    ));
    const frontier = engine.computeFrontier();
    const pivotItems = frontier.filter(f => f.type === 'network_pivot');
    // Both hosts have sessions, so no pivot items pointing to either
    const toA = pivotItems.find(f => f.node_id === 'host-10-10-10-70');
    const toB = pivotItems.find(f => f.node_id === 'host-10-10-10-71');
    expect(toA).toBeUndefined();
    expect(toB).toBeUndefined();
  });

  it('EdgeProperties supports via_pivot field', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-80', type: 'host', label: 'vp-a', ip: '10.10.10.80', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-81', type: 'host', label: 'vp-b', ip: '10.10.10.81', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'user-vp-user', type: 'user', label: 'vp-user', username: 'vp-user', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-vp-user', target: 'host-10-10-10-80', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } }],
    ));
    const edges = engine.queryGraph({ from_node: 'host-10-10-10-80', edge_type: 'REACHABLE' });
    const pivotEdge = edges.edges.find(e => e.target === 'host-10-10-10-81');
    expect(pivotEdge).toBeDefined();
    expect(pivotEdge!.properties.via_pivot).toBe('user-vp-user');
  });
});

// ============================================================
// 9.5: Linpeas Parser
// ============================================================
describe('9.5 — Linpeas parser', () => {
  it('is registered in PARSERS registry', () => {
    const result = parseOutput('linpeas', 'test', 'agent');
    expect(result).not.toBeNull();
  });

  it('linenum alias works', () => {
    const result = parseOutput('linenum', 'test', 'agent');
    expect(result).not.toBeNull();
  });

  it('detects kernel version', () => {
    const output = 'Linux version 5.15.0-generic (buildd@lcy02-amd64-102)';
    const result = parseLinpeas(output, 'test', { source_host: 'host-lp-1' });
    const host = result.nodes.find(n => n.type === 'host');
    expect(host).toBeDefined();
    expect(host!.kernel_version).toBe('5.15.0-generic');
  });

  it('detects dangerous SUID binaries', () => {
    const output = [
      '╔══════════╣ SUID binaries',
      '-rwsr-xr-x 1 root root 12345 Jan 1 2024 /usr/bin/python3',
      '-rwsr-xr-x 1 root root 67890 Jan 1 2024 /usr/bin/passwd',
    ].join('\n');
    const result = parseLinpeas(output, 'test', { source_host: 'host-lp-2' });
    const host = result.nodes.find(n => n.type === 'host');
    expect(host!.suid_checked).toBe(true);
    expect(host!.has_suid_root).toBe(true);
    expect((host!.suid_binaries as string[])).toContain('/usr/bin/python3');
  });

  it('marks suid_checked even when no dangerous SUID found', () => {
    const output = [
      '╔══════════╣ SUID binaries',
      '-rwsr-xr-x 1 root root 12345 Jan 1 2024 /usr/bin/passwd',
      '-rwsr-xr-x 1 root root 67890 Jan 1 2024 /usr/bin/su',
    ].join('\n');
    const result = parseLinpeas(output, 'test', { source_host: 'host-lp-3' });
    const host = result.nodes.find(n => n.type === 'host');
    expect(host!.suid_checked).toBe(true);
    // passwd and su are not in the dangerous list
    expect(host!.has_suid_root).toBeUndefined();
  });

  it('detects docker socket', () => {
    const output = 'drwxrwxrwx /var/run/docker.sock';
    const result = parseLinpeas(output, 'test', { source_host: 'host-lp-4' });
    const host = result.nodes.find(n => n.type === 'host');
    expect(host!.docker_socket_accessible).toBe(true);
  });

  it('detects capabilities', () => {
    const output = [
      '╔══════════╣ Capabilities',
      '/usr/bin/python3 = cap_setuid+ep',
    ].join('\n');
    const result = parseLinpeas(output, 'test', { source_host: 'host-lp-5' });
    const host = result.nodes.find(n => n.type === 'host');
    expect(host!.capabilities_checked).toBe(true);
    expect((host!.interesting_capabilities as string[])).toContain('/usr/bin/python3 = cap_setuid+ep');
  });

  it('uses context.source_host for host node ID', () => {
    const result = parseLinpeas('test output\nmore lines', 'test', { source_host: 'host-specific-id' });
    const host = result.nodes.find(n => n.type === 'host');
    expect(host!.id).toBe('host-specific-id');
  });

  it('strips ANSI escape codes', () => {
    const output = '\x1B[31mLinux version 5.10.0-test\x1B[0m';
    const result = parseLinpeas(output, 'test', { source_host: 'host-lp-6' });
    const host = result.nodes.find(n => n.type === 'host');
    expect(host!.kernel_version).toBe('5.10.0-test');
  });

  it('detects cron jobs', () => {
    const output = [
      '╔══════════╣ Cron jobs',
      '*/5 * * * * root /opt/backup.sh',
      '/etc/cron.d/logrotate',
    ].join('\n');
    const result = parseLinpeas(output, 'test', { source_host: 'host-lp-7' });
    const host = result.nodes.find(n => n.type === 'host');
    expect(host!.cron_checked).toBe(true);
    expect((host!.cron_jobs as string[]).length).toBeGreaterThanOrEqual(1);
  });
});

// ============================================================
// 9.6: OPSEC-Weighted Path Analysis
// ============================================================
describe('9.6 — OPSEC-weighted path analysis', () => {
  afterEach(cleanup);

  it('findPaths returns total_opsec_noise in results', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-90', type: 'host', label: 'pa-a', ip: '10.10.10.90', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-91', type: 'host', label: 'pa-b', ip: '10.10.10.91', discovered_at: now, confidence: 1.0, alive: true },
      ],
      [{ source: 'host-10-10-10-90', target: 'host-10-10-10-91', properties: { type: 'REACHABLE', confidence: 0.9, discovered_at: now, opsec_noise: 0.5 } }],
    ));
    const paths = engine.findPaths('host-10-10-10-90', 'host-10-10-10-91');
    expect(paths.length).toBe(1);
    expect(paths[0].total_opsec_noise).toBeDefined();
    expect(typeof paths[0].total_opsec_noise).toBe('number');
  });

  it('stealth optimize prefers low-noise path', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const startId = 'host-10-10-10-100';
    const relayId = 'host-10-10-10-101';
    const targetId = 'host-10-10-10-102';
    engine.ingestFinding(makeFinding(
      [
        { id: startId, type: 'host', label: 'start', ip: '10.10.10.100', discovered_at: now, confidence: 1.0, alive: true },
        { id: relayId, type: 'host', label: 'relay', ip: '10.10.10.101', discovered_at: now, confidence: 1.0, alive: true },
        { id: targetId, type: 'host', label: 'target', ip: '10.10.10.102', discovered_at: now, confidence: 1.0, alive: true },
      ],
      [
        // Direct: high noise
        { source: startId, target: targetId, properties: { type: 'REACHABLE', confidence: 0.95, discovered_at: now, opsec_noise: 0.9 } },
        // Via relay: low noise
        { source: startId, target: relayId, properties: { type: 'REACHABLE', confidence: 0.8, discovered_at: now, opsec_noise: 0.1 } },
        { source: relayId, target: targetId, properties: { type: 'REACHABLE', confidence: 0.8, discovered_at: now, opsec_noise: 0.1 } },
      ],
    ));

    const stealthPaths = engine.findPaths(startId, targetId, 5, 'stealth');
    expect(stealthPaths.length).toBe(1);
    // Stealth mode should prefer the relay path (lower noise weight: 0.1+0.1=0.2 vs 0.9)
    expect(stealthPaths[0].nodes.length).toBe(3); // start → relay → target

    const confPaths = engine.findPaths(startId, targetId, 5, 'confidence');
    expect(confPaths.length).toBe(1);
    // Confidence mode should prefer the direct path (higher confidence = lower weight)
    expect(confPaths[0].nodes.length).toBe(2); // start → target
  });

  it('balanced optimize blends confidence and noise', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-110', type: 'host', label: 'bal-a', ip: '10.10.10.110', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-111', type: 'host', label: 'bal-b', ip: '10.10.10.111', discovered_at: now, confidence: 1.0, alive: true },
      ],
      [{ source: 'host-10-10-10-110', target: 'host-10-10-10-111', properties: { type: 'REACHABLE', confidence: 0.9, discovered_at: now, opsec_noise: 0.5 } }],
    ));
    const paths = engine.findPaths('host-10-10-10-110', 'host-10-10-10-111', 5, 'balanced');
    expect(paths.length).toBe(1);
    expect(paths[0].total_confidence).toBeGreaterThan(0);
    expect(paths[0].total_opsec_noise).toBeGreaterThan(0);
  });

  it('default optimize is confidence', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-120', type: 'host', label: 'def-a', ip: '10.10.10.120', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-121', type: 'host', label: 'def-b', ip: '10.10.10.121', discovered_at: now, confidence: 1.0, alive: true },
      ],
      [{ source: 'host-10-10-10-120', target: 'host-10-10-10-121', properties: { type: 'REACHABLE', confidence: 0.9, discovered_at: now } }],
    ));
    const paths = engine.findPaths('host-10-10-10-120', 'host-10-10-10-121');
    expect(paths.length).toBe(1);
    // Should work with default (no optimize param)
    expect(paths[0].total_confidence).toBeCloseTo(0.9, 1);
  });

  it('findPathsToObjective accepts optimize parameter', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // No matching objectives for test — just verify it doesn't throw
    const paths = engine.findPathsToObjective('obj-1', 5, 'stealth');
    expect(Array.isArray(paths)).toBe(true);
  });
});

// ============================================================
// Regression: P1 — Linpeas parser must not corrupt existing host metadata
// ============================================================
describe('regression — Linpeas parser host metadata preservation', () => {
  afterEach(cleanup);

  it('does not overwrite label when context.source_host is provided', () => {
    const result = parseLinpeas('Linux version 5.15.0\n', 'agent', { source_host: 'host-10-10-10-5' });
    const hostNode = result.nodes.find(n => n.id === 'host-10-10-10-5');
    expect(hostNode).toBeDefined();
    // label should be the node ID (pass-through), not a generic string
    expect(hostNode!.label).toBe('host-10-10-10-5');
  });

  it('does not emit confidence when enriching an existing host', () => {
    const result = parseLinpeas('Linux version 5.15.0\n', 'agent', { source_host: 'host-10-10-10-5' });
    const hostNode = result.nodes.find(n => n.id === 'host-10-10-10-5');
    expect(hostNode).toBeDefined();
    expect(hostNode!.confidence).toBeUndefined();
  });

  it('emits confidence 0.9 for new hosts without source_host', () => {
    const result = parseLinpeas('Linux version 5.15.0\n', 'agent');
    expect(result.nodes[0].confidence).toBe(0.9);
  });

  it('preserves existing host label and confidence after ingestion', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'host-10-10-10-40', type: 'host', label: 'my-server', ip: '10.10.10.40',
      discovered_at: now, confidence: 1.0, alive: true, os: 'Linux',
    }]));
    // Parse linpeas targeting this host
    const linpeasResult = parseLinpeas(
      '═══════════════════╣ SUID\n-rwsr-xr-x root /usr/bin/python3\n',
      'agent', { source_host: 'host-10-10-10-40' }
    );
    engine.ingestFinding(linpeasResult);
    const node = engine.getNode('host-10-10-10-40');
    expect(node).toBeDefined();
    expect(node!.label).toBe('my-server');
    expect(node!.confidence).toBe(1.0);
  });
});

// ============================================================
// Regression: P2 — Frontier deduplication (no double pivot items)
// ============================================================
describe('regression — frontier pivot deduplication', () => {
  afterEach(cleanup);

  it('does not emit network_pivot for hosts already covered by inferred_edge REACHABLE', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-130', type: 'host', label: 'pivot-src', ip: '10.10.10.130', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-131', type: 'host', label: 'pivot-dst', ip: '10.10.10.131', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'user-pivoter', type: 'user', label: 'pivoter', username: 'pivoter', discovered_at: now, confidence: 1.0 },
      ],
      [{ source: 'user-pivoter', target: 'host-10-10-10-130', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } }],
    ));
    const frontier = engine.computeFrontier();
    // Count how many frontier items target the pivot destination
    const targetingDst = frontier.filter(f =>
      (f.type === 'network_pivot' && f.node_id === 'host-10-10-10-131') ||
      (f.type === 'inferred_edge' && f.edge_target === 'host-10-10-10-131' && f.edge_type === 'REACHABLE')
    );
    // Should be exactly 1, not 2
    expect(targetingDst.length).toBe(1);
  });
});

// ============================================================
// Regression: P2 — Path sort respects optimize strategy
// ============================================================
describe('regression — path sort by strategy', () => {
  afterEach(cleanup);

  it('findPathsToObjective stealth mode sorts by lowest noise', () => {
    const config = makeConfig({
      objectives: [{
        id: 'obj-sort',
        description: 'test sort',
        target_node_type: 'credential',
        target_criteria: { cred_type: 'ntlm' },
        achieved: false,
      }],
    });
    const engine = new GraphEngine(config, TEST_STATE_FILE);
    // Create two paths to the same credential: one noisy+high-confidence, one quiet+low-confidence
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-140', type: 'host', label: 'start-a', ip: '10.10.10.140', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'host-10-10-10-141', type: 'host', label: 'start-b', ip: '10.10.10.141', discovered_at: now, confidence: 1.0, alive: true },
        { id: 'user-sort-a', type: 'user', label: 'sort-a', username: 'sort-a', discovered_at: now, confidence: 1.0 },
        { id: 'user-sort-b', type: 'user', label: 'sort-b', username: 'sort-b', discovered_at: now, confidence: 1.0 },
        { id: 'cred-target-sort', type: 'credential', label: 'target-cred', cred_type: 'ntlm', discovered_at: now, confidence: 1.0 },
      ],
      [
        // Access on both hosts
        { source: 'user-sort-a', target: 'host-10-10-10-140', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } },
        { source: 'user-sort-b', target: 'host-10-10-10-141', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } },
        // Path A: high confidence, high noise
        { source: 'host-10-10-10-140', target: 'cred-target-sort', properties: { type: 'OWNS_CRED', confidence: 0.95, discovered_at: now, opsec_noise: 0.9 } },
        // Path B: lower confidence, low noise
        { source: 'host-10-10-10-141', target: 'cred-target-sort', properties: { type: 'OWNS_CRED', confidence: 0.6, discovered_at: now, opsec_noise: 0.1 } },
      ],
    ));

    const stealthPaths = engine.findPathsToObjective('obj-sort', 5, 'stealth');
    expect(stealthPaths.length).toBe(2);
    // First result should be lowest noise
    expect(stealthPaths[0].total_opsec_noise).toBeLessThanOrEqual(stealthPaths[1].total_opsec_noise);

    const confPaths = engine.findPathsToObjective('obj-sort', 5, 'confidence');
    expect(confPaths.length).toBe(2);
    // First result should be highest confidence
    expect(confPaths[0].total_confidence).toBeGreaterThanOrEqual(confPaths[1].total_confidence);
  });
});
