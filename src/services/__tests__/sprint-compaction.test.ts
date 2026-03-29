import { describe, it, expect, afterEach } from 'vitest';
import { GraphEngine } from '../graph-engine.js';
import { ColdStore, classifyNodeTemperature, toColdRecord, isInterestingEdgeType } from '../cold-store.js';
import type { EngagementConfig, Finding, NodeProperties } from '../../types.js';
import { unlinkSync, existsSync } from 'fs';

const TEST_STATE_FILE = './state-test-compaction.json';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-compaction',
    name: 'Compaction Test',
    created_at: '2026-04-01T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/24', '192.168.1.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [{
      id: 'obj-1',
      description: 'Compromise DC',
      target_node_type: 'host',
      target_criteria: { hostname: 'dc01' },
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
  return { id: `f-${Date.now()}-${Math.random()}`, agent_id: 'test', timestamp: now, nodes, edges };
}

function createEngine(overrides: Partial<EngagementConfig> = {}): GraphEngine {
  return new GraphEngine(makeConfig(overrides), TEST_STATE_FILE);
}

// ============================================================
// Phase 1: classifyNodeTemperature
// ============================================================

describe('classifyNodeTemperature', () => {
  it('classifies alive IP-only host with no services/edges as cold', () => {
    const node = { id: 'host-1', type: 'host' as const, alive: true };
    expect(classifyNodeTemperature(node, false)).toBe('cold');
  });

  it('classifies alive host with interesting edge as hot', () => {
    const node = { id: 'host-1', type: 'host' as const, alive: true };
    expect(classifyNodeTemperature(node, true)).toBe('hot');
  });

  it('classifies dead host as hot (needs scope tracking)', () => {
    const node = { id: 'host-1', type: 'host' as const, alive: false };
    expect(classifyNodeTemperature(node, false)).toBe('hot');
  });

  it('classifies host with alive=undefined as hot', () => {
    const node = { id: 'host-1', type: 'host' as const };
    expect(classifyNodeTemperature(node, false)).toBe('hot');
  });

  it('classifies host with hostname as hot (identity-bearing)', () => {
    const node = { id: 'host-1', type: 'host' as const, alive: true, hostname: 'dc01.test.local' };
    expect(classifyNodeTemperature(node, false)).toBe('hot');
  });

  it('classifies host with OS as hot (enriched beyond ping)', () => {
    const node = { id: 'host-1', type: 'host' as const, alive: true, os: 'Linux' };
    expect(classifyNodeTemperature(node, false)).toBe('hot');
  });

  it('classifies non-host types as always hot', () => {
    for (const type of ['service', 'user', 'credential', 'domain', 'group', 'webapp', 'vulnerability', 'cloud_identity', 'subnet', 'objective']) {
      const node = { id: `${type}-1`, type: type as any };
      expect(classifyNodeTemperature(node, false)).toBe('hot');
    }
  });

  it('defaults to hot for safety', () => {
    const node = { id: 'host-1', type: 'host' as const, alive: true };
    // Even though alive with no edges, if hasInterestingEdge is true → hot
    expect(classifyNodeTemperature(node, true)).toBe('hot');
  });
});

// ============================================================
// Phase 1: isInterestingEdgeType
// ============================================================

describe('isInterestingEdgeType', () => {
  it('recognizes HAS_SESSION as interesting', () => {
    expect(isInterestingEdgeType('HAS_SESSION')).toBe(true);
  });

  it('recognizes ADMIN_TO as interesting', () => {
    expect(isInterestingEdgeType('ADMIN_TO')).toBe(true);
  });

  it('recognizes RUNS as interesting', () => {
    expect(isInterestingEdgeType('RUNS')).toBe(true);
  });

  it('does not consider RELATED as interesting', () => {
    expect(isInterestingEdgeType('RELATED')).toBe(false);
  });

  it('does not consider MEMBER_OF as interesting', () => {
    expect(isInterestingEdgeType('MEMBER_OF')).toBe(false);
  });
});

// ============================================================
// Phase 1: ColdStore unit tests
// ============================================================

describe('ColdStore', () => {
  it('add/get/has round-trip', () => {
    const store = new ColdStore();
    const record = {
      id: 'host-10-10-10-5',
      type: 'host',
      label: '10.10.10.5',
      ip: '10.10.10.5',
      discovered_at: now,
      last_seen_at: now,
      subnet_cidr: '10.10.10.0/24',
      alive: true,
    };
    store.add(record);
    expect(store.has('host-10-10-10-5')).toBe(true);
    expect(store.get('host-10-10-10-5')).toEqual(record);
    expect(store.count()).toBe(1);
  });

  it('promote removes from store and returns record', () => {
    const store = new ColdStore();
    store.add({ id: 'h1', type: 'host', label: 'h1', discovered_at: now, last_seen_at: now });
    const promoted = store.promote('h1');
    expect(promoted).toBeDefined();
    expect(promoted!.id).toBe('h1');
    expect(store.has('h1')).toBe(false);
    expect(store.count()).toBe(0);
  });

  it('promote returns undefined for missing node', () => {
    const store = new ColdStore();
    expect(store.promote('nonexistent')).toBeUndefined();
  });

  it('countBySubnet groups correctly', () => {
    const store = new ColdStore();
    store.add({ id: 'h1', type: 'host', label: 'h1', discovered_at: now, last_seen_at: now, subnet_cidr: '10.0.0.0/24' });
    store.add({ id: 'h2', type: 'host', label: 'h2', discovered_at: now, last_seen_at: now, subnet_cidr: '10.0.0.0/24' });
    store.add({ id: 'h3', type: 'host', label: 'h3', discovered_at: now, last_seen_at: now, subnet_cidr: '192.168.1.0/24' });
    const counts = store.countBySubnet();
    expect(counts['10.0.0.0/24']).toBe(2);
    expect(counts['192.168.1.0/24']).toBe(1);
  });

  it('export/import round-trip', () => {
    const store = new ColdStore();
    store.add({ id: 'h1', type: 'host', label: 'h1', discovered_at: now, last_seen_at: now, subnet_cidr: '10.0.0.0/24' });
    store.add({ id: 'h2', type: 'host', label: 'h2', discovered_at: now, last_seen_at: now });
    const exported = store.export();
    expect(exported).toHaveLength(2);

    const store2 = new ColdStore();
    store2.import(exported);
    expect(store2.count()).toBe(2);
    expect(store2.has('h1')).toBe(true);
    expect(store2.has('h2')).toBe(true);
  });

  it('merge on re-add keeps earliest discovered_at and latest last_seen_at', () => {
    const store = new ColdStore();
    store.add({ id: 'h1', type: 'host', label: 'h1', discovered_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:00Z' });
    store.add({ id: 'h1', type: 'host', label: 'h1', discovered_at: '2026-02-01T00:00:00Z', last_seen_at: '2026-03-01T00:00:00Z' });
    const record = store.get('h1')!;
    expect(record.discovered_at).toBe('2026-01-01T00:00:00Z');
    expect(record.last_seen_at).toBe('2026-03-01T00:00:00Z');
  });
});

// ============================================================
// Phase 1: toColdRecord
// ============================================================

describe('toColdRecord', () => {
  it('extracts minimal fields from NodeProperties', () => {
    const node: NodeProperties = {
      id: 'host-10-10-10-5',
      type: 'host',
      label: '10.10.10.5',
      ip: '10.10.10.5',
      hostname: 'box1',
      discovered_at: now,
      last_seen_at: now,
      discovered_by: 'agent-1',
      alive: true,
      confidence: 1.0,
    };
    const record = toColdRecord(node, '10.10.10.0/24');
    expect(record.id).toBe('host-10-10-10-5');
    expect(record.type).toBe('host');
    expect(record.ip).toBe('10.10.10.5');
    expect(record.hostname).toBe('box1');
    expect(record.subnet_cidr).toBe('10.10.10.0/24');
    expect(record.provenance).toBe('agent-1');
    expect(record.alive).toBe(true);
  });
});

// ============================================================
// Phase 1: Integration — ingestFinding with compaction
// ============================================================

describe('Graph compaction integration', () => {
  afterEach(cleanup);

  it('diverts ping-only host to cold store', () => {
    const engine = createEngine();
    engine.ingestFinding(makeFinding([
      { id: 'host-10-10-10-5', type: 'host', label: '10.10.10.5', ip: '10.10.10.5', alive: true },
    ]));

    // Should NOT be in the hot graph
    expect(engine.getNode('host-10-10-10-5')).toBeNull();
    // Should be in the cold store
    const state = engine.getState();
    expect(state.graph_summary.cold_node_count).toBe(1);
  });

  it('keeps host with services in hot graph', () => {
    const engine = createEngine();
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-5', type: 'host', label: '10.10.10.5', ip: '10.10.10.5', alive: true },
        { id: 'svc-smb', type: 'service', label: 'smb', port: 445, service_name: 'smb' },
      ],
      [
        { source: 'host-10-10-10-5', target: 'svc-smb', properties: { type: 'RUNS', confidence: 1.0 } },
      ],
    ));

    // Host should be in hot graph because it has a RUNS edge (edge promotion guard)
    expect(engine.getNode('host-10-10-10-5')).not.toBeNull();
    expect(engine.getState().graph_summary.cold_node_count).toBe(0);
  });

  it('promotes cold host when edge arrives later', () => {
    const engine = createEngine();

    // First: ingest ping-only host → goes cold
    engine.ingestFinding(makeFinding([
      { id: 'host-10-10-10-5', type: 'host', label: '10.10.10.5', ip: '10.10.10.5', alive: true },
    ]));
    expect(engine.getNode('host-10-10-10-5')).toBeNull();
    expect(engine.getState().graph_summary.cold_node_count).toBe(1);

    // Second: ingest a service for that host → edge promotion guard kicks in
    engine.ingestFinding(makeFinding(
      [
        { id: 'svc-ssh', type: 'service', label: 'ssh', port: 22, service_name: 'ssh' },
      ],
      [
        { source: 'host-10-10-10-5', target: 'svc-ssh', properties: { type: 'RUNS', confidence: 1.0 } },
      ],
    ));

    // Host should now be promoted to hot graph
    expect(engine.getNode('host-10-10-10-5')).not.toBeNull();
    expect(engine.getNode('host-10-10-10-5')!.alive).toBe(true);
    expect(engine.getState().graph_summary.cold_node_count).toBe(0);
  });

  it('promotes cold host when re-ingested with services', () => {
    const engine = createEngine();

    // Ingest ping-only → cold
    engine.ingestFinding(makeFinding([
      { id: 'host-10-10-10-7', type: 'host', label: '10.10.10.7', ip: '10.10.10.7', alive: true },
    ]));
    expect(engine.getState().graph_summary.cold_node_count).toBe(1);

    // Re-ingest same host with more properties → should promote (wasCold path)
    engine.ingestFinding(makeFinding([
      { id: 'host-10-10-10-7', type: 'host', label: '10.10.10.7', ip: '10.10.10.7', alive: true, os: 'Linux' },
    ]));
    expect(engine.getNode('host-10-10-10-7')).not.toBeNull();
    expect(engine.getNode('host-10-10-10-7')!.os).toBe('Linux');
    expect(engine.getState().graph_summary.cold_node_count).toBe(0);
  });

  it('dead host stays in hot graph', () => {
    const engine = createEngine();
    engine.ingestFinding(makeFinding([
      { id: 'host-10-10-10-99', type: 'host', label: '10.10.10.99', ip: '10.10.10.99', alive: false },
    ]));
    // Dead hosts are hot (alive !== true)
    expect(engine.getNode('host-10-10-10-99')).not.toBeNull();
    expect(engine.getState().graph_summary.cold_node_count).toBe(0);
  });

  it('non-host types are never cold', () => {
    const engine = createEngine();
    engine.ingestFinding(makeFinding([
      { id: 'user-bob', type: 'user', label: 'bob', username: 'bob' },
      { id: 'cred-1', type: 'credential', label: 'bob-ntlm', cred_type: 'ntlm', cred_value: 'hash' },
    ]));
    expect(engine.getNode('user-bob')).not.toBeNull();
    expect(engine.getNode('cred-1')).not.toBeNull();
    expect(engine.getState().graph_summary.cold_node_count).toBe(0);
  });

  it('multiple cold hosts tracked by subnet', () => {
    const engine = createEngine();
    engine.ingestFinding(makeFinding([
      { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', alive: true },
      { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2', alive: true },
      { id: 'host-192-168-1-1', type: 'host', label: '192.168.1.1', ip: '192.168.1.1', alive: true },
    ]));

    const state = engine.getState();
    expect(state.graph_summary.cold_node_count).toBe(3);
    expect(state.graph_summary.cold_nodes_by_subnet).toBeDefined();
    expect(state.graph_summary.cold_nodes_by_subnet!['10.10.10.0/24']).toBe(2);
    expect(state.graph_summary.cold_nodes_by_subnet!['192.168.1.0/24']).toBe(1);
  });

  it('already-hot nodes are never demoted on re-ingest', () => {
    const engine = createEngine();

    // First: host with a service → hot
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-5', type: 'host', label: '10.10.10.5', ip: '10.10.10.5', alive: true },
        { id: 'svc-http', type: 'service', label: 'http', port: 80, service_name: 'http' },
      ],
      [
        { source: 'host-10-10-10-5', target: 'svc-http', properties: { type: 'RUNS', confidence: 1.0 } },
      ],
    ));
    expect(engine.getNode('host-10-10-10-5')).not.toBeNull();

    // Re-ingest same host without edge info → should stay hot (alreadyHot path)
    engine.ingestFinding(makeFinding([
      { id: 'host-10-10-10-5', type: 'host', label: '10.10.10.5', ip: '10.10.10.5', alive: true },
    ]));
    expect(engine.getNode('host-10-10-10-5')).not.toBeNull();
    expect(engine.getState().graph_summary.cold_node_count).toBe(0);
  });

  it('cold store persists through save/load cycle', () => {
    const engine = createEngine();
    engine.ingestFinding(makeFinding([
      { id: 'host-10-10-10-5', type: 'host', label: '10.10.10.5', ip: '10.10.10.5', alive: true },
    ]));
    expect(engine.getState().graph_summary.cold_node_count).toBe(1);

    // Load a fresh engine from the same state file
    const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    expect(engine2.getState().graph_summary.cold_node_count).toBe(1);
  });

  it('cold_nodes_by_subnet omitted when cold store is empty', () => {
    const engine = createEngine();
    const state = engine.getState();
    expect(state.graph_summary.cold_node_count).toBe(0);
    expect(state.graph_summary.cold_nodes_by_subnet).toBeUndefined();
  });

  it('edge promotion works for both source and target cold nodes', () => {
    const engine = createEngine();

    // Ingest two cold hosts
    engine.ingestFinding(makeFinding([
      { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', alive: true },
      { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2', alive: true },
    ]));
    expect(engine.getState().graph_summary.cold_node_count).toBe(2);

    // Connect them with a REACHABLE edge → both should promote
    engine.ingestFinding(makeFinding(
      [],
      [
        { source: 'host-10-10-10-1', target: 'host-10-10-10-2', properties: { type: 'REACHABLE', confidence: 0.8 } },
      ],
    ));
    expect(engine.getNode('host-10-10-10-1')).not.toBeNull();
    expect(engine.getNode('host-10-10-10-2')).not.toBeNull();
    expect(engine.getState().graph_summary.cold_node_count).toBe(0);
  });
});

// ============================================================
// Phase 2: dispatch_subnet_agents integration
// ============================================================

describe('dispatch_subnet_agents', () => {
  afterEach(cleanup);

  it('dispatches agents for scope CIDRs', () => {
    const engine = createEngine();
    const frontier = engine.computeFrontier();
    // Should have network_discovery items for the 2 scope CIDRs
    const discoveryItems = frontier.filter(f => f.type === 'network_discovery');
    expect(discoveryItems.length).toBe(2);
  });

  it('agents registered for CIDRs appear as running', () => {
    const engine = createEngine();
    const frontier = engine.computeFrontier();
    const discoveryItem = frontier.find(f => f.type === 'network_discovery' && f.target_cidr === '10.10.10.0/24');
    expect(discoveryItem).toBeDefined();

    // Register an agent for this frontier item
    engine.registerAgent({
      id: 'task-1',
      agent_id: 'agent-subnet-test',
      assigned_at: now,
      status: 'running',
      frontier_item_id: discoveryItem!.id,
      subgraph_node_ids: [],
    });

    // The agent should be running
    const running = engine.getRunningTaskForFrontierItem(discoveryItem!.id);
    expect(running).toBeDefined();
    expect(running!.agent_id).toBe('agent-subnet-test');
  });

  it('frontier items use correct CIDR slug format', () => {
    const engine = createEngine();
    const frontier = engine.computeFrontier();
    const item = frontier.find(f => f.id === 'frontier-discovery-10-10-10-0-24');
    expect(item).toBeDefined();
    expect(item!.target_cidr).toBe('10.10.10.0/24');
  });

  it('fully-discovered CIDRs have no frontier item', () => {
    const engine = createEngine();
    // Fill the /24 with 254 hosts → frontier should suppress that CIDR
    const nodes: Finding['nodes'] = [];
    const edges: Finding['edges'] = [];
    for (let i = 1; i <= 254; i++) {
      const ip = `192.168.1.${i}`;
      const id = `host-192-168-1-${i}`;
      nodes.push({ id, type: 'host', label: ip, ip, alive: true });
      // Add a service so they stay hot
      const svcId = `svc-${id}`;
      nodes.push({ id: svcId, type: 'service', label: `ssh-${i}`, port: 22, service_name: 'ssh' });
      edges.push({ source: id, target: svcId, properties: { type: 'RUNS', confidence: 1.0 } });
    }
    engine.ingestFinding(makeFinding(nodes, edges));

    const frontier = engine.computeFrontier();
    const item192 = frontier.find(f => f.id === 'frontier-discovery-192-168-1-0-24');
    expect(item192).toBeUndefined(); // fully discovered
    // But the 10.10.10.0/24 should still have a discovery item
    const item10 = frontier.find(f => f.id === 'frontier-discovery-10-10-10-0-24');
    expect(item10).toBeDefined();
  });
});
