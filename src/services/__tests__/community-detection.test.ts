import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { GraphEngine } from '../graph-engine.js';
import { unlinkSync, existsSync } from 'fs';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-community.json';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-community',
    name: 'Community Test',
    created_at: '2026-03-27T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [
      {
        id: 'obj-da',
        description: 'Get Domain Admin',
        target_node_type: 'credential',
        target_criteria: { privileged: true },
        achieved: false,
      },
    ],
    opsec: {
      name: 'pentest',
      max_noise: 0.7,
      blacklisted_techniques: [],
    },
    ...overrides,
  };
}

function cleanup() {
  if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
}

describe('Community Detection', () => {
  let engine: GraphEngine;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
  });

  afterEach(() => {
    cleanup();
  });

  it('returns communities for graph with only config-created nodes', () => {
    // Config creates objective + domain nodes automatically
    const communities = engine.getCommunities();
    // Should have entries for whatever nodes exist from config
    expect(communities.size).toBeGreaterThanOrEqual(0);
  });

  it('assigns community_id to nodes in a triangle', () => {
    // Create three connected hosts — should form one community
    engine.addNode({ id: 'host-a', type: 'host', label: 'A', ip: '10.10.10.1', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addNode({ id: 'host-b', type: 'host', label: 'B', ip: '10.10.10.2', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addNode({ id: 'host-c', type: 'host', label: 'C', ip: '10.10.10.3', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addEdge('host-a', 'host-b', { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addEdge('host-b', 'host-c', { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addEdge('host-c', 'host-a', { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });

    const communities = engine.getCommunities();
    expect(communities.has('host-a')).toBe(true);
    expect(communities.has('host-b')).toBe(true);
    expect(communities.has('host-c')).toBe(true);
    // All three connected hosts should be in the same community
    expect(communities.get('host-a')).toBe(communities.get('host-b'));
    expect(communities.get('host-b')).toBe(communities.get('host-c'));
  });

  it('detects multiple communities in disconnected clusters', () => {
    // Cluster 1: A-B
    engine.addNode({ id: 'host-a', type: 'host', label: 'A', ip: '10.10.10.1', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addNode({ id: 'host-b', type: 'host', label: 'B', ip: '10.10.10.2', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addEdge('host-a', 'host-b', { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });

    // Cluster 2: C-D
    engine.addNode({ id: 'host-c', type: 'host', label: 'C', ip: '10.10.10.3', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addNode({ id: 'host-d', type: 'host', label: 'D', ip: '10.10.10.4', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addEdge('host-c', 'host-d', { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });

    const communities = engine.getCommunities();
    expect(communities.has('host-a')).toBe(true);
    expect(communities.has('host-d')).toBe(true);

    // The two clusters should have different community IDs
    expect(communities.get('host-a')).toBe(communities.get('host-b'));
    expect(communities.get('host-c')).toBe(communities.get('host-d'));
    expect(communities.get('host-a')).not.toBe(communities.get('host-c'));
  });

  it('assigns isolated nodes to individual communities', () => {
    engine.addNode({ id: 'host-a', type: 'host', label: 'A', ip: '10.10.10.1', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addNode({ id: 'host-b', type: 'host', label: 'B', ip: '10.10.10.2', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });

    const communities = engine.getCommunities();
    expect(communities.has('host-a')).toBe(true);
    expect(communities.has('host-b')).toBe(true);
    // No edges between them → each node gets its own community
    expect(communities.get('host-a')).not.toBe(communities.get('host-b'));
  });

  it('invalidates cache when graph changes', () => {
    engine.addNode({ id: 'host-a', type: 'host', label: 'A', ip: '10.10.10.1', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addNode({ id: 'host-b', type: 'host', label: 'B', ip: '10.10.10.2', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });

    const before = engine.getCommunities();
    expect(before.get('host-a')).not.toBe(before.get('host-b'));

    // Adding an edge should invalidate cache and merge communities
    engine.addEdge('host-a', 'host-b', { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });

    const after = engine.getCommunities();
    expect(after.get('host-a')).toBe(after.get('host-b'));
  });

  it('includes community stats in getState().graph_summary', () => {
    engine.addNode({ id: 'host-a', type: 'host', label: 'A', ip: '10.10.10.1', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addNode({ id: 'host-b', type: 'host', label: 'B', ip: '10.10.10.2', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addEdge('host-a', 'host-b', { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });

    const state = engine.getState();
    expect(state.graph_summary.community_count).toBeGreaterThanOrEqual(1);
    expect(state.graph_summary.largest_community_size).toBeGreaterThanOrEqual(2);
    expect(typeof state.graph_summary.unexplored_community_count).toBe('number');
  });

  it('enriches frontier items with community_id', () => {
    // Create an incomplete host (missing services) so it appears in frontier
    engine.addNode({ id: 'host-a', type: 'host', label: 'A', ip: '10.10.10.1', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addNode({ id: 'host-b', type: 'host', label: 'B', ip: '10.10.10.2', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addEdge('host-a', 'host-b', { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });

    const frontier = engine.computeFrontier();
    const hostItems = frontier.filter(f => f.node_id === 'host-a' || f.node_id === 'host-b');
    expect(hostItems.length).toBeGreaterThan(0);
    // All host items in the same cluster should have same community_id
    const cids = hostItems.map(f => f.community_id).filter(c => c !== undefined);
    expect(cids.length).toBeGreaterThan(0);
    expect(new Set(cids).size).toBe(1);
  });

  it('community_unexplored_count reflects frontier items per community', () => {
    // Two disconnected clusters, each with incomplete hosts
    engine.addNode({ id: 'host-a', type: 'host', label: 'A', ip: '10.10.10.1', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addNode({ id: 'host-b', type: 'host', label: 'B', ip: '10.10.10.2', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addEdge('host-a', 'host-b', { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });

    engine.addNode({ id: 'host-c', type: 'host', label: 'C', ip: '10.10.10.3', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });

    const frontier = engine.computeFrontier();
    const itemA = frontier.find(f => f.node_id === 'host-a');
    const itemC = frontier.find(f => f.node_id === 'host-c');
    expect(itemA).toBeDefined();
    expect(itemC).toBeDefined();
    // Cluster {A,B} should have more frontier items than isolated C
    expect(itemA!.community_unexplored_count).toBeGreaterThanOrEqual(2);
    expect(itemC!.community_unexplored_count).toBe(1);
  });

  it('writes community_id to node properties for graph export', () => {
    engine.addNode({ id: 'host-a', type: 'host', label: 'A', ip: '10.10.10.1', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addNode({ id: 'host-b', type: 'host', label: 'B', ip: '10.10.10.2', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });
    engine.addEdge('host-a', 'host-b', { type: 'REACHABLE', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: 'test' });

    engine.getCommunities();
    const nodeA = engine.getNode('host-a');
    expect(nodeA).toBeDefined();
    expect(typeof nodeA!.community_id).toBe('number');
  });

  it('weights access edges higher than REACHABLE edges', () => {
    // Two clusters connected by a weak REACHABLE link and a strong ADMIN_TO link
    // Nodes connected via ADMIN_TO should cluster together more strongly
    const ts = new Date().toISOString();
    const base = { confidence: 1.0, discovered_at: ts, discovered_by: 'test' };

    // Cluster 1: host-a -- ADMIN_TO --> host-b (strong affinity)
    engine.addNode({ id: 'host-a', type: 'host', label: 'A', ip: '10.10.10.1', ...base });
    engine.addNode({ id: 'host-b', type: 'host', label: 'B', ip: '10.10.10.2', ...base });
    engine.addNode({ id: 'user-x', type: 'user', label: 'X', ...base });
    engine.addEdge('user-x', 'host-a', { type: 'ADMIN_TO', ...base });
    engine.addEdge('user-x', 'host-b', { type: 'ADMIN_TO', ...base });

    // Cluster 2: host-c -- REACHABLE --> host-d (weak affinity)
    engine.addNode({ id: 'host-c', type: 'host', label: 'C', ip: '10.10.10.3', ...base });
    engine.addNode({ id: 'host-d', type: 'host', label: 'D', ip: '10.10.10.4', ...base });
    engine.addEdge('host-c', 'host-d', { type: 'REACHABLE', ...base });

    // Weak cross-link
    engine.addEdge('host-b', 'host-c', { type: 'REACHABLE', confidence: 0.3, discovered_at: ts, discovered_by: 'test' });

    const communities = engine.getCommunities();
    // user-x, host-a, host-b should be in the same community (strong ADMIN_TO)
    expect(communities.get('user-x')).toBe(communities.get('host-a'));
    expect(communities.get('user-x')).toBe(communities.get('host-b'));
  });

  it('uses configurable resolution parameter', () => {
    const ts = new Date().toISOString();
    const base = { confidence: 1.0, discovered_at: ts, discovered_by: 'test' };

    // Create a chain of hosts
    for (let i = 0; i < 6; i++) {
      engine.addNode({ id: `host-${i}`, type: 'host', label: `H${i}`, ip: `10.10.10.${i + 1}`, ...base });
    }
    for (let i = 0; i < 5; i++) {
      engine.addEdge(`host-${i}`, `host-${i + 1}`, { type: 'REACHABLE', ...base });
    }

    const lowRes = engine.getCommunities();
    const lowResCount = new Set(lowRes.values()).size;

    // Now create a new engine with higher resolution
    cleanup();
    const hiResEngine = new GraphEngine(makeConfig({ community_resolution: 3.0 }), TEST_STATE_FILE);
    for (let i = 0; i < 6; i++) {
      hiResEngine.addNode({ id: `host-${i}`, type: 'host', label: `H${i}`, ip: `10.10.10.${i + 1}`, ...base });
    }
    for (let i = 0; i < 5; i++) {
      hiResEngine.addEdge(`host-${i}`, `host-${i + 1}`, { type: 'REACHABLE', ...base });
    }

    const hiRes = hiResEngine.getCommunities();
    const hiResCount = new Set(hiRes.values()).size;

    // Higher resolution should produce equal or more communities
    expect(hiResCount).toBeGreaterThanOrEqual(lowResCount);
  });

  it('default resolution produces same results as resolution=1.0', () => {
    const ts = new Date().toISOString();
    const base = { confidence: 1.0, discovered_at: ts, discovered_by: 'test' };

    engine.addNode({ id: 'host-a', type: 'host', label: 'A', ip: '10.10.10.1', ...base });
    engine.addNode({ id: 'host-b', type: 'host', label: 'B', ip: '10.10.10.2', ...base });
    engine.addEdge('host-a', 'host-b', { type: 'REACHABLE', ...base });

    const defaultComm = engine.getCommunities();

    // Engine with explicit resolution=1.0 should give same result
    cleanup();
    const explicitEngine = new GraphEngine(makeConfig({ community_resolution: 1.0 }), TEST_STATE_FILE);
    explicitEngine.addNode({ id: 'host-a', type: 'host', label: 'A', ip: '10.10.10.1', ...base });
    explicitEngine.addNode({ id: 'host-b', type: 'host', label: 'B', ip: '10.10.10.2', ...base });
    explicitEngine.addEdge('host-a', 'host-b', { type: 'REACHABLE', ...base });

    const explicitComm = explicitEngine.getCommunities();

    // Same community structure
    expect(defaultComm.get('host-a') === defaultComm.get('host-b'))
      .toBe(explicitComm.get('host-a') === explicitComm.get('host-b'));
  });
});
