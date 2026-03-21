import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { GraphEngine } from '../graph-engine.js';
import { unlinkSync, existsSync } from 'fs';
import type { EngagementConfig, Finding, NodeType, AgentTask } from '../../types.js';

const TEST_STATE_FILE = './state-test-eng.json';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-eng',
    name: 'Test Engagement',
    created_at: '2026-03-20T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/28'],
      domains: ['test.local'],
      exclusions: ['10.10.10.14'],
    },
    objectives: [
      {
        id: 'obj-da',
        description: 'Get Domain Admin',
        target_node_type: 'credential',
        target_criteria: { privileged: true, cred_domain: 'test.local' },
        achieved: false,
      },
    ],
    opsec: {
      name: 'pentest',
      max_noise: 0.7,
      blacklisted_techniques: ['zerologon'],
    },
    ...overrides,
  };
}

function cleanup() {
  if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
}

describe('GraphEngine', () => {
  afterEach(cleanup);

  // =============================================
  // Seeding
  // =============================================
  describe('seeding from config', () => {
    it('creates host nodes from CIDR', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      // /28 = 14 usable hosts
      expect(state.graph_summary.nodes_by_type['host']).toBe(14);
    });

    it('creates domain nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      expect(state.graph_summary.nodes_by_type['domain']).toBe(1);
    });

    it('creates objective nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      expect(state.graph_summary.nodes_by_type['objective']).toBe(1);
    });

    it('creates explicit host nodes', () => {
      const config = makeConfig({
        scope: {
          cidrs: [],
          domains: ['test.local'],
          exclusions: [],
          hosts: ['dc01.test.local', 'web01.test.local'],
        },
      });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      const state = engine.getState();
      expect(state.graph_summary.nodes_by_type['host']).toBe(2);
    });
  });

  // =============================================
  // Finding Ingestion
  // =============================================
  describe('ingestFinding', () => {
    it('adds new nodes to the graph', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB on .1', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      expect(result.new_nodes).toContain('svc-10-10-10-1-445');
      expect(result.new_edges.length).toBeGreaterThan(0);
    });

    it('merges properties on existing nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // First: host exists from seeding with no OS
      const before = engine.getState();
      const hostNode = before.frontier.find(f => f.node_id === 'host-10-10-10-1');
      expect(hostNode).toBeDefined();

      // Update with OS info
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true, os: 'Windows Server 2022' },
        ],
      }));

      const state = engine.getState();
      // Node count should not increase for the host type
      expect(state.graph_summary.nodes_by_type['host']).toBe(14);
    });

    it('skips edges with missing source/target nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.ingestFinding(makeFinding({
        edges: [
          { source: 'nonexistent-a', target: 'nonexistent-b', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      expect(result.new_edges.length).toBe(0);
    });

    it('deduplicates edges of the same type', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add a service first
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'svc-test', type: 'service', label: 'test svc' }],
        edges: [{ source: 'host-10-10-10-1', target: 'svc-test', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));

      const before = engine.getState();
      const edgesBefore = before.graph_summary.total_edges;

      // Report same edge again
      engine.ingestFinding(makeFinding({
        edges: [{ source: 'host-10-10-10-1', target: 'svc-test', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));

      const after = engine.getState();
      expect(after.graph_summary.total_edges).toBe(edgesBefore);
    });
  });

  // =============================================
  // Inference Rules
  // =============================================
  describe('inference rules', () => {
    it('infers MEMBER_OF_DOMAIN from Kerberos service', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add a Kerberos service on a host
      const result = engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-1-88', type: 'service', label: 'Kerberos', port: 88, service_name: 'kerberos' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-88', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      expect(result.inferred_edges.length).toBeGreaterThan(0);
      // Should have inferred MEMBER_OF_DOMAIN
      const state = engine.getState();
      expect(state.graph_summary.edges_by_type['MEMBER_OF_DOMAIN']).toBeGreaterThan(0);
    });

    it('infers RELAY_TARGET from SMB signing disabled', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Need a compromised host first for the relay source
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
        ],
        edges: [
          { source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Now add a service with signing disabled on a different host
      const result = engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-2-445', type: 'service', label: 'SMB .2', port: 445, service_name: 'smb', smb_signing: false },
        ],
        edges: [
          { source: 'host-10-10-10-2', target: 'svc-10-10-10-2-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // RELAY_TARGET should be inferred from compromised host to parent host of the service
      expect(result.inferred_edges.some(e => e.includes('RELAY_TARGET'))).toBe(true);
    });

    it('fires inference on property updates (P1.5 fix)', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      // Add SMB service without signing info — no relay inference
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-3-445', type: 'service', label: 'SMB .3', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-3', target: 'svc-10-10-10-3-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Need a compromised host for relay source
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'user-attacker', type: 'user', label: 'attacker' },
        ],
        edges: [
          { source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Now UPDATE the service to have signing disabled — should fire relay inference
      const result = engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-3-445', type: 'service', label: 'SMB .3', port: 445, service_name: 'smb', smb_signing: false },
        ],
      }));

      expect(result.inferred_edges.some(e => e.includes('RELAY_TARGET'))).toBe(true);
    });

    it('infers POTENTIAL_AUTH for new credentials', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add a service that accepts domain auth
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB .1', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      // Now add a credential
      const result = engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'cred-jdoe-ntlm', type: 'credential', label: 'jdoe NTLM', cred_type: 'ntlm', cred_user: 'jdoe', cred_domain: 'test.local' },
        ],
      }));

      expect(result.inferred_edges.some(e => e.includes('POTENTIAL_AUTH'))).toBe(true);
    });
  });

  // =============================================
  // Frontier Computation
  // =============================================
  describe('frontier', () => {
    it('generates incomplete_node items for hosts missing alive status', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      const aliveItems = state.frontier.filter(
        f => f.type === 'incomplete_node' && f.missing_properties?.includes('alive')
      );
      // All 14 hosts should be missing alive status initially
      // (minus excluded IP which is filtered out by the deterministic layer)
      expect(aliveItems.length).toBeGreaterThan(0);
    });

    it('generates inferred_edge items for untested inferred edges', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Create an inferred edge via Kerberos
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-1-88', type: 'service', label: 'Kerberos', port: 88, service_name: 'kerberos' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-88', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const state = engine.getState();
      const inferredItems = state.frontier.filter(f => f.type === 'inferred_edge');
      expect(inferredItems.length).toBeGreaterThan(0);
    });

    it('filters out excluded IPs', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      const excludedItems = state.frontier.filter(f => f.node_id === 'host-10-10-10-14');
      expect(excludedItems.length).toBe(0);
    });

    it('filters out dead hosts', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: false }],
      }));

      const state = engine.getState();
      const deadItems = state.frontier.filter(f => f.node_id === 'host-10-10-10-1');
      expect(deadItems.length).toBe(0);
    });

    it('filters items exceeding OPSEC noise ceiling', () => {
      const config = makeConfig({ opsec: { name: 'redteam', max_noise: 0.1 } });
      const engine = new GraphEngine(config, TEST_STATE_FILE);
      const state = engine.getState();
      // With noise ceiling 0.1, most items should be filtered (ping sweep = 0.2)
      const highNoiseInFrontier = state.frontier.filter(f => f.opsec_noise > 0.1);
      expect(highNoiseInFrontier.length).toBe(0);
    });
  });

  // =============================================
  // Validation
  // =============================================
  describe('validation', () => {
    it('validates existing nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ target_node: 'host-10-10-10-1' });
      expect(result.valid).toBe(true);
    });

    it('rejects nonexistent nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ target_node: 'host-does-not-exist' });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('rejects excluded IPs', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ target_node: 'host-10-10-10-14' });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('out of scope'))).toBe(true);
    });

    it('rejects blacklisted techniques', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ technique: 'zerologon' });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('blacklisted'))).toBe(true);
    });

    it('allows non-blacklisted techniques', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const result = engine.validateAction({ target_node: 'host-10-10-10-1', technique: 'portscan' });
      expect(result.valid).toBe(true);
    });
  });

  // =============================================
  // Path Analysis
  // =============================================
  describe('path analysis', () => {
    it('hopsToNearestObjective returns null for disconnected nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const hops = engine.hopsToNearestObjective('host-10-10-10-1');
      // No edges exist initially, so no path
      expect(hops).toBeNull();
    });

    it('findPaths returns empty for nonexistent nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const paths = engine.findPaths('nonexistent', 'also-nonexistent');
      expect(paths).toEqual([]);
    });

    it('findPaths finds a path between connected nodes', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-10-10-10-1-445', type: 'service', label: 'SMB', port: 445, service_name: 'smb' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-10-10-10-1-445', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));

      const paths = engine.findPaths('host-10-10-10-1', 'svc-10-10-10-1-445');
      expect(paths.length).toBe(1);
      expect(paths[0].nodes).toContain('host-10-10-10-1');
      expect(paths[0].nodes).toContain('svc-10-10-10-1-445');
      expect(paths[0].total_confidence).toBe(1.0);
    });
  });

  // =============================================
  // Agent Lifecycle
  // =============================================
  describe('agent lifecycle', () => {
    it('registers and retrieves a task', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const task: AgentTask = {
        id: 'task-1',
        agent_id: 'agent-recon-1',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'frontier-node-host-10-10-10-1',
        subgraph_node_ids: ['host-10-10-10-1'],
      };
      engine.registerAgent(task);

      const retrieved = engine.getTask('task-1');
      expect(retrieved).not.toBeNull();
      expect(retrieved!.agent_id).toBe('agent-recon-1');
      expect(retrieved!.status).toBe('running');
    });

    it('returns null for unknown task', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      expect(engine.getTask('nonexistent')).toBeNull();
    });

    it('updates task status', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const task: AgentTask = {
        id: 'task-2',
        agent_id: 'agent-2',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-1',
        subgraph_node_ids: [],
      };
      engine.registerAgent(task);

      const success = engine.updateAgentStatus('task-2', 'completed', 'Scan finished');
      expect(success).toBe(true);

      const updated = engine.getTask('task-2');
      expect(updated!.status).toBe('completed');
      expect(updated!.result_summary).toBe('Scan finished');
      expect(updated!.completed_at).toBeDefined();
    });

    it('returns false for updating unknown task (P1.4 fix)', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const success = engine.updateAgentStatus('nonexistent', 'failed');
      expect(success).toBe(false);
    });

    it('shows active agents in state', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.registerAgent({
        id: 'task-3',
        agent_id: 'agent-3',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-1',
        subgraph_node_ids: ['host-10-10-10-1'],
      });

      const state = engine.getState();
      expect(state.active_agents.length).toBe(1);
      expect(state.active_agents[0].agent_id).toBe('agent-3');
    });

    it('returns scoped subgraph for agent', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      // Add a service connected to host-10-10-10-1
      engine.ingestFinding(makeFinding({
        nodes: [{ id: 'svc-test', type: 'service', label: 'test' }],
        edges: [{ source: 'host-10-10-10-1', target: 'svc-test', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));

      const subgraph = engine.getSubgraphForAgent(['host-10-10-10-1']);
      // Should include host-10-10-10-1 + neighbor svc-test
      expect(subgraph.nodes.length).toBeGreaterThanOrEqual(2);
      expect(subgraph.nodes.some(n => n.id === 'host-10-10-10-1')).toBe(true);
      expect(subgraph.nodes.some(n => n.id === 'svc-test')).toBe(true);
    });
  });

  // =============================================
  // Objective Tracking
  // =============================================
  describe('objective tracking', () => {
    it('marks objective achieved when criteria are met', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      // Report a privileged credential matching the DA objective criteria
      engine.ingestFinding(makeFinding({
        nodes: [{
          id: 'cred-da',
          type: 'credential',
          label: 'DA cred',
          cred_type: 'ntlm',
          cred_user: 'admin',
          cred_domain: 'test.local',
          privileged: true,
        }],
      }));

      const state = engine.getState();
      const daObj = state.objectives.find(o => o.id === 'obj-da');
      expect(daObj?.achieved).toBe(true);
      expect(daObj?.achieved_at).toBeDefined();
    });

    it('does not mark objective achieved with non-matching criteria', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      engine.ingestFinding(makeFinding({
        nodes: [{
          id: 'cred-unprivileged',
          type: 'credential',
          label: 'low priv cred',
          cred_type: 'ntlm',
          cred_user: 'jdoe',
          cred_domain: 'test.local',
          privileged: false,
        }],
      }));

      const state = engine.getState();
      const daObj = state.objectives.find(o => o.id === 'obj-da');
      expect(daObj?.achieved).toBe(false);
    });
  });

  // =============================================
  // Persistence
  // =============================================
  describe('persistence', () => {
    it('persists and reloads state', () => {
      // Create engine, add some data
      const engine1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine1.ingestFinding(makeFinding({
        nodes: [
          { id: 'svc-persist', type: 'service', label: 'persist test', port: 80, service_name: 'http' },
        ],
        edges: [
          { source: 'host-10-10-10-1', target: 'svc-persist', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } },
        ],
      }));
      engine1.registerAgent({
        id: 'task-persist',
        agent_id: 'agent-persist',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-1',
        subgraph_node_ids: ['host-10-10-10-1'],
      });

      const state1 = engine1.getState();

      // Create new engine from same state file — should reload
      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state2 = engine2.getState();

      expect(state2.graph_summary.total_nodes).toBe(state1.graph_summary.total_nodes);
      expect(state2.graph_summary.total_edges).toBe(state1.graph_summary.total_edges);
    });

    it('persists agent state across reloads (P1.3 fix)', () => {
      const engine1 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine1.registerAgent({
        id: 'task-agent-persist',
        agent_id: 'agent-ap',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-1',
        subgraph_node_ids: [],
      });

      // Reload
      const engine2 = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const task = engine2.getTask('task-agent-persist');
      expect(task).not.toBeNull();
      expect(task!.agent_id).toBe('agent-ap');
    });
  });

  // =============================================
  // Access Summary
  // =============================================
  describe('access summary', () => {
    it('reports no access initially', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      const state = engine.getState();
      expect(state.access_summary.compromised_hosts.length).toBe(0);
      expect(state.access_summary.current_access_level).toBe('none');
    });

    it('reports compromised hosts with HAS_SESSION', () => {
      const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
      engine.ingestFinding(makeFinding({
        nodes: [
          { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', alive: true },
          { id: 'user-attacker', type: 'user', label: 'attacker' },
        ],
        edges: [{ source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: new Date().toISOString() } }],
      }));

      const state = engine.getState();
      expect(state.access_summary.compromised_hosts.length).toBe(1);
      expect(state.access_summary.current_access_level).toBe('user');
    });
  });
});

// =============================================
// Helpers
// =============================================
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  const enrichedNodes = (overrides.nodes || []).map(n => ({
    discovered_at: new Date().toISOString(),
    confidence: 1.0,
    label: n.label || n.id,
    ...n,
  })) as Finding['nodes'];

  return {
    id: 'finding-' + Math.random().toString(36).slice(2),
    agent_id: 'test-agent',
    timestamp: new Date().toISOString(),
    nodes: enrichedNodes,
    edges: overrides.edges || [],
  };
}
