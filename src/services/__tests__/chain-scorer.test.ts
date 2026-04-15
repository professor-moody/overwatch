import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties, EdgeProperties, FrontierItem } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { ChainScorer } from '../chain-scorer.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

function makeConfig(overrides: Record<string, unknown> = {}) {
  return {
    id: 'test-eng',
    name: 'Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
    ...overrides,
  } as any;
}

const now = new Date().toISOString();

function addNode(graph: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  graph.addNode(id, { id, label: id, discovered_at: now, confidence: 1.0, ...props } as NodeProperties);
}

function addEdge(graph: OverwatchGraph, src: string, tgt: string, type: string, extra: Record<string, unknown> = {}) {
  return graph.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: now, ...extra } as EdgeProperties);
}

function buildScorer(graph: OverwatchGraph, config?: any, hopsToObjective?: (id: string) => number | null) {
  const ctx = new EngineContext(graph, config || makeConfig(), './test-state.json');
  const hopsFn = hopsToObjective || (() => null);
  return new ChainScorer(ctx, hopsFn);
}

function makeFrontierItem(overrides: Partial<FrontierItem>): FrontierItem {
  return {
    id: `fi-${Math.random().toString(36).slice(2, 8)}`,
    type: 'inferred_edge',
    description: 'test item',
    graph_metrics: { hops_to_objective: null, fan_out_estimate: 1, node_degree: 1, confidence: 1.0 },
    opsec_noise: 0.3,
    staleness_seconds: 0,
    ...overrides,
  } as FrontierItem;
}

describe('ChainScorer', () => {
  describe('basic chain grouping', () => {
    it('groups POTENTIAL_AUTH edges by credential source', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass123' });
      addNode(graph, 'svc-smb', { type: 'service', service_name: 'smb', port: 445 });
      addNode(graph, 'svc-ssh', { type: 'service', service_name: 'ssh', port: 22 });
      addEdge(graph, 'cred-1', 'svc-smb', 'POTENTIAL_AUTH');
      addEdge(graph, 'cred-1', 'svc-ssh', 'POTENTIAL_AUTH');

      const fi1 = makeFrontierItem({ edge_source: 'cred-1', edge_target: 'svc-smb', edge_type: 'POTENTIAL_AUTH' as any });
      const fi2 = makeFrontierItem({ edge_source: 'cred-1', edge_target: 'svc-ssh', edge_type: 'POTENTIAL_AUTH' as any });

      const scorer = buildScorer(graph);
      const groups = scorer.scoreChains([fi1, fi2]);

      expect(groups.length).toBe(1);
      expect(groups[0].chain_id).toBe('chain-cred-1');
      expect(groups[0].credential_id).toBe('cred-1');
      expect(groups[0].target_service_ids).toContain('svc-smb');
      expect(groups[0].target_service_ids).toContain('svc-ssh');
      expect(groups[0].total_count).toBe(2);
      expect(groups[0].confirmed_count).toBe(0);
    });

    it('creates separate chains for different credentials', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass1' });
      addNode(graph, 'cred-2', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass2' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });

      const fi1 = makeFrontierItem({ edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });
      const fi2 = makeFrontierItem({ edge_source: 'cred-2', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });

      const scorer = buildScorer(graph);
      const groups = scorer.scoreChains([fi1, fi2]);

      expect(groups.length).toBe(2);
      expect(groups.map(g => g.credential_id).sort()).toEqual(['cred-1', 'cred-2']);
    });

    it('skips non-auth frontier items', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1' });

      const fi = makeFrontierItem({ type: 'incomplete_node', node_id: 'host-1' });

      const scorer = buildScorer(graph);
      const groups = scorer.scoreChains([fi]);

      expect(groups.length).toBe(0);
      expect(fi.chain_id).toBeUndefined();
    });
  });

  describe('chain completion tracking', () => {
    it('counts already-tested edges for completion percentage', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass123' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addNode(graph, 'svc-2', { type: 'service', service_name: 'ssh', port: 22 });
      // One edge already tested (success)
      addEdge(graph, 'cred-1', 'svc-1', 'POTENTIAL_AUTH', { tested: true, test_result: 'success' });
      // One edge untested (in frontier)
      addEdge(graph, 'cred-1', 'svc-2', 'POTENTIAL_AUTH');

      const fi = makeFrontierItem({ edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any });

      const scorer = buildScorer(graph);
      const groups = scorer.scoreChains([fi]);

      expect(groups.length).toBe(1);
      expect(groups[0].confirmed_count).toBe(1);
      expect(groups[0].total_count).toBe(2);
      expect(fi.chain_completion_pct).toBeCloseTo(0.5, 2);
    });
  });

  describe('frontier item annotation', () => {
    it('annotates frontier items with chain data', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass123' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'cred-1', 'svc-1', 'POTENTIAL_AUTH');

      const fi = makeFrontierItem({ edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });

      const scorer = buildScorer(graph);
      scorer.scoreChains([fi]);

      expect(fi.chain_id).toBe('chain-cred-1');
      expect(fi.chain_depth).toBe(0);
      expect(fi.chain_length).toBe(1);
      expect(fi.chain_completion_pct).toBe(0);
      expect(typeof fi.chain_score).toBe('number');
      expect(fi.chain_score).toBeGreaterThan(0);
    });
  });

  describe('credential quality scoring', () => {
    it('scores usable credentials higher than stale ones', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-fresh', { type: 'credential', cred_type: 'plaintext', cred_value: 'fresh123' });
      addNode(graph, 'cred-expired', { type: 'credential', cred_type: 'plaintext', cred_value: 'stale123', credential_status: 'expired' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addNode(graph, 'svc-2', { type: 'service', service_name: 'ssh', port: 22 });
      addEdge(graph, 'cred-fresh', 'svc-1', 'POTENTIAL_AUTH');
      addEdge(graph, 'cred-expired', 'svc-2', 'POTENTIAL_AUTH');

      const fiFresh = makeFrontierItem({ edge_source: 'cred-fresh', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });
      const fiExpired = makeFrontierItem({ edge_source: 'cred-expired', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any });

      const scorer = buildScorer(graph);
      scorer.scoreChains([fiFresh, fiExpired]);

      expect(fiFresh.chain_score!).toBeGreaterThan(fiExpired.chain_score!);
    });

    it('scores expired credentials lowest', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-expired', { type: 'credential', cred_type: 'plaintext', cred_value: 'old', credential_status: 'expired' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'cred-expired', 'svc-1', 'POTENTIAL_AUTH');

      const fi = makeFrontierItem({ edge_source: 'cred-expired', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });

      const scorer = buildScorer(graph);
      scorer.scoreChains([fi]);

      // Expired creds: not usable, is stale → score gets 0 from credential quality
      expect(fi.chain_score!).toBeLessThan(1);
    });
  });

  describe('objective proximity', () => {
    it('boosts chains near objectives', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass123' });
      addNode(graph, 'svc-near', { type: 'service', service_name: 'smb', port: 445 });
      addNode(graph, 'svc-far', { type: 'service', service_name: 'ssh', port: 22 });
      addEdge(graph, 'cred-1', 'svc-near', 'POTENTIAL_AUTH');
      addEdge(graph, 'cred-1', 'svc-far', 'POTENTIAL_AUTH');

      const fiNear = makeFrontierItem({ edge_source: 'cred-1', edge_target: 'svc-near', edge_type: 'POTENTIAL_AUTH' as any });
      const fiFar = makeFrontierItem({ edge_source: 'cred-1', edge_target: 'svc-far', edge_type: 'POTENTIAL_AUTH' as any });

      // svc-near is 1 hop from objective, svc-far is 5 hops
      const hopsFn = (id: string) => {
        if (id === 'svc-near') return 1;
        if (id === 'svc-far') return 5;
        return null;
      };
      const scorer = buildScorer(graph, undefined, hopsFn);
      const groups = scorer.scoreChains([fiNear, fiFar]);

      // Both in same chain, but chain should mark objective adjacency
      expect(groups[0].has_objective_adjacent).toBe(true);
      expect(groups[0].min_hops_to_objective).toBe(1);
    });

    it('reports no objective proximity when hopsToObjective returns null', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass123' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'cred-1', 'svc-1', 'POTENTIAL_AUTH');

      const fi = makeFrontierItem({ edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });

      const scorer = buildScorer(graph); // default hopsToObjective returns null
      const groups = scorer.scoreChains([fi]);

      expect(groups[0].min_hops_to_objective).toBeNull();
      expect(groups[0].has_objective_adjacent).toBe(false);
      expect(fi.chain_target_objective).toBe(false);
    });
  });

  describe('host resolution', () => {
    it('resolves service targets to parent hosts via RUNS edge', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass123' });
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1', alive: true });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');
      addEdge(graph, 'cred-1', 'svc-1', 'POTENTIAL_AUTH');

      // hopsToObjective returns 0 for host-1 (it IS the objective)
      const hopsFn = (id: string) => (id === 'host-1' ? 0 : null);

      const fi = makeFrontierItem({ edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });

      const scorer = buildScorer(graph, undefined, hopsFn);
      const groups = scorer.scoreChains([fi]);

      expect(groups[0].target_host_ids).toContain('host-1');
      // Host IS objective → should be adjacent
      expect(groups[0].has_objective_adjacent).toBe(true);
    });
  });

  describe('multi-hop chains', () => {
    it('scores lateral movement edges extending confirmed access chains', () => {
      const graph = makeGraph();
      // Credential with confirmed access to host-1
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass123' });
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1', alive: true });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');
      addEdge(graph, 'cred-1', 'svc-1', 'POTENTIAL_AUTH', { tested: true, test_result: 'success' });

      // host-1 has confirmed session
      addEdge(graph, 'cred-1', 'host-1', 'HAS_SESSION', { confidence: 1.0 });

      // Lateral movement target from host-1
      addNode(graph, 'host-2', { type: 'host', ip: '10.10.10.2', alive: true });
      addNode(graph, 'svc-2', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-2', 'svc-2', 'RUNS');

      // A lateral movement frontier item (non-auth edge type, so it goes through multi-hop scoring)
      const fiLateral = makeFrontierItem({ edge_source: 'host-1', edge_target: 'svc-2', edge_type: 'ADMIN_TO' as any });

      const scorer = buildScorer(graph);
      scorer.scoreChains([fiLateral]);

      // It should be scored as a multi-hop chain extension
      expect(fiLateral.chain_id).toBeDefined();
      expect(fiLateral.chain_depth).toBe(1); // one hop beyond confirmed access
      expect(fiLateral.chain_completion_pct).toBe(0.5);
    });
  });

  describe('already-accessed target penalty', () => {
    it('penalizes chains targeting already-accessed hosts', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'p1' });
      addNode(graph, 'cred-2', { type: 'credential', cred_type: 'plaintext', cred_value: 'p2' });
      addNode(graph, 'host-accessed', { type: 'host', ip: '10.10.10.1', alive: true });
      addNode(graph, 'host-new', { type: 'host', ip: '10.10.10.2', alive: true });
      addNode(graph, 'svc-accessed', { type: 'service', service_name: 'smb', port: 445 });
      addNode(graph, 'svc-new', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-accessed', 'svc-accessed', 'RUNS');
      addEdge(graph, 'host-new', 'svc-new', 'RUNS');
      // host-accessed already has a confirmed session
      addNode(graph, 'someone', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      addEdge(graph, 'someone', 'host-accessed', 'HAS_SESSION', { confidence: 1.0 });

      addEdge(graph, 'cred-1', 'svc-accessed', 'POTENTIAL_AUTH');
      addEdge(graph, 'cred-2', 'svc-new', 'POTENTIAL_AUTH');

      const fiAccessed = makeFrontierItem({ edge_source: 'cred-1', edge_target: 'svc-accessed', edge_type: 'POTENTIAL_AUTH' as any });
      const fiNew = makeFrontierItem({ edge_source: 'cred-2', edge_target: 'svc-new', edge_type: 'POTENTIAL_AUTH' as any });

      const scorer = buildScorer(graph);
      scorer.scoreChains([fiAccessed, fiNew]);

      // Chain targeting already-accessed host should have lower score  
      expect(fiAccessed.chain_score!).toBeLessThan(fiNew.chain_score!);
    });
  });

  describe('edge cases', () => {
    it('handles empty frontier', () => {
      const graph = makeGraph();
      const scorer = buildScorer(graph);
      const groups = scorer.scoreChains([]);
      expect(groups).toEqual([]);
    });

    it('handles frontier with no auth edges', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1' });

      const fi = makeFrontierItem({ type: 'incomplete_node', node_id: 'host-1' });

      const scorer = buildScorer(graph);
      const groups = scorer.scoreChains([fi]);
      expect(groups).toEqual([]);
    });

    it('handles credential node missing from graph', () => {
      const graph = makeGraph();
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });

      // Frontier item references a credential not in the graph
      const fi = makeFrontierItem({ edge_source: 'ghost-cred', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });

      const scorer = buildScorer(graph);
      const groups = scorer.scoreChains([fi]);

      // Should still produce a group, just with degraded scoring
      expect(groups.length).toBe(1);
      expect(groups[0].credential_usable).toBe(false);
    });

    it('score is always non-negative', () => {
      const graph = makeGraph();
      // Worst case: expired cred targeting already-accessed host
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'old', credential_status: 'expired' });
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1', alive: true });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');
      addNode(graph, 'someone', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      addEdge(graph, 'someone', 'host-1', 'HAS_SESSION', { confidence: 1.0 });
      addEdge(graph, 'cred-1', 'svc-1', 'POTENTIAL_AUTH');

      const fi = makeFrontierItem({ edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });

      const scorer = buildScorer(graph);
      scorer.scoreChains([fi]);

      expect(fi.chain_score!).toBeGreaterThanOrEqual(0);
    });
  });
});
