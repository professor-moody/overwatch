import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties, EdgeProperties, FrontierItem } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { CampaignPlanner } from '../campaign-planner.js';
import type { ChainGroup } from '../chain-scorer.js';

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

function buildPlanner(graph: OverwatchGraph, config?: any) {
  const ctx = new EngineContext(graph, config || makeConfig(), './test-state.json');
  return new CampaignPlanner(ctx);
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

function makeChainGroup(overrides: Partial<ChainGroup> = {}): ChainGroup {
  return {
    chain_id: 'chain-cred-1',
    credential_id: 'cred-1',
    credential_usable: true,
    credential_stale: false,
    target_service_ids: ['svc-1', 'svc-2'],
    target_host_ids: ['host-1'],
    confirmed_count: 0,
    total_count: 2,
    min_hops_to_objective: null,
    has_objective_adjacent: false,
    chain_score: 4.5,
    ...overrides,
  };
}

describe('CampaignPlanner', () => {
  // =============================================
  // Campaign generation
  // =============================================
  describe('generateCampaigns', () => {
    it('creates credential spray campaigns from chain groups with >1 target', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass123' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addNode(graph, 'svc-2', { type: 'service', service_name: 'ssh', port: 22 });

      const planner = buildPlanner(graph);
      const fi1 = makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });
      const fi2 = makeFrontierItem({ id: 'fi-2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any });
      const chainGroup = makeChainGroup({ chain_id: 'chain-cred-1', credential_id: 'cred-1', total_count: 2 });

      const campaigns = planner.generateCampaigns([fi1, fi2], [chainGroup]);

      const spray = campaigns.filter(c => c.strategy === 'credential_spray');
      expect(spray.length).toBe(1);
      expect(spray[0].items).toContain('fi-1');
      expect(spray[0].items).toContain('fi-2');
      expect(spray[0].chain_id).toBe('chain-cred-1');
      expect(spray[0].status).toBe('draft');
      expect(spray[0].progress.total).toBe(2);
    });

    it('does not create spray campaign for single-target chains', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass123' });

      const planner = buildPlanner(graph);
      const fi = makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });
      const chainGroup = makeChainGroup({ total_count: 1 });

      const campaigns = planner.generateCampaigns([fi], [chainGroup]);
      const spray = campaigns.filter(c => c.strategy === 'credential_spray');
      expect(spray.length).toBe(0);
    });

    it('creates enumeration campaigns when ≥3 incomplete nodes of same type', () => {
      const graph = makeGraph();
      addNode(graph, 'h1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'h2', { type: 'host', ip: '10.10.10.2' });
      addNode(graph, 'h3', { type: 'host', ip: '10.10.10.3' });

      const planner = buildPlanner(graph);
      const items = [
        makeFrontierItem({ id: 'fi-h1', type: 'incomplete_node', node_id: 'h1' }),
        makeFrontierItem({ id: 'fi-h2', type: 'incomplete_node', node_id: 'h2' }),
        makeFrontierItem({ id: 'fi-h3', type: 'incomplete_node', node_id: 'h3' }),
      ];

      const campaigns = planner.generateCampaigns(items, []);
      const enums = campaigns.filter(c => c.strategy === 'enumeration');
      expect(enums.length).toBe(1);
      expect(enums[0].items.length).toBe(3);
      expect(enums[0].name).toContain('host');
    });

    it('does not create enumeration campaign below threshold', () => {
      const graph = makeGraph();
      addNode(graph, 'h1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'h2', { type: 'host', ip: '10.10.10.2' });

      const planner = buildPlanner(graph);
      const items = [
        makeFrontierItem({ id: 'fi-h1', type: 'incomplete_node', node_id: 'h1' }),
        makeFrontierItem({ id: 'fi-h2', type: 'incomplete_node', node_id: 'h2' }),
      ];

      const campaigns = planner.generateCampaigns(items, []);
      const enums = campaigns.filter(c => c.strategy === 'enumeration');
      expect(enums.length).toBe(0);
    });

    it('creates post-exploitation campaigns for items sourced from compromised hosts', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1', alive: true });
      addNode(graph, 'user-1', { type: 'user', username: 'admin' });
      addEdge(graph, 'user-1', 'host-1', 'HAS_SESSION', { confidence: 1.0 });

      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addNode(graph, 'svc-2', { type: 'service', service_name: 'ssh', port: 22 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');
      addEdge(graph, 'host-1', 'svc-2', 'RUNS');

      const planner = buildPlanner(graph);
      const items = [
        makeFrontierItem({ id: 'fi-1', edge_source: 'host-1', edge_target: 'svc-1', edge_type: 'ADMIN_TO' as any }),
        makeFrontierItem({ id: 'fi-2', edge_source: 'host-1', edge_target: 'svc-2', edge_type: 'ADMIN_TO' as any }),
      ];

      const campaigns = planner.generateCampaigns(items, []);
      const postex = campaigns.filter(c => c.strategy === 'post_exploitation');
      expect(postex.length).toBe(1);
      expect(postex[0].items.length).toBe(2);
    });

    it('creates network discovery campaigns from discovery items', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      const fi = makeFrontierItem({
        id: 'fi-disc',
        type: 'network_discovery',
        target_cidr: '10.10.10.0/28',
      });

      const campaigns = planner.generateCampaigns([fi], []);
      const discs = campaigns.filter(c => c.strategy === 'network_discovery');
      expect(discs.length).toBe(1);
      expect(discs[0].items).toEqual(['fi-disc']);
    });

    it('skips chain-scored items from post-exploitation grouping', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1', alive: true });
      addNode(graph, 'user-1', { type: 'user', username: 'admin' });
      addEdge(graph, 'user-1', 'host-1', 'HAS_SESSION', { confidence: 1.0 });

      const planner = buildPlanner(graph);
      // Item already in a spray chain — should not also appear in post-exploitation
      const fi = makeFrontierItem({
        id: 'fi-1',
        edge_source: 'host-1',
        edge_target: 'svc-1',
        chain_id: 'chain-cred-1',
      });

      const campaigns = planner.generateCampaigns([fi], []);
      const postex = campaigns.filter(c => c.strategy === 'post_exploitation');
      expect(postex.length).toBe(0);
    });
  });

  // =============================================
  // Campaign stability across recomputation
  // =============================================
  describe('campaign identity stability', () => {
    it('preserves campaign ID across regeneration with same chain', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass123' });

      const planner = buildPlanner(graph);
      const fi1 = makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });
      const fi2 = makeFrontierItem({ id: 'fi-2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any });
      const chain = makeChainGroup();

      const first = planner.generateCampaigns([fi1, fi2], [chain]);
      const secondFi = makeFrontierItem({ id: 'fi-3', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-3', edge_type: 'POTENTIAL_AUTH' as any });
      const second = planner.generateCampaigns([fi1, fi2, secondFi], [chain]);

      const sprayFirst = first.find(c => c.strategy === 'credential_spray')!;
      const spraySecond = second.find(c => c.strategy === 'credential_spray')!;
      expect(spraySecond.id).toBe(sprayFirst.id);
      expect(spraySecond.items.length).toBe(3);
    });

    it('preserves status and progress across regeneration', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'pass123' });

      const planner = buildPlanner(graph);
      const fi1 = makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });
      const fi2 = makeFrontierItem({ id: 'fi-2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any });
      const chain = makeChainGroup();

      const campaigns = planner.generateCampaigns([fi1, fi2], [chain]);
      const c = campaigns.find(c => c.strategy === 'credential_spray')!;
      planner.activateCampaign(c.id);
      planner.updateCampaignProgress(c.id, 'fi-1', 'success');

      // Regenerate
      const regen = planner.generateCampaigns([fi1, fi2], [chain]);
      const regenC = regen.find(r => r.id === c.id)!;
      expect(regenC.status).toBe('active');
      expect(regenC.progress.succeeded).toBe(1);
    });
  });

  // =============================================
  // Campaign lifecycle
  // =============================================
  describe('lifecycle', () => {
    it('activates a draft campaign', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const fi = makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any });
      const [campaign] = planner.generateCampaigns([fi, makeFrontierItem({ id: 'fi-2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any })], [makeChainGroup()]);

      expect(campaign.status).toBe('draft');
      const activated = planner.activateCampaign(campaign.id);
      expect(activated?.status).toBe('active');
      expect(activated?.started_at).toBeTruthy();
    });

    it('pauses and resumes an active campaign', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const items = [
        makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any }),
        makeFrontierItem({ id: 'fi-2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any }),
      ];
      const [c] = planner.generateCampaigns(items, [makeChainGroup()]);
      planner.activateCampaign(c.id);

      const paused = planner.pauseCampaign(c.id);
      expect(paused?.status).toBe('paused');

      const resumed = planner.resumeCampaign(c.id);
      expect(resumed?.status).toBe('active');
    });

    it('aborts a campaign', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const items = [
        makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any }),
        makeFrontierItem({ id: 'fi-2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any }),
      ];
      const [c] = planner.generateCampaigns(items, [makeChainGroup()]);
      planner.activateCampaign(c.id);

      const aborted = planner.abortCampaign(c.id);
      expect(aborted?.status).toBe('aborted');
      expect(aborted?.completed_at).toBeTruthy();
    });

    it('cannot activate a non-draft campaign', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const items = [
        makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any }),
        makeFrontierItem({ id: 'fi-2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any }),
      ];
      const [c] = planner.generateCampaigns(items, [makeChainGroup()]);
      planner.activateCampaign(c.id);

      const result = planner.activateCampaign(c.id);
      expect(result).toBeNull();
    });
  });

  // =============================================
  // Progress tracking
  // =============================================
  describe('progress tracking', () => {
    it('tracks success and failure counts', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const items = [
        makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any }),
        makeFrontierItem({ id: 'fi-2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any }),
      ];
      const [c] = planner.generateCampaigns(items, [makeChainGroup()]);
      planner.activateCampaign(c.id);

      planner.updateCampaignProgress(c.id, 'fi-1', 'success', 'finding-1');
      planner.updateCampaignProgress(c.id, 'fi-2', 'failure');

      const updated = planner.getCampaign(c.id)!;
      expect(updated.progress.completed).toBe(2);
      expect(updated.progress.succeeded).toBe(1);
      expect(updated.progress.failed).toBe(1);
      expect(updated.findings).toContain('finding-1');
    });

    it('auto-completes campaign when all items processed', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const items = [
        makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any }),
        makeFrontierItem({ id: 'fi-2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any }),
      ];
      const [c] = planner.generateCampaigns(items, [makeChainGroup()]);
      planner.activateCampaign(c.id);

      planner.updateCampaignProgress(c.id, 'fi-1', 'success');
      planner.updateCampaignProgress(c.id, 'fi-2', 'success');

      const completed = planner.getCampaign(c.id)!;
      expect(completed.status).toBe('completed');
      expect(completed.completed_at).toBeTruthy();
    });

    it('ignores items not belonging to campaign', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const items = [
        makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any }),
        makeFrontierItem({ id: 'fi-2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any }),
      ];
      const [c] = planner.generateCampaigns(items, [makeChainGroup()]);

      const result = planner.updateCampaignProgress(c.id, 'fi-unknown', 'success');
      expect(result?.progress.completed).toBe(0);
    });
  });

  // =============================================
  // Abort conditions
  // =============================================
  describe('abort conditions', () => {
    it('triggers consecutive failures abort', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const items = Array.from({ length: 6 }, (_, i) =>
        makeFrontierItem({ id: `fi-${i}`, chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: `svc-${i}`, edge_type: 'POTENTIAL_AUTH' as any })
      );
      const chain = makeChainGroup({ total_count: 6 });
      const [c] = planner.generateCampaigns(items, [chain]);
      planner.activateCampaign(c.id);

      // Default spray abort: 5 consecutive failures
      for (let i = 0; i < 5; i++) {
        planner.updateCampaignProgress(c.id, `fi-${i}`, 'failure');
      }

      const check = planner.checkAbortConditions(c.id);
      expect(check.should_abort).toBe(true);
      expect(check.reason).toContain('consecutive failures');
    });

    it('resets consecutive failures on success', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const items = Array.from({ length: 8 }, (_, i) =>
        makeFrontierItem({ id: `fi-${i}`, chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: `svc-${i}`, edge_type: 'POTENTIAL_AUTH' as any })
      );
      const chain = makeChainGroup({ total_count: 8 });
      const [c] = planner.generateCampaigns(items, [chain]);
      planner.activateCampaign(c.id);

      // 4 failures then a success resets counter
      for (let i = 0; i < 4; i++) {
        planner.updateCampaignProgress(c.id, `fi-${i}`, 'failure');
      }
      planner.updateCampaignProgress(c.id, 'fi-4', 'success');

      const check = planner.checkAbortConditions(c.id);
      expect(check.should_abort).toBe(false);
    });

    it('triggers total failure percentage abort', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const items = Array.from({ length: 20 }, (_, i) =>
        makeFrontierItem({ id: `fi-${i}`, chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: `svc-${i}`, edge_type: 'POTENTIAL_AUTH' as any })
      );
      const chain = makeChainGroup({ total_count: 20 });
      const [c] = planner.generateCampaigns(items, [chain]);
      planner.activateCampaign(c.id);

      // Interleave a success every 4 failures to avoid consecutive_failures (threshold 5)
      // but keep overall failure rate > 90%: 16 failures + 4 successes = 80% — need higher.
      // Use: 4 fail, 1 succeed, 4 fail, 1 succeed, 4 fail, 1 succeed, 4 fail → 16F/3S = 84%
      // Need > 90%. Use: 4 fail, 1 succeed, 4 fail, 1 succeed, 9 fail → 17F/2S but 9 consecutive.
      // Just override abort_conditions to disable consecutive and only test pct:
      c.abort_conditions = [{ type: 'total_failures_pct', threshold: 0.9 }];
      for (let i = 0; i < 19; i++) {
        planner.updateCampaignProgress(c.id, `fi-${i}`, 'failure');
      }

      const check = planner.checkAbortConditions(c.id);
      expect(check.should_abort).toBe(true);
      expect(check.reason).toContain('failure rate');
    });

    it('does not trigger failure percentage with insufficient data', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const items = Array.from({ length: 10 }, (_, i) =>
        makeFrontierItem({ id: `fi-${i}`, chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: `svc-${i}`, edge_type: 'POTENTIAL_AUTH' as any })
      );
      const chain = makeChainGroup({ total_count: 10 });
      const [c] = planner.generateCampaigns(items, [chain]);
      planner.activateCampaign(c.id);

      // Only 2 failures — not enough data to trigger pct check (needs ≥3)
      planner.updateCampaignProgress(c.id, 'fi-0', 'failure');
      planner.updateCampaignProgress(c.id, 'fi-1', 'failure');

      const check = planner.checkAbortConditions(c.id);
      // consecutive_failures = 2, threshold = 5 → not triggered
      // total_failures_pct = 100% but only 2 samples → not triggered
      expect(check.should_abort).toBe(false);
    });
  });

  // =============================================
  // Lookup helpers
  // =============================================
  describe('findCampaignForItem', () => {
    it('finds the campaign containing a frontier item', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      const planner = buildPlanner(graph);
      const items = [
        makeFrontierItem({ id: 'fi-1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any }),
        makeFrontierItem({ id: 'fi-2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any }),
      ];
      planner.generateCampaigns(items, [makeChainGroup()]);

      const found = planner.findCampaignForItem('fi-1');
      expect(found).toBeTruthy();
      expect(found!.strategy).toBe('credential_spray');
    });

    it('returns null for unaffiliated item', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      planner.generateCampaigns([], []);

      expect(planner.findCampaignForItem('nonexistent')).toBeNull();
    });
  });

  // =============================================
  // Edge cases
  // =============================================
  describe('edge cases', () => {
    it('handles empty frontier', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      const campaigns = planner.generateCampaigns([], []);
      expect(campaigns).toEqual([]);
    });

    it('handles frontier with no groupable items', () => {
      const graph = makeGraph();
      addNode(graph, 'h1', { type: 'host', ip: '10.10.10.1' });

      const planner = buildPlanner(graph);
      // Only 1 incomplete host — below threshold
      const fi = makeFrontierItem({ id: 'fi-1', type: 'incomplete_node', node_id: 'h1' });
      const campaigns = planner.generateCampaigns([fi], []);
      expect(campaigns.length).toBe(0);
    });

    it('listCampaigns filters by status', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_value: 'x' });
      addNode(graph, 'h1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'h2', { type: 'host', ip: '10.10.10.2' });
      addNode(graph, 'h3', { type: 'host', ip: '10.10.10.3' });

      const planner = buildPlanner(graph);
      const sprayItems = [
        makeFrontierItem({ id: 'fi-s1', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-1', edge_type: 'POTENTIAL_AUTH' as any }),
        makeFrontierItem({ id: 'fi-s2', chain_id: 'chain-cred-1', edge_source: 'cred-1', edge_target: 'svc-2', edge_type: 'POTENTIAL_AUTH' as any }),
      ];
      const enumItems = [
        makeFrontierItem({ id: 'fi-h1', type: 'incomplete_node', node_id: 'h1' }),
        makeFrontierItem({ id: 'fi-h2', type: 'incomplete_node', node_id: 'h2' }),
        makeFrontierItem({ id: 'fi-h3', type: 'incomplete_node', node_id: 'h3' }),
      ];
      const allItems = [...sprayItems, ...enumItems];

      planner.generateCampaigns(allItems, [makeChainGroup()]);
      const all = planner.listCampaigns();
      expect(all.length).toBe(2);

      // Activate one
      planner.activateCampaign(all[0].id);
      const active = planner.listCampaigns({ status: 'active' });
      expect(active.length).toBe(1);

      const drafts = planner.listCampaigns({ status: 'draft' });
      expect(drafts.length).toBe(1);
    });
  });

  // =============================================
  // Manual CRUD
  // =============================================
  describe('createCampaign', () => {
    it('creates a campaign with specified items and strategy', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);

      const campaign = planner.createCampaign({
        name: 'Custom spray',
        strategy: 'credential_spray',
        item_ids: ['fi-1', 'fi-2', 'fi-3'],
      });

      expect(campaign.id).toBeTruthy();
      expect(campaign.name).toBe('Custom spray');
      expect(campaign.strategy).toBe('credential_spray');
      expect(campaign.status).toBe('draft');
      expect(campaign.items).toEqual(['fi-1', 'fi-2', 'fi-3']);
      expect(campaign.progress.total).toBe(3);
      expect(campaign.progress.completed).toBe(0);
      // Default abort conditions for credential_spray
      expect(campaign.abort_conditions).toEqual([
        { type: 'consecutive_failures', threshold: 5 },
        { type: 'total_failures_pct', threshold: 0.9 },
      ]);
    });

    it('uses custom abort conditions when provided', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);

      const campaign = planner.createCampaign({
        name: 'Careful enum',
        strategy: 'enumeration',
        item_ids: ['fi-1'],
        abort_conditions: [{ type: 'consecutive_failures', threshold: 2 }],
      });

      expect(campaign.abort_conditions).toEqual([{ type: 'consecutive_failures', threshold: 2 }]);
    });

    it('throws when name is empty', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      expect(() => planner.createCampaign({ name: '', strategy: 'custom', item_ids: ['fi-1'] }))
        .toThrow('Campaign name is required');
    });

    it('throws when item_ids is empty', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      expect(() => planner.createCampaign({ name: 'Test', strategy: 'custom', item_ids: [] }))
        .toThrow('At least one frontier item is required');
    });

    it('created campaign is retrievable via getCampaign and listCampaigns', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);

      const campaign = planner.createCampaign({
        name: 'Lookup test',
        strategy: 'custom',
        item_ids: ['fi-1'],
      });

      expect(planner.getCampaign(campaign.id)).toBe(campaign);
      expect(planner.listCampaigns()).toContain(campaign);
    });
  });

  describe('updateCampaign', () => {
    it('updates name and abort conditions on a draft campaign', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      const campaign = planner.createCampaign({ name: 'Original', strategy: 'custom', item_ids: ['fi-1'] });

      const updated = planner.updateCampaign(campaign.id, {
        name: 'Renamed',
        abort_conditions: [{ type: 'time_limit_seconds', threshold: 300 }],
      });

      expect(updated!.name).toBe('Renamed');
      expect(updated!.abort_conditions).toEqual([{ type: 'time_limit_seconds', threshold: 300 }]);
    });

    it('adds and removes items', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      const campaign = planner.createCampaign({ name: 'Items', strategy: 'custom', item_ids: ['fi-1', 'fi-2'] });

      planner.updateCampaign(campaign.id, { add_items: ['fi-3'] });
      expect(campaign.items).toEqual(['fi-1', 'fi-2', 'fi-3']);
      expect(campaign.progress.total).toBe(3);

      planner.updateCampaign(campaign.id, { remove_items: ['fi-1'] });
      expect(campaign.items).toEqual(['fi-2', 'fi-3']);
      expect(campaign.progress.total).toBe(2);
    });

    it('does not duplicate items on add', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      const campaign = planner.createCampaign({ name: 'Dup', strategy: 'custom', item_ids: ['fi-1'] });

      planner.updateCampaign(campaign.id, { add_items: ['fi-1'] });
      expect(campaign.items).toEqual(['fi-1']);
    });

    it('allows update on paused campaigns', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      const campaign = planner.createCampaign({ name: 'Pause update', strategy: 'custom', item_ids: ['fi-1'] });
      planner.activateCampaign(campaign.id);
      planner.pauseCampaign(campaign.id);

      const updated = planner.updateCampaign(campaign.id, { name: 'New name' });
      expect(updated!.name).toBe('New name');
    });

    it('throws when updating an active campaign', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      const campaign = planner.createCampaign({ name: 'Active', strategy: 'custom', item_ids: ['fi-1'] });
      planner.activateCampaign(campaign.id);

      expect(() => planner.updateCampaign(campaign.id, { name: 'Nope' }))
        .toThrow("Cannot update campaign in 'active' status");
    });

    it('returns null for nonexistent campaign', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      expect(planner.updateCampaign('nonexistent', { name: 'x' })).toBeNull();
    });
  });

  describe('deleteCampaign', () => {
    it('deletes a draft campaign', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      const campaign = planner.createCampaign({ name: 'Delete me', strategy: 'custom', item_ids: ['fi-1'] });

      expect(planner.deleteCampaign(campaign.id)).toBe(true);
      expect(planner.getCampaign(campaign.id)).toBeNull();
      expect(planner.listCampaigns()).not.toContain(campaign);
    });

    it('throws when deleting a non-draft campaign', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      const campaign = planner.createCampaign({ name: 'Active', strategy: 'custom', item_ids: ['fi-1'] });
      planner.activateCampaign(campaign.id);

      expect(() => planner.deleteCampaign(campaign.id)).toThrow("Cannot delete campaign in 'active' status");
    });

    it('returns false for nonexistent campaign', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      expect(planner.deleteCampaign('nonexistent')).toBe(false);
    });
  });

  describe('cloneCampaign', () => {
    it('clones a campaign as a new draft', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      const original = planner.createCampaign({
        name: 'Original',
        strategy: 'enumeration',
        item_ids: ['fi-1', 'fi-2'],
        abort_conditions: [{ type: 'consecutive_failures', threshold: 3 }],
      });
      planner.activateCampaign(original.id);

      const clone = planner.cloneCampaign(original.id);

      expect(clone).toBeTruthy();
      expect(clone!.id).not.toBe(original.id);
      expect(clone!.name).toBe('Original (copy)');
      expect(clone!.strategy).toBe('enumeration');
      expect(clone!.status).toBe('draft');
      expect(clone!.items).toEqual(['fi-1', 'fi-2']);
      expect(clone!.abort_conditions).toEqual([{ type: 'consecutive_failures', threshold: 3 }]);
      expect(clone!.progress.completed).toBe(0);
      expect(clone!.progress.succeeded).toBe(0);
    });

    it('cloned campaign has independent abort conditions', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      const original = planner.createCampaign({
        name: 'Shared AC',
        strategy: 'custom',
        item_ids: ['fi-1'],
        abort_conditions: [{ type: 'consecutive_failures', threshold: 5 }],
      });

      const clone = planner.cloneCampaign(original.id)!;
      clone.abort_conditions[0].threshold = 99;
      expect(original.abort_conditions[0].threshold).toBe(5);
    });

    it('returns null for nonexistent campaign', () => {
      const graph = makeGraph();
      const planner = buildPlanner(graph);
      expect(planner.cloneCampaign('nonexistent')).toBeNull();
    });
  });
});
