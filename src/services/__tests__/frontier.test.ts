import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties, EdgeProperties } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { FrontierComputer } from '../frontier.js';
import { KnowledgeBase } from '../knowledge-base.js';

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

function buildFrontier(graph: OverwatchGraph, config?: any) {
  const ctx = new EngineContext(graph, config || makeConfig(), './test-state.json');
  const hopsToObjective = () => null;
  return { frontier: new FrontierComputer(ctx, hopsToObjective), ctx };
}

describe('FrontierComputer', () => {
  // =============================================
  // Section 1: Incomplete nodes
  // =============================================
  describe('incomplete nodes', () => {
    it('detects host missing alive status', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1' });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const hostItems = items.filter(i => i.type === 'incomplete_node' && i.node_id === 'host-1');
      expect(hostItems.length).toBe(1);
      expect(hostItems[0].missing_properties).toContain('alive');
    });

    it('detects alive host missing OS', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1', alive: true });
      // Add a service so 'services' isn't missing
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const hostItems = items.filter(i => i.type === 'incomplete_node' && i.node_id === 'host-1');
      expect(hostItems.length).toBe(1);
      expect(hostItems[0].missing_properties).toContain('os');
    });

    it('detects alive host missing services', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1', alive: true, os: 'Windows' });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const hostItems = items.filter(i => i.type === 'incomplete_node' && i.node_id === 'host-1');
      expect(hostItems.length).toBe(1);
      expect(hostItems[0].missing_properties).toContain('services');
    });

    it('does NOT flag dead host for missing OS/services', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1', alive: false });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const hostItems = items.filter(i => i.type === 'incomplete_node' && i.node_id === 'host-1');
      expect(hostItems.length).toBe(0);
    });

    it('flags Linux host for missing suid_checked/cron_checked/capabilities_checked', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1', alive: true, os: 'Linux Ubuntu 22.04' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'ssh', port: 22 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const hostItems = items.filter(i => i.type === 'incomplete_node' && i.node_id === 'host-1');
      expect(hostItems.length).toBe(1);
      expect(hostItems[0].missing_properties).toContain('suid_checked');
      expect(hostItems[0].missing_properties).toContain('cron_checked');
      expect(hostItems[0].missing_properties).toContain('capabilities_checked');
    });

    it('skips superseded nodes', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1', identity_status: 'superseded' });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const hostItems = items.filter(i => i.type === 'incomplete_node' && i.node_id === 'host-1');
      expect(hostItems.length).toBe(0);
    });

    it('detects service missing version', () => {
      const graph = makeGraph();
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const svcItems = items.filter(i => i.type === 'incomplete_node' && i.node_id === 'svc-1');
      expect(svcItems.length).toBe(1);
      expect(svcItems[0].missing_properties).toContain('version');
    });

    it('detects user missing privilege_level', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', username: 'jdoe' });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const userItems = items.filter(i => i.type === 'incomplete_node' && i.node_id === 'user-1');
      expect(userItems.length).toBe(1);
      expect(userItems[0].missing_properties).toContain('privilege_level');
    });
  });

  // =============================================
  // Section 2: Untested inferred edges
  // =============================================
  describe('untested inferred edges', () => {
    it('includes untested low-confidence edges', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'cred-1', 'svc-1', 'POTENTIAL_AUTH', { confidence: 0.4, tested: false });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const edgeItems = items.filter(i => i.type === 'inferred_edge' && i.edge_type === 'POTENTIAL_AUTH');
      expect(edgeItems.length).toBe(1);
    });

    it('excludes tested edges', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'cred-1', 'svc-1', 'POTENTIAL_AUTH', { confidence: 0.4, tested: true });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const edgeItems = items.filter(i => i.type === 'inferred_edge' && i.edge_type === 'POTENTIAL_AUTH');
      expect(edgeItems.length).toBe(0);
    });

    it('includes high-confidence untested edges in frontier', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user' });
      addNode(graph, 'host-1', { type: 'host' });
      addEdge(graph, 'user-1', 'host-1', 'HAS_SESSION', { confidence: 1.0, tested: false });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const edgeItems = items.filter(i => i.type === 'inferred_edge');
      expect(edgeItems.length).toBe(1);
    });

    it('excludes high-confidence tested edges from frontier', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user' });
      addNode(graph, 'host-1', { type: 'host' });
      addEdge(graph, 'user-1', 'host-1', 'HAS_SESSION', { confidence: 1.0, tested: true });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const edgeItems = items.filter(i => i.type === 'inferred_edge');
      expect(edgeItems.length).toBe(0);
    });

    it('penalizes stale credential edges', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', {
        type: 'credential',
        cred_type: 'ntlm',
        cred_material_kind: 'ntlm_hash',
        cred_usable_for_auth: true,
        cred_value: 'aabbccdd',
        credential_status: 'expired',
      });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'cred-1', 'svc-1', 'POTENTIAL_AUTH', { confidence: 0.8, tested: false });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const edgeItems = items.filter(i => i.type === 'inferred_edge');
      expect(edgeItems.length).toBe(1);
      // Stale credential should be penalized (confidence * 0.1)
      expect(edgeItems[0].graph_metrics.confidence).toBeCloseTo(0.08);
      expect(edgeItems[0].stale_credential).toBe(true);
    });
  });

  // =============================================
  // Section 3: Network discovery
  // =============================================
  describe('network discovery', () => {
    it('generates discovery items from scope CIDRs', () => {
      const graph = makeGraph();
      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const discoveryItems = items.filter(i => i.type === 'network_discovery');
      expect(discoveryItems.length).toBe(1);
      expect(discoveryItems[0].target_cidr).toBe('10.10.10.0/28');
    });

    it('suppresses fully-discovered CIDRs', () => {
      const graph = makeGraph();
      // Add enough hosts to fill a /28 (14 hosts)
      for (let i = 1; i <= 14; i++) {
        addNode(graph, `host-${i}`, { type: 'host', ip: `10.10.10.${i}` });
      }

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const discoveryItems = items.filter(i => i.type === 'network_discovery');
      expect(discoveryItems.length).toBe(0);
    });

    it('reduces fan_out for partially-discovered CIDRs', () => {
      const graph = makeGraph();
      // Add 5 hosts out of 14 possible in /28
      for (let i = 1; i <= 5; i++) {
        addNode(graph, `host-${i}`, { type: 'host', ip: `10.10.10.${i}` });
      }

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const discoveryItems = items.filter(i => i.type === 'network_discovery');
      expect(discoveryItems.length).toBe(1);
      expect(discoveryItems[0].graph_metrics.fan_out_estimate).toBe(14 - 5);
    });

    it('counts cold store IPs toward CIDR discovery', () => {
      const graph = makeGraph();
      const { frontier, ctx } = buildFrontier(graph);

      // Add 14 cold store IPs to fill the /28
      for (let i = 1; i <= 14; i++) {
        ctx.coldStore.add({
          id: `host-cold-${i}`,
          type: 'host',
          label: `10.10.10.${i}`,
          ip: `10.10.10.${i}`,
          discovered_at: now,
          last_seen_at: now,
          alive: true,
        });
      }

      const items = frontier.compute();
      const discoveryItems = items.filter(i => i.type === 'network_discovery');
      expect(discoveryItems.length).toBe(0);
    });

    it('handles very broad CIDRs without overflow', () => {
      const graph = makeGraph();
      const config = makeConfig({ scope: { cidrs: ['10.0.0.0/1'], domains: ['test.local'], exclusions: [] } });
      const { frontier } = buildFrontier(graph, config);
      const items = frontier.compute();

      const discoveryItems = items.filter(i => i.type === 'network_discovery');
      expect(discoveryItems.length).toBe(1);
      // Should be capped at 254, not negative due to bit-shift overflow
      expect(discoveryItems[0].graph_metrics.fan_out_estimate).toBe(254);
    });
  });

  // =============================================
  // Section 4: Network pivot items
  // =============================================
  describe('network pivot', () => {
    it('generates pivot items for reachable hosts without sessions', () => {
      const graph = makeGraph();
      const config = makeConfig({ scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] } });

      // Subnet node
      addNode(graph, 'subnet-10-10-10-0-24', { type: 'subnet', subnet_cidr: '10.10.10.0/24' });

      // Pivot host with session
      addNode(graph, 'host-pivot', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'user-attacker', { type: 'user' });
      addEdge(graph, 'user-attacker', 'host-pivot', 'HAS_SESSION');

      // Peer host without session in same subnet
      addNode(graph, 'host-peer', { type: 'host', ip: '10.10.10.5' });

      const { frontier } = buildFrontier(graph, config);
      const items = frontier.compute();

      const pivotItems = items.filter(i => i.type === 'network_pivot');
      expect(pivotItems.length).toBe(1);
      expect(pivotItems[0].node_id).toBe('host-peer');
      expect(pivotItems[0].pivot_host_id).toBe('host-pivot');
    });

    it('skips peers that already have sessions', () => {
      const graph = makeGraph();
      const config = makeConfig({ scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] } });

      addNode(graph, 'subnet-10-10-10-0-24', { type: 'subnet', subnet_cidr: '10.10.10.0/24' });
      addNode(graph, 'host-pivot', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'host-peer', { type: 'host', ip: '10.10.10.5' });
      addNode(graph, 'user-1', { type: 'user' });
      addNode(graph, 'user-2', { type: 'user' });
      addEdge(graph, 'user-1', 'host-pivot', 'HAS_SESSION');
      addEdge(graph, 'user-2', 'host-peer', 'HAS_SESSION');

      const { frontier } = buildFrontier(graph, config);
      const items = frontier.compute();

      const pivotItems = items.filter(i => i.type === 'network_pivot');
      expect(pivotItems.length).toBe(0);
    });
  });

  // =============================================
  // Graph metrics
  // =============================================
  describe('graph metrics', () => {
    it('includes node_degree in frontier items', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', ip: '10.10.10.1' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const hostItem = items.find(i => i.type === 'incomplete_node' && i.node_id === 'host-1');
      expect(hostItem).toBeDefined();
      expect(hostItem!.graph_metrics.node_degree).toBe(1);
    });

    it('estimates fan_out for kerberos service', () => {
      const graph = makeGraph();
      addNode(graph, 'svc-kerb', { type: 'service', service_name: 'kerberos', port: 88 });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const svcItem = items.find(i => i.type === 'incomplete_node' && i.node_id === 'svc-kerb');
      expect(svcItem).toBeDefined();
      expect(svcItem!.graph_metrics.fan_out_estimate).toBe(50);
    });
  });

  // =============================================
  // KB-informed scoring
  // =============================================
  describe('KB-informed scoring', () => {
    it('adjusts inferred edge confidence using KB success rate', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user' });
      addNode(graph, 'host-dc', { type: 'host', ip: '10.10.10.1', alive: true, os: 'Windows Server 2019' });
      addEdge(graph, 'user-1', 'host-dc', 'CAN_DCSYNC', { tested: false });

      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const kb = new KnowledgeBase('/tmp/test-kb-frontier-' + Date.now() + '.json');
      // Record a high-success technique (DCSync = T1003.006)
      kb.recordTechniqueAttempt('T1003.006', 'DCSync', true, 0.8);
      kb.recordTechniqueAttempt('T1003.006', 'DCSync', true, 0.7);
      kb.recordTechniqueAttempt('T1003.006', 'DCSync', false, 0.9);

      const frontier = new FrontierComputer(ctx, () => null, kb);
      const items = frontier.compute();

      const dcSync = items.find(i => i.type === 'inferred_edge' && i.edge_type === 'CAN_DCSYNC');
      expect(dcSync).toBeDefined();
      // KB success 67% → boost = 1 + (0.67-0.5)*0.4 ≈ 1.068
      expect(dcSync!.graph_metrics.confidence).toBeGreaterThan(1.0);
      // Noise should come from KB avg_noise
      expect(dcSync!.opsec_noise).toBeCloseTo(0.8, 1);
      expect(dcSync!.description).toContain('KB:');
    });

    it('reduces confidence for low-success KB technique', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user' });
      addNode(graph, 'svc-1', { type: 'service' });
      addEdge(graph, 'user-1', 'svc-1', 'KERBEROASTABLE', { tested: false });

      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const kb = new KnowledgeBase('/tmp/test-kb-frontier2-' + Date.now() + '.json');
      // Record a low-success technique (Kerberoasting = T1558.003)
      kb.recordTechniqueAttempt('T1558.003', 'Kerberoasting', false, 0.5);
      kb.recordTechniqueAttempt('T1558.003', 'Kerberoasting', false, 0.4);
      kb.recordTechniqueAttempt('T1558.003', 'Kerberoasting', false, 0.6);

      const frontier = new FrontierComputer(ctx, () => null, kb);
      const items = frontier.compute();

      const kerb = items.find(i => i.type === 'inferred_edge' && i.edge_type === 'KERBEROASTABLE');
      expect(kerb).toBeDefined();
      // KB success 0% → boost = 1 + (0-0.5)*0.4 = 0.8
      expect(kerb!.graph_metrics.confidence).toBeLessThan(1.0);
    });

    it('uses default noise when no KB available', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user' });
      addNode(graph, 'host-1', { type: 'host' });
      addEdge(graph, 'user-1', 'host-1', 'CAN_DCSYNC', { tested: false });

      const { frontier } = buildFrontier(graph);
      const items = frontier.compute();

      const dcSync = items.find(i => i.type === 'inferred_edge' && i.edge_type === 'CAN_DCSYNC');
      expect(dcSync).toBeDefined();
      expect(dcSync!.opsec_noise).toBe(0.3); // default
      expect(dcSync!.description).not.toContain('KB:');
    });
  });
});
