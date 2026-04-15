import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties, EdgeProperties, EdgeType } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { BloodHoundPathEnricher, ATTACK_PATH_TEMPLATES } from '../bloodhound-paths.js';
import { PathAnalyzer } from '../path-analyzer.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

function makeConfig(overrides: Record<string, unknown> = {}) {
  return {
    id: 'test-eng',
    name: 'Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local'], exclusions: [] },
    objectives: [{ id: 'obj-da', description: 'Get DA', target_node_type: 'credential', target_criteria: { privileged: true }, achieved: false }],
    opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
    ...overrides,
  } as any;
}

const now = new Date().toISOString();

const BIDIR: Set<EdgeType> = new Set([
  'HAS_SESSION', 'ADMIN_TO', 'CAN_RDPINTO', 'CAN_PSREMOTE',
  'OWNS_CRED', 'VALID_ON', 'MEMBER_OF', 'MEMBER_OF_DOMAIN',
  'RELATED', 'SAME_DOMAIN', 'TRUSTS', 'ASSUMES_ROLE', 'MANAGED_BY',
] as EdgeType[]);

function addNode(graph: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  graph.addNode(id, { id, label: id, discovered_at: now, confidence: 1.0, ...props } as NodeProperties);
}

function addEdge(graph: OverwatchGraph, src: string, tgt: string, type: string, extra: Record<string, unknown> = {}) {
  return graph.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: now, ...extra } as EdgeProperties);
}

function buildEnricher(graph: OverwatchGraph, config?: any) {
  const ctx = new EngineContext(graph, config || makeConfig(), './test-state.json');
  return new BloodHoundPathEnricher(ctx);
}



describe('BloodHound Path Enricher', () => {

  describe('computeHighValueTargets', () => {
    it('tags Domain Admins group as HVT', () => {
      const graph = makeGraph();
      addNode(graph, 'grp-da', { type: 'group', label: 'Domain Admins', sid: 'S-1-5-21-1234-512' });
      addNode(graph, 'user-bob', { type: 'user', label: 'bob' });
      addEdge(graph, 'user-bob', 'grp-da', 'MEMBER_OF');

      const enricher = buildEnricher(graph);
      const hvts = enricher.computeHighValueTargets();

      expect(hvts.length).toBeGreaterThanOrEqual(2);
      const daGroup = hvts.find(h => h.node_id === 'grp-da');
      expect(daGroup).toBeDefined();
      expect(daGroup!.reason).toContain('Domain Admins');

      // Bob should also be tagged as member
      const bob = hvts.find(h => h.node_id === 'user-bob');
      expect(bob).toBeDefined();
      expect(bob!.reason).toContain('Member of');
    });

    it('tags users with DCSync rights as HVT', () => {
      const graph = makeGraph();
      addNode(graph, 'user-evil', { type: 'user', label: 'evil-admin' });
      addNode(graph, 'domain-root', { type: 'domain', label: 'test.local' });
      addEdge(graph, 'user-evil', 'domain-root', 'CAN_DCSYNC');

      const enricher = buildEnricher(graph);
      const hvts = enricher.computeHighValueTargets();

      const evilUser = hvts.find(h => h.node_id === 'user-evil');
      expect(evilUser).toBeDefined();
      expect(evilUser!.reason).toContain('DCSync');
    });

    it('tags Enterprise Admins by SID suffix', () => {
      const graph = makeGraph();
      addNode(graph, 'grp-ea', { type: 'group', label: 'Enterprise Admins', sid: 'S-1-5-21-9999-519' });

      const enricher = buildEnricher(graph);
      const hvts = enricher.computeHighValueTargets();

      expect(hvts.some(h => h.node_id === 'grp-ea')).toBe(true);
    });

    it('tags privileged users', () => {
      const graph = makeGraph();
      addNode(graph, 'user-priv', { type: 'user', label: 'svc-admin', privileged: true });

      const enricher = buildEnricher(graph);
      const hvts = enricher.computeHighValueTargets();

      expect(hvts.some(h => h.node_id === 'user-priv')).toBe(true);
    });

    it('tags Azure Global Admin', () => {
      const graph = makeGraph();
      addNode(graph, 'azure-ga', { type: 'cloud_identity', label: 'GlobalAdmin@corp.com', role_name: 'Global Administrator' } as any);

      const enricher = buildEnricher(graph);
      const hvts = enricher.computeHighValueTargets();

      expect(hvts.some(h => h.node_id === 'azure-ga')).toBe(true);
    });

    it('returns empty for graph with no HVTs', () => {
      const graph = makeGraph();
      addNode(graph, 'user-regular', { type: 'user', label: 'normie' });
      addNode(graph, 'host-ws', { type: 'host', label: 'workstation1' });

      const enricher = buildEnricher(graph);
      const hvts = enricher.computeHighValueTargets();

      expect(hvts.length).toBe(0);
    });
  });

  describe('getOwnedNodes', () => {
    it('returns nodes with confirmed access edges', () => {
      const graph = makeGraph();
      addNode(graph, 'host-owned', { type: 'host', label: 'owned-host' });
      addNode(graph, 'user-compromised', { type: 'user', label: 'compromised' });
      addNode(graph, 'host-target', { type: 'host', label: 'target' });
      addEdge(graph, 'user-compromised', 'host-owned', 'ADMIN_TO');

      const enricher = buildEnricher(graph);
      const owned = enricher.getOwnedNodes();

      expect(owned).toContain('user-compromised');
    });
  });

  describe('matchPathTemplate', () => {
    it('matches ACL takeover template', () => {
      const graph = makeGraph();
      addNode(graph, 'a', { type: 'user', label: 'attacker' });
      addNode(graph, 'b', { type: 'user', label: 'middle' });
      addNode(graph, 'c', { type: 'group', label: 'target-group' });
      addNode(graph, 'd', { type: 'user', label: 'victim' });
      addNode(graph, 'e', { type: 'user', label: 'final' });
      addEdge(graph, 'a', 'b', 'WRITE_OWNER');
      addEdge(graph, 'b', 'c', 'WRITE_DACL');
      addEdge(graph, 'c', 'd', 'GENERIC_ALL');
      addEdge(graph, 'd', 'e', 'FORCE_CHANGE_PASSWORD');

      const enricher = buildEnricher(graph);
      const template = enricher.matchPathTemplate(['a', 'b', 'c', 'd', 'e']);

      expect(template).toBeDefined();
      expect(template!.id).toBe('acl-takeover');
    });

    it('matches ADCS ESC1 chain', () => {
      const graph = makeGraph();
      addNode(graph, 'user1', { type: 'user', label: 'user1' });
      addNode(graph, 'cert-tmpl', { type: 'certificate', label: 'VulnTemplate' });
      addNode(graph, 'ca', { type: 'host', label: 'CA01' });
      addNode(graph, 'target', { type: 'user', label: 'admin' });
      addEdge(graph, 'user1', 'cert-tmpl', 'CAN_ENROLL');
      addEdge(graph, 'cert-tmpl', 'ca', 'ESC1');
      addEdge(graph, 'ca', 'target', 'AUTHENTICATED_AS');

      const enricher = buildEnricher(graph);
      const template = enricher.matchPathTemplate(['user1', 'cert-tmpl', 'ca', 'target']);

      expect(template).toBeDefined();
      expect(template!.id).toBe('adcs-esc1');
    });

    it('returns undefined for non-matching paths', () => {
      const graph = makeGraph();
      addNode(graph, 'x', { type: 'host', label: 'x' });
      addNode(graph, 'y', { type: 'host', label: 'y' });
      addEdge(graph, 'x', 'y', 'REACHABLE');

      const enricher = buildEnricher(graph);
      expect(enricher.matchPathTemplate(['x', 'y'])).toBeUndefined();
    });
  });

  describe('ATTACK_PATH_TEMPLATES', () => {
    it('has unique IDs', () => {
      const ids = ATTACK_PATH_TEMPLATES.map(t => t.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it('has valid edge sequences', () => {
      for (const t of ATTACK_PATH_TEMPLATES) {
        expect(t.edge_sequence.length).toBeGreaterThan(0);
        expect(t.confidence_modifier).toBeGreaterThan(0);
        expect(t.confidence_modifier).toBeLessThanOrEqual(1);
      }
    });
  });

  describe('preComputeAttackPaths', () => {
    it('finds paths from owned nodes to HVTs', () => {
      const graph = makeGraph();
      // Set up: user with session → host → admin → DC (HVT)
      addNode(graph, 'user-owned', { type: 'user', label: 'hacker' });
      addNode(graph, 'host-ws', { type: 'host', label: 'workstation' });
      addNode(graph, 'grp-da', { type: 'group', label: 'Domain Admins', sid: 'S-1-5-21-1234-512' });
      addEdge(graph, 'user-owned', 'host-ws', 'HAS_SESSION');
      addEdge(graph, 'host-ws', 'grp-da', 'GENERIC_ALL');

      // Build enricher with shared context
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const enricher = new BloodHoundPathEnricher(ctx);
      const queryGraph = (query: any) => {
        const nodes: any[] = [];
        graph.forEachNode((id: string, attrs) => {
          if (query.node_type && attrs.type !== query.node_type) return;
          if (query.node_filter) {
            for (const [k, v] of Object.entries(query.node_filter)) {
              if ((attrs as any)[k] !== v) return;
            }
          }
          nodes.push({ id, properties: attrs });
        });
        return { nodes, edges: [] };
      };
      const pathAnalyzer = new PathAnalyzer(ctx, BIDIR, queryGraph);

      // Tag HVTs first
      enricher.computeHighValueTargets();

      const paths = enricher.preComputeAttackPaths(pathAnalyzer);
      expect(paths.length).toBeGreaterThan(0);
      // Either user-owned or host-ws can be "from" since HAS_SESSION is bidirectional
      const fromNodes = paths.map(p => p.from);
      expect(fromNodes.some(f => f === 'user-owned' || f === 'host-ws')).toBe(true);
    });

    it('returns empty when no owned nodes', () => {
      const graph = makeGraph();
      addNode(graph, 'grp-da', { type: 'group', label: 'Domain Admins', sid: 'S-1-5-21-1234-512' });

      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const enricher = new BloodHoundPathEnricher(ctx);
      const queryGraph = () => ({ nodes: [], edges: [] });
      const pathAnalyzer = new PathAnalyzer(ctx, BIDIR, queryGraph);

      enricher.computeHighValueTargets();
      const paths = enricher.preComputeAttackPaths(pathAnalyzer);
      expect(paths.length).toBe(0);
    });
  });
});
