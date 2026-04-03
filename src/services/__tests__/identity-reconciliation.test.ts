import { describe, it, expect, beforeEach } from 'vitest';
import GraphImport from 'graphology';
const Graph = (GraphImport as any).default || GraphImport;
import type { NodeProperties, EdgeProperties } from '../../types.js';
import type { OverwatchGraph, ActivityLogEntry } from '../engine-context.js';
import { IdentityReconciler } from '../identity-reconciliation.js';
import type { ReconcilerCallbacks } from '../identity-reconciliation.js';

function makeGraph(): OverwatchGraph {
  return new Graph({ multi: true, type: 'directed', allowSelfLoops: true }) as unknown as OverwatchGraph;
}

function makeNode(id: string, overrides: Partial<NodeProperties> = {}): NodeProperties {
  return {
    id,
    type: 'host',
    label: id,
    discovered_at: new Date().toISOString(),
    confidence: 1.0,
    ...overrides,
  } as NodeProperties;
}

function edgeProps(type: string, extra: Record<string, unknown> = {}): EdgeProperties {
  return { type, confidence: 1.0, discovered_at: new Date().toISOString(), ...extra } as EdgeProperties;
}

describe('IdentityReconciler', () => {
  let graph: OverwatchGraph;
  let logEntries: Array<Partial<ActivityLogEntry>>;
  let pathInvalidated: boolean;
  let callbacks: ReconcilerCallbacks;

  beforeEach(() => {
    graph = makeGraph();
    logEntries = [];
    pathInvalidated = false;
    callbacks = {
      getNode: (id: string) => graph.hasNode(id) ? graph.getNodeAttributes(id) as NodeProperties : null,
      addEdge: (source: string, target: string, props: EdgeProperties) => {
        // Dedup by source+target+type
        for (const e of graph.edges(source, target)) {
          if (graph.getEdgeAttributes(e).type === props.type) {
            return { id: e, isNew: false };
          }
        }
        const id = graph.addEdge(source, target, props);
        return { id, isNew: true };
      },
      logActionEvent: (event) => { logEntries.push(event); },
      invalidatePathGraph: () => { pathInvalidated = true; },
    };
  });

  // =============================================
  // Forward merge: unresolved alias → canonical
  // =============================================
  describe('forward merge (unresolved alias → canonical)', () => {
    it('merges an unresolved alias into a canonical node and retargets edges', () => {
      // Alias: unresolved user with identity marker
      graph.addNode('bh-user-s-1-5-21-1', makeNode('bh-user-s-1-5-21-1', {
        type: 'user',
        label: 'mystery-user',
        identity_status: 'unresolved',
        identity_markers: ['user:acct:test-local:jsmith'],
      }));
      // Target host that the alias has an edge to
      graph.addNode('host-10-10-10-2', makeNode('host-10-10-10-2', {
        type: 'host',
        label: '10.10.10.2',
        ip: '10.10.10.2',
      }));
      graph.addEdge('bh-user-s-1-5-21-1', 'host-10-10-10-2', edgeProps('HAS_SESSION'));

      // Canonical: resolved user with matching marker
      graph.addNode('user-test-local-jsmith', makeNode('user-test-local-jsmith', {
        type: 'user',
        label: 'JSMITH@TEST.LOCAL',
        username: 'jsmith',
        domain_name: 'test.local',
      }));

      const reconciler = new IdentityReconciler(graph, callbacks);
      const result = reconciler.reconcileCanonicalNode('user-test-local-jsmith');

      expect(result.removed_nodes).toContain('bh-user-s-1-5-21-1');
      expect(result.updated_canonical).toBe(true);
      expect(graph.hasNode('bh-user-s-1-5-21-1')).toBe(false);
      expect(graph.hasNode('user-test-local-jsmith')).toBe(true);
      // Edge should be retargeted
      const outEdges = graph.outEdges('user-test-local-jsmith');
      expect(outEdges.length).toBeGreaterThan(0);
      const retargeted = outEdges.some(e =>
        graph.target(e) === 'host-10-10-10-2' && graph.getEdgeAttributes(e).type === 'HAS_SESSION'
      );
      expect(retargeted).toBe(true);
      expect(pathInvalidated).toBe(true);
      expect(logEntries.length).toBeGreaterThan(0);
    });

    it('removes alias node from graph after merge', () => {
      graph.addNode('bh-user-old', makeNode('bh-user-old', {
        type: 'user',
        label: 'old-alias',
        identity_status: 'unresolved',
        identity_markers: ['user:acct:corp:admin'],
      }));
      graph.addNode('user-corp-admin', makeNode('user-corp-admin', {
        type: 'user',
        label: 'ADMIN@CORP',
        username: 'admin',
        domain_name: 'corp',
      }));

      const reconciler = new IdentityReconciler(graph, callbacks);
      const result = reconciler.reconcileCanonicalNode('user-corp-admin');

      expect(result.removed_nodes).toContain('bh-user-old');
      expect(graph.hasNode('bh-user-old')).toBe(false);
    });
  });

  // =============================================
  // Reverse merge: weaker → stronger existing
  // =============================================
  describe('reverse merge (hostname-only → IP-based host)', () => {
    it('merges a hostname-only host into an existing IP-based host', () => {
      // Stronger node (has IP)
      graph.addNode('host-10-10-10-5', makeNode('host-10-10-10-5', {
        type: 'host',
        label: 'dc01.test.local',
        hostname: 'dc01.test.local',
        ip: '10.10.10.5',
        alive: true,
      }));
      // Weaker node (hostname only, no IP) with an edge
      graph.addNode('host-dc01', makeNode('host-dc01', {
        type: 'host',
        label: 'DC01',
        hostname: 'DC01',
        smb_signing: false,
      }));
      graph.addNode('share-dc01-admin', makeNode('share-dc01-admin', {
        type: 'share',
        label: '\\\\DC01\\admin$',
        share_name: 'admin$',
      }));
      graph.addEdge('host-dc01', 'share-dc01-admin', edgeProps('RELATED'));

      const reconciler = new IdentityReconciler(graph, callbacks);
      // Reconcile the weaker node — it should reverse-merge into the stronger one
      const result = reconciler.reconcileCanonicalNode('host-dc01');

      expect(result.reverse_target).toBe('host-10-10-10-5');
      expect(result.removed_nodes).toContain('host-dc01');
      expect(graph.hasNode('host-dc01')).toBe(false);
      // Properties merged onto the IP-based host
      const ipHost = graph.getNodeAttributes('host-10-10-10-5') as NodeProperties;
      expect(ipHost.smb_signing).toBe(false);
      // Edge retargeted to IP-based host
      const edges = graph.outEdges('host-10-10-10-5');
      const shareEdge = edges.find(e =>
        graph.target(e) === 'share-dc01-admin' && graph.getEdgeAttributes(e).type === 'RELATED'
      );
      expect(shareEdge).toBeDefined();
    });
  });

  // =============================================
  // Self-loop prevention
  // =============================================
  describe('self-loop prevention', () => {
    it('does not create self-loop edges when retargeting', () => {
      // Two user nodes that share markers, with an edge between them
      graph.addNode('bh-user-alias', makeNode('bh-user-alias', {
        type: 'user',
        label: 'alias-user',
        identity_status: 'unresolved',
        identity_markers: ['user:acct:test:bob'],
      }));
      graph.addNode('user-test-bob', makeNode('user-test-bob', {
        type: 'user',
        label: 'BOB@TEST',
        username: 'bob',
        domain_name: 'test',
      }));
      // Edge from alias → canonical (would become self-loop after merge)
      graph.addEdge('bh-user-alias', 'user-test-bob', edgeProps('RELATED'));

      const reconciler = new IdentityReconciler(graph, callbacks);
      reconciler.reconcileCanonicalNode('user-test-bob');

      // Verify no self-loops exist
      for (const e of graph.edges()) {
        expect(graph.source(e)).not.toBe(graph.target(e));
      }
    });
  });

  // =============================================
  // Property merge precedence
  // =============================================
  describe('property merge precedence', () => {
    it('canonical node type and label win, alias fills missing properties', () => {
      graph.addNode('bh-user-alias', makeNode('bh-user-alias', {
        type: 'user',
        label: 'alias-label',
        identity_status: 'unresolved',
        identity_markers: ['user:acct:test:carol'],
        email: 'carol@test.local',
      }));
      graph.addNode('user-test-carol', makeNode('user-test-carol', {
        type: 'user',
        label: 'CAROL@TEST',
        username: 'carol',
        domain_name: 'test',
      }));

      const reconciler = new IdentityReconciler(graph, callbacks);
      reconciler.reconcileCanonicalNode('user-test-carol');

      const merged = graph.getNodeAttributes('user-test-carol') as NodeProperties;
      // Canonical label wins
      expect(merged.label).toBe('CAROL@TEST');
      expect(merged.type).toBe('user');
      // Alias property fills gap
      expect(merged.email).toBe('carol@test.local');
      expect(merged.identity_status).toBe('canonical');
    });

    it('takes higher confidence from either node', () => {
      graph.addNode('bh-user-x', makeNode('bh-user-x', {
        type: 'user',
        label: 'x',
        identity_status: 'unresolved',
        identity_markers: ['user:acct:dom:userx'],
        confidence: 0.9,
      }));
      graph.addNode('user-dom-userx', makeNode('user-dom-userx', {
        type: 'user',
        label: 'USERX@DOM',
        username: 'userx',
        domain_name: 'dom',
        confidence: 0.5,
      }));

      const reconciler = new IdentityReconciler(graph, callbacks);
      reconciler.reconcileCanonicalNode('user-dom-userx');

      const merged = graph.getNodeAttributes('user-dom-userx') as NodeProperties;
      expect(merged.confidence).toBe(0.9);
    });
  });

  // =============================================
  // Marker union
  // =============================================
  describe('marker union', () => {
    it('merged node carries markers from both alias and canonical', () => {
      graph.addNode('bh-user-sid', makeNode('bh-user-sid', {
        type: 'user',
        label: 'sid-user',
        identity_status: 'unresolved',
        identity_markers: ['user:sid:s-1-5-21-1234', 'user:acct:test:dave'],
      }));
      graph.addNode('user-test-dave', makeNode('user-test-dave', {
        type: 'user',
        label: 'DAVE@TEST',
        username: 'dave',
        domain_name: 'test',
      }));

      const reconciler = new IdentityReconciler(graph, callbacks);
      reconciler.reconcileCanonicalNode('user-test-dave');

      const merged = graph.getNodeAttributes('user-test-dave') as NodeProperties;
      const markers = merged.identity_markers as string[];
      expect(markers).toContain('user:sid:s-1-5-21-1234');
      expect(markers).toContain('user:acct:test:dave');
    });
  });

  // =============================================
  // No-op cases
  // =============================================
  describe('no-op cases', () => {
    it('returns empty result when canonical node has no identity markers', () => {
      graph.addNode('svc-1', makeNode('svc-1', {
        type: 'service',
        label: 'HTTP service',
      }));

      const reconciler = new IdentityReconciler(graph, callbacks);
      const result = reconciler.reconcileCanonicalNode('svc-1');

      expect(result.removed_nodes.length).toBe(0);
      expect(result.updated_canonical).toBe(false);
    });

    it('returns empty result when node does not exist', () => {
      const reconciler = new IdentityReconciler(graph, callbacks);
      const result = reconciler.reconcileCanonicalNode('nonexistent-node');

      expect(result.removed_nodes.length).toBe(0);
      expect(result.updated_canonical).toBe(false);
    });

    it('returns empty result when candidate is same type but has no shared markers', () => {
      graph.addNode('user-test-alice', makeNode('user-test-alice', {
        type: 'user',
        label: 'ALICE@TEST',
        username: 'alice',
        domain_name: 'test',
      }));
      graph.addNode('user-test-bob', makeNode('user-test-bob', {
        type: 'user',
        label: 'BOB@TEST',
        username: 'bob',
        domain_name: 'test',
      }));

      const reconciler = new IdentityReconciler(graph, callbacks);
      const result = reconciler.reconcileCanonicalNode('user-test-alice');

      expect(result.removed_nodes.length).toBe(0);
      expect(result.updated_canonical).toBe(false);
      // Both nodes still exist
      expect(graph.hasNode('user-test-alice')).toBe(true);
      expect(graph.hasNode('user-test-bob')).toBe(true);
    });

    it('does not merge nodes of different types even with overlapping markers', () => {
      // A user and group with overlapping name but different type
      graph.addNode('user-test-admins', makeNode('user-test-admins', {
        type: 'user',
        label: 'admins',
        username: 'admins',
        domain_name: 'test',
      }));
      graph.addNode('group-test-admins', makeNode('group-test-admins', {
        type: 'group',
        label: 'admins',
        group_name: 'admins',
        domain_name: 'test',
      }));

      const reconciler = new IdentityReconciler(graph, callbacks);
      const result = reconciler.reconcileCanonicalNode('user-test-admins');

      expect(result.removed_nodes.length).toBe(0);
      expect(result.updated_canonical).toBe(false);
    });
  });

  // =============================================
  // Edge retargeting
  // =============================================
  describe('edge retargeting', () => {
    it('retargets both inbound and outbound edges from alias to canonical', () => {
      graph.addNode('bh-user-alias', makeNode('bh-user-alias', {
        type: 'user',
        label: 'alias',
        identity_status: 'unresolved',
        identity_markers: ['user:acct:test:eve'],
      }));
      graph.addNode('user-test-eve', makeNode('user-test-eve', {
        type: 'user',
        label: 'EVE@TEST',
        username: 'eve',
        domain_name: 'test',
      }));
      graph.addNode('host-a', makeNode('host-a', { type: 'host' }));
      graph.addNode('cred-b', makeNode('cred-b', { type: 'credential' }));

      // Outbound edge from alias
      graph.addEdge('bh-user-alias', 'host-a', edgeProps('HAS_SESSION'));
      // Inbound edge to alias
      graph.addEdge('cred-b', 'bh-user-alias', edgeProps('OWNS_CRED'));

      const reconciler = new IdentityReconciler(graph, callbacks);
      reconciler.reconcileCanonicalNode('user-test-eve');

      // Outbound retargeted
      const outEdges = graph.outEdges('user-test-eve');
      expect(outEdges.some(e => graph.target(e) === 'host-a' && graph.getEdgeAttributes(e).type === 'HAS_SESSION')).toBe(true);
      // Inbound retargeted
      const inEdges = graph.inEdges('user-test-eve');
      expect(inEdges.some(e => graph.source(e) === 'cred-b' && graph.getEdgeAttributes(e).type === 'OWNS_CRED')).toBe(true);
    });

    it('does not duplicate edges that already exist on canonical', () => {
      graph.addNode('bh-user-alias', makeNode('bh-user-alias', {
        type: 'user',
        label: 'alias',
        identity_status: 'unresolved',
        identity_markers: ['user:acct:test:frank'],
      }));
      graph.addNode('user-test-frank', makeNode('user-test-frank', {
        type: 'user',
        label: 'FRANK@TEST',
        username: 'frank',
        domain_name: 'test',
      }));
      graph.addNode('host-a', makeNode('host-a', { type: 'host' }));

      // Both alias and canonical have HAS_SESSION to same host
      graph.addEdge('bh-user-alias', 'host-a', edgeProps('HAS_SESSION'));
      graph.addEdge('user-test-frank', 'host-a', edgeProps('HAS_SESSION'));

      const reconciler = new IdentityReconciler(graph, callbacks);
      reconciler.reconcileCanonicalNode('user-test-frank');

      // Should have exactly one HAS_SESSION edge, not two
      const outEdges = graph.outEdges('user-test-frank').filter(e =>
        graph.target(e) === 'host-a' && graph.getEdgeAttributes(e).type === 'HAS_SESSION'
      );
      expect(outEdges.length).toBe(1);
    });
  });
});
