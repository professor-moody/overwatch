import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties, EdgeProperties } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { CredentialCoverageTracker } from '../credential-coverage.js';
import { FrontierComputer } from '../frontier.js';

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

function buildTracker(graph: OverwatchGraph, config?: any) {
  const ctx = new EngineContext(graph, config || makeConfig(), './test-state.json');
  return { tracker: new CredentialCoverageTracker(ctx), ctx };
}

// =============================================
// CredentialCoverageTracker
// =============================================

describe('CredentialCoverageTracker', () => {
  describe('compute()', () => {
    it('returns empty coverage when graph has no credentials', () => {
      const graph = makeGraph();
      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.1' });

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      expect(result.total_credentials).toBe(0);
      expect(result.total_targets).toBe(0);
      expect(result.total_pairs).toBe(0);
      expect(result.coverage_pct).toBe(0);
      expect(result.top_untested).toEqual([]);
    });

    it('returns empty coverage when graph has no auth-accepting targets', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true });
      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.1' });
      // No services → not an auth target

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      expect(result.total_credentials).toBe(1);
      expect(result.total_targets).toBe(0);
      expect(result.total_pairs).toBe(0);
    });

    it('identifies untested credential/target pairs', () => {
      const graph = makeGraph();
      // Credential with owner
      addNode(graph, 'user-1', { type: 'user', username: 'jdoe', domain: 'test.local' });
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true, label: 'jdoe:pass' });
      addEdge(graph, 'user-1', 'cred-1', 'OWNS_CRED');

      // Host with auth-accepting service
      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.1', domain: 'test.local' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      expect(result.total_credentials).toBe(1);
      expect(result.total_targets).toBe(1);
      expect(result.total_pairs).toBe(1);
      expect(result.tested_pairs).toBe(0);
      expect(result.coverage_pct).toBe(0);
      expect(result.top_untested.length).toBe(1);
      expect(result.top_untested[0].target).toBe('host-1');
    });

    it('marks pairs as tested via TESTED_CRED edge', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', username: 'jdoe', domain: 'test.local' });
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true });
      addEdge(graph, 'user-1', 'cred-1', 'OWNS_CRED');

      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.1', domain: 'test.local' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      // Mark as tested via user → host TESTED_CRED
      addEdge(graph, 'user-1', 'host-1', 'TESTED_CRED', { confidence: 0.0 });

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      expect(result.tested_pairs).toBe(1);
      expect(result.coverage_pct).toBe(100);
      expect(result.top_untested.length).toBe(0);
    });

    it('marks pairs as tested via VALID_ON edge', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'ntlm', cred_usable_for_auth: true });

      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.1' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'rdp', port: 3389 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      // Credential directly valid on host
      addEdge(graph, 'cred-1', 'host-1', 'VALID_ON');

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      expect(result.tested_pairs).toBe(1);
      expect(result.coverage_pct).toBe(100);
    });

    it('computes coverage across multiple credentials and targets', () => {
      const graph = makeGraph();

      // 2 credentials
      addNode(graph, 'user-a', { type: 'user', username: 'admin', domain: 'test.local' });
      addNode(graph, 'cred-a', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true, label: 'admin:pass' });
      addEdge(graph, 'user-a', 'cred-a', 'OWNS_CRED');

      addNode(graph, 'user-b', { type: 'user', username: 'jdoe', domain: 'test.local' });
      addNode(graph, 'cred-b', { type: 'credential', cred_type: 'ntlm', cred_usable_for_auth: true, label: 'jdoe:ntlm' });
      addEdge(graph, 'user-b', 'cred-b', 'OWNS_CRED');

      // 2 targets
      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.1', domain: 'test.local' });
      addNode(graph, 'svc-smb', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-smb', 'RUNS');

      addNode(graph, 'host-2', { type: 'host', alive: true, ip: '10.10.10.2', domain: 'test.local' });
      addNode(graph, 'svc-rdp', { type: 'service', service_name: 'rdp', port: 3389 });
      addEdge(graph, 'host-2', 'svc-rdp', 'RUNS');

      // Test 1 of 4 pairs
      addEdge(graph, 'cred-a', 'host-1', 'TESTED_CRED', { confidence: 0.0 });

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      expect(result.total_credentials).toBe(2);
      expect(result.total_targets).toBe(2);
      expect(result.total_pairs).toBe(4);
      expect(result.tested_pairs).toBe(1);
      expect(result.coverage_pct).toBe(25);
      expect(result.untested_pairs.length).toBe(3);
    });

    it('excludes stale/expired credentials', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-expired', {
        type: 'credential',
        cred_type: 'plaintext',
        cred_usable_for_auth: true,
        credential_status: 'expired',
      });

      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.1' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      expect(result.total_credentials).toBe(0);
    });

    it('excludes superseded credentials', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-old', {
        type: 'credential',
        cred_type: 'plaintext',
        cred_usable_for_auth: true,
        identity_status: 'superseded',
      });

      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.1' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'ssh', port: 22 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      expect(result.total_credentials).toBe(0);
    });

    it('does not count hosts without auth services as targets', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true });

      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.1' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'dns', port: 53 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      expect(result.total_targets).toBe(0);
    });

    it('prioritizes plaintext credentials over NTLM hashes', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-plain', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true, label: 'plain' });
      addNode(graph, 'cred-ntlm', { type: 'credential', cred_type: 'ntlm', cred_usable_for_auth: true, label: 'ntlm' });

      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.1' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      // Plaintext pair should have higher priority
      const plainPair = result.untested_pairs.find(p => p.credential_id === 'cred-plain');
      const ntlmPair = result.untested_pairs.find(p => p.credential_id === 'cred-ntlm');
      expect(plainPair).toBeDefined();
      expect(ntlmPair).toBeDefined();
      expect(plainPair!.priority).toBeGreaterThan(ntlmPair!.priority);
    });
  });

  describe('computeFrontierItems()', () => {
    it('generates credential_test frontier items', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', username: 'jdoe', domain: 'test.local' });
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true, label: 'jdoe:pass' });
      addEdge(graph, 'user-1', 'cred-1', 'OWNS_CRED');

      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.1', domain: 'test.local' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      const { tracker } = buildTracker(graph);
      const items = tracker.computeFrontierItems();

      // F2: credential_test frontier items now point at the SERVICE node,
      // not the host. A host running SMB+SSH yields two coverage targets
      // and two frontier items, one per service.
      expect(items.length).toBe(1);
      expect(items[0].type).toBe('credential_test');
      expect(items[0].credential_id).toBe('cred-1');
      expect(items[0].node_id).toBe('svc-1');
      expect(items[0].description).toContain('jdoe');
      expect(items[0].description).toContain('smb');
    });

    it('respects maxItems limit', () => {
      const graph = makeGraph();

      // Create many creds and targets
      for (let i = 0; i < 5; i++) {
        addNode(graph, `cred-${i}`, { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true });
      }
      for (let i = 0; i < 5; i++) {
        addNode(graph, `host-${i}`, { type: 'host', alive: true, ip: `10.10.10.${i + 1}` });
        addNode(graph, `svc-${i}`, { type: 'service', service_name: 'smb', port: 445 });
        addEdge(graph, `host-${i}`, `svc-${i}`, 'RUNS');
      }

      const { tracker } = buildTracker(graph);
      const items = tracker.computeFrontierItems(3);

      expect(items.length).toBe(3);
    });
  });

  describe('frontier integration', () => {
    it('FrontierComputer includes credential_test items', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', username: 'jdoe', domain: 'test.local' });
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true, label: 'jdoe:pass' });
      addEdge(graph, 'user-1', 'cred-1', 'OWNS_CRED');

      addNode(graph, 'host-1', { type: 'host', alive: true, os: 'Windows', ip: '10.10.10.1', domain: 'test.local' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const frontier = new FrontierComputer(ctx, () => null);
      const items = frontier.compute();

      const credTests = items.filter(i => i.type === 'credential_test');
      expect(credTests.length).toBeGreaterThanOrEqual(1);
      expect(credTests[0].credential_id).toBe('cred-1');
      // F2: target is the service node, not the host.
      expect(credTests[0].node_id).toBe('svc-1');
    });

    // F2: testing one credential against SMB on a host that also runs
    // SSH must NOT mark the SSH pair tested. Each service is its own
    // coverage target.
    it('keeps SSH pair untested when only SMB was tested (F2 per-service granularity)', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true });
      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.5' });
      addNode(graph, 'svc-smb', { type: 'service', service_name: 'smb', port: 445 });
      addNode(graph, 'svc-ssh', { type: 'service', service_name: 'ssh', port: 22 });
      addEdge(graph, 'host-1', 'svc-smb', 'RUNS');
      addEdge(graph, 'host-1', 'svc-ssh', 'RUNS');
      // Test against SMB only.
      addEdge(graph, 'cred-1', 'svc-smb', 'TESTED_CRED');

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      expect(result.total_targets).toBe(2);
      expect(result.tested_pairs).toBe(1);
      const untestedTargets = result.top_untested.map(p => p.service);
      expect(untestedTargets).toContain('ssh');
      expect(untestedTargets).not.toContain('smb');
    });

    // F2: when a host-targeted edge carries `tested_service: 'smb'` (the
    // hint nxc now stamps), only the SMB pair is tested — SSH/RDP/etc.
    // remain in the untested list. Without the hint we fall back to
    // host-rollup for backwards compatibility.
    it('honors tested_service hint on host-level TESTED_CRED edges (F2)', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', username: 'jdoe' });
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true });
      addEdge(graph, 'user-1', 'cred-1', 'OWNS_CRED');
      addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.5' });
      addNode(graph, 'svc-smb', { type: 'service', service_name: 'smb', port: 445 });
      addNode(graph, 'svc-ssh', { type: 'service', service_name: 'ssh', port: 22 });
      addEdge(graph, 'host-1', 'svc-smb', 'RUNS');
      addEdge(graph, 'host-1', 'svc-ssh', 'RUNS');
      // Host-level TESTED_CRED with hint — should mark only SMB tested.
      addEdge(graph, 'user-1', 'host-1', 'TESTED_CRED', { tested_service: 'smb' });

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      expect(result.tested_pairs).toBe(1);
      const untestedServices = result.top_untested.map(p => p.service);
      expect(untestedServices).toEqual(['ssh']);
    });

    // F3: parsers populate `domain_name` (not `domain`). Coverage now
    // reads both, so the same-domain boost actually applies on real
    // ingests, and cross-domain pairs are correctly skipped.
    it('honors domain_name on hosts and cred_domain on credentials (F3)', () => {
      const graph = makeGraph();
      addNode(graph, 'user-a', { type: 'user', username: 'jdoe', domain_name: 'acme.local' });
      addNode(graph, 'cred-a', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true, cred_domain: 'acme.local' });
      addEdge(graph, 'user-a', 'cred-a', 'OWNS_CRED');
      addNode(graph, 'host-acme', { type: 'host', alive: true, ip: '10.10.10.5', domain_name: 'acme.local' });
      addNode(graph, 'svc-smb-a', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-acme', 'svc-smb-a', 'RUNS');
      // Different-domain host: cred should be filtered out (cross-domain noise).
      addNode(graph, 'host-other', { type: 'host', alive: true, ip: '10.20.20.5', domain_name: 'other.local' });
      addNode(graph, 'svc-smb-o', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-other', 'svc-smb-o', 'RUNS');

      const { tracker } = buildTracker(graph);
      const result = tracker.compute();

      // Only the same-domain pair should be in the untested list.
      expect(result.total_targets).toBe(2);
      const untestedTargetIds = result.untested_pairs.map(p => p.target_id);
      expect(untestedTargetIds).toContain('svc-smb-a');
      expect(untestedTargetIds).not.toContain('svc-smb-o');
    });

    it('does not duplicate credential_test when inferred_edge already exists for same pair', () => {
      const graph = makeGraph();
      addNode(graph, 'cred-1', { type: 'credential', cred_type: 'plaintext', cred_usable_for_auth: true, label: 'jdoe:pass' });

      addNode(graph, 'host-1', { type: 'host', alive: true, os: 'Windows', ip: '10.10.10.1' });
      addNode(graph, 'svc-1', { type: 'service', service_name: 'smb', port: 445 });
      addEdge(graph, 'host-1', 'svc-1', 'RUNS');

      // Add an inferred edge that the frontier will surface as inferred_edge
      addEdge(graph, 'cred-1', 'host-1', 'VALID_ON', { confidence: 0.5, inferred: true });

      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const frontier = new FrontierComputer(ctx, () => null);
      const items = frontier.compute();

      const credTests = items.filter(i => i.type === 'credential_test' && i.credential_id === 'cred-1' && i.node_id === 'host-1');
      const inferredEdges = items.filter(i => i.type === 'inferred_edge' && i.edge_source === 'cred-1' && i.edge_target === 'host-1');

      // Should have inferred_edge but not a duplicate credential_test
      expect(inferredEdges.length).toBe(1);
      expect(credTests.length).toBe(0);
    });
  });
});
