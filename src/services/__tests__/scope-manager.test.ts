import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import type { ScopeManagerHost } from '../scope-manager.js';
import { updateScope, collectScopeSuggestions, previewScopeChange } from '../scope-manager.js';

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

function addHost(graph: OverwatchGraph, id: string, ip: string, extra: Partial<NodeProperties> = {}) {
  graph.addNode(id, {
    id,
    type: 'host',
    label: ip,
    ip,
    discovered_at: now,
    confidence: 1.0,
    ...extra,
  } as NodeProperties);
}

function makeHost(graph: OverwatchGraph, ctx: EngineContext): ScopeManagerHost {
  let persistCalled = false;
  let frontierInvalidated = false;
  let healthInvalidated = false;
  return {
    ctx,
    addNode(props: NodeProperties) {
      graph.addNode(props.id, props);
      return props.id;
    },
    logActionEvent() { /* no-op for tests */ },
    persist() { persistCalled = true; },
    invalidateFrontierCache() { frontierInvalidated = true; },
    invalidateHealthReport() { healthInvalidated = true; },
    get _persistCalled() { return persistCalled; },
    get _frontierInvalidated() { return frontierInvalidated; },
    get _healthInvalidated() { return healthInvalidated; },
  } as ScopeManagerHost & { _persistCalled: boolean; _frontierInvalidated: boolean; _healthInvalidated: boolean };
}

describe('scope-manager', () => {
  // =============================================
  // updateScope
  // =============================================
  describe('updateScope', () => {
    it('adds a CIDR to scope', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const result = updateScope(host, { add_cidrs: ['192.168.1.0/24'], reason: 'Pivot' });

      expect(result.applied).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.after.cidrs).toContain('192.168.1.0/24');
      expect(result.before.cidrs).not.toContain('192.168.1.0/24');
    });

    it('does not duplicate an already-present CIDR', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      updateScope(host, { add_cidrs: ['10.10.10.0/28'], reason: 'Duplicate test' });

      expect(ctx.config.scope.cidrs.filter(c => c === '10.10.10.0/28')).toHaveLength(1);
    });

    it('removes a CIDR from scope', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      expect(ctx.config.scope.cidrs).toContain('10.10.10.0/28');

      const result = updateScope(host, { remove_cidrs: ['10.10.10.0/28'], reason: 'Reducing scope' });

      expect(result.applied).toBe(true);
      expect(result.after.cidrs).not.toContain('10.10.10.0/28');
    });

    it('adds a domain to scope', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const result = updateScope(host, { add_domains: ['corp.local'], reason: 'New domain' });

      expect(result.applied).toBe(true);
      expect(result.after.domains).toContain('corp.local');
      expect(result.before.domains).not.toContain('corp.local');
    });

    it('does not duplicate an already-present domain', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      updateScope(host, { add_domains: ['test.local'], reason: 'Dup domain' });

      expect(ctx.config.scope.domains.filter(d => d === 'test.local')).toHaveLength(1);
    });

    it('removes a domain from scope', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const result = updateScope(host, { remove_domains: ['test.local'], reason: 'Drop domain' });

      expect(result.applied).toBe(true);
      expect(result.after.domains).not.toContain('test.local');
    });

    it('rejects invalid CIDR in add_cidrs', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const result = updateScope(host, { add_cidrs: ['not-a-cidr'], reason: 'Bad input' });

      expect(result.applied).toBe(false);
      expect(result.errors[0]).toContain('Invalid CIDR');
      expect(result.before).toEqual(result.after);
    });

    it('rejects invalid CIDR in remove_cidrs', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const result = updateScope(host, { remove_cidrs: ['bogus'], reason: 'Bad remove' });

      expect(result.applied).toBe(false);
      expect(result.errors[0]).toContain('Invalid CIDR');
    });

    it('rejects invalid exclusion CIDR', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const result = updateScope(host, { add_exclusions: ['xyz'], reason: 'Bad exclusion' });

      expect(result.applied).toBe(false);
      expect(result.errors[0]).toContain('Invalid exclusion');
    });

    it('counts affected host nodes that enter scope', () => {
      const graph = makeGraph();
      addHost(graph, 'host-172-16-1-5', '172.16.1.5');
      addHost(graph, 'host-172-16-1-6', '172.16.1.6');
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const result = updateScope(host, { add_cidrs: ['172.16.1.0/24'], reason: 'Expand' });

      expect(result.applied).toBe(true);
      expect(result.affected_node_count).toBe(2);
    });

    it('does not count already-in-scope hosts as affected', () => {
      const graph = makeGraph();
      addHost(graph, 'host-10-10-10-1', '10.10.10.1');
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const result = updateScope(host, { add_cidrs: ['192.168.1.0/24'], reason: 'Unrelated expand' });

      expect(result.affected_node_count).toBe(0);
    });

    it('promotes cold store records when they enter scope', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      ctx.coldStore.add({
        id: 'cold-host-1',
        type: 'host',
        label: '172.16.2.10',
        ip: '172.16.2.10',
        discovered_at: now,
        last_seen_at: now,
        alive: true,
      });
      const host = makeHost(graph, ctx);

      const result = updateScope(host, { add_cidrs: ['172.16.2.0/24'], reason: 'Cold promotion' });

      expect(result.applied).toBe(true);
      expect(result.affected_node_count).toBe(1);
      expect(graph.hasNode('cold-host-1')).toBe(true);
      expect(ctx.coldStore.has('cold-host-1')).toBe(false);
    });

    it('does not promote cold records that remain out of scope', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      ctx.coldStore.add({
        id: 'cold-oos',
        type: 'host',
        label: '192.168.99.1',
        ip: '192.168.99.1',
        discovered_at: now,
        last_seen_at: now,
      });
      const host = makeHost(graph, ctx);

      updateScope(host, { add_cidrs: ['172.16.3.0/24'], reason: 'Different subnet' });

      expect(graph.hasNode('cold-oos')).toBe(false);
      expect(ctx.coldStore.has('cold-oos')).toBe(true);
    });

    it('calls persist, invalidateFrontierCache, and invalidateHealthReport on success', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx) as ScopeManagerHost & {
        _persistCalled: boolean;
        _frontierInvalidated: boolean;
        _healthInvalidated: boolean;
      };

      updateScope(host, { add_cidrs: ['192.168.5.0/24'], reason: 'Side effects' });

      expect(host._persistCalled).toBe(true);
      expect(host._frontierInvalidated).toBe(true);
      expect(host._healthInvalidated).toBe(true);
    });

    it('handles exclusion add and remove', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const r1 = updateScope(host, { add_exclusions: ['10.10.10.5/32'], reason: 'Exclude host' });
      expect(r1.applied).toBe(true);
      expect(r1.after.exclusions).toContain('10.10.10.5/32');

      const r2 = updateScope(host, { remove_exclusions: ['10.10.10.5/32'], reason: 'Remove exclude' });
      expect(r2.applied).toBe(true);
      expect(r2.after.exclusions).not.toContain('10.10.10.5/32');
    });
  });

  // =============================================
  // collectScopeSuggestions
  // =============================================
  describe('collectScopeSuggestions', () => {
    it('groups out-of-scope hosts into /24 suggestions', () => {
      const graph = makeGraph();
      addHost(graph, 'host-172-16-1-5', '172.16.1.5', { discovered_by: 'nmap' });
      addHost(graph, 'host-172-16-1-10', '172.16.1.10', { discovered_by: 'nmap' });
      addHost(graph, 'host-192-168-5-1', '192.168.5.1', { discovered_by: 'arp' });
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const suggestions = collectScopeSuggestions(host);

      expect(suggestions).toHaveLength(2);

      const s1 = suggestions.find(s => s.suggested_cidr === '172.16.1.0/24');
      expect(s1).toBeDefined();
      expect(s1!.out_of_scope_ips).toEqual(['172.16.1.10', '172.16.1.5']);
      expect(s1!.source_descriptions).toContain('nmap');

      const s2 = suggestions.find(s => s.suggested_cidr === '192.168.5.0/24');
      expect(s2).toBeDefined();
      expect(s2!.out_of_scope_ips).toEqual(['192.168.5.1']);
    });

    it('returns empty when all hosts are in scope', () => {
      const graph = makeGraph();
      addHost(graph, 'host-10-10-10-1', '10.10.10.1');
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const suggestions = collectScopeSuggestions(host);

      expect(suggestions).toHaveLength(0);
    });

    it('skips non-host nodes', () => {
      const graph = makeGraph();
      graph.addNode('domain-1', {
        id: 'domain-1',
        type: 'domain',
        label: 'evil.com',
        ip: '172.16.99.1',
        discovered_at: now,
        confidence: 1.0,
      } as NodeProperties);
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const suggestions = collectScopeSuggestions(host);

      expect(suggestions).toHaveLength(0);
    });

    it('skips hosts without an IP', () => {
      const graph = makeGraph();
      graph.addNode('host-noip', {
        id: 'host-noip',
        type: 'host',
        label: 'mystery-box',
        discovered_at: now,
        confidence: 1.0,
      } as NodeProperties);
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const suggestions = collectScopeSuggestions(host);

      expect(suggestions).toHaveLength(0);
    });

    it('skips IPv6 addresses (not 4-octet)', () => {
      const graph = makeGraph();
      addHost(graph, 'host-v6', 'fe80::1');
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const suggestions = collectScopeSuggestions(host);

      expect(suggestions).toHaveLength(0);
    });

    it('tracks first_seen_at as the earliest discovered_at in the group', () => {
      const graph = makeGraph();
      const early = '2026-01-01T00:00:00Z';
      const late = '2026-03-15T00:00:00Z';
      addHost(graph, 'host-a', '172.16.1.5', { discovered_at: late });
      addHost(graph, 'host-b', '172.16.1.6', { discovered_at: early });
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const suggestions = collectScopeSuggestions(host);

      expect(suggestions).toHaveLength(1);
      expect(suggestions[0].first_seen_at).toBe(early);
    });
  });

  // =============================================
  // previewScopeChange
  // =============================================
  describe('previewScopeChange', () => {
    it('counts nodes entering scope without mutating config', () => {
      const graph = makeGraph();
      addHost(graph, 'host-172-16-1-5', '172.16.1.5');
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const cidrsBefore = [...ctx.config.scope.cidrs];

      const preview = previewScopeChange(host, { add_cidrs: ['172.16.1.0/24'] });

      expect(preview.nodes_entering_scope).toBe(1);
      expect(preview.nodes_leaving_scope).toBe(0);
      expect(ctx.config.scope.cidrs).toEqual(cidrsBefore);
    });

    it('counts nodes leaving scope when removing a CIDR', () => {
      const graph = makeGraph();
      addHost(graph, 'host-10-10-10-1', '10.10.10.1');
      const cfg = makeConfig({
        scope: { cidrs: ['10.10.10.0/28', '192.168.1.0/24'], domains: ['test.local'], exclusions: [] },
      });
      const ctx = new EngineContext(graph, cfg, './test-state.json');
      const host = makeHost(graph, ctx);

      const preview = previewScopeChange(host, { remove_cidrs: ['10.10.10.0/28'] });

      expect(preview.nodes_leaving_scope).toBe(1);
      expect(preview.nodes_entering_scope).toBe(0);
    });

    it('returns before and after scope snapshots', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const preview = previewScopeChange(host, {
        add_cidrs: ['192.168.1.0/24'],
        add_domains: ['newdomain.local'],
      });

      expect(preview.before.cidrs).not.toContain('192.168.1.0/24');
      expect(preview.after.cidrs).toContain('192.168.1.0/24');
      expect(preview.before.domains).not.toContain('newdomain.local');
      expect(preview.after.domains).toContain('newdomain.local');
    });

    it('resolves pending scope suggestions when the preview covers them', () => {
      const graph = makeGraph();
      addHost(graph, 'host-172-16-1-5', '172.16.1.5');
      addHost(graph, 'host-172-16-1-6', '172.16.1.6');
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const preview = previewScopeChange(host, { add_cidrs: ['172.16.1.0/24'] });

      expect(preview.pending_suggestions_resolved).toContain('172.16.1.0/24');
    });

    it('does not resolve suggestions for unrelated CIDRs', () => {
      const graph = makeGraph();
      addHost(graph, 'host-172-16-1-5', '172.16.1.5');
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const preview = previewScopeChange(host, { add_cidrs: ['192.168.99.0/24'] });

      expect(preview.pending_suggestions_resolved).not.toContain('172.16.1.0/24');
    });

    it('handles exclusion changes in preview', () => {
      const graph = makeGraph();
      addHost(graph, 'host-10-10-10-1', '10.10.10.1');
      const cfg = makeConfig({ scope: { cidrs: ['10.10.10.0/28'], domains: [], exclusions: [] } });
      const ctx = new EngineContext(graph, cfg, './test-state.json');
      const host = makeHost(graph, ctx);

      const preview = previewScopeChange(host, { add_exclusions: ['10.10.10.0/29'] });

      expect(preview.nodes_leaving_scope).toBe(1);
      expect(preview.after.exclusions).toContain('10.10.10.0/29');
    });

    it('does not mutate the graph or config', () => {
      const graph = makeGraph();
      addHost(graph, 'host-10-10-10-1', '10.10.10.1');
      const ctx = new EngineContext(graph, makeConfig(), './test-state.json');
      const host = makeHost(graph, ctx);

      const nodeCountBefore = graph.order;
      const cidrsBefore = [...ctx.config.scope.cidrs];
      const domainsBefore = [...ctx.config.scope.domains];

      previewScopeChange(host, {
        add_cidrs: ['172.16.1.0/24'],
        remove_domains: ['test.local'],
      });

      expect(graph.order).toBe(nodeCountBefore);
      expect(ctx.config.scope.cidrs).toEqual(cidrsBefore);
      expect(ctx.config.scope.domains).toEqual(domainsBefore);
    });
  });
});
