import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties, EdgeProperties } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { FrontierComputer } from '../frontier.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

function makeConfig(overrides: Record<string, unknown> = {}) {
  return {
    id: 'test-eng', name: 'Test', created_at: '2026-03-20T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local'], exclusions: [] },
    objectives: [], opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
    ...overrides,
  } as any;
}

const now = new Date().toISOString();
function addNode(graph: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  graph.addNode(id, { id, label: id, discovered_at: now, confidence: 1.0, ...props } as NodeProperties);
}
function addEdge(graph: OverwatchGraph, src: string, tgt: string, type: string) {
  return graph.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: now } as EdgeProperties);
}
function build(graph: OverwatchGraph, config?: any) {
  const ctx = new EngineContext(graph, config || makeConfig(), './test-state.json');
  return new FrontierComputer(ctx, () => null);
}
const byType = <T extends { type: string }>(items: T[], t: string): T[] => items.filter(i => i.type === t);

describe('FrontierComputer — OSINT external recon (Phase 2D)', () => {
  it('emits domain_enumeration for an in-scope domain with no subdomains (0 noise)', () => {
    const g = makeGraph();
    addNode(g, 'domain-test.local', { type: 'domain', domain_name: 'test.local' });
    const items = build(g).compute();
    const de = byType(items, 'domain_enumeration');
    expect(de).toHaveLength(1);
    expect(de[0].node_id).toBe('domain-test.local');
    expect((de[0] as { opsec_noise: number }).opsec_noise).toBe(0.0);
  });

  it('does NOT emit domain_enumeration for an out-of-scope domain', () => {
    const g = makeGraph();
    addNode(g, 'domain-evil.com', { type: 'domain', domain_name: 'evil.com' });
    expect(byType(build(g).compute(), 'domain_enumeration')).toHaveLength(0);
  });

  it('retires domain_enumeration once subdomains_enumerated_at is set', () => {
    const g = makeGraph();
    addNode(g, 'domain-test.local', { type: 'domain', domain_name: 'test.local', subdomains_enumerated_at: now });
    expect(byType(build(g).compute(), 'domain_enumeration')).toHaveLength(0);
  });

  it('retires domain_enumeration once a SUBDOMAIN_OF edge exists', () => {
    const g = makeGraph();
    addNode(g, 'domain-test.local', { type: 'domain', domain_name: 'test.local' });
    addNode(g, 'subdomain-api.test.local', { type: 'subdomain', subdomain_name: 'api.test.local' });
    addEdge(g, 'subdomain-api.test.local', 'domain-test.local', 'SUBDOMAIN_OF');
    expect(byType(build(g).compute(), 'domain_enumeration')).toHaveLength(0);
  });

  it('does not crash compute() on a domain node missing both domain_name and label', () => {
    const g = makeGraph();
    // No label/domain_name — the scope gate must skip it, not throw and abort the
    // whole frontier. An unrelated in-scope domain still yields its item.
    g.addNode('domain-broken', { id: 'domain-broken', type: 'domain', discovered_at: now, confidence: 1.0 } as any);
    addNode(g, 'domain-test.local', { type: 'domain', domain_name: 'test.local' });
    const items = build(g).compute();
    expect(byType(items, 'domain_enumeration')).toHaveLength(1);
    expect(byType(items, 'domain_enumeration')[0].node_id).toBe('domain-test.local');
  });

  it('produces no domain_enumeration when the engagement has no scoped domains (CIDR-only)', () => {
    const g = makeGraph();
    addNode(g, 'domain-test.local', { type: 'domain', domain_name: 'test.local' });
    const cidrOnly = makeConfig({ scope: { cidrs: ['10.10.10.0/28'], domains: [], exclusions: [] } });
    expect(byType(build(g, cidrOnly).compute(), 'domain_enumeration')).toHaveLength(0);
  });
});
