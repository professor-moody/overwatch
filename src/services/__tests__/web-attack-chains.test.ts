import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties, EdgeProperties } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { WebChainEnricher, WEB_CHAIN_TEMPLATES } from '../web-attack-chains.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

function makeConfig() {
  return {
    id: 'test-eng',
    name: 'Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
  } as any;
}

const now = new Date().toISOString();

function addNode(g: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  g.addNode(id, { id, label: id, discovered_at: now, confidence: 1.0, ...props } as NodeProperties);
}

function addEdge(g: OverwatchGraph, src: string, tgt: string, type: string) {
  return g.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: now } as EdgeProperties);
}

function makeCtx(graph: OverwatchGraph) {
  return new EngineContext(graph, makeConfig(), './test-state.json');
}

describe('WebChainEnricher', () => {
  it('exports 5 chain templates', () => {
    expect(WEB_CHAIN_TEMPLATES.length).toBe(5);
    const ids = WEB_CHAIN_TEMPLATES.map(t => t.id);
    expect(ids).toContain('sqli-to-lateral');
    expect(ids).toContain('lfi-to-creds');
    expect(ids).toContain('auth-bypass-to-admin');
    expect(ids).toContain('ssrf-to-cloud');
    expect(ids).toContain('rce-to-pivot');
  });

  describe('sqli-to-lateral', () => {
    it('matches full chain: vuln → credential → service → host', () => {
      const g = makeGraph();
      addNode(g, 'sqli-1', { type: 'vulnerability', vuln_type: 'sqli', exploitable: true } as any);
      addNode(g, 'cred-1', { type: 'credential' });
      addNode(g, 'svc-1', { type: 'service' });
      addNode(g, 'host-1', { type: 'host' });

      addEdge(g, 'sqli-1', 'cred-1', 'EXPLOITS');
      addEdge(g, 'cred-1', 'svc-1', 'VALID_ON');
      addEdge(g, 'host-1', 'svc-1', 'RUNS');

      const enricher = new WebChainEnricher(makeCtx(g));
      const chains = enricher.matchChainTemplates();

      const match = chains.find(c => c.template_id === 'sqli-to-lateral');
      expect(match).toBeDefined();
      expect(match!.confirmed_hops).toBe(3);
      expect(match!.completion).toBe(1.0);
      expect(match!.gap_index).toBe(-1);
      expect(match!.node_path).toEqual(['sqli-1', 'cred-1', 'svc-1', 'host-1']);
    });

    it('matches partial chain: vuln → credential (missing service)', () => {
      const g = makeGraph();
      addNode(g, 'sqli-1', { type: 'vulnerability', vuln_type: 'sqli', exploitable: true } as any);
      addNode(g, 'cred-1', { type: 'credential' });

      addEdge(g, 'sqli-1', 'cred-1', 'EXPLOITS');

      const enricher = new WebChainEnricher(makeCtx(g));
      const chains = enricher.matchChainTemplates();

      const match = chains.find(c => c.template_id === 'sqli-to-lateral');
      expect(match).toBeDefined();
      expect(match!.confirmed_hops).toBe(1);
      expect(match!.total_hops).toBe(3);
      expect(match!.completion).toBeCloseTo(1 / 3);
      expect(match!.gap_index).toBe(1);
    });

    it('does not match when entry node is not exploitable sqli', () => {
      const g = makeGraph();
      addNode(g, 'xss-1', { type: 'vulnerability', vuln_type: 'xss' } as any);
      addNode(g, 'cred-1', { type: 'credential' });
      addEdge(g, 'xss-1', 'cred-1', 'EXPLOITS');

      const enricher = new WebChainEnricher(makeCtx(g));
      const chains = enricher.matchChainTemplates();

      const match = chains.find(c => c.template_id === 'sqli-to-lateral');
      expect(match).toBeUndefined();
    });
  });

  describe('lfi-to-creds', () => {
    it('matches full chain: lfi → host → credential', () => {
      const g = makeGraph();
      addNode(g, 'lfi-1', { type: 'vulnerability', vuln_type: 'lfi' } as any);
      addNode(g, 'host-1', { type: 'host' });
      addNode(g, 'cred-1', { type: 'credential' });

      addEdge(g, 'lfi-1', 'host-1', 'EXPLOITS');
      addEdge(g, 'cred-1', 'host-1', 'DUMPED_FROM');

      const enricher = new WebChainEnricher(makeCtx(g));
      const chains = enricher.matchChainTemplates();

      const match = chains.find(c => c.template_id === 'lfi-to-creds');
      expect(match).toBeDefined();
      expect(match!.completion).toBe(1.0);
      expect(match!.node_path).toEqual(['lfi-1', 'host-1', 'cred-1']);
    });
  });

  describe('auth-bypass-to-admin', () => {
    it('matches full chain: auth_bypass → webapp → service → host', () => {
      const g = makeGraph();
      addNode(g, 'bypass-1', { type: 'vulnerability', vuln_type: 'auth_bypass' } as any);
      addNode(g, 'webapp-1', { type: 'webapp' });
      addNode(g, 'svc-1', { type: 'service' });
      addNode(g, 'host-1', { type: 'host' });

      addEdge(g, 'bypass-1', 'webapp-1', 'AUTH_BYPASS');
      addEdge(g, 'svc-1', 'webapp-1', 'HOSTS');
      addEdge(g, 'host-1', 'svc-1', 'RUNS');

      const enricher = new WebChainEnricher(makeCtx(g));
      const chains = enricher.matchChainTemplates();

      const match = chains.find(c => c.template_id === 'auth-bypass-to-admin');
      expect(match).toBeDefined();
      expect(match!.completion).toBe(1.0);
    });
  });

  describe('ssrf-to-cloud', () => {
    it('matches partial chain: ssrf → host (missing cloud identity)', () => {
      const g = makeGraph();
      addNode(g, 'ssrf-1', { type: 'vulnerability', vuln_type: 'ssrf' } as any);
      addNode(g, 'host-1', { type: 'host' });

      addEdge(g, 'ssrf-1', 'host-1', 'EXPLOITS');

      const enricher = new WebChainEnricher(makeCtx(g));
      const chains = enricher.matchChainTemplates();

      const match = chains.find(c => c.template_id === 'ssrf-to-cloud');
      expect(match).toBeDefined();
      expect(match!.confirmed_hops).toBe(1);
      expect(match!.total_hops).toBe(2);
      expect(match!.gap_index).toBe(1);
    });
  });

  describe('rce-to-pivot', () => {
    it('matches full chain: rce → host → user → host2', () => {
      const g = makeGraph();
      addNode(g, 'rce-1', { type: 'vulnerability', vuln_type: 'rce' } as any);
      addNode(g, 'host-1', { type: 'host' });
      addNode(g, 'user-1', { type: 'user' });
      addNode(g, 'host-2', { type: 'host' });

      addEdge(g, 'rce-1', 'host-1', 'EXPLOITS');
      addEdge(g, 'user-1', 'host-1', 'HAS_SESSION');
      addEdge(g, 'user-1', 'host-2', 'ADMIN_TO');

      const enricher = new WebChainEnricher(makeCtx(g));
      const chains = enricher.matchChainTemplates();

      const match = chains.find(c => c.template_id === 'rce-to-pivot');
      expect(match).toBeDefined();
      expect(match!.completion).toBe(1.0);
      expect(match!.node_path).toEqual(['rce-1', 'host-1', 'user-1', 'host-2']);
    });
  });

  it('returns empty when graph has no web vulnerability nodes', () => {
    const g = makeGraph();
    addNode(g, 'host-1', { type: 'host' });
    addNode(g, 'svc-1', { type: 'service' });
    addEdge(g, 'host-1', 'svc-1', 'RUNS');

    const enricher = new WebChainEnricher(makeCtx(g));
    const chains = enricher.matchChainTemplates();
    expect(chains.length).toBe(0);
  });

  it('getMatchedChains returns cached results', () => {
    const g = makeGraph();
    addNode(g, 'sqli-1', { type: 'vulnerability', vuln_type: 'sqli', exploitable: true } as any);
    addNode(g, 'cred-1', { type: 'credential' });
    addEdge(g, 'sqli-1', 'cred-1', 'EXPLOITS');

    const enricher = new WebChainEnricher(makeCtx(g));
    expect(enricher.getMatchedChains()).toEqual([]);
    enricher.matchChainTemplates();
    expect(enricher.getMatchedChains().length).toBeGreaterThan(0);
  });

  it('handles multiple entry nodes for same template', () => {
    const g = makeGraph();
    addNode(g, 'sqli-1', { type: 'vulnerability', vuln_type: 'sqli', exploitable: true } as any);
    addNode(g, 'sqli-2', { type: 'vulnerability', vuln_type: 'sqli', exploitable: true } as any);
    addNode(g, 'cred-1', { type: 'credential' });
    addNode(g, 'cred-2', { type: 'credential' });
    addEdge(g, 'sqli-1', 'cred-1', 'EXPLOITS');
    addEdge(g, 'sqli-2', 'cred-2', 'EXPLOITS');

    const enricher = new WebChainEnricher(makeCtx(g));
    const chains = enricher.matchChainTemplates();
    const sqliChains = chains.filter(c => c.template_id === 'sqli-to-lateral');
    expect(sqliChains.length).toBe(2);
  });
});
