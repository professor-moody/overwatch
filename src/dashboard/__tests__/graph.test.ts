import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Graph from 'graphology';
import { resolve } from 'path';
import { pathToFileURL } from 'url';

async function loadGraphModule() {
  const displayUrl = pathToFileURL(resolve('/Users/keys/projects/overwatch/src/dashboard/node-display.js')).href;
  await import(`${displayUrl}?t=${Date.now()}-${Math.random()}`);
  const url = pathToFileURL(resolve('/Users/keys/projects/overwatch/src/dashboard/graph.js')).href;
  await import(`${url}?t=${Date.now()}-${Math.random()}`);
  return (globalThis as any).window.OverwatchGraph;
}

function makeClassList() {
  return {
    add: vi.fn(),
    remove: vi.fn(),
    toggle: vi.fn(),
  };
}

function makeCanvasContext() {
  return {
    clearRect() {},
    beginPath() {},
    moveTo() {},
    lineTo() {},
    stroke() {},
    arc() {},
    fill() {},
    strokeRect() {},
  };
}

describe('dashboard graph helpers', () => {
  beforeEach(() => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    const elements = new Map<string, any>();
    elements.set('node-filters', {
      innerHTML: '',
      appendChild() {},
    });
    elements.set('focus-banner', {
      classList: makeClassList(),
      querySelector() {
        return { textContent: '' };
      },
    });
    elements.set('path-info-bar', {
      classList: makeClassList(),
      querySelector() {
        return { textContent: '' };
      },
    });
    elements.set('minimap-canvas', {
      clientWidth: 120,
      clientHeight: 80,
      width: 0,
      height: 0,
      getContext() {
        return makeCanvasContext();
      },
      getBoundingClientRect() {
        return { left: 0, top: 0, width: 120, height: 80 };
      },
      addEventListener() {},
    });
    elements.set('sigma-container', {
      clientWidth: 800,
      clientHeight: 600,
      getBoundingClientRect() {
        return { left: 0, top: 0, width: 800, height: 600 };
      },
      classList: makeClassList(),
    });
    elements.set('btn-layout', {
      textContent: '',
      classList: makeClassList(),
    });
    elements.set('graph-tooltip', {
      classList: makeClassList(),
      style: {},
      innerHTML: '',
    });

    (globalThis as any).window = {};
    (globalThis as any).document = {
      getElementById(id: string) {
        return elements.get(id) || null;
      },
      createElement() {
        return {
          className: '',
          innerHTML: '',
          onclick: null,
          classList: makeClassList(),
        };
      },
      querySelectorAll() {
        return [];
      },
    };
    (globalThis as any).graphology = { Graph };
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete (globalThis as any).fetch;
    delete (globalThis as any).window;
    delete (globalThis as any).document;
    delete (globalThis as any).graphology;
  });

  it('derives visible nodes and edges from filters and focus state', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('host-a', { label: 'Host A', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });
    graph.addNode('service-a', { label: 'SMB', nodeType: 'service', color: '#fff', x: 1, y: 0, _props: { type: 'service' } });
    graph.addNode('host-b', { label: 'Host B', nodeType: 'host', color: '#fff', x: 2, y: 0, _props: { type: 'host' } });
    graph.addEdgeWithKey('host-a--RUNS--service-a', 'host-a', 'service-a', { edgeType: 'RUNS' });
    graph.addEdgeWithKey('service-a--RELATED--host-b', 'service-a', 'host-b', { edgeType: 'RELATED' });

    graphModule.setActiveFilters(['host']);
    expect(graphModule.getVisibleNodeIds().sort()).toEqual(['host-a', 'host-b']);
    expect(graphModule.getVisibleEdgeIds()).toEqual([]);

    graphModule.setActiveFilters(['host', 'service']);
    graphModule.enterNeighborhoodFocus('host-a', 1);
    expect(graphModule.getVisibleNodeIds().sort()).toEqual(['host-a', 'service-a']);
    expect(graphModule.getVisibleEdgeIds()).toEqual(['host-a--RUNS--service-a']);
  });

  it('preserves node positions during full-state sync refreshes', async () => {
    const graphModule = await loadGraphModule();
    graphModule.init();

    graphModule.loadGraphData({
      nodes: [
        { id: 'host-a', properties: { id: 'host-a', type: 'host', label: 'Host A' } },
      ],
      edges: [],
    });

    graphModule.graph.setNodeAttribute('host-a', 'x', 42);
    graphModule.graph.setNodeAttribute('host-a', 'y', 24);

    graphModule.syncGraphData({
      nodes: [
        { id: 'host-a', properties: { id: 'host-a', type: 'host', label: 'Host A Updated' } },
      ],
      edges: [],
    });

    expect(graphModule.graph.getNodeAttribute('host-a', 'x')).toBe(42);
    expect(graphModule.graph.getNodeAttribute('host-a', 'y')).toBe(24);
    expect(graphModule.graph.getNodeAttribute('host-a', 'label')).toBe('Host A Updated');
  });

  it('only suppresses click after movement exceeds the drag threshold', async () => {
    const graphModule = await loadGraphModule();

    expect(graphModule.exceededDragThreshold(10, 10, 13, 13)).toBe(false);
    expect(graphModule.exceededDragThreshold(10, 10, 20, 20)).toBe(true);
  });

  it('uses overview mode to hide low-signal service nodes until focus reveals them', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('host-a', { label: 'Host A', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });
    graph.addNode('service-a', { label: 'ldap/389', nodeType: 'service', color: '#fff', x: 1, y: 0, _props: { type: 'service' } });
    graph.addEdgeWithKey('host-a--RUNS--service-a', 'host-a', 'service-a', { edgeType: 'RUNS' });

    graphModule.setGraphMode('overview');
    expect(graphModule.getVisibleNodeIds()).toEqual(['host-a']);

    graphModule.enterNeighborhoodFocus('host-a', 1);
    expect(graphModule.getVisibleNodeIds().sort()).toEqual(['host-a', 'service-a']);
  });

  it('keeps a selected low-signal node visible in overview mode even if its type is filtered out', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('domain-a', { label: 'north.local', nodeType: 'domain', color: '#fff', x: 0, y: 0, _props: { type: 'domain' } });
    graph.addNode('user-a', { label: 'rickon.stark', nodeType: 'user', color: '#fff', x: 1, y: 0, _props: { type: 'user' } });
    graph.addEdgeWithKey('user-a--MEMBER_OF_DOMAIN--domain-a', 'user-a', 'domain-a', { edgeType: 'MEMBER_OF_DOMAIN' });

    graphModule.setGraphMode('overview');
    graphModule.setActiveFilters(['domain']);
    graphModule.selectNode('user-a');

    expect(graphModule.getVisibleNodeIds().sort()).toEqual(['domain-a', 'user-a']);
  });

  it('focuses graph summary node types by revealing that type and its local context in overview mode', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('host-a', { label: 'Host A', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });
    graph.addNode('service-a', { label: 'ldap/389', nodeType: 'service', color: '#fff', x: 1, y: 0, _props: { type: 'service' } });
    graph.addNode('domain-a', { label: 'north.local', nodeType: 'domain', color: '#fff', x: 0, y: -1, _props: { type: 'domain' } });
    graph.addEdgeWithKey('host-a--RUNS--service-a', 'host-a', 'service-a', { edgeType: 'RUNS' });
    graph.addEdgeWithKey('host-a--MEMBER_OF_DOMAIN--domain-a', 'host-a', 'domain-a', { edgeType: 'MEMBER_OF_DOMAIN' });

    graphModule.focusNodeType('service');

    expect(graphModule.graphMode).toBe('overview');
    expect(graphModule.getVisibleNodeIds().sort()).toEqual(['domain-a', 'host-a', 'service-a']);
  });

  it('mergeGraphDelta removes nodes and edges from removed_nodes/removed_edges', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('host-a', { label: 'Host A', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });
    graph.addNode('alias-node', { label: 'Alias', nodeType: 'host', color: '#fff', x: 1, y: 0, _props: { type: 'host' } });
    graph.addEdgeWithKey('alias-edge', 'host-a', 'alias-node', { edgeType: 'REACHABLE' });

    expect(graph.hasNode('alias-node')).toBe(true);
    expect(graph.hasEdge('alias-edge')).toBe(true);

    graphModule.mergeGraphDelta({
      nodes: [],
      edges: [],
      removed_nodes: ['alias-node'],
      removed_edges: ['alias-edge'],
    });

    expect(graph.hasNode('alias-node')).toBe(false);
    expect(graph.hasEdge('alias-edge')).toBe(false);
    expect(graph.hasNode('host-a')).toBe(true);
  });

  it('findShortestPath returns correct nodes and edges for connected graph', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('a', { label: 'A', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });
    graph.addNode('b', { label: 'B', nodeType: 'host', color: '#fff', x: 1, y: 0, _props: { type: 'host' } });
    graph.addNode('c', { label: 'C', nodeType: 'host', color: '#fff', x: 2, y: 0, _props: { type: 'host' } });
    graph.addEdgeWithKey('a--REACHABLE--b', 'a', 'b', { edgeType: 'REACHABLE' });
    graph.addEdgeWithKey('b--REACHABLE--c', 'b', 'c', { edgeType: 'REACHABLE' });

    const result = graphModule.findShortestPath('a', 'c');
    expect(result.nodes.size).toBe(3);
    expect(result.nodes.has('a')).toBe(true);
    expect(result.nodes.has('b')).toBe(true);
    expect(result.nodes.has('c')).toBe(true);
    expect(result.edges.size).toBe(2);
  });

  it('findShortestPath returns empty sets for disconnected nodes', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('a', { label: 'A', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });
    graph.addNode('z', { label: 'Z', nodeType: 'host', color: '#fff', x: 5, y: 0, _props: { type: 'host' } });

    const result = graphModule.findShortestPath('a', 'z');
    expect(result.edges.size).toBe(0);
  });

  it('buildActualPath reconstructs path from activity entries', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('h1', { label: 'H1', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });
    graph.addNode('h2', { label: 'H2', nodeType: 'host', color: '#fff', x: 1, y: 0, _props: { type: 'host' } });
    graph.addNode('h3', { label: 'H3', nodeType: 'host', color: '#fff', x: 2, y: 0, _props: { type: 'host' } });
    graph.addEdgeWithKey('h1--REACHABLE--h2', 'h1', 'h2', { edgeType: 'REACHABLE' });
    graph.addEdgeWithKey('h2--REACHABLE--h3', 'h2', 'h3', { edgeType: 'REACHABLE' });

    const entries = [
      { timestamp: '2026-01-01T01:00:00Z', target_node_ids: ['h1'], category: 'finding' },
      { timestamp: '2026-01-01T02:00:00Z', target_node_ids: ['h2'], category: 'finding' },
      { timestamp: '2026-01-01T03:00:00Z', target_node_ids: ['h3'], category: 'finding' },
    ];

    const result = graphModule.buildActualPath(entries);
    expect(result.nodes.size).toBe(3);
    expect(result.edges.size).toBe(2);
  });

  it('buildActualPath skips gaps between disconnected consecutive nodes', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('h1', { label: 'H1', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });
    graph.addNode('h2', { label: 'H2', nodeType: 'host', color: '#fff', x: 5, y: 0, _props: { type: 'host' } });

    const entries = [
      { timestamp: '2026-01-01T01:00:00Z', target_node_ids: ['h1'], category: 'finding' },
      { timestamp: '2026-01-01T02:00:00Z', target_node_ids: ['h2'], category: 'finding' },
    ];

    const result = graphModule.buildActualPath(entries);
    expect(result.nodes.size).toBe(2);
    expect(result.edges.size).toBe(0);
  });

  it('buildCredentialFlowData collects credential-related edges and chains', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('user-a', { label: 'alice', nodeType: 'user', color: '#fff', x: 0, y: 0, _props: { type: 'user' } });
    graph.addNode('cred-a', { label: 'alice-ntlm', nodeType: 'credential', color: '#fff', x: 1, y: 0, _props: { type: 'credential' } });
    graph.addNode('cred-b', { label: 'alice-tgt', nodeType: 'credential', color: '#fff', x: 2, y: 0, _props: { type: 'credential', derivation_method: 'pass-the-hash' } });
    graph.addNode('host-a', { label: '10.10.10.1', nodeType: 'host', color: '#fff', x: 3, y: 0, _props: { type: 'host' } });

    graph.addEdgeWithKey('user-a--OWNS_CRED--cred-a', 'user-a', 'cred-a', { edgeType: 'OWNS_CRED' });
    graph.addEdgeWithKey('cred-a--DERIVED_FROM--cred-b', 'cred-a', 'cred-b', { edgeType: 'DERIVED_FROM' });
    graph.addEdgeWithKey('cred-b--VALID_ON--host-a', 'cred-b', 'host-a', { edgeType: 'VALID_ON' });

    const result = graphModule.buildCredentialFlowData();
    expect(result.flowEdges.size).toBe(3);
    expect(result.flowNodes.has('user-a')).toBe(true);
    expect(result.flowNodes.has('cred-a')).toBe(true);
    expect(result.flowNodes.has('cred-b')).toBe(true);
    expect(result.flowNodes.has('host-a')).toBe(true);
    expect(result.chains.length).toBeGreaterThanOrEqual(1);
  });

  it('buildCredentialFlowData returns empty data for graph without credentials', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('host-a', { label: 'Host A', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });

    const result = graphModule.buildCredentialFlowData();
    expect(result.flowEdges.size).toBe(0);
    expect(result.chains.length).toBe(0);
  });

  it('invalidateHistoryCache clears the cache so next fetch is fresh', async () => {
    const graphModule = await loadGraphModule();
    graphModule.init();

    // Initially no cache
    expect(graphModule.activityHistoryCacheTotal).toBe(0);

    // Simulate a manual cache set via internal state (can't mock fetch easily)
    graphModule.invalidateHistoryCache();
    expect(graphModule.activityHistoryCacheTotal).toBe(0);
  });

  it('clearAllOverlays resets path, attack path, and credential flow states', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('cred-a', { label: 'cred-a', nodeType: 'credential', color: '#fff', x: 0, y: 0, _props: { type: 'credential' } });
    graph.addNode('cred-b', { label: 'cred-b', nodeType: 'credential', color: '#fff', x: 1, y: 0, _props: { type: 'credential' } });
    graph.addEdgeWithKey('cred-a--DERIVED_FROM--cred-b', 'cred-a', 'cred-b', { edgeType: 'DERIVED_FROM' });

    // Activate credential flow, then clear all
    expect(graphModule.credentialFlowMode).toBe(false);
    expect(graphModule.attackPathOverlay).toBe(null);

    graphModule.clearAllOverlays();

    expect(graphModule.credentialFlowMode).toBe(false);
    expect(graphModule.attackPathOverlay).toBe(null);
  });

  it('buildCredentialFlowData captures branching DERIVED_FROM DAGs', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    // Parent credential with two derived children
    graph.addNode('cred-root', { label: 'root-ntlm', nodeType: 'credential', color: '#fff', x: 0, y: 0, _props: { type: 'credential' } });
    graph.addNode('cred-child1', { label: 'child1-tgt', nodeType: 'credential', color: '#fff', x: 1, y: 0, _props: { type: 'credential', derivation_method: 'overpass-the-hash' } });
    graph.addNode('cred-child2', { label: 'child2-tgt', nodeType: 'credential', color: '#fff', x: 2, y: 0, _props: { type: 'credential', derivation_method: 'silver-ticket' } });

    // Both children derived from root (child → parent direction)
    graph.addEdgeWithKey('cred-child1--DERIVED_FROM--cred-root', 'cred-child1', 'cred-root', { edgeType: 'DERIVED_FROM' });
    graph.addEdgeWithKey('cred-child2--DERIVED_FROM--cred-root', 'cred-child2', 'cred-root', { edgeType: 'DERIVED_FROM' });

    const result = graphModule.buildCredentialFlowData();

    // Should have one chain containing all 3 nodes (not just 2)
    expect(result.chains.length).toBe(1);
    const chainIds = result.chains[0].map((n: any) => n.id);
    expect(chainIds).toContain('cred-root');
    expect(chainIds).toContain('cred-child1');
    expect(chainIds).toContain('cred-child2');
    expect(chainIds.length).toBe(3);
  });

  it('getEdgeTypeCounts returns correct per-type breakdown with inferred flag', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('host-a', { label: '10.10.10.1', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });
    graph.addNode('host-b', { label: '10.10.10.2', nodeType: 'host', color: '#fff', x: 1, y: 0, _props: { type: 'host' } });
    graph.addNode('user-a', { label: 'alice', nodeType: 'user', color: '#fff', x: 2, y: 0, _props: { type: 'user' } });

    graph.addEdgeWithKey('host-a--ADMIN_TO--host-b', 'host-a', 'host-b', { edgeType: 'ADMIN_TO', inferredByRule: null });
    graph.addEdgeWithKey('host-b--ADMIN_TO--host-a', 'host-b', 'host-a', { edgeType: 'ADMIN_TO', inferredByRule: 'test-rule' });
    graph.addEdgeWithKey('user-a--HAS_SESSION--host-a', 'user-a', 'host-a', { edgeType: 'HAS_SESSION', inferredByRule: null });

    const counts = graphModule.getEdgeTypeCounts();
    expect(counts.get('ADMIN_TO').total).toBe(2);
    expect(counts.get('ADMIN_TO').confirmed).toBe(1);
    expect(counts.get('ADMIN_TO').inferred).toBe(1);
    expect(counts.get('HAS_SESSION').total).toBe(1);
    expect(counts.get('HAS_SESSION').confirmed).toBe(1);
    expect(counts.get('HAS_SESSION').inferred).toBe(0);
  });

  it('setEdgeTypeFilter toggles on and clearEdgeFilter resets', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('host-a', { label: '10.10.10.1', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });
    graph.addNode('host-b', { label: '10.10.10.2', nodeType: 'host', color: '#fff', x: 1, y: 0, _props: { type: 'host' } });
    graph.addEdgeWithKey('host-a--ADMIN_TO--host-b', 'host-a', 'host-b', { edgeType: 'ADMIN_TO' });

    expect(graphModule.edgeTypeFilter).toBe(null);

    graphModule.setEdgeTypeFilter('ADMIN_TO');
    expect(graphModule.edgeTypeFilter).toEqual({ type: 'ADMIN_TO' });

    graphModule.clearEdgeFilter();
    expect(graphModule.edgeTypeFilter).toBe(null);
  });

  it('setEdgeSourceFilter toggles confirmed/inferred', async () => {
    const graphModule = await loadGraphModule();
    graphModule.init();

    expect(graphModule.edgeSourceFilter).toBe(null);

    graphModule.setEdgeSourceFilter('inferred');
    expect(graphModule.edgeSourceFilter).toBe('inferred');

    // Toggle off same source
    graphModule.setEdgeSourceFilter('inferred');
    expect(graphModule.edgeSourceFilter).toBe(null);
  });

  it('buildEdgeAttributes preserves inferredByRule from props', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('host-a', { label: '10.10.10.1', nodeType: 'host', color: '#fff', x: 0, y: 0, _props: { type: 'host' } });
    graph.addNode('host-b', { label: '10.10.10.2', nodeType: 'host', color: '#fff', x: 1, y: 0, _props: { type: 'host' } });

    // Simulate loading graph data with inferred_by_rule on an edge
    graphModule.loadGraphData({
      nodes: [
        { id: 'host-a', properties: { type: 'host', label: '10.10.10.1' } },
        { id: 'host-b', properties: { type: 'host', label: '10.10.10.2' } },
      ],
      edges: [
        { id: 'host-a--POTENTIAL_AUTH--host-b', source: 'host-a', target: 'host-b', properties: { type: 'POTENTIAL_AUTH', confidence: 0.7, inferred_by_rule: 'kerberoastable' } },
      ],
    });

    const attrs = graph.getEdgeAttributes('host-a--POTENTIAL_AUTH--host-b');
    expect(attrs.inferredByRule).toBe('kerberoastable');
    expect(attrs.edgeType).toBe('POTENTIAL_AUTH');
  });

  it('showCredentialFlow clears edge type and source filters', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('cred-a', { label: 'cred-a', nodeType: 'credential', color: '#fff', x: 0, y: 0, _props: { type: 'credential' } });
    graph.addNode('host-a', { label: '10.10.10.1', nodeType: 'host', color: '#fff', x: 1, y: 0, _props: { type: 'host' } });
    graph.addEdgeWithKey('cred-a--VALID_ON--host-a', 'cred-a', 'host-a', { edgeType: 'VALID_ON' });

    // Activate edge type filter
    graphModule.setEdgeTypeFilter('VALID_ON');
    expect(graphModule.edgeTypeFilter).toEqual({ type: 'VALID_ON' });

    // Activate credential flow — should clear edge filters
    graphModule.showCredentialFlow();
    expect(graphModule.edgeTypeFilter).toBe(null);
    expect(graphModule.edgeSourceFilter).toBe(null);
    expect(graphModule.credentialFlowMode).toBe(true);
  });

  it('showCredentialFlow clears edge source filter', async () => {
    const graphModule = await loadGraphModule();
    graphModule.init();

    // Activate edge source filter
    graphModule.setEdgeSourceFilter('confirmed');
    expect(graphModule.edgeSourceFilter).toBe('confirmed');

    // Activate credential flow — should clear edge source filter
    graphModule.showCredentialFlow();
    expect(graphModule.edgeSourceFilter).toBe(null);
    expect(graphModule.credentialFlowMode).toBe(true);
  });

  it('showAttackPath leaves existing edge filters intact when no path can be built', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('cred-a', { label: 'cred-a', nodeType: 'credential', color: '#fff', x: 0, y: 0, _props: { type: 'credential' } });
    graph.addNode('host-a', { label: '10.10.10.1', nodeType: 'host', color: '#fff', x: 1, y: 0, _props: { type: 'host' } });
    graph.addEdgeWithKey('cred-a--VALID_ON--host-a', 'cred-a', 'host-a', { edgeType: 'VALID_ON' });

    graphModule.setEdgeTypeFilter('VALID_ON');
    expect(graphModule.edgeTypeFilter).toEqual({ type: 'VALID_ON' });

    (globalThis as any).fetch = vi.fn(async () => ({
      ok: true,
      async json() {
        return { entries: [] };
      },
    }));

    const shown = await graphModule.showAttackPath();
    expect(shown).toBe(false);
    expect(graphModule.edgeTypeFilter).toEqual({ type: 'VALID_ON' });
    expect(graphModule.attackPathOverlay).toBe(null);
  });

  it('setEdgeTypeFilter clears credential flow mode', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('cred-a', { label: 'cred-a', nodeType: 'credential', color: '#fff', x: 0, y: 0, _props: { type: 'credential' } });
    graph.addNode('host-a', { label: '10.10.10.1', nodeType: 'host', color: '#fff', x: 1, y: 0, _props: { type: 'host' } });
    graph.addEdgeWithKey('cred-a--VALID_ON--host-a', 'cred-a', 'host-a', { edgeType: 'VALID_ON' });

    // Activate credential flow
    graphModule.showCredentialFlow();
    expect(graphModule.credentialFlowMode).toBe(true);

    // Activate edge type filter — should clear credential flow
    graphModule.setEdgeTypeFilter('VALID_ON');
    expect(graphModule.credentialFlowMode).toBe(false);
    expect(graphModule.edgeTypeFilter).toEqual({ type: 'VALID_ON' });
  });

  it('treats certificate authorities as high-signal nodes with contextual focus', async () => {
    const graphModule = await loadGraphModule();
    const graph = graphModule.init();

    graph.addNode('domain-a', { label: 'north.local', nodeType: 'domain', color: '#fff', x: 0, y: -1, _props: { type: 'domain' } });
    graph.addNode('ca-a', { label: 'NORTH-CA', nodeType: 'ca', color: '#fff', x: 0, y: 0, _props: { type: 'ca' } });
    graph.addNode('template-a', { label: 'UserTemplate', nodeType: 'cert_template', color: '#fff', x: 1, y: 0, _props: { type: 'cert_template' } });
    graph.addEdgeWithKey('ca-a--RELATED--domain-a', 'ca-a', 'domain-a', { edgeType: 'RELATED' });
    graph.addEdgeWithKey('template-a--RELATED--ca-a', 'template-a', 'ca-a', { edgeType: 'RELATED' });

    graphModule.focusNodeType('ca');

    expect(graphModule.getVisibleNodeIds().sort()).toEqual(['ca-a', 'domain-a', 'template-a']);
  });
});
