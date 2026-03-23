import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Graph from 'graphology';
import { resolve } from 'path';
import { pathToFileURL } from 'url';

async function loadGraphModule() {
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
    };
    (globalThis as any).graphology = { Graph };
  });

  afterEach(() => {
    vi.restoreAllMocks();
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
