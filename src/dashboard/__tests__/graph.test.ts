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
});
