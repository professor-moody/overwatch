import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resolve } from 'path';
import { pathToFileURL } from 'url';

function makeClassList(initial: string[] = []) {
  const classes = new Set(initial);
  return {
    add(name: string) {
      classes.add(name);
    },
    remove(name: string) {
      classes.delete(name);
    },
    toggle(name: string) {
      if (classes.has(name)) classes.delete(name);
      else classes.add(name);
    },
    contains(name: string) {
      return classes.has(name);
    },
  };
}

function makeElement(overrides: Record<string, unknown> = {}) {
  const listeners = new Map<string, (event: any) => unknown>();
  const element: any = {
    dataset: { active: 'false' },
    disabled: false,
    classList: makeClassList(),
    style: {},
    value: '',
    innerHTML: '',
    textContent: '',
    addEventListener(type: string, handler: (event: any) => unknown) {
      listeners.set(type, handler);
    },
    async trigger(type: string, extra: Record<string, unknown> = {}) {
      const handler = listeners.get(type);
      if (!handler) return;
      return await handler({
        currentTarget: element,
        target: element,
        stopPropagation() {},
        preventDefault() {},
        closest() { return null; },
        ...extra,
      });
    },
    ...overrides,
  };
  return element;
}

async function loadMainModule() {
  const url = pathToFileURL(resolve('/Users/keys/projects/overwatch/src/dashboard/main.js')).href;
  await import(`${url}?t=${Date.now()}-${Math.random()}`);
}

describe('dashboard main entrypoint', () => {
  let elements: Map<string, any>;
  let domReadyHandler: (() => unknown) | null;
  let edgeRow: any;

  beforeEach(() => {
    elements = new Map();
    domReadyHandler = null;
    edgeRow = { classList: makeClassList(['active']), dataset: { edgeType: 'VALID_ON' }, addEventListener() {} };

    const ids = [
      'btn-fit',
      'btn-layout',
      'btn-reset',
      'btn-zoom-in',
      'btn-zoom-out',
      'export-dropdown',
      'btn-export',
      'btn-export-png',
      'btn-export-svg',
      'layers-dropdown',
      'btn-layers',
      'btn-layer-attack-path',
      'btn-layer-compare-shortest',
      'btn-layer-cred-flow',
      'btn-edge-confirmed',
      'btn-edge-inferred',
      'btn-shortcuts',
      'graph-mode-select',
      'label-density-select',
      'focus-show-all',
      'path-close',
      'detail-close',
      'edge-type-list',
    ];

    for (const id of ids) {
      elements.set(id, makeElement());
    }

    elements.get('btn-edge-confirmed').dataset.active = 'true';
    elements.get('btn-layer-compare-shortest').disabled = true;

    (globalThis as any).window = {
      addEventListener(event: string, handler: () => unknown) {
        if (event === 'DOMContentLoaded') domReadyHandler = handler;
      },
      OverwatchGraph: {
        init: vi.fn(),
        initRenderer: vi.fn(),
        zoomToFit: vi.fn(),
        toggleLayout: vi.fn(),
        resetFilters: vi.fn(),
        zoomIn: vi.fn(),
        zoomOut: vi.fn(),
        exportScreenshot: vi.fn(),
        exportSVG: vi.fn(),
        showAttackPath: vi.fn().mockResolvedValue(false),
        clearAttackPathOverlay: vi.fn(),
        showTheoreticalComparison: vi.fn(),
        clearTheoreticalComparison: vi.fn(),
        showCredentialFlow: vi.fn(),
        clearCredentialFlowMode: vi.fn(),
        setEdgeSourceFilter: vi.fn(),
        clearEdgeFilter: vi.fn(),
        updateMinimap: vi.fn(),
        setGraphMode: vi.fn(),
        setLabelDensity: vi.fn(),
        exitNeighborhoodFocus: vi.fn(),
        clearAllOverlays: vi.fn(),
        loadGraphData: vi.fn(),
        syncGraphData: vi.fn(),
        mergeGraphDelta: vi.fn(),
        getEdgeTypeCounts: vi.fn(() => new Map()),
        get renderer() { return null; },
        get edgeTypeFilter() { return null; },
        get activityHistoryCacheTotal() { return 0; },
      },
      OverwatchUI: {
        init: vi.fn(),
        toggleShortcutsOverlay: vi.fn(),
        hideDetail: vi.fn(),
        updateUI: vi.fn(),
      },
      OverwatchWS: {
        connect: vi.fn(),
      },
    };

    (globalThis as any).document = {
      getElementById(id: string) {
        return elements.get(id) || null;
      },
      querySelectorAll(selector: string) {
        if (selector === '.edge-type-row.active') {
          return edgeRow.classList.contains('active') ? [edgeRow] : [];
        }
        if (selector === '.toolbar-dropdown.open') return [];
        return [];
      },
      addEventListener() {},
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete (globalThis as any).window;
    delete (globalThis as any).document;
  });

  it('preserves existing filter UI when attack path activation finds no path', async () => {
    await loadMainModule();
    expect(domReadyHandler).toBeTypeOf('function');
    await domReadyHandler?.();

    const attackBtn = elements.get('btn-layer-attack-path');
    const compareBtn = elements.get('btn-layer-compare-shortest');
    const confirmedBtn = elements.get('btn-edge-confirmed');
    const graphApi = (globalThis as any).window.OverwatchGraph;

    await attackBtn.trigger('click');

    expect(graphApi.showAttackPath).toHaveBeenCalledTimes(1);
    expect(attackBtn.dataset.active).toBe('false');
    expect(compareBtn.disabled).toBe(true);
    expect(compareBtn.dataset.active).toBe('false');
    expect(confirmedBtn.dataset.active).toBe('true');
    expect(edgeRow.classList.contains('active')).toBe(true);
  });
});
