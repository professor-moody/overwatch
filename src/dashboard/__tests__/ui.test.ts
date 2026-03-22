import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { resolve } from 'path';
import { pathToFileURL } from 'url';
import { readFileSync } from 'fs';

async function loadUiModule() {
  const url = pathToFileURL(resolve('/Users/keys/projects/overwatch/src/dashboard/ui.js')).href;
  await import(`${url}?t=${Date.now()}-${Math.random()}`);
  return (globalThis as any).window.OverwatchUI;
}

describe('dashboard ui frontier helpers', () => {
  beforeEach(() => {
    const elements = new Map<string, any>();
    elements.set('shortcuts-overlay', {
      classList: {
        classes: new Set<string>(),
        add(name: string) { this.classes.add(name); },
        remove(name: string) { this.classes.delete(name); },
        toggle(name: string, force?: boolean) {
          if (typeof force === 'boolean') {
            if (force) this.classes.add(name);
            else this.classes.delete(name);
            return force;
          }
          if (this.classes.has(name)) {
            this.classes.delete(name);
            return false;
          }
          this.classes.add(name);
          return true;
        },
        contains(name: string) { return this.classes.has(name); },
      },
    });
    elements.set('frontier-list', { innerHTML: '' });
    elements.set('frontier-count', { textContent: '' });
    elements.set('engagement-name', { textContent: '' });
    elements.set('stat-nodes', { textContent: '' });
    elements.set('stat-edges', { textContent: '' });
    elements.set('stat-access', { textContent: '' });
    elements.set('readiness-status', { className: '', textContent: '' });
    elements.set('readiness-issues', { innerHTML: '' });
    elements.set('stat-grid', { innerHTML: '' });
    elements.set('objectives-list', { innerHTML: '' });
    elements.set('obj-count', { textContent: '' });
    elements.set('agents-list', { innerHTML: '' });
    elements.set('agent-count', { textContent: '' });
    elements.set('activity-list', { innerHTML: '' });
    elements.set('detail-title', { textContent: '' });
    elements.set('detail-subtitle', { textContent: '' });
    elements.set('detail-type-badge', { style: {}, textContent: '' });
    elements.set('detail-props', { innerHTML: '', querySelectorAll() { return []; } });
    elements.set('node-detail', { classList: { add() {}, remove() {} } });

    const graphNodes: Record<string, any> = {
      'host-1': { label: 'host-1', nodeType: 'host', _props: { label: 'host-1', type: 'host' } },
      'svc-1': { label: 'ldap/389', nodeType: 'service', _props: { label: 'ldap/389', type: 'service', service_name: 'ldap', port: 389 } },
    };

    (globalThis as any).window = {
      OverwatchGraph: {
        NODE_COLORS: { host: '#fff', service: '#0ff' },
        graph: {
          hasNode(id: string) { return !!graphNodes[id]; },
          getNodeAttribute(id: string, key: string) { return graphNodes[id]?.[key]; },
          getNodeAttributes(id: string) { return graphNodes[id]; },
          degree(id: string) { return id === 'host-1' ? 1 : 1; },
          outEdges(id: string) { return id === 'host-1' ? ['edge-1'] : []; },
          inEdges(id: string) { return id === 'host-1' ? [] : ['edge-1']; },
          getEdgeAttributes() { return { edgeType: 'RUNS', confidence: 1.0 }; },
          target() { return 'svc-1'; },
          source() { return 'host-1'; },
          neighbors(id: string) { return id === 'host-1' ? ['svc-1'] : ['host-1']; },
          edges() { return ['edge-1']; },
        },
        renderer: {
          getCamera() {
            return { animate() {} };
          },
        },
        selectNode() {},
        highlightEdges() {},
        enterNeighborhoodFocus() {},
      },
    };
    (globalThis as any).document = {
      getElementById(id: string) {
        return elements.get(id) || null;
      },
    };
  });

  afterEach(() => {
    delete (globalThis as any).window;
    delete (globalThis as any).document;
  });

  it('derives navigation target from incomplete node frontier items', async () => {
    const ui = await loadUiModule();

    expect(ui.getFrontierTargetNodeIds({
      type: 'incomplete_node',
      node_id: 'host-10-3-10-10',
    })).toEqual(['host-10-3-10-10']);
  });

  it('derives navigation targets from edge frontier items', async () => {
    const ui = await loadUiModule();

    expect(ui.getFrontierTargetNodeIds({
      type: 'inferred_edge',
      edge_source: 'user-admin',
      edge_target: 'host-10-3-10-10',
    })).toEqual(['user-admin', 'host-10-3-10-10']);
  });

  it('keeps shortcuts overlay state synchronized across repeated toggles', async () => {
    const ui = await loadUiModule();
    const overlay = (globalThis as any).document.getElementById('shortcuts-overlay');

    ui.toggleShortcutsOverlay();
    expect(overlay.classList.contains('visible')).toBe(true);

    ui.toggleShortcutsOverlay();
    expect(overlay.classList.contains('visible')).toBe(false);

    ui.setShortcutsOverlayVisible(true);
    expect(overlay.classList.contains('visible')).toBe(true);

    ui.toggleShortcutsOverlay();
    expect(overlay.classList.contains('visible')).toBe(false);
  });

  it('renders frontier cards from graph_metrics instead of missing top-level fields', async () => {
    const ui = await loadUiModule();
    const list = (globalThis as any).document.getElementById('frontier-list');

    ui.updateUI({
      engagement: {},
      graph_summary: {},
      lab_readiness: { status: 'ready', top_issues: [] },
      objectives: [],
      active_agents: [],
      recent_activity: [],
      access_summary: {},
      frontier: [{
        id: 'frontier-node-host-1',
        type: 'incomplete_node',
        node_id: 'host-1',
        missing_properties: ['os', 'services'],
        description: 'host "host-1" missing: os, services',
        graph_metrics: {
          hops_to_objective: 2,
          fan_out_estimate: 15,
          node_degree: 4,
          confidence: 0.9,
        },
        opsec_noise: 0.3,
        staleness_seconds: 10,
      }],
    });

    expect(list.innerHTML).toContain('host-1');
    expect(list.innerHTML).toContain('15');
    expect(list.innerHTML).toContain('0.9');
    expect(list.innerHTML).toContain('services');
  });

  it('renders directional connection rows in the node drawer', async () => {
    const ui = await loadUiModule();
    const props = (globalThis as any).document.getElementById('detail-props');

    ui.showNodeDetail('host-1');

    expect(props.innerHTML).toContain('Outgoing');
    expect(props.innerHTML).toContain('RUNS');
    expect(props.innerHTML).toContain('ldap/389');
  });

  it('does not reference Google Fonts in dashboard html', () => {
    const html = readFileSync(resolve('/Users/keys/projects/overwatch/src/dashboard/index.html'), 'utf8');
    expect(html).not.toContain('fonts.googleapis.com');
    expect(html).not.toContain('fonts.gstatic.com');
  });
});
