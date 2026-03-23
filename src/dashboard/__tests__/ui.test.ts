import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resolve } from 'path';
import { pathToFileURL } from 'url';
import { readFileSync } from 'fs';

async function loadUiModule() {
  const displayUrl = pathToFileURL(resolve('/Users/keys/projects/overwatch/src/dashboard/node-display.js')).href;
  await import(`${displayUrl}?t=${Date.now()}-${Math.random()}`);
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
        NODE_COLORS: { host: '#fff', service: '#0ff', group: '#f9c', ca: '#8cf', cert_template: '#c9f', pki_store: '#99a', subnet: '#8aa', certificate: '#7bf', ou: '#7aa', gpo: '#d87' },
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
        focusNodeContext: vi.fn(),
        focusNodeType: vi.fn(),
        getVisibleNodeIds() { return ['host-1', 'svc-1']; },
        graphMode: 'overview',
        selectNode() {},
        highlightEdges() {},
        enterNeighborhoodFocus() {},
      },
    };
    (globalThis as any).document = {
      getElementById(id: string) {
        return elements.get(id) || null;
      },
      querySelector() { return null; },
      querySelectorAll() { return []; },
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
    expect(list.innerHTML).toContain('Zoom');
    expect(list.innerHTML).toContain('Focus');
    expect(list.innerHTML).toContain('Top Priority');
    expect(list.innerHTML).toContain('Incomplete Nodes');
  });

  it('falls back to node ids or quoted descriptions when graph labels are unavailable', async () => {
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
      frontier: [
        {
          id: 'frontier-node-host-2',
          type: 'incomplete_node',
          node_id: 'host-10-3-10-22',
          description: 'host "braavos.essos.local" missing: os',
          graph_metrics: { node_degree: 8, confidence: 1.0 },
          opsec_noise: 0.3,
        },
        {
          id: 'frontier-edge-test-1',
          type: 'untested_edge',
          edge_source: 'user-rickon',
          edge_target: 'domain-north',
          description: 'Validate relationship between rickon and north.local',
          graph_metrics: { confidence: 0.8 },
          opsec_noise: 0.2,
        },
      ],
    });

    expect(list.innerHTML).toContain('host-10-3-10-22');
    expect(list.innerHTML).toContain('user-rickon -&gt; domain-north');
  });

  it('uses the shared node display contract for frontier and drawer labels', async () => {
    const ui = await loadUiModule();
    const list = (globalThis as any).document.getElementById('frontier-list');
    const props = (globalThis as any).document.getElementById('detail-props');
    (globalThis as any).window.OverwatchGraph.graph.getNodeAttributes = (id: string) => {
      if (id === 'host-1') {
        return {
          label: 'host-1',
          nodeType: 'host',
          _props: { type: 'host', label: 'host-1', hostname: 'winterfell.north.local', ip: '10.0.0.10' },
        };
      }
      return {
        label: 'ldap/389',
        nodeType: 'service',
        _props: { type: 'service', label: 'ldap/389', service_name: 'ldap', port: 389 },
      };
    };

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
        description: 'host "winterfell.north.local" missing: os',
        graph_metrics: { node_degree: 1, confidence: 1.0 },
        opsec_noise: 0.1,
      }],
    });

    ui.showNodeDetail('host-1');

    expect(list.innerHTML).toContain('winterfell.north.local');
    expect(props.innerHTML).toContain('winterfell.north.local');
    expect(props.innerHTML).toContain('10.0.0.10');
  });

  it('resets transient frontier expanded state after a section disappears', async () => {
    const ui = await loadUiModule();
    const list = (globalThis as any).document.getElementById('frontier-list');

    const expandedFrontier = Array.from({ length: 12 }, (_, idx) => ({
      id: `frontier-node-host-${idx}`,
      type: 'incomplete_node',
      node_id: 'host-1',
      description: `host "host-1" missing: field-${idx}`,
      missing_properties: [`field-${idx}`],
      graph_metrics: { node_degree: 4, confidence: 0.9 },
      opsec_noise: 0.3,
    }));

    ui.updateUI({
      engagement: {},
      graph_summary: {},
      lab_readiness: { status: 'ready', top_issues: [] },
      objectives: [],
      active_agents: [],
      recent_activity: [],
      access_summary: {},
      frontier: expandedFrontier,
    });

    ui.toggleFrontierSectionExpanded('incomplete_node');
    expect(list.innerHTML).toContain('Show Less');

    ui.updateUI({
      engagement: {},
      graph_summary: {},
      lab_readiness: { status: 'ready', top_issues: [] },
      objectives: [],
      active_agents: [],
      recent_activity: [],
      access_summary: {},
      frontier: [],
    });

    ui.updateUI({
      engagement: {},
      graph_summary: {},
      lab_readiness: { status: 'ready', top_issues: [] },
      objectives: [],
      active_agents: [],
      recent_activity: [],
      access_summary: {},
      frontier: expandedFrontier,
    });

    expect(list.innerHTML).toContain('Show 1 More');
    expect(list.innerHTML).not.toContain('Show Less');
  });

  it('navigates through graph context instead of hard-coding a camera jump', async () => {
    const ui = await loadUiModule();
    const graphApi = (globalThis as any).window.OverwatchGraph;

    ui.navigateToNode('svc-1', { edgeIds: ['edge-1'], hops: 1 });

    expect(graphApi.focusNodeContext).toHaveBeenCalledWith('svc-1', expect.objectContaining({
      edgeIds: ['edge-1'],
      hops: 1,
      persistent: false,
    }));
  });

  it('renders directional connection rows in the node drawer', async () => {
    const ui = await loadUiModule();
    const props = (globalThis as any).document.getElementById('detail-props');

    ui.showNodeDetail('host-1');

    expect(props.innerHTML).toContain('Outgoing');
    expect(props.innerHTML).toContain('RUNS');
    expect(props.innerHTML).toContain('ldap/389');
  });

  it('routes graph summary card clicks through type-focused graph navigation', async () => {
    const ui = await loadUiModule();
    const graphApi = (globalThis as any).window.OverwatchGraph;

    ui.handleGraphSummaryCardClick('service');

    expect(graphApi.focusNodeType).toHaveBeenCalledWith('service');
  });

  it('renders BH-heavy and PKI summary cards as clickable graph filters', async () => {
    const ui = await loadUiModule();
    const statGrid = (globalThis as any).document.getElementById('stat-grid');

    ui.updateUI({
      engagement: {},
      graph_summary: {
        total_nodes: 0,
        total_edges: 0,
        nodes_by_type: { group: 4, ca: 2, subnet: 1, gpo: 3 },
        confirmed_edges: 10,
        inferred_edges: 5,
      },
      lab_readiness: { status: 'ready', top_issues: [] },
      objectives: [],
      active_agents: [],
      recent_activity: [],
      access_summary: {},
      frontier: [],
    });

    expect(statGrid.innerHTML).toContain("handleGraphSummaryCardClick('group')");
    expect(statGrid.innerHTML).toContain("handleGraphSummaryCardClick('ca')");
    expect(statGrid.innerHTML).toContain("handleGraphSummaryCardClick('subnet')");
    expect(statGrid.innerHTML).toContain("handleGraphSummaryCardClick('gpo')");
  });

  it('does not reference Google Fonts in dashboard html', () => {
    const html = readFileSync(resolve('/Users/keys/projects/overwatch/src/dashboard/index.html'), 'utf8');
    expect(html).not.toContain('fonts.googleapis.com');
    expect(html).not.toContain('fonts.gstatic.com');
  });
});
