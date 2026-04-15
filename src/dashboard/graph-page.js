// ============================================================
// Overwatch Graph Explorer — Page Boot Script
// Initializes sigma.js graph, toolbar, and WebSocket for graph page
// ============================================================

window.addEventListener('DOMContentLoaded', () => {
  const G = window.OverwatchGraph;
  const UI = window.OverwatchUI;
  const WS = window.OverwatchWS;

  // Boot guard
  const missing = [];
  if (!G) missing.push('OverwatchGraph (graph.js)');
  if (!UI) missing.push('OverwatchUI (ui.js)');
  if (!WS) missing.push('OverwatchWS (ws.js)');
  if (missing.length > 0) {
    const badge = document.getElementById('ws-status');
    if (badge) {
      badge.className = 'status-badge boot-failed';
      badge.innerHTML = '<span class="status-dot"></span><span>Boot failed</span>';
    }
    console.error('[Overwatch Graph] Boot failed — missing modules:', missing.join(', '));
    return;
  }

  // Initialize graph and renderer
  G.init();
  G.initRenderer();

  // Initialize UI (search, keyboard shortcuts, minimap)
  UI.init();

  // Wire graph control buttons
  document.getElementById('btn-fit').addEventListener('click', () => G.zoomToFit());
  document.getElementById('btn-layout').addEventListener('click', () => G.toggleLayout());
  document.getElementById('btn-reset').addEventListener('click', () => {
    G.resetFilters();
    const presetSelect = document.getElementById('focus-preset-select');
    if (presetSelect) presetSelect.value = '';
  });
  document.getElementById('btn-zoom-in').addEventListener('click', () => G.zoomIn());
  document.getElementById('btn-zoom-out').addEventListener('click', () => G.zoomOut());

  // Export dropdown
  setupToolbarDropdown('export-dropdown', 'btn-export');
  document.getElementById('btn-export-png')?.addEventListener('click', () => {
    G.exportScreenshot();
    closeAllDropdowns();
  });
  document.getElementById('btn-export-svg')?.addEventListener('click', () => {
    G.exportSVG();
    closeAllDropdowns();
  });

  // Layers dropdown
  setupToolbarDropdown('layers-dropdown', 'btn-layers');
  document.getElementById('btn-layer-attack-path')?.addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    const active = btn.dataset.active !== 'true';
    if (active) {
      const shown = await G.showAttackPath();
      btn.dataset.active = String(shown);
      if (!shown) {
        document.getElementById('btn-layer-compare-shortest').disabled = true;
        document.getElementById('btn-layer-compare-shortest').dataset.active = 'false';
        return;
      }
      document.getElementById('btn-layer-cred-flow').dataset.active = 'false';
      document.getElementById('btn-edge-confirmed').dataset.active = 'false';
      document.getElementById('btn-edge-inferred').dataset.active = 'false';
      document.querySelectorAll('.edge-type-row.active').forEach(el => el.classList.remove('active'));
    } else {
      btn.dataset.active = 'false';
      G.clearAttackPathOverlay();
    }
    document.getElementById('btn-layer-compare-shortest').disabled = !active;
    if (!active) document.getElementById('btn-layer-compare-shortest').dataset.active = 'false';
  });
  document.getElementById('btn-layer-compare-shortest')?.addEventListener('click', (e) => {
    const btn = e.currentTarget;
    const active = btn.dataset.active !== 'true';
    btn.dataset.active = String(active);
    if (active) G.showTheoreticalComparison();
    else G.clearTheoreticalComparison();
  });
  document.getElementById('btn-layer-cred-flow')?.addEventListener('click', (e) => {
    const btn = e.currentTarget;
    const active = btn.dataset.active !== 'true';
    btn.dataset.active = String(active);
    if (active) {
      document.getElementById('btn-layer-attack-path').dataset.active = 'false';
      document.getElementById('btn-layer-compare-shortest').dataset.active = 'false';
      document.getElementById('btn-layer-compare-shortest').disabled = true;
      document.getElementById('btn-edge-confirmed').dataset.active = 'false';
      document.getElementById('btn-edge-inferred').dataset.active = 'false';
      document.querySelectorAll('.edge-type-row.active').forEach(el => el.classList.remove('active'));
      G.showCredentialFlow();
    } else {
      G.clearCredentialFlowMode();
    }
  });

  document.getElementById('btn-layer-community-hulls')?.addEventListener('click', (e) => {
    const btn = e.currentTarget;
    const active = btn.dataset.active !== 'true';
    btn.dataset.active = String(active);
    G.communityHullsEnabled = active;
  });

  document.getElementById('btn-layer-hide-orphans')?.addEventListener('click', (e) => {
    const btn = e.currentTarget;
    const active = btn.dataset.active !== 'true';
    btn.dataset.active = String(active);
    G.setHideOrphans(active);
  });

  document.getElementById('btn-layer-hide-reachable-only')?.addEventListener('click', (e) => {
    const btn = e.currentTarget;
    const active = btn.dataset.active !== 'true';
    btn.dataset.active = String(active);
    G.setHideReachableOnly(active);
  });

  // Edge source filter toggles
  document.getElementById('btn-edge-confirmed')?.addEventListener('click', (e) => {
    const btn = e.currentTarget;
    const active = btn.dataset.active !== 'true';
    btn.dataset.active = String(active);
    document.getElementById('btn-edge-inferred').dataset.active = 'false';
    document.getElementById('btn-layer-attack-path').dataset.active = 'false';
    document.getElementById('btn-layer-compare-shortest').dataset.active = 'false';
    document.getElementById('btn-layer-cred-flow').dataset.active = 'false';
    document.querySelectorAll('.edge-type-row.active').forEach(el => el.classList.remove('active'));
    if (active) G.setEdgeSourceFilter('confirmed');
    else G.clearEdgeFilter();
  });
  document.getElementById('btn-edge-inferred')?.addEventListener('click', (e) => {
    const btn = e.currentTarget;
    const active = btn.dataset.active !== 'true';
    btn.dataset.active = String(active);
    document.getElementById('btn-edge-confirmed').dataset.active = 'false';
    document.getElementById('btn-layer-attack-path').dataset.active = 'false';
    document.getElementById('btn-layer-compare-shortest').dataset.active = 'false';
    document.getElementById('btn-layer-cred-flow').dataset.active = 'false';
    document.querySelectorAll('.edge-type-row.active').forEach(el => el.classList.remove('active'));
    if (active) G.setEdgeSourceFilter('inferred');
    else G.clearEdgeFilter();
  });

  document.getElementById('btn-shortcuts').addEventListener('click', () => UI.toggleShortcutsOverlay());
  document.getElementById('graph-mode-select')?.addEventListener('change', (e) => {
    G.setGraphMode(e.target.value);
    G.updateMinimap();
  });
  document.getElementById('label-density-select')?.addEventListener('change', (e) => {
    G.setLabelDensity(e.target.value);
  });
  document.getElementById('focus-preset-select')?.addEventListener('change', (e) => {
    const name = e.target.value;
    if (name) G.applyFocusPreset(name);
    else G.clearFocusPreset();
  });

  const focusShowAll = document.getElementById('focus-show-all');
  if (focusShowAll) focusShowAll.addEventListener('click', () => G.exitNeighborhoodFocus());

  const pathClose = document.getElementById('path-close');
  if (pathClose) pathClose.addEventListener('click', () => G.clearAllOverlays());

  document.getElementById('detail-close').addEventListener('click', () => UI.hideDetail());

  // Camera → minimap
  const renderer = G.renderer;
  if (renderer) {
    renderer.getCamera().on('updated', () => G.updateMinimap());
  }

  // Close dropdowns on outside click
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.toolbar-dropdown')) closeAllDropdowns();
  });

  // Handle URL parameters for deep linking
  handleDeepLink();

  // Connect WebSocket
  WS.connect({
    onInitialState(data) {
      G.loadGraphData(data.graph);
      updateGraphHeader(data.state);
      refreshEdgeTypeList();
      setTimeout(() => G.updateMinimap(), 500);
    },
    onStateRefresh(data) {
      G.syncGraphData(data.graph);
      updateGraphHeader(data.state);
      G.updateMinimap();
      refreshEdgeTypeList();
      checkHistoryChanged(data.state || data);
    },
    onGraphUpdate(data) {
      G.mergeGraphDelta(data.delta);
      updateGraphHeader(data.state);
      G.updateMinimap();
      refreshEdgeTypeList();
      checkHistoryChanged(data.state || data);
    },
  });
});

// ============================================================
// Graph page header updates (lightweight — no panel rendering)
// ============================================================

function updateGraphHeader(state) {
  if (!state) return;
  const el = document.getElementById('engagement-name');
  if (el) el.textContent = state.engagement?.name || state.config?.name || '—';
  const nodes = document.getElementById('stat-nodes');
  if (nodes) nodes.textContent = state.graph_summary?.total_nodes || 0;
  const edges = document.getElementById('stat-edges');
  if (edges) edges.textContent = state.graph_summary?.total_edges || 0;
  const access = document.getElementById('stat-access');
  if (access) access.textContent = state.access_summary?.current_access_level || 'none';
}

// ============================================================
// Deep linking: ?focus=nodeId or ?path=from,to
// ============================================================

function handleDeepLink() {
  const params = new URLSearchParams(window.location.search);
  const focusNode = params.get('focus');
  const pathParam = params.get('path');

  if (focusNode) {
    // Wait for graph data to load, then navigate
    const check = setInterval(() => {
      const G = window.OverwatchGraph;
      if (G?.graph?.hasNode(focusNode)) {
        clearInterval(check);
        if (window.OverwatchUI) {
          window.OverwatchUI.navigateToNode(focusNode, { hops: 1 });
        }
      }
    }, 500);
    // Give up after 10s
    setTimeout(() => clearInterval(check), 10000);
  }

  if (pathParam) {
    const parts = pathParam.split(',');
    if (parts.length === 2) {
      const check = setInterval(() => {
        const G = window.OverwatchGraph;
        if (G?.graph?.hasNode(parts[0]) && G.graph.hasNode(parts[1])) {
          clearInterval(check);
          G.showShortestPath(parts[0], parts[1]);
        }
      }, 500);
      setTimeout(() => clearInterval(check), 10000);
    }
  }
}

// ============================================================
// Toolbar helpers (same as main.js)
// ============================================================

function setupToolbarDropdown(wrapperId, toggleBtnId) {
  const wrapper = document.getElementById(wrapperId);
  const btn = document.getElementById(toggleBtnId);
  if (!wrapper || !btn) return;
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    const wasOpen = wrapper.classList.contains('open');
    closeAllDropdowns();
    if (!wasOpen) wrapper.classList.add('open');
  });
}

function closeAllDropdowns() {
  document.querySelectorAll('.toolbar-dropdown.open').forEach(el => el.classList.remove('open'));
}

function refreshEdgeTypeList() {
  const G = window.OverwatchGraph;
  if (!G) return;
  const list = document.getElementById('edge-type-list');
  if (!list) return;
  const counts = G.getEdgeTypeCounts();
  if (counts.size === 0) {
    list.innerHTML = '<div style="padding:4px 10px;color:var(--text-muted);font-size:11px">No edges</div>';
    return;
  }
  const categories = G.EDGE_CATEGORIES || {};
  const activeType = G.edgeTypeFilter?.type || null;
  const sorted = [...counts.entries()].sort((a, b) => b[1].total - a[1].total);
  const esc = window.OverwatchShared?.escapeHtml || G.escapeHtml;
  list.innerHTML = sorted.map(([edgeType, c]) => {
    const color = categories[edgeType] || 'rgba(110,158,255,0.25)';
    const activeClass = activeType === edgeType ? ' active' : '';
    const inferLabel = c.inferred > 0 ? ` (${c.inferred} inf)` : '';
    return `<div class="edge-type-row${activeClass}" data-edge-type="${esc(edgeType)}">
      <span class="edge-type-dot" style="background:${esc(color)}"></span>
      <span class="edge-type-name">${esc(edgeType)}</span>
      <span class="edge-type-count">${c.total}${inferLabel}</span>
    </div>`;
  }).join('');
  list.querySelectorAll('.edge-type-row').forEach(row => {
    row.addEventListener('click', () => {
      const et = row.dataset.edgeType;
      document.getElementById('btn-edge-confirmed').dataset.active = 'false';
      document.getElementById('btn-edge-inferred').dataset.active = 'false';
      document.getElementById('btn-layer-attack-path').dataset.active = 'false';
      document.getElementById('btn-layer-compare-shortest').dataset.active = 'false';
      document.getElementById('btn-layer-cred-flow').dataset.active = 'false';
      const wasActive = row.classList.contains('active');
      list.querySelectorAll('.edge-type-row.active').forEach(el => el.classList.remove('active'));
      if (!wasActive) row.classList.add('active');
      G.setEdgeTypeFilter(et);
    });
  });
  refreshEdgeLegend();
}

const EDGE_LEGEND_CATEGORIES = [
  { label: 'Network', types: ['REACHABLE', 'RUNS'] },
  { label: 'Access', types: ['ADMIN_TO', 'HAS_SESSION', 'CAN_RDPINTO', 'CAN_PSREMOTE'] },
  { label: 'Credentials', types: ['VALID_ON', 'OWNS_CRED', 'TESTED_CRED'] },
  { label: 'Cred Reuse', types: ['SHARED_CREDENTIAL'] },
  { label: 'AD Attack', types: ['CAN_DCSYNC', 'GENERIC_ALL', 'WRITE_DACL'] },
  { label: 'ADCS', types: ['CAN_ENROLL', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC6', 'ESC7', 'ESC8'] },
  { label: 'Delegation', types: ['DELEGATES_TO', 'CAN_DELEGATE_TO'] },
  { label: 'Roasting', types: ['KERBEROASTABLE', 'AS_REP_ROASTABLE'] },
  { label: 'Lateral', types: ['RELAY_TARGET', 'NULL_SESSION'] },
  { label: 'Cred Chain', types: ['DERIVED_FROM', 'DUMPED_FROM'] },
  { label: 'Domain', types: ['MEMBER_OF', 'TRUSTS'] },
  { label: 'Web', types: ['VULNERABLE_TO', 'EXPLOITS'] },
  { label: 'Cloud', types: ['ASSUMES_ROLE', 'POLICY_ALLOWS'] },
  { label: 'Inferred', types: ['_inferred_'] },
];

function refreshEdgeLegend() {
  const G = window.OverwatchGraph;
  if (!G) return;
  const body = document.getElementById('edge-legend-body');
  if (!body) return;
  const categories = G.EDGE_CATEGORIES || {};
  const esc = window.OverwatchShared?.escapeHtml || G.escapeHtml;

  body.innerHTML = EDGE_LEGEND_CATEGORIES.map(cat => {
    if (cat.types[0] === '_inferred_') {
      return `<div class="edge-legend-row">
        <span class="edge-legend-swatch inferred" style="border-color:var(--text-muted)"></span>
        <span class="edge-legend-label">Inferred (no arrow)</span>
      </div>`;
    }
    const color = categories[cat.types[0]] || '#888';
    return `<div class="edge-legend-row">
      <span class="edge-legend-swatch" style="background:${esc(color)}"></span>
      <span class="edge-legend-label">${esc(cat.label)}</span>
    </div>`;
  }).join('');

  const legend = document.getElementById('edge-legend');
  const toggle = document.getElementById('edge-legend-toggle');
  if (legend && toggle && !toggle._bound) {
    toggle._bound = true;
    legend.addEventListener('click', (e) => {
      if (e.target.closest('.edge-legend-header')) {
        legend.classList.toggle('collapsed');
      }
    });
  }
}

function checkHistoryChanged(state) {
  const serverCount = state?.history_count;
  if (typeof serverCount !== 'number') return;
  const G = window.OverwatchGraph;
  if (!G) return;
  if (serverCount > G.activityHistoryCacheTotal) {
    G.refreshAttackPathIfActive();
  }
}
