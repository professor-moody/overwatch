// ============================================================
// Overwatch Dashboard — Main Entry Point
// Wires graph, UI, and WebSocket modules together
// ============================================================

window.addEventListener('DOMContentLoaded', () => {
  const G = window.OverwatchGraph;
  const UI = window.OverwatchUI;
  const WS = window.OverwatchWS;

  // Defensive boot guard — abort cleanly if any module failed to load
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
    console.error('[Overwatch] Dashboard boot failed — missing modules:', missing.join(', '));
    return;
  }

  // Initialize graph and renderer
  G.init();
  G.initRenderer();

  // Initialize UI (collapsible panels, search, keyboard shortcuts, minimap)
  UI.init();

  // Wire up graph control buttons
  document.getElementById('btn-fit').addEventListener('click', () => G.zoomToFit());
  document.getElementById('btn-layout').addEventListener('click', () => G.toggleLayout());
  document.getElementById('btn-reset').addEventListener('click', () => G.resetFilters());
  document.getElementById('btn-zoom-in').addEventListener('click', () => G.zoomIn());
  document.getElementById('btn-zoom-out').addEventListener('click', () => G.zoomOut());
  document.getElementById('btn-export').addEventListener('click', () => G.exportScreenshot());
  document.getElementById('btn-shortcuts').addEventListener('click', () => {
    UI.toggleShortcutsOverlay();
  });
  document.getElementById('graph-mode-select')?.addEventListener('change', (event) => {
    G.setGraphMode(event.target.value);
    G.updateMinimap();
  });
  document.getElementById('label-density-select')?.addEventListener('change', (event) => {
    G.setLabelDensity(event.target.value);
  });

  // Focus banner "Show All" button
  const focusShowAll = document.getElementById('focus-show-all');
  if (focusShowAll) {
    focusShowAll.addEventListener('click', () => G.exitNeighborhoodFocus());
  }

  // Path info bar close
  const pathClose = document.getElementById('path-close');
  if (pathClose) {
    pathClose.addEventListener('click', () => G.clearPathHighlight());
  }

  // Node detail close
  document.getElementById('detail-close').addEventListener('click', () => UI.hideDetail());

  // Update minimap when camera moves
  const renderer = G.renderer;
  if (renderer) {
    renderer.getCamera().on('updated', () => {
      G.updateMinimap();
    });
  }

  // Connect WebSocket
  WS.connect({
    onInitialState(data) {
      G.loadGraphData(data.graph);
      UI.updateUI(data.state);
      // Delayed minimap update after layout settles
      setTimeout(() => G.updateMinimap(), 500);
    },
    onStateRefresh(data) {
      G.syncGraphData(data.graph);
      UI.updateUI(data.state);
      G.updateMinimap();
    },
    onGraphUpdate(data) {
      G.mergeGraphDelta(data.delta);
      UI.updateUI(data.state);
      G.updateMinimap();
    },
  });
});
