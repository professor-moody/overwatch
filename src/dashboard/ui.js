// ============================================================
// Overwatch Dashboard — UI Module
// Sidebar panels, detail overlay, keyboard shortcuts, search
// ============================================================

const G = () => window.OverwatchGraph;

// ============================================================
// Sidebar Panel Collapse
// ============================================================

function initCollapsiblePanels() {
  document.querySelectorAll('.panel-header').forEach((header) => {
    const panelId = header.dataset.panel;
    if (!panelId) return;

    const body = document.getElementById(panelId);
    if (!body) return;

    // Restore from localStorage
    const collapsed = localStorage.getItem(`panel-${panelId}`) === '1';
    const chevron = header.querySelector('.chevron');

    if (collapsed) {
      body.classList.add('collapsed');
      if (chevron) chevron.classList.add('collapsed');
    }

    header.addEventListener('click', () => {
      const isCollapsed = body.classList.toggle('collapsed');
      if (chevron) chevron.classList.toggle('collapsed', isCollapsed);
      localStorage.setItem(`panel-${panelId}`, isCollapsed ? '1' : '0');
    });
  });
}

// ============================================================
// UI State Updates
// ============================================================

let lastState = null;

function updateUI(state) {
  lastState = state;
  updateHeader(state);
  updateStats(state);
  updateReadiness(state);
  updateObjectives(state);
  updateFrontier(state);
  updateAgents(state);
  updateActivity(state);
}

function updateHeader(state) {
  document.getElementById('engagement-name').textContent =
    state.engagement?.name || state.config?.name || '—';
  document.getElementById('stat-nodes').textContent =
    state.graph_summary?.total_nodes || 0;
  document.getElementById('stat-edges').textContent =
    state.graph_summary?.total_edges || 0;
  document.getElementById('stat-access').textContent =
    state.access_summary?.current_access_level || 'none';
}

function updateReadiness(state) {
  const badge = document.getElementById('readiness-status');
  const issues = document.getElementById('readiness-issues');
  const readiness = state.lab_readiness || { status: 'ready', top_issues: [] };

  badge.className = `readiness-badge ${readiness.status || 'ready'}`;
  badge.textContent = readiness.status || 'ready';

  const topIssues = readiness.top_issues || [];
  if (topIssues.length === 0) {
    issues.innerHTML = '<div class="empty-state">No immediate readiness issues</div>';
    return;
  }
  issues.innerHTML = topIssues.map(issue =>
    `<div class="readiness-issue">${escapeHtml(issue)}</div>`
  ).join('');
}

function updateStats(state) {
  const grid = document.getElementById('stat-grid');
  const nodesByType = state.graph_summary?.nodes_by_type || {};
  const confirmed = state.graph_summary?.confirmed_edges || 0;
  const inferred = state.graph_summary?.inferred_edges || 0;
  const colors = G().NODE_COLORS;

  let html = '';
  const types = Object.entries(nodesByType).sort((a, b) => b[1] - a[1]);
  for (const [type, count] of types) {
    const color = colors[type] || '#888';
    html += `<div class="stat-item">
      <div class="stat-value" style="color:${color}">${count}</div>
      <div class="stat-label">${type}s</div>
    </div>`;
  }
  html += `<div class="stat-item">
    <div class="stat-value" style="color:var(--accent)">${confirmed}</div>
    <div class="stat-label">Confirmed edges</div>
  </div>`;
  html += `<div class="stat-item">
    <div class="stat-value" style="color:var(--purple)">${inferred}</div>
    <div class="stat-label">Inferred edges</div>
  </div>`;
  grid.innerHTML = html;
}

function updateObjectives(state) {
  const list = document.getElementById('objectives-list');
  const objectives = state.objectives || [];
  document.getElementById('obj-count').textContent =
    `(${objectives.filter(o => o.achieved).length}/${objectives.length})`;

  if (objectives.length === 0) {
    list.innerHTML = '<div class="empty-state">No objectives defined</div>';
    return;
  }
  list.innerHTML = objectives.map(o => `
    <div class="objective-card ${o.achieved ? 'achieved' : 'pending'}">
      <div class="obj-name">${escapeHtml(o.description)}</div>
      <div class="obj-status">${o.achieved ? '✓ Achieved' : '○ In progress'}</div>
    </div>
  `).join('');
}

function updateFrontier(state) {
  const list = document.getElementById('frontier-list');
  const frontier = state.frontier || [];
  document.getElementById('frontier-count').textContent = `(${frontier.length})`;

  const top15 = frontier.slice(0, 15);
  if (top15.length === 0) {
    list.innerHTML = '<div class="empty-state">Frontier empty</div>';
    return;
  }
  list.innerHTML = top15.map((f, idx) => {
    const typeClass = f.type === 'incomplete_node' ? 'incomplete' : 'inferred';
    const noise = f.opsec_noise !== undefined ? f.opsec_noise.toFixed(1) : '—';
    const nodeIds = (f.node_ids || []).join(',');
    return `<div class="frontier-item" data-node-ids="${escapeHtml(nodeIds)}" onclick="handleFrontierClick(this)">
      <span class="fi-type ${typeClass}">${f.type === 'incomplete_node' ? 'node' : 'edge'}</span>
      <span class="fi-desc" title="${escapeHtml(f.description || '')}">${escapeHtml(f.description || f.id)}</span>
      <span class="fi-noise">${noise}</span>
    </div>`;
  }).join('');
}

function updateAgents(state) {
  const list = document.getElementById('agents-list');
  const agents = state.active_agents || [];
  document.getElementById('agent-count').textContent = `(${agents.length})`;

  if (agents.length === 0) {
    list.innerHTML = '<div class="empty-state">No active agents</div>';
    return;
  }
  list.innerHTML = agents.map(a => `
    <div class="agent-card">
      <div class="agent-id">${escapeHtml(a.agent_id || a.id)}</div>
      <div class="agent-status ${a.status}">${a.status}${a.skill ? ' · ' + escapeHtml(a.skill) : ''}</div>
    </div>
  `).join('');
}

function updateActivity(state) {
  const list = document.getElementById('activity-list');
  const history = state.recent_activity || [];
  const recent = history.slice(-20).reverse();

  if (recent.length === 0) {
    list.innerHTML = '<div class="empty-state">No activity yet</div>';
    return;
  }
  list.innerHTML = recent.map(a => {
    const time = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '';
    return `<div class="activity-item">
      <span class="act-time">${time}</span>
      <span class="act-msg">${escapeHtml(a.description || '')}</span>
    </div>`;
  }).join('');
}

// ============================================================
// Node Detail Panel
// ============================================================

function showNodeDetail(nodeId) {
  const g = G();
  const graph = g.graph;
  if (!graph || !graph.hasNode(nodeId)) return;

  const attrs = graph.getNodeAttributes(nodeId);
  const props = attrs._props || {};
  const nodeType = attrs.nodeType || 'unknown';
  const color = g.NODE_COLORS[nodeType] || '#888';
  const panel = document.getElementById('node-detail');

  document.getElementById('detail-title').textContent = props.label || nodeId;

  // Type badge
  const typeBadge = document.getElementById('detail-type-badge');
  if (typeBadge) {
    typeBadge.style.background = color + '22';
    typeBadge.style.color = color;
    typeBadge.textContent = nodeType;
  }

  // Properties
  const skip = new Set(['label', 'type']);
  let html = '';
  const entries = Object.entries(props).filter(([k]) => !skip.has(k));
  for (const [key, val] of entries) {
    if (val === undefined || val === null) continue;
    const display = typeof val === 'object' ? JSON.stringify(val) : String(val);
    html += `<div class="prop-row">
      <span class="prop-key">${escapeHtml(key)}</span>
      <span class="prop-val" title="${escapeHtml(display)}">${escapeHtml(display)}</span>
    </div>`;
  }

  // Connections
  const degree = graph.degree(nodeId);
  html += `<div class="prop-row">
    <span class="prop-key">connections</span>
    <span class="prop-val">${degree}</span>
  </div>`;

  // Neighbor list
  const neighbors = graph.neighbors(nodeId);
  if (neighbors.length > 0) {
    html += `<div class="detail-section">
      <div class="detail-section-title">Neighbors (${neighbors.length})</div>`;
    const displayed = neighbors.slice(0, 15);
    for (const nid of displayed) {
      const nAttrs = graph.getNodeAttributes(nid);
      const nType = nAttrs.nodeType || '?';
      const nColor = g.NODE_COLORS[nType] || '#888';
      const nLabel = nAttrs.label || nid;
      html += `<div class="neighbor-item" onclick="navigateToNode('${escapeHtml(nid)}')" title="${escapeHtml(nid)}">
        <span style="color:${nColor}">●</span> ${escapeHtml(nLabel)}
      </div>`;
    }
    if (neighbors.length > 15) {
      html += `<div class="neighbor-item" style="color:var(--text-muted)">… and ${neighbors.length - 15} more</div>`;
    }
    html += '</div>';
  }

  document.getElementById('detail-props').innerHTML = html;
  panel.classList.add('visible');
}

function hideDetail() {
  document.getElementById('node-detail').classList.remove('visible');
}

function navigateToNode(nodeId) {
  const g = G();
  if (!g.graph || !g.graph.hasNode(nodeId)) return;
  showNodeDetail(nodeId);
  // Zoom camera to node
  const attrs = g.graph.getNodeAttributes(nodeId);
  g.renderer.getCamera().animate(
    { x: attrs.x, y: attrs.y, ratio: 0.15 },
    { duration: 300 }
  );
}

// ============================================================
// Frontier Click → Zoom to Node
// ============================================================

function handleFrontierClick(el) {
  const nodeIds = (el.dataset.nodeIds || '').split(',').filter(Boolean);
  if (nodeIds.length === 0) return;

  const g = G();
  const graph = g.graph;
  // Find the first node that exists in the graph
  for (const nodeId of nodeIds) {
    if (graph && graph.hasNode(nodeId)) {
      navigateToNode(nodeId);
      return;
    }
  }
}

// ============================================================
// Search
// ============================================================

function initSearch() {
  const input = document.getElementById('search-input');
  if (!input) return;

  input.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    const g = G();
    const graph = g.graph;
    if (!graph) return;

    if (!query) {
      graph.forEachNode((id, attrs) => {
        graph.setNodeAttribute(id, 'highlighted', false);
      });
      if (g.renderer) g.renderer.refresh();
      return;
    }

    graph.forEachNode((id, attrs) => {
      const label = (attrs.label || '').toLowerCase();
      const ip = (attrs._props?.ip || '').toLowerCase();
      const hostname = (attrs._props?.hostname || '').toLowerCase();
      const match = label.includes(query) || ip.includes(query) ||
                    hostname.includes(query) || id.toLowerCase().includes(query);
      graph.setNodeAttribute(id, 'highlighted', match);
    });
    if (g.renderer) g.renderer.refresh();
  });
}

// ============================================================
// Keyboard Shortcuts
// ============================================================

let shortcutsVisible = false;

function initKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    // Don't capture when typing in an input
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

    const g = G();
    switch (e.key.toLowerCase()) {
      case 'f':
        e.preventDefault();
        g.zoomToFit();
        break;
      case ' ':
        e.preventDefault();
        g.toggleLayout();
        break;
      case 'escape':
        e.preventDefault();
        g.clearPathHighlight();
        g.exitNeighborhoodFocus();
        hideDetail();
        break;
      case 'r':
        e.preventDefault();
        g.resetFilters();
        break;
      case '=':
      case '+':
        e.preventDefault();
        g.zoomIn();
        break;
      case '-':
        e.preventDefault();
        g.zoomOut();
        break;
      case '?':
        e.preventDefault();
        toggleShortcutsOverlay();
        break;
    }
  });
}

function toggleShortcutsOverlay() {
  const overlay = document.getElementById('shortcuts-overlay');
  if (!overlay) return;
  shortcutsVisible = !shortcutsVisible;
  overlay.classList.toggle('visible', shortcutsVisible);
}

// ============================================================
// Minimap Click
// ============================================================

function initMinimapClick() {
  const canvas = document.getElementById('minimap-canvas');
  if (!canvas) return;

  canvas.addEventListener('click', (e) => {
    const g = G();
    if (!g.graph || g.graph.order === 0 || !g.renderer) return;

    // Map click position to graph coordinates (approximate)
    const rect = canvas.getBoundingClientRect();
    const clickX = (e.clientX - rect.left) / rect.width;
    const clickY = (e.clientY - rect.top) / rect.height;

    // Get graph bounds
    let minX = Infinity, maxX = -Infinity;
    let minY = Infinity, maxY = -Infinity;
    g.graph.forEachNode((id, attrs) => {
      minX = Math.min(minX, attrs.x);
      maxX = Math.max(maxX, attrs.x);
      minY = Math.min(minY, attrs.y);
      maxY = Math.max(maxY, attrs.y);
    });

    const graphX = minX + clickX * (maxX - minX);
    const graphY = minY + clickY * (maxY - minY);

    g.renderer.getCamera().animate(
      { x: graphX, y: graphY },
      { duration: 300 }
    );
  });
}

// ============================================================
// Utilities
// ============================================================

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ============================================================
// Exports (global)
// ============================================================

window.OverwatchUI = {
  init() {
    initCollapsiblePanels();
    initSearch();
    initKeyboardShortcuts();
    initMinimapClick();
  },
  updateUI,
  showNodeDetail,
  hideDetail,
  navigateToNode,
  handleFrontierClick,
};

// Global functions referenced in HTML onclick
window.showNodeDetail = showNodeDetail;
window.hideDetail = hideDetail;
window.navigateToNode = navigateToNode;
window.handleFrontierClick = handleFrontierClick;
