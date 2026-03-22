// ============================================================
// Overwatch Dashboard — UI Module v2
// Sidebar toggle, panels, drawer, frontier expand, activity colors
// ============================================================

const G = () => window.OverwatchGraph;

// ============================================================
// Sidebar Toggle
// ============================================================

let sidebarOpen = true;

function initSidebarToggle() {
  const toggle = document.getElementById('sidebar-toggle');
  const layout = document.getElementById('app-layout');
  if (!toggle || !layout) return;

  // Restore from localStorage
  const saved = localStorage.getItem('sidebar-open');
  if (saved === '0') {
    sidebarOpen = false;
    layout.classList.add('sidebar-collapsed');
  }

  toggle.addEventListener('click', () => {
    sidebarOpen = !sidebarOpen;
    layout.classList.toggle('sidebar-collapsed', !sidebarOpen);
    localStorage.setItem('sidebar-open', sidebarOpen ? '1' : '0');

    // Give sigma time to recalculate container size
    setTimeout(() => {
      const g = G();
      if (g.renderer) g.renderer.refresh();
    }, 300);
  });
}

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
  badge.textContent = (readiness.status || 'ready').toUpperCase();

  const topIssues = readiness.top_issues || [];
  if (topIssues.length === 0) {
    issues.innerHTML = '<div class="empty-state">No issues detected</div>';
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
    html += `<div class="stat-item" style="border-left-color:${color}">
      <div class="stat-value" style="color:${color}">${count}</div>
      <div class="stat-label">${type}s</div>
    </div>`;
  }
  html += `<div class="stat-item" style="border-left-color:var(--accent)">
    <div class="stat-value" style="color:var(--accent)">${confirmed}</div>
    <div class="stat-label">Confirmed</div>
  </div>`;
  html += `<div class="stat-item" style="border-left-color:var(--purple)">
    <div class="stat-value" style="color:var(--purple)">${inferred}</div>
    <div class="stat-label">Inferred</div>
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

// ============================================================
// Frontier — Compact with Expand
// ============================================================

function getNoiseColor(noise) {
  if (noise <= 0.3) return 'var(--green)';
  if (noise <= 0.6) return 'var(--amber)';
  return 'var(--red)';
}

function updateFrontier(state) {
  const list = document.getElementById('frontier-list');
  const frontier = state.frontier || [];
  document.getElementById('frontier-count').textContent = `(${frontier.length})`;

  const top20 = frontier.slice(0, 20);
  if (top20.length === 0) {
    list.innerHTML = '<div class="empty-state">Frontier empty — ingest data to generate candidates</div>';
    return;
  }
  list.innerHTML = top20.map((f, idx) => {
    const typeClass = f.type === 'incomplete_node' ? 'incomplete'
      : f.type === 'untested_edge' ? 'untested' : 'inferred';
    const typeLabel = f.type === 'incomplete_node' ? 'node'
      : f.type === 'untested_edge' ? 'test' : 'infer';
    const noise = f.opsec_noise !== undefined ? f.opsec_noise : 0;
    const noisePercent = Math.round(noise * 100);
    const noiseColor = getNoiseColor(noise);
    const nodeIds = getFrontierTargetNodeIds(f).join(',');
    const hops = f.hops_to_objective !== undefined ? f.hops_to_objective : '—';
    const fanOut = f.fan_out !== undefined ? f.fan_out : '—';
    const confidence = f.confidence !== undefined ? f.confidence.toFixed(1) : '—';

    return `<div class="frontier-item" data-idx="${idx}" data-node-ids="${escapeHtml(nodeIds)}" onclick="handleFrontierExpand(this, event)">
      <span class="fi-type ${typeClass}">${typeLabel}</span>
      <span class="fi-desc" title="${escapeHtml(f.description || '')}">${escapeHtml(f.description || f.id)}</span>
      <span class="fi-noise"><span class="fi-noise-fill" style="width:${noisePercent}%;background:${noiseColor}"></span></span>
      <div class="frontier-item-detail">
        <span class="fi-metric"><span class="fi-metric-label">noise</span> <span class="fi-metric-value">${noise.toFixed(1)}</span></span>
        <span class="fi-metric"><span class="fi-metric-label">hops</span> <span class="fi-metric-value">${hops}</span></span>
        <span class="fi-metric"><span class="fi-metric-label">fan</span> <span class="fi-metric-value">${fanOut}</span></span>
        <span class="fi-metric"><span class="fi-metric-label">conf</span> <span class="fi-metric-value">${confidence}</span></span>
        <button class="fi-zoom-btn" onclick="handleFrontierZoom(this, event)">Zoom</button>
      </div>
    </div>`;
  }).join('');
}

function handleFrontierExpand(el, event) {
  // Don't expand if clicking zoom button
  if (event.target.closest('.fi-zoom-btn')) return;
  el.classList.toggle('expanded');
}

function handleFrontierZoom(btn, event) {
  event.stopPropagation();
  const item = btn.closest('.frontier-item');
  if (!item) return;
  const nodeIds = (item.dataset.nodeIds || '').split(',').filter(Boolean);
  if (nodeIds.length === 0) return;

  const g = G();
  const graph = g.graph;
  for (const nodeId of nodeIds) {
    if (graph && graph.hasNode(nodeId)) {
      navigateToNode(nodeId);
      return;
    }
  }
}

// ============================================================
// Agents
// ============================================================

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

// ============================================================
// Activity Feed — Color-coded
// ============================================================

function getActivityColorClass(entry) {
  const desc = (entry.description || '').toLowerCase();
  const type = (entry.event_type || entry.type || '').toLowerCase();

  if (type.includes('started') || desc.includes('started')) return 'started';
  if (type.includes('completed') || desc.includes('completed')) return 'completed';
  if (type.includes('failed') || desc.includes('failed')) return 'failed';
  if (type.includes('finding') || desc.includes('finding') || desc.includes('reported') || desc.includes('parsed')) return 'finding';
  return 'default';
}

function updateActivity(state) {
  const list = document.getElementById('activity-list');
  const history = state.recent_activity || [];
  const recent = history.slice(-25).reverse();

  if (recent.length === 0) {
    list.innerHTML = '<div class="empty-state">No activity yet</div>';
    return;
  }
  list.innerHTML = recent.map(a => {
    const time = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '';
    const colorClass = getActivityColorClass(a);
    return `<div class="activity-item">
      <div class="act-color-bar ${colorClass}"></div>
      <div class="act-content">
        <span class="act-time">${time}</span>
        <span class="act-msg">${escapeHtml(a.description || '')}</span>
      </div>
    </div>`;
  }).join('');
}

// ============================================================
// Node Detail Drawer (right side)
// ============================================================

function showNodeDetail(nodeId) {
  const g = G();
  const graph = g.graph;
  if (!graph || !graph.hasNode(nodeId)) return;

  const attrs = graph.getNodeAttributes(nodeId);
  const props = attrs._props || {};
  const nodeType = attrs.nodeType || 'unknown';
  const color = g.NODE_COLORS[nodeType] || '#888';
  const drawer = document.getElementById('node-detail');

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

  // Edge details
  const edgeEntries = graph.edges(nodeId);
  if (edgeEntries.length > 0) {
    const edgeTypes = {};
    for (const eid of edgeEntries) {
      const eAttrs = graph.getEdgeAttributes(eid);
      const eType = eAttrs.edgeType || '?';
      edgeTypes[eType] = (edgeTypes[eType] || 0) + 1;
    }
    html += `<div class="detail-section">
      <div class="detail-section-title">Edge Types</div>`;
    for (const [eType, count] of Object.entries(edgeTypes).sort((a, b) => b[1] - a[1])) {
      html += `<div class="prop-row">
        <span class="prop-key">${escapeHtml(eType)}</span>
        <span class="prop-val">${count}</span>
      </div>`;
    }
    html += '</div>';
  }

  document.getElementById('detail-props').innerHTML = html;
  drawer.classList.add('visible');
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

function getFrontierTargetNodeIds(frontierItem) {
  if (!frontierItem) return [];

  if (frontierItem.type === 'incomplete_node') {
    return frontierItem.node_id ? [frontierItem.node_id] : [];
  }

  const targets = [];
  if (frontierItem.edge_source) targets.push(frontierItem.edge_source);
  if (frontierItem.edge_target) targets.push(frontierItem.edge_target);
  return [...new Set(targets)];
}

function handleFrontierClick(el) {
  const nodeIds = (el.dataset.nodeIds || '').split(',').filter(Boolean);
  if (nodeIds.length === 0) return;

  const g = G();
  const graph = g.graph;
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
      case 'b':
        e.preventDefault();
        toggleSidebar();
        break;
    }
  });
}

function toggleSidebar() {
  const toggle = document.getElementById('sidebar-toggle');
  if (toggle) toggle.click();
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
    initSidebarToggle();
    initCollapsiblePanels();
    initSearch();
    initKeyboardShortcuts();
    initMinimapClick();
  },
  updateUI,
  getFrontierTargetNodeIds,
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
window.handleFrontierExpand = handleFrontierExpand;
window.handleFrontierZoom = handleFrontierZoom;
