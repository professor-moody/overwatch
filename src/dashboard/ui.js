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

function getFrontierMetric(frontierItem, key, fallback = '—') {
  const value = frontierItem?.graph_metrics?.[key];
  return value !== undefined && value !== null ? value : fallback;
}

function getFrontierPrimaryLabel(frontierItem) {
  const g = G();
  const graph = g.graph;
  const targetNodeIds = getFrontierTargetNodeIds(frontierItem);
  for (const nodeId of targetNodeIds) {
    if (graph?.hasNode(nodeId)) {
      return graph.getNodeAttribute(nodeId, 'label') || nodeId;
    }
  }
  return frontierItem.description || frontierItem.id;
}

function renderFrontierChips(frontierItem) {
  const chips = [];
  if (frontierItem.missing_properties?.length) {
    chips.push(...frontierItem.missing_properties.map(prop => `<span class="fi-chip">${escapeHtml(prop)}</span>`));
  }
  if (frontierItem.edge_type) {
    chips.push(`<span class="fi-chip">${escapeHtml(frontierItem.edge_type)}</span>`);
  }
  const degree = getFrontierMetric(frontierItem, 'node_degree', null);
  if (degree !== null) chips.push(`<span class="fi-chip">deg ${degree}</span>`);
  return chips.join('');
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
    const hops = getFrontierMetric(f, 'hops_to_objective');
    const fanOut = getFrontierMetric(f, 'fan_out_estimate');
    const confidence = Number(getFrontierMetric(f, 'confidence', 0)).toFixed(1);
    const label = getFrontierPrimaryLabel(f);
    const chips = renderFrontierChips(f);

    return `<div class="frontier-item" data-idx="${idx}" data-node-ids="${escapeHtml(nodeIds)}" onclick="handleFrontierExpand(this, event)">
      <span class="fi-type ${typeClass}">${typeLabel}</span>
      <span class="fi-desc" title="${escapeHtml(f.description || '')}">${escapeHtml(label)}</span>
      <span class="fi-noise"><span class="fi-noise-fill" style="width:${noisePercent}%;background:${noiseColor}"></span></span>
      <div class="frontier-item-chips">${chips}</div>
      <div class="frontier-item-detail">
        <span class="fi-metric"><span class="fi-metric-label">noise</span> <span class="fi-metric-value">${noise.toFixed(1)}</span></span>
        <span class="fi-metric"><span class="fi-metric-label">hops</span> <span class="fi-metric-value">${hops}</span></span>
        <span class="fi-metric"><span class="fi-metric-label">fan</span> <span class="fi-metric-value">${fanOut}</span></span>
        <span class="fi-metric"><span class="fi-metric-label">conf</span> <span class="fi-metric-value">${confidence}</span></span>
        <button class="fi-zoom-btn" onclick="handleFrontierZoom(this, event)">Zoom</button>
        <button class="fi-zoom-btn fi-focus-btn" onclick="handleFrontierFocus(this, event)">Focus</button>
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

function handleFrontierFocus(btn, event) {
  event.stopPropagation();
  const item = btn.closest('.frontier-item');
  if (!item) return;
  const nodeIds = (item.dataset.nodeIds || '').split(',').filter(Boolean);
  const g = G();
  for (const nodeId of nodeIds) {
    if (g.graph?.hasNode(nodeId)) {
      g.enterNeighborhoodFocus(nodeId, 1);
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
  const outEdges = graph.outEdges(nodeId);
  const inEdges = graph.inEdges(nodeId);
  document.getElementById('detail-subtitle').textContent =
    `${graph.degree(nodeId)} connections · ${outEdges.length} out · ${inEdges.length} in`;

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

  html += buildServiceSummary(nodeId, graph);
  html += buildConnectionSection(nodeId, graph, 'out');
  html += buildConnectionSection(nodeId, graph, 'in');

  document.getElementById('detail-props').innerHTML = html;
  attachConnectionHandlers();
  drawer.classList.add('visible');
}

function hideDetail() {
  document.getElementById('node-detail').classList.remove('visible');
}

function navigateToNode(nodeId) {
  const g = G();
  if (!g.graph || !g.graph.hasNode(nodeId)) return;
  g.selectNode(nodeId);
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

function buildServiceSummary(nodeId, graph) {
  const attrs = graph.getNodeAttributes(nodeId);
  if (attrs.nodeType !== 'host') return '';

  const serviceRows = graph.outEdges(nodeId)
    .map(edgeId => ({ edgeId, targetId: graph.target(edgeId), edgeAttrs: graph.getEdgeAttributes(edgeId) }))
    .filter(entry => entry.edgeAttrs.edgeType === 'RUNS' && graph.hasNode(entry.targetId))
    .map(entry => {
      const serviceAttrs = graph.getNodeAttributes(entry.targetId);
      const props = serviceAttrs._props || {};
      return {
        type: props.service_name || serviceAttrs.label || 'service',
        target: serviceAttrs.label || entry.targetId,
        meta: props.version || `port ${props.port || '?'}`,
      };
    })
    .sort((a, b) => a.target.localeCompare(b.target));

  if (serviceRows.length === 0) return '';

  return `<div class="detail-section">
    <div class="detail-section-title">Open Services (${serviceRows.length})</div>
    <div class="service-summary-list">
      ${serviceRows.map(service => `
        <div class="service-summary-item">
          <span class="connection-direction">SVC</span>
          <span class="service-summary-type">${escapeHtml(service.type)}</span>
          <span class="service-summary-target">${escapeHtml(service.target)}</span>
          <span class="service-summary-meta">${escapeHtml(service.meta)}</span>
        </div>
      `).join('')}
    </div>
  </div>`;
}

function buildConnectionSection(nodeId, graph, direction) {
  const edgeIds = direction === 'out' ? graph.outEdges(nodeId) : graph.inEdges(nodeId);
  const rows = edgeIds.map(edgeId => {
    const edgeAttrs = graph.getEdgeAttributes(edgeId);
    const counterpartId = direction === 'out' ? graph.target(edgeId) : graph.source(edgeId);
    const counterpartAttrs = graph.getNodeAttributes(counterpartId);
    const counterpartProps = counterpartAttrs?._props || {};
    const confidence = edgeAttrs.confidence !== undefined ? Number(edgeAttrs.confidence).toFixed(1) : '1.0';
    return {
      edgeId,
      counterpartId,
      edgeType: edgeAttrs.edgeType || '?',
      counterpartLabel: counterpartAttrs?.label || counterpartProps.label || counterpartId,
      counterpartType: counterpartAttrs?.nodeType || counterpartProps.type || '?',
      meta: confidence === '1.0' ? 'confirmed' : `conf ${confidence}`,
    };
  }).sort((a, b) => a.edgeType.localeCompare(b.edgeType) || a.counterpartLabel.localeCompare(b.counterpartLabel));

  if (rows.length === 0) return '';

  const title = direction === 'out' ? `Outgoing (${rows.length})` : `Incoming (${rows.length})`;
  const dirLabel = direction.toUpperCase();
  return `<div class="detail-section">
    <div class="detail-section-title">${title}</div>
    <div class="connection-list">
      ${rows.map(row => `
        <div class="connection-row" data-node-id="${escapeHtml(row.counterpartId)}" data-edge-id="${escapeHtml(row.edgeId)}">
          <span class="connection-direction">${dirLabel}</span>
          <span class="connection-type">${escapeHtml(row.edgeType)}</span>
          <span class="connection-target">${escapeHtml(row.counterpartLabel)} · ${escapeHtml(row.counterpartType)}</span>
          <span class="connection-meta">${escapeHtml(row.meta)}</span>
        </div>
      `).join('')}
    </div>
  </div>`;
}

function attachConnectionHandlers() {
  const body = document.getElementById('detail-props');
  if (!body) return;
  body.querySelectorAll('.connection-row').forEach((row) => {
    row.addEventListener('click', () => {
      const nodeId = row.getAttribute('data-node-id');
      const edgeId = row.getAttribute('data-edge-id');
      if (!nodeId || !edgeId) return;
      const g = G();
      g.highlightEdges([edgeId]);
      navigateToNode(nodeId);
      g.highlightEdges([edgeId]);
    });
  });
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

function setShortcutsOverlayVisible(visible) {
  const overlay = document.getElementById('shortcuts-overlay');
  if (!overlay) return;
  overlay.classList.toggle('visible', visible);
}

function toggleShortcutsOverlay() {
  const overlay = document.getElementById('shortcuts-overlay');
  if (!overlay) return;
  const isVisible = overlay.classList.contains('visible');
  setShortcutsOverlayVisible(!isVisible);
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
  handleFrontierFocus,
  toggleShortcutsOverlay,
  setShortcutsOverlayVisible,
};

// Global functions referenced in HTML onclick
window.showNodeDetail = showNodeDetail;
window.hideDetail = hideDetail;
window.navigateToNode = navigateToNode;
window.handleFrontierClick = handleFrontierClick;
window.handleFrontierExpand = handleFrontierExpand;
window.handleFrontierZoom = handleFrontierZoom;
window.handleFrontierFocus = handleFrontierFocus;
