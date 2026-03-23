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
let frontierTypeFilter = null;
const FRONTIER_SECTION_DEFAULT_LIMIT = 5;
const FRONTIER_SECTION_PRIORITY_LIMIT = 6;
const frontierSectionState = {
  priority: { collapsed: false, expanded: false },
  incomplete_node: { collapsed: false, expanded: false },
  untested_edge: { collapsed: false, expanded: false },
  inferred_edge: { collapsed: false, expanded: false },
};

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
  const clickableTypes = new Set([
    'host', 'domain', 'objective', 'credential', 'service', 'share', 'user',
    'group', 'ou', 'gpo', 'certificate', 'subnet', 'ca', 'cert_template', 'pki_store',
  ]);

  let html = '';
  const types = Object.entries(nodesByType).sort((a, b) => b[1] - a[1]);
  for (const [type, count] of types) {
    const color = colors[type] || '#888';
    const clickable = clickableTypes.has(type);
    const label = window.OverwatchNodeDisplay.getFriendlyNodeTypeLabel(type);
    html += `<button class="stat-item ${clickable ? 'clickable' : 'telemetry'}" ${clickable ? `onclick="handleGraphSummaryCardClick('${escapeHtml(type)}')"` : 'type="button" disabled'} style="border-left-color:${color}">
      <div class="stat-value" style="color:${color}">${count}</div>
      <div class="stat-label">${escapeHtml(label)}</div>
    </button>`;
  }
  html += `<div class="stat-item telemetry" style="border-left-color:var(--accent)">
    <div class="stat-value" style="color:var(--accent)">${confirmed}</div>
    <div class="stat-label">Confirmed</div>
  </div>`;
  html += `<div class="stat-item telemetry" style="border-left-color:var(--purple)">
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
      const attrs = graph.getNodeAttributes(nodeId) || {};
      const props = attrs._props || {};
      const label = window.OverwatchNodeDisplay.getNodeDisplayLabel(props, nodeId) || attrs.label;
      if (label) return label;
      if (props.ip) return props.ip;
      return nodeId;
    }
  }

  if (frontierItem.node_id) return frontierItem.node_id;

  const quotedMatch = /"([^"]+)"/.exec(frontierItem.description || '');
  if (quotedMatch?.[1]) return quotedMatch[1];

  if (frontierItem.edge_source && frontierItem.edge_target) {
    return `${frontierItem.edge_source} -> ${frontierItem.edge_target}`;
  }

  if (frontierItem.description) return frontierItem.description;
  return frontierItem.id;
}

function renderFrontierChips(frontierItem) {
  const chips = [];
  if (frontierItem.missing_properties?.length) {
    chips.push(...frontierItem.missing_properties.map(prop => `<span class="fi-chip fi-chip-warning">${escapeHtml(prop)}</span>`));
  }
  if (frontierItem.edge_type) {
    chips.push(`<span class="fi-chip fi-chip-edge">${escapeHtml(frontierItem.edge_type)}</span>`);
  }
  const degree = getFrontierMetric(frontierItem, 'node_degree', null);
  if (degree !== null) chips.push(`<span class="fi-chip fi-chip-neutral">deg ${degree}</span>`);
  return chips.join('');
}

function getFrontierSectionLabel(type) {
  switch (type) {
    case 'incomplete_node': return 'Incomplete Nodes';
    case 'untested_edge': return 'Untested Edges';
    case 'inferred_edge': return 'Inferred Opportunities';
    default: return type;
  }
}

function getFrontierSectionItems(frontier) {
  const topPriority = frontier.slice(0, FRONTIER_SECTION_PRIORITY_LIMIT);
  const topIds = new Set(topPriority.map((item) => item.id));
  return [
    { key: 'priority', title: 'Top Priority', items: topPriority, total: frontier.length === 0 ? 0 : topPriority.length },
    ...['incomplete_node', 'untested_edge', 'inferred_edge'].map((type) => {
      const items = frontier.filter((item) => item.type === type && !topIds.has(item.id));
      return {
        key: type,
        title: getFrontierSectionLabel(type),
        items,
        total: frontier.filter((item) => item.type === type).length,
      };
    }),
  ].filter((section) => section.total > 0);
}

function renderFrontierItem(f, idx) {
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
  const support = f.description && f.description !== label ? escapeHtml(f.description) : '';

  return `<div class="frontier-item" data-idx="${idx}" data-node-ids="${escapeHtml(nodeIds)}" onclick="handleFrontierExpand(this, event)">
    <div class="fi-header">
      <span class="fi-type ${typeClass}">${typeLabel}</span>
      <span class="fi-desc" title="${escapeHtml(f.description || '')}">${escapeHtml(label)}</span>
    </div>
    <div class="frontier-item-chips">${chips}</div>
    ${support ? `<div class="fi-support">${support}</div>` : ''}
    <div class="fi-footer">
      <div class="frontier-item-detail">
        <span class="fi-noise" aria-hidden="true"><span class="fi-noise-fill" style="width:${noisePercent}%;background:${noiseColor}"></span></span>
        <span class="fi-metric"><span class="fi-metric-label">noise</span> <span class="fi-metric-value">${noise.toFixed(1)}</span></span>
        <span class="fi-metric"><span class="fi-metric-label">hops</span> <span class="fi-metric-value">${hops}</span></span>
        <span class="fi-metric"><span class="fi-metric-label">fan</span> <span class="fi-metric-value">${fanOut}</span></span>
        <span class="fi-metric"><span class="fi-metric-label">conf</span> <span class="fi-metric-value">${confidence}</span></span>
      </div>
      <div class="fi-actions">
        <button class="fi-zoom-btn" onclick="handleFrontierZoom(this, event)">Zoom</button>
        <button class="fi-zoom-btn fi-focus-btn" onclick="handleFrontierFocus(this, event)">Focus</button>
      </div>
    </div>
  </div>`;
}

function renderFrontierSection(section, offset = 0) {
  const sectionState = frontierSectionState[section.key] || { collapsed: false, expanded: false };
  const limit = section.key === 'priority' ? FRONTIER_SECTION_PRIORITY_LIMIT : FRONTIER_SECTION_DEFAULT_LIMIT;
  const visibleItems = sectionState.expanded ? section.items : section.items.slice(0, limit);
  const hasMore = section.items.length > limit;

  return `<div class="frontier-section ${sectionState.collapsed ? 'collapsed' : ''}" data-section="${section.key}">
    <button class="frontier-section-header" type="button" onclick="toggleFrontierSection('${section.key}', event)">
      <span class="frontier-section-title">${escapeHtml(section.title)}</span>
      <span class="frontier-section-count">${section.total}</span>
    </button>
    <div class="frontier-section-body">
      ${visibleItems.map((item, idx) => renderFrontierItem(item, offset + idx)).join('')}
      ${hasMore ? `<button class="frontier-section-more" type="button" onclick="toggleFrontierSectionExpanded('${section.key}', event)">${sectionState.expanded ? 'Show Less' : `Show ${section.items.length - visibleItems.length} More`}</button>` : ''}
    </div>
  </div>`;
}

function matchesFrontierTypeFilter(item, graph) {
  if (!frontierTypeFilter) return true;
  if (item.type === 'incomplete_node' && item.node_id) {
    if (graph?.hasNode(item.node_id)) {
      return graph.getNodeAttribute(item.node_id, 'nodeType') === frontierTypeFilter;
    }
  }
  const targets = [item.edge_source, item.edge_target].filter(Boolean);
  for (const nodeId of targets) {
    if (graph?.hasNode(nodeId) && graph.getNodeAttribute(nodeId, 'nodeType') === frontierTypeFilter) {
      return true;
    }
  }
  return false;
}

function renderFrontierFilterBadge() {
  if (!frontierTypeFilter) return '';
  const colors = G().NODE_COLORS;
  const color = colors[frontierTypeFilter] || '#888';
  return `<div class="frontier-filter-badge" style="border-color:${color}">
    <span>Showing: <strong>${frontierTypeFilter}s</strong></span>
    <button onclick="clearFrontierTypeFilter()" title="Clear filter">&times;</button>
  </div>`;
}

function updateFrontier(state) {
  const list = document.getElementById('frontier-list');
  const allFrontier = state.frontier || [];
  const graph = G().graph;
  let filtered = frontierTypeFilter
    ? allFrontier.filter((item) => matchesFrontierTypeFilter(item, graph))
    : null;
  // Fall back to full frontier when type filter matches nothing
  const filterEmpty = frontierTypeFilter && filtered && filtered.length === 0 && allFrontier.length > 0;
  const frontier = filterEmpty ? allFrontier : (filtered || allFrontier);
  const countLabel = frontierTypeFilter && !filterEmpty
    ? `(${filtered.length}/${allFrontier.length})`
    : `(${allFrontier.length})`;
  document.getElementById('frontier-count').textContent = countLabel;

  const currentSectionTotals = {
    priority: Math.min(frontier.length, FRONTIER_SECTION_PRIORITY_LIMIT),
    incomplete_node: frontier.filter((item) => item.type === 'incomplete_node').length,
    untested_edge: frontier.filter((item) => item.type === 'untested_edge').length,
    inferred_edge: frontier.filter((item) => item.type === 'inferred_edge').length,
  };
  Object.entries(frontierSectionState).forEach(([key, sectionState]) => {
    if ((currentSectionTotals[key] || 0) === 0) {
      sectionState.expanded = false;
    }
  });

  const badgeHtml = renderFrontierFilterBadge();
  const fallbackNote = filterEmpty
    ? `<div class="frontier-filter-fallback">No frontier items target <strong>${escapeHtml(frontierTypeFilter)}s</strong> directly — showing all</div>`
    : '';

  if (frontier.length === 0) {
    list.innerHTML = badgeHtml + `<div class="empty-state">Frontier empty — ingest data to generate candidates</div>`;
    return;
  }
  const sections = getFrontierSectionItems(frontier);
  let offset = 0;
  list.innerHTML = badgeHtml + fallbackNote + sections.map((section) => {
    const html = renderFrontierSection(section, offset);
    offset += section.items.length;
    return html;
  }).join('');
}

function handleFrontierExpand(el, event) {
  // Don't navigate if clicking the action buttons
  if (event.target.closest('.fi-zoom-btn')) return;
  handleFrontierZoom(el, event);
}

function handleFrontierZoom(btn, event) {
  event.stopPropagation();
  const item = btn.closest ? btn.closest('.frontier-item') : btn;
  if (!item) return;
  const nodeIds = (item.dataset.nodeIds || '').split(',').filter(Boolean);
  if (nodeIds.length === 0) return;

  const g = G();
  const graph = g.graph;
  for (const nodeId of nodeIds) {
    if (graph && graph.hasNode(nodeId)) {
      navigateToNode(nodeId, { hops: 1 });
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
      navigateToNode(nodeId, { hops: 1, persistent: true });
      return;
    }
  }
}

function toggleFrontierSection(sectionKey, event) {
  event?.stopPropagation?.();
  const sectionState = frontierSectionState[sectionKey];
  if (!sectionState) return;
  sectionState.collapsed = !sectionState.collapsed;
  if (lastState) updateFrontier(lastState);
}

function toggleFrontierSectionExpanded(sectionKey, event) {
  event?.stopPropagation?.();
  const sectionState = frontierSectionState[sectionKey];
  if (!sectionState) return;
  sectionState.expanded = !sectionState.expanded;
  if (lastState) updateFrontier(lastState);
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

  document.getElementById('detail-title').textContent = window.OverwatchNodeDisplay.getNodeDisplayLabel(props, nodeId);
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

  // Properties — split into identity and metadata groups
  const identityRows = [];
  const metadataRows = [];
  const identityEntries = window.OverwatchNodeDisplay.getNodeIdentityEntries(props, nodeId);
  const identityKeys = new Set(identityEntries.map((entry) => entry.key));

  for (const { key, value: val } of identityEntries) {
    const display = formatPropValue(key, val);
    if (display === null) continue;
    const raw = typeof val === 'object' ? JSON.stringify(val) : String(val);
    const valClass = TIMESTAMP_PROPS.has(key) ? ' prop-val-ts' : ' prop-val-highlight';
    const row = `<div class="prop-row">
      <span class="prop-key">${escapeHtml(key)}</span>
      <span class="prop-val${valClass}" title="${escapeHtml(raw)}">${escapeHtml(display)}</span>
    </div>`;
    identityRows.push(row);
  }

  for (const [key, val] of Object.entries(props)) {
    if (key === 'label' || key === 'type' || identityKeys.has(key)) continue;
    const display = formatPropValue(key, val);
    if (display === null) continue;
    const raw = typeof val === 'object' ? JSON.stringify(val) : String(val);
    const valClass = TIMESTAMP_PROPS.has(key) ? ' prop-val-ts' : '';
    metadataRows.push(`<div class="prop-row">
      <span class="prop-key">${escapeHtml(key)}</span>
      <span class="prop-val${valClass}" title="${escapeHtml(raw)}">${escapeHtml(display)}</span>
    </div>`);
  }

  // Fan-out badge for credential nodes
  const potentialAuthCount = (nodeType === 'credential')
    ? outEdges.filter(eid => graph.getEdgeAttributes(eid).edgeType === 'POTENTIAL_AUTH').length
    : 0;

  let html = '';

  // 1. Identity / core properties — right under the header
  if (identityRows.length) {
    html += `<div class="detail-section">
      <div class="detail-section-title">Identity</div>
      ${identityRows.join('')}
    </div>`;
  }

  // Fan-out indicator for credentials
  if (potentialAuthCount > 0) {
    html += `<div class="detail-fanout-badge">${potentialAuthCount} potential auth target${potentialAuthCount !== 1 ? 's' : ''}</div>`;
  }

  // 2. Services (host nodes only)
  html += buildServiceSummary(nodeId, graph);

  // 3. Grouped connections
  html += buildConnectionSection(nodeId, graph, 'out');
  html += buildConnectionSection(nodeId, graph, 'in');

  // 4. Metadata — at the bottom
  if (metadataRows.length) {
    html += `<div class="detail-section">
      <div class="detail-section-title">Metadata</div>
      ${metadataRows.join('')}
    </div>`;
  }

  document.getElementById('detail-props').innerHTML = html;
  attachConnectionHandlers();
  attachPropExpandHandlers();
  drawer.classList.add('visible');
}

function hideDetail() {
  document.getElementById('node-detail').classList.remove('visible');
}

function handleGraphSummaryCardClick(nodeType) {
  const g = G();
  if (!nodeType || typeof g.focusNodeType !== 'function') return;
  g.focusNodeType(nodeType);
  setFrontierTypeFilter(nodeType);
}

function setFrontierTypeFilter(nodeType) {
  frontierTypeFilter = nodeType || null;
  if (lastState) updateFrontier(lastState);
  if (frontierTypeFilter) {
    const frontierBody = document.getElementById('frontier-body');
    if (frontierBody?.classList.contains('collapsed')) {
      const header = document.querySelector('[data-panel="frontier-body"]');
      if (header) header.click();
    }
    const panel = document.querySelector('[data-panel="frontier-body"]');
    if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function clearFrontierTypeFilter() {
  frontierTypeFilter = null;
  if (lastState) updateFrontier(lastState);
}

function navigateToNode(nodeId, options = {}) {
  const g = G();
  if (!g.graph || !g.graph.hasNode(nodeId)) return;
  const edgeIds = Array.isArray(options.edgeIds) ? options.edgeIds : [];
  g.focusNodeContext(nodeId, {
    hops: options.hops || 1,
    persistent: options.persistent === true,
    edgeIds,
  });
  showNodeDetail(nodeId);
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
        target: window.OverwatchNodeDisplay.getNodeDisplayLabel(props, entry.targetId),
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

const CONNECTION_GROUP_CAP = 3;

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
      counterpartLabel: window.OverwatchNodeDisplay.getNodeDisplayLabel(counterpartProps, counterpartId),
      counterpartType: counterpartAttrs?.nodeType || counterpartProps.type || '?',
      meta: confidence === '1.0' ? 'confirmed' : `conf ${confidence}`,
    };
  }).sort((a, b) => a.edgeType.localeCompare(b.edgeType) || a.counterpartLabel.localeCompare(b.counterpartLabel));

  if (rows.length === 0) return '';

  // Group by edge type
  const groups = new Map();
  for (const row of rows) {
    if (!groups.has(row.edgeType)) groups.set(row.edgeType, []);
    groups.get(row.edgeType).push(row);
  }

  const title = direction === 'out' ? `Outgoing (${rows.length})` : `Incoming (${rows.length})`;
  const dirLabel = direction.toUpperCase();
  const sectionId = `conn-${direction}-${nodeId}`;

  let groupsHtml = '';
  for (const [edgeType, groupRows] of groups) {
    const groupId = `${sectionId}-${edgeType}`;
    const capped = groupRows.length > CONNECTION_GROUP_CAP;
    const visible = capped ? groupRows.slice(0, CONNECTION_GROUP_CAP) : groupRows;
    const hidden = capped ? groupRows.slice(CONNECTION_GROUP_CAP) : [];

    groupsHtml += `<div class="connection-group" data-group-id="${escapeHtml(groupId)}">
      <div class="connection-group-header">
        <span class="connection-type">${escapeHtml(edgeType)}</span>
        <span class="connection-group-count">${groupRows.length}</span>
      </div>
      <div class="connection-group-body">
        ${visible.map(row => renderConnectionRow(row, dirLabel)).join('')}
        ${hidden.length > 0 ? `<div class="connection-group-hidden" style="display:none">
          ${hidden.map(row => renderConnectionRow(row, dirLabel)).join('')}
        </div>
        <button class="connection-group-more" type="button" onclick="toggleConnectionGroup(this, event)">Show ${hidden.length} more</button>` : ''}
      </div>
    </div>`;
  }

  return `<div class="detail-section">
    <div class="detail-section-title">${title}</div>
    <div class="connection-list">${groupsHtml}</div>
  </div>`;
}

function renderConnectionRow(row, dirLabel) {
  return `<div class="connection-row" data-node-id="${escapeHtml(row.counterpartId)}" data-edge-id="${escapeHtml(row.edgeId)}">
    <span class="connection-direction">${dirLabel}</span>
    <span class="connection-target-wrap">
      <span class="connection-target">${escapeHtml(row.counterpartLabel)}</span>
      <span class="connection-node-type">${escapeHtml(row.counterpartType)}</span>
    </span>
    <span class="connection-meta">${escapeHtml(row.meta)}</span>
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
      body.querySelectorAll('.connection-row.active').forEach((activeRow) => activeRow.classList.remove('active'));
      row.classList.add('active');
      g.highlightEdges([edgeId]);
      navigateToNode(nodeId, { edgeIds: [edgeId], hops: 1, persistent: g.graphMode === 'focused' });
    });
  });
}

function attachPropExpandHandlers() {
  const body = document.getElementById('detail-props');
  if (!body) return;
  body.querySelectorAll('.prop-val').forEach((el) => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      el.classList.toggle('expanded');
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

    // Map click position to display coordinates (sigma's camera space)
    const rect = canvas.getBoundingClientRect();
    const clickX = (e.clientX - rect.left) / rect.width;
    const clickY = (e.clientY - rect.top) / rect.height;

    // Get visible node bounds in display space (same coords minimap is drawn with)
    const visibleNodeIds = g.getVisibleNodeIds ? g.getVisibleNodeIds() : [];
    if (visibleNodeIds.length === 0) return;

    let minX = Infinity, maxX = -Infinity;
    let minY = Infinity, maxY = -Infinity;
    visibleNodeIds.forEach((id) => {
      const dd = g.renderer.getNodeDisplayData(id);
      if (!dd || dd.hidden) return;
      minX = Math.min(minX, dd.x);
      maxX = Math.max(maxX, dd.x);
      minY = Math.min(minY, dd.y);
      maxY = Math.max(maxY, dd.y);
    });

    if (minX === Infinity) return;

    // Account for minimap padding (matches updateMinimap: pad=10, retina 2x)
    const cw = canvas.clientWidth * 2;
    const ch = canvas.clientHeight * 2;
    const pad = 10;
    const dx = maxX - minX || 1;
    const dy = maxY - minY || 1;
    const scale = Math.min((cw - 2 * pad) / dx, (ch - 2 * pad) / dy);
    const ox = pad + ((cw - 2 * pad) - dx * scale) / 2;
    const oy = pad + ((ch - 2 * pad) - dy * scale) / 2;

    // Convert click pixel (in retina canvas coords) to display coords
    const canvasX = clickX * cw;
    const canvasY = clickY * ch;
    const displayX = minX + (canvasX - ox) / scale;
    const displayY = minY + (canvasY - oy) / scale;

    g.renderer.getCamera().animate(
      { x: displayX, y: displayY },
      { duration: 300 }
    );
  });
}

// ============================================================
// Utilities
// ============================================================

const TIMESTAMP_PROPS = new Set([
  'discovered_at', 'first_seen_at', 'last_seen_at', 'confirmed_at',
]);

function formatPropValue(key, val) {
  if (val === undefined || val === null) return null;
  if (Array.isArray(val)) return val.join(', ');
  const str = typeof val === 'object' ? JSON.stringify(val) : String(val);
  if (TIMESTAMP_PROPS.has(key) && /^\d{4}-\d{2}-\d{2}T/.test(str)) {
    try {
      const d = new Date(str);
      const mon = d.toLocaleString('en', { month: 'short' });
      const day = d.getDate();
      const h = String(d.getHours()).padStart(2, '0');
      const m = String(d.getMinutes()).padStart(2, '0');
      return `${mon} ${day} · ${h}:${m}`;
    } catch { return str; }
  }
  return str;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function toggleConnectionGroup(btn, event) {
  event?.stopPropagation?.();
  const group = btn.closest('.connection-group');
  if (!group) return;
  const hidden = group.querySelector('.connection-group-hidden');
  if (!hidden) return;
  const isShown = hidden.style.display !== 'none';
  hidden.style.display = isShown ? 'none' : '';
  const totalInHidden = hidden.querySelectorAll('.connection-row').length;
  btn.textContent = isShown ? `Show ${totalInHidden} more` : 'Show less';
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
  handleGraphSummaryCardClick,
  toggleFrontierSection,
  toggleFrontierSectionExpanded,
  toggleShortcutsOverlay,
  setShortcutsOverlayVisible,
  setFrontierTypeFilter,
  clearFrontierTypeFilter,
};

// Global functions referenced in HTML onclick
window.showNodeDetail = showNodeDetail;
window.hideDetail = hideDetail;
window.navigateToNode = navigateToNode;
window.handleFrontierClick = handleFrontierClick;
window.handleFrontierExpand = handleFrontierExpand;
window.handleFrontierZoom = handleFrontierZoom;
window.handleFrontierFocus = handleFrontierFocus;
window.handleGraphSummaryCardClick = handleGraphSummaryCardClick;
window.toggleFrontierSection = toggleFrontierSection;
window.toggleFrontierSectionExpanded = toggleFrontierSectionExpanded;
window.clearFrontierTypeFilter = clearFrontierTypeFilter;
window.setFrontierTypeFilter = setFrontierTypeFilter;
window.toggleConnectionGroup = toggleConnectionGroup;
