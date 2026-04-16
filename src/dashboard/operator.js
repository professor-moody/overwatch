// ============================================================
// Overwatch Operator Dashboard — Page Boot Script
// Nav switching, state rendering, WebSocket integration
// ============================================================

window.addEventListener('DOMContentLoaded', () => {
  const WS = window.OverwatchWS;
  const esc = window.OverwatchShared?.escapeHtml || function(s) { return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); };

  if (!WS) {
    const badge = document.getElementById('ws-status');
    if (badge) {
      badge.className = 'status-badge boot-failed';
      badge.innerHTML = '<span class="status-dot"></span><span>Boot failed</span>';
    }
    console.error('[Overwatch Operator] Boot failed — missing OverwatchWS');
    return;
  }

  // ============================================================
  // Nav Panel Switching
  // ============================================================

  let activePanel = 'overview';
  const nav = document.getElementById('op-nav');
  const PANEL_ORDER = ['overview', 'campaigns', 'agents', 'sessions', 'actions', 'frontier', 'activity', 'evidence', 'settings'];

  function switchToPanel(panel) {
    if (!panel || panel === activePanel) return;
    nav.querySelector('.op-nav-item.active')?.classList.remove('active');
    document.getElementById('panel-' + activePanel)?.classList.remove('active');
    const btn = nav.querySelector(`.op-nav-item[data-panel="${panel}"]`);
    if (btn) btn.classList.add('active');
    document.getElementById('panel-' + panel)?.classList.add('active');
    activePanel = panel;
  }

  nav.addEventListener('click', (e) => {
    const btn = e.target.closest('.op-nav-item');
    if (!btn) return;
    switchToPanel(btn.dataset.panel);
  });

  // ============================================================
  // Keyboard Shortcuts
  // ============================================================

  let shortcutHelpOpen = false;

  document.addEventListener('keydown', (e) => {
    // Ignore when typing in inputs
    const tag = e.target.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || e.target.isContentEditable) return;

    // ? — toggle shortcut help
    if (e.key === '?' || (e.shiftKey && e.key === '/')) {
      e.preventDefault();
      toggleShortcutHelp();
      return;
    }

    // Escape — close overlays
    if (e.key === 'Escape') {
      if (shortcutHelpOpen) { toggleShortcutHelp(); return; }
      return;
    }

    // 1-8 — switch panels
    const num = parseInt(e.key);
    if (num >= 1 && num <= PANEL_ORDER.length && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      switchToPanel(PANEL_ORDER[num - 1]);
      return;
    }

    // n — new campaign (when on campaigns panel)
    if (e.key === 'n' && activePanel === 'campaigns') {
      e.preventDefault();
      document.getElementById('new-campaign-btn')?.click();
      return;
    }

    // a — approve selected action (when on actions panel)
    if (e.key === 'a' && activePanel === 'actions') {
      e.preventDefault();
      document.querySelector('.pa-btn-approve')?.click();
      return;
    }

    // d — deny selected action (when on actions panel)
    if (e.key === 'd' && activePanel === 'actions') {
      e.preventDefault();
      document.querySelector('.pa-btn-deny')?.click();
      return;
    }

    // g — open graph explorer
    if (e.key === 'g' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      window.open('/graph', '_blank');
      return;
    }
  });

  function toggleShortcutHelp() {
    let overlay = document.getElementById('shortcut-help-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'shortcut-help-overlay';
      overlay.className = 'shortcut-overlay';
      overlay.innerHTML = `<div class="shortcut-modal">
        <h3 class="shortcut-title">Keyboard Shortcuts</h3>
        <div class="shortcut-grid">
          <div class="shortcut-row"><kbd>1</kbd>–<kbd>9</kbd><span>Switch panels</span></div>
          <div class="shortcut-row"><kbd>n</kbd><span>New campaign (Campaigns panel)</span></div>
          <div class="shortcut-row"><kbd>a</kbd><span>Approve action (Actions panel)</span></div>
          <div class="shortcut-row"><kbd>d</kbd><span>Deny action (Actions panel)</span></div>
          <div class="shortcut-row"><kbd>g</kbd><span>Open Graph Explorer</span></div>
          <div class="shortcut-row"><kbd>?</kbd><span>Toggle this help</span></div>
          <div class="shortcut-row"><kbd>Esc</kbd><span>Close overlay</span></div>
        </div>
        <button class="op-btn op-btn-sm shortcut-close" id="shortcut-close">Close</button>
      </div>`;
      document.body.appendChild(overlay);
      overlay.addEventListener('click', (e) => { if (e.target === overlay) toggleShortcutHelp(); });
      overlay.querySelector('#shortcut-close').addEventListener('click', toggleShortcutHelp);
    }

    shortcutHelpOpen = !shortcutHelpOpen;
    overlay.style.display = shortcutHelpOpen ? 'flex' : 'none';
  }

  // ============================================================
  // Initialize optional panel modules
  // ============================================================

  const TM = window.OverwatchTerminal;
  if (TM) TM.init();

  const AP = window.OverwatchAgentPanel;
  if (AP) AP.init();

  const CP = window.OverwatchCampaigns;
  if (CP) CP.init();

  const PA = window.OverwatchPendingActions;
  if (PA) PA.init();

  const EV = window.OverwatchEvidence;
  if (EV) EV.init();

  // ============================================================
  // State tracking
  // ============================================================

  let lastState = null;

  // ============================================================
  // Connect WebSocket
  // ============================================================

  WS.connect({
    onInitialState(data) {
      lastState = data.state;
      updateOperatorUI(data.state);
      if (EV) EV.updateFromState(data.state);
    },
    onStateRefresh(data) {
      lastState = data.state;
      updateOperatorUI(data.state);
      if (AP) AP.updateFromState(data.state);
      if (CP) CP.updateFromState();
      if (EV) EV.updateFromState(data.state);
    },
    onGraphUpdate(data) {
      lastState = data.state;
      updateOperatorUI(data.state);
      if (AP) AP.updateFromState(data.state);
      if (CP) CP.updateFromState();
      if (EV) EV.updateFromState(data.state);
    },
  });

  // ============================================================
  // UI Update — render all panels from state
  // ============================================================

  function updateOperatorUI(state) {
    if (!state) return;
    updateHeader(state);
    updateSummaryCards(state);
    updateReadiness(state);
    updatePhaseTimeline(state);
    updateObjectives(state);
    updateGraphSummary(state);
    updateFrontier(state);
    updateActivity(state);
    updateOverviewActivity(state);
  }

  // ---- Header + toolbar stats ----

  function updateHeader(state) {
    const el = document.getElementById('engagement-name');
    if (el) el.textContent = state.engagement?.name || state.config?.name || '—';
    const nodes = document.getElementById('stat-nodes');
    if (nodes) nodes.textContent = state.graph_summary?.total_nodes || 0;
    const edges = document.getElementById('stat-edges');
    if (edges) edges.textContent = state.graph_summary?.total_edges || 0;
    const access = document.getElementById('stat-access');
    if (access) access.textContent = state.access_summary?.current_access_level || 'none';
  }

  // ---- Summary Cards ----

  function updateSummaryCards(state) {
    const el = (id) => document.getElementById(id);
    const gs = state.graph_summary || {};
    const objectives = state.objectives || [];
    const achieved = objectives.filter(o => o.achieved).length;

    if (el('card-nodes')) el('card-nodes').textContent = gs.total_nodes || 0;
    if (el('card-edges')) el('card-edges').textContent = gs.total_edges || 0;
    if (el('card-objectives')) el('card-objectives').textContent = `${achieved}/${objectives.length}`;
    if (el('card-access')) el('card-access').textContent = state.access_summary?.current_access_level || 'none';
    if (el('card-agents')) el('card-agents').textContent = (state.active_agents || []).length;
    if (el('card-campaigns')) el('card-campaigns').textContent = (state.campaigns || []).length;
  }

  // ---- Lab Readiness ----

  function updateReadiness(state) {
    const badge = document.getElementById('readiness-status');
    const issuesEl = document.getElementById('readiness-issues');
    if (!badge || !issuesEl) return;

    const readiness = state.lab_readiness || { status: 'ready', top_issues: [] };
    const healthWarnings = state.warnings || {};

    let effectiveStatus = readiness.status || 'ready';
    if (effectiveStatus === 'ready' && healthWarnings.status && healthWarnings.status !== 'healthy') {
      effectiveStatus = healthWarnings.status === 'critical' ? 'blocked' : 'warning';
    }

    badge.className = `readiness-badge ${effectiveStatus}`;
    badge.textContent = effectiveStatus.toUpperCase();

    const allIssues = [...(readiness.top_issues || [])];
    const healthTopIssues = healthWarnings.top_issues || [];
    for (const hi of healthTopIssues) {
      const msg = hi.message || (typeof hi === 'string' ? hi : '');
      if (msg && !allIssues.some(existing => existing.includes(msg))) allIssues.push(msg);
    }

    if (allIssues.length === 0) {
      issuesEl.innerHTML = '<div class="empty-state">No issues detected</div>';
      return;
    }
    issuesEl.innerHTML = allIssues.slice(0, 5).map(issue =>
      `<div class="readiness-issue">${esc(typeof issue === 'string' ? issue : issue.message || JSON.stringify(issue))}</div>`
    ).join('');
  }

  // ---- Phase Timeline ----

  function updatePhaseTimeline(state) {
    const container = document.getElementById('phase-timeline');
    if (!container) return;
    const phases = state.phases || [];
    const currentPhase = state.current_phase;

    if (phases.length === 0) {
      container.innerHTML = '';
      container.closest('.op-section')?.classList.add('hidden');
      return;
    }
    container.closest('.op-section')?.classList.remove('hidden');

    const sorted = [...phases].sort((a, b) => a.order - b.order);
    container.innerHTML = sorted.map(p => {
      const isCurrent = p.id === currentPhase;
      const statusIcon = p.status === 'completed' ? '✓' : (p.status === 'active' ? '●' : '○');
      const statusClass = `phase-${p.status}`;
      return `<div class="phase-step ${statusClass}${isCurrent ? ' phase-current' : ''}">
        <div class="phase-icon">${statusIcon}</div>
        <div class="phase-info">
          <div class="phase-name">${esc(p.name)}</div>
          <div class="phase-strategies">${(p.strategies || []).join(', ')}</div>
        </div>
      </div>`;
    }).join('<div class="phase-connector"></div>');
  }

  // ---- Objectives ----

  function updateObjectives(state) {
    const list = document.getElementById('objectives-list');
    if (!list) return;
    const objectives = state.objectives || [];

    if (objectives.length === 0) {
      list.innerHTML = '<div class="empty-state">No objectives defined</div>';
      return;
    }
    list.innerHTML = objectives.map(o => `
      <div class="objective-card ${o.achieved ? 'achieved' : 'pending'}">
        <div class="obj-name">${esc(o.description)}</div>
        <div class="obj-status">${o.achieved ? '✓ Achieved' : '○ In progress'}</div>
      </div>
    `).join('');
  }

  // ---- Graph Summary (node type breakdown) ----

  function updateGraphSummary(state) {
    const grid = document.getElementById('stat-grid');
    if (!grid) return;

    const nodesByType = state.graph_summary?.nodes_by_type || {};
    const confirmed = state.graph_summary?.confirmed_edges || 0;
    const inferred = state.graph_summary?.inferred_edges || 0;
    const ND = window.OverwatchNodeDisplay;

    // Use NODE_COLORS from node-display if available, otherwise fallback
    const defaultColors = { host: '#5b8def', domain: '#a78bfa', credential: '#eab308', service: '#3ecf8e', user: '#f472b6', group: '#ef4444' };

    let html = '';
    const types = Object.entries(nodesByType).sort((a, b) => b[1] - a[1]);
    for (const [type, count] of types) {
      const color = defaultColors[type] || '#888';
      const label = ND ? ND.getFriendlyNodeTypeLabel(type) : type;
      html += `<a href="/graph?filter=${encodeURIComponent(type)}" class="stat-item clickable" style="border-left-color:${esc(color)}">
        <div class="stat-value" style="color:${esc(color)}">${count}</div>
        <div class="stat-label">${esc(label)}</div>
      </a>`;
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

  // ---- Frontier ----

  function updateFrontier(state) {
    const list = document.getElementById('frontier-list');
    const countEl = document.getElementById('frontier-count');
    if (!list) return;

    const frontier = state.frontier || [];
    if (countEl) countEl.textContent = `(${frontier.length})`;

    if (frontier.length === 0) {
      list.innerHTML = '<div class="empty-state">Frontier empty — ingest data to generate candidates</div>';
      return;
    }

    // Group by type
    const groups = { incomplete_node: [], untested_edge: [], inferred_edge: [] };
    frontier.forEach(f => {
      const bucket = groups[f.type] || groups.inferred_edge;
      bucket.push(f);
    });

    const topPriority = frontier.slice(0, 6);

    let html = '<div class="op-frontier-section"><div class="op-frontier-section-title">Top Priority</div>';
    html += topPriority.map(f => renderFrontierItem(f)).join('');
    html += '</div>';

    const sectionLabels = { incomplete_node: 'Incomplete Nodes', untested_edge: 'Untested Edges', inferred_edge: 'Inferred Opportunities' };
    for (const [type, items] of Object.entries(groups)) {
      if (items.length === 0) continue;
      html += `<div class="op-frontier-section">
        <div class="op-frontier-section-title">${sectionLabels[type]} <span class="count">(${items.length})</span></div>
        ${items.slice(0, 10).map(f => renderFrontierItem(f)).join('')}
        ${items.length > 10 ? `<div class="op-frontier-more">${items.length - 10} more items</div>` : ''}
      </div>`;
    }

    list.innerHTML = html;

    // Wire frontier deploy buttons
    list.querySelectorAll('.fi-deploy-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const nodeId = btn.dataset.nodeId;
        const frontierId = btn.dataset.frontierId;
        if (nodeId && window.OverwatchAgentPanel?.openDispatchModal) {
          window.OverwatchAgentPanel.openDispatchModal([nodeId], frontierId);
        }
      });
    });
  }

  function renderFrontierItem(f) {
    const typeClass = f.type === 'incomplete_node' ? 'incomplete' : f.type === 'untested_edge' ? 'untested' : 'inferred';
    const typeLabel = f.type === 'incomplete_node' ? 'node' : f.type === 'untested_edge' ? 'test' : 'infer';
    const noise = f.opsec_noise !== undefined ? f.opsec_noise : 0;
    const noisePercent = Math.round(noise * 100);
    const noiseColor = noise <= 0.3 ? 'var(--green)' : noise <= 0.6 ? 'var(--amber)' : 'var(--red)';
    const label = f.description || f.node_id || f.id;
    const nodeId = f.node_id || f.edge_target || '';

    // Enrichment: chain info
    const chainInfo = f.chain_id
      ? `<span class="fi-chain" title="Chain: ${esc(f.chain_id)}${f.chain_depth ? ', depth ' + f.chain_depth : ''}">🔗${f.chain_completion != null ? ` ${Math.round(f.chain_completion * 100)}%` : ''}</span>`
      : '';

    // Enrichment: hops to objective
    const hops = f.hops_to_objective != null ? f.hops_to_objective : (f.graph_metrics?.hops_to_objective ?? null);
    const hopsHtml = hops != null
      ? `<span class="fi-hops fi-hops-${hops <= 2 ? 'close' : hops <= 4 ? 'mid' : 'far'}" title="${hops} hop${hops !== 1 ? 's' : ''} to objective">${hops}h</span>`
      : '';

    // Enrichment: campaign assignment
    const camp = f.campaign_name || f.assigned_campaign;
    const campHtml = camp
      ? `<span class="fi-campaign-tag" title="Assigned to campaign: ${esc(String(camp))}">${esc(String(camp))}</span>`
      : '';

    // Fan-out tooltip
    const fanOut = f.fan_out || f.graph_metrics?.fan_out;
    const fanTitle = fanOut ? `Fan-out: ${fanOut}` : '';

    return `<div class="frontier-item" ${fanTitle ? `title="${fanTitle}"` : ''}>
      <div class="fi-header">
        <span class="fi-type ${typeClass}">${typeLabel}</span>
        <span class="fi-desc" title="${esc(f.description || '')}">${esc(label)}</span>
        ${hopsHtml}
        ${chainInfo}
        ${campHtml}
        ${nodeId ? `<a href="/graph?focus=${encodeURIComponent(nodeId)}" class="fi-graph-link" title="View in Graph">⊙</a>` : ''}
        ${nodeId ? `<button class="fi-deploy-btn" data-node-id="${esc(nodeId)}" data-frontier-id="${esc(f.id)}" title="Deploy Agent">▶</button>` : ''}
      </div>
      <div class="fi-footer">
        <div class="frontier-item-detail">
          <span class="fi-noise"><span class="fi-noise-fill" style="width:${noisePercent}%;background:${noiseColor}"></span></span>
          <span class="fi-metric"><span class="fi-metric-label">noise</span> <span class="fi-metric-value">${noise.toFixed(1)}</span></span>
        </div>
      </div>
    </div>`;
  }

  // ---- Activity ----

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
    if (!list) return;
    const history = state.recent_activity || [];
    const recent = history.slice(-50).reverse();

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
          <span class="act-msg">${esc(a.description || '')}</span>
        </div>
      </div>`;
    }).join('');
  }

  // Overview panel shows last 10 activity items
  function updateOverviewActivity(state) {
    const list = document.getElementById('overview-activity-list');
    if (!list) return;
    const history = state.recent_activity || [];
    const recent = history.slice(-10).reverse();

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
          <span class="act-msg">${esc(a.description || '')}</span>
        </div>
      </div>`;
    }).join('');
  }
});
