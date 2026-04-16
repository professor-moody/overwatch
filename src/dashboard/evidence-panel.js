// ============================================================
// Overwatch Dashboard — Evidence Chain & Attack Path Panel
// Node evidence timeline, finding cards, and objective path viewer
// with graph ↔ evidence click-through integration
// ============================================================

window.OverwatchEvidence = (() => {
  let cachedObjectives = [];

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function init() {
    document.getElementById('ev-search-btn')?.addEventListener('click', searchEvidence);
    document.getElementById('ev-node-search')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') searchEvidence();
    });
    document.getElementById('ev-path-btn')?.addEventListener('click', searchPaths);
  }

  function destroy() { /* no timers */ }

  // =============================================
  // Cross-panel navigation helpers
  // =============================================

  function navigateToNode(nodeId) {
    const G = window.OverwatchGraph;
    if (G && G.graph && G.graph.hasNode(nodeId)) {
      G.selectAndCenter(nodeId);
      // If on operator dashboard, open graph explorer
      if (window.location.pathname !== '/graph') {
        window.open(`/graph?focus=${encodeURIComponent(nodeId)}`, '_blank');
      }
    }
  }

  function highlightPathInGraph(nodeIds) {
    const G = window.OverwatchGraph;
    if (!G || !G.graph) return;
    G.highlightPath(nodeIds);
  }

  // Public API for graph → evidence navigation
  function showEvidenceForNode(nodeId) {
    const input = document.getElementById('ev-node-search');
    if (input) {
      input.value = nodeId;
      searchEvidence();
    }
  }

  // =============================================
  // Evidence Chain Search
  // =============================================

  async function searchEvidence() {
    const input = document.getElementById('ev-node-search');
    const container = document.getElementById('ev-chain-container');
    if (!input || !container) return;

    const query = input.value.trim();
    if (!query) { container.innerHTML = '<div class="empty-state">Enter a node ID or label to search</div>'; return; }

    container.innerHTML = '<div class="ev-loading">Searching…</div>';

    try {
      const res = await fetch(`/api/evidence-chains/${encodeURIComponent(query)}`);
      if (!res.ok) {
        container.innerHTML = '<div class="empty-state">No evidence found</div>';
        return;
      }
      const data = await res.json();
      renderChain(data, container);
    } catch {
      container.innerHTML = '<div class="empty-state">Error fetching evidence</div>';
    }
  }

  function renderChain(data, container) {
    const { node_id, chains, count, node_props, findings } = data;

    if (!chains || chains.length === 0) {
      container.innerHTML = `<div class="empty-state">No evidence chain entries for <span class="mono">${escapeHtml(node_id)}</span></div>`;
      return;
    }

    // Node info header with properties
    const propsHtml = node_props ? renderNodeProps(node_id, node_props) : '';

    const header = `<div class="ev-chain-header">
      <span class="ev-chain-node mono" data-node-id="${escapeHtml(node_id)}" role="button" tabindex="0">${escapeHtml(node_id)}</span>
      <span class="ev-chain-count">${count} entries</span>
      <button class="op-btn op-btn-sm ev-graph-btn" data-action="show-in-graph" data-node="${escapeHtml(node_id)}" title="Select in Graph">⊙ Graph</button>
    </div>`;

    // Finding cards (from enriched API)
    const findingsHtml = findings && findings.length > 0 ? renderFindings(findings) : '';

    const timeline = chains.map((entry, i) => {
      const ts = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '—';
      const toolBadge = entry.tool
        ? `<span class="ev-tool-badge">${escapeHtml(entry.tool)}</span>`
        : '';
      const actionLink = entry.action_id
        ? `<span class="ev-action-id mono">${escapeHtml(entry.action_id.slice(0, 8))}</span>`
        : '';
      const snippet = entry.snippet
        ? `<div class="ev-entry-snippet">${escapeHtml(entry.snippet)}</div>`
        : '';

      return `<div class="ev-entry">
        <div class="ev-connector">${i < chains.length - 1 ? '<div class="ev-line"></div>' : ''}<div class="ev-dot"></div></div>
        <div class="ev-entry-content">
          <div class="ev-entry-header">
            <span class="ev-entry-ts">${ts}</span>
            ${toolBadge}
            ${actionLink}
          </div>
          ${snippet}
        </div>
      </div>`;
    }).join('');

    container.innerHTML = header + propsHtml + findingsHtml + `<div class="ev-timeline">${timeline}</div>`;

    // Wire up click handlers
    container.querySelectorAll('[data-action="show-in-graph"]').forEach(btn => {
      btn.addEventListener('click', () => navigateToNode(btn.dataset.node));
    });
    container.querySelectorAll('.ev-chain-node[data-node-id]').forEach(el => {
      el.addEventListener('click', () => navigateToNode(el.dataset.nodeId));
    });
  }

  function renderNodeProps(nodeId, props) {
    const items = [];
    if (props.type) items.push(`<span class="ev-prop-tag ev-prop-type">${escapeHtml(props.type)}</span>`);
    if (props.label && props.label !== nodeId) items.push(`<span class="ev-prop-tag">${escapeHtml(props.label)}</span>`);
    if (props.os) items.push(`<span class="ev-prop-tag">${escapeHtml(props.os)}</span>`);
    if (props.confidence != null) items.push(`<span class="ev-prop-tag">conf: ${Math.round(props.confidence * 100)}%</span>`);
    if (props.chain_template) items.push(`<span class="ev-prop-tag ev-prop-chain">🔗 ${escapeHtml(props.chain_template)}</span>`);
    if (items.length === 0) return '';
    return `<div class="ev-node-props">${items.join('')}</div>`;
  }

  function renderFindings(findings) {
    const cards = findings.map(f => {
      const sevClass = f.severity === 'critical' ? 'sev-critical'
        : f.severity === 'high' ? 'sev-high'
        : f.severity === 'medium' ? 'sev-medium' : 'sev-low';
      const sevBadge = f.severity
        ? `<span class="ev-finding-sev ${sevClass}">${escapeHtml(f.severity)}</span>`
        : '';
      const techBadge = f.technique_id
        ? `<span class="ev-finding-tech">${escapeHtml(f.technique_id)}</span>`
        : '';
      const typeLabel = f.finding_type ? escapeHtml(f.finding_type) : 'finding';
      const desc = f.description ? `<div class="ev-finding-desc mono">${escapeHtml(f.description)}</div>` : '';
      return `<div class="ev-finding-card">
        <div class="ev-finding-header">
          <span class="ev-finding-type">${typeLabel}</span>
          ${sevBadge}
          ${techBadge}
        </div>
        ${desc}
      </div>`;
    }).join('');
    return `<div class="ev-findings-section">
      <div class="ev-findings-title">Findings (${findings.length})</div>
      ${cards}
    </div>`;
  }

  // =============================================
  // Attack Path Viewer
  // =============================================

  function updateFromState(state) {
    const objectives = state?.objectives || [];
    if (JSON.stringify(objectives) !== JSON.stringify(cachedObjectives)) {
      cachedObjectives = objectives;
      populateObjectiveDropdown(objectives);
    }
  }

  function populateObjectiveDropdown(objectives) {
    const select = document.getElementById('ev-objective-select');
    if (!select) return;

    const current = select.value;
    select.innerHTML = '<option value="">Select objective…</option>' +
      objectives.map(obj => {
        const label = obj.description || obj.id;
        const achieved = obj.achieved ? ' ✓' : '';
        return `<option value="${escapeHtml(obj.id)}">${escapeHtml(label)}${achieved}</option>`;
      }).join('');
    if (current) select.value = current;
  }

  async function searchPaths() {
    const objectiveId = document.getElementById('ev-objective-select')?.value;
    const optimize = document.getElementById('ev-optimize')?.value || 'confidence';
    const container = document.getElementById('ev-path-list');
    if (!container) return;

    if (!objectiveId) {
      container.innerHTML = '<div class="empty-state">Select an objective first</div>';
      return;
    }

    container.innerHTML = '<div class="ev-loading">Finding paths…</div>';

    try {
      const res = await fetch(`/api/paths/${encodeURIComponent(objectiveId)}?optimize=${optimize}&limit=5`);
      if (!res.ok) {
        container.innerHTML = '<div class="empty-state">No paths found</div>';
        return;
      }
      const data = await res.json();
      renderPaths(data, container);
    } catch {
      container.innerHTML = '<div class="empty-state">Error fetching paths</div>';
    }
  }

  function renderPaths(data, container) {
    const { paths } = data;

    if (!paths || paths.length === 0) {
      container.innerHTML = '<div class="empty-state">No attack paths found for this objective</div>';
      return;
    }

    container.innerHTML = paths.map((path, i) => {
      const conf = path.confidence != null ? Math.round(path.confidence * 100) : null;
      const noise = path.opsec_noise != null ? Math.round(path.opsec_noise * 100) : null;
      const nodeIds = (path.nodes || []).map(n => n.id || n);

      const nodeChain = (path.nodes || []).map(n => {
        const label = n.label || n.id || n;
        const nodeId = n.id || n;
        const typeClass = n.type ? `ev-pn-${escapeHtml(n.type)}` : '';
        const edgeLabel = n.edge_type ? `<span class="ev-edge-label">${escapeHtml(n.edge_type)}</span>` : '';
        return `${edgeLabel}<span class="ev-path-node ${typeClass}" data-action="select-node" data-node="${escapeHtml(String(nodeId))}" role="button" tabindex="0" title="${escapeHtml(String(nodeId))}">${escapeHtml(String(label))}</span>`;
      }).join('<span class="ev-path-arrow">→</span>');

      // Confidence + noise bars
      const confBar = conf != null
        ? `<div class="ev-metric-bar"><span class="ev-metric-label">confidence</span><div class="ev-bar"><div class="ev-bar-fill ev-bar-conf" style="width:${conf}%"></div></div><span class="ev-metric-val">${conf}%</span></div>`
        : '';
      const noiseBar = noise != null
        ? `<div class="ev-metric-bar"><span class="ev-metric-label">noise</span><div class="ev-bar"><div class="ev-bar-fill ev-bar-noise" style="width:${noise}%"></div></div><span class="ev-metric-val">${noise}%</span></div>`
        : '';

      return `<div class="ev-path">
        <div class="ev-path-header">
          <span class="ev-path-num">#${i + 1}</span>
          <span class="ev-path-conf">${conf != null ? `${conf}% conf` : ''}</span>
          <button class="op-btn op-btn-sm ev-graph-btn" data-action="highlight-path" data-nodes="${escapeHtml(JSON.stringify(nodeIds))}" title="Highlight in Graph">⊙ Highlight</button>
        </div>
        <div class="ev-path-chain">${nodeChain}</div>
        <div class="ev-path-metrics">${confBar}${noiseBar}</div>
      </div>`;
    }).join('');

    // Wire click handlers
    container.querySelectorAll('[data-action="select-node"]').forEach(el => {
      el.addEventListener('click', () => navigateToNode(el.dataset.node));
    });
    container.querySelectorAll('[data-action="highlight-path"]').forEach(btn => {
      btn.addEventListener('click', () => {
        try {
          const nodeIds = JSON.parse(btn.dataset.nodes);
          highlightPathInGraph(nodeIds);
        } catch { /* ignore */ }
      });
    });
  }

  return { init, destroy, updateFromState, showEvidenceForNode };
})();
