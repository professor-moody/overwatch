// ============================================================
// Overwatch Dashboard — Evidence Chain & Attack Path Panel
// Node evidence timeline and objective path viewer
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
    const { node_id, chains, count } = data;

    if (!chains || chains.length === 0) {
      container.innerHTML = `<div class="empty-state">No evidence chain entries for <span class="mono">${escapeHtml(node_id)}</span></div>`;
      return;
    }

    const header = `<div class="ev-chain-header">
      <span class="ev-chain-node mono">${escapeHtml(node_id)}</span>
      <span class="ev-chain-count">${count} entries</span>
      <a class="fi-graph-link" href="/graph?focus=${encodeURIComponent(node_id)}" target="_blank" title="View in graph">View in Graph ⊞</a>
    </div>`;

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

    container.innerHTML = header + `<div class="ev-timeline">${timeline}</div>`;
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
      const conf = path.confidence != null ? `${Math.round(path.confidence * 100)}%` : '—';
      const nodeChain = (path.nodes || []).map(n => {
        const label = n.label || n.id || n;
        const nodeId = n.id || n;
        return `<span class="ev-path-node" title="${escapeHtml(String(nodeId))}">${escapeHtml(String(label))}</span>`;
      }).join('<span class="ev-path-arrow">→</span>');

      const focusNodes = (path.nodes || []).map(n => n.id || n).join(',');
      const graphLink = `/graph?path=${encodeURIComponent(focusNodes)}`;

      return `<div class="ev-path">
        <div class="ev-path-header">
          <span class="ev-path-num">#${i + 1}</span>
          <span class="ev-path-conf">Confidence: ${conf}</span>
          <a class="fi-graph-link" href="${graphLink}" target="_blank">Highlight in Graph ⊞</a>
        </div>
        <div class="ev-path-chain">${nodeChain}</div>
      </div>`;
    }).join('');
  }

  return { init, destroy, updateFromState };
})();
