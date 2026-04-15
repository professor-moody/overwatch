// ============================================================
// Overwatch Dashboard — Agent Supervision Panel
// Rich agent cards with detail view and cancel support
// ============================================================

window.OverwatchAgentPanel = (() => {
  let pollTimer = null;
  let agents = [];
  let detailTaskId = null;

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function init() {
    fetchAgents();
    pollTimer = setInterval(fetchAgents, 3000);
  }

  function destroy() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  async function fetchAgents() {
    try {
      const res = await fetch('/api/agents');
      if (!res.ok) return;
      const data = await res.json();
      agents = data.agents || [];
      renderAgentList(agents);
      updateCount(agents);
      // Refresh detail if open
      if (detailTaskId) {
        const a = agents.find(x => x.id === detailTaskId);
        if (a) renderAgentDetail(a);
      }
    } catch { /* network error — keep stale data */ }
  }

  function updateCount(list) {
    const el = document.getElementById('agent-count');
    if (el) el.textContent = `(${list.length})`;
  }

  function formatElapsed(ms) {
    if (!ms || ms < 0) return '—';
    const s = Math.floor(ms / 1000);
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ${s % 60}s`;
    const h = Math.floor(m / 60);
    return `${h}h ${m % 60}m`;
  }

  function statusDotClass(status) {
    switch (status) {
      case 'running': return 'status-running';
      case 'completed': return 'status-completed';
      case 'failed': return 'status-failed';
      case 'interrupted': return 'status-failed';
      case 'pending': return 'status-pending';
      default: return '';
    }
  }

  function renderAgentList(list) {
    const container = document.getElementById('agents-list');
    if (!container) return;

    if (list.length === 0) {
      container.innerHTML = '<div class="empty-state">No agents</div>';
      return;
    }

    // Sort: running first, then pending, then completed/failed by most recent
    const order = { running: 0, pending: 1, failed: 2, interrupted: 3, completed: 4 };
    const sorted = [...list].sort((a, b) => (order[a.status] ?? 5) - (order[b.status] ?? 5));

    container.innerHTML = sorted.map(a => {
      const elapsed = a.status === 'running' && a.elapsed_ms
        ? formatElapsed(a.elapsed_ms)
        : '';
      const summary = a.result_summary
        ? escapeHtml(a.result_summary.length > 80 ? a.result_summary.slice(0, 77) + '…' : a.result_summary)
        : '';
      const campaignBadge = a.campaign?.name
        ? `<span class="agent-campaign-badge" title="${escapeHtml(a.campaign.name)}">${escapeHtml(a.campaign.strategy || 'campaign')}</span>`
        : '';
      const cancelBtn = (a.status === 'running' || a.status === 'pending')
        ? `<button class="agent-cancel-btn" data-task-id="${a.id}" title="Cancel agent">✕</button>`
        : '';

      return `<div class="agent-card agent-card--rich" data-task-id="${a.id}">
        <div class="agent-card-header">
          <span class="agent-status-dot ${statusDotClass(a.status)}"></span>
          <span class="agent-id">${escapeHtml(a.agent_id || a.id)}</span>
          ${cancelBtn}
        </div>
        <div class="agent-card-meta">
          <span class="agent-status-label ${a.status}">${a.status}</span>
          ${a.skill ? `<span class="agent-skill">${escapeHtml(a.skill)}</span>` : ''}
          ${elapsed ? `<span class="agent-elapsed">${elapsed}</span>` : ''}
          ${campaignBadge}
        </div>
        ${summary ? `<div class="agent-card-summary">${summary}</div>` : ''}
      </div>`;
    }).join('');

    // Click handlers
    container.querySelectorAll('.agent-card--rich').forEach(card => {
      card.addEventListener('click', (e) => {
        if (e.target.closest('.agent-cancel-btn')) return;
        const tid = card.dataset.taskId;
        showDetail(tid);
      });
    });

    container.querySelectorAll('.agent-cancel-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        cancelAgent(btn.dataset.taskId);
      });
    });
  }

  async function showDetail(taskId) {
    detailTaskId = taskId;
    const agent = agents.find(a => a.id === taskId);
    if (!agent) return;

    // Fetch context (subgraph)
    let context = null;
    try {
      const res = await fetch(`/api/agents/${encodeURIComponent(taskId)}/context`);
      if (res.ok) context = await res.json();
    } catch { /* ignore */ }

    renderAgentDetail(agent, context);
  }

  function renderAgentDetail(agent, context) {
    const drawer = document.getElementById('agent-detail-drawer');
    if (!drawer) return;

    const elapsed = agent.status === 'running' && agent.elapsed_ms
      ? formatElapsed(agent.elapsed_ms)
      : agent.completed_at && agent.assigned_at
        ? formatElapsed(new Date(agent.completed_at).getTime() - new Date(agent.assigned_at).getTime())
        : '—';

    const subgraphInfo = context?.subgraph
      ? `<div class="agent-detail-section">
           <div class="agent-detail-label">Scoped Subgraph</div>
           <div class="agent-detail-value">${context.subgraph.nodes?.length || 0} nodes, ${context.subgraph.edges?.length || 0} edges</div>
           ${(context.subgraph.nodes || []).slice(0, 10).map(n =>
             `<div class="agent-subgraph-node">${escapeHtml(n.properties?.label || n.id)}</div>`
           ).join('')}
           ${(context.subgraph.nodes || []).length > 10 ? '<div class="agent-subgraph-more">… and more</div>' : ''}
         </div>`
      : '';

    const cancelBtn = (agent.status === 'running' || agent.status === 'pending')
      ? `<button class="agent-detail-cancel" data-task-id="${agent.id}">Cancel Agent</button>`
      : '';

    drawer.innerHTML = `
      <div class="agent-detail-header">
        <span class="agent-status-dot ${statusDotClass(agent.status)}"></span>
        <span class="agent-detail-title">${escapeHtml(agent.agent_id || agent.id)}</span>
        <button class="agent-detail-close" id="agent-detail-close">✕</button>
      </div>
      <div class="agent-detail-body">
        <div class="agent-detail-section">
          <div class="agent-detail-row"><span class="agent-detail-label">Status</span><span class="agent-detail-value agent-status-label ${agent.status}">${agent.status}</span></div>
          <div class="agent-detail-row"><span class="agent-detail-label">Task ID</span><span class="agent-detail-value mono">${agent.id}</span></div>
          <div class="agent-detail-row"><span class="agent-detail-label">Assigned</span><span class="agent-detail-value">${new Date(agent.assigned_at).toLocaleString()}</span></div>
          <div class="agent-detail-row"><span class="agent-detail-label">Elapsed</span><span class="agent-detail-value">${elapsed}</span></div>
          ${agent.skill ? `<div class="agent-detail-row"><span class="agent-detail-label">Skill</span><span class="agent-detail-value">${escapeHtml(agent.skill)}</span></div>` : ''}
          ${agent.frontier_item_id ? `<div class="agent-detail-row"><span class="agent-detail-label">Frontier Item</span><span class="agent-detail-value mono">${escapeHtml(agent.frontier_item_id)}</span></div>` : ''}
          ${agent.campaign_id ? `<div class="agent-detail-row"><span class="agent-detail-label">Campaign</span><span class="agent-detail-value mono">${escapeHtml(agent.campaign_id)}</span></div>` : ''}
          ${agent.result_summary ? `<div class="agent-detail-row"><span class="agent-detail-label">Result</span><span class="agent-detail-value">${escapeHtml(agent.result_summary)}</span></div>` : ''}
          <div class="agent-detail-row"><span class="agent-detail-label">Scope Nodes</span><span class="agent-detail-value">${(agent.subgraph_node_ids || []).length}</span></div>
        </div>
        ${subgraphInfo}
        ${cancelBtn}
      </div>
    `;

    drawer.classList.add('open');

    drawer.querySelector('#agent-detail-close')?.addEventListener('click', closeDetail);
    drawer.querySelector('.agent-detail-cancel')?.addEventListener('click', (e) => {
      cancelAgent(e.currentTarget.dataset.taskId);
    });
  }

  function closeDetail() {
    detailTaskId = null;
    const drawer = document.getElementById('agent-detail-drawer');
    if (drawer) drawer.classList.remove('open');
  }

  async function cancelAgent(taskId) {
    if (!confirm('Cancel this agent?')) return;
    try {
      const res = await fetch(`/api/agents/${encodeURIComponent(taskId)}/cancel`, { method: 'POST' });
      if (res.ok) {
        await fetchAgents();
      }
    } catch { /* ignore */ }
  }

  // Called by main.js to update from WS state pushes
  function updateFromState(state) {
    // state.active_agents is running-only; fetchAgents gets all via REST
    // but we can still use state push to trigger a fetch
    fetchAgents();
  }

  return { init, destroy, updateFromState, fetchAgents, closeDetail };
})();
