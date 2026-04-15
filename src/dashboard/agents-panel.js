// ============================================================
// Overwatch Dashboard — Agent Supervision Panel
// Rich agent cards with detail view and cancel support
// ============================================================

window.OverwatchAgentPanel = (() => {
  let pollTimer = null;
  let agents = [];
  let detailTaskId = null;
  let selectedAgentIds = new Set();

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

  let collapsedGroups = new Set();

  function renderAgentList(list) {
    const container = document.getElementById('agents-list');
    if (!container) return;

    if (list.length === 0) {
      container.innerHTML = '<div class="empty-state">No agents</div>';
      return;
    }

    // Group by campaign
    const groups = new Map(); // campaign_id -> { name, strategy, agents[] }
    const ungrouped = [];
    for (const a of list) {
      const cid = a.campaign_id || a.campaign?.id;
      if (cid) {
        if (!groups.has(cid)) groups.set(cid, { name: a.campaign?.name || cid, strategy: a.campaign?.strategy || '', agents: [] });
        groups.get(cid).agents.push(a);
      } else {
        ungrouped.push(a);
      }
    }

    // Clean up stale selections
    const validIds = new Set(list.map(a => a.id));
    for (const id of selectedAgentIds) {
      if (!validIds.has(id)) selectedAgentIds.delete(id);
    }
    const allSelected = list.length > 0 && list.every(a => selectedAgentIds.has(a.id));

    let html = `<div class="batch-select-header">
      <label class="batch-select-all"><input type="checkbox" class="agent-select-all" ${allSelected ? 'checked' : ''} /> Select all</label>
    </div>`;

    // Render campaign groups
    for (const [cid, group] of groups) {
      const collapsed = collapsedGroups.has(cid);
      const running = group.agents.filter(a => a.status === 'running').length;
      const total = group.agents.length;
      const icon = STRATEGY_ICONS[group.strategy] || '⚙';
      const sorted = sortAgents(group.agents);
      const hasRunning = group.agents.some(a => a.status === 'running' || a.status === 'pending');

      html += `<div class="agent-group">
        <div class="agent-group-header" data-group-id="${cid}">
          <span class="agent-group-toggle">${collapsed ? '▸' : '▾'}</span>
          <span class="agent-group-icon">${icon}</span>
          <span class="agent-group-name">${escapeHtml(group.name)}</span>
          <span class="agent-group-count">${running}/${total} running</span>
          ${hasRunning ? `<button class="agent-group-cancel" data-group-id="${cid}" title="Cancel all agents in this campaign">Cancel All</button>` : ''}
        </div>
        ${collapsed ? '' : `<div class="agent-group-body">${sorted.map(renderAgentCard).join('')}</div>`}
      </div>`;
    }

    // Render ungrouped agents
    if (ungrouped.length > 0) {
      const collapsed = collapsedGroups.has('__ungrouped__');
      const sorted = sortAgents(ungrouped);
      html += `<div class="agent-group">
        <div class="agent-group-header" data-group-id="__ungrouped__">
          <span class="agent-group-toggle">${collapsed ? '▸' : '▾'}</span>
          <span class="agent-group-name">Ungrouped</span>
          <span class="agent-group-count">${ungrouped.length}</span>
        </div>
        ${collapsed ? '' : `<div class="agent-group-body">${sorted.map(renderAgentCard).join('')}</div>`}
      </div>`;
    }

    container.innerHTML = html;

    // Wire group toggles
    container.querySelectorAll('.agent-group-header').forEach(hdr => {
      hdr.addEventListener('click', (e) => {
        if (e.target.closest('.agent-group-cancel')) return;
        const gid = hdr.dataset.groupId;
        if (collapsedGroups.has(gid)) collapsedGroups.delete(gid);
        else collapsedGroups.add(gid);
        renderAgentList(agents);
      });
    });

    // Wire cancel-all buttons
    container.querySelectorAll('.agent-group-cancel').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        cancelGroupAgents(btn.dataset.groupId);
      });
    });

    // Wire card clicks & individual cancel
    container.querySelectorAll('.agent-card--rich').forEach(card => {
      card.addEventListener('click', (e) => {
        if (e.target.closest('.agent-cancel-btn')) return;
        showDetail(card.dataset.taskId);
      });
    });

    container.querySelectorAll('.agent-cancel-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        cancelAgent(btn.dataset.taskId);
      });
    });

    // Wire select-all
    container.querySelector('.agent-select-all')?.addEventListener('change', (e) => {
      if (e.target.checked) {
        list.forEach(a => selectedAgentIds.add(a.id));
      } else {
        selectedAgentIds.clear();
      }
      renderAgentList(agents);
    });

    // Wire individual checkboxes
    container.querySelectorAll('.agent-select-cb').forEach(cb => {
      cb.addEventListener('click', (e) => e.stopPropagation());
      cb.addEventListener('change', (e) => {
        if (e.target.checked) selectedAgentIds.add(e.target.dataset.id);
        else selectedAgentIds.delete(e.target.dataset.id);
        renderAgentBatchBar(agents);
        const all = container.querySelector('.agent-select-all');
        if (all) all.checked = list.every(a => selectedAgentIds.has(a.id));
      });
    });

    renderAgentBatchBar(agents);
  }

  function renderAgentBatchBar(list) {
    let bar = document.getElementById('agent-batch-bar');
    if (selectedAgentIds.size === 0) {
      if (bar) bar.remove();
      return;
    }

    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'agent-batch-bar';
      bar.className = 'batch-action-bar';
      document.getElementById('panel-agents')?.appendChild(bar);
    }

    const selected = list.filter(a => selectedAgentIds.has(a.id));
    const hasCancellable = selected.some(a => a.status === 'running' || a.status === 'pending');

    bar.innerHTML = `
      <span class="batch-count">${selectedAgentIds.size} selected</span>
      ${hasCancellable ? '<button class="batch-btn batch-cancel">Cancel Selected</button>' : ''}
      <button class="batch-btn batch-deselect">Deselect All</button>
    `;

    bar.querySelector('.batch-cancel')?.addEventListener('click', batchCancelAgents);
    bar.querySelector('.batch-deselect')?.addEventListener('click', () => {
      selectedAgentIds.clear();
      renderAgentList(agents);
    });
  }

  async function batchCancelAgents() {
    if (!confirm(`Cancel ${selectedAgentIds.size} agent(s)?`)) return;
    const cancellable = agents.filter(a => selectedAgentIds.has(a.id) && (a.status === 'running' || a.status === 'pending'));
    await Promise.allSettled(cancellable.map(a =>
      fetch(`/api/agents/${encodeURIComponent(a.id)}/cancel`, { method: 'POST' })
    ));
    selectedAgentIds.clear();
    await fetchAgents();
  }

  const STRATEGY_ICONS = {
    credential_spray: '🔑',
    enumeration: '🔍',
    post_exploitation: '⚡',
    network_discovery: '🌐',
    custom: '⚙',
  };

  function sortAgents(list) {
    const order = { running: 0, pending: 1, failed: 2, interrupted: 3, completed: 4 };
    return [...list].sort((a, b) => (order[a.status] ?? 5) - (order[b.status] ?? 5));
  }

  function renderAgentCard(a) {
    const elapsed = a.status === 'running' && a.elapsed_ms
      ? formatElapsed(a.elapsed_ms)
      : '';
    const summary = a.result_summary
      ? escapeHtml(a.result_summary.length > 80 ? a.result_summary.slice(0, 77) + '…' : a.result_summary)
      : '';
    const cancelBtn = (a.status === 'running' || a.status === 'pending')
      ? `<button class="agent-cancel-btn" data-task-id="${a.id}" title="Cancel agent">✕</button>`
      : '';
    const checked = selectedAgentIds.has(a.id) ? 'checked' : '';

    return `<div class="agent-card agent-card--rich" data-task-id="${a.id}">
      <div class="agent-card-header">
        <input type="checkbox" class="agent-select-cb" data-id="${a.id}" ${checked} />
        <span class="agent-status-dot ${statusDotClass(a.status)}"></span>
        <span class="agent-id">${escapeHtml(a.agent_id || a.id)}</span>
        ${cancelBtn}
      </div>
      <div class="agent-card-meta">
        <span class="agent-status-label ${a.status}">${a.status}</span>
        ${a.skill ? `<span class="agent-skill">${escapeHtml(a.skill)}</span>` : ''}
        ${elapsed ? `<span class="agent-elapsed">${elapsed}</span>` : ''}
      </div>
      ${summary ? `<div class="agent-card-summary">${summary}</div>` : ''}
    </div>`;
  }

  async function cancelGroupAgents(groupId) {
    if (!confirm('Cancel all agents in this campaign?')) return;
    const group = groupId === '__ungrouped__'
      ? agents.filter(a => !a.campaign_id && !a.campaign?.id)
      : agents.filter(a => (a.campaign_id || a.campaign?.id) === groupId);
    const cancellable = group.filter(a => a.status === 'running' || a.status === 'pending');
    await Promise.allSettled(cancellable.map(a =>
      fetch(`/api/agents/${encodeURIComponent(a.id)}/cancel`, { method: 'POST' })
    ));
    await fetchAgents();
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
