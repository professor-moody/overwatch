// ============================================================
// Overwatch Dashboard — Campaign Management Panel
// Campaign cards, progress, lifecycle actions, agent dispatch
// ============================================================

window.OverwatchCampaigns = (() => {
  let pollTimer = null;
  let campaigns = [];
  let detailCampaignId = null;

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function init() {
    fetchCampaigns();
    pollTimer = setInterval(fetchCampaigns, 3000);
  }

  function destroy() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  async function fetchCampaigns() {
    try {
      const res = await fetch('/api/campaigns');
      if (!res.ok) return;
      const data = await res.json();
      campaigns = data.campaigns || [];
      renderCampaignList(campaigns);
      updateCount(campaigns);
      if (detailCampaignId) refreshDetail(detailCampaignId);
    } catch { /* network error */ }
  }

  function updateCount(list) {
    const el = document.getElementById('campaign-count');
    if (el) el.textContent = `(${list.length})`;
  }

  const STRATEGY_ICONS = {
    credential_spray: '🔑',
    enumeration: '🔍',
    post_exploitation: '⚡',
    network_discovery: '🌐',
    custom: '⚙',
  };

  const STATUS_CLASSES = {
    draft: 'campaign-status-draft',
    active: 'campaign-status-active',
    paused: 'campaign-status-paused',
    completed: 'campaign-status-completed',
    aborted: 'campaign-status-aborted',
  };

  function renderCampaignList(list) {
    const container = document.getElementById('campaigns-list');
    if (!container) return;

    if (list.length === 0) {
      container.innerHTML = '<div class="empty-state">No campaigns</div>';
      return;
    }

    // Sort: active first, then paused, draft, completed, aborted
    const order = { active: 0, paused: 1, draft: 2, completed: 3, aborted: 4 };
    const sorted = [...list].sort((a, b) => (order[a.status] ?? 5) - (order[b.status] ?? 5));

    container.innerHTML = sorted.map(c => {
      const icon = STRATEGY_ICONS[c.strategy] || '⚙';
      const pct = c.progress?.total > 0 ? Math.round((c.progress.completed / c.progress.total) * 100) : 0;
      const statusClass = STATUS_CLASSES[c.status] || '';

      return `<div class="campaign-card" data-campaign-id="${c.id}">
        <div class="campaign-card-header">
          <span class="campaign-strategy-icon" title="${escapeHtml(c.strategy)}">${icon}</span>
          <span class="campaign-name">${escapeHtml(c.name || c.id)}</span>
          <span class="campaign-status-badge ${statusClass}">${c.status}</span>
        </div>
        <div class="campaign-progress-row">
          <div class="campaign-progress-bar">
            <div class="campaign-progress-fill" style="width:${pct}%"></div>
          </div>
          <span class="campaign-progress-label">${c.progress?.completed || 0}/${c.progress?.total || 0}</span>
        </div>
        <div class="campaign-card-meta">
          <span class="campaign-agents">${c.running_agents || 0}/${c.agent_count || 0} agents</span>
          ${c.progress?.failed > 0 ? `<span class="campaign-failures">${c.progress.failed} failed</span>` : ''}
        </div>
      </div>`;
    }).join('');

    container.querySelectorAll('.campaign-card').forEach(card => {
      card.addEventListener('click', () => showDetail(card.dataset.campaignId));
    });
  }

  async function showDetail(campaignId) {
    detailCampaignId = campaignId;
    try {
      const res = await fetch(`/api/campaigns/${encodeURIComponent(campaignId)}`);
      if (!res.ok) return;
      const data = await res.json();
      renderCampaignDetail(data);
    } catch { /* ignore */ }
  }

  async function refreshDetail(campaignId) {
    try {
      const res = await fetch(`/api/campaigns/${encodeURIComponent(campaignId)}`);
      if (!res.ok) return;
      const data = await res.json();
      renderCampaignDetail(data);
    } catch { /* ignore */ }
  }

  function renderCampaignDetail(data) {
    const { campaign: c, agents, abort_check } = data;
    const drawer = document.getElementById('campaign-detail-drawer');
    if (!drawer) return;

    const icon = STRATEGY_ICONS[c.strategy] || '⚙';
    const statusClass = STATUS_CLASSES[c.status] || '';
    const pct = c.progress?.total > 0 ? Math.round((c.progress.completed / c.progress.total) * 100) : 0;

    // Action buttons based on status
    const actions = [];
    if (c.status === 'draft') actions.push({ action: 'activate', label: 'Activate', cls: 'campaign-btn-activate' });
    if (c.status === 'active') {
      actions.push({ action: 'pause', label: 'Pause', cls: 'campaign-btn-pause' });
      actions.push({ action: 'abort', label: 'Abort', cls: 'campaign-btn-abort' });
    }
    if (c.status === 'paused') {
      actions.push({ action: 'resume', label: 'Resume', cls: 'campaign-btn-activate' });
      actions.push({ action: 'abort', label: 'Abort', cls: 'campaign-btn-abort' });
    }
    // Dispatch button for draft/active
    const canDispatch = c.status === 'draft' || c.status === 'active';

    const actionHtml = actions.map(a =>
      `<button class="campaign-action-btn ${a.cls}" data-action="${a.action}">${a.label}</button>`
    ).join('');

    const dispatchHtml = canDispatch
      ? `<button class="campaign-action-btn campaign-btn-dispatch" id="campaign-dispatch-btn">Dispatch Agents</button>`
      : '';

    // Abort conditions
    const abortHtml = (c.abort_conditions || []).map(ac => {
      let current = '—';
      if (ac.type === 'consecutive_failures') current = String(c.progress?.consecutive_failures || 0);
      else if (ac.type === 'total_failures_pct' && c.progress?.total > 0) current = `${Math.round((c.progress.failed / c.progress.total) * 100)}%`;
      return `<div class="campaign-abort-row">
        <span class="campaign-abort-type">${escapeHtml(ac.type)}</span>
        <span class="campaign-abort-values">${current} / ${ac.threshold}${ac.type === 'total_failures_pct' ? '%' : ''}</span>
      </div>`;
    }).join('');

    // Agents list
    const agentHtml = (agents || []).map(a => `
      <div class="campaign-agent-item">
        <span class="agent-status-dot ${a.status === 'running' ? 'status-running' : a.status === 'failed' ? 'status-failed' : a.status === 'pending' ? 'status-pending' : 'status-completed'}"></span>
        <span class="campaign-agent-id">${escapeHtml(a.agent_id || a.id)}</span>
        <span class="campaign-agent-status">${a.status}</span>
      </div>
    `).join('');

    // Findings
    const findingsHtml = (c.findings || []).length > 0
      ? `<div class="campaign-detail-section">
           <div class="campaign-detail-label">Findings (${c.findings.length})</div>
           ${c.findings.slice(0, 10).map(f => `<div class="campaign-finding-id">${escapeHtml(f)}</div>`).join('')}
           ${c.findings.length > 10 ? `<div class="campaign-more">… ${c.findings.length - 10} more</div>` : ''}
         </div>`
      : '';

    drawer.innerHTML = `
      <div class="campaign-detail-header">
        <span class="campaign-strategy-icon">${icon}</span>
        <span class="campaign-detail-title">${escapeHtml(c.name || c.id)}</span>
        <span class="campaign-status-badge ${statusClass}">${c.status}</span>
        <button class="campaign-detail-close" id="campaign-detail-close">✕</button>
      </div>
      <div class="campaign-detail-body">
        <div class="campaign-detail-section">
          <div class="campaign-detail-row"><span class="campaign-detail-label">Strategy</span><span class="campaign-detail-value">${escapeHtml(c.strategy)}</span></div>
          <div class="campaign-detail-row"><span class="campaign-detail-label">ID</span><span class="campaign-detail-value mono">${c.id}</span></div>
          ${c.chain_id ? `<div class="campaign-detail-row"><span class="campaign-detail-label">Chain</span><span class="campaign-detail-value mono">${escapeHtml(c.chain_id)}</span></div>` : ''}
          <div class="campaign-detail-row"><span class="campaign-detail-label">Created</span><span class="campaign-detail-value">${new Date(c.created_at).toLocaleString()}</span></div>
          ${c.started_at ? `<div class="campaign-detail-row"><span class="campaign-detail-label">Started</span><span class="campaign-detail-value">${new Date(c.started_at).toLocaleString()}</span></div>` : ''}
        </div>

        <div class="campaign-detail-section">
          <div class="campaign-detail-label">Progress</div>
          <div class="campaign-progress-row campaign-progress-row--detail">
            <div class="campaign-progress-bar campaign-progress-bar--lg">
              <div class="campaign-progress-fill" style="width:${pct}%"></div>
            </div>
            <span class="campaign-progress-label">${pct}%</span>
          </div>
          <div class="campaign-detail-row"><span class="campaign-detail-label">Completed</span><span class="campaign-detail-value">${c.progress?.completed || 0} / ${c.progress?.total || 0}</span></div>
          <div class="campaign-detail-row"><span class="campaign-detail-label">Succeeded</span><span class="campaign-detail-value" style="color:var(--green)">${c.progress?.succeeded || 0}</span></div>
          <div class="campaign-detail-row"><span class="campaign-detail-label">Failed</span><span class="campaign-detail-value" style="color:var(--red)">${c.progress?.failed || 0}</span></div>
          <div class="campaign-detail-row"><span class="campaign-detail-label">Consecutive Failures</span><span class="campaign-detail-value">${c.progress?.consecutive_failures || 0}</span></div>
        </div>

        ${abortHtml ? `<div class="campaign-detail-section"><div class="campaign-detail-label">Abort Conditions</div>${abortHtml}${abort_check?.should_abort ? `<div class="campaign-abort-warning">⚠ Would abort: ${escapeHtml(abort_check.reason || '')}</div>` : ''}</div>` : ''}

        ${findingsHtml}

        ${agentHtml ? `<div class="campaign-detail-section"><div class="campaign-detail-label">Agents (${agents.length})</div>${agentHtml}</div>` : ''}

        <div class="campaign-actions">
          ${actionHtml}
          ${dispatchHtml}
        </div>
      </div>
    `;

    drawer.classList.add('open');

    drawer.querySelector('#campaign-detail-close')?.addEventListener('click', closeDetail);
    drawer.querySelectorAll('.campaign-action-btn[data-action]').forEach(btn => {
      btn.addEventListener('click', () => manageCampaign(c.id, btn.dataset.action));
    });
    drawer.querySelector('#campaign-dispatch-btn')?.addEventListener('click', () => dispatchAgents(c.id));
  }

  function closeDetail() {
    detailCampaignId = null;
    const drawer = document.getElementById('campaign-detail-drawer');
    if (drawer) drawer.classList.remove('open');
  }

  async function manageCampaign(campaignId, action) {
    if (action === 'abort' && !confirm('Abort this campaign? Running agents will be interrupted.')) return;
    try {
      const res = await fetch(`/api/campaigns/${encodeURIComponent(campaignId)}/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      });
      if (res.ok) await fetchCampaigns();
    } catch { /* ignore */ }
  }

  async function dispatchAgents(campaignId) {
    try {
      const res = await fetch(`/api/campaigns/${encodeURIComponent(campaignId)}/dispatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (res.ok) await fetchCampaigns();
    } catch { /* ignore */ }
  }

  function updateFromState() {
    fetchCampaigns();
  }

  return { init, destroy, updateFromState, fetchCampaigns, closeDetail };
})();
