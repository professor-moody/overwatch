// ============================================================
// Overwatch Dashboard — Campaign Management Panel
// Campaign cards, progress, lifecycle actions, agent dispatch
// ============================================================

window.OverwatchCampaigns = (() => {
  let pollTimer = null;
  let campaigns = [];
  let detailCampaignId = null;
  let builderOpen = false;
  let editingCampaignId = null;
  let selectedItemIds = new Set();
  let cachedFrontier = [];
  let abortRows = [];
  let selectedCampaignIds = new Set();

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function init() {
    fetchCampaigns();
    pollTimer = setInterval(fetchCampaigns, 3000);
    document.getElementById('new-campaign-btn')?.addEventListener('click', () => openBuilder(null));
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
      renderCampaignBatchBar([]);
      return;
    }

    // Sort: active first, then paused, draft, completed, aborted
    const order = { active: 0, paused: 1, draft: 2, completed: 3, aborted: 4 };
    const sorted = [...list].sort((a, b) => (order[a.status] ?? 5) - (order[b.status] ?? 5));

    // Clean up stale selections
    const validIds = new Set(list.map(c => c.id));
    for (const id of selectedCampaignIds) {
      if (!validIds.has(id)) selectedCampaignIds.delete(id);
    }
    const allSelected = sorted.length > 0 && sorted.every(c => selectedCampaignIds.has(c.id));

    let html = `<div class="batch-select-header">
      <label class="batch-select-all"><input type="checkbox" class="campaign-select-all" ${allSelected ? 'checked' : ''} /> Select all</label>
    </div>`;

    html += sorted.map(c => {
      const icon = STRATEGY_ICONS[c.strategy] || '⚙';
      const pct = c.progress?.total > 0 ? Math.round((c.progress.completed / c.progress.total) * 100) : 0;
      const statusClass = STATUS_CLASSES[c.status] || '';
      const checked = selectedCampaignIds.has(c.id) ? 'checked' : '';

      return `<div class="campaign-card" data-campaign-id="${c.id}">
        <div class="campaign-card-header">
          <input type="checkbox" class="campaign-select-cb" data-id="${c.id}" ${checked} />
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
          ${(c.findings || []).length > 0 ? `<span class="campaign-findings-count">${c.findings.length} finding${c.findings.length !== 1 ? 's' : ''}</span>` : ''}
          ${c.progress?.failed > 0 ? `<span class="campaign-failures">${c.progress.failed} failed</span>` : ''}
        </div>
      </div>`;
    }).join('');

    container.innerHTML = html;

    // Wire select-all
    container.querySelector('.campaign-select-all')?.addEventListener('change', (e) => {
      if (e.target.checked) {
        sorted.forEach(c => selectedCampaignIds.add(c.id));
      } else {
        selectedCampaignIds.clear();
      }
      renderCampaignList(campaigns);
    });

    // Wire individual checkboxes (stop click from bubbling into card click)
    container.querySelectorAll('.campaign-select-cb').forEach(cb => {
      cb.addEventListener('click', (e) => e.stopPropagation());
      cb.addEventListener('change', (e) => {
        if (e.target.checked) selectedCampaignIds.add(e.target.dataset.id);
        else selectedCampaignIds.delete(e.target.dataset.id);
        renderCampaignBatchBar(campaigns);
        // Update select-all checkbox
        const all = container.querySelector('.campaign-select-all');
        if (all) all.checked = sorted.every(c => selectedCampaignIds.has(c.id));
      });
    });

    // Wire card clicks
    container.querySelectorAll('.campaign-card').forEach(card => {
      card.addEventListener('click', (e) => {
        if (e.target.closest('.campaign-select-cb')) return;
        showDetail(card.dataset.campaignId);
      });
    });

    renderCampaignBatchBar(campaigns);
  }

  function renderCampaignBatchBar(list) {
    let bar = document.getElementById('campaign-batch-bar');
    if (selectedCampaignIds.size === 0) {
      if (bar) bar.remove();
      return;
    }

    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'campaign-batch-bar';
      bar.className = 'batch-action-bar';
      document.getElementById('panel-campaigns')?.appendChild(bar);
    }

    const selected = list.filter(c => selectedCampaignIds.has(c.id));
    const hasActivatable = selected.some(c => c.status === 'draft' || c.status === 'paused');
    const hasPausable = selected.some(c => c.status === 'active');
    const hasAbortable = selected.some(c => c.status === 'active' || c.status === 'paused');

    bar.innerHTML = `
      <span class="batch-count">${selectedCampaignIds.size} selected</span>
      ${hasActivatable ? '<button class="batch-btn batch-activate">Activate</button>' : ''}
      ${hasPausable ? '<button class="batch-btn batch-pause">Pause</button>' : ''}
      ${hasAbortable ? '<button class="batch-btn batch-abort">Abort</button>' : ''}
      <button class="batch-btn batch-deselect">Deselect All</button>
    `;

    bar.querySelector('.batch-activate')?.addEventListener('click', () => batchCampaignAction('activate'));
    bar.querySelector('.batch-pause')?.addEventListener('click', () => batchCampaignAction('pause'));
    bar.querySelector('.batch-abort')?.addEventListener('click', () => batchCampaignAction('abort'));
    bar.querySelector('.batch-deselect')?.addEventListener('click', () => {
      selectedCampaignIds.clear();
      renderCampaignList(campaigns);
    });
  }

  async function batchCampaignAction(action) {
    if (!confirm(`${action} ${selectedCampaignIds.size} campaign(s)?`)) return;
    await Promise.allSettled([...selectedCampaignIds].map(id =>
      fetch(`/api/campaigns/${encodeURIComponent(id)}/${action}`, { method: 'POST' })
    ));
    selectedCampaignIds.clear();
    fetchCampaigns();
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
    const { campaign: c, agents, abort_check, finding_details } = data;
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

    // Findings (enriched)
    const findings = finding_details || [];
    const findingsHtml = findings.length > 0
      ? `<div class="campaign-detail-section">
           <div class="campaign-detail-label">Findings (${findings.length})</div>
           ${findings.slice(0, 20).map(f => {
             const typeBadge = `<span class="campaign-finding-type type-${f.type}">${escapeHtml(f.type)}</span>`;
             const ts = f.created_at ? `<span class="campaign-finding-ts">${new Date(f.created_at).toLocaleTimeString()}</span>` : '';
             return `<div class="campaign-finding-row">
               ${typeBadge}
               <span class="campaign-finding-label">${escapeHtml(f.label)}</span>
               ${ts}
               <a class="fi-graph-link" href="/graph?focus=${encodeURIComponent(f.id)}" target="_blank" title="View in graph">⊞</a>
             </div>`;
           }).join('')}
           ${findings.length > 20 ? `<div class="campaign-more">… ${findings.length - 20} more</div>` : ''}
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
          ${c.status === 'draft' || c.status === 'paused' ? `<button class="campaign-action-btn campaign-btn-edit" id="campaign-edit-btn">Edit</button>` : ''}
          <button class="campaign-action-btn campaign-btn-clone" id="campaign-clone-btn">Clone</button>
          ${c.status === 'draft' ? `<button class="campaign-action-btn campaign-btn-delete" id="campaign-delete-btn">Delete</button>` : ''}
        </div>
      </div>
    `;

    drawer.classList.add('open');

    drawer.querySelector('#campaign-detail-close')?.addEventListener('click', closeDetail);
    drawer.querySelectorAll('.campaign-action-btn[data-action]').forEach(btn => {
      btn.addEventListener('click', () => manageCampaign(c.id, btn.dataset.action));
    });
    drawer.querySelector('#campaign-dispatch-btn')?.addEventListener('click', () => dispatchAgents(c.id));
    drawer.querySelector('#campaign-edit-btn')?.addEventListener('click', () => editCampaign(c.id));
    drawer.querySelector('#campaign-clone-btn')?.addEventListener('click', () => cloneCampaign(c.id));
    drawer.querySelector('#campaign-delete-btn')?.addEventListener('click', () => deleteCampaign(c.id));
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
    openDispatchModal(campaignId);
  }

  // =============================================
  // Dispatch Modal
  // =============================================

  function openDispatchModal(campaignId) {
    const c = campaigns.find(x => x.id === campaignId);
    const itemCount = c?.items?.length || c?.progress?.total || 0;
    const overlay = document.getElementById('dispatch-modal-overlay');
    const modal = document.getElementById('dispatch-modal');
    if (!overlay || !modal) return;

    // Reset to defaults
    document.getElementById('dm-max-agents').value = 8;
    document.getElementById('dm-max-agents-val').textContent = '8';
    document.getElementById('dm-hops').value = 2;
    document.getElementById('dm-hops-val').textContent = '2';
    document.getElementById('dm-skill').value = '';
    document.getElementById('dm-throttle').value = '0';
    updateAgentEstimate(itemCount, 8);

    // Wire range slider displays
    document.getElementById('dm-max-agents').oninput = (e) => {
      document.getElementById('dm-max-agents-val').textContent = e.target.value;
      updateAgentEstimate(itemCount, parseInt(e.target.value));
    };
    document.getElementById('dm-hops').oninput = (e) => {
      document.getElementById('dm-hops-val').textContent = e.target.value;
    };

    // Wire buttons
    document.getElementById('dm-cancel').onclick = closeDispatchModal;
    document.getElementById('dm-dispatch').onclick = () => executeDispatch(campaignId);
    overlay.onclick = (e) => { if (e.target === overlay) closeDispatchModal(); };

    overlay.style.display = 'flex';
  }

  function updateAgentEstimate(itemCount, maxAgents) {
    const est = Math.min(itemCount, maxAgents);
    const el = document.getElementById('dm-agent-estimate');
    if (el) el.textContent = `≈ ${est} agent${est !== 1 ? 's' : ''} for ${itemCount} item${itemCount !== 1 ? 's' : ''}`;
  }

  function closeDispatchModal() {
    const overlay = document.getElementById('dispatch-modal-overlay');
    if (overlay) overlay.style.display = 'none';
  }

  async function executeDispatch(campaignId) {
    const maxAgents = parseInt(document.getElementById('dm-max-agents')?.value) || 8;
    const hops = parseInt(document.getElementById('dm-hops')?.value) || 2;
    const skill = document.getElementById('dm-skill')?.value?.trim() || undefined;
    const throttle = parseInt(document.getElementById('dm-throttle')?.value) || 0;

    closeDispatchModal();

    try {
      const res = await fetch(`/api/campaigns/${encodeURIComponent(campaignId)}/dispatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ max_agents: maxAgents, hops, skill }),
      });
      if (res.ok) await fetchCampaigns();
    } catch { /* ignore */ }
  }

  // =============================================
  // Campaign Builder
  // =============================================

  const ABORT_TYPES = [
    { value: 'consecutive_failures', label: 'Consecutive Failures', defaultThreshold: 5 },
    { value: 'total_failures_pct', label: 'Total Failure %', defaultThreshold: 0.9 },
    { value: 'opsec_noise_ceiling', label: 'OPSEC Noise Ceiling', defaultThreshold: 0.8 },
    { value: 'time_limit_seconds', label: 'Time Limit (seconds)', defaultThreshold: 3600 },
  ];

  const DEFAULT_ABORT_CONDITIONS = {
    credential_spray: [
      { type: 'consecutive_failures', threshold: 5 },
      { type: 'total_failures_pct', threshold: 0.9 },
    ],
    enumeration: [{ type: 'consecutive_failures', threshold: 10 }],
    post_exploitation: [{ type: 'consecutive_failures', threshold: 3 }],
    network_discovery: [],
    custom: [],
  };

  function openBuilder(campaign) {
    builderOpen = true;
    editingCampaignId = campaign ? campaign.id : null;
    selectedItemIds = new Set(campaign ? campaign.items : []);

    const builder = document.getElementById('campaign-builder');
    const title = document.getElementById('campaign-builder-title');
    if (!builder) return;

    title.textContent = campaign ? `Edit: ${campaign.name}` : 'New Campaign';
    document.getElementById('cb-name').value = campaign ? campaign.name : '';
    document.getElementById('cb-strategy').value = campaign ? campaign.strategy : 'custom';

    abortRows = campaign
      ? campaign.abort_conditions.map(ac => ({ ...ac }))
      : [...(DEFAULT_ABORT_CONDITIONS['custom'] || [])];

    renderAbortConditions();
    loadFrontierItems();
    builder.style.display = '';

    // Wire strategy change to update default abort conditions
    document.getElementById('cb-strategy').onchange = () => {
      if (!editingCampaignId) {
        const strategy = document.getElementById('cb-strategy').value;
        abortRows = [...(DEFAULT_ABORT_CONDITIONS[strategy] || [])];
        renderAbortConditions();
        // Auto-suggest name
        const nameEl = document.getElementById('cb-name');
        if (!nameEl.value) nameEl.value = `${strategy.replace(/_/g, ' ')} campaign`;
      }
    };

    // Wire buttons
    document.getElementById('campaign-builder-cancel').onclick = closeBuilder;
    document.getElementById('cb-save-draft').onclick = () => submitBuilder(false);
    document.getElementById('cb-create-activate').onclick = () => submitBuilder(true);
    document.getElementById('cb-add-abort').onclick = addAbortRow;
    document.getElementById('cb-item-search').oninput = renderFrontierList;
    document.getElementById('cb-item-type-filter').onchange = renderFrontierList;
  }

  function closeBuilder() {
    builderOpen = false;
    editingCampaignId = null;
    selectedItemIds.clear();
    const builder = document.getElementById('campaign-builder');
    if (builder) builder.style.display = 'none';
  }

  async function loadFrontierItems() {
    try {
      const res = await fetch('/api/state');
      if (!res.ok) return;
      const data = await res.json();
      cachedFrontier = data.state?.frontier || [];
      renderFrontierList();
    } catch { /* ignore */ }
  }

  function renderFrontierList() {
    const container = document.getElementById('cb-item-list');
    if (!container) return;

    const searchText = (document.getElementById('cb-item-search')?.value || '').toLowerCase();
    const typeFilter = document.getElementById('cb-item-type-filter')?.value || '';

    // Find items already assigned to other campaigns
    const assignedItems = new Map();
    for (const c of campaigns) {
      if (editingCampaignId && c.id === editingCampaignId) continue;
      for (const itemId of (c.items || [])) {
        assignedItems.set(itemId, c.name);
      }
    }

    let items = cachedFrontier;
    if (typeFilter) items = items.filter(fi => fi.type === typeFilter);
    if (searchText) items = items.filter(fi => (fi.description || '').toLowerCase().includes(searchText));

    // Limit display to 100 items
    const display = items.slice(0, 100);

    container.innerHTML = display.map(fi => {
      const checked = selectedItemIds.has(fi.id) ? 'checked' : '';
      const assigned = assignedItems.get(fi.id);
      const dimClass = assigned ? 'cb-item-dimmed' : '';
      const noiseColor = fi.opsec_noise <= 0.3 ? 'var(--green)' : fi.opsec_noise <= 0.6 ? 'var(--yellow,#e8a838)' : 'var(--red)';
      const typeBadge = fi.type === 'incomplete_node' ? 'node' : fi.type === 'untested_edge' ? 'test' : fi.type === 'inferred_edge' ? 'infer' : 'disc';

      return `<label class="cb-item ${dimClass}" title="${assigned ? 'Assigned to: ' + escapeHtml(assigned) : ''}">
        <input type="checkbox" class="cb-item-check" data-item-id="${fi.id}" ${checked} />
        <span class="cb-item-type">${typeBadge}</span>
        <span class="cb-item-desc">${escapeHtml(fi.description || fi.id)}</span>
        <span class="cb-item-noise" style="color:${noiseColor}">${fi.opsec_noise?.toFixed(1) || '—'}</span>
        ${assigned ? `<span class="cb-item-assigned">${escapeHtml(assigned)}</span>` : ''}
      </label>`;
    }).join('');

    if (items.length > 100) {
      container.innerHTML += `<div class="cb-item-more">… ${items.length - 100} more items</div>`;
    }

    // Wire checkboxes
    container.querySelectorAll('.cb-item-check').forEach(cb => {
      cb.addEventListener('change', () => {
        if (cb.checked) selectedItemIds.add(cb.dataset.itemId);
        else selectedItemIds.delete(cb.dataset.itemId);
        updateSelectedCount();
      });
    });
    updateSelectedCount();
  }

  function updateSelectedCount() {
    const el = document.getElementById('cb-selected-count');
    if (el) el.textContent = `${selectedItemIds.size} selected`;
  }

  function renderAbortConditions() {
    const container = document.getElementById('cb-abort-list');
    if (!container) return;

    container.innerHTML = abortRows.map((ac, i) => {
      const options = ABORT_TYPES.map(at =>
        `<option value="${at.value}" ${at.value === ac.type ? 'selected' : ''}>${at.label}</option>`
      ).join('');
      return `<div class="cb-abort-row" data-idx="${i}">
        <select class="cb-select cb-select-sm cb-abort-type">${options}</select>
        <input type="number" class="cb-input cb-input-sm cb-abort-threshold" value="${ac.threshold}" step="any" min="0" />
        <button class="cb-abort-remove" title="Remove">✕</button>
      </div>`;
    }).join('');

    // Wire events
    container.querySelectorAll('.cb-abort-row').forEach(row => {
      const idx = parseInt(row.dataset.idx);
      row.querySelector('.cb-abort-type').onchange = (e) => { abortRows[idx].type = e.target.value; };
      row.querySelector('.cb-abort-threshold').onchange = (e) => { abortRows[idx].threshold = parseFloat(e.target.value) || 0; };
      row.querySelector('.cb-abort-remove').onclick = () => { abortRows.splice(idx, 1); renderAbortConditions(); };
    });
  }

  function addAbortRow() {
    abortRows.push({ type: 'consecutive_failures', threshold: 5 });
    renderAbortConditions();
  }

  async function submitBuilder(activate) {
    const name = document.getElementById('cb-name')?.value?.trim();
    const strategy = document.getElementById('cb-strategy')?.value;

    if (!name) { alert('Campaign name is required'); return; }
    if (selectedItemIds.size === 0) { alert('Select at least one frontier item'); return; }

    const body = {
      name, strategy,
      item_ids: Array.from(selectedItemIds),
      abort_conditions: abortRows.filter(ac => ac.threshold > 0),
    };

    try {
      let res;
      if (editingCampaignId) {
        // Update existing campaign
        res = await fetch(`/api/campaigns/${encodeURIComponent(editingCampaignId)}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: body.name,
            abort_conditions: body.abort_conditions,
            add_items: body.item_ids,
          }),
        });
      } else {
        // Create new campaign  
        res = await fetch('/api/campaigns', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
      }

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Failed to save campaign');
        return;
      }

      const data = await res.json();
      const campaignId = data.campaign?.id;

      // Activate if requested
      if (activate && campaignId && data.campaign?.status === 'draft') {
        await fetch(`/api/campaigns/${encodeURIComponent(campaignId)}/action`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'activate' }),
        });
      }

      closeBuilder();
      await fetchCampaigns();
    } catch (e) {
      alert('Network error saving campaign');
    }
  }

  // =============================================
  // Clone & Edit
  // =============================================

  async function cloneCampaign(campaignId) {
    try {
      const res = await fetch(`/api/campaigns/${encodeURIComponent(campaignId)}/clone`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (res.ok) {
        const data = await res.json();
        closeDetail();
        await fetchCampaigns();
        if (data.campaign?.id) openBuilder(data.campaign);
      }
    } catch { /* ignore */ }
  }

  async function deleteCampaign(campaignId) {
    if (!confirm('Delete this draft campaign?')) return;
    try {
      const res = await fetch(`/api/campaigns/${encodeURIComponent(campaignId)}`, { method: 'DELETE' });
      if (res.ok) { closeDetail(); await fetchCampaigns(); }
      else {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Failed to delete campaign');
      }
    } catch { /* ignore */ }
  }

  async function editCampaign(campaignId) {
    try {
      const res = await fetch(`/api/campaigns/${encodeURIComponent(campaignId)}`);
      if (!res.ok) return;
      const data = await res.json();
      closeDetail();
      openBuilder(data.campaign);
    } catch { /* ignore */ }
  }

  function updateFromState() {
    fetchCampaigns();
  }

  return { init, destroy, updateFromState, fetchCampaigns, closeDetail };
})();
