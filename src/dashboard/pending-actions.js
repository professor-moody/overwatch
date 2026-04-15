// ============================================================
// Overwatch Dashboard — Pending Actions Panel
// Approval gate UI: shows pending actions, approve/deny buttons,
// countdown timer for auto-approve timeout.
// ============================================================

window.OverwatchPendingActions = (() => {
  let pollTimer = null;
  let pending = [];
  let countdownTimers = {};
  let sortMode = 'arrival'; // 'arrival' | 'noise-desc' | 'timeout-asc'
  let expandedAction = null; // action_id whose inline form is open

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function init() {
    fetchPending();
    pollTimer = setInterval(fetchPending, 2000);

    const sortSelect = document.getElementById('pa-sort-select');
    if (sortSelect) {
      sortSelect.addEventListener('change', () => {
        sortMode = sortSelect.value;
        renderPendingList(pending);
      });
    }

    const bulkApproveBtn = document.getElementById('pa-bulk-approve');
    if (bulkApproveBtn) bulkApproveBtn.addEventListener('click', bulkApprove);
    const bulkDenyBtn = document.getElementById('pa-bulk-deny');
    if (bulkDenyBtn) bulkDenyBtn.addEventListener('click', bulkDeny);
  }

  function destroy() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    Object.values(countdownTimers).forEach(clearInterval);
    countdownTimers = {};
  }

  async function fetchPending() {
    try {
      const res = await fetch('/api/actions/pending');
      if (!res.ok) return;
      const data = await res.json();
      pending = data.pending || [];
      renderPendingList(pending);
      updateCount(pending);
      updateBulkButtons(pending);
    } catch { /* network error — keep stale data */ }
  }

  function updateCount(list) {
    const el = document.getElementById('pending-actions-count');
    if (!el) return;
    el.textContent = `(${list.length})`;
    if (list.length > 0) {
      el.classList.add('pending-actions-badge');
    } else {
      el.classList.remove('pending-actions-badge');
    }
  }

  // --- Sorting ---

  function sortedPending(list) {
    const sorted = [...list];
    if (sortMode === 'noise-desc') {
      sorted.sort((a, b) => {
        const na = (a.opsec_context && a.opsec_context.noise_level) || 0;
        const nb = (b.opsec_context && b.opsec_context.noise_level) || 0;
        return nb - na;
      });
    } else if (sortMode === 'timeout-asc') {
      sorted.sort((a, b) => {
        const ta = a.timeout_at ? new Date(a.timeout_at).getTime() : Infinity;
        const tb = b.timeout_at ? new Date(b.timeout_at).getTime() : Infinity;
        return ta - tb;
      });
    }
    return sorted;
  }

  // --- Priority indicator ---

  function computePriority(action) {
    const opsec = action.opsec_context || {};
    const noise = opsec.noise_level || 0;
    const signals = (opsec.defensive_signals || []).length;
    // Higher noise + more signals = higher priority (needs attention)
    const score = noise * 2 + signals;
    if (score >= 6) return { label: 'HIGH', cls: 'pa-prio-high' };
    if (score >= 3) return { label: 'MED', cls: 'pa-prio-med' };
    return { label: 'LOW', cls: 'pa-prio-low' };
  }

  // --- Rendering ---

  function renderPendingList(list) {
    const container = document.getElementById('pending-actions-list');
    if (!container) return;

    if (list.length === 0) {
      container.innerHTML = '<div class="empty-state">No pending actions</div>';
      Object.values(countdownTimers).forEach(clearInterval);
      countdownTimers = {};
      return;
    }

    const sorted = sortedPending(list);
    container.innerHTML = sorted.map(action => renderActionCard(action)).join('');

    // Wire up buttons
    container.querySelectorAll('.pa-approve-btn').forEach(btn => {
      btn.addEventListener('click', () => toggleApproveForm(btn.dataset.id));
    });
    container.querySelectorAll('.pa-deny-btn').forEach(btn => {
      btn.addEventListener('click', () => toggleDenyForm(btn.dataset.id));
    });
    container.querySelectorAll('.pa-confirm-approve').forEach(btn => {
      btn.addEventListener('click', () => confirmApprove(btn.dataset.id));
    });
    container.querySelectorAll('.pa-confirm-deny').forEach(btn => {
      btn.addEventListener('click', () => confirmDeny(btn.dataset.id));
    });
    container.querySelectorAll('.pa-cancel-form').forEach(btn => {
      btn.addEventListener('click', () => { expandedAction = null; renderPendingList(pending); });
    });

    startCountdowns(sorted);
  }

  function renderActionCard(action) {
    const timeLeft = getTimeLeftMs(action.timeout_at);
    const timeLeftStr = formatCountdown(timeLeft);
    const opsec = action.opsec_context || {};
    const approach = opsec.recommended_approach || '—';
    const budgetPct = opsec.noise_budget_remaining !== undefined
      ? Math.round(opsec.noise_budget_remaining * 100) + '%'
      : '—';
    const signals = (opsec.defensive_signals || []).length;
    const prio = computePriority(action);
    const isExpanded = expandedAction === action.action_id;

    let formHtml = '';
    if (isExpanded && action._formType === 'approve') {
      formHtml = `
        <div class="pa-inline-form">
          <input class="pa-notes-input" id="pa-notes-${escapeHtml(action.action_id)}" type="text" placeholder="Notes (optional)…" />
          <div class="pa-form-btns">
            <button class="pa-confirm-approve" data-id="${escapeHtml(action.action_id)}">Confirm Approve</button>
            <button class="pa-cancel-form">Cancel</button>
          </div>
        </div>`;
    } else if (isExpanded && action._formType === 'deny') {
      formHtml = `
        <div class="pa-inline-form">
          <input class="pa-reason-input" id="pa-reason-${escapeHtml(action.action_id)}" type="text" placeholder="Reason for denial (optional)…" />
          <div class="pa-form-btns">
            <button class="pa-confirm-deny" data-id="${escapeHtml(action.action_id)}">Confirm Deny</button>
            <button class="pa-cancel-form">Cancel</button>
          </div>
        </div>`;
    }

    return `
      <div class="pa-card" data-action-id="${escapeHtml(action.action_id)}">
        <div class="pa-card-header">
          <span class="pa-technique">${escapeHtml(action.technique || 'unknown')}</span>
          <span class="pa-prio ${prio.cls}">${prio.label}</span>
          <span class="pa-validation ${action.validation_result === 'warning_only' ? 'pa-warn' : 'pa-valid'}">${escapeHtml(action.validation_result)}</span>
        </div>
        <div class="pa-description">${escapeHtml(action.description)}</div>
        <div class="pa-meta">
          ${action.target_node ? `<span class="pa-meta-item">Target: <strong>${escapeHtml(action.target_node)}</strong></span>` : ''}
          ${action.target_ip ? `<span class="pa-meta-item">IP: <strong>${escapeHtml(action.target_ip)}</strong></span>` : ''}
          <span class="pa-meta-item">Budget: <strong>${budgetPct}</strong></span>
          <span class="pa-meta-item">Approach: <strong class="pa-approach-${approach}">${approach}</strong></span>
          ${signals > 0 ? `<span class="pa-meta-item pa-signals">Signals: <strong>${signals}</strong></span>` : ''}
        </div>
        <div class="pa-actions-row">
          <button class="pa-approve-btn" data-id="${escapeHtml(action.action_id)}">Approve</button>
          <button class="pa-deny-btn" data-id="${escapeHtml(action.action_id)}">Deny</button>
          <span class="pa-countdown" data-countdown-id="${escapeHtml(action.action_id)}">${timeLeftStr}</span>
        </div>
        ${formHtml}
      </div>`;
  }

  // --- Inline form toggles ---

  function toggleApproveForm(actionId) {
    if (expandedAction === actionId) { expandedAction = null; }
    else { expandedAction = actionId; setFormType(actionId, 'approve'); }
    renderPendingList(pending);
  }

  function toggleDenyForm(actionId) {
    if (expandedAction === actionId) { expandedAction = null; }
    else { expandedAction = actionId; setFormType(actionId, 'deny'); }
    renderPendingList(pending);
  }

  function setFormType(actionId, type) {
    const action = pending.find(a => a.action_id === actionId);
    if (action) action._formType = type;
  }

  // --- Approve / Deny with notes ---

  async function confirmApprove(actionId) {
    const input = document.getElementById(`pa-notes-${actionId}`);
    const notes = input ? input.value.trim() : '';
    try {
      const res = await fetch(`/api/actions/${actionId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(notes ? { notes } : {}),
      });
      if (res.ok) { expandedAction = null; fetchPending(); }
    } catch { /* network error */ }
  }

  async function confirmDeny(actionId) {
    const input = document.getElementById(`pa-reason-${actionId}`);
    const reason = input ? input.value.trim() : '';
    try {
      const res = await fetch(`/api/actions/${actionId}/deny`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reason ? { reason } : {}),
      });
      if (res.ok) { expandedAction = null; fetchPending(); }
    } catch { /* network error */ }
  }

  // --- Bulk operations ---

  function getSimilarGroups(list) {
    const groups = {};
    for (const action of list) {
      const key = action.technique || 'unknown';
      if (!groups[key]) groups[key] = [];
      groups[key].push(action);
    }
    return groups;
  }

  function updateBulkButtons(list) {
    const groups = getSimilarGroups(list);
    const hasBulk = Object.values(groups).some(g => g.length >= 2);
    const approveBtn = document.getElementById('pa-bulk-approve');
    const denyBtn = document.getElementById('pa-bulk-deny');
    if (approveBtn) approveBtn.style.display = hasBulk ? '' : 'none';
    if (denyBtn) denyBtn.style.display = hasBulk ? '' : 'none';
  }

  async function bulkApprove() {
    const groups = getSimilarGroups(pending);
    const bulkGroups = Object.entries(groups).filter(([, g]) => g.length >= 2);
    if (bulkGroups.length === 0) return;
    const techniqueList = bulkGroups.map(([t, g]) => `${t} (${g.length})`).join(', ');
    if (!confirm(`Bulk approve similar actions?\n${techniqueList}`)) return;
    for (const [, group] of bulkGroups) {
      for (const action of group) {
        try {
          await fetch(`/api/actions/${action.action_id}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ notes: 'bulk approved' }),
          });
        } catch { /* skip */ }
      }
    }
    expandedAction = null;
    fetchPending();
  }

  async function bulkDeny() {
    const groups = getSimilarGroups(pending);
    const bulkGroups = Object.entries(groups).filter(([, g]) => g.length >= 2);
    if (bulkGroups.length === 0) return;
    const techniqueList = bulkGroups.map(([t, g]) => `${t} (${g.length})`).join(', ');
    const reason = prompt(`Bulk deny similar actions?\n${techniqueList}\n\nReason (optional):`);
    if (reason === null) return; // cancelled
    for (const [, group] of bulkGroups) {
      for (const action of group) {
        try {
          await fetch(`/api/actions/${action.action_id}/deny`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(reason ? { reason } : {}),
          });
        } catch { /* skip */ }
      }
    }
    expandedAction = null;
    fetchPending();
  }

  // --- Countdown timers ---

  function startCountdowns(list) {
    const activeIds = new Set(list.map(a => a.action_id));
    for (const [id, timer] of Object.entries(countdownTimers)) {
      if (!activeIds.has(id)) {
        clearInterval(timer);
        delete countdownTimers[id];
      }
    }
    for (const action of list) {
      if (countdownTimers[action.action_id]) continue;
      countdownTimers[action.action_id] = setInterval(() => {
        const el = document.querySelector(`[data-countdown-id="${action.action_id}"]`);
        if (!el) return;
        const timeLeft = getTimeLeftMs(action.timeout_at);
        el.textContent = formatCountdown(timeLeft);
        if (timeLeft <= 0) {
          clearInterval(countdownTimers[action.action_id]);
          delete countdownTimers[action.action_id];
          fetchPending();
        }
      }, 1000);
    }
  }

  function getTimeLeftMs(timeoutAt) {
    return new Date(timeoutAt).getTime() - Date.now();
  }

  function formatCountdown(ms) {
    if (ms <= 0) return 'auto-approving…';
    const s = Math.ceil(ms / 1000);
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  }

  // Legacy direct approve (used by keyboard shortcut 'a')
  async function approveAction(actionId) {
    try {
      const res = await fetch(`/api/actions/${actionId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (res.ok) fetchPending();
    } catch { /* ignore network errors */ }
  }

  // Legacy direct deny (used by keyboard shortcut 'd')
  async function denyAction(actionId) {
    try {
      const reason = prompt('Reason for denial (optional):');
      const res = await fetch(`/api/actions/${actionId}/deny`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: reason || undefined }),
      });
      if (res.ok) fetchPending();
    } catch { /* ignore network errors */ }
  }

  // WebSocket handler — called by ws.js when action events arrive
  function handleWsEvent(event) {
    if (event.type === 'action_pending' || event.type === 'action_resolved') {
      fetchPending();
    }
  }

  return { init, destroy, fetchPending, handleWsEvent, approveAction, denyAction };
})();
