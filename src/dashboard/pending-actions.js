// ============================================================
// Overwatch Dashboard — Pending Actions Panel
// Approval gate UI: shows pending actions, approve/deny buttons,
// countdown timer for auto-approve timeout.
// ============================================================

window.OverwatchPendingActions = (() => {
  let pollTimer = null;
  let pending = [];
  let countdownTimers = {};

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function init() {
    fetchPending();
    pollTimer = setInterval(fetchPending, 2000);
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
    } catch { /* network error — keep stale data */ }
  }

  function updateCount(list) {
    const el = document.getElementById('pending-actions-count');
    if (!el) return;
    el.textContent = `(${list.length})`;
    // Highlight badge when actions pending
    if (list.length > 0) {
      el.classList.add('pending-actions-badge');
    } else {
      el.classList.remove('pending-actions-badge');
    }
  }

  function renderPendingList(list) {
    const container = document.getElementById('pending-actions-list');
    if (!container) return;

    if (list.length === 0) {
      container.innerHTML = '<div class="empty-state">No pending actions</div>';
      // Clear all countdown timers
      Object.values(countdownTimers).forEach(clearInterval);
      countdownTimers = {};
      return;
    }

    container.innerHTML = list.map(action => renderActionCard(action)).join('');

    // Wire up buttons
    container.querySelectorAll('.pa-approve-btn').forEach(btn => {
      btn.addEventListener('click', () => approveAction(btn.dataset.id));
    });
    container.querySelectorAll('.pa-deny-btn').forEach(btn => {
      btn.addEventListener('click', () => denyAction(btn.dataset.id));
    });

    // Start countdown timers for each pending action
    startCountdowns(list);
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

    return `
      <div class="pa-card" data-action-id="${escapeHtml(action.action_id)}">
        <div class="pa-card-header">
          <span class="pa-technique">${escapeHtml(action.technique || 'unknown')}</span>
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
      </div>`;
  }

  function startCountdowns(list) {
    // Clear old timers for actions no longer pending
    const activeIds = new Set(list.map(a => a.action_id));
    for (const [id, timer] of Object.entries(countdownTimers)) {
      if (!activeIds.has(id)) {
        clearInterval(timer);
        delete countdownTimers[id];
      }
    }
    // Start new timers
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
          fetchPending(); // Refresh to pick up auto-approve
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

  return { init, destroy, fetchPending, handleWsEvent };
})();
