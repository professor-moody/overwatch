// ============================================================
// Settings Panel — Runtime OPSEC & Health Configuration
// ============================================================
(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);

  // --- Elements ---
  const maxNoiseSlider = $('#set-max-noise');
  const maxNoiseVal = $('#set-max-noise-val');
  const approvalMode = $('#set-approval-mode');
  const timeoutSlider = $('#set-approval-timeout');
  const timeoutVal = $('#set-approval-timeout-val');
  const twStart = $('#set-tw-start');
  const twEnd = $('#set-tw-end');
  const twClear = $('#set-tw-clear');
  const blacklist = $('#set-blacklist');
  const noiseBar = $('#set-noise-bar');
  const noiseLabel = $('#set-noise-label');
  const ceilingVal = $('#set-ceiling');
  const hostCeilingVal = $('#set-host-ceiling');
  const profileVal = $('#set-profile');
  const healthStatus = $('#settings-health-status');
  const saveBtn = $('#settings-save');
  const saveStatus = $('#settings-save-status');
  const refreshBtn = $('#settings-refresh');

  // --- Slider live update ---
  if (maxNoiseSlider) {
    maxNoiseSlider.addEventListener('input', () => {
      maxNoiseVal.textContent = parseFloat(maxNoiseSlider.value).toFixed(2);
    });
  }
  if (timeoutSlider) {
    timeoutSlider.addEventListener('input', () => {
      timeoutVal.textContent = timeoutSlider.value + 's';
    });
  }

  // --- Load settings ---
  async function loadSettings() {
    try {
      const resp = await fetch('/api/settings');
      if (!resp.ok) return;
      const data = await resp.json();

      // OPSEC
      if (maxNoiseSlider) {
        maxNoiseSlider.value = data.opsec.max_noise;
        maxNoiseVal.textContent = parseFloat(data.opsec.max_noise).toFixed(2);
      }
      if (approvalMode) {
        approvalMode.value = data.opsec.approval_mode || 'approve-critical';
      }
      if (timeoutSlider) {
        const secs = Math.round((data.opsec.approval_timeout_ms || 300000) / 1000);
        timeoutSlider.value = secs;
        timeoutVal.textContent = secs + 's';
      }
      if (twStart && twEnd) {
        if (data.opsec.time_window) {
          twStart.value = data.opsec.time_window.start_hour;
          twEnd.value = data.opsec.time_window.end_hour;
        } else {
          twStart.value = '';
          twEnd.value = '';
        }
      }
      if (blacklist) {
        blacklist.value = (data.opsec.blacklisted_techniques || []).join('\n');
      }

      // Noise state
      const spent = data.noise_state.global_noise_spent || 0;
      const max = data.opsec.max_noise || 1;
      const pct = Math.min(100, (spent / max) * 100);
      if (noiseBar) {
        noiseBar.style.width = pct + '%';
        noiseBar.className = 'settings-gauge-bar' + (pct > 85 ? ' danger' : pct > 60 ? ' warn' : '');
      }
      if (noiseLabel) {
        noiseLabel.textContent = spent.toFixed(2) + ' / ' + max.toFixed(2);
      }
      if (ceilingVal) ceilingVal.textContent = Math.round(data.noise_state.noise_ceiling_ratio * 100) + '%';
      if (hostCeilingVal) hostCeilingVal.textContent = Math.round(data.noise_state.per_host_ceiling_ratio * 100) + '%';
      if (profileVal) profileVal.textContent = data.profile || '—';

      // Health
      loadHealthStatus();
    } catch (err) {
      console.error('[settings] load failed:', err);
    }
  }

  async function loadHealthStatus() {
    if (!healthStatus) return;
    healthStatus.innerHTML = '<div class="settings-health"><span class="settings-health-dot"></span><span>Loading…</span></div>';
    try {
      const resp = await fetch('/api/health');
      if (!resp.ok) throw new Error('API error');
      const data = await resp.json();

      const stats = data.graph_stats || {};
      const nodeTypes = stats.node_types || {};
      const checks = data.health_checks || {};
      const totalIssues = (checks.warnings || []).length + (checks.errors || []).length;
      const dotClass = totalIssues === 0 ? 'ok' : (checks.errors || []).length > 0 ? 'error' : 'warn';

      let html = `<div class="settings-health"><span class="settings-health-dot ${dotClass}"></span>
        <span>${stats.nodes || 0} nodes, ${stats.edges || 0} edges${data.ad_context ? ' (AD)' : ''}</span></div>`;

      // Node type breakdown
      const typeEntries = Object.entries(nodeTypes).sort((a, b) => b[1] - a[1]);
      if (typeEntries.length > 0) {
        html += '<div style="margin-top:8px;font-size:12px;color:var(--text-secondary)">';
        html += typeEntries.map(([t, c]) => `${t}: ${c}`).join(' · ');
        html += '</div>';
      }

      // Health issues
      if (totalIssues > 0) {
        html += '<div style="margin-top:8px">';
        for (const err of (checks.errors || [])) {
          html += `<div style="font-size:12px;color:var(--red)">✕ ${esc(err.message || err)}</div>`;
        }
        for (const warn of (checks.warnings || [])) {
          html += `<div style="font-size:12px;color:var(--amber)">⚠ ${esc(warn.message || warn)}</div>`;
        }
        html += '</div>';
      }

      healthStatus.innerHTML = html;
    } catch {
      healthStatus.innerHTML = '<div class="settings-health"><span class="settings-health-dot error"></span><span>Health check failed</span></div>';
    }
  }

  function esc(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  const healthRefreshBtn = $('#health-refresh-btn');
  if (healthRefreshBtn) healthRefreshBtn.addEventListener('click', loadHealthStatus);

  // --- Save settings ---
  async function saveSettings() {
    const body = {
      max_noise: parseFloat(maxNoiseSlider?.value || '0.7'),
      approval_mode: approvalMode?.value || 'approve-critical',
      approval_timeout_ms: parseInt(timeoutSlider?.value || '300', 10) * 1000,
      blacklisted_techniques: (blacklist?.value || '').split('\n').map(s => s.trim()).filter(Boolean),
    };

    // Time window
    const startH = twStart?.value ? parseInt(twStart.value, 10) : null;
    const endH = twEnd?.value ? parseInt(twEnd.value, 10) : null;
    if (startH !== null && endH !== null && !isNaN(startH) && !isNaN(endH)) {
      body.time_window = { start_hour: startH, end_hour: endH };
    } else {
      body.time_window = null;
    }

    try {
      const resp = await fetch('/api/settings', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await resp.json();
      if (saveStatus) {
        saveStatus.textContent = data.updated ? 'Saved ✓' : 'No changes';
        saveStatus.className = 'settings-save-status ' + (data.updated ? 'ok' : '');
        setTimeout(() => { saveStatus.textContent = ''; }, 3000);
      }
      // Reload to refresh noise gauge
      loadSettings();
    } catch (err) {
      if (saveStatus) {
        saveStatus.textContent = 'Error saving';
        saveStatus.className = 'settings-save-status error';
      }
    }
  }

  // --- Clear time window ---
  if (twClear) {
    twClear.addEventListener('click', () => {
      if (twStart) twStart.value = '';
      if (twEnd) twEnd.value = '';
    });
  }

  // --- Wire buttons ---
  if (saveBtn) saveBtn.addEventListener('click', saveSettings);
  if (refreshBtn) refreshBtn.addEventListener('click', loadSettings);

  // --- Auto-load when panel becomes active ---
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.target.id === 'panel-settings' && m.target.classList.contains('active')) {
        loadSettings();
        loadFrontierWeights();
      }
    }
  });
  const settingsPanel = $('#panel-settings');
  if (settingsPanel) {
    observer.observe(settingsPanel, { attributes: true, attributeFilter: ['class'] });
  }

  // ====================================================
  // Frontier Weights Editor
  // ====================================================
  const fwFanoutTable = $('#fw-fanout-table');
  const fwNoiseTable = $('#fw-noise-table');
  const fwSaveBtn = $('#fw-save');
  const fwResetBtn = $('#fw-reset');
  const fwSaveStatus = $('#fw-save-status');

  function renderWeightTable(container, data, inputClass) {
    if (!container) return;
    container.innerHTML = '';
    const keys = Object.keys(data).sort((a, b) => a === 'default' ? 1 : b === 'default' ? -1 : a.localeCompare(b));
    for (const key of keys) {
      const row = document.createElement('div');
      row.className = 'fw-row';
      row.innerHTML = `<span class="fw-key">${key}</span><input class="fw-input" type="number" step="any" data-key="${key}" value="${data[key]}" />`;
      container.appendChild(row);
    }
  }

  async function loadFrontierWeights() {
    try {
      const resp = await fetch('/api/frontier/weights');
      if (!resp.ok) return;
      const data = await resp.json();
      renderWeightTable(fwFanoutTable, data.fan_out, 'fw-fanout');
      renderWeightTable(fwNoiseTable, data.noise, 'fw-noise');
    } catch (err) {
      console.error('[settings] frontier weights load failed:', err);
    }
  }

  function collectWeights(container) {
    const result = {};
    if (!container) return result;
    container.querySelectorAll('.fw-input').forEach(input => {
      const val = parseFloat(input.value);
      if (!isNaN(val)) result[input.dataset.key] = val;
    });
    return result;
  }

  async function saveFrontierWeights() {
    const body = {
      fan_out: collectWeights(fwFanoutTable),
      noise: collectWeights(fwNoiseTable),
    };
    try {
      const resp = await fetch('/api/frontier/weights', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await resp.json();
      if (fwSaveStatus) {
        fwSaveStatus.textContent = data.updated ? 'Saved ✓' : 'Error';
        fwSaveStatus.className = 'settings-save-status ' + (data.updated ? 'ok' : 'error');
        setTimeout(() => { fwSaveStatus.textContent = ''; }, 3000);
      }
    } catch (err) {
      if (fwSaveStatus) {
        fwSaveStatus.textContent = 'Error saving';
        fwSaveStatus.className = 'settings-save-status error';
      }
    }
  }

  async function resetFrontierWeights() {
    try {
      await fetch('/api/frontier/weights/reset', { method: 'POST' });
      loadFrontierWeights();
      if (fwSaveStatus) {
        fwSaveStatus.textContent = 'Reset ✓';
        fwSaveStatus.className = 'settings-save-status ok';
        setTimeout(() => { fwSaveStatus.textContent = ''; }, 3000);
      }
    } catch (err) {
      console.error('[settings] reset failed:', err);
    }
  }

  if (fwSaveBtn) fwSaveBtn.addEventListener('click', saveFrontierWeights);
  if (fwResetBtn) fwResetBtn.addEventListener('click', resetFrontierWeights);
})();
