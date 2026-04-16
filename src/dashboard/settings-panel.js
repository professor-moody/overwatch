// ============================================================
// Settings Panel — Full Engagement Configuration
// Identity, Scope, Objectives, Failure Patterns, OPSEC, Frontier Weights
// ============================================================
(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);

  function esc(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  // ====================================================
  // Engagement Identity
  // ====================================================
  const cfgName = $('#cfg-name');
  const cfgProfile = $('#cfg-profile');
  const cfgCommunityRes = $('#cfg-community-res');
  const cfgCommunityResVal = $('#cfg-community-res-val');
  const cfgId = $('#cfg-id');
  const cfgCreatedAt = $('#cfg-created-at');
  const cfgTemplate = $('#cfg-template');

  if (cfgCommunityRes) {
    cfgCommunityRes.addEventListener('input', () => {
      cfgCommunityResVal.textContent = parseFloat(cfgCommunityRes.value).toFixed(1);
    });
  }

  // ====================================================
  // Scope Editor — Tag Lists
  // ====================================================
  const SCOPE_FIELDS = [
    { id: 'cfg-cidrs', key: 'cidrs' },
    { id: 'cfg-domains', key: 'domains' },
    { id: 'cfg-exclusions', key: 'exclusions' },
    { id: 'cfg-hosts', key: 'hosts' },
    { id: 'cfg-url-patterns', key: 'url_patterns' },
    { id: 'cfg-aws-accounts', key: 'aws_accounts' },
    { id: 'cfg-azure-subscriptions', key: 'azure_subscriptions' },
    { id: 'cfg-gcp-projects', key: 'gcp_projects' },
  ];

  // Keep scope data in-memory for tag management
  let scopeData = {};

  function renderTags(containerId, items) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = (items || []).map((val, i) =>
      `<span class="cfg-tag">${esc(val)}<button class="cfg-tag-remove" data-container="${containerId}" data-index="${i}">✕</button></span>`
    ).join('');
  }

  function renderAllTags() {
    for (const f of SCOPE_FIELDS) {
      renderTags(f.id, scopeData[f.key] || []);
    }
  }

  // Wire tag add buttons
  document.querySelectorAll('[data-tag-target]').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.tagTarget;
      const field = SCOPE_FIELDS.find(f => f.id === targetId);
      if (!field) return;
      const input = document.getElementById(targetId + '-input');
      const val = input?.value?.trim();
      if (!val) return;
      if (!scopeData[field.key]) scopeData[field.key] = [];
      if (!scopeData[field.key].includes(val)) {
        scopeData[field.key].push(val);
        renderTags(targetId, scopeData[field.key]);
      }
      if (input) input.value = '';
    });
  });

  // Wire tag add on Enter key
  document.querySelectorAll('.cfg-tag-input').forEach(input => {
    input.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter') return;
      e.preventDefault();
      const btn = input.parentElement?.querySelector('[data-tag-target]');
      if (btn) btn.click();
    });
  });

  // Wire tag remove via event delegation
  document.addEventListener('click', (e) => {
    const rm = e.target.closest('.cfg-tag-remove');
    if (!rm) return;
    const containerId = rm.dataset.container;
    const idx = parseInt(rm.dataset.index, 10);
    const field = SCOPE_FIELDS.find(f => f.id === containerId);
    if (!field || !scopeData[field.key]) return;
    scopeData[field.key].splice(idx, 1);
    renderTags(containerId, scopeData[field.key]);
  });

  // Save Scope
  const scopeSaveBtn = $('#cfg-scope-save');
  const scopeStatus = $('#cfg-scope-status');
  if (scopeSaveBtn) {
    scopeSaveBtn.addEventListener('click', async () => {
      try {
        const resp = await fetch('/api/config/scope', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(scopeData),
        });
        const data = await resp.json();
        if (scopeStatus) {
          scopeStatus.textContent = data.updated ? 'Saved ✓' : 'Error';
          scopeStatus.className = 'settings-save-status ' + (data.updated ? 'ok' : 'error');
          setTimeout(() => { scopeStatus.textContent = ''; }, 3000);
        }
      } catch {
        if (scopeStatus) {
          scopeStatus.textContent = 'Error saving';
          scopeStatus.className = 'settings-save-status error';
        }
      }
    });
  }

  // ====================================================
  // Objectives Editor
  // ====================================================
  const objList = $('#cfg-objectives-list');
  const objForm = $('#cfg-obj-form');
  const objAddBtn = $('#cfg-obj-add-btn');
  const objSubmit = $('#cfg-obj-submit');
  const objCancel = $('#cfg-obj-cancel');
  let objectives = [];

  function renderObjectives() {
    if (!objList) return;
    if (objectives.length === 0) {
      objList.innerHTML = '<div class="empty-state" style="font-size:12px">No objectives defined</div>';
      return;
    }
    objList.innerHTML = objectives.map(o => `
      <div class="cfg-obj-card ${o.achieved ? 'achieved' : ''}">
        <input type="checkbox" class="cfg-obj-check" data-id="${o.id}" ${o.achieved ? 'checked' : ''} title="Mark achieved" />
        <div class="cfg-obj-body">
          <div class="cfg-obj-desc">${esc(o.description)}</div>
          <div class="cfg-obj-meta">
            ${o.target_node_type ? `<span>type: ${esc(o.target_node_type)}</span>` : ''}
            ${o.achievement_edge_types?.length ? `<span>edges: ${o.achievement_edge_types.map(e => esc(e)).join(', ')}</span>` : ''}
            ${o.achieved_at ? `<span>✓ ${new Date(o.achieved_at).toLocaleDateString()}</span>` : ''}
          </div>
        </div>
        <button class="cfg-obj-remove" data-id="${o.id}" title="Delete objective">✕</button>
      </div>
    `).join('');

    // Wire checkboxes
    objList.querySelectorAll('.cfg-obj-check').forEach(cb => {
      cb.addEventListener('change', async () => {
        await fetch(`/api/config/objectives/${cb.dataset.id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ achieved: cb.checked }),
        });
        await loadConfig();
      });
    });

    // Wire remove buttons
    objList.querySelectorAll('.cfg-obj-remove').forEach(btn => {
      btn.addEventListener('click', async () => {
        await fetch(`/api/config/objectives/${btn.dataset.id}`, { method: 'DELETE' });
        await loadConfig();
      });
    });
  }

  if (objAddBtn) objAddBtn.addEventListener('click', () => { if (objForm) objForm.style.display = ''; });
  if (objCancel) objCancel.addEventListener('click', () => { if (objForm) objForm.style.display = 'none'; });
  if (objSubmit) {
    objSubmit.addEventListener('click', async () => {
      const desc = $('#cfg-obj-desc')?.value?.trim();
      if (!desc) return;
      const nodeType = $('#cfg-obj-node-type')?.value || undefined;
      const edgeTypesRaw = $('#cfg-obj-edge-types')?.value?.trim();
      const edgeTypes = edgeTypesRaw ? edgeTypesRaw.split(',').map(s => s.trim()).filter(Boolean) : undefined;
      await fetch('/api/config/objectives', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: desc, target_node_type: nodeType, achievement_edge_types: edgeTypes }),
      });
      if ($('#cfg-obj-desc')) $('#cfg-obj-desc').value = '';
      if ($('#cfg-obj-node-type')) $('#cfg-obj-node-type').value = '';
      if ($('#cfg-obj-edge-types')) $('#cfg-obj-edge-types').value = '';
      if (objForm) objForm.style.display = 'none';
      await loadConfig();
    });
  }

  // ====================================================
  // Failure Patterns
  // ====================================================
  const fpList = $('#cfg-failure-patterns');
  const fpForm = $('#cfg-fp-form');
  const fpAddBtn = $('#cfg-fp-add-btn');
  const fpSubmit = $('#cfg-fp-submit');
  const fpCancel = $('#cfg-fp-cancel');
  let failurePatterns = [];

  function renderFailurePatterns() {
    if (!fpList) return;
    if (failurePatterns.length === 0) {
      fpList.innerHTML = '<div class="empty-state" style="font-size:12px">No failure patterns</div>';
      return;
    }
    fpList.innerHTML = failurePatterns.map((fp, i) => `
      <div class="cfg-fp-row">
        <span class="cfg-fp-technique">${esc(fp.technique)}</span>
        ${fp.target_pattern ? `<span class="cfg-fp-target">${esc(fp.target_pattern)}</span>` : ''}
        <span class="cfg-fp-warning">${esc(fp.warning)}</span>
        <button class="cfg-fp-remove" data-index="${i}" title="Remove">✕</button>
      </div>
    `).join('');

    fpList.querySelectorAll('.cfg-fp-remove').forEach(btn => {
      btn.addEventListener('click', async () => {
        const idx = parseInt(btn.dataset.index, 10);
        failurePatterns.splice(idx, 1);
        await fetch('/api/config', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ failure_patterns: failurePatterns }),
        });
        renderFailurePatterns();
      });
    });
  }

  if (fpAddBtn) fpAddBtn.addEventListener('click', () => { if (fpForm) fpForm.style.display = ''; });
  if (fpCancel) fpCancel.addEventListener('click', () => { if (fpForm) fpForm.style.display = 'none'; });
  if (fpSubmit) {
    fpSubmit.addEventListener('click', async () => {
      const technique = $('#cfg-fp-technique')?.value?.trim();
      const target = $('#cfg-fp-target')?.value?.trim() || undefined;
      const warning = $('#cfg-fp-warning')?.value?.trim();
      if (!technique || !warning) return;
      failurePatterns.push({ technique, target_pattern: target, warning });
      await fetch('/api/config', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ failure_patterns: failurePatterns }),
      });
      if ($('#cfg-fp-technique')) $('#cfg-fp-technique').value = '';
      if ($('#cfg-fp-target')) $('#cfg-fp-target').value = '';
      if ($('#cfg-fp-warning')) $('#cfg-fp-warning').value = '';
      if (fpForm) fpForm.style.display = 'none';
      renderFailurePatterns();
    });
  }

  // ====================================================
  // OPSEC Settings (existing)
  // ====================================================
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

  // --- Load engagement config ---
  async function loadConfig() {
    try {
      const resp = await fetch('/api/config');
      if (!resp.ok) return;
      const config = await resp.json();

      // Identity
      if (cfgName) cfgName.value = config.name || '';
      if (cfgProfile) cfgProfile.value = config.profile || '';
      if (cfgCommunityRes) {
        cfgCommunityRes.value = config.community_resolution ?? 1.0;
        if (cfgCommunityResVal) cfgCommunityResVal.textContent = parseFloat(cfgCommunityRes.value).toFixed(1);
      }
      if (cfgId) cfgId.textContent = config.id || '—';
      if (cfgCreatedAt) cfgCreatedAt.textContent = config.created_at ? new Date(config.created_at).toLocaleString() : '—';
      if (cfgTemplate) cfgTemplate.textContent = config.template || '—';

      // Scope
      scopeData = { ...config.scope };
      renderAllTags();

      // Objectives
      objectives = config.objectives || [];
      renderObjectives();

      // Failure patterns
      failurePatterns = config.failure_patterns || [];
      renderFailurePatterns();
    } catch (err) {
      console.error('[settings] config load failed:', err);
    }
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

  const healthRefreshBtn = $('#health-refresh-btn');
  if (healthRefreshBtn) healthRefreshBtn.addEventListener('click', loadHealthStatus);

  // --- Save settings ---
  async function saveSettings() {
    // Save identity fields via /api/config
    const configBody = {};
    if (cfgName?.value) configBody.name = cfgName.value.trim();
    if (cfgProfile) configBody.profile = cfgProfile.value || undefined;
    if (cfgCommunityRes) configBody.community_resolution = parseFloat(cfgCommunityRes.value);

    // Save OPSEC
    const opsecBody = {
      max_noise: parseFloat(maxNoiseSlider?.value || '0.7'),
      approval_mode: approvalMode?.value || 'approve-critical',
      approval_timeout_ms: parseInt(timeoutSlider?.value || '300', 10) * 1000,
      blacklisted_techniques: (blacklist?.value || '').split('\n').map(s => s.trim()).filter(Boolean),
    };

    // Time window
    const startH = twStart?.value ? parseInt(twStart.value, 10) : null;
    const endH = twEnd?.value ? parseInt(twEnd.value, 10) : null;
    if (startH !== null && endH !== null && !isNaN(startH) && !isNaN(endH)) {
      opsecBody.time_window = { start_hour: startH, end_hour: endH };
    } else {
      opsecBody.time_window = null;
    }

    configBody.opsec = opsecBody;

    try {
      const resp = await fetch('/api/config', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(configBody),
      });
      const data = await resp.json();
      if (saveStatus) {
        saveStatus.textContent = data.updated ? 'Saved ✓' : 'No changes';
        saveStatus.className = 'settings-save-status ' + (data.updated ? 'ok' : '');
        setTimeout(() => { saveStatus.textContent = ''; }, 3000);
      }
      // Reload to refresh
      loadConfig();
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
  if (refreshBtn) refreshBtn.addEventListener('click', () => { loadConfig(); loadSettings(); });

  // --- Auto-load when panel becomes active ---
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.target.id === 'panel-settings' && m.target.classList.contains('active')) {
        loadConfig();
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
