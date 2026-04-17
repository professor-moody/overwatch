// ============================================================
// Overwatch — Engagements Panel
// Create and browse engagement configs
// ============================================================

(function () {
  'use strict';

  /* ---- state ---- */
  let engagements = [];
  let activeId = null;
  let templates = [];
  let formVisible = false;

  /* ---- tag input helpers ---- */
  function TagInput(listId, inputId) {
    const list = document.getElementById(listId);
    const input = document.getElementById(inputId);
    const tags = [];
    if (!list || !input) return { getTags: () => [], clear: () => {}, setTags: () => {} };

    function render() {
      list.innerHTML = tags.map((t, i) =>
        `<span class="cfg-tag">${esc(t)}<button class="cfg-tag-remove" data-i="${i}">×</button></span>`
      ).join('');
    }

    list.addEventListener('click', e => {
      const btn = e.target.closest('[data-i]');
      if (btn) { tags.splice(parseInt(btn.dataset.i, 10), 1); render(); }
    });
    input.addEventListener('keydown', e => {
      if ((e.key === 'Enter' || e.key === ',') && input.value.trim()) {
        e.preventDefault();
        const val = input.value.trim().replace(/,$/, '');
        if (val && !tags.includes(val)) tags.push(val);
        input.value = '';
        render();
      }
    });
    return {
      getTags: () => [...tags],
      clear: () => { tags.length = 0; render(); },
      setTags: (newTags) => { tags.length = 0; tags.push(...newTags); render(); },
    };
  }

  /* ---- opsec noise → select value ---- */
  function noiseToOpsec(maxNoise) {
    if (maxNoise <= 0.2) return 'stealth';
    if (maxNoise <= 0.5) return 'normal';
    if (maxNoise <= 0.7) return 'pentest';
    return 'loud';
  }

  /* ---- init ---- */
  window.initEngagementsPanel = function () {
    const panel = document.getElementById('panel-engagements');
    if (!panel) return;

    const cidrInput = TagInput('eng-form-cidrs', 'eng-form-cidr-input');
    const domainInput = TagInput('eng-form-domains', 'eng-form-domain-input');
    const exclusionInput = TagInput('eng-form-exclusions', 'eng-form-exclusion-input');

    document.getElementById('eng-new-btn')?.addEventListener('click', () => toggleForm(true));
    document.getElementById('eng-form-cancel')?.addEventListener('click', () => {
      resetForm(cidrInput, domainInput, exclusionInput);
      toggleForm(false);
    });
    document.getElementById('eng-form-submit')?.addEventListener('click', () =>
      submitForm(cidrInput, domainInput, exclusionInput));

    // Objective rows
    document.getElementById('eng-add-obj-btn')?.addEventListener('click', addObjectiveRow);

    // Template picker change handler
    document.getElementById('eng-form-template')?.addEventListener('change', e => {
      applyTemplate(e.target.value);
    });

    loadTemplates();
    loadEngagements();
  };

  /* ---- template loading ---- */
  async function loadTemplates() {
    try {
      const res = await fetch('/api/templates');
      const data = await res.json();
      templates = data.templates || [];
      populateTemplateSelect();
    } catch {
      // non-fatal — form still works without templates
    }
  }

  function populateTemplateSelect() {
    const sel = document.getElementById('eng-form-template');
    if (!sel) return;
    // Remove all except first option (the "None" placeholder)
    while (sel.options.length > 1) sel.remove(1);
    templates.forEach(t => {
      const opt = document.createElement('option');
      opt.value = t.id;
      opt.textContent = t.name + (t.description ? ` — ${t.description.slice(0, 60)}` : '');
      sel.appendChild(opt);
    });
  }

  /* ---- template pre-fill ---- */
  function applyTemplate(templateId) {
    const profileSel = document.getElementById('eng-form-profile');
    const opsecSel = document.getElementById('eng-form-opsec');
    const objRows = document.getElementById('eng-obj-rows');

    if (!templateId) {
      // Reset to defaults
      if (profileSel) profileSel.value = 'network';
      if (opsecSel) opsecSel.value = 'pentest';
      if (objRows) objRows.innerHTML = '';
      return;
    }

    const tmpl = templates.find(t => t.id === templateId);
    if (!tmpl) return;

    // Set profile
    if (profileSel && tmpl.profile) profileSel.value = tmpl.profile;

    // Set opsec
    if (opsecSel && tmpl.opsec && tmpl.opsec.max_noise != null) {
      opsecSel.value = noiseToOpsec(tmpl.opsec.max_noise);
    }

    // Pre-fill objective rows from template
    if (objRows && Array.isArray(tmpl.objectives) && tmpl.objectives.length > 0) {
      objRows.innerHTML = '';
      tmpl.objectives.forEach(obj => {
        addObjectiveRow(obj.description || '');
      });
    }
  }

  /* ---- form visibility ---- */
  function toggleForm(show) {
    formVisible = show;
    const form = document.getElementById('eng-form');
    const list = document.getElementById('eng-list-section');
    if (form) form.style.display = show ? 'block' : 'none';
    if (list) list.style.display = show ? 'none' : 'block';
    if (show) document.getElementById('eng-form-name')?.focus();
  }

  /* ---- reset form ---- */
  function resetForm(cidrInput, domainInput, exclusionInput) {
    const name = document.getElementById('eng-form-name');
    const tmpl = document.getElementById('eng-form-template');
    const profile = document.getElementById('eng-form-profile');
    const opsec = document.getElementById('eng-form-opsec');
    const objRows = document.getElementById('eng-obj-rows');
    if (name) name.value = '';
    if (tmpl) tmpl.value = '';
    if (profile) profile.value = 'network';
    if (opsec) opsec.value = 'pentest';
    if (objRows) objRows.innerHTML = '';
    cidrInput.clear();
    domainInput.clear();
    exclusionInput.clear();
  }

  /* ---- load + render list ---- */
  async function loadEngagements() {
    try {
      const res = await fetch('/api/engagements');
      const data = await res.json();
      engagements = data.engagements || [];
      activeId = data.active_id || null;
      renderList();
    } catch {
      renderList();
    }
  }

  function renderList() {
    const container = document.getElementById('eng-list');
    const count = document.getElementById('eng-count');
    if (!container) return;
    if (count) count.textContent = `(${engagements.length})`;

    if (engagements.length === 0) {
      container.innerHTML = '<div class="eng-empty">No engagements yet. Create one above.</div>';
      return;
    }

    container.innerHTML = engagements.map(e => {
      const isActive = e.is_active || e.id === activeId;
      const scopeStr = e.scope_cidrs.length ? e.scope_cidrs.join(', ') : (e.scope_domains.join(', ') || '—');
      return `<div class="eng-card${isActive ? ' eng-card-active' : ''}">
        <div class="eng-card-header">
          <div class="eng-card-name">${esc(e.name)}${isActive ? '<span class="eng-badge eng-badge-active">ACTIVE</span>' : ''}</div>
          <div class="eng-card-meta">
            ${e.profile ? `<span class="eng-badge eng-badge-profile">${esc(e.profile)}</span>` : ''}
            <span class="eng-meta-stat">${e.objectives_count} obj</span>
            <span class="eng-meta-stat">${e.phases_count} phases</span>
          </div>
        </div>
        <div class="eng-card-scope">${esc(scopeStr)}</div>
        <div class="eng-card-footer">
          <span class="eng-card-id mono">${esc(e.id)}</span>
          ${e.created_at ? `<span class="eng-card-date">${new Date(e.created_at).toLocaleDateString()}</span>` : ''}
          ${!isActive ? `<button class="op-btn op-btn-sm eng-card-load-btn" data-id="${esc(e.id)}" title="Restart server with this engagement">Load</button>` : ''}
        </div>
      </div>`;
    }).join('');

    container.querySelectorAll('.eng-card-load-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const eng = engagements.find(e => e.id === btn.dataset.id);
        if (!eng) return;
        showLoadHint(eng);
      });
    });
  }

  function showLoadHint(eng) {
    const hint = document.getElementById('eng-load-hint');
    const path = document.getElementById('eng-load-path');
    if (hint && path) {
      path.textContent = eng.config_path;
      hint.style.display = 'block';
      hint.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  /* ---- objective rows ---- */
  function addObjectiveRow(prefillDesc) {
    const container = document.getElementById('eng-obj-rows');
    if (!container) return;
    const row = document.createElement('div');
    row.className = 'eng-obj-row';
    row.innerHTML = `
      <input type="text" class="cb-input eng-obj-desc" placeholder="e.g. Compromise Domain Controller" />
      <button class="op-btn op-btn-sm eng-obj-remove">✕</button>`;
    if (prefillDesc && typeof prefillDesc === 'string') {
      row.querySelector('.eng-obj-desc').value = prefillDesc;
    }
    row.querySelector('.eng-obj-remove').addEventListener('click', () => row.remove());
    container.appendChild(row);
    if (!prefillDesc) row.querySelector('.eng-obj-desc')?.focus();
  }

  /* ---- submit ---- */
  async function submitForm(cidrInput, domainInput, exclusionInput) {
    const name = document.getElementById('eng-form-name')?.value.trim();
    if (!name) {
      alert('Engagement name is required.');
      return;
    }
    const template_id = document.getElementById('eng-form-template')?.value || undefined;
    const profile = document.getElementById('eng-form-profile')?.value || 'network';
    const opsec_profile = document.getElementById('eng-form-opsec')?.value || 'pentest';
    const cidrs = cidrInput.getTags();
    const domains = domainInput.getTags();
    const exclusions = exclusionInput.getTags();

    const objectives = [];
    document.querySelectorAll('#eng-obj-rows .eng-obj-desc').forEach((inp, i) => {
      const desc = inp.value.trim();
      if (desc) objectives.push({ id: `obj-${i + 1}`, description: desc });
    });

    const btn = document.getElementById('eng-form-submit');
    if (btn) { btn.disabled = true; btn.textContent = 'Creating…'; }

    try {
      const body = { name, profile, opsec_profile, cidrs, domains, exclusions, objectives };
      if (template_id) body.template_id = template_id;

      const res = await fetch('/api/engagements', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert('Error: ' + (err.error || res.statusText));
        return;
      }
      resetForm(cidrInput, domainInput, exclusionInput);
      toggleForm(false);
      await loadEngagements();
    } catch (err) {
      alert('Failed to create engagement: ' + err.message);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Create Engagement'; }
    }
  }

  /* ---- refresh when panel is activated ---- */
  document.addEventListener('panel-activated', e => {
    if (e.detail === 'engagements') loadEngagements();
  });
})();


  /* ---- tag input helpers ---- */
  function TagInput(listId, inputId) {
    const list = document.getElementById(listId);
    const input = document.getElementById(inputId);
    const tags = [];
    if (!list || !input) return { getTags: () => [] };

    function render() {
      list.innerHTML = tags.map((t, i) =>
        `<span class="cfg-tag">${esc(t)}<button class="cfg-tag-remove" data-i="${i}">×</button></span>`
      ).join('');
    }

    list.addEventListener('click', e => {
      const btn = e.target.closest('[data-i]');
      if (btn) { tags.splice(parseInt(btn.dataset.i, 10), 1); render(); }
    });
    input.addEventListener('keydown', e => {
      if ((e.key === 'Enter' || e.key === ',') && input.value.trim()) {
        e.preventDefault();
        const val = input.value.trim().replace(/,$/, '');
        if (val && !tags.includes(val)) tags.push(val);
        input.value = '';
        render();
      }
    });
    return { getTags: () => [...tags], clear: () => { tags.length = 0; render(); } };
  }

  /* ---- init ---- */
  window.initEngagementsPanel = function () {
    const panel = document.getElementById('panel-engagements');
    if (!panel) return;

    const cidrInput = TagInput('eng-form-cidrs', 'eng-form-cidr-input');
    const domainInput = TagInput('eng-form-domains', 'eng-form-domain-input');

    document.getElementById('eng-new-btn')?.addEventListener('click', () => toggleForm(true));
    document.getElementById('eng-form-cancel')?.addEventListener('click', () => toggleForm(false));
    document.getElementById('eng-form-submit')?.addEventListener('click', () => submitForm(cidrInput, domainInput));

    // Objective rows
    document.getElementById('eng-add-obj-btn')?.addEventListener('click', addObjectiveRow);

    loadEngagements();
  };

  /* ---- form visibility ---- */
  function toggleForm(show) {
    formVisible = show;
    const form = document.getElementById('eng-form');
    const list = document.getElementById('eng-list-section');
    if (form) form.style.display = show ? 'block' : 'none';
    if (list) list.style.display = show ? 'none' : 'block';
    if (show) document.getElementById('eng-form-name')?.focus();
  }

  /* ---- load + render list ---- */
  async function loadEngagements() {
    try {
      const res = await fetch('/api/engagements');
      const data = await res.json();
      engagements = data.engagements || [];
      activeId = data.active_id || null;
      renderList();
    } catch {
      renderList();
    }
  }

  function renderList() {
    const container = document.getElementById('eng-list');
    const count = document.getElementById('eng-count');
    if (!container) return;
    if (count) count.textContent = `(${engagements.length})`;

    if (engagements.length === 0) {
      container.innerHTML = '<div class="eng-empty">No engagements yet. Create one above.</div>';
      return;
    }

    container.innerHTML = engagements.map(e => {
      const isActive = e.is_active || e.id === activeId;
      const scopeStr = e.scope_cidrs.length ? e.scope_cidrs.join(', ') : (e.scope_domains.join(', ') || '—');
      return `<div class="eng-card${isActive ? ' eng-card-active' : ''}">
        <div class="eng-card-header">
          <div class="eng-card-name">${esc(e.name)}${isActive ? '<span class="eng-badge eng-badge-active">ACTIVE</span>' : ''}</div>
          <div class="eng-card-meta">
            ${e.profile ? `<span class="eng-badge eng-badge-profile">${esc(e.profile)}</span>` : ''}
            <span class="eng-meta-stat">${e.objectives_count} obj</span>
            <span class="eng-meta-stat">${e.phases_count} phases</span>
          </div>
        </div>
        <div class="eng-card-scope">${esc(scopeStr)}</div>
        <div class="eng-card-footer">
          <span class="eng-card-id mono">${esc(e.id)}</span>
          ${e.created_at ? `<span class="eng-card-date">${new Date(e.created_at).toLocaleDateString()}</span>` : ''}
          ${!isActive ? `<button class="op-btn op-btn-sm eng-card-load-btn" data-id="${esc(e.id)}" title="Restart server with this engagement">Load</button>` : ''}
        </div>
      </div>`;
    }).join('');

    // Load buttons show copy-path hint (server restart required)
    container.querySelectorAll('.eng-card-load-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const eng = engagements.find(e => e.id === btn.dataset.id);
        if (!eng) return;
        showLoadHint(eng);
      });
    });
  }

  function showLoadHint(eng) {
    const hint = document.getElementById('eng-load-hint');
    const path = document.getElementById('eng-load-path');
    if (hint && path) {
      path.textContent = eng.config_path;
      hint.style.display = 'block';
      hint.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  /* ---- objective rows ---- */
  function addObjectiveRow() {
    const container = document.getElementById('eng-obj-rows');
    if (!container) return;
    const row = document.createElement('div');
    row.className = 'eng-obj-row';
    row.innerHTML = `
      <input type="text" class="cb-input eng-obj-desc" placeholder="e.g. Compromise Domain Controller" />
      <button class="op-btn op-btn-sm eng-obj-remove">✕</button>`;
    row.querySelector('.eng-obj-remove').addEventListener('click', () => row.remove());
    container.appendChild(row);
    row.querySelector('.eng-obj-desc')?.focus();
  }

  /* ---- submit ---- */
  async function submitForm(cidrInput, domainInput) {
    const name = document.getElementById('eng-form-name')?.value.trim();
    if (!name) {
      alert('Engagement name is required.');
      return;
    }
    const profile = document.getElementById('eng-form-profile')?.value || 'network';
    const opsec_profile = document.getElementById('eng-form-opsec')?.value || 'pentest';
    const cidrs = cidrInput.getTags();
    const domains = domainInput.getTags();

    // Collect objectives
    const objectives = [];
    document.querySelectorAll('#eng-obj-rows .eng-obj-desc').forEach((inp, i) => {
      const desc = inp.value.trim();
      if (desc) objectives.push({ id: `obj-${i + 1}`, description: desc });
    });

    const btn = document.getElementById('eng-form-submit');
    if (btn) { btn.disabled = true; btn.textContent = 'Creating…'; }

    try {
      const res = await fetch('/api/engagements', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, profile, opsec_profile, cidrs, domains, objectives }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert('Error: ' + (err.error || res.statusText));
        return;
      }
      // Reset form
      document.getElementById('eng-form-name').value = '';
      cidrInput.clear();
      domainInput.clear();
      document.getElementById('eng-obj-rows').innerHTML = '';
      toggleForm(false);
      await loadEngagements();
    } catch (err) {
      alert('Failed to create engagement: ' + err.message);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Create Engagement'; }
    }
  }

  /* ---- refresh when panel is activated ---- */
  document.addEventListener('panel-activated', e => {
    if (e.detail === 'engagements') loadEngagements();
  });
})();
