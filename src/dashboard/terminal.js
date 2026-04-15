// ============================================================
// Overwatch Dashboard — Terminal Multiplexer
// xterm.js sessions managed over WebSocket
// ============================================================

const Terminal = window.Terminal;
const FitAddon = window.FitAddon?.FitAddon || window.FitAddon;

const terminals = new Map(); // sessionId → { term, ws, fitAddon, tabEl }
let activeSessionId = null;
let sessionPollTimer = null;

function init() {
  // Start polling for session list updates
  sessionPollTimer = setInterval(fetchSessions, 5000);
  fetchSessions();

  // Resize active terminal when window resizes
  window.addEventListener('resize', () => {
    const active = terminals.get(activeSessionId);
    if (active?.fitAddon) {
      try { active.fitAddon.fit(); } catch { /* ignore */ }
    }
  });
}

async function fetchSessions() {
  try {
    const res = await fetch('/api/sessions');
    if (!res.ok) return;
    const data = await res.json();
    renderSessionList(data.sessions || []);
  } catch { /* silent */ }
}

function renderSessionList(sessions) {
  const list = document.getElementById('sessions-list');
  if (!list) return;

  const count = document.getElementById('session-count');
  const active = sessions.filter(s => s.state === 'connected' || s.state === 'pending');
  if (count) count.textContent = `(${active.length})`;

  if (sessions.length === 0) {
    list.innerHTML = '<div class="empty-state">No sessions</div>';
    return;
  }

  list.innerHTML = sessions.map(s => {
    const stateClass = s.state === 'connected' ? 'connected' : s.state === 'pending' ? 'pending' : 'closed';
    const attached = terminals.has(s.id) ? ' attached' : '';
    const isActive = s.id === activeSessionId ? ' active' : '';
    return `<div class="session-card${isActive}${attached}" data-session-id="${escapeHtml(s.id)}">
      <div class="session-status-dot ${stateClass}"></div>
      <div class="session-info">
        <div class="session-title">${escapeHtml(s.title || s.id.slice(0, 8))}</div>
        <div class="session-meta">${escapeHtml(s.kind || '')} · ${stateClass}</div>
      </div>
      ${s.state === 'connected' ? `<button class="session-attach-btn" title="Attach terminal">▶</button>` : ''}
    </div>`;
  }).join('');

  // Click handlers
  list.querySelectorAll('.session-card').forEach(card => {
    const sid = card.dataset.sessionId;
    card.addEventListener('click', () => {
      if (terminals.has(sid)) {
        switchToSession(sid);
      }
    });
    const btn = card.querySelector('.session-attach-btn');
    if (btn) {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        attachSession(sid);
      });
    }
  });
}

function attachSession(sessionId) {
  if (terminals.has(sessionId)) {
    switchToSession(sessionId);
    return;
  }

  if (!Terminal) {
    console.error('[Terminal] xterm.js not loaded');
    return;
  }

  // Show terminal panel
  const panel = document.getElementById('terminal-panel');
  if (panel) panel.classList.add('visible');

  // Create tab
  const tabBar = document.getElementById('terminal-tabs');
  const tabEl = document.createElement('div');
  tabEl.className = 'terminal-tab active';
  tabEl.dataset.sessionId = sessionId;
  tabEl.innerHTML = `<span class="tab-label">${escapeHtml(sessionId.slice(0, 8))}</span><button class="tab-close" title="Detach">✕</button>`;
  tabEl.querySelector('.tab-label').addEventListener('click', () => switchToSession(sessionId));
  tabEl.querySelector('.tab-close').addEventListener('click', (e) => {
    e.stopPropagation();
    detachSession(sessionId);
  });
  tabBar.appendChild(tabEl);

  // Create terminal container
  const container = document.getElementById('terminal-container');
  const termEl = document.createElement('div');
  termEl.className = 'terminal-instance';
  termEl.dataset.sessionId = sessionId;
  container.appendChild(termEl);

  // Initialize xterm
  const term = new Terminal({
    cursorBlink: true,
    fontSize: 13,
    fontFamily: 'JetBrains Mono, Menlo, Monaco, monospace',
    theme: {
      background: '#0d1117',
      foreground: '#c9d1d9',
      cursor: '#58a6ff',
      selectionBackground: '#264f78',
      black: '#484f58',
      red: '#ff7b72',
      green: '#3fb950',
      yellow: '#d29922',
      blue: '#58a6ff',
      magenta: '#bc8cff',
      cyan: '#39d353',
      white: '#b1bac4',
    },
  });

  let fitAddon = null;
  if (FitAddon) {
    fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
  }

  term.open(termEl);
  if (fitAddon) {
    try { fitAddon.fit(); } catch { /* ignore */ }
  }

  // Connect WebSocket
  const host = window.location?.host || 'localhost';
  const scheme = window.location?.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${scheme}://${host}/ws/session/${sessionId}`);

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === 'output' && msg.text) {
        term.write(msg.text);
      } else if (msg.type === 'session_meta') {
        const label = tabEl.querySelector('.tab-label');
        if (label && msg.data?.title) label.textContent = msg.data.title;
      } else if (msg.type === 'session_closed') {
        term.write('\r\n\x1b[31m[Session closed]\x1b[0m\r\n');
        tabEl.classList.add('closed');
      }
    } catch { /* ignore parse errors */ }
  };

  ws.onclose = () => {
    tabEl.classList.add('disconnected');
  };

  ws.onerror = () => {
    ws.close();
  };

  // Forward input
  term.onData((data) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'input', data }));
    }
  });

  // Forward resize
  term.onResize(({ cols, rows }) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'resize', cols, rows }));
    }
  });

  terminals.set(sessionId, { term, ws, fitAddon, tabEl, termEl });
  switchToSession(sessionId);
  fetchSessions(); // Refresh list to show attached state
}

function switchToSession(sessionId) {
  if (!terminals.has(sessionId)) return;

  activeSessionId = sessionId;

  // Update tabs
  document.querySelectorAll('.terminal-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.sessionId === sessionId);
  });

  // Update terminal visibility
  document.querySelectorAll('.terminal-instance').forEach(el => {
    el.classList.toggle('hidden', el.dataset.sessionId !== sessionId);
  });

  // Fit active terminal
  const entry = terminals.get(sessionId);
  if (entry?.fitAddon) {
    try { entry.fitAddon.fit(); } catch { /* ignore */ }
  }
  if (entry?.term) {
    entry.term.focus();
  }

  // Update session card highlights
  document.querySelectorAll('.session-card').forEach(card => {
    card.classList.toggle('active', card.dataset.sessionId === sessionId);
  });
}

function detachSession(sessionId) {
  const entry = terminals.get(sessionId);
  if (!entry) return;

  // Close WS
  if (entry.ws && entry.ws.readyState === WebSocket.OPEN) {
    entry.ws.close();
  }

  // Dispose terminal
  entry.term.dispose();
  entry.tabEl.remove();
  entry.termEl.remove();
  terminals.delete(sessionId);

  // Switch to another session or hide panel
  if (terminals.size > 0) {
    const next = terminals.keys().next().value;
    switchToSession(next);
  } else {
    activeSessionId = null;
    const panel = document.getElementById('terminal-panel');
    if (panel) panel.classList.remove('visible');
  }

  fetchSessions();
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function destroy() {
  if (sessionPollTimer) {
    clearInterval(sessionPollTimer);
    sessionPollTimer = null;
  }
  for (const [id] of terminals) {
    detachSession(id);
  }
}

// ============================================================
// Exports (global)
// ============================================================

window.OverwatchTerminal = {
  init,
  fetchSessions,
  attachSession,
  detachSession,
  destroy,
};
