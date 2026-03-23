// ============================================================
// Overwatch Dashboard — WebSocket Module
// Connection management, reconnection, HTTP polling fallback
// ============================================================

let ws = null;
let reconnectTimer = null;
let pollTimer = null;
let onInitialState = null;
let onStateRefresh = null;
let onGraphUpdate = null;
let hasLoadedState = false;
let reconnectFailures = 0;
const MAX_RECONNECT_FAILURES = 3;

function connectWS(callbacks) {
  onInitialState = callbacks.onInitialState;
  onStateRefresh = callbacks.onStateRefresh;
  onGraphUpdate = callbacks.onGraphUpdate;
  doConnect();

  // Fallback polling every 5s if WS fails
  if (!pollTimer) {
    pollTimer = setInterval(() => {
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        pollState();
      }
    }, 5000);
  }

  // Initial load via HTTP
  pollState();
}

function setBadge(state, label) {
  const badge = document.getElementById('ws-status');
  if (!badge) return;
  badge.className = 'status-badge' + (state ? ' ' + state : '');
  badge.innerHTML = '<span class="status-dot"></span><span>' + label + '</span>';
}

function handleStateSnapshot(data) {
  // Update badge on successful poll when WS is not open
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    setBadge('snapshot', 'Snapshot');
  }

  if (!hasLoadedState) {
    hasLoadedState = true;
    if (onInitialState) onInitialState(data);
    return;
  }

  if (onStateRefresh) onStateRefresh(data);
}

function doConnect() {
  const host = window.location?.host || 'localhost';
  const wsUrl = `ws://${host}/ws`;
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    reconnectFailures = 0;
    setBadge('', 'Live');
    if (reconnectTimer) {
      clearInterval(reconnectTimer);
      reconnectTimer = null;
    }
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === 'full_state') {
        setBadge('', 'Live');
        handleStateSnapshot(msg.data);
      } else if (msg.type === 'graph_update' && onGraphUpdate) {
        onGraphUpdate(msg.data);
      }
    } catch (err) {
      console.error('WS message parse error:', err);
    }
  };

  ws.onclose = () => {
    reconnectFailures++;
    if (reconnectFailures >= MAX_RECONNECT_FAILURES && !hasLoadedState) {
      setBadge('disconnected', 'Disconnected');
    } else {
      setBadge('reconnecting', 'Reconnecting\u2026');
    }
    if (!reconnectTimer) {
      reconnectTimer = setInterval(() => doConnect(), 3000);
    }
  };

  ws.onerror = () => {
    ws.close();
  };
}

async function pollState() {
  try {
    const res = await fetch('/api/state');
    if (res.ok) {
      const data = await res.json();
      handleStateSnapshot(data);
    }
  } catch { /* silent */ }
}

// ============================================================
// Exports (global)
// ============================================================

window.OverwatchWS = {
  connect: connectWS,
};
