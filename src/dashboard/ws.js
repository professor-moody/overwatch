// ============================================================
// Overwatch Dashboard — WebSocket Module
// Connection management, reconnection, HTTP polling fallback
// ============================================================

let ws = null;
let reconnectTimer = null;
let onFullState = null;
let onGraphUpdate = null;

function connectWS(callbacks) {
  onFullState = callbacks.onFullState;
  onGraphUpdate = callbacks.onGraphUpdate;
  doConnect();

  // Fallback polling every 5s if WS fails
  setInterval(() => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      pollState();
    }
  }, 5000);

  // Initial load via HTTP
  pollState();
}

function doConnect() {
  const wsUrl = `ws://${window.location.host}/ws`;
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    const badge = document.getElementById('ws-status');
    badge.className = 'status-badge';
    badge.innerHTML = '<span class="status-dot"></span><span>Live</span>';
    if (reconnectTimer) {
      clearInterval(reconnectTimer);
      reconnectTimer = null;
    }
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === 'full_state' && onFullState) {
        onFullState(msg.data);
      } else if (msg.type === 'graph_update' && onGraphUpdate) {
        onGraphUpdate(msg.data);
      }
    } catch (err) {
      console.error('WS message parse error:', err);
    }
  };

  ws.onclose = () => {
    const badge = document.getElementById('ws-status');
    badge.className = 'status-badge disconnected';
    badge.innerHTML = '<span class="status-dot"></span><span>Disconnected</span>';
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
      if (onFullState) onFullState(data);
    }
  } catch { /* silent */ }
}

// ============================================================
// Exports (global)
// ============================================================

window.OverwatchWS = {
  connect: connectWS,
};
