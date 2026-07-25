import { WebSocket, type WebSocketServer } from 'ws';

/**
 * Backpressure watermark: terminate a client whose outbound buffer grows past this.
 * A backgrounded/throttled tab or a half-open TCP connection stays `OPEN` while its
 * send buffer fills, so a `readyState`-only guard lets one dead reader grow daemon
 * memory without bound on a busy engagement. 8 MB is generous for the dashboard's
 * coalesced state/graph payloads while still bounding a stuck socket.
 */
export const WS_MAX_BUFFERED_BYTES = 8 * 1024 * 1024;

/**
 * Send a pre-serialized message, dropping the client if the socket is closed or is
 * not draining (buffered bytes over the watermark). Returns true iff the message was
 * handed to the socket. Callers that track their own client set should delete the ws
 * when this returns false.
 */
export function sendOrDrop(
  ws: WebSocket,
  message: string,
  maxBufferedBytes: number = WS_MAX_BUFFERED_BYTES,
): boolean {
  if (ws.readyState !== WebSocket.OPEN) return false;
  if (ws.bufferedAmount > maxBufferedBytes) {
    // The reader is not keeping up; queuing more only grows memory. Drop it — the
    // client reconnects and gets a fresh full snapshot.
    try { ws.terminate(); } catch { /* already gone */ }
    return false;
  }
  try {
    ws.send(message);
    return true;
  } catch {
    try { ws.close(); } catch { /* already gone */ }
    return false;
  }
}

/**
 * Attach a ping/pong liveness sweep to a hub's server. Each interval, any socket that
 * did not answer the previous ping (half-open TCP the OS has not surfaced as closed)
 * is terminated; survivors are pinged again. Returns a disposer that stops the sweep.
 * The timer is unref'd so it never keeps the process alive on its own.
 */
export function startWebSocketHeartbeat(
  server: WebSocketServer,
  intervalMs: number = 30_000,
): () => void {
  const alive = new WeakMap<WebSocket, boolean>();
  const onConnection = (ws: WebSocket) => {
    alive.set(ws, true);
    ws.on('pong', () => alive.set(ws, true));
  };
  server.on('connection', onConnection);
  const timer = setInterval(() => {
    for (const ws of server.clients) {
      if (alive.get(ws) === false) {
        try { ws.terminate(); } catch { /* already gone */ }
        continue;
      }
      alive.set(ws, false);
      try {
        ws.ping();
      } catch {
        try { ws.terminate(); } catch { /* already gone */ }
      }
    }
  }, intervalMs);
  if (typeof timer.unref === 'function') timer.unref();
  return () => {
    clearInterval(timer);
    server.off('connection', onConnection);
  };
}
