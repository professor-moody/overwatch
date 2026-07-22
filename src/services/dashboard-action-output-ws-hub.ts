import { WebSocket, WebSocketServer } from 'ws';
import type { GraphEngine } from './graph-engine.js';
import { sendOrDrop, startWebSocketHeartbeat } from './dashboard-ws-liveness.js';
import {
  ActionOutputWebSocketEventSchema,
  type ActionOutputWebSocketEvent,
} from '../contracts/dashboard-v1.js';

export class DashboardActionOutputWebSocketHub {
  readonly server = new WebSocketServer({ noServer: true });
  pollers = new Map<WebSocket, ReturnType<typeof setInterval>>();
  private readonly stopHeartbeat: () => void;

  constructor(
    private readonly engine: GraphEngine,
    private readonly pollMs = 100,
  ) {
    this.server.on('error', () => { /* connection-local errors are handled below */ });
    this.stopHeartbeat = startWebSocketHeartbeat(this.server);
  }

  handleConnection(ws: WebSocket, actionId: string): void {
    const buffer = this.engine.getActionOutputBuffer();
    if (!buffer.has(actionId)) {
      this.send(ws, { type: 'action_done' });
      ws.close(4404, 'No live output');
      return;
    }

    let outCursor = 0;
    let errCursor = 0;
    const flush = () => {
      for (const stream of ['stdout', 'stderr'] as const) {
        const cursor = stream === 'stdout' ? outCursor : errCursor;
        const result = buffer.read(actionId, stream, cursor);
        if (result?.text) {
          this.send(ws, {
            type: 'output',
            stream,
            text: result.text,
            end_pos: result.end_pos,
            dropped: result.dropped,
          });
          if (stream === 'stdout') outCursor = result.end_pos;
          else errCursor = result.end_pos;
        }
      }
    };

    try { flush(); } catch { /* connection may have closed */ }
    const poller = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) {
        this.cleanup(ws);
        return;
      }
      try {
        flush();
        if (buffer.isDone(actionId)) {
          this.send(ws, { type: 'action_done' });
          this.cleanup(ws);
          ws.close(1000, 'done');
        }
      } catch {
        this.cleanup(ws);
        try { this.send(ws, { type: 'action_done' }); } catch { /* socket gone */ }
        try { ws.close(); } catch { /* already closed */ }
      }
    }, this.pollMs);
    if (typeof poller.unref === 'function') poller.unref();
    this.pollers.set(ws, poller);
    ws.on('close', () => this.cleanup(ws));
    ws.on('error', () => this.cleanup(ws));
  }

  closeConnections(): void {
    for (const ws of this.pollers.keys()) {
      this.cleanup(ws);
      ws.close();
    }
  }

  closeServer(): Promise<void> {
    this.stopHeartbeat();
    this.closeConnections();
    return new Promise(resolve => this.server.close(() => resolve()));
  }

  private cleanup(ws: WebSocket): void {
    const poller = this.pollers.get(ws);
    if (poller) clearInterval(poller);
    this.pollers.delete(ws);
  }

  private send(ws: WebSocket, event: ActionOutputWebSocketEvent): void {
    sendOrDrop(ws, JSON.stringify(ActionOutputWebSocketEventSchema.parse(event)));
  }
}
