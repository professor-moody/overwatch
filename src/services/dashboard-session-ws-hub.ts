import { WebSocket, WebSocketServer } from 'ws';
import type { GraphEngine } from './graph-engine.js';
import type { SessionManager } from './session-manager.js';
import {
  SessionWebSocketClientEventSchema,
  SessionWebSocketServerEventSchema,
} from '../contracts/dashboard-v1.js';

export interface SessionSocketExpectedGeneration {
  expected_connection_id?: string;
  expected_connection_generation?: number;
}

export class DashboardSessionWebSocketHub {
  readonly server = new WebSocketServer({ noServer: true });
  pollers = new Map<WebSocket, ReturnType<typeof setInterval>>();

  constructor(
    private readonly engine: GraphEngine,
    private sessionManager: SessionManager | null,
    private readonly pollMs = 50,
  ) {
    this.server.on('error', () => { /* connection-local errors are handled below */ });
  }

  setSessionManager(sessionManager: SessionManager | null): void {
    this.sessionManager = sessionManager;
  }

  handleConnection(
    ws: WebSocket,
    sessionId: string,
    expected: SessionSocketExpectedGeneration = {},
  ): void {
    if (!this.sessionManager) {
      ws.close(4503, 'Session manager not available');
      return;
    }

    const meta = this.sessionManager.getSession(sessionId);
    if (!meta) {
      ws.close(4404, 'Session not found');
      return;
    }
    if (meta.state !== 'connected') {
      ws.close(4409, `Session not connected (state: ${meta.state})`);
      return;
    }
    if (
      (expected.expected_connection_id !== undefined
        && meta.connection_id !== expected.expected_connection_id)
      || (expected.expected_connection_generation !== undefined
        && meta.connection_generation !== expected.expected_connection_generation)
    ) {
      ws.close(4409, 'Session connection generation changed before attachment');
      return;
    }

    const connectionId = meta.connection_id;
    const connectionGeneration = meta.connection_generation;
    const expectedGeneration = {
      ...(connectionId !== undefined ? { connection_id: connectionId } : {}),
      ...(connectionGeneration !== undefined
        ? { connection_generation: connectionGeneration }
        : {}),
    };
    const generationAddressed = connectionId !== undefined || connectionGeneration !== undefined;
    const readGeneration = (from?: number, tail?: number) => generationAddressed
      ? this.sessionManager!.read(sessionId, from, tail, expectedGeneration)
      : this.sessionManager!.read(sessionId, from, tail);

    this.send(ws, { type: 'session_meta', data: meta });
    try {
      const initial = readGeneration(undefined, 8192);
      if (initial.text) {
        this.send(ws, { type: 'output', text: initial.text, end_pos: initial.end_pos });
      }
    } catch { /* the accepted connection generation ended before the initial read */ }

    let cursor = readGeneration(undefined, 0).end_pos;
    const poller = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) {
        this.cleanup(ws);
        return;
      }
      try {
        const current = this.sessionManager!.getSession(sessionId);
        if (!current || current.state !== 'connected' || current.connection_id !== connectionId) {
          this.send(ws, { type: 'session_closed', connection_id: connectionId });
          this.cleanup(ws);
          ws.close(4410, 'Session generation ended');
          return;
        }
        const result = readGeneration(cursor);
        if (result.text) {
          this.send(ws, { type: 'output', text: result.text, end_pos: result.end_pos });
          cursor = result.end_pos;
        }
      } catch {
        try { this.send(ws, { type: 'session_closed' }); } catch { /* socket already gone */ }
        this.cleanup(ws);
        ws.close(4410, 'Session closed');
      }
    }, this.pollMs);
    if (typeof poller.unref === 'function') poller.unref();
    this.pollers.set(ws, poller);

    ws.on('message', raw => {
      const parsed = SessionWebSocketClientEventSchema.safeParse(this.parse(raw));
      if (!parsed.success) {
        this.send(ws, {
          type: 'error',
          op: 'message',
          code: 'SESSION_MESSAGE_INVALID',
          error: 'Invalid terminal message.',
        });
        return;
      }
      if (!this.engine.isPersistenceWritable()) {
        this.send(ws, {
          type: 'error',
          op: 'persistence',
          code: 'PERSISTENCE_READ_ONLY',
          error: 'Durable mutations are disabled while persistence recovery is incomplete.',
          recovery: this.engine.getPersistenceRecoveryStatus(),
        });
        ws.close(4503, 'Persistence is read-only');
        return;
      }
      const current = this.sessionManager!.getSession(sessionId);
      if (!current || current.state !== 'connected' || current.connection_id !== connectionId) {
        this.send(ws, {
          type: 'error',
          op: 'generation',
          code: 'SESSION_GENERATION_ENDED',
          error: 'This terminal is attached to a connection generation that has ended.',
        });
        ws.close(4410, 'Session generation ended');
        return;
      }

      if (parsed.data.type === 'input') {
        try {
          if (generationAddressed) {
            this.sessionManager!.write(
              sessionId,
              parsed.data.data,
              'dashboard',
              true,
              expectedGeneration,
            );
          } else {
            this.sessionManager!.write(sessionId, parsed.data.data, 'dashboard', true);
          }
        } catch (error) {
          this.send(ws, {
            type: 'error',
            op: 'input',
            error: error instanceof Error ? error.message : String(error),
          });
        }
      } else {
        try {
          this.sessionManager!.resize(
            sessionId,
            parsed.data.cols,
            parsed.data.rows,
            'dashboard',
            true,
          );
        } catch (error) {
          this.send(ws, {
            type: 'error',
            op: 'resize',
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
    });

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
    this.closeConnections();
    return new Promise(resolve => this.server.close(() => resolve()));
  }

  private cleanup(ws: WebSocket): void {
    const poller = this.pollers.get(ws);
    if (poller) clearInterval(poller);
    this.pollers.delete(ws);
  }

  private send(ws: WebSocket, event: unknown): void {
    ws.send(JSON.stringify(SessionWebSocketServerEventSchema.parse(event)));
  }

  private parse(raw: unknown): unknown {
    try { return JSON.parse(String(raw)); } catch { return undefined; }
  }
}
