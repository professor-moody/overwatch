import { randomUUID } from 'node:crypto';
import { WebSocket, WebSocketServer } from 'ws';
import { z } from 'zod';
import type { GraphEngine } from './graph-engine.js';
import type { SessionManager } from './session-manager.js';
import {
  SessionWebSocketClientEventSchema,
  SessionWebSocketServerEventSchema,
} from '../contracts/dashboard-v1.js';
import {
  buildExternalMutationFingerprint,
} from './external-mutation-command-service.js';
import {
  ApplicationCommandService,
  type ApplicationCommandExecution,
} from './application-command-service.js';

const SessionMutationDescriptorSchema = z.object({
  operation_id: z.string().trim().min(1).max(256),
  request_fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();

// Session input is ordered within one accepted connection generation. Retain
// enough receipts to make response-loss retries safe without allowing normal
// typing to grow snapshots forever. The class cap naturally retires receipts
// from closed generations as newer terminal activity arrives.
const SESSION_RECEIPTS_PER_GENERATION = 512;
const SESSION_RECEIPTS_GLOBAL = 4_096;

export interface SessionSocketExpectedGeneration {
  expected_connection_id?: string;
  expected_connection_generation?: number;
}

export class DashboardSessionWebSocketHub {
  readonly server = new WebSocketServer({ noServer: true });
  pollers = new Map<WebSocket, ReturnType<typeof setInterval>>();
  private readonly mutationBoundary: ApplicationCommandService;

  constructor(
    private readonly engine: GraphEngine,
    private sessionManager: SessionManager | null,
    private readonly pollMs = 50,
  ) {
    this.mutationBoundary = new ApplicationCommandService(engine);
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
    // Legacy clients may omit command identity. A connection generation can
    // have multiple terminals and reconnects, so sequence alone is not unique.
    const attachmentId = randomUUID();
    let mutationSequence = 0;
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

      const event = parsed.data;
      const sequence = ++mutationSequence;
      const publicCommandId = event.command_id
        ?? `ws-session-${sessionId}-${connectionGeneration ?? 0}-${attachmentId}-${sequence}`;
      const idempotencyKey = event.idempotency_key
        ?? `ws-session:${sessionId}:${connectionId ?? connectionGeneration ?? 'legacy'}:${publicCommandId}`;
      const descriptor = {
          operation_id: `ws.session.${event.type}`,
          request_fingerprint: buildExternalMutationFingerprint({
            session_id: sessionId,
            connection_id: connectionId,
            connection_generation: connectionGeneration,
            ...(event.type === 'input'
              ? { data_sha256: buildExternalMutationFingerprint(event.data) }
              : { cols: event.cols, rows: event.rows }),
          }),
        };
      const retention = {
        retention_class: 'dashboard.session_ws',
        retention_group:
          `${sessionId}:${connectionId ?? connectionGeneration ?? 'legacy'}`,
        max_group_records: SESSION_RECEIPTS_PER_GENERATION,
        max_class_records: SESSION_RECEIPTS_GLOBAL,
      } as const;
      try {
        const reserved = this.mutationBoundary.reserveSync({
          command_kind: `external.${descriptor.operation_id}`,
          input: descriptor,
          schema: SessionMutationDescriptorSchema,
          metadata: {
          transport: 'dashboard',
          command_id: publicCommandId,
          idempotency_key: idempotencyKey,
          ...(event.retry_token ? { retry_token: event.retry_token } : {}),
          },
          retention,
          reserve: () => ({ result: { reserved: true } }),
        });
        let command: ApplicationCommandExecution<unknown> = reserved;
        if (!reserved.replayed) {
          let operationError: unknown;
          try {
            if (event.type === 'input') {
              if (generationAddressed) {
                this.sessionManager!.write(
                  sessionId,
                  event.data,
                  'dashboard',
                  true,
                  expectedGeneration,
                );
              } else {
                this.sessionManager!.write(sessionId, event.data, 'dashboard', true);
              }
            } else {
              this.sessionManager!.resize(
                sessionId,
                event.cols,
                event.rows,
                'dashboard',
                true,
              );
            }
          } catch (error) {
            operationError = error;
          }
          // A failure of the external write itself can be finalized as failed.
          // Keep the success transition outside that catch: if its WAL/fsync
          // fails after the bytes were sent, the accepted reservation must
          // remain ambiguous and a retry must never execute the input again.
          if (operationError !== undefined) {
            command = this.mutationBoundary.transition(
              reserved.command_id,
              {
                status: 'failed',
                error: {
                  code: typeof (operationError as { code?: unknown })?.code === 'string'
                    ? (operationError as { code: string }).code
                    : 'SESSION_MUTATION_FAILED',
                  message: operationError instanceof Error
                    ? operationError.message
                    : String(operationError),
                },
              },
              [],
              undefined,
              retention,
            );
          } else {
            command = this.mutationBoundary.transition(
              reserved.command_id,
              { status: 'succeeded', result: { op: event.type } },
              [],
              undefined,
              retention,
            );
          }
        }
        if (ws.readyState !== WebSocket.OPEN) return;
        if (command.status !== 'succeeded') {
          this.send(ws, {
            type: 'error',
            op: event.type,
            code: command.error?.code
              ?? 'APPLICATION_COMMAND_NOT_SUCCEEDED',
            error: command.error?.message
              ?? `Session command is ${command.status}.`,
            command_id: command.command_id,
            retry_token: command.retry_token,
            status: command.status,
            replayed: command.replayed,
          });
          return;
        }
        this.send(ws, {
          type: 'command_result',
          op: event.type,
          command_id: command.command_id,
          retry_token: command.retry_token,
          status: command.status,
          replayed: command.replayed,
        });
      } catch (error) {
        if (ws.readyState !== WebSocket.OPEN) return;
        this.send(ws, {
          type: 'error',
          op: event.type,
          code: typeof (error as { code?: unknown })?.code === 'string'
            ? (error as { code: string }).code
            : undefined,
          error: error instanceof Error ? error.message : String(error),
          command_id: publicCommandId,
        });
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
