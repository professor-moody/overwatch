import { describe, it, expect, vi } from 'vitest';
import { WebSocket } from 'ws';
import { EventEmitter } from 'node:events';
import { sendOrDrop, startWebSocketHeartbeat, WS_MAX_BUFFERED_BYTES } from '../dashboard-ws-liveness.js';

function fakeWs(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    readyState: WebSocket.OPEN,
    bufferedAmount: 0,
    send: vi.fn(),
    close: vi.fn(),
    terminate: vi.fn(),
    ...overrides,
  } as unknown as WebSocket & { send: ReturnType<typeof vi.fn>; terminate: ReturnType<typeof vi.fn>; close: ReturnType<typeof vi.fn> };
}

describe('sendOrDrop', () => {
  it('sends to an open, draining client', () => {
    const ws = fakeWs();
    expect(sendOrDrop(ws, 'hi')).toBe(true);
    expect(ws.send).toHaveBeenCalledWith('hi');
    expect(ws.terminate).not.toHaveBeenCalled();
  });

  it('drops a non-open client without sending', () => {
    const ws = fakeWs({ readyState: WebSocket.CLOSING });
    expect(sendOrDrop(ws, 'hi')).toBe(false);
    expect(ws.send).not.toHaveBeenCalled();
  });

  it('terminates a client whose buffer is over the watermark instead of queuing more', () => {
    const ws = fakeWs({ bufferedAmount: WS_MAX_BUFFERED_BYTES + 1 });
    expect(sendOrDrop(ws, 'hi')).toBe(false);
    expect(ws.send).not.toHaveBeenCalled();
    expect(ws.terminate).toHaveBeenCalledTimes(1);
  });

  it('closes a client whose send throws', () => {
    const ws = fakeWs({ send: vi.fn(() => { throw new Error('broken pipe'); }) });
    expect(sendOrDrop(ws, 'hi')).toBe(false);
    expect(ws.close).toHaveBeenCalledTimes(1);
  });
});

describe('startWebSocketHeartbeat', () => {
  it('terminates a socket that never pongs and keeps a responsive one', () => {
    vi.useFakeTimers();
    try {
      const server = new EventEmitter() as unknown as import('ws').WebSocketServer;
      const clients = new Set<WebSocket>();
      (server as unknown as { clients: Set<WebSocket> }).clients = clients;

      const responsive = fakeWs({ ping: vi.fn(), on: vi.fn() }) as unknown as WebSocket;
      const dead = fakeWs({ ping: vi.fn(), on: vi.fn() }) as unknown as WebSocket;
      // Wire pong forwarding the way the helper expects.
      const pongCbs = new Map<WebSocket, () => void>();
      for (const ws of [responsive, dead]) {
        (ws.on as unknown as ReturnType<typeof vi.fn>).mockImplementation((ev: string, cb: () => void) => {
          if (ev === 'pong') pongCbs.set(ws, cb);
        });
      }

      const stop = startWebSocketHeartbeat(server, 1000);
      server.emit('connection', responsive);
      server.emit('connection', dead);
      clients.add(responsive);
      clients.add(dead);

      // Tick 1: both marked not-alive and pinged.
      vi.advanceTimersByTime(1000);
      expect((responsive as unknown as { ping: ReturnType<typeof vi.fn> }).ping).toHaveBeenCalled();

      // Only the responsive one pongs back.
      pongCbs.get(responsive)!();

      // Tick 2: the silent one is terminated; the responsive one survives.
      vi.advanceTimersByTime(1000);
      expect((dead as unknown as { terminate: ReturnType<typeof vi.fn> }).terminate).toHaveBeenCalledTimes(1);
      expect((responsive as unknown as { terminate: ReturnType<typeof vi.fn> }).terminate).not.toHaveBeenCalled();

      stop();
    } finally {
      vi.useRealTimers();
    }
  });
});
