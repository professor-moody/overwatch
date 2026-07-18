import { afterEach, describe, expect, it, vi } from 'vitest';
import { FallbackPollCoordinator, GenerationSocketController, type ManagedSocket } from '../generation-socket';

class FakeSocket implements ManagedSocket {
  readyState = 0;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  close = vi.fn(() => {
    this.readyState = 3;
    this.onclose?.({} as CloseEvent);
  });
}

afterEach(() => {
  vi.useRealTimers();
});

describe('generation-owned main socket', () => {
  it('connects immediately, owns one socket/timer, and applies capped one-shot backoff', () => {
    vi.useFakeTimers();
    const sockets: FakeSocket[] = [];
    const controller = new GenerationSocketController({
      createSocket: () => {
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket;
      },
      onMessage: () => {},
      onSynchronizedChange: () => {},
    });

    controller.start();
    controller.start();
    expect(sockets).toHaveLength(1);
    sockets[0].close();
    vi.advanceTimersByTime(999);
    expect(sockets).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(sockets).toHaveLength(2);
    sockets[1].close();
    vi.advanceTimersByTime(1_999);
    expect(sockets).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(sockets).toHaveLength(3);
    for (const delay of [4_000, 8_000, 16_000, 30_000, 30_000]) {
      sockets.at(-1)!.close();
      vi.advanceTimersByTime(delay - 1);
      const before = sockets.length;
      expect(sockets).toHaveLength(before);
      vi.advanceTimersByTime(1);
      expect(sockets).toHaveLength(before + 1);
    }
    controller.stop();
  });

  it('does not declare synchronization until a full state is acknowledged', () => {
    vi.useFakeTimers();
    const socket = new FakeSocket();
    const changes: boolean[] = [];
    const controller = new GenerationSocketController({
      createSocket: () => socket,
      onMessage: (_data, generation) => controller.markSynchronized(generation),
      onSynchronizedChange: value => changes.push(value),
    });
    controller.start();
    socket.onopen?.({} as Event);
    expect(controller.isSynchronized()).toBe(false);
    socket.onmessage?.({ data: '{"type":"full_state"}' } as MessageEvent);
    expect(controller.isSynchronized()).toBe(true);
    expect(changes).toEqual([true]);
    controller.stop();
  });

  it('closes a connection that misses the five-second full-state deadline', () => {
    vi.useFakeTimers();
    const socket = new FakeSocket();
    const controller = new GenerationSocketController({
      createSocket: () => socket,
      onMessage: () => {},
      onSynchronizedChange: () => {},
    });
    controller.start();
    socket.onopen?.({} as Event);
    vi.advanceTimersByTime(4_999);
    expect(socket.close).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(socket.close).toHaveBeenCalledOnce();
    controller.stop();
  });

  it('ignores callbacks from stale generations', () => {
    vi.useFakeTimers();
    const sockets: FakeSocket[] = [];
    const messages: unknown[] = [];
    const controller = new GenerationSocketController({
      createSocket: () => {
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket;
      },
      onMessage: data => messages.push(data),
      onSynchronizedChange: () => {},
    });
    controller.start();
    const staleMessage = sockets[0].onmessage!;
    sockets[0].close();
    vi.advanceTimersByTime(1_000);
    staleMessage({ data: 'stale' } as MessageEvent);
    sockets[1].onmessage?.({ data: 'current' } as MessageEvent);
    expect(messages).toEqual(['current']);
    controller.stop();
  });

  it('invalidates a synchronized generation and requires a fresh full state after reconnect', () => {
    vi.useFakeTimers();
    const sockets: FakeSocket[] = [];
    const changes: boolean[] = [];
    const messages: unknown[] = [];
    const controller = new GenerationSocketController({
      createSocket: () => {
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket;
      },
      onMessage: (data, generation) => {
        messages.push(data);
        controller.markSynchronized(generation);
      },
      onSynchronizedChange: value => changes.push(value),
    });
    controller.start();
    const staleMessage = sockets[0].onmessage!;
    sockets[0].onmessage?.({ data: 'baseline-1' } as MessageEvent);
    expect(controller.isSynchronized()).toBe(true);

    controller.reconnect();
    expect(sockets[0].close).toHaveBeenCalledOnce();
    expect(controller.isSynchronized()).toBe(false);
    staleMessage({ data: 'stale' } as MessageEvent);
    vi.advanceTimersByTime(1_000);
    expect(sockets).toHaveLength(2);
    expect(controller.isSynchronized()).toBe(false);
    sockets[1].onmessage?.({ data: 'baseline-2' } as MessageEvent);
    expect(controller.isSynchronized()).toBe(true);
    expect(messages).toEqual(['baseline-1', 'baseline-2']);
    expect(changes).toEqual([true, false, true]);
    controller.stop();
  });

  it('cancels retries on stop and never resurrects a socket', () => {
    vi.useFakeTimers();
    const sockets: FakeSocket[] = [];
    const controller = new GenerationSocketController({
      createSocket: () => {
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket;
      },
      onMessage: () => {},
      onSynchronizedChange: () => {},
    });
    controller.start();
    sockets[0].close();
    controller.stop();
    vi.advanceTimersByTime(60_000);
    expect(sockets).toHaveLength(1);
  });

  it('retries a constructor failure and resets backoff after synchronization', () => {
    vi.useFakeTimers();
    const sockets: FakeSocket[] = [];
    let throwOnce = true;
    const controller = new GenerationSocketController({
      createSocket: () => {
        if (throwOnce) {
          throwOnce = false;
          throw new Error('constructor failed');
        }
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket;
      },
      onMessage: (_data, generation) => controller.markSynchronized(generation),
      onSynchronizedChange: () => {},
    });
    controller.start();
    vi.advanceTimersByTime(999);
    expect(sockets).toHaveLength(0);
    vi.advanceTimersByTime(1);
    expect(sockets).toHaveLength(1);

    sockets[0].close();
    vi.advanceTimersByTime(2_000);
    expect(sockets).toHaveLength(2);
    sockets[1].onmessage?.({ data: 'full-state' } as MessageEvent);
    sockets[1].close();
    vi.advanceTimersByTime(999);
    expect(sockets).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(sockets).toHaveLength(3);
    controller.stop();
  });
});

describe('fallback HTTP snapshot generations', () => {
  it('aborts stale polls and never lets them publish after a newer poll or socket sync', () => {
    const polls = new FallbackPollCoordinator();
    const first = polls.begin();
    const second = polls.begin();
    expect(first.controller.signal.aborted).toBe(true);
    expect(polls.isCurrent(first)).toBe(false);
    expect(polls.isCurrent(second)).toBe(true);

    polls.invalidate();
    expect(second.controller.signal.aborted).toBe(true);
    expect(polls.isCurrent(second)).toBe(false);
  });
});
