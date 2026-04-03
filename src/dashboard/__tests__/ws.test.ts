import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resolve } from 'path';
import { pathToFileURL } from 'url';

async function loadWsModule() {
  const url = pathToFileURL(resolve(import.meta.dirname, '..', 'ws.js')).href;
  await import(`${url}?t=${Date.now()}-${Math.random()}`);
  return (globalThis as any).window.OverwatchWS;
}

function makeBadge() {
  return {
    className: '',
    innerHTML: '',
  };
}

describe('dashboard websocket controller', () => {
  let badge: ReturnType<typeof makeBadge>;
  let fetchMock: ReturnType<typeof vi.fn>;
  let intervals: Array<() => void>;

  beforeEach(() => {
    vi.useFakeTimers();
    badge = makeBadge();
    intervals = [];

    (globalThis as any).window = {};
    (globalThis as any).document = {
      getElementById(id: string) {
        return id === 'ws-status' ? badge : null;
      },
    };

    fetchMock = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        async json() {
          return { state: { graph_summary: { total_nodes: 1 } }, graph: { nodes: [], edges: [] } };
        },
      })
      .mockResolvedValueOnce({
        ok: true,
        async json() {
          return { state: { graph_summary: { total_nodes: 2 } }, graph: { nodes: [], edges: [] } };
        },
      });
    (globalThis as any).fetch = fetchMock;

    (globalThis as any).setInterval = vi.fn((fn: () => void) => {
      intervals.push(fn);
      return intervals.length;
    });
    (globalThis as any).clearInterval = vi.fn();

    class MockWebSocket {
      static OPEN = 1;
      static instances: MockWebSocket[] = [];
      readyState = 0;
      onopen?: () => void;
      onmessage?: (event: { data: string }) => void;
      onclose?: () => void;
      onerror?: () => void;

      constructor(public url: string) {
        MockWebSocket.instances.push(this);
      }

      close() {
        this.readyState = 3;
        this.onclose?.();
      }
    }

    (globalThis as any).WebSocket = MockWebSocket;
  });

  afterEach(() => {
    vi.useRealTimers();
    delete (globalThis as any).window;
    delete (globalThis as any).document;
    delete (globalThis as any).fetch;
    delete (globalThis as any).setInterval;
    delete (globalThis as any).clearInterval;
    delete (globalThis as any).WebSocket;
  });

  it('uses one poll timer, routes the first snapshot as initial state, and preserves later refreshes', async () => {
    const wsModule = await loadWsModule();
    const initial = vi.fn();
    const refresh = vi.fn();
    const delta = vi.fn();

    wsModule.connect({
      onInitialState: initial,
      onStateRefresh: refresh,
      onGraphUpdate: delta,
    });

    await Promise.resolve();
    await Promise.resolve();

    expect((globalThis as any).setInterval).toHaveBeenCalledTimes(1);
    expect(initial).toHaveBeenCalledTimes(1);
    expect(refresh).not.toHaveBeenCalled();

    const instance = (globalThis as any).WebSocket.instances[0];
    instance.readyState = (globalThis as any).WebSocket.OPEN;
    instance.onmessage?.({
      data: JSON.stringify({
        type: 'full_state',
        data: { state: { graph_summary: { total_nodes: 3 } }, graph: { nodes: [], edges: [] } },
      }),
    });

    expect(refresh).toHaveBeenCalledTimes(1);

    instance.readyState = 3;
    instance.onclose?.();
    expect((globalThis as any).setInterval).toHaveBeenCalledTimes(2);

    intervals[0]();
    await Promise.resolve();
    await Promise.resolve();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(refresh).toHaveBeenCalledTimes(2);
  });
});
