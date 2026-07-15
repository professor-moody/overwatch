import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  TOKEN_STORAGE_KEY,
  authenticatedWebSocketUrl,
  dashboardFetch,
  downloadDashboardResource,
  fetchAuthenticatedBlobUrl,
  initializeDashboardAuth,
  openDashboardResource,
} from '../dashboard-transport';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('dashboard transport', () => {
  it('captures the landing token and scrubs every token parameter without losing route/query/hash', () => {
    const values = new Map<string, string>();
    const replacements: string[] = [];
    const token = initializeDashboardAuth({
      href: 'https://ops.example.test/graph?node=host-1&token=old&view=full&token=new%2Bvalue#details',
      storage: {
        getItem: key => values.get(key) ?? null,
        setItem: (key, value) => { values.set(key, value); },
      },
      replaceState: (_state, _unused, url) => { replacements.push(String(url)); },
      historyState: { route: 'graph' },
    });

    expect(token).toBe('new+value');
    expect(values.get(TOKEN_STORAGE_KEY)).toBe('new+value');
    expect(replacements).toEqual(['/graph?node=host-1&view=full#details']);
  });

  it('keeps an in-memory token when session storage throws', () => {
    expect(initializeDashboardAuth({
      href: 'http://127.0.0.1:3000/?token=fallback-token',
      storage: {
        getItem: () => { throw new Error('disabled'); },
        setItem: () => { throw new Error('disabled'); },
      },
    })).toBe('fallback-token');
  });

  it('keeps a fresh landing token authoritative over stale readable storage', () => {
    const storage = {
      getItem: () => 'stale-token',
      setItem: () => { throw new Error('quota exceeded'); },
    };
    initializeDashboardAuth({ href: 'https://ops.example.test/?token=fresh-token', storage });
    expect(new URL(authenticatedWebSocketUrl('/ws', 'https://ops.example.test/')).searchParams.get('token'))
      .toBe('fresh-token');
  });

  it('falls back safely when acquiring sessionStorage throws', () => {
    const replaceState = vi.fn();
    vi.stubGlobal('window', {
      location: { href: 'https://ops.example.test/?token=getter-token' },
      history: { state: null, replaceState },
      get sessionStorage() { throw new Error('storage blocked'); },
    });
    expect(initializeDashboardAuth()).toBe('getter-token');
    expect(replaceState).toHaveBeenCalledWith(null, '', '/');
  });

  it('keeps the captured token when history scrubbing is unavailable', () => {
    expect(initializeDashboardAuth({
      href: 'https://ops.example.test/?token=history-fallback',
      replaceState: () => { throw new Error('history disabled'); },
    })).toBe('history-fallback');
    expect(new URL(authenticatedWebSocketUrl('/ws', 'https://ops.example.test/')).searchParams.get('token'))
      .toBe('history-fallback');
  });

  it('merges caller headers and authenticates every fetch', async () => {
    initializeDashboardAuth({ href: 'https://ops.example.test/?token=bearer-token' });
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    await dashboardFetch('/api/state', { headers: { Accept: 'application/json', 'X-Trace': 'one' } });
    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get('Authorization')).toBe('Bearer bearer-token');
    expect(headers.get('Accept')).toBe('application/json');
    expect(headers.get('X-Trace')).toBe('one');
  });

  it('encodes the token on all WebSocket paths', () => {
    initializeDashboardAuth({ href: 'https://ops.example.test/?token=a%2Bb%2F%3D%3F' });
    for (const path of ['/ws', '/ws/session/session-1', '/ws/actions/action-1/output']) {
      const url = authenticatedWebSocketUrl(path, 'https://ops.example.test/app');
      expect(new URL(url).protocol).toBe('wss:');
      expect(new URL(url).pathname).toBe(path);
      expect(new URL(url).searchParams.get('token')).toBe('a+b/=?');
    }
  });

  it('loads authenticated blobs and revokes object URLs exactly once', async () => {
    initializeDashboardAuth({ href: 'https://ops.example.test/?token=blob-token' });
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(new Blob(['image']), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const create = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:test');
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});

    const resource = await fetchAuthenticatedBlobUrl('/api/evidence/ev-1/image');
    expect(create).toHaveBeenCalledOnce();
    const headers = new Headers(fetchMock.mock.calls[0][1]?.headers);
    expect(headers.get('Authorization')).toBe('Bearer blob-token');
    resource.revoke();
    resource.revoke();
    expect(revoke).toHaveBeenCalledTimes(1);
  });

  it('attaches downloads and defers object URL revocation until a later task', async () => {
    vi.useFakeTimers();
    initializeDashboardAuth({ href: 'https://ops.example.test/?token=download-token' });
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(new Blob(['bundle']), {
      status: 200,
      headers: { 'Content-Disposition': 'attachment; filename="engagement.zip"' },
    })));
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:download');
    const anchor = { href: '', download: '', rel: '', hidden: false, click: vi.fn(), remove: vi.fn() };
    const append = vi.fn();
    vi.stubGlobal('document', { createElement: () => anchor, body: { append } });

    await expect(downloadDashboardResource('/api/bundle')).resolves.toEqual({
      filename: 'engagement.zip', bytes: 6,
    });
    expect(append).toHaveBeenCalledWith(anchor);
    expect(anchor.click).toHaveBeenCalledOnce();
    expect(anchor.remove).toHaveBeenCalledOnce();
    expect(revoke).not.toHaveBeenCalled();
    vi.runOnlyPendingTimers();
    expect(revoke).toHaveBeenCalledOnce();
    vi.useRealTimers();
  });

  it('keeps opened blobs alive for navigation and revokes them on success or failure', async () => {
    initializeDashboardAuth({ href: 'https://ops.example.test/?token=report-token' });
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(new Blob(['report']), { status: 200 })));
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:report');
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    let scheduled: (() => void) | undefined;
    const replace = vi.fn();
    const close = vi.fn();
    vi.stubGlobal('window', {
      open: () => ({ opener: {}, location: { replace }, close }),
      setTimeout: (callback: () => void) => { scheduled = callback; return 1; },
    });
    await openDashboardResource('/api/reports/report-1');
    expect(replace).toHaveBeenCalledWith('blob:report');
    expect(revoke).not.toHaveBeenCalled();
    scheduled?.();
    expect(revoke).toHaveBeenCalledOnce();

    revoke.mockClear();
    vi.stubGlobal('window', {
      open: () => ({ opener: {}, location: { replace: () => { throw new Error('navigation failed'); } }, close }),
      setTimeout: vi.fn(),
    });
    await expect(openDashboardResource('/api/reports/report-2')).rejects.toThrow('navigation failed');
    expect(revoke).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();

    revoke.mockClear();
    vi.stubGlobal('window', { open: () => null, setTimeout: vi.fn() });
    await expect(openDashboardResource('/api/reports/report-3')).rejects.toThrow('blocked');
    expect(revoke).toHaveBeenCalledOnce();
  });
});
