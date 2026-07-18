import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  TOKEN_STORAGE_KEY,
  authenticatedWebSocketUrl,
  dashboardFetch,
  downloadDashboardResource,
  fetchAuthenticatedBlobUrl,
  initializeDashboardAuth,
  openDashboardResource,
  resetDashboardPendingCommandsForTest,
} from '../dashboard-transport';
import { resetBrowserStorageMemoryForTest } from '../browser-storage';

afterEach(() => {
  resetDashboardPendingCommandsForTest();
  resetBrowserStorageMemoryForTest();
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

  it('retries one failed mutation transport with the exact same command identity', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError('response connection lost'))
      .mockResolvedValueOnce(new Response('{"ok":true}', {
        status: 200,
        headers: { 'X-Overwatch-Server-Response': '1' },
      }));
    vi.stubGlobal('fetch', fetchMock);

    const response = await dashboardFetch('/api/config/objectives', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ description: 'one mutation' }),
    });
    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const firstHeaders = new Headers(fetchMock.mock.calls[0][1]?.headers);
    const secondHeaders = new Headers(fetchMock.mock.calls[1][1]?.headers);
    expect(secondHeaders.get('X-Overwatch-Command-Id'))
      .toBe(firstHeaders.get('X-Overwatch-Command-Id'));
    expect(secondHeaders.get('Idempotency-Key'))
      .toBe(firstHeaders.get('Idempotency-Key'));
    expect(fetchMock.mock.calls[1][1]?.body).toBe(fetchMock.mock.calls[0][1]?.body);
  });

  it('retains a bounded binary mutation identity across a complete outage', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError('response connection lost'))
      .mockRejectedValueOnce(new TypeError('daemon remains unavailable'));
    vi.stubGlobal('fetch', fetchMock);
    const request = {
      method: 'POST',
      body: new Blob([new Uint8Array([1, 2, 3, 4])]),
    };

    await expect(dashboardFetch('/api/binary-mutation', request))
      .rejects.toThrow('daemon remains unavailable');
    const retainedId = new Headers(fetchMock.mock.calls[0][1]?.headers)
      .get('X-Overwatch-Command-Id');
    expect(new Headers(fetchMock.mock.calls[1][1]?.headers)
      .get('X-Overwatch-Command-Id')).toBe(retainedId);

    fetchMock.mockResolvedValueOnce(new Response('{"ok":true}', {
      status: 200,
      headers: { 'X-Overwatch-Server-Response': '1' },
    }));
    const response = await dashboardFetch('/api/binary-mutation', request);
    expect(new Headers(fetchMock.mock.calls[2][1]?.headers)
      .get('X-Overwatch-Command-Id')).toBe(retainedId);
    await response.text();
  });

  it('fails closed before sending an unidentifiable oversized binary mutation', async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal('fetch', fetchMock);
    await expect(dashboardFetch('/api/binary-mutation', {
      method: 'POST',
      body: new Uint8Array(256 * 1024 + 1),
    })).rejects.toThrow(/no larger than 262144 bytes/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fingerprints the effective body of Request inputs', async () => {
    const requests: Request[] = [];
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async input => {
      requests.push(input as Request);
      return new Response('{"error":"ambiguous proxy response"}', { status: 504 });
    }));

    await dashboardFetch(new Request('https://ops.example.test/api/settings', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: true }),
    }));
    await dashboardFetch(new Request('https://ops.example.test/api/settings', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: false }),
    }));

    expect(requests).toHaveLength(2);
    expect(requests[0].headers.get('X-Overwatch-Command-Id'))
      .not.toBe(requests[1].headers.get('X-Overwatch-Command-Id'));
    expect(await requests[0].clone().text()).toBe('{"enabled":true}');
    expect(await requests[1].clone().text()).toBe('{"enabled":false}');
  });

  it('retries a consumed Request body with identical bytes and identity', async () => {
    const bodies: string[] = [];
    const commandIds: Array<string | null> = [];
    const fetchMock = vi.fn<typeof fetch>(async input => {
      const request = input as Request;
      commandIds.push(request.headers.get('X-Overwatch-Command-Id'));
      bodies.push(await request.text());
      if (bodies.length === 1) throw new TypeError('response lost after body upload');
      return new Response('{"ok":true}', {
        status: 200,
        headers: { 'X-Overwatch-Server-Response': '1' },
      });
    });
    vi.stubGlobal('fetch', fetchMock);

    const response = await dashboardFetch(new Request(
      'https://ops.example.test/api/config/objectives',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: 'request body replay' }),
      },
    ));
    expect(response.status).toBe(200);
    expect(bodies).toEqual([
      '{"description":"request body replay"}',
      '{"description":"request body replay"}',
    ]);
    expect(commandIds[1]).toBe(commandIds[0]);
  });

  it('hashes a RequestInit body override as the effective mutation body', async () => {
    const requests: Request[] = [];
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async input => {
      requests.push(input as Request);
      return new Response('{"error":"ambiguous proxy response"}', { status: 504 });
    }));
    const original = new Request('https://ops.example.test/api/settings', {
      method: 'PATCH',
      body: '{"enabled":false}',
    });
    await dashboardFetch(original, { body: '{"enabled":true}' });
    await dashboardFetch(new Request('https://ops.example.test/api/settings', {
      method: 'PATCH',
      body: '{"enabled":true}',
    }));
    expect(await requests[0].clone().text()).toBe('{"enabled":true}');
    expect(requests[0].headers.get('X-Overwatch-Command-Id'))
      .toBe(requests[1].headers.get('X-Overwatch-Command-Id'));
  });

  it('fails closed before sending an unidentifiable oversized Request mutation', async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal('fetch', fetchMock);
    const request = new Request('https://ops.example.test/api/settings', {
      method: 'PATCH',
      body: 'x'.repeat(256 * 1024 + 1),
    });
    await expect(dashboardFetch(request)).rejects.toThrow(/no larger than 262144 bytes/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('retains a pending mutation identity across an outage and clears it after a response', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError('daemon stopped after commit'))
      .mockRejectedValueOnce(new TypeError('daemon remains unavailable'));
    vi.stubGlobal('fetch', fetchMock);
    const request = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ description: 'outage-safe mutation' }),
    };
    await expect(dashboardFetch('/api/config/objectives', request))
      .rejects.toThrow('daemon remains unavailable');
    const retainedId = new Headers(fetchMock.mock.calls[0][1]?.headers)
      .get('X-Overwatch-Command-Id');

    fetchMock.mockResolvedValueOnce(new Response('{"ok":true}', {
      status: 200,
      headers: { 'X-Overwatch-Server-Response': '1' },
    }));
    const recovered = await dashboardFetch('/api/config/objectives', request);
    expect(new Headers(fetchMock.mock.calls[2][1]?.headers).get('X-Overwatch-Command-Id'))
      .toBe(retainedId);
    await recovered.text();

    fetchMock.mockResolvedValueOnce(new Response('{"ok":true}', {
      status: 200,
      headers: { 'X-Overwatch-Server-Response': '1' },
    }));
    await dashboardFetch('/api/config/objectives', request);
    expect(new Headers(fetchMock.mock.calls[3][1]?.headers).get('X-Overwatch-Command-Id'))
      .not.toBe(retainedId);
  });

  it('keeps a pending identity after a proxy-generated complete response', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response('{"error":"gateway timeout"}', { status: 504 }))
      .mockResolvedValueOnce(new Response('{"ok":true}', {
        status: 200,
        headers: { 'X-Overwatch-Server-Response': '1' },
      }));
    vi.stubGlobal('fetch', fetchMock);
    const request = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ description: 'proxy ambiguity' }),
    };

    await (await dashboardFetch('/api/config/objectives', request)).text();
    const firstId = new Headers(fetchMock.mock.calls[0][1]?.headers)
      .get('X-Overwatch-Command-Id');
    await (await dashboardFetch('/api/config/objectives', request)).text();
    expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get('X-Overwatch-Command-Id'))
      .toBe(firstId);
  });

  it('retains identity for an authoritative but response-unavailable command receipt', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response('{"status":"running"}', {
        status: 409,
        headers: {
          'X-Overwatch-Server-Response': '1',
          'X-Overwatch-Boundary-Command-Id': 'boundary-running',
          'X-Overwatch-Command-Status': 'running',
          'X-Overwatch-Command-Response-Available': '0',
        },
      }))
      .mockResolvedValueOnce(new Response('{"ok":true}', {
        status: 200,
        headers: {
          'X-Overwatch-Server-Response': '1',
          'X-Overwatch-Boundary-Command-Id': 'boundary-running',
          'X-Overwatch-Command-Status': 'succeeded',
          'X-Overwatch-Command-Response-Available': '1',
        },
      }))
      .mockResolvedValueOnce(new Response('{"ok":true}', {
        status: 200,
        headers: { 'X-Overwatch-Server-Response': '1' },
      }));
    vi.stubGlobal('fetch', fetchMock);
    const request = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ description: 'ambiguous receipt' }),
    };
    await (await dashboardFetch('/api/config/objectives', request)).text();
    const retained = new Headers(fetchMock.mock.calls[0][1]?.headers)
      .get('X-Overwatch-Command-Id');
    await (await dashboardFetch('/api/config/objectives', request)).text();
    expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get('X-Overwatch-Command-Id'))
      .toBe(retained);
    await (await dashboardFetch('/api/config/objectives', request)).text();
    expect(new Headers(fetchMock.mock.calls[2][1]?.headers).get('X-Overwatch-Command-Id'))
      .not.toBe(retained);
  });

  it('clears a pending identity after a definitive expired-receipt response', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response('{"error":"receipt expired"}', {
        status: 409,
        headers: {
          'X-Overwatch-Server-Response': '1',
          'X-Overwatch-Boundary-Command-Id': 'boundary-expired',
          'X-Overwatch-Command-Status': 'failed',
          'X-Overwatch-Command-Response-Available': '1',
        },
      }))
      .mockResolvedValueOnce(new Response('{"ok":true}', {
        status: 200,
        headers: { 'X-Overwatch-Server-Response': '1' },
      }));
    vi.stubGlobal('fetch', fetchMock);
    const request = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ description: 'expired pending identity' }),
    };
    await (await dashboardFetch('/api/config/objectives', request)).text();
    const expiredId = new Headers(fetchMock.mock.calls[0][1]?.headers)
      .get('X-Overwatch-Command-Id');
    await dashboardFetch('/api/config/objectives', request);
    expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get('X-Overwatch-Command-Id'))
      .not.toBe(expiredId);
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

  it('rejects truncated or digest-mismatched protected downloads before creating a blob URL', async () => {
    initializeDashboardAuth({ href: 'https://ops.example.test/' });
    const create = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:should-not-exist');
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(new Blob(['short']), {
      status: 200,
      headers: { 'Content-Length': '99' },
    })));
    await expect(fetchAuthenticatedBlobUrl('/api/bundle')).rejects.toThrow(/truncated/i);
    expect(create).not.toHaveBeenCalled();

    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(new Blob(['bundle']), {
      status: 200,
      headers: { 'Content-Digest': 'sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:' },
    })));
    await expect(fetchAuthenticatedBlobUrl('/api/bundle')).rejects.toThrow(/integrity/i);
    expect(create).not.toHaveBeenCalled();
  });

  it('verifies a valid digest incrementally before publishing the blob URL', async () => {
    initializeDashboardAuth({ href: 'https://ops.example.test/' });
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(new Blob(['bundle']), {
      status: 200,
      headers: {
        'Content-Length': '6',
        'Content-Digest': 'sha-256=:Hm7WXXfWNk7q7Vp0W6XEmFritwDdhdfPfwJ73ylKM/w=:',
      },
    })));
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:verified');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    const resource = await fetchAuthenticatedBlobUrl('/api/bundle');
    expect(resource.bytes).toBe(6);
    expect(resource.url).toBe('blob:verified');
    resource.revoke();
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
