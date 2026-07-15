const TOKEN_STORAGE_KEY = 'overwatch.dashboard.token';

let memoryToken: string | null = null;

export interface DashboardAuthEnvironment {
  href: string;
  storage?: Pick<Storage, 'getItem' | 'setItem'>;
  replaceState?: (state: unknown, unused: string, url?: string | URL | null) => void;
  historyState?: unknown;
}

function browserStorage(): Pick<Storage, 'getItem' | 'setItem'> | undefined {
  if (typeof window === 'undefined') return undefined;
  try {
    return window.sessionStorage;
  } catch {
    return undefined;
  }
}

function browserEnvironment(): DashboardAuthEnvironment {
  if (typeof window === 'undefined') return { href: 'http://localhost/' };
  let replaceState: DashboardAuthEnvironment['replaceState'];
  let historyState: unknown;
  try {
    replaceState = window.history.replaceState.bind(window.history);
    historyState = window.history.state;
  } catch {
    // Storage-restricted or synthetic environments may also restrict history.
  }
  return {
    href: window.location.href,
    storage: browserStorage(),
    replaceState,
    historyState,
  };
}

/**
 * Capture a landing-page token before React mounts and scrub every token query
 * parameter from the visible URL. A module-memory copy keeps remote mode usable
 * when sessionStorage is disabled or throws (privacy modes, storage policies).
 */
export function initializeDashboardAuth(environment?: DashboardAuthEnvironment): string | null {
  const environmentToUse = environment ?? browserEnvironment();
  const url = new URL(environmentToUse.href);
  const landingTokens = url.searchParams.getAll('token');
  const landingToken = [...landingTokens].reverse().find(value => value.length > 0) ?? null;

  if (landingToken) {
    memoryToken = landingToken;
    try {
      environmentToUse.storage?.setItem(TOKEN_STORAGE_KEY, landingToken);
    } catch {
      // The in-memory token remains authoritative for this page lifetime.
    }
  } else {
    try {
      memoryToken = environmentToUse.storage?.getItem(TOKEN_STORAGE_KEY) ?? memoryToken;
    } catch {
      // Preserve the last captured in-memory value.
    }
  }

  if (landingTokens.length > 0) {
    url.searchParams.delete('token');
    const scrubbed = `${url.pathname}${url.search}${url.hash}`;
    try {
      environmentToUse.replaceState?.(environmentToUse.historyState, '', scrubbed);
    } catch {
      // Keep the captured credential usable even in restricted history modes.
    }
  }
  return memoryToken;
}

export function getDashboardToken(storage?: Pick<Storage, 'getItem'>): string | null {
  // A token captured from the current landing URL is newer and more
  // authoritative than any stale value left in storage. Consult storage only
  // when this page lifetime has not captured or loaded a token yet.
  if (memoryToken) return memoryToken;
  try {
    const persisted = (storage ?? browserStorage())?.getItem(TOKEN_STORAGE_KEY);
    if (persisted) memoryToken = persisted;
  } catch {
    // Fall back to the token captured during bootstrap.
  }
  return memoryToken;
}

/** Fetch any protected dashboard resource with the shared Bearer credential. */
export function dashboardFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(input instanceof Request ? input.headers : undefined);
  new Headers(init.headers).forEach((value, key) => headers.set(key, value));
  const token = getDashboardToken();
  if (token && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${token}`);
  return globalThis.fetch(input, { ...init, headers });
}

export function authenticatedWebSocketUrl(path: string, href?: string): string {
  const baseHref = href ?? (typeof window === 'undefined' ? 'http://localhost/' : window.location.href);
  const url = new URL(path, baseHref);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  const token = getDashboardToken();
  if (token) url.searchParams.set('token', token);
  return url.toString();
}

export function createDashboardWebSocket(path: string, protocols?: string | string[]): WebSocket {
  return new globalThis.WebSocket(authenticatedWebSocketUrl(path), protocols);
}

export interface AuthenticatedBlobUrl {
  url: string;
  bytes: number;
  response: Response;
  revoke: () => void;
}

export async function fetchAuthenticatedBlobUrl(path: string, signal?: AbortSignal): Promise<AuthenticatedBlobUrl> {
  const response = await dashboardFetch(path, { signal });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`${response.status} ${response.statusText}: ${body}`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  let revoked = false;
  return {
    url,
    bytes: blob.size,
    response,
    revoke: () => {
      if (revoked) return;
      revoked = true;
      URL.revokeObjectURL(url);
    },
  };
}

export interface DashboardDownloadResult {
  filename: string;
  bytes: number;
}

export async function downloadDashboardResource(
  path: string,
  options: { filename?: string; signal?: AbortSignal } = {},
): Promise<DashboardDownloadResult> {
  const resource = await fetchAuthenticatedBlobUrl(path, options.signal);
  let anchor: HTMLAnchorElement | null = null;
  try {
    const disposition = resource.response.headers.get('Content-Disposition') ?? '';
    const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
    const quoted = disposition.match(/filename="([^"]+)"/i)?.[1];
    const filename = options.filename
      ?? (encoded ? decodeURIComponent(encoded) : quoted)
      ?? `overwatch-download-${Date.now()}`;
    anchor = document.createElement('a');
    anchor.href = resource.url;
    anchor.download = filename;
    anchor.rel = 'noopener';
    anchor.hidden = true;
    document.body.append(anchor);
    anchor.click();
    // Give the browser a task to consume the object URL before releasing it.
    globalThis.setTimeout(resource.revoke, 0);
    return { filename, bytes: resource.bytes };
  } catch (error) {
    resource.revoke();
    throw error;
  } finally {
    anchor?.remove();
  }
}

export async function openDashboardResource(path: string, signal?: AbortSignal): Promise<void> {
  const popup = window.open('about:blank', '_blank');
  let resource: AuthenticatedBlobUrl | undefined;
  let cleanupScheduled = false;
  try {
    resource = await fetchAuthenticatedBlobUrl(path, signal);
    if (!popup) {
      throw new Error('The browser blocked the report window');
    }
    popup.opener = null;
    popup.location.replace(resource.url);
    // The new document owns the bytes after navigation. Keep the URL alive long
    // enough for slow renderers (notably PDF), then release it deterministically.
    window.setTimeout(resource.revoke, 60_000);
    cleanupScheduled = true;
  } catch (error) {
    if (!cleanupScheduled) resource?.revoke();
    popup?.close();
    throw error;
  }
}

export { TOKEN_STORAGE_KEY };
