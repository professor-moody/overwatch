import { safeSessionStorage } from './browser-storage';

const TOKEN_STORAGE_KEY = 'overwatch.dashboard.token';
const PENDING_COMMAND_STORAGE_PREFIX = 'overwatch.dashboard.pending.';

let memoryToken: string | null = null;
const pendingCommandMemory = new Map<string, string>();

export function resetDashboardAuthMemoryForTest(): void {
  memoryToken = null;
}

export function resetDashboardPendingCommandsForTest(): void {
  for (const key of pendingCommandMemory.keys()) safeSessionStorage.removeItem(key);
  pendingCommandMemory.clear();
}

export interface DashboardAuthEnvironment {
  href: string;
  storage?: Pick<Storage, 'getItem' | 'setItem'>;
  replaceState?: (state: unknown, unused: string, url?: string | URL | null) => void;
  historyState?: unknown;
}

function browserStorage(): Pick<Storage, 'getItem' | 'setItem'> | undefined {
  return safeSessionStorage;
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

export function createDashboardCommandId(): string {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  return `dashboard-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function pendingMutationStorageKey(
  input: RequestInfo | URL,
  method: string,
  body: BodyInit | null | undefined,
): Promise<string | null> {
  let bytes: Uint8Array;
  if (body === undefined || body === null) {
    bytes = new Uint8Array();
  } else if (typeof body === 'string') {
    bytes = new TextEncoder().encode(body);
  } else if (body instanceof URLSearchParams) {
    bytes = new TextEncoder().encode(body.toString());
  } else if (body instanceof Blob) {
    if (body.size > MAX_REPLAYABLE_MUTATION_REQUEST_BYTES) return null;
    try {
      bytes = new Uint8Array(await body.arrayBuffer());
    } catch {
      return null;
    }
  } else if (body instanceof ArrayBuffer) {
    if (body.byteLength > MAX_REPLAYABLE_MUTATION_REQUEST_BYTES) return null;
    bytes = new Uint8Array(body);
  } else if (ArrayBuffer.isView(body)) {
    if (body.byteLength > MAX_REPLAYABLE_MUTATION_REQUEST_BYTES) return null;
    bytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  } else {
    return null;
  }
  if (bytes.byteLength > MAX_REPLAYABLE_MUTATION_REQUEST_BYTES) return null;
  const target = input instanceof Request ? input.url : String(input);
  return pendingMutationStorageKeyFromBytes(
    target,
    method,
    bytes,
  );
}

function pendingMutationStorageKeyFromBytes(
  target: string,
  method: string,
  body: Uint8Array,
): string {
  const digest = new StreamingSha256();
  digest.update(new TextEncoder().encode(`${method}\0${target}\0`));
  digest.update(body);
  const suffix = [...digest.digest()]
    .map(value => value.toString(16).padStart(2, '0'))
    .join('');
  return `${PENDING_COMMAND_STORAGE_PREFIX}${suffix}`;
}

const MAX_REPLAYABLE_MUTATION_REQUEST_BYTES = 256 * 1024;

async function boundedRequestBody(
  request: Request,
): Promise<Uint8Array | null> {
  if (!request.body) return new Uint8Array();
  const reader = request.clone().body!.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      bytes += next.value.byteLength;
      if (bytes > MAX_REPLAYABLE_MUTATION_REQUEST_BYTES) {
        await reader.cancel('dashboard mutation body exceeds replay limit');
        return null;
      }
      chunks.push(next.value);
    }
  } catch {
    return null;
  }
  const body = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function pendingDashboardCommandId(storageKey: string | null): string {
  if (storageKey) {
    const retained = pendingCommandMemory.get(storageKey) ?? safeSessionStorage.getItem(storageKey);
    if (retained) {
      pendingCommandMemory.set(storageKey, retained);
      return retained;
    }
  }
  const commandId = createDashboardCommandId();
  if (storageKey) {
    pendingCommandMemory.set(storageKey, commandId);
    safeSessionStorage.setItem(storageKey, commandId);
  }
  return commandId;
}

function clearPendingDashboardCommand(storageKey: string | null): void {
  if (!storageKey) return;
  pendingCommandMemory.delete(storageKey);
  safeSessionStorage.removeItem(storageKey);
}

function clearPendingWhenResponseCompletes(
  response: Response,
  storageKey: string | null,
): Response {
  if (!storageKey) return response;
  const boundaryReserved = response.headers.has('X-Overwatch-Boundary-Command-Id');
  const authoritative = boundaryReserved
    ? response.headers.get('X-Overwatch-Command-Response-Available') === '1'
    : response.headers.get('X-Overwatch-Server-Response') === '1';
  // A reverse proxy may synthesize a complete 502/504 after the daemon
  // committed but before it returned headers. A durable boundary marker is
  // conclusive only when the original response is available for replay;
  // accepted/running/delivery-error receipts remain pending.
  if (!authoritative) return response;
  if (!response.body) {
    clearPendingDashboardCommand(storageKey);
    return response;
  }
  const reader = response.body.getReader();
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const next = await reader.read();
        if (next.done) {
          clearPendingDashboardCommand(storageKey);
          controller.close();
        } else {
          controller.enqueue(next.value);
        }
      } catch (error) {
        // A body-level transport failure is still an ambiguous delivery. Keep
        // the receipt so a later identical mutation replays the durable result.
        controller.error(error);
      }
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

/** Fetch any protected dashboard resource with the shared Bearer credential. */
export async function dashboardFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  if (input instanceof Request) {
    const effective = new Request(input, init);
    const method = effective.method.toUpperCase();
    const mutation = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
    const body = mutation ? await boundedRequestBody(effective) : new Uint8Array();
    const headers = new Headers(effective.headers);
    const token = getDashboardToken();
    if (token && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${token}`);
    if (!headers.has('X-Overwatch-Client')) headers.set('X-Overwatch-Client', 'dashboard');
    let pendingStorageKey: string | null = null;
    if (mutation) {
      if (!body && !headers.has('X-Overwatch-Command-Id')) {
        throw new Error(
          `Dashboard mutation Request bodies must be readable and no larger than ${MAX_REPLAYABLE_MUTATION_REQUEST_BYTES} bytes unless the caller supplies X-Overwatch-Command-Id.`,
        );
      }
      if (!headers.has('X-Overwatch-Command-Id') && body) {
        pendingStorageKey = pendingMutationStorageKeyFromBytes(
          effective.url,
          method,
          body,
        );
      }
      const commandId = headers.get('X-Overwatch-Command-Id')
        ?? pendingDashboardCommandId(pendingStorageKey);
      if (!headers.has('X-Overwatch-Command-Id')) {
        headers.set('X-Overwatch-Command-Id', commandId);
      }
      if (!headers.has('Idempotency-Key')) {
        headers.set('Idempotency-Key', `dashboard:${method}:${commandId}`);
      }
    }
    const request = new Request(effective, { headers });
    const retry = mutation && body ? request.clone() : null;
    try {
      const response = await globalThis.fetch(request);
      return clearPendingWhenResponseCompletes(response, pendingStorageKey);
    } catch (firstError) {
      if (!retry) throw firstError;
      const response = await globalThis.fetch(retry);
      return clearPendingWhenResponseCompletes(response, pendingStorageKey);
    }
  }
  const headers = new Headers(input instanceof Request ? input.headers : undefined);
  new Headers(init.headers).forEach((value, key) => headers.set(key, value));
  const token = getDashboardToken();
  if (token && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${token}`);
  const method = (init.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
  let pendingStorageKey: string | null = null;
  if (!headers.has('X-Overwatch-Client')) headers.set('X-Overwatch-Client', 'dashboard');
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    if (!headers.has('X-Overwatch-Command-Id')) {
      pendingStorageKey = await pendingMutationStorageKey(input, method, init.body);
      if (!pendingStorageKey) {
        throw new Error(
          `Dashboard mutation bodies must be replayable and no larger than ${MAX_REPLAYABLE_MUTATION_REQUEST_BYTES} bytes unless the caller supplies X-Overwatch-Command-Id.`,
        );
      }
    }
    const commandId = headers.get('X-Overwatch-Command-Id')
      ?? pendingDashboardCommandId(pendingStorageKey);
    if (!headers.has('X-Overwatch-Command-Id')) {
      headers.set('X-Overwatch-Command-Id', commandId);
    }
    if (!headers.has('Idempotency-Key')) {
      headers.set('Idempotency-Key', `dashboard:${method}:${commandId}`);
    }
  }
  const request = { ...init, headers };
  try {
    const response = await globalThis.fetch(input, request);
    return clearPendingWhenResponseCompletes(response, pendingStorageKey);
  } catch (firstError) {
    // A transport failure may happen after the daemon committed but before
    // the browser received the response. Reuse the exact same command and
    // idempotency headers once; the server will replay instead of mutating
    // twice. Streaming request bodies cannot be safely replayed here.
    const replayableBody = init.body === undefined
      || init.body === null
      || typeof init.body === 'string'
      || init.body instanceof URLSearchParams
      || init.body instanceof Blob
      || init.body instanceof ArrayBuffer
      || ArrayBuffer.isView(init.body);
    if (
      method === 'GET'
      || method === 'HEAD'
      || method === 'OPTIONS'
      || !replayableBody
    ) throw firstError;
    const response = await globalThis.fetch(input, request);
    return clearPendingWhenResponseCompletes(response, pendingStorageKey);
  }
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

const MAX_AUTHENTICATED_BLOB_BYTES = 512 * 1024 * 1024;

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotateRight(value: number, bits: number): number {
  return (value >>> bits) | (value << (32 - bits));
}

/** Small incremental SHA-256 used only for authenticated downloads. WebCrypto
 * requires one contiguous ArrayBuffer; this keeps verification bounded to the
 * 64-byte working block while the Blob retains the sole payload copy. */
class StreamingSha256 {
  private state = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  private block = new Uint8Array(64);
  private blockLength = 0;
  private bytes = 0;

  update(input: Uint8Array): void {
    this.bytes += input.byteLength;
    let offset = 0;
    while (offset < input.byteLength) {
      const take = Math.min(64 - this.blockLength, input.byteLength - offset);
      this.block.set(input.subarray(offset, offset + take), this.blockLength);
      this.blockLength += take;
      offset += take;
      if (this.blockLength === 64) {
        this.compress(this.block);
        this.blockLength = 0;
      }
    }
  }

  digest(): Uint8Array {
    const bitLength = this.bytes * 8;
    this.block[this.blockLength++] = 0x80;
    if (this.blockLength > 56) {
      this.block.fill(0, this.blockLength);
      this.compress(this.block);
      this.blockLength = 0;
    }
    this.block.fill(0, this.blockLength, 56);
    const high = Math.floor(bitLength / 0x1_0000_0000);
    const low = bitLength >>> 0;
    for (let i = 0; i < 4; i++) {
      this.block[56 + i] = (high >>> (24 - i * 8)) & 0xff;
      this.block[60 + i] = (low >>> (24 - i * 8)) & 0xff;
    }
    this.compress(this.block);
    const output = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      output[i * 4] = this.state[i] >>> 24;
      output[i * 4 + 1] = this.state[i] >>> 16;
      output[i * 4 + 2] = this.state[i] >>> 8;
      output[i * 4 + 3] = this.state[i];
    }
    return output;
  }

  private compress(block: Uint8Array): void {
    const words = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      const j = i * 4;
      words[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const x = words[i - 15];
      const y = words[i - 2];
      const s0 = rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >>> 3);
      const s1 = rotateRight(y, 17) ^ rotateRight(y, 19) ^ (y >>> 10);
      words[i] = (words[i - 16] + s0 + words[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = this.state;
    for (let i = 0; i < 64; i++) {
      const s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choice = (e & f) ^ (~e & g);
      const t1 = (h + s1 + choice + SHA256_K[i] + words[i]) >>> 0;
      const s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + majority) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    this.state[0] = (this.state[0] + a) >>> 0;
    this.state[1] = (this.state[1] + b) >>> 0;
    this.state[2] = (this.state[2] + c) >>> 0;
    this.state[3] = (this.state[3] + d) >>> 0;
    this.state[4] = (this.state[4] + e) >>> 0;
    this.state[5] = (this.state[5] + f) >>> 0;
    this.state[6] = (this.state[6] + g) >>> 0;
    this.state[7] = (this.state[7] + h) >>> 0;
  }
}

function digestBytesToBase64(bytes: ArrayBuffer | Uint8Array): string {
  let binary = '';
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function cancelResponse(response: Response): Promise<void> {
  try { await response.body?.cancel(); } catch { /* rejection remains primary */ }
}

export async function fetchAuthenticatedBlobUrl(path: string, signal?: AbortSignal): Promise<AuthenticatedBlobUrl> {
  const response = await dashboardFetch(path, { signal });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`${response.status} ${response.statusText}: ${body}`);
  }
  const declaredLengthRaw = response.headers.get('Content-Length');
  const declaredLength = declaredLengthRaw === null ? undefined : Number(declaredLengthRaw);
  if (declaredLength !== undefined && (!Number.isSafeInteger(declaredLength) || declaredLength < 0)) {
    await cancelResponse(response);
    throw new Error('Dashboard resource declared an invalid Content-Length.');
  }
  if (declaredLength !== undefined && declaredLength > MAX_AUTHENTICATED_BLOB_BYTES) {
    await cancelResponse(response);
    throw new Error('Dashboard resource exceeds the 512 MiB browser download limit; use the terminal bundle command for larger exports.');
  }
  const digestHeader = response.headers.get('Content-Digest');
  const digestMatch = digestHeader?.match(/^sha-256=:([A-Za-z0-9+/]+={0,2}):$/i);
  if (digestHeader && !digestMatch) {
    await cancelResponse(response);
    throw new Error('Dashboard resource declared an unsupported Content-Digest.');
  }
  const chunks: BlobPart[] = [];
  const digest = new StreamingSha256();
  let observedBytes = 0;
  if (response.body) {
    const reader = response.body.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        observedBytes += value.byteLength;
        if (observedBytes > MAX_AUTHENTICATED_BLOB_BYTES) {
          await reader.cancel();
          throw new Error('Dashboard resource exceeds the 512 MiB browser download limit; use the terminal bundle command for larger exports.');
        }
        digest.update(value);
        chunks.push(value as BlobPart);
      }
    } catch (error) {
      try { await reader.cancel(); } catch { /* preserve the read failure */ }
      throw error;
    }
  }
  if (declaredLength !== undefined && observedBytes !== declaredLength) {
    throw new Error(`Dashboard resource was truncated: expected ${declaredLength} bytes, received ${observedBytes}.`);
  }
  if (digestMatch && digestBytesToBase64(digest.digest()) !== digestMatch[1]) {
    throw new Error('Dashboard resource failed its SHA-256 integrity check.');
  }
  const blob = new Blob(chunks, { type: response.headers.get('Content-Type') ?? undefined });
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
