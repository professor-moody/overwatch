// ============================================================
// Operator CLI — Node HTTP client over the Overwatch /api surface
// ============================================================
// A thin standalone client (NOT the browser src/dashboard-next/src/lib/api.ts —
// that uses relative URLs + no token injection). Node 20+ provides global fetch.
// Loopback needs no auth; remote uses a bearer token. A CLI sends no Origin
// header, so the server's CSRF check never triggers.

import { randomUUID } from 'node:crypto';

export interface ClientOptions {
  url: string;
  token?: string;
}

const DEFAULT_URL = 'http://127.0.0.1:8384';

/** Resolve base URL + token from flags (--url/--token) then env then default. */
export function resolveClientOptions(args: string[]): ClientOptions {
  const flag = (name: string): string | undefined => {
    const i = args.indexOf(`--${name}`);
    return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
  };
  const url = flag('url') || process.env.OVERWATCH_URL || DEFAULT_URL;
  const token = flag('token') || process.env.OVERWATCH_DASHBOARD_TOKEN || undefined;
  return { url: url.replace(/\/+$/, ''), token };
}

/** A normalized API failure (unreachable server, or non-2xx with server detail). */
export class ApiError extends Error {
  constructor(message: string, readonly status?: number, readonly body?: unknown) {
    super(message);
    this.name = 'ApiError';
  }
  /** True when the server could not be reached at all (vs. an HTTP error). */
  get unreachable(): boolean { return this.status === undefined; }
}

async function request<T>(opts: ClientOptions, method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {
    'X-Overwatch-Client': 'cli',
  };
  if (opts.token) headers['Authorization'] = `Bearer ${opts.token}`;
  if (body !== undefined) {
    const commandId = randomUUID();
    headers['Content-Type'] = 'application/json';
    headers['X-Overwatch-Command-Id'] = commandId;
    headers['Idempotency-Key'] = `cli:${method}:${path}:${commandId}`;
  }

  let res: Response;
  try {
    res = await fetch(`${opts.url}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(
      `Overwatch server not reachable at ${opts.url}. Start it with \`npm start -- --http\` (or pass --url / set OVERWATCH_URL).`,
    );
  }

  const text = await res.text();
  let parsed: unknown;
  if (text) {
    try { parsed = JSON.parse(text); } catch { parsed = text; }
  }

  if (!res.ok) {
    const detail =
      parsed && typeof parsed === 'object'
        ? String((parsed as Record<string, unknown>).error ?? (parsed as Record<string, unknown>).reason ?? res.statusText)
        : (typeof parsed === 'string' && parsed ? parsed : res.statusText);
    throw new ApiError(`${res.status} ${detail}`, res.status, parsed);
  }

  return parsed as T;
}

export interface ApiClient {
  get<T>(path: string): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
}

export function createClient(opts: ClientOptions): ApiClient {
  return {
    get: <T>(path: string) => request<T>(opts, 'GET', path),
    post: <T>(path: string, body?: unknown) => request<T>(opts, 'POST', path, body ?? {}),
  };
}
