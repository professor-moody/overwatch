// ============================================================
// Operator CLI — Node HTTP client over the Overwatch /api surface
// ============================================================
// A thin standalone client (NOT the browser src/dashboard-next/src/lib/api.ts —
// that uses relative URLs + no token injection). Node 20+ provides global fetch.
// Loopback needs no auth; remote uses a bearer token. A CLI sends no Origin
// header, so the server's CSRF check never triggers.

import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export interface ClientOptions {
  url: string;
  token?: string;
  /** Explicit identity for deliberately independent, otherwise-identical mutations. */
  commandId?: string;
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
  const commandId = flag('command-id') || process.env.OVERWATCH_COMMAND_ID || undefined;
  return { url: url.replace(/\/+$/, ''), token, commandId };
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

interface PendingCliCommand {
  version: 1;
  command_id: string;
  created_at: number;
  request_fingerprint: string;
}

const MAX_PENDING_CLI_COMMANDS = 128;

function pendingCommandDirectory(): string {
  return process.env.OVERWATCH_CLI_PENDING_DIR
    ?? join(homedir(), '.overwatch', 'cli-pending-commands');
}

function syncDirectory(path: string): void {
  try {
    const descriptor = openSync(path, 'r');
    try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
  } catch {
    // Some platforms do not permit directory descriptors. The receipt file
    // itself is still fsynced before any network mutation is sent.
  }
}

function ensureDirectoryDurable(path: string): void {
  if (existsSync(path)) return;
  const parent = dirname(path);
  if (parent !== path) ensureDirectoryDurable(parent);
  try {
    mkdirSync(path, { mode: 0o700 });
  } catch (error) {
    if (!existsSync(path)) throw error;
  }
  // Creation durability requires the parent directory entry itself to reach
  // disk; syncing only the newly opened receipt file is insufficient.
  syncDirectory(parent);
  syncDirectory(path);
}

function pendingCommandPath(fingerprint: string): string {
  return join(pendingCommandDirectory(), `${fingerprint}.json`);
}

function readPendingCommand(path: string, fingerprint: string): PendingCliCommand | null {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as PendingCliCommand;
    if (
      parsed.version !== 1
      || parsed.request_fingerprint !== fingerprint
      || typeof parsed.command_id !== 'string'
      || !Number.isFinite(parsed.created_at)
    ) return null;
    return parsed;
  } catch {
    return null;
  }
}

function acquirePendingCommand(
  fingerprint: string,
  requestedCommandId?: string,
): { commandId: string; path: string } {
  const directory = pendingCommandDirectory();
  const path = pendingCommandPath(fingerprint);
  try {
    ensureDirectoryDurable(directory);
    const retained = readPendingCommand(path, fingerprint);
    if (retained) {
      if (requestedCommandId && retained.command_id !== requestedCommandId) {
        throw new Error(
          `pending receipt ${path} belongs to command ${retained.command_id}, not ${requestedCommandId}`,
        );
      }
      return { commandId: retained.command_id, path };
    }
    if (
      readdirSync(directory).filter(name => /^[a-f0-9]{64}\.json$/.test(name)).length
      >= MAX_PENDING_CLI_COMMANDS
    ) {
      throw new Error(
        `the pending receipt limit (${MAX_PENDING_CLI_COMMANDS}) is reached; `
        + 'retry or inspect existing CLI mutations before sending another',
      );
    }

    const record: PendingCliCommand = {
      version: 1,
      command_id: requestedCommandId ?? randomUUID(),
      created_at: Date.now(),
      request_fingerprint: fingerprint,
    };
    let descriptor: number;
    try {
      descriptor = openSync(path, 'wx', 0o600);
    } catch (error) {
      const raced = readPendingCommand(path, fingerprint);
      if (raced) return { commandId: raced.command_id, path };
      throw error;
    }
    try {
      writeFileSync(descriptor, JSON.stringify(record));
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    syncDirectory(directory);
    return { commandId: record.command_id, path };
  } catch (error) {
    throw new ApiError(
      `Cannot durably reserve a CLI mutation receipt in ${directory}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

function clearPendingCommand(path: string): void {
  try {
    rmSync(path, { force: true });
    syncDirectory(pendingCommandDirectory());
  } catch {
    // Retaining a completed receipt is safe: a later identical request will
    // replay the server outcome and clear it on the next received response.
  }
}

async function request<T>(opts: ClientOptions, method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {
    'X-Overwatch-Client': 'cli',
  };
  if (opts.token) headers['Authorization'] = `Bearer ${opts.token}`;
  const serializedBody = body !== undefined ? JSON.stringify(body) : undefined;
  let pendingReceiptPath: string | undefined;
  if (serializedBody !== undefined) {
    const requestFingerprint = createHash('sha256')
      .update(`${opts.url}\0${method}\0${path}\0${serializedBody}\0${opts.commandId ?? ''}`)
      .digest('hex');
    const pending = acquirePendingCommand(requestFingerprint, opts.commandId);
    const commandId = pending.commandId;
    pendingReceiptPath = pending.path;
    headers['Content-Type'] = 'application/json';
    headers['X-Overwatch-Command-Id'] = commandId;
    headers['Idempotency-Key'] = `cli:${method}:${path}:${commandId}`;
  }

  let res: Response;
  try {
    const request = {
      method,
      headers,
      body: serializedBody,
    };
    try {
      res = await fetch(`${opts.url}${path}`, request);
    } catch (firstError) {
      if (body === undefined) throw firstError;
      // One same-identity retry closes the commit/response-loss window. The
      // server's external command receipt guarantees this cannot execute the
      // mutation a second time.
      res = await fetch(`${opts.url}${path}`, request);
    }
  } catch {
    throw new ApiError(
      `Overwatch server not reachable at ${opts.url}. Start it with \`npm run start:daemon\` (or pass --url / set OVERWATCH_URL).`,
    );
  }

  const text = await res.text();
  const boundaryReserved = res.headers.has('X-Overwatch-Boundary-Command-Id');
  const authoritativeResponse = boundaryReserved
    ? res.headers.get('X-Overwatch-Command-Response-Available') === '1'
    : res.headers.get('X-Overwatch-Server-Response') === '1';
  if (pendingReceiptPath && authoritativeResponse) clearPendingCommand(pendingReceiptPath);
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
