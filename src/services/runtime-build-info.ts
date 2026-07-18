import { createHash, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { join, relative, resolve } from 'node:path';

export interface RuntimeBuildInfo {
  schema_version: number;
  git_sha?: string | null;
  input_sha256: string;
  input_file_count?: number;
  built_at?: string;
  runtime_pid: number;
  runtime_started_at: string;
  runtime_instance_id: string;
}

const runtimeStartedAt = new Date().toISOString();
const runtimeInstanceId = randomUUID();
const FALLBACK_INPUT_PATHS = [
  'src',
  'scripts',
  'skills',
  'engagement-templates',
  'package.json',
  'package-lock.json',
  'tsconfig.json',
  'tsconfig.build.json',
] as const;
let cachedFallback: { root: string; sha256: string; fileCount: number } | undefined;

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value);
}

function collectFingerprintFiles(root: string, input: string, files: string[]): void {
  const absolute = join(root, input);
  if (!existsSync(absolute)) return;
  const stat = statSync(absolute);
  if (stat.isFile()) {
    files.push(absolute);
    return;
  }
  if (!stat.isDirectory()) return;
  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist') continue;
    collectFingerprintFiles(root, join(input, entry.name), files);
  }
}

function fingerprintRuntimeInputs(root: string): { sha256: string; fileCount: number } {
  const files: string[] = [];
  for (const input of FALLBACK_INPUT_PATHS) collectFingerprintFiles(root, input, files);
  files.sort((left, right) => left.localeCompare(right));
  const hash = createHash('sha256');
  for (const file of files) {
    hash.update(relative(root, file));
    hash.update('\0');
    hash.update(readFileSync(file));
    hash.update('\0');
  }
  return { sha256: hash.digest('hex'), fileCount: files.length };
}

export interface ReadRuntimeBuildInfoOptions {
  metadataCandidates?: readonly URL[];
  fallbackRoot?: string;
}

/** Read the metadata written by `npm run build`. The first path is correct in
 * packaged/compiled execution; the second keeps source-mode tests and local
 * development pointed at the same dist metadata. A clean source checkout has
 * no dist artifact, so derive the same input fingerprint directly rather than
 * omitting runtime identity or depending on residue from a previous build. */
export function readRuntimeBuildInfo(options: ReadRuntimeBuildInfoOptions = {}): RuntimeBuildInfo {
  const candidates = options.metadataCandidates ?? [
    new URL('../build-info.json', import.meta.url),
    new URL('../../dist/build-info.json', import.meta.url),
  ];
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(readFileSync(candidate, 'utf8')) as Record<string, unknown>;
      if (!Number.isInteger(parsed.schema_version) || !isSha256(parsed.input_sha256)) continue;
      return {
        schema_version: Number(parsed.schema_version),
        ...(typeof parsed.git_sha === 'string' || parsed.git_sha === null
          ? { git_sha: parsed.git_sha }
          : {}),
        input_sha256: parsed.input_sha256.toLowerCase(),
        ...(Number.isInteger(parsed.input_file_count)
          ? { input_file_count: Number(parsed.input_file_count) }
          : {}),
        ...(typeof parsed.built_at === 'string' ? { built_at: parsed.built_at } : {}),
        runtime_pid: process.pid,
        runtime_started_at: runtimeStartedAt,
        runtime_instance_id: runtimeInstanceId,
      };
    } catch {
      // Try the next package/source-layout candidate.
    }
  }
  const root = resolve(options.fallbackRoot ?? fileURLToPath(new URL('../../', import.meta.url)));
  const fingerprint = options.fallbackRoot === undefined && cachedFallback?.root === root
    ? cachedFallback
    : { root, ...fingerprintRuntimeInputs(root) };
  if (options.fallbackRoot === undefined) cachedFallback = fingerprint;
  return {
    schema_version: 1,
    input_sha256: fingerprint.sha256,
    input_file_count: fingerprint.fileCount,
    runtime_pid: process.pid,
    runtime_started_at: runtimeStartedAt,
    runtime_instance_id: runtimeInstanceId,
  };
}

export interface RunningDashboardProbe {
  running: boolean;
  runtime_build?: RuntimeBuildInfo;
}

/** Fail-closed ownership check. An occupied dashboard port means another
 * process already owns the runtime surface, even when its HTTP identity is
 * protected, slow, malformed, or from an older Overwatch build. */
export async function isDashboardPortOccupied(
  port: number,
  host = '127.0.0.1',
): Promise<boolean> {
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) return false;
  return new Promise(resolve => {
    const server = createServer();
    server.once('error', () => resolve(true));
    server.once('listening', () => {
      server.close(() => resolve(false));
    });
    server.listen(port, host);
  });
}

function probeAddress(host: string): string {
  const normalized = host.trim().toLowerCase();
  if (normalized === '0.0.0.0') return '127.0.0.1';
  if (normalized === '::' || normalized === '[::]') return '[::1]';
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

export async function probeRunningDashboard(
  port: number,
  fetchImpl: typeof fetch = fetch,
  portOccupied: (port: number, host: string) => Promise<boolean> = isDashboardPortOccupied,
  authorization?: string,
  host = '127.0.0.1',
): Promise<RunningDashboardProbe> {
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) return { running: false };
  if (!(await portOccupied(port, host))) return { running: false };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1_500);
  try {
    const response = await fetchImpl(`http://${probeAddress(host)}:${port}/api/runtime`, {
      ...(authorization ? { headers: { Authorization: authorization } } : {}),
      signal: controller.signal,
    });
    if (!response.ok) return { running: true };
    const body = await response.json() as Record<string, unknown>;
    const candidate = body.runtime_build;
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
      return { running: true };
    }
    const record = candidate as Record<string, unknown>;
    if (!isSha256(record.input_sha256)) return { running: true };
    return {
      running: true,
      runtime_build: {
        schema_version: Number(record.schema_version) || 1,
        ...(typeof record.git_sha === 'string' || record.git_sha === null
          ? { git_sha: record.git_sha }
          : {}),
        input_sha256: record.input_sha256.toLowerCase(),
        ...(Number.isInteger(record.input_file_count)
          ? { input_file_count: Number(record.input_file_count) }
          : {}),
        ...(typeof record.built_at === 'string' ? { built_at: record.built_at } : {}),
        runtime_pid: Number(record.runtime_pid) || 0,
        runtime_started_at: typeof record.runtime_started_at === 'string'
          ? record.runtime_started_at
          : '',
        runtime_instance_id: typeof record.runtime_instance_id === 'string'
          ? record.runtime_instance_id
          : '',
      },
    };
  } catch {
    return { running: true };
  } finally {
    clearTimeout(timer);
  }
}
