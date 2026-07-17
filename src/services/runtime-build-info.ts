import { readFileSync } from 'node:fs';

export interface RuntimeBuildInfo {
  schema_version: number;
  git_sha?: string | null;
  input_sha256: string;
  input_file_count?: number;
  built_at?: string;
  runtime_pid: number;
  runtime_started_at: string;
}

const runtimeStartedAt = new Date().toISOString();

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value);
}

/** Read the metadata written by `npm run build`. The first path is correct in
 * packaged/compiled execution; the second keeps source-mode tests and local
 * development pointed at the same dist metadata. */
export function readRuntimeBuildInfo(): RuntimeBuildInfo | undefined {
  const candidates = [
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
      };
    } catch {
      // Try the next package/source-layout candidate.
    }
  }
  return undefined;
}

export interface RunningDashboardProbe {
  running: boolean;
  runtime_build?: RuntimeBuildInfo;
}

export async function probeRunningDashboard(
  port: number,
  fetchImpl: typeof fetch = fetch,
): Promise<RunningDashboardProbe> {
  if (!Number.isFinite(port) || port <= 0) return { running: false };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1_500);
  try {
    const response = await fetchImpl(`http://127.0.0.1:${port}/api/health`, {
      signal: controller.signal,
    });
    if (!response.ok) return { running: false };
    const body = await response.json() as Record<string, unknown>;
    const running = 'health_checks' in body || 'status' in body || 'issues' in body;
    if (!running) return { running: false };
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
      },
    };
  } catch {
    return { running: false };
  } finally {
    clearTimeout(timer);
  }
}
