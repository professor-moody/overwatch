import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import type { DaemonInstanceLease, DaemonLifecyclePhase } from './daemon-instance-lease.js';
import type { RuntimeBuildInfo } from './runtime-build-info.js';
import { readProcessStartIdentity } from './process-identity.js';
import { fsyncDirectory } from './durable-fs.js';

export interface ManagedDaemonRecordV1 {
  version: 1;
  management_nonce: string;
  pid: number;
  process_start_identity: string;
  daemon_instance_id: string;
  runtime_instance_id: string;
  runtime_started_at: string;
  build_input_sha256: string;
  mcp_token_sha256?: string;
  dashboard_token_sha256?: string;
  engagement_id: string;
  config_path: string;
  state_file_path: string;
  config_identity_sha256: string;
  state_identity_sha256: string;
  transport: 'http';
  phase: DaemonLifecyclePhase | 'stopped';
  dashboard_url?: string;
  mcp_url?: string;
  log_path?: string;
  shutdown_succeeded?: boolean;
  shutdown_error?: string;
  managed_at: string;
  updated_at: string;
}

function configuredPath(): string | undefined {
  if (process.env.OVERWATCH_DAEMON_MANAGED !== '1') return undefined;
  const path = process.env.OVERWATCH_DAEMON_RECORD;
  const nonce = process.env.OVERWATCH_DAEMON_MANAGEMENT_NONCE;
  if (!path || !nonce) {
    throw new Error('managed daemon startup requires a record path and management nonce');
  }
  return resolve(path);
}

function writeAtomic(path: string, record: ManagedDaemonRecordV1): void {
  const directory = dirname(path);
  const directoryExisted = existsSync(directory);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (!directoryExisted) fsyncDirectory(dirname(directory));
  const temp = `${path}.tmp-${process.pid}-${randomUUID()}`;
  let fd: number | undefined;
  try {
    fd = openSync(temp, 'wx', 0o600);
    writeFileSync(fd, `${JSON.stringify(record, null, 2)}\n`);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    fsyncDirectory(directory);
  } finally {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temp); } catch { /* renamed or already cleaned */ }
  }
}

function readCurrent(path: string): ManagedDaemonRecordV1 | undefined {
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as ManagedDaemonRecordV1;
  } catch (error) {
    throw new Error(`managed daemon record is unreadable: ${path}`, { cause: error });
  }
}

export function publishManagedDaemonReady(input: {
  runtimeLease?: DaemonInstanceLease;
  runtimeBuild?: RuntimeBuildInfo;
  phase: Extract<DaemonLifecyclePhase, 'ready' | 'ready_read_only'>;
  dashboard_url?: string;
  mcp_url?: string;
}): void {
  const path = configuredPath();
  if (!path) return;
  const nonce = process.env.OVERWATCH_DAEMON_MANAGEMENT_NONCE!;
  const owner = input.runtimeLease?.getOwner();
  const build = input.runtimeBuild;
  if (!owner || !build) {
    throw new Error('managed daemon cannot publish readiness without runtime ownership and build identity');
  }
  const startIdentity = readProcessStartIdentity(process.pid);
  if (!startIdentity) {
    throw new Error(`managed daemon PID ${process.pid} start identity cannot be verified`);
  }
  const now = new Date().toISOString();
  const mcpToken = process.env.OVERWATCH_MCP_TOKEN?.trim();
  if (!mcpToken) {
    throw new Error('managed daemon cannot publish readiness without its operator MCP authority');
  }
  const dashboardToken = process.env.OVERWATCH_DASHBOARD_TOKEN?.trim();
  writeAtomic(path, {
    version: 1,
    management_nonce: nonce,
    pid: process.pid,
    process_start_identity: startIdentity,
    daemon_instance_id: owner.daemon_instance_id,
    runtime_instance_id: build.runtime_instance_id,
    runtime_started_at: build.runtime_started_at,
    build_input_sha256: build.input_sha256,
    mcp_token_sha256: createHash('sha256').update(mcpToken).digest('hex'),
    ...(dashboardToken
      ? { dashboard_token_sha256: createHash('sha256').update(dashboardToken).digest('hex') }
      : {}),
    engagement_id: owner.engagement_id,
    config_path: owner.config_file,
    state_file_path: owner.state_file,
    config_identity_sha256: owner.config_identity_sha256,
    state_identity_sha256: owner.state_identity_sha256,
    transport: 'http',
    phase: input.phase,
    ...(input.dashboard_url ? { dashboard_url: input.dashboard_url } : {}),
    ...(input.mcp_url ? { mcp_url: input.mcp_url } : {}),
    ...(process.env.OVERWATCH_DAEMON_LOG
      ? { log_path: resolve(process.env.OVERWATCH_DAEMON_LOG) }
      : {}),
    managed_at: now,
    updated_at: now,
  });
}

export function publishManagedDaemonShutdownOutcome(
  succeeded: boolean,
  error?: unknown,
): void {
  const path = configuredPath();
  if (!path || !existsSync(path)) return;
  const current = readCurrent(path);
  const nonce = process.env.OVERWATCH_DAEMON_MANAGEMENT_NONCE!;
  if (
    !current
    || current.management_nonce !== nonce
    || current.pid !== process.pid
  ) return;
  const now = new Date().toISOString();
  const next: ManagedDaemonRecordV1 = {
    ...current,
    phase: succeeded ? 'stopped' : 'failed',
    shutdown_succeeded: succeeded,
    updated_at: now,
  };
  if (succeeded) delete next.shutdown_error;
  else next.shutdown_error = error instanceof Error ? error.message : String(error);
  writeAtomic(path, next);
}
