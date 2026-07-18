// ============================================================
// Overwatch — process-lifetime state-family ownership
// ============================================================

import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, parse, resolve } from 'node:path';
import { fsyncDirectory } from './durable-fs.js';
import {
  processIsAlive,
  processStartIdentityMatches,
  readProcessStartIdentity,
} from './process-identity.js';
import { acquireStateMigrationWriteGuard } from './state-migration-lock.js';

export type DaemonLifecyclePhase =
  | 'recovering'
  | 'binding'
  | 'ready'
  | 'ready_read_only'
  | 'stopping'
  | 'failed';

export interface DaemonInstanceOwnerV1 {
  version: 1;
  daemon_instance_id: string;
  pid: number;
  process_start_identity: string;
  transport: 'http' | 'stdio';
  phase: DaemonLifecyclePhase;
  engagement_id: string;
  config_file: string;
  state_file: string;
  config_identity_sha256: string;
  state_identity_sha256: string;
  build_input_sha256: string;
  git_sha?: string | null;
  dashboard_url?: string;
  mcp_url?: string;
  persistence_writable?: boolean;
  recovery_reason?: string;
  started_at: string;
  updated_at: string;
}

export interface DaemonRuntimeStatus {
  daemon_instance_id: string;
  phase: DaemonLifecyclePhase;
  transport: 'http' | 'stdio';
  engagement_id: string;
  config_identity_sha256: string;
  state_identity_sha256: string;
  dashboard_url?: string;
  mcp_url?: string;
  persistence_writable: boolean;
  recovery_reason?: string;
}

export interface AcquireDaemonInstanceLeaseInput {
  state_file: string;
  config_file: string;
  engagement_id: string;
  transport: 'http' | 'stdio';
  build_input_sha256: string;
  git_sha?: string | null;
  dashboard_url?: string;
  mcp_url?: string;
}

export interface DaemonInstanceLease {
  readonly owner_path: string;
  readonly instance_id: string;
  readonly state_file: string;
  getOwner(): DaemonInstanceOwnerV1;
  getStatus(): DaemonRuntimeStatus;
  update(update: {
    phase?: DaemonLifecyclePhase;
    dashboard_url?: string;
    mcp_url?: string;
    persistence_writable?: boolean;
    recovery_reason?: string | null;
  }): void;
  release(): void;
}

export interface DaemonLeaseProcessObserver {
  isAlive(pid: number): boolean;
  startIdentity(pid: number): string | undefined;
}

const defaultObserver: DaemonLeaseProcessObserver = {
  isAlive: processIsAlive,
  startIdentity: readProcessStartIdentity,
};

/** Resolve symlinked ancestors even when the final state file does not exist yet. */
export function canonicalRuntimePath(path: string): string {
  let candidate = resolve(path);
  const suffix: string[] = [];
  while (!existsSync(candidate)) {
    const parent = dirname(candidate);
    if (parent === candidate || candidate === parse(candidate).root) break;
    suffix.unshift(basename(candidate));
    candidate = parent;
  }
  const physicalBase = existsSync(candidate) ? realpathSync.native(candidate) : candidate;
  return suffix.length > 0 ? join(physicalBase, ...suffix) : physicalBase;
}

export function runtimePathIdentity(path: string): string {
  return createHash('sha256').update(canonicalRuntimePath(path)).digest('hex');
}

export function daemonInstanceLeasePath(stateFilePath: string): string {
  return `${canonicalRuntimePath(stateFilePath)}.runtime-owner.json`;
}

function parseOwner(path: string): DaemonInstanceOwnerV1 {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`runtime owner record is unreadable: ${path}`, { cause: error });
  }
  const owner = value as Partial<DaemonInstanceOwnerV1>;
  if (
    owner.version !== 1
    || typeof owner.daemon_instance_id !== 'string'
    || !Number.isSafeInteger(owner.pid)
    || Number(owner.pid) <= 0
    || typeof owner.process_start_identity !== 'string'
    || owner.process_start_identity.length === 0
    || (owner.transport !== 'http' && owner.transport !== 'stdio')
    || ![
      'recovering',
      'binding',
      'ready',
      'ready_read_only',
      'stopping',
      'failed',
    ].includes(String(owner.phase))
    || typeof owner.engagement_id !== 'string'
    || typeof owner.config_file !== 'string'
    || typeof owner.state_file !== 'string'
    || typeof owner.config_identity_sha256 !== 'string'
    || typeof owner.state_identity_sha256 !== 'string'
    || typeof owner.build_input_sha256 !== 'string'
    || typeof owner.started_at !== 'string'
    || typeof owner.updated_at !== 'string'
  ) {
    throw new Error(`runtime owner record is invalid: ${path}`);
  }
  return owner as DaemonInstanceOwnerV1;
}

function samePhysicalProcess(
  owner: DaemonInstanceOwnerV1,
  observer: DaemonLeaseProcessObserver,
): boolean {
  if (!observer.isAlive(owner.pid)) return false;
  const observed = observer.startIdentity(owner.pid);
  // A live PID whose start identity cannot be inspected remains authoritative.
  // Reclaiming it would risk admitting a second writer on restricted hosts.
  if (
    observed === undefined
    || owner.process_start_identity.startsWith('unverifiable-current-process-')
    || observed === owner.process_start_identity
  ) return true;
  // The pre-stable format stored the locale-sensitive raw `ps lstart` value.
  // Only the production observer can safely invoke the compatibility probe;
  // injected observers remain deterministic for tests.
  if (observer === defaultObserver) {
    return processStartIdentityMatches(owner.pid, owner.process_start_identity) !== false;
  }
  return false;
}

function writeOwnerAtomic(path: string, owner: DaemonInstanceOwnerV1): void {
  const directory = dirname(path);
  const tempPath = `${path}.tmp-${process.pid}-${randomUUID()}`;
  let fd: number | undefined;
  try {
    fd = openSync(tempPath, 'wx', 0o600);
    writeFileSync(fd, `${JSON.stringify(owner, null, 2)}\n`);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(tempPath, path);
    fsyncDirectory(directory);
  } finally {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(tempPath); } catch { /* rename or cleanup already completed */ }
  }
}

function createOwnerExclusive(path: string, owner: DaemonInstanceOwnerV1): void {
  const fd = openSync(path, 'wx', 0o600);
  try {
    writeFileSync(fd, `${JSON.stringify(owner, null, 2)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  fsyncDirectory(dirname(path));
}

export function readDaemonInstanceOwner(stateFilePath: string): DaemonInstanceOwnerV1 | undefined {
  const path = daemonInstanceLeasePath(stateFilePath);
  return existsSync(path) ? parseOwner(path) : undefined;
}

export function acquireDaemonInstanceLease(
  input: AcquireDaemonInstanceLeaseInput,
  observer: DaemonLeaseProcessObserver = defaultObserver,
): DaemonInstanceLease {
  const stateFile = canonicalRuntimePath(input.state_file);
  const configFile = canonicalRuntimePath(input.config_file);
  if (existsSync(stateFile) && statSync(stateFile).nlink > 1) {
    throw new Error(
      `durable state ${stateFile} has multiple hard links; refusing ambiguous runtime ownership. `
      + 'Copy it to a uniquely owned path before starting Overwatch.',
    );
  }
  const ownerPath = daemonInstanceLeasePath(stateFile);
  const directory = dirname(ownerPath);
  mkdirSync(directory, { recursive: true });
  // Fast-path an established live owner before joining the state-writer
  // bakery. A healthy daemon may retain the journal writer capability between
  // appends; duplicate startup should report the daemon owner immediately,
  // not wait for and mislabel that lower-level filesystem guard.
  if (existsSync(ownerPath)) {
    const existing = parseOwner(ownerPath);
    if (samePhysicalProcess(existing, observer)) {
      throw new Error(
        `engagement ${existing.engagement_id} is already owned by Overwatch PID ${existing.pid} `
        + `(${existing.transport}, ${existing.phase}). Reuse that runtime or stop it before starting another.`,
      );
    }
  }
  const releaseWriter = acquireStateMigrationWriteGuard(stateFile);
  const now = new Date().toISOString();
  const instanceId = randomUUID();
  const startIdentity = observer.startIdentity(process.pid)
    ?? `unverifiable-current-process-${instanceId}`;
  let owner: DaemonInstanceOwnerV1 = {
    version: 1,
    daemon_instance_id: instanceId,
    pid: process.pid,
    process_start_identity: startIdentity,
    transport: input.transport,
    phase: 'recovering',
    engagement_id: input.engagement_id,
    config_file: configFile,
    state_file: stateFile,
    config_identity_sha256: runtimePathIdentity(configFile),
    state_identity_sha256: runtimePathIdentity(stateFile),
    build_input_sha256: input.build_input_sha256,
    ...(input.git_sha !== undefined ? { git_sha: input.git_sha } : {}),
    ...(input.dashboard_url ? { dashboard_url: input.dashboard_url } : {}),
    ...(input.mcp_url ? { mcp_url: input.mcp_url } : {}),
    started_at: now,
    updated_at: now,
  };
  try {
    if (existsSync(ownerPath)) {
      const stat = lstatSync(ownerPath);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        throw new Error(`runtime owner path is not a private regular file: ${ownerPath}`);
      }
      const existing = parseOwner(ownerPath);
      if (samePhysicalProcess(existing, observer)) {
        throw new Error(
          `engagement ${existing.engagement_id} is already owned by Overwatch PID ${existing.pid} `
          + `(${existing.transport}, ${existing.phase}). Reuse that runtime or stop it before starting another.`,
        );
      }
      rmSync(ownerPath);
      fsyncDirectory(directory);
    }
    createOwnerExclusive(ownerPath, owner);
  } finally {
    releaseWriter();
  }

  let released = false;
  const assertOwned = (): void => {
    if (released) throw new Error('runtime owner lease has already been released');
    const current = parseOwner(ownerPath);
    if (
      current.daemon_instance_id !== instanceId
      || current.pid !== process.pid
      || current.process_start_identity !== startIdentity
    ) {
      throw new Error('runtime owner lease identity changed unexpectedly');
    }
  };

  return {
    owner_path: ownerPath,
    instance_id: instanceId,
    state_file: stateFile,
    getOwner: () => ({ ...owner }),
    getStatus: () => ({
      daemon_instance_id: owner.daemon_instance_id,
      phase: owner.phase,
      transport: owner.transport,
      engagement_id: owner.engagement_id,
      config_identity_sha256: owner.config_identity_sha256,
      state_identity_sha256: owner.state_identity_sha256,
      ...(owner.dashboard_url ? { dashboard_url: owner.dashboard_url } : {}),
      ...(owner.mcp_url ? { mcp_url: owner.mcp_url } : {}),
      persistence_writable: owner.persistence_writable ?? false,
      ...(owner.recovery_reason ? { recovery_reason: owner.recovery_reason } : {}),
    }),
    update: update => {
      assertOwned();
      const next: DaemonInstanceOwnerV1 = { ...owner };
      if (update.phase) next.phase = update.phase;
      if (update.dashboard_url) next.dashboard_url = update.dashboard_url;
      if (update.mcp_url) next.mcp_url = update.mcp_url;
      if (update.persistence_writable !== undefined) {
        next.persistence_writable = update.persistence_writable;
      }
      if (update.recovery_reason === null) delete next.recovery_reason;
      else if (update.recovery_reason !== undefined) next.recovery_reason = update.recovery_reason;
      next.updated_at = new Date().toISOString();
      owner = next;
      writeOwnerAtomic(ownerPath, owner);
    },
    release: () => {
      if (released) return;
      assertOwned();
      unlinkSync(ownerPath);
      fsyncDirectory(directory);
      released = true;
    },
  };
}
