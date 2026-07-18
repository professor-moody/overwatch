// ============================================================
// Overwatch — Cross-process state-migration write lease
// ============================================================

import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'fs';
import { createHash, randomUUID } from 'crypto';
import { dirname, join, resolve } from 'path';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';
import { parseJsonBytes } from './durable-json.js';
import {
  processIsAlive as runtimeProcessIsAlive,
  readProcessStartIdentity,
  processStartIdentityMatches,
} from './process-identity.js';

interface ProcessOwnerIdentity {
  pid: number;
  process_start_identity: string;
}

interface MigrationLeaseOwnerV1 extends ProcessOwnerIdentity {
  version: 1;
  token: string;
  created_at: string;
}

interface StateWriterContenderV1 extends ProcessOwnerIdentity {
  version: 1;
  token: string;
  choosing: boolean;
  ticket?: number;
  created_at: string;
}

interface ListedWriterContender {
  name: string;
  path: string;
  pid: number;
  token: string;
  process_start_identity_verifiable: boolean;
  process_start_identity_hash: string;
  record?: StateWriterContenderV1;
}

class MigrationLeaseRecordError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'MigrationLeaseRecordError';
  }
}

export interface StateMigrationLeaseRelease {
  (): void;
  readonly token: string;
  readonly state_file: string;
}

const heldWriterLocks = new Map<string, number>();
const sleepCell = new Int32Array(new SharedArrayBuffer(4));
const WRITER_LOCK_WAIT_MS = 5_000;
const WRITER_CONTENDER_PATTERN =
  /^(\d+)-([uv])-([0-9a-f]{16})-([0-9a-f]{32})\.json$/;

/** Process-local recursion depth for the exact state writer mutex. Retained
 * journal owners use this to prove they are the sole outer holder before
 * transferring ownership to another same-process journal instance. */
export function getStateWriterLockDepth(stateFilePath: string): number {
  return heldWriterLocks.get(resolve(stateFilePath)) ?? 0;
}

function processIdentityHash(identity: string): string {
  return createHash('sha256').update(identity).digest('hex').slice(0, 16);
}

function processIsAlive(owner: ProcessOwnerIdentity): boolean {
  if (!runtimeProcessIsAlive(owner.pid)) return false;
  const matches = processStartIdentityMatches(owner.pid, owner.process_start_identity);
  // If this platform cannot provide a start identity, a live PID remains
  // authoritative rather than risking removal of another writer's lease.
  return matches === undefined
    || owner.process_start_identity.startsWith('unverifiable-current-process-')
    || matches;
}

export function stateMigrationLockDirectory(stateFilePath: string): string {
  return `${resolve(stateFilePath)}.migration-lock`;
}

function stateWriterLockDirectory(stateFilePath: string): string {
  return `${resolve(stateFilePath)}.writer-lock`;
}

function writeExclusiveOwner(
  ownerPath: string,
  owner: MigrationLeaseOwnerV1,
): void {
  const fd = openSync(ownerPath, 'wx', 0o600);
  try {
    writeFileSync(fd, `${JSON.stringify(owner)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  fsyncDirectory(dirname(ownerPath));
}

/**
 * Writer contenders use unique tokenized pathnames. A crash may leave a
 * partial contender, but no later process ever reuses that pathname; readers
 * block while its PID is live and remove it after the exact process dies.
 */
function writeWriterContender(
  contenderPath: string,
  contender: StateWriterContenderV1,
  exclusive: boolean,
): void {
  const fd = openSync(contenderPath, exclusive ? 'wx' : 'w', 0o600);
  try {
    writeFileSync(fd, `${JSON.stringify(contender)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  fsyncDirectory(dirname(contenderPath));
}

function readWriterContender(path: string): StateWriterContenderV1 | undefined {
  try {
    const owner = parseJsonBytes(readFileSync(path)) as StateWriterContenderV1;
    if (
      owner.version !== 1
      || !Number.isSafeInteger(owner.pid)
      || owner.pid <= 0
      || typeof owner.process_start_identity !== 'string'
      || owner.process_start_identity.length === 0
      || typeof owner.token !== 'string'
      || owner.token.length === 0
      || typeof owner.choosing !== 'boolean'
      || typeof owner.created_at !== 'string'
      || (
        !owner.choosing
        && (!Number.isSafeInteger(owner.ticket) || owner.ticket! < 1)
      )
    ) {
      return undefined;
    }
    return owner;
  } catch {
    return undefined;
  }
}

function parseWriterContenderName(
  name: string,
): {
  pid: number;
  process_start_identity_verifiable: boolean;
  process_start_identity_hash: string;
  token: string;
} | undefined {
  const match = WRITER_CONTENDER_PATTERN.exec(name);
  if (!match) return undefined;
  const pid = Number(match[1]);
  if (!Number.isSafeInteger(pid) || pid <= 0) return undefined;
  return {
    pid,
    process_start_identity_verifiable: match[2] === 'v',
    process_start_identity_hash: match[3],
    token: match[4],
  };
}

function removeWriterContender(path: string, directory: string): void {
  try {
    unlinkSync(path);
    try {
      fsyncDirectory(directory);
    } catch (error) {
      // The ownership name is already gone. A crash can at worst resurrect a
      // dead-owner contender, which the PID/start-identity reclaimer removes;
      // do not turn an already-committed caller mutation into a false failure.
      process.stderr.write(`[state-writer-lock] contender removal fsync deferred: ${error instanceof Error ? error.message : String(error)}\n`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

function listLiveWriterContenders(directory: string): ListedWriterContender[] {
  const contenders: ListedWriterContender[] = [];
  for (const name of readdirSync(directory)) {
    if (!name.endsWith('.json')) continue;
    const named = parseWriterContenderName(name);
    if (!named) {
      throw new Error(`state writer lock contains an unrecognized contender: ${join(directory, name)}`);
    }
    const path = join(directory, name);
    const record = readWriterContender(path);
    const identity: ProcessOwnerIdentity = {
      pid: named.pid,
      process_start_identity: record?.process_start_identity ?? '',
    };
    const alive = record
      ? record.pid === named.pid
        && record.token === named.token
        && processIdentityHash(record.process_start_identity) === named.process_start_identity_hash
        && processIsAlive(identity)
      : (() => {
          try {
            process.kill(named.pid, 0);
          } catch (error) {
            return (error as NodeJS.ErrnoException).code !== 'ESRCH';
          }
          const observed = readProcessStartIdentity(named.pid);
          return !named.process_start_identity_verifiable
            || observed === undefined
            || processIdentityHash(observed) === named.process_start_identity_hash
            // A legacy contender without a readable record contains only a
            // locale-sensitive hash. A live PID must remain authoritative when
            // that old hash cannot be reconstructed safely.
            || runtimeProcessIsAlive(named.pid);
        })();
    if (!alive) {
      removeWriterContender(path, directory);
      continue;
    }
    contenders.push({
      name,
      path,
      pid: named.pid,
      token: named.token,
      process_start_identity_verifiable: named.process_start_identity_verifiable,
      process_start_identity_hash: named.process_start_identity_hash,
      ...(record ? { record } : {}),
    });
  }
  return contenders;
}

/**
 * A Lamport bakery over unique contender files provides a cross-process mutex
 * without a canonical lock pathname that stale reclaimers can delete out from
 * under a new owner. The directory persists when empty; only tokenized
 * contender files represent ownership.
 */
function acquireStateWriterMutex(stateFilePath: string): () => void {
  const absoluteStatePath = resolve(stateFilePath);
  const existingDepth = heldWriterLocks.get(absoluteStatePath);
  if (existingDepth !== undefined) {
    heldWriterLocks.set(absoluteStatePath, existingDepth + 1);
    return () => {
      const depth = heldWriterLocks.get(absoluteStatePath);
      if (depth === undefined) throw new Error('state writer lock depth was lost');
      if (depth === 1) heldWriterLocks.delete(absoluteStatePath);
      else heldWriterLocks.set(absoluteStatePath, depth - 1);
    };
  }

  const lockDirectory = stateWriterLockDirectory(absoluteStatePath);
  mkdirDurable(lockDirectory);
  const token = randomUUID().replaceAll('-', '');
  const observedProcessIdentity = readProcessStartIdentity(process.pid);
  const processIdentity = observedProcessIdentity
    ?? `unverifiable-current-process-${token}`;
  const contenderName =
    `${process.pid}-${observedProcessIdentity === undefined ? 'u' : 'v'}-`
    + `${processIdentityHash(processIdentity)}-${token}.json`;
  const contenderPath = join(lockDirectory, contenderName);
  const createdAt = new Date().toISOString();
  const choosing: StateWriterContenderV1 = {
    version: 1,
    pid: process.pid,
    process_start_identity: processIdentity,
    token,
    choosing: true,
    created_at: createdAt,
  };

  let acquired = false;
  try {
    writeWriterContender(contenderPath, choosing, true);
    const maximumTicket = listLiveWriterContenders(lockDirectory).reduce(
      (maximum, contender) => Math.max(maximum, contender.record?.ticket ?? 0),
      0,
    );
    const elected: StateWriterContenderV1 = {
      ...choosing,
      choosing: false,
      ticket: maximumTicket + 1,
    };
    writeWriterContender(contenderPath, elected, false);

    const deadline = Date.now() + WRITER_LOCK_WAIT_MS;
    for (;;) {
      let blocked = false;
      for (const contender of listLiveWriterContenders(lockDirectory)) {
        if (contender.name === contenderName) continue;
        if (!contender.record || contender.record.choosing) {
          blocked = true;
          break;
        }
        const otherTicket = contender.record.ticket!;
        if (
          otherTicket < elected.ticket!
          || (
            otherTicket === elected.ticket!
            && contender.record.token < token
          )
        ) {
          blocked = true;
          break;
        }
      }
      if (!blocked) break;
      if (Date.now() >= deadline) {
        throw new Error(`state writer lock is already owned for ${absoluteStatePath}`);
      }
      Atomics.wait(sleepCell, 0, 0, 10);
    }

    const current = readWriterContender(contenderPath);
    if (
      !current
      || current.pid !== process.pid
      || current.token !== token
      || current.process_start_identity !== processIdentity
      || current.choosing
      || current.ticket !== elected.ticket
    ) {
      throw new Error('state writer lock ownership changed during acquisition');
    }
    heldWriterLocks.set(absoluteStatePath, 1);
    acquired = true;
  } finally {
    if (!acquired) {
      try { removeWriterContender(contenderPath, lockDirectory); } catch { /* preserve acquisition failure */ }
    }
  }

  return () => {
    const depth = heldWriterLocks.get(absoluteStatePath);
    if (depth === undefined) throw new Error('state writer lock ownership was lost');
    if (depth > 1) {
      heldWriterLocks.set(absoluteStatePath, depth - 1);
      return;
    }
    const current = readWriterContender(contenderPath);
    if (
      !current
      || current.token !== token
      || current.pid !== process.pid
      || current.process_start_identity !== processIdentity
    ) {
      throw new Error('state writer lock ownership changed before release');
    }
    removeWriterContender(contenderPath, lockDirectory);
    heldWriterLocks.delete(absoluteStatePath);
  };
}

function readLeaseOwner(stateFilePath: string): MigrationLeaseOwnerV1 | undefined {
  const ownerPath = join(stateMigrationLockDirectory(stateFilePath), 'owner.json');
  if (!existsSync(ownerPath)) return undefined;
  let owner: MigrationLeaseOwnerV1;
  try {
    owner = parseJsonBytes(readFileSync(ownerPath)) as MigrationLeaseOwnerV1;
  } catch (error) {
    throw new MigrationLeaseRecordError(
      `state migration lock owner is invalid: ${dirname(ownerPath)}`,
      { cause: error },
    );
  }
  if (
    owner.version !== 1
    || !Number.isSafeInteger(owner.pid)
    || owner.pid <= 0
    || typeof owner.process_start_identity !== 'string'
    || owner.process_start_identity.length === 0
    || typeof owner.token !== 'string'
    || owner.token.length === 0
    || typeof owner.created_at !== 'string'
  ) {
    throw new MigrationLeaseRecordError(`state migration lock is invalid: ${dirname(ownerPath)}`);
  }
  return owner;
}

function removeMigrationLockDirectory(lockDirectory: string): void {
  rmSync(lockDirectory, { recursive: true });
  fsyncDirectory(dirname(lockDirectory));
}

function createMigrationLockDirectory(
  lockDirectory: string,
  owner: MigrationLeaseOwnerV1,
): void {
  const ownerPath = join(lockDirectory, 'owner.json');
  try {
    mkdirSync(lockDirectory);
    fsyncDirectory(dirname(lockDirectory));
    writeExclusiveOwner(ownerPath, owner);
  } catch (error) {
    try {
      rmSync(lockDirectory, { recursive: true, force: true });
      fsyncDirectory(dirname(lockDirectory));
    } catch { /* preserve creation failure */ }
    throw error;
  }
}

/**
 * Every writer of state, WAL, snapshots, or the active config calls this
 * immediately before its filesystem boundary. Only the lease capability that
 * created the lock may write while migration is in progress.
 */
export function assertStateMigrationWriteAllowed(
  stateFilePath: string,
  ownerToken?: string,
): void {
  const lockDirectory = stateMigrationLockDirectory(stateFilePath);
  if (!existsSync(lockDirectory)) return;
  let owner: MigrationLeaseOwnerV1 | undefined;
  try {
    owner = readLeaseOwner(stateFilePath);
  } catch (error) {
    throw new Error(
      `state writes are blocked by an unreadable migration lease at ${lockDirectory}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (owner && ownerToken && owner.token === ownerToken) return;
  throw new Error(
    owner
      ? `state writes are blocked while migration is owned by PID ${owner.pid}`
      : `state writes are blocked while migration lease initialization is incomplete at ${lockDirectory}`,
  );
}

/**
 * Serialize each filesystem write boundary with migration acquisition. This
 * closes the check-then-write race where a migration could otherwise acquire
 * its exclusive lease immediately after an ordinary writer checked it.
 */
export function withStateMigrationWriteGuard<T>(
  stateFilePath: string,
  ownerToken: string | undefined,
  operation: () => T,
): T {
  const release = acquireStateMigrationWriteGuard(stateFilePath, ownerToken);
  try {
    return operation();
  } finally {
    release();
  }
}

/**
 * Acquire the crash-reclaiming writer mutex until the returned release
 * callback is invoked. Long-lived single-writer components can retain this
 * guard across a burst of fsync-backed appends instead of recreating durable
 * contender files for every record.
 */
export function acquireStateMigrationWriteGuard(
  stateFilePath: string,
  ownerToken?: string,
): () => void {
  const release = acquireStateWriterMutex(stateFilePath);
  try {
    assertStateMigrationWriteAllowed(stateFilePath, ownerToken);
    return release;
  } catch (error) {
    release();
    throw error;
  }
}

export function acquireStateMigrationLease(
  stateFilePath: string,
): StateMigrationLeaseRelease {
  const absoluteStatePath = resolve(stateFilePath);
  const lockDirectory = stateMigrationLockDirectory(absoluteStatePath);
  const token = randomUUID();
  const owner: MigrationLeaseOwnerV1 = {
    version: 1,
    pid: process.pid,
    process_start_identity: readProcessStartIdentity(process.pid)
      ?? `unverifiable-current-process-${token}`,
    token,
    created_at: new Date().toISOString(),
  };

  const releaseWriter = acquireStateWriterMutex(absoluteStatePath);
  try {
    if (existsSync(lockDirectory)) {
      const stat = lstatSync(lockDirectory);
      if (!stat.isDirectory() || stat.isSymbolicLink()) {
        throw new Error(`state migration lock is not a private directory: ${lockDirectory}`);
      }
      let existing: MigrationLeaseOwnerV1 | undefined;
      try {
        existing = readLeaseOwner(absoluteStatePath);
      } catch (error) {
        if (!(error instanceof MigrationLeaseRecordError)) throw error;
        // The writer mutex proves that no live cooperating process is still
        // initializing this directory. An invalid/partial owner is therefore a
        // crash remnant and can be reclaimed safely.
        removeMigrationLockDirectory(lockDirectory);
      }
      if (existing) {
        if (processIsAlive(existing)) {
          throw new Error(`state migration is already owned by PID ${existing.pid}`);
        }
        removeMigrationLockDirectory(lockDirectory);
      } else if (existsSync(lockDirectory)) {
        // Crash after directory creation but before owner publication.
        removeMigrationLockDirectory(lockDirectory);
      }
    }
    createMigrationLockDirectory(lockDirectory, owner);
  } finally {
    releaseWriter();
  }

  const release = (() => {
    const releaseWriterLock = acquireStateWriterMutex(absoluteStatePath);
    try {
      const current = readLeaseOwner(absoluteStatePath);
      if (!current || current.token !== token || current.pid !== process.pid) {
        throw new Error('state migration lease ownership changed before release');
      }
      removeMigrationLockDirectory(lockDirectory);
    } finally {
      releaseWriterLock();
    }
  }) as StateMigrationLeaseRelease;
  Object.defineProperties(release, {
    token: { value: token, enumerable: true },
    state_file: { value: absoluteStatePath, enumerable: true },
  });
  return release;
}
