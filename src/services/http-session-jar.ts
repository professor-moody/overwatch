// ============================================================
// HTTP session jars — crash-safe named curl cookie files.
// ============================================================

import { createHash, randomUUID } from 'crypto';
import { basename, dirname, join } from 'path';
import {
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readSync,
} from 'fs';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';
import {
  DurableArtifactPublicationError,
  publishArtifactFileDurable,
  removeArtifactDurable,
  writeArtifactAtomicDurable,
} from './durable-artifact.js';
import { withStateMigrationWriteGuard } from './state-migration-lock.js';
import { readProcessStartIdentity } from './process-identity.js';

const SAFE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_COOKIE_JAR_BYTES = 10 * 1024 * 1024;
const STALE_STAGE_MIN_AGE_MS = 60 * 60 * 1000;
const STAGE_FILE = /^\.[A-Za-z0-9_-]+\.jar\.tmp-(\d+)(?:-([uv])([0-9a-f]{16}))?-[0-9a-f-]+$/i;
const currentProcessStartIdentity = readProcessStartIdentity(process.pid);
const currentProcessStartHash = createHash('sha256')
  .update(currentProcessStartIdentity ?? `unverifiable-current-process-${process.pid}`)
  .digest('hex')
  .slice(0, 16);

const localJarTails = new Map<string, Promise<void>>();

function pidMayBeLive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // Permission/inspection failures are unverifiable, not proof of death.
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

export interface SessionJarTransaction {
  /** Canonical prior jar used for cookie replay. May not exist yet. */
  readPath: string;
  /** Unique private path passed to curl's `-c`. */
  writePath: string;
  /** Validate, fsync, and atomically replace the canonical jar. */
  /** Returns true only when a reusable cookie was published. */
  commit: (fallbackCookie?: { url: string; name: string; value: string }) => SessionJarCommitResult;
  /** Remove staging bytes and release ownership without changing the old jar. */
  abort: () => void;
}

export interface SessionJarCommitResult {
  published: boolean;
  durability_confirmed: boolean;
  warning?: string;
}

export function isValidSessionJarId(id: string): boolean {
  return typeof id === 'string' && SAFE_ID.test(id);
}

export function sessionJarsDir(stateFilePath: string): string {
  return join(dirname(stateFilePath), 'session-jars');
}

function validateJarDirectory(stateFilePath: string, create: boolean): string {
  const directory = sessionJarsDir(stateFilePath);
  if (existsSync(directory)) {
    const existing = lstatSync(directory);
    if (existing.isSymbolicLink() || !existing.isDirectory()) {
      throw new Error(`Session-jar root must be a private regular directory: ${directory}`);
    }
  } else if (create) {
    mkdirDurable(directory);
  } else {
    return directory;
  }
  const stat = lstatSync(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`Session-jar root must be a private regular directory: ${directory}`);
  }
  chmodSync(directory, 0o700);
  return directory;
}

function cleanupStaleStages(directory: string, now = Date.now()): void {
  for (const name of readdirSync(directory)) {
    const match = STAGE_FILE.exec(name);
    if (!match) continue;
    const path = join(directory, name);
    try {
      const stat = lstatSync(path);
      const pid = Number(match[1]);
      const verifiability = match[2];
      const recordedStartHash = match[3];
      let ownerAlive = pidMayBeLive(pid);
      if (ownerAlive && verifiability === 'v' && recordedStartHash) {
        const observed = readProcessStartIdentity(pid);
        ownerAlive = observed === undefined
          || createHash('sha256').update(observed).digest('hex').slice(0, 16) === recordedStartHash;
      }
      if (
        stat.isSymbolicLink()
        || !stat.isFile()
        || now - stat.mtimeMs < STALE_STAGE_MIN_AGE_MS
        || ownerAlive
      ) continue;
      removeArtifactDurable(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
}

async function acquireLocalJar(path: string): Promise<() => void> {
  const prior = localJarTails.get(path) ?? Promise.resolve();
  let releaseGate!: () => void;
  const gate = new Promise<void>(resolve => { releaseGate = resolve; });
  const tail = prior.catch(() => undefined).then(() => gate);
  localJarTails.set(path, tail);
  await prior.catch(() => undefined);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    releaseGate();
    void tail.finally(() => {
      if (localJarTails.get(path) === tail) localJarTails.delete(path);
    });
  };
}

function fileIdentity(path: string): string {
  try {
    const bytes = readBoundedJar(path);
    return `${bytes.byteLength}:${createHash('sha256').update(bytes).digest('hex')}`;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return 'missing';
    throw error;
  }
}

function readBoundedJar(path: string): Buffer {
  assertSafeJarFile(path);
  const fd = openSync(path, 'r');
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size > MAX_COOKIE_JAR_BYTES) {
      throw new Error('Session jar exceeds the 10 MiB safety limit.');
    }
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw new Error('Session jar changed while it was being read.');
      offset += count;
    }
    const after = fstatSync(fd);
    if (
      after.dev !== before.dev
      || after.ino !== before.ino
      || after.size !== before.size
      || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs
    ) throw new Error('Session jar changed while it was being read.');
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function canonicalJarPath(stateFilePath: string, id: string): string {
  if (!isValidSessionJarId(id)) {
    throw new Error(`Invalid session_jar_id '${id}': must be 1–64 chars of [A-Za-z0-9_-].`);
  }
  const directory = validateJarDirectory(stateFilePath, true);
  cleanupStaleStages(directory);
  return join(directory, `${id}.jar`);
}

function assertSafeJarFile(path: string): void {
  if (!existsSync(path)) return;
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`Session jar must be a regular file: ${path}`);
  }
  if (stat.size > MAX_COOKIE_JAR_BYTES) throw new Error('Session jar exceeds the 10 MiB safety limit.');
}

function validateNetscapeCookieJar(path: string): number {
  const text = readBoundedJar(path).toString('utf8');
  const lines = text.split(/\r?\n/);
  if (!lines.some(line => line.includes('Netscape HTTP Cookie File'))) {
    throw new Error('curl did not produce a valid Netscape cookie jar.');
  }
  let cookieCount = 0;
  for (const original of lines) {
    const line = original.startsWith('#HttpOnly_') ? original.slice(1) : original;
    if (line.length === 0 || (line.startsWith('#') && !original.startsWith('#HttpOnly_'))) continue;
    const fields = line.split('\t');
    if (
      fields.length !== 7
      || fields[0].length === 0
      || !['TRUE', 'FALSE'].includes(fields[1])
      || !['TRUE', 'FALSE'].includes(fields[3])
      || !/^\d+$/.test(fields[4])
      || fields[5].length === 0
    ) throw new Error('curl produced a malformed Netscape cookie-jar record.');
    cookieCount++;
  }
  return cookieCount;
}

function seedFallbackCookie(
  path: string,
  fallback: { url: string; name: string; value: string },
): boolean {
  if (/[\u0000\r\n\t;]/.test(fallback.name) || /[\u0000\r\n\t]/.test(fallback.value)) return false;
  let url: URL;
  try { url = new URL(fallback.url); } catch { return false; }
  if (!url.hostname || (url.protocol !== 'http:' && url.protocol !== 'https:')) return false;
  const content = [
    '# Netscape HTTP Cookie File',
    `${url.hostname}\tFALSE\t/\t${url.protocol === 'https:' ? 'TRUE' : 'FALSE'}\t0\t${fallback.name}\t${fallback.value}`,
    '',
  ].join('\n');
  writeArtifactAtomicDurable(path, content, { mode: 0o600 });
  return true;
}

/** Canonical path for read-only consumers such as authenticated crawlers. */
export function sessionJarPath(stateFilePath: string, id: string): string {
  const path = canonicalJarPath(stateFilePath, id);
  assertSafeJarFile(path);
  return path;
}

/**
 * Reserve one named jar across processes. Curl writes only to the unique
 * staging file; the previous authenticated session remains intact unless the
 * request succeeds and the staged Netscape jar validates.
 */
export async function beginSessionJarTransaction(stateFilePath: string, id: string): Promise<SessionJarTransaction> {
  const readPath = canonicalJarPath(stateFilePath, id);
  assertSafeJarFile(readPath);
  const releaseLocal = await acquireLocalJar(readPath);
  let priorIdentity: string;
  let writePath: string;
  try {
    priorIdentity = fileIdentity(readPath);
    writePath = join(
      dirname(readPath),
      `.${basename(readPath)}.tmp-${process.pid}-${currentProcessStartIdentity ? 'v' : 'u'}${currentProcessStartHash}-${randomUUID()}`,
    );
  } catch (error) {
    releaseLocal();
    throw error;
  }
  let finished = false;

  const finish = (publish: boolean, fallbackCookie?: { url: string; name: string; value: string }): SessionJarCommitResult => {
    if (finished) return { published: false, durability_confirmed: true };
    let operationError: unknown;
    let published = false;
    let durabilityConfirmed = true;
    let warning: string | undefined;
    try {
      if (publish) {
        if (!existsSync(writePath)) throw new Error('curl completed without producing a cookie jar.');
        let cookieCount = validateNetscapeCookieJar(writePath);
        if (cookieCount === 0 && fallbackCookie && seedFallbackCookie(writePath, fallbackCookie)) {
          cookieCount = validateNetscapeCookieJar(writePath);
        }
        if (cookieCount === 0) {
          removeArtifactDurable(writePath);
          return { published: false, durability_confirmed: true };
        }
        chmodSync(writePath, 0o600);
        // The target request runs without a blocking filesystem mutex. Only
        // the short validate/publish boundary is serialized across processes,
        // so another async login cannot stall the daemon's event loop.
        try {
          withStateMigrationWriteGuard(readPath, undefined, () => {
            assertSafeJarFile(readPath);
            if (fileIdentity(readPath) !== priorIdentity) {
              throw new Error('Session jar changed while authentication was in flight; refusing a stale replacement.');
            }
            publishArtifactFileDurable(writePath, readPath);
          });
          published = true;
        } catch (error) {
          if (
            error instanceof DurableArtifactPublicationError
            && error.publication_visible
            && error.destination_path === readPath
          ) {
            // The canonical name already changed. Return the truthful reusable
            // outcome instead of inviting a duplicate authentication attempt.
            published = true;
            durabilityConfirmed = error.durability_confirmed;
            warning = error.message;
            process.stderr.write(`[session-jar] ${error.message}\n`);
          } else {
            throw error;
          }
        }
      } else if (existsSync(writePath)) {
        removeArtifactDurable(writePath);
      }
    } catch (error) {
      operationError = error;
      throw error;
    } finally {
      finished = true;
      releaseLocal();
      if ((!publish || operationError !== undefined) && existsSync(writePath)) {
        try { removeArtifactDurable(writePath); } catch { /* preserve the request failure */ }
      }
    }
    return {
      published,
      durability_confirmed: durabilityConfirmed,
      ...(warning ? { warning } : {}),
    };
  };

  return {
    readPath,
    writePath,
    commit: fallbackCookie => finish(true, fallbackCookie),
    abort: () => { finish(false); },
  };
}

export function listSessionJars(stateFilePath: string): string[] {
  const directory = validateJarDirectory(stateFilePath, false);
  if (!existsSync(directory)) return [];
  const stat = lstatSync(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error(`Invalid session-jar root: ${directory}`);
  cleanupStaleStages(directory);
  return readdirSync(directory)
    .filter(name => {
      if (!name.endsWith('.jar')) return false;
      const path = join(directory, name);
      const entry = lstatSync(path);
      return entry.isFile() && !entry.isSymbolicLink();
    })
    .map(name => name.slice(0, -'.jar'.length))
    .sort();
}

export function clearSessionJar(stateFilePath: string, id: string): boolean {
  if (!isValidSessionJarId(id)) return false;
  const directory = validateJarDirectory(stateFilePath, false);
  const path = join(directory, `${id}.jar`);
  if (!existsSync(dirname(path))) return false;
  return withStateMigrationWriteGuard(path, undefined, () => {
    assertSafeJarFile(path);
    return removeArtifactDurable(path, fsyncDirectory);
  });
}
