// ============================================================
// Overwatch — crash-safe engagement bundle capture and publication.
// ============================================================

import { spawn } from 'child_process';
import {
  constants,
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  linkSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  truncateSync,
} from 'fs';
import { createHash, randomUUID } from 'crypto';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'path';
import { tmpdir } from 'os';
import type { GraphEngine } from './graph-engine.js';
import type { EngagementConfig } from '../types.js';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';
import {
  DurableArtifactPublicationError,
  publishArtifactFileDurable,
  removeArtifactDurable,
  writeArtifactAtomicDurable,
} from './durable-artifact.js';
import { acquireStateMigrationWriteGuard } from './state-migration-lock.js';
import { computeConfigHash } from './engagement-config-service.js';
import { CURRENT_JOURNAL_VERSION, CURRENT_STATE_VERSION } from './persisted-state.js';

export interface BundleOptions {
  includeSnapshots?: boolean;
  includeTapes?: boolean;
}

export interface BundleFileManifestEntry {
  path: string;
  size_bytes: number;
  sha256: string;
}

export interface BundleManifest {
  manifest_version: 2;
  bundle_id: string;
  status: 'complete';
  engagement_id: string;
  created_at: string;
  state_file: string;
  state_version: number;
  journal_version: number;
  checkpoint: {
    highest_allocated_logical_seq?: number;
    highest_contiguous_applied_logical_seq?: number;
  };
  config: {
    revision?: number;
    hash?: string;
    captured_path?: string;
    source_path?: string;
    file?: { revision?: number; hash?: string; declared_hash?: string; parse_error?: string };
    state?: { revision?: number; hash?: string; declared_hash?: string };
    runtime?: { revision?: number; hash?: string; declared_hash?: string };
  };
  recovery: {
    complete: boolean;
    writable: boolean;
    outcome: string;
    source?: string;
    base_checkpoint?: number;
    config_status?: string;
    reason?: string;
    state_parse_error?: string;
    state_migration?: {
      status?: string;
      backup_manifest_sha256?: string;
    };
    authorities?: Array<{
      kind: string;
      source_path: string;
      captured_path: string;
      capture_status?: 'complete' | 'live_prefix';
      source_size_bytes?: number;
      captured_size_bytes?: number;
    }>;
  };
  sections: Array<{
    path: string;
    size_bytes: number;
    file_count: number;
    description: string;
  }>;
  files: BundleFileManifestEntry[];
  tape_paths: string[];
}

export interface PreparedBundle {
  /** Private, immutable capture tree used as tar's source directory. */
  stateDir: string;
  entries: string[];
  manifest: BundleManifest;
  cleanup: () => void;
}

interface TarOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

const TAR_STDERR_LIMIT = 64 * 1024;
const TAR_TIMEOUT_MS = 5 * 60_000;
const STALE_BUNDLE_STAGE_AGE_MS = 60 * 60 * 1000;
const STATE_ENVELOPE_PREFIX_BYTES = 1024 * 1024;

function readStateEnvelopeMetadata(path: string): {
  stateVersion?: number;
  journalVersion?: number;
  parseError?: string;
} {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) return { parseError: 'state authority is not a regular file' };
    const length = Math.min(stat.size, STATE_ENVELOPE_PREFIX_BYTES);
    const bytes = Buffer.alloc(length);
    let offset = 0;
    while (offset < length) {
      const count = readSync(fd, bytes, offset, length - offset, offset);
      if (count === 0) break;
      offset += count;
    }
    const prefix = bytes.subarray(0, offset).toString('utf8');
    const stateMatch = /"state_version"\s*:\s*(-?\d+)/.exec(prefix);
    const journalMatch = /"journal_version"\s*:\s*(-?\d+)/.exec(prefix);
    const stateVersion = stateMatch ? Number(stateMatch[1]) : 0;
    const journalVersion = journalMatch ? Number(journalMatch[1]) : 0;
    if (!Number.isSafeInteger(stateVersion) || stateVersion < 0) {
      return { parseError: `invalid state version ${stateMatch?.[1] ?? 'unknown'}` };
    }
    if (!Number.isSafeInteger(journalVersion) || journalVersion < 0) {
      return { stateVersion, parseError: `invalid journal version ${journalMatch?.[1] ?? 'unknown'}` };
    }
    if (stateVersion > CURRENT_STATE_VERSION) {
      return { stateVersion, journalVersion, parseError: `unsupported state version ${stateVersion}` };
    }
    if (journalVersion > CURRENT_JOURNAL_VERSION) {
      return { stateVersion, journalVersion, parseError: `unsupported journal version ${journalVersion}` };
    }
    return { stateVersion, journalVersion };
  } finally {
    closeSync(fd);
  }
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

function cleanupStaleBundleStages(directory: string): void {
  if (!existsSync(directory)) return;
  let changed = false;
  for (const name of readdirSync(directory)) {
    const match = /^\.overwatch-bundle-stage-(\d+)-/.exec(name);
    if (!match) continue;
    const path = join(directory, name);
    try {
      const stat = lstatSync(path);
      if (
        !stat.isDirectory()
        || stat.isSymbolicLink()
        || Date.now() - stat.mtimeMs < STALE_BUNDLE_STAGE_AGE_MS
        || processIsAlive(Number(match[1]))
      ) continue;
      rmSync(path, { recursive: true, force: false });
      changed = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
  if (changed) fsyncDirectory(directory);
}

async function hashFileAsync(path: string, signal?: AbortSignal): Promise<string> {
  const hash = createHash('sha256');
  const stream = (await import('fs')).createReadStream(path, { highWaterMark: 1024 * 1024 });
  const abort = () => stream.destroy(new Error('Bundle creation aborted.'));
  signal?.addEventListener('abort', abort, { once: true });
  try {
    for await (const chunk of stream) {
      if (signal?.aborted) throw new Error('Bundle creation aborted.');
      hash.update(chunk as Buffer);
    }
    return hash.digest('hex');
  } finally {
    signal?.removeEventListener('abort', abort);
  }
}

function assertRegularFile(path: string): void {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`Bundle source must be a regular file: ${path}`);
  }
}

function copyRegularFile(
  source: string,
  destination: string,
  mutable = false,
  forceCopy = false,
): void {
  assertRegularFile(source);
  mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
  if (!mutable && !forceCopy) {
    try {
      linkSync(source, destination);
      return;
    } catch (error) {
      if (![
        'EXDEV', 'EMLINK', 'EPERM', 'EACCES', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS',
      ].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
    }
  }
  // FICLONE gives a point-in-time copy-on-write snapshot where supported and
  // falls back to a bounded kernel copy. It never allocates the file in JS.
  copyFileSync(source, destination, constants.COPYFILE_FICLONE);
}

function copyTree(
  source: string,
  destination: string,
  skip?: (sourcePath: string, name: string) => boolean,
  forceCopy = false,
): void {
  const stat = lstatSync(source);
  if (stat.isSymbolicLink()) throw new Error(`Bundle source may not contain symbolic links: ${source}`);
  if (stat.isFile()) {
    copyRegularFile(source, destination, basename(source).includes('.tmp-'), forceCopy);
    return;
  }
  if (!stat.isDirectory()) throw new Error(`Unsupported bundle source type: ${source}`);
  mkdirSync(destination, { recursive: true, mode: 0o700 });
  for (const name of readdirSync(source).sort()) {
    if (name.endsWith('.writer-lock') || name.endsWith('.migration-lock')) continue;
    if (skip?.(source, name)) continue;
    copyTree(join(source, name), join(destination, name), skip, forceCopy);
  }
}

function trimJsonlToCompletePrefix(path: string): {
  capture_status: 'complete' | 'live_prefix';
  source_size_bytes: number;
  captured_size_bytes: number;
} {
  const sourceSize = statSync(path).size;
  if (sourceSize === 0) return {
    capture_status: 'complete', source_size_bytes: 0, captured_size_bytes: 0,
  };
  const fd = openSync(path, 'r+');
  let keep = sourceSize;
  try {
    const last = Buffer.allocUnsafe(1);
    readSync(fd, last, 0, 1, sourceSize - 1);
    if (last[0] !== 0x0a) {
      keep = 0;
      const buffer = Buffer.allocUnsafe(64 * 1024);
      let cursor = sourceSize;
      while (cursor > 0 && keep === 0) {
        const start = Math.max(0, cursor - buffer.length);
        const count = readSync(fd, buffer, 0, cursor - start, start);
        for (let index = count - 1; index >= 0; index--) {
          if (buffer[index] === 0x0a) { keep = start + index + 1; break; }
        }
        cursor = start;
      }
      truncateSync(path, keep);
      fsyncSync(fd);
      fsyncDirectory(dirname(path));
    }
  } finally {
    closeSync(fd);
  }
  return {
    capture_status: keep === sourceSize ? 'complete' : 'live_prefix',
    source_size_bytes: sourceSize,
    captured_size_bytes: keep,
  };
}

function withBundleCaptureBarrier<T>(
  stateFilePath: string,
  operation: () => T,
): T {
  const stateDir = dirname(stateFilePath);
  // Artifact domains precede state. Normal writers publish artifact authority,
  // release that lock, then persist its state reference; this order prevents a
  // capture from seeing a newer state reference with an older artifact tree.
  const candidates = [
    join(stateDir, 'evidence', 'manifest.json'),
    join(stateDir, 'reports', 'manifest.json'),
    stateFilePath,
  ];
  const paths = candidates.filter((path, index) => {
    if (index < 2 && !existsSync(dirname(path))) return false;
    return candidates.findIndex(candidate => resolve(candidate) === resolve(path)) === index;
  });
  const releases: Array<() => void> = [];
  try {
    for (const path of paths) releases.push(acquireStateMigrationWriteGuard(path));
    return operation();
  } finally {
    for (const release of releases.reverse()) release();
  }
}

function reportDeletionFilter(reportDirectory: string): (sourcePath: string, name: string) => boolean {
  const tombstones = new Set(
    readdirSync(reportDirectory)
      .map(name => {
        const id = /^([0-9a-f-]{36})\.deleted\.json$/i.exec(name)?.[1];
        if (!id) return undefined;
        try {
          const path = join(reportDirectory, name);
          const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
          let text: string;
          try {
            const stat = fstatSync(fd);
            if (!stat.isFile() || stat.size > 64 * 1024) return undefined;
            const bytes = Buffer.alloc(stat.size);
            let offset = 0;
            while (offset < bytes.length) {
              const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
              if (count === 0) return undefined;
              offset += count;
            }
            text = bytes.toString('utf8');
          } finally {
            closeSync(fd);
          }
          const value = JSON.parse(text) as Record<string, unknown>;
          return value.tombstone_version === 1 && value.report_id === id ? id : undefined;
        } catch {
          return undefined;
        }
      })
      .filter((id): id is string => Boolean(id)),
  );
  return (sourcePath, name) => sourcePath === reportDirectory
    && [...tombstones].some(id => name.startsWith(`${id}.`) && name !== `${id}.deleted.json`);
}

async function listFiles(root: string, signal?: AbortSignal, cursor = root): Promise<BundleFileManifestEntry[]> {
  const result: BundleFileManifestEntry[] = [];
  for (const name of readdirSync(cursor).sort()) {
    if (signal?.aborted) throw new Error('Bundle creation aborted.');
    const path = join(cursor, name);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) throw new Error(`Bundle staging tree contains a symbolic link: ${path}`);
    if (stat.isDirectory()) result.push(...await listFiles(root, signal, path));
    else if (stat.isFile()) result.push({
      path: relative(root, path).split(sep).join('/'),
      size_bytes: stat.size,
      sha256: await hashFileAsync(path, signal),
    });
  }
  return result;
}

function sectionDescription(path: string, stateName: string, journalName: string): string {
  return path === stateName ? 'Engagement state (graph + activity log + config)'
    : path === journalName ? 'Write-ahead mutation journal'
    : path === 'active-engagement-config.json' ? 'Converged active engagement configuration'
    : path === 'evidence' ? 'Evidence files and manifest'
    : path === 'reports' ? 'Rendered report archive'
    : path === '.snapshots' ? 'Periodic state snapshots'
    : path;
}

function buildSections(
  files: BundleFileManifestEntry[],
  stateName: string,
  journalName: string,
): BundleManifest['sections'] {
  const sections = new Map<string, { size_bytes: number; file_count: number }>();
  for (const file of files) {
    const top = file.path.split('/')[0];
    const current = sections.get(top) ?? { size_bytes: 0, file_count: 0 };
    current.size_bytes += file.size_bytes;
    current.file_count += 1;
    sections.set(top, current);
  }
  return [...sections.entries()].map(([path, aggregate]) => ({
    path,
    ...aggregate,
    description: sectionDescription(path, stateName, journalName),
  }));
}

function isInside(path: string, root: string): boolean {
  const rel = relative(root, path);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}

function canonicalDestination(path: string): string {
  const absolute = resolve(path);
  let existingAncestor = dirname(absolute);
  const missing: string[] = [basename(absolute)];
  while (!existsSync(existingAncestor)) {
    const parent = dirname(existingAncestor);
    if (parent === existingAncestor) break;
    missing.unshift(basename(existingAncestor));
    existingAncestor = parent;
  }
  const canonicalAncestor = realpathSync(existingAncestor);
  return join(canonicalAncestor, ...missing);
}

function assertSafeBundleOutput(engine: GraphEngine, outputPath: string): string {
  const destination = canonicalDestination(outputPath);
  if (existsSync(destination) && lstatSync(destination).isSymbolicLink()) {
    throw new Error(`Refusing to replace a symbolic-link bundle destination: ${destination}`);
  }
  const configuredStatePath = resolve(engine.getStateFilePath());
  const statePath = existsSync(configuredStatePath) ? realpathSync(configuredStatePath) : configuredStatePath;
  const stateDir = dirname(statePath);
  const journalPath = join(stateDir, `${basename(statePath, '.json')}.journal.jsonl`);
  const configPath = engine.getConfigRecoveryStatus().file_path;
  const configStatus = engine.getConfigRecoveryStatus();
  const canonicalConfigPath = configPath
    ? existsSync(configPath) ? realpathSync(configPath) : resolve(configPath)
    : undefined;
  const recovery = engine.getPersistenceRecoveryStatus();
  const exactSources = [
    statePath,
    journalPath,
    canonicalConfigPath,
    configStatus.intent_path,
    configStatus.conflicted_intent?.archive_path,
    recovery.journal?.path,
    recovery.state_migration?.backup_path,
    `${configuredStatePath}.rollback-intent.json`,
    ...extractTapePaths(engine),
  ]
    .filter((path): path is string => Boolean(path));
  const canonicalExactSources = exactSources.map(path => {
    try { return existsSync(path) ? realpathSync(path) : resolve(path); } catch { return resolve(path); }
  });
  if (canonicalExactSources.includes(destination)) {
    throw new Error(`Bundle output collides with live engagement data: ${destination}`);
  }
  for (let index = 0; index < exactSources.length; index++) {
    const source = exactSources[index];
    try {
      if (lstatSync(source).isDirectory() && isInside(destination, canonicalExactSources[index])) {
        throw new Error(`Bundle output collides with live engagement data: ${destination}`);
      }
    } catch (error) {
      if (error instanceof Error && error.message.startsWith('Bundle output collides')) throw error;
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        // An unreadable protected source remains protected by its canonical
        // exact path; do not fail diagnostics merely because it cannot be statted.
      }
    }
  }
  for (const configuredRoot of ['evidence', 'reports', '.snapshots', 'session-jars'].map(name => join(stateDir, name))) {
    const root = existsSync(configuredRoot) ? realpathSync(configuredRoot) : configuredRoot;
    if (isInside(destination, root)) {
      throw new Error(`Bundle output may not be placed inside live artifact storage: ${destination}`);
    }
  }
  const diagnosticPattern = /(quarantine|corrupt|recovery|rollback|backup|intent|conflict|migration)/i;
  if (existsSync(stateDir)) {
    for (const name of readdirSync(stateDir)) {
      if (!diagnosticPattern.test(name)) continue;
      const path = join(stateDir, name);
      let canonical = path;
      try { canonical = realpathSync(path); } catch { /* compare unresolved path */ }
      if (destination === canonical || (existsSync(path) && lstatSync(path).isDirectory() && isInside(destination, canonical))) {
        throw new Error(`Bundle output collides with live recovery data: ${destination}`);
      }
    }
  }
  return destination;
}

/** Derive registered tape file paths from the activity log. */
export function extractTapePaths(engine: GraphEngine): string[] {
  const paths: string[] = [];
  const seen = new Set<string>();
  for (const entry of engine.getFullHistory()) {
    if ((entry as Record<string, unknown>).event_type !== 'tape_session_started') continue;
    const details = (entry as Record<string, unknown>).details as Record<string, unknown> | undefined;
    const path = typeof details?.tape_path === 'string' ? details.tape_path : undefined;
    if (path && !seen.has(path)) { seen.add(path); paths.push(path); }
  }
  return paths;
}

function activeTapePaths(engine: GraphEngine): Set<string> {
  const active = new Map<string, { path: string; session_id?: string }>();
  for (const entry of engine.getFullHistory()) {
    const event = entry as Record<string, unknown>;
    const details = event.details as Record<string, unknown> | undefined;
    const path = typeof details?.tape_path === 'string' ? resolve(details.tape_path) : undefined;
    if (!path) continue;
    const sessionId = typeof details?.session_id === 'string' ? details.session_id : undefined;
    if (event.event_type === 'tape_session_started') {
      const startId = typeof event.event_id === 'string'
        ? event.event_id
        : `legacy:${path}:${sessionId ?? ''}`;
      active.set(startId, { path, ...(sessionId ? { session_id: sessionId } : {}) });
      continue;
    }
    if (event.event_type !== 'tape_session_stopped' && details?.tape_lifecycle !== 'failed') continue;
    const linkedStartId = typeof details?.started_event_id === 'string'
      ? details.started_event_id
      : undefined;
    if (linkedStartId) {
      active.delete(linkedStartId);
      continue;
    }
    // Legacy terminal records predate started_event_id. Retire only matching
    // path/session starts; never clear a newer generation merely because it
    // reused the same explicit pathname.
    for (const [startId, started] of active) {
      if (started.path !== path) continue;
      if (sessionId && started.session_id && sessionId !== started.session_id) continue;
      active.delete(startId);
    }
  }
  return new Set([...active.values()].map(started => started.path));
}

/** Compatibility helper retained for callers that inspect live source names. */
export function gatherBundleEntries(
  stateFilePath: string,
  opts: BundleOptions = {},
): { stateDir: string; entries: string[] } {
  const stateDir = dirname(stateFilePath);
  const entries = [basename(stateFilePath)];
  const journal = `${basename(stateFilePath, '.json')}.journal.jsonl`;
  if (existsSync(join(stateDir, journal))) entries.push(journal);
  for (const name of ['evidence', 'reports']) if (existsSync(join(stateDir, name))) entries.push(name);
  if (opts.includeSnapshots && existsSync(join(stateDir, '.snapshots'))) entries.push('.snapshots');
  return { stateDir, entries };
}

function runTar(args: string[], options: TarOptions = {}): Promise<void> {
  return new Promise((resolvePromise, rejectPromise) => {
    if (options.signal?.aborted) {
      rejectPromise(new Error('Bundle creation aborted.'));
      return;
    }
    const child = spawn('tar', args, { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    let settled = false;
    let killTimer: NodeJS.Timeout | undefined;
    const timeout = setTimeout(() => {
      child.kill('SIGTERM');
      killTimer = setTimeout(() => child.kill('SIGKILL'), 2_000);
    }, options.timeoutMs ?? TAR_TIMEOUT_MS);
    timeout.unref?.();

    const abort = () => {
      child.kill('SIGTERM');
      killTimer = setTimeout(() => child.kill('SIGKILL'), 2_000);
      killTimer.unref?.();
    };
    options.signal?.addEventListener('abort', abort, { once: true });
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderr.length < TAR_STDERR_LIMIT) stderr += chunk.toString().slice(0, TAR_STDERR_LIMIT - stderr.length);
    });
    const settle = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (killTimer) clearTimeout(killTimer);
      options.signal?.removeEventListener('abort', abort);
      if (error) rejectPromise(error); else resolvePromise();
    };
    child.on('error', error => settle(new Error(`tar spawn failed: ${error.message}`)));
    child.on('close', code => {
      if (options.signal?.aborted) settle(new Error('Bundle creation aborted.'));
      else if (code !== 0) settle(new Error(`tar exited ${code}: ${stderr.trim()}`));
      else settle();
    });
  });
}

/** Write a tar.gz to the supplied path. Callers publish it atomically. */
export async function createTarGz(
  outPath: string,
  stateDir: string,
  entries: string[],
  options: TarOptions = {},
): Promise<number> {
  await runTar(['czf', outPath, '-C', stateDir, ...entries], options);
  const stat = statSync(outPath);
  if (!stat.isFile() || stat.size <= 0) throw new Error('tar completed without a non-empty regular archive.');
  return stat.size;
}

/** Capture a point-in-time private staging tree and write its complete manifest. */
export async function prepareBundle(
  engine: GraphEngine,
  opts: BundleOptions & { signal?: AbortSignal } = {},
): Promise<PreparedBundle> {
  const sourceStatePath = resolve(engine.getStateFilePath());
  const sourceStateDir = dirname(sourceStatePath);
  const stateName = basename(sourceStatePath);
  const journalName = `${basename(sourceStatePath, '.json')}.journal.jsonl`;
  const initialRecovery = engine.getPersistenceRecoveryStatus();
  if (engine.isPersistenceWritable() && initialRecovery.writable) engine.flushNow();
  const captureWritable = engine.isPersistenceWritable()
    && engine.getPersistenceRecoveryStatus().writable;
  const stageParent = captureWritable ? sourceStateDir : tmpdir();
  let stagingDir: string | undefined;
  let cleanup = (): void => {};
  try {
    if (captureWritable) cleanupStaleBundleStages(sourceStateDir);
    stagingDir = mkdtempSync(join(
      stageParent,
      captureWritable ? `.overwatch-bundle-stage-${process.pid}-` : `overwatch-bundle-stage-${process.pid}-`,
    ));
    const stage = stagingDir;
    cleanup = () => {
      try {
        rmSync(stage, { recursive: true, force: true });
        fsyncDirectory(stageParent);
      } catch (error) {
        // Cleanup cannot make an already-published bundle look failed. Writable
        // captures are reclaimed on the next run; diagnostic stages live only
        // in the OS temp root and never mutate the engagement directory.
        console.error(`[bundle] staging cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    };
    fsyncDirectory(stageParent);

    type ConfigStatus = ReturnType<GraphEngine['getConfigRecoveryStatus']>;
    type RecoveryStatus = ReturnType<GraphEngine['getPersistenceRecoveryStatus']>;
    const authorities: NonNullable<BundleManifest['recovery']['authorities']> = [];
    const capturedSources = new Set<string>();
    const forceCopy = !captureWritable;

    const captureAuthority = (
      kind: string,
      sourcePath: string | undefined,
      capturedPath: string,
    ): NonNullable<BundleManifest['recovery']['authorities']>[number] | undefined => {
      if (!sourcePath || !existsSync(sourcePath)) return undefined;
      const canonical = (() => {
        try { return realpathSync(sourcePath); } catch { return resolve(sourcePath); }
      })();
      if (capturedSources.has(canonical)) return undefined;
      const stat = lstatSync(sourcePath);
      if (stat.isSymbolicLink()) throw new Error(`Bundle recovery authority may not be a symbolic link: ${sourcePath}`);
      const destination = join(stage, capturedPath);
      if (stat.isDirectory()) copyTree(sourcePath, destination, undefined, forceCopy);
      else if (stat.isFile()) copyRegularFile(sourcePath, destination, true, forceCopy);
      else throw new Error(`Unsupported bundle recovery authority: ${sourcePath}`);
      capturedSources.add(canonical);
      const authority = { kind, source_path: sourcePath, captured_path: capturedPath };
      authorities.push(authority);
      return authority;
    };

    const captureSources = (): {
      configStatus: ConfigStatus;
      recovery: RecoveryStatus;
      config: EngagementConfig;
      tapePaths: string[];
    } => {
      const configStatus = JSON.parse(JSON.stringify(engine.getConfigRecoveryStatus())) as ConfigStatus;
      const recovery = JSON.parse(JSON.stringify(engine.getPersistenceRecoveryStatus())) as RecoveryStatus;
      const config = JSON.parse(JSON.stringify(engine.getConfig())) as EngagementConfig;
      const tapePaths = opts.includeTapes === false ? [] : extractTapePaths(engine);
      const activeTapes = opts.includeTapes === false ? new Set<string>() : activeTapePaths(engine);

      if (existsSync(sourceStatePath)) copyRegularFile(sourceStatePath, join(stage, stateName), false, forceCopy);
      const journalPath = join(sourceStateDir, journalName);
      if (existsSync(journalPath)) copyRegularFile(journalPath, join(stage, journalName), true, forceCopy);
      if (configStatus.file_path && existsSync(configStatus.file_path)) {
        copyRegularFile(configStatus.file_path, join(stage, 'active-engagement-config.json'), false, forceCopy);
      }

      for (const name of ['evidence', 'reports']) {
        const source = join(sourceStateDir, name);
        if (!existsSync(source)) continue;
        copyTree(
          source,
          join(stage, name),
          name === 'reports' ? reportDeletionFilter(source) : undefined,
          forceCopy,
        );
      }
      if ((opts.includeSnapshots || !recovery.writable) && existsSync(join(sourceStateDir, '.snapshots'))) {
        copyTree(join(sourceStateDir, '.snapshots'), join(stage, '.snapshots'), undefined, forceCopy);
      }

      captureAuthority('config_write_intent', configStatus.intent_path, 'recovery-artifacts/config-write-intent');
      captureAuthority(
        'config_intent_conflict',
        configStatus.conflicted_intent?.archive_path,
        'recovery-artifacts/config-intent-conflict',
      );
      captureAuthority(
        'state_migration_backup',
        recovery.state_migration?.backup_path,
        'recovery-artifacts/state-migration-backup',
      );
      captureAuthority(
        'state_rollback_intent',
        `${sourceStatePath}.rollback-intent.json`,
        'recovery-artifacts/state-rollback-intent.json',
      );
      if (recovery.journal?.path && resolve(recovery.journal.path) !== resolve(journalPath)) {
        captureAuthority('recovery_journal', recovery.journal.path, 'recovery-artifacts/recovery-journal.jsonl');
      }
      for (let index = 0; index < tapePaths.length; index++) {
        const capturedPath = join('tapes', `${String(index + 1).padStart(4, '0')}-${basename(tapePaths[index]!)}`);
        let sourceBefore: ReturnType<typeof lstatSync>;
        try {
          sourceBefore = lstatSync(tapePaths[index]!);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
          throw error;
        }
        const authority = captureAuthority(
          'mcp_tape',
          tapePaths[index],
          capturedPath,
        );
        if (authority) {
          const prefix = trimJsonlToCompletePrefix(join(stage, capturedPath));
          let sourceChanged = true;
          let sourceSize = sourceBefore.size;
          try {
            const sourceAfter = lstatSync(tapePaths[index]!);
            sourceSize = sourceAfter.size;
            sourceChanged = sourceAfter.dev !== sourceBefore.dev
              || sourceAfter.ino !== sourceBefore.ino
              || sourceAfter.size !== sourceBefore.size
              || sourceAfter.mtimeMs !== sourceBefore.mtimeMs
              || sourceAfter.ctimeMs !== sourceBefore.ctimeMs;
          } catch {
            sourceChanged = true;
          }
          Object.assign(authority, {
            ...prefix,
            source_size_bytes: sourceSize,
            capture_status: activeTapes.has(resolve(tapePaths[index]!))
              || sourceChanged || prefix.capture_status === 'live_prefix'
              ? 'live_prefix'
              : 'complete',
          });
        }
      }

      if (!recovery.writable) {
        const stateStem = basename(sourceStatePath, '.json');
        const diagnosticPattern = /(quarantine|corrupt|recovery|rollback|backup|intent|conflict|migration)/i;
        for (const name of readdirSync(sourceStateDir).sort()) {
          if (!name.startsWith(`${stateStem}.`) || !diagnosticPattern.test(name)) continue;
          const source = join(sourceStateDir, name);
          const destination = join(stage, 'recovery-artifacts', name);
          if (existsSync(destination)) continue;
          const stat = lstatSync(source);
          if (stat.isFile() && !stat.isSymbolicLink()) {
            copyRegularFile(source, destination, false, forceCopy);
          }
        }
      }
      return { configStatus, recovery, config, tapePaths };
    };

    const captured = captureWritable
      ? withBundleCaptureBarrier(sourceStatePath, captureSources)
      : captureSources();
    const { configStatus, recovery, config, tapePaths: sampledTapePaths } = captured;

    // State/config bytes are already captured verbatim. Derive metadata from
    // the recovery/config services that validated those authorities at startup
    // instead of materializing a potentially huge or corrupt state file again.
    const envelope = existsSync(join(stage, stateName))
      ? readStateEnvelopeMetadata(join(stage, stateName))
      : {};
    const stateVersion = recovery.state_migration?.observed_state_version
      ?? envelope.stateVersion
      ?? 0;
    const journalVersion = recovery.journal?.format_version
      ?? recovery.state_migration?.observed_journal_version
      ?? envelope.journalVersion
      ?? 0;
    const stateParseError = envelope.parseError
      ?? (!recovery.complete ? recovery.persistence_reason ?? recovery.reason : undefined);
    const runtimeConfigIdentity = {
      revision: config.config_revision,
      hash: computeConfigHash(config),
      declared_hash: config.config_hash,
    };
    const stateConfigIdentity: BundleManifest['config']['state'] =
      configStatus.state_revision !== undefined || configStatus.state_hash !== undefined
        ? { revision: configStatus.state_revision, hash: configStatus.state_hash }
        : undefined;
    let fileConfigIdentity: BundleManifest['config']['file'];
    if (configStatus.file_path) {
      fileConfigIdentity = configStatus.file_valid === false
        ? { parse_error: configStatus.reason ?? 'active configuration is invalid' }
        : { revision: configStatus.file_revision, hash: configStatus.file_hash };
    }
    const capturedTapePaths = sampledTapePaths.filter(path => {
      try { return lstatSync(path).isFile() && !lstatSync(path).isSymbolicLink(); } catch { return false; }
    });
    const files = await listFiles(stage, opts.signal);
    const manifest: BundleManifest = {
      manifest_version: 2,
      bundle_id: randomUUID(),
      status: 'complete',
      engagement_id: config.id,
      created_at: new Date().toISOString(),
      state_file: stateName,
      state_version: stateVersion,
      journal_version: journalVersion,
      checkpoint: {
        ...(recovery.highest_allocated_logical_seq !== undefined
          ? { highest_allocated_logical_seq: recovery.highest_allocated_logical_seq }
          : {}),
        ...(recovery.highest_contiguous_applied_logical_seq !== undefined
          ? { highest_contiguous_applied_logical_seq: recovery.highest_contiguous_applied_logical_seq }
          : {}),
      },
      config: {
        revision: runtimeConfigIdentity.revision,
        // Compatibility projection remains the declared runtime hash; the
        // independently recomputed identities below expose divergence.
        hash: config.config_hash ?? runtimeConfigIdentity.hash,
        file: fileConfigIdentity,
        state: stateConfigIdentity,
        runtime: runtimeConfigIdentity,
        ...(configStatus.file_path && existsSync(join(stagingDir, 'active-engagement-config.json'))
          ? { captured_path: 'active-engagement-config.json', source_path: configStatus.file_path }
          : {}),
      },
      recovery: {
        complete: recovery.complete,
        writable: recovery.writable,
        outcome: recovery.outcome,
        source: recovery.source,
        base_checkpoint: recovery.base_checkpoint,
        config_status: configStatus.status,
        ...(recovery.reason ? { reason: recovery.reason } : {}),
        ...(stateParseError ? { state_parse_error: stateParseError } : {}),
        ...(recovery.state_migration ? {
          state_migration: {
            status: recovery.state_migration.status,
            backup_manifest_sha256: recovery.state_migration.backup_manifest_sha256,
          },
        } : {}),
        ...(authorities.length > 0 ? { authorities } : {}),
      },
      sections: buildSections(files, stateName, journalName),
      files,
      tape_paths: capturedTapePaths,
    };
    writeArtifactAtomicDurable(
      join(stage, 'bundle-manifest.json'),
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
    const entries = readdirSync(stage).sort();
    return { stateDir: stage, entries, manifest, cleanup };
  } catch (error) {
    cleanup();
    throw error;
  }
}

async function validateTarGz(path: string, signal?: AbortSignal): Promise<void> {
  await runTar(['tzf', path], { signal, timeoutMs: TAR_TIMEOUT_MS });
}

export async function buildBundle(
  engine: GraphEngine,
  opts: BundleOptions & { outputPath?: string; signal?: AbortSignal } = {},
): Promise<{
  archivePath: string;
  sizeBytes: number;
  sha256: string;
  bundleId: string;
  manifest: BundleManifest;
  durabilityConfirmed: boolean;
}> {
  const config = engine.getConfig();
  const timestamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
  const requestedPath = opts.outputPath ?? join(
    engine.getPersistenceRecoveryStatus().writable
      ? dirname(engine.getStateFilePath())
      : tmpdir(),
    `bundle-${config.id}-${timestamp}-${randomUUID().slice(0, 8)}.tar.gz`,
  );
  const archivePath = assertSafeBundleOutput(engine, requestedPath);
  // Collision validation above is intentionally side-effect free. Only create
  // an authorized output parent after every protected-source check passes.
  mkdirDurable(dirname(archivePath));
  const prepared = await prepareBundle(engine, opts);
  const stagedArchivePath = join(
    dirname(archivePath),
    `.${basename(archivePath)}.tmp-${process.pid}-${randomUUID()}`,
  );
  let published = false;
  let durabilityConfirmed = true;
  try {
    await createTarGz(stagedArchivePath, prepared.stateDir, prepared.entries, { signal: opts.signal });
    await validateTarGz(stagedArchivePath, opts.signal);
    const stagedStat = statSync(stagedArchivePath);
    const stagedSha256 = await hashFileAsync(stagedArchivePath, opts.signal);
    chmodSync(stagedArchivePath, 0o600);
    try {
      publishArtifactFileDurable(stagedArchivePath, archivePath);
      published = true;
    } catch (error) {
      if (
        error instanceof DurableArtifactPublicationError
        && error.publication_visible
        && error.destination_path === archivePath
      ) {
        published = true;
        durabilityConfirmed = error.durability_confirmed;
      } else {
        throw error;
      }
    }
    return {
      archivePath,
      sizeBytes: stagedStat.size,
      sha256: stagedSha256,
      bundleId: prepared.manifest.bundle_id,
      manifest: prepared.manifest,
      durabilityConfirmed,
    };
  } finally {
    prepared.cleanup();
    if (!published && existsSync(stagedArchivePath)) {
      try { removeArtifactDurable(stagedArchivePath); } catch { /* preserve the build failure */ }
    }
  }
}
