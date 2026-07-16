import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'fs';
import { createHash, randomBytes } from 'crypto';
import { execFileSync } from 'child_process';
import { basename, dirname, join, resolve } from 'path';
import { tmpdir } from 'os';
import type { ConfigIntentConflict, ConfigRecoveryStatus, EngagementConfig } from '../types.js';
import { engagementConfigSchema } from '../types.js';
import type { PersistedApplicationCommandV1 } from './persisted-state.js';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';
import { parseJsonBytes } from './durable-json.js';

export type ConfigResolutionMode = 'use_file' | 'use_state';

export interface ConfigApplyContext {
  source: string;
  recovery: boolean;
  semantic_change: boolean;
}

export interface ConfigCommitEvent {
  description: string;
  result: 'success' | 'failure';
  details: Record<string, unknown>;
}

export interface EngagementConfigServiceHost {
  getRuntimeConfig(): EngagementConfig;
  nowIso(): string;
  /** Cross-process lease shared by active-config, state, snapshot, and WAL writers. */
  assertWriteAllowed?(): void;
  withWriteGuard?<T>(operation: () => T): T;
  applyRuntimeConfig(config: EngagementConfig, context: ConfigApplyContext): void;
  /** Optional canonical transaction boundary for runtime config, derived graph
   * effects, and the associated audit event. Legacy/unit hosts fall back to the
   * three primitive callbacks below. */
  commitRuntimeConfig?(
    config: EngagementConfig,
    context: ConfigApplyContext,
    event?: ConfigCommitEvent,
    applicationCommand?: PersistedApplicationCommandV1,
  ): void;
  recordApplicationCommand?(command: PersistedApplicationCommandV1): void;
  hasApplicationCommand?(idempotencyKey: string): boolean;
  persistRuntimeState(): void;
  recordConfigEvent(input: ConfigCommitEvent): void;
}

interface ConfigFileObservation {
  raw_hash?: string;
  config?: EngagementConfig;
  semantic_hash?: string;
  valid: boolean;
  error?: string;
}

interface ConfigWriteIntentV1 {
  /** V2 adds the application-command envelope. Older binaries reject it
   * instead of completing the config write while silently losing idempotency. */
  version: 1 | 2;
  engagement_id: string;
  created_at: string;
  source: string;
  from_file_hash?: string;
  from_state_hash: string;
  to_revision: number;
  to_hash: string;
  config: EngagementConfig;
  /** Audit reference for an intent that explicit reconciliation supersedes. */
  superseded_intent_conflict?: ConfigIntentConflict;
  /** Command outcome committed atomically with the runtime/durable config. */
  application_command?: PersistedApplicationCommandV1;
  intent_checksum: string;
}

interface ConfigIntentConflictRecordV1 {
  version: 1;
  engagement_id: string;
  detected_at: string;
  active_intent_path: string;
  intent_raw_base64: string;
  intent_sha256: string;
  intent_checksum?: string;
  reason: string;
  observed_file: {
    hash: string;
    raw_hash?: string;
    semantic_hash?: string;
    valid: boolean;
  };
  observed_state_hash: string;
  file_classification: 'from' | 'to' | 'third' | 'invalid';
  state_classification: 'from' | 'to' | 'third';
  conflict_checksum: string;
}

interface PendingJournalReplayConfig {
  created_at: string;
  from_file_hash: string;
  from_state_hash: string;
  target: EngagementConfig;
  existing_intent_checksum?: string;
  existing_intent_target_hash?: string;
  /** A committed WAL target may recover independently of an externally edited
   * config file. Preserve that file and surface ordinary reconciliation after
   * the recovered state checkpoint is durable. */
  preserve_external_file?: boolean;
  external_file_reason?: string;
}

export interface ResolveConfigDivergenceInput {
  mode: ConfigResolutionMode;
  expected_file_hash: string;
  expected_state_hash: string;
}

export interface ResolveConfigDivergenceResult {
  resolved: true;
  mode: ConfigResolutionMode;
  config: EngagementConfig;
  recovery: ConfigRecoveryStatus;
}

export interface PreparedConfigResolution {
  mode: ConfigResolutionMode;
  config: EngagementConfig;
  expected_file_hash: string;
  expected_state_hash: string;
  intent_conflict?: ConfigIntentConflict;
}

/** RFC-8785-style subset sufficient for JSON-compatible engagement configs. */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Cannot canonicalize a non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const object = value as Record<string, unknown>;
    const keys = Object.keys(object).filter(key => object[key] !== undefined).sort();
    return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(',')}}`;
  }
  throw new Error(`Cannot canonicalize ${typeof value}`);
}

export function computeConfigHash(config: EngagementConfig): string {
  const payload = JSON.parse(JSON.stringify(config)) as Record<string, unknown>;
  delete payload.config_hash;
  return createHash('sha256').update(canonicalJson(payload)).digest('hex');
}

function semanticPayload(config: EngagementConfig): Record<string, unknown> {
  const payload = JSON.parse(JSON.stringify(config)) as Record<string, unknown>;
  delete payload.config_hash;
  delete payload.config_revision;
  return payload;
}

export function configsSemanticallyEqual(left: EngagementConfig, right: EngagementConfig): boolean {
  return canonicalJson(semanticPayload(left)) === canonicalJson(semanticPayload(right));
}

export function withConfigMetadata(config: EngagementConfig, revision: number): EngagementConfig {
  const raw = JSON.parse(JSON.stringify(config)) as Record<string, unknown>;
  delete raw.config_revision;
  delete raw.config_hash;
  const parsed = engagementConfigSchema.parse(raw);
  const revisioned = { ...parsed, config_revision: revision } as EngagementConfig;
  return engagementConfigSchema.parse({
    ...revisioned,
    config_hash: computeConfigHash(revisioned),
  });
}

const durableWriteLocks = new Set<string>();
const DURABLE_WRITE_LOCK_WAIT_MS = 30_000;
const durableWriteWaitBuffer = new Int32Array(new SharedArrayBuffer(4));

function codedError(message: string, code: string): Error {
  const error = new Error(message);
  (error as Error & { code?: string }).code = code;
  return error;
}

function processIsAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

interface DurableWriteContender {
  version: 1;
  pid: number;
  process_start_identity: string;
  token: string;
  choosing: boolean;
  ticket?: number;
}

function processStartIdentity(pid: number): string | undefined {
  if (!Number.isSafeInteger(pid) || pid <= 0 || process.platform === 'win32') return undefined;
  try {
    const started = execFileSync(
      'ps',
      ['-o', 'lstart=', '-p', String(pid)],
      { encoding: 'utf8', timeout: 1_000, stdio: ['ignore', 'pipe', 'ignore'] },
    ).trim();
    return started.length > 0 ? started : undefined;
  } catch {
    return undefined;
  }
}

const durableWriteProcessStartIdentity = processStartIdentity(process.pid)
  ?? `unverifiable-current-process-${randomBytes(16).toString('hex')}`;

function writeJsonFileDurableUnlocked(path: string, value: unknown): void {
  const directory = dirname(path);
  mkdirDurable(directory);
  const tempPath = `${path}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
  let fd: number | undefined;
  try {
    fd = openSync(tempPath, 'wx', 0o600);
    writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(tempPath, path);
    fsyncDirectory(directory);
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* preserve the durable write error */ }
    }
    if (existsSync(tempPath)) {
      try {
        unlinkSync(tempPath);
        fsyncDirectory(directory);
      } catch { /* preserve the durable write error */ }
    }
  }
}

function readDurableWriteContender(path: string): DurableWriteContender | undefined {
  try {
    const value = JSON.parse(readFileSync(path, 'utf8')) as Partial<DurableWriteContender>;
    if (
      value.version !== 1
      || !Number.isSafeInteger(value.pid)
      || typeof value.process_start_identity !== 'string'
      || value.process_start_identity.length === 0
      || typeof value.token !== 'string'
      || typeof value.choosing !== 'boolean'
      || (!value.choosing && (!Number.isSafeInteger(value.ticket) || value.ticket! < 1))
    ) return undefined;
    return value as DurableWriteContender;
  } catch {
    return undefined;
  }
}

function contenderPid(name: string): number | undefined {
  const match = /^(\d+)-[0-9a-f]+\.json$/.exec(name);
  if (!match) return undefined;
  const pid = Number(match[1]);
  return Number.isSafeInteger(pid) && pid > 0 ? pid : undefined;
}

function acquireDurableWriteLock(path: string): () => void {
  const lockDirectory = join(
    tmpdir(),
    'overwatch-durable-write-locks',
    createHash('sha256').update(resolve(path)).digest('hex'),
  );
  mkdirDurable(lockDirectory);
  if (durableWriteLocks.has(lockDirectory)) {
    throw codedError(`A durable write for ${path} is already active in this process.`, 'CONFIG_FILE_LOCKED');
  }
  const token = randomBytes(16).toString('hex');
  const contenderName = `${process.pid}-${token}.json`;
  const contenderPath = join(lockDirectory, contenderName);
  const choosing: DurableWriteContender = {
    version: 1,
    pid: process.pid,
    process_start_identity: durableWriteProcessStartIdentity,
    token,
    choosing: true,
  };
  writeJsonFileDurableUnlocked(contenderPath, choosing);

  const listContenders = (): Array<{ name: string; path: string; record?: DurableWriteContender }> => {
    const contenders: Array<{ name: string; path: string; record?: DurableWriteContender }> = [];
    for (const name of readdirSync(lockDirectory).filter(entry => entry.endsWith('.json'))) {
      const contenderPathname = join(lockDirectory, name);
      const record = readDurableWriteContender(contenderPathname);
      const pid = record?.pid ?? contenderPid(name);
      const observedStartIdentity = pid === undefined
        ? undefined
        : pid === process.pid
          ? durableWriteProcessStartIdentity
          : processStartIdentity(pid);
      const ownerStillMatches = pid !== undefined && processIsAlive(pid) && (
        !record
        || observedStartIdentity === undefined
        || observedStartIdentity === record.process_start_identity
      );
      if (pid !== undefined && !ownerStillMatches) {
        try {
          unlinkSync(contenderPathname);
          fsyncDirectory(lockDirectory);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        }
        continue;
      }
      contenders.push({ name, path: contenderPathname, record });
    }
    return contenders;
  };

  try {
    const maxTicket = listContenders().reduce(
      (maximum, contender) => Math.max(maximum, contender.record?.ticket ?? 0),
      0,
    );
    const elected: DurableWriteContender = {
      version: 1,
      pid: process.pid,
      process_start_identity: durableWriteProcessStartIdentity,
      token,
      choosing: false,
      ticket: maxTicket + 1,
    };
    writeJsonFileDurableUnlocked(contenderPath, elected);

    const startedAt = Date.now(); // clock-ok: bounded cross-process file-lock acquisition timeout
    while (true) {
      let blocked = false;
      for (const contender of listContenders()) {
        if (contender.name === contenderName) continue;
        if (!contender.record || contender.record.choosing) {
          blocked = true;
          break;
        }
        const otherTicket = contender.record.ticket!;
        if (
          otherTicket < elected.ticket!
          || (otherTicket === elected.ticket! && contender.record.token < token)
        ) {
          blocked = true;
          break;
        }
      }
      if (!blocked) break;
      if (Date.now() - startedAt >= DURABLE_WRITE_LOCK_WAIT_MS) { // clock-ok: bounded cross-process file-lock acquisition timeout
        throw codedError(`Another process is replacing ${path}; retry after its durable write completes.`, 'CONFIG_FILE_LOCKED');
      }
      Atomics.wait(durableWriteWaitBuffer, 0, 0, 10);
    }

    durableWriteLocks.add(lockDirectory);
    return () => {
      durableWriteLocks.delete(lockDirectory);
      const observed = readDurableWriteContender(contenderPath);
      if (
        !observed
        || observed.token !== token
        || observed.pid !== process.pid
        || observed.process_start_identity !== durableWriteProcessStartIdentity
      ) {
        throw codedError(`The durable write ownership record for ${path} changed before release.`, 'CONFIG_FILE_LOCK_LOST');
      }
      unlinkSync(contenderPath);
      fsyncDirectory(lockDirectory);
    };
  } catch (error) {
    try {
      const observed = readDurableWriteContender(contenderPath);
      if (
        observed?.token === token
        && observed.pid === process.pid
        && observed.process_start_identity === durableWriteProcessStartIdentity
      ) {
        unlinkSync(contenderPath);
        fsyncDirectory(lockDirectory);
      }
    } catch { /* retain the acquisition failure */ }
    throw error;
  }
}

/**
 * Atomically replace JSON after an optional compare callback. Every caller,
 * including inactive engagement writes, shares the same per-path lock.
 */
export function writeJsonAtomicDurable(
  path: string,
  value: unknown,
  assertCurrent?: (capturedPath?: string) => void,
): void {
  const directory = dirname(path);
  mkdirDurable(directory);
  const release = acquireDurableWriteLock(path);
  const tempPath = `${path}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
  const capturedPath = `${path}.overwatch-cas-${process.pid}-${randomBytes(8).toString('hex')}.previous`;
  let fd: number | undefined;
  let captured = false;
  let capturedCanBeRemoved = false;
  let operationError: unknown;
  try {
    fd = openSync(tempPath, 'wx', 0o600);
    writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;

    if (!assertCurrent) {
      renameSync(tempPath, path);
      fsyncDirectory(directory);
      return;
    }

    if (existsSync(path)) {
      renameSync(path, capturedPath);
      captured = true;
      fsyncDirectory(directory);
    }
    try {
      assertCurrent(captured ? capturedPath : undefined);
    } catch (error) {
      if (captured && !existsSync(path)) {
        linkSync(capturedPath, path);
        fsyncDirectory(directory);
        capturedCanBeRemoved = true;
      }
      throw error;
    }

    try {
      linkSync(tempPath, path);
      fsyncDirectory(directory);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
        // The captured file already passed the expected-hash check. The
        // uncooperative file at the active pathname is the state to preserve.
        capturedCanBeRemoved = true;
        throw codedError(
          `Configuration changed while ${path} was being installed; the external file was preserved.`,
          'CONFIG_HASH_CONFLICT',
        );
      }
      throw error;
    }

    // A writer that already held the old inode can finish after the rename.
    // Revalidate the captured inode before releasing it.
    if (captured) {
      try {
        assertCurrent(capturedPath);
      } catch (error) {
        const installedPath = `${capturedPath}.target`;
        renameSync(path, installedPath);
        linkSync(capturedPath, path);
        fsyncDirectory(directory);
        capturedCanBeRemoved = true;
        throw error;
      }
    }

    capturedCanBeRemoved = true;
    unlinkSync(tempPath);
    fsyncDirectory(directory);
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* preserve the durable write error */ }
    }
    if (existsSync(tempPath)) {
      try {
        unlinkSync(tempPath);
        fsyncDirectory(directory);
      } catch { /* preserve the durable write error */ }
    }
    if (captured && capturedCanBeRemoved && existsSync(capturedPath) && existsSync(path)) {
      try {
        // An editor may still hold a descriptor to the captured inode after
        // the final comparison. Archiving instead of unlinking guarantees any
        // delayed bytes remain recoverable without poisoning crash restore.
        renameSync(capturedPath, `${capturedPath}.archived`);
        fsyncDirectory(directory);
      } catch { /* the active path or intent remains authoritative */ }
    }
    try {
      release();
    } catch (releaseError) {
      if (operationError === undefined) throw releaseError;
    }
  }
}

function removeFileDurableIf(
  path: string,
  assertCaptured: (capturedPath: string) => void,
): void {
  if (!existsSync(path)) return;
  const directory = dirname(path);
  const release = acquireDurableWriteLock(path);
  const capturedPath = `${path}.overwatch-remove-${process.pid}-${randomBytes(8).toString('hex')}`;
  let operationError: unknown;
  try {
    if (!existsSync(path)) return;
    renameSync(path, capturedPath);
    fsyncDirectory(directory);
    try {
      assertCaptured(capturedPath);
    } catch (error) {
      if (!existsSync(path)) {
        linkSync(capturedPath, path);
        fsyncDirectory(directory);
      }
      throw error;
    }
    unlinkSync(capturedPath);
    fsyncDirectory(directory);
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      release();
    } catch (releaseError) {
      if (operationError === undefined) throw releaseError;
    }
  }
}

/** Restore the latest captured pre-image if a process died in the brief
 * move-aside/exclusive-install window before the active pathname was remade. */
export function recoverInterruptedAtomicJsonWrite(path: string): void {
  const directory = dirname(path);
  if (!existsSync(directory)) return;
  const prefix = `${basename(path)}.overwatch-cas-`;
  const listCandidates = () => readdirSync(directory)
    .filter(name => name.startsWith(prefix) && name.endsWith('.previous'))
    .map(name => join(directory, name));
  if (listCandidates().length === 0) return;

  const release = acquireDurableWriteLock(path);
  let operationError: unknown;
  try {
    const candidates = listCandidates();
    if (candidates.length === 0) return;
    if (existsSync(path)) {
      // The active pathname may be the installed target or an uncooperative
      // writer. Keep every captured inode for audit instead of guessing, but
      // retire it from automatic missing-path restoration.
      for (const candidate of candidates) {
        renameSync(candidate, `${candidate}.archived`);
      }
      fsyncDirectory(directory);
      return;
    }
    if (candidates.length !== 1) {
      throw codedError(
        `Multiple interrupted atomic-write pre-images exist for ${path}; preserve them and reconcile explicitly.`,
        'CONFIG_WRITE_INCOMPLETE',
      );
    }
    linkSync(candidates[0], path);
    fsyncDirectory(directory);
    unlinkSync(candidates[0]);
    fsyncDirectory(directory);
  } catch (error) {
    operationError = error;
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  } finally {
    try {
      release();
    } catch (releaseError) {
      if (operationError === undefined) throw releaseError;
    }
  }
}

function checksumIntent(intent: Omit<ConfigWriteIntentV1, 'intent_checksum'>): string {
  return createHash('sha256').update(canonicalJson(intent)).digest('hex');
}

function checksumIntentConflict(
  record: Omit<ConfigIntentConflictRecordV1, 'conflict_checksum'>,
): string {
  return createHash('sha256').update(canonicalJson(record)).digest('hex');
}

function cloneConfig(config: EngagementConfig): EngagementConfig {
  return JSON.parse(JSON.stringify(config)) as EngagementConfig;
}

function cloneApplicationCommand(
  command: PersistedApplicationCommandV1,
): PersistedApplicationCommandV1 {
  return JSON.parse(JSON.stringify(command)) as PersistedApplicationCommandV1;
}

function isEmbeddedApplicationCommand(
  value: unknown,
): value is PersistedApplicationCommandV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const command = value as Partial<PersistedApplicationCommandV1>;
  return typeof command.command_id === 'string'
    && command.command_id.length > 0
    && command.command_id.length <= 256
    && typeof command.idempotency_key === 'string'
    && command.idempotency_key.length > 0
    && command.idempotency_key.length <= 512
    && typeof command.input_sha256 === 'string'
    && /^[a-f0-9]{64}$/.test(command.input_sha256)
    && typeof command.command_kind === 'string'
    && command.command_kind.length > 0
    && [
      'mcp',
      'dashboard',
      'cli',
      'planner',
      'scripted_runner',
      'headless_runner',
      'system',
    ].includes(command.transport ?? '')
    && (command.actor_task_id === null
      || typeof command.actor_task_id === 'string')
    && command.status === 'succeeded'
    && typeof command.created_at === 'string'
    && Number.isFinite(Date.parse(command.created_at))
    && typeof command.completed_at === 'string'
    && Number.isFinite(Date.parse(command.completed_at))
    && command.validated_input !== undefined;
}

function hashObservationMarker(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isIntentConflict(value: unknown): value is ConfigIntentConflict {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const conflict = value as Partial<ConfigIntentConflict>;
  return typeof conflict.archive_path === 'string'
    && conflict.archive_path.length > 0
    && isSha256(conflict.intent_sha256)
    && (conflict.intent_checksum === undefined || isSha256(conflict.intent_checksum))
    && typeof conflict.reason === 'string'
    && conflict.reason.length > 0
    && isSha256(conflict.observed_file_hash)
    && isSha256(conflict.observed_state_hash);
}

export class EngagementConfigService {
  private readonly configPath?: string;
  private readonly intentPath?: string;
  private status: ConfigRecoveryStatus;
  private resolving = false;
  /** Last configuration known to have completed the durable state write. */
  private durableConfig: EngagementConfig;
  private pendingJournalReplay?: PendingJournalReplayConfig;
  private journalMutationInProgress = false;
  /** Expected synchronous file/runtime/state convergence inside commitDesired. */
  private writeThroughCommitInProgress = false;
  private intentConflict?: ConfigIntentConflict;

  constructor(
    private readonly host: EngagementConfigServiceHost,
    configPath?: string,
  ) {
    this.configPath = configPath ? resolve(configPath) : undefined;
    this.intentPath = this.configPath ? `${this.configPath}.write-intent.json` : undefined;
    this.durableConfig = cloneConfig(this.host.getRuntimeConfig());
    this.status = {
      status: this.configPath ? 'in_sync' : 'unmanaged',
      resolution_required: false,
      ...(this.configPath ? { file_path: this.configPath, intent_path: this.intentPath } : {}),
      intent_present: this.intentPath ? existsSync(this.intentPath) : false,
    };
  }

  initialize(input: {
    restored: boolean;
    persistence_writable: boolean;
    /** Last checkpointed config before any uncheckpointed partial WAL replay. */
    durable_config?: EngagementConfig;
  }): ConfigRecoveryStatus {
    if (!this.configPath) return this.getStatus();

    // Config CAS recovery changes pathnames and therefore must not run ahead of
    // state/WAL recovery or a V0 migration backup. A degraded persistence
    // owner exposes the artifacts read-only and retries them on a later clean
    // startup.
    if (input.persistence_writable) {
      this.withWriteGuard(() => {
        recoverInterruptedAtomicJsonWrite(this.configPath!);
        if (this.intentPath) recoverInterruptedAtomicJsonWrite(this.intentPath);
      });
    }
    const recoveredByJournalReplay = this.status.status === 'recovered';
    const file = this.observeFile();
    const runtime = this.host.getRuntimeConfig();
    const state = input.durable_config
      ? engagementConfigSchema.parse(cloneConfig(input.durable_config))
      : runtime;
    // A restored runtime is the validated durable base selected by the
    // persistence recovery state machine. Keep that authority separate from
    // later in-process runtime changes that may fail to fsync.
    this.durableConfig = cloneConfig(state);
    const stateHash = computeConfigHash(state);

    if (this.intentPath && existsSync(this.intentPath)) {
      if (!input.persistence_writable) {
        return this.block('write_incomplete', 'A config write intent exists but persistence recovery is not writable.', file, runtime);
      }
      try {
        if (this.hasArchivedConflictForActiveIntent(state.id)) {
          this.intentConflict = this.quarantineIntentConflict(
            file,
            state,
            undefined,
            new Error('This active intent was already preserved as a configuration conflict.'),
          );
          return this.block(
            'diverged',
            'A previously quarantined configuration write intent reappeared after a crash; its active marker was cleared and explicit reconciliation is still required.',
            file,
            runtime,
          );
        }
      } catch (error) {
        return this.block(
          'write_incomplete',
          `A preserved config-intent conflict could not be validated safely: ${error instanceof Error ? error.message : String(error)}`,
          this.observeFile(),
          this.host.getRuntimeConfig(),
        );
      }
      let intent: ConfigWriteIntentV1;
      try {
        intent = this.readIntent();
      } catch (error) {
        try {
          this.intentConflict = this.quarantineIntentConflict(file, state, undefined, error);
          return this.block(
            'diverged',
            'A malformed or unverifiable configuration write intent was preserved for audit; explicit reconciliation is required.',
            file,
            runtime,
          );
        } catch (quarantineError) {
          return this.block(
            'write_incomplete',
            `Interrupted config intent could not be validated or preserved safely: ${quarantineError instanceof Error ? quarantineError.message : String(quarantineError)}`,
            this.observeFile(),
            this.host.getRuntimeConfig(),
          );
        }
      }

      const fileHash = file.semantic_hash ?? file.raw_hash;
      const fileRecognized = fileHash === intent.from_file_hash || fileHash === intent.to_hash;
      const stateRecognized = stateHash === intent.from_state_hash || stateHash === intent.to_hash;
      if (!fileRecognized || !stateRecognized) {
        try {
          this.intentConflict = this.quarantineIntentConflict(
            file,
            state,
            intent,
            new Error('The current file/state pair is outside the write intent from/to states.'),
          );
          return this.block(
            'diverged',
            'A configuration write intent conflicts with the observed file or durable state and was preserved for audit; explicit reconciliation is required.',
            file,
            runtime,
          );
        } catch (quarantineError) {
          return this.block(
            'write_incomplete',
            `Conflicting config intent could not be preserved safely: ${quarantineError instanceof Error ? quarantineError.message : String(quarantineError)}`,
            this.observeFile(),
            this.host.getRuntimeConfig(),
          );
        }
      }

      try {
        this.resumeIntent(file, state, intent);
        return this.getStatus();
      } catch (error) {
        return this.block(
          'write_incomplete',
          `Interrupted config write could not be completed: ${error instanceof Error ? error.message : String(error)}`,
          this.observeFile(),
          this.host.getRuntimeConfig(),
        );
      }
    }

    this.intentConflict = this.findMatchingIntentConflict(state);
    if (this.intentConflict) {
      return this.block(
        'diverged',
        'A previously conflicted configuration write intent is preserved for audit; explicit reconciliation is required.',
        file,
        runtime,
      );
    }

    if (!file.valid || !file.config || !file.semantic_hash) {
      return this.block('diverged', file.error ?? 'The active config file is invalid.', file, runtime);
    }

    if (!configsSemanticallyEqual(file.config, state)) {
      return this.block(
        'diverged',
        'The active config file and durable state contain different configuration semantics.',
        file,
        runtime,
      );
    }

    const fileRevision = file.config.config_revision;
    const stateRevision = state.config_revision;
    const fileHasMetadata = fileRevision !== undefined;
    const stateHasMetadata = stateRevision !== undefined;
    const fileDeclaredValid = fileHasMetadata && file.config.config_hash === file.semantic_hash;
    const stateDeclaredValid = stateHasMetadata && state.config_hash === stateHash;

    if (fileHasMetadata !== stateHasMetadata) {
      return this.block(
        'diverged',
        'Only one configuration representation has revision/hash metadata; explicit reconciliation is required.',
        file,
        runtime,
      );
    }

    if (fileHasMetadata && stateHasMetadata) {
      if (!fileDeclaredValid || !stateDeclaredValid) {
        return this.block(
          'diverged',
          'A declared configuration hash does not match its canonical configuration content.',
          file,
          runtime,
        );
      }
      if (fileRevision !== stateRevision || file.semantic_hash !== stateHash) {
        return this.block(
          'diverged',
          'Configuration semantics match, but revision/hash metadata differs between file and durable state.',
          file,
          runtime,
        );
      }
      const runtimeHash = computeConfigHash(runtime);
      if (runtimeHash !== stateHash) {
        return this.block(
          input.persistence_writable ? 'diverged' : 'write_incomplete',
          input.persistence_writable
            ? 'Live configuration differs from the durable configuration selected during startup.'
            : 'Live configuration includes an uncheckpointed partial WAL replay; repair recovery and restart before reconciling configuration.',
          file,
          runtime,
        );
      }
      this.status = this.inSyncStatus(file.config, recoveredByJournalReplay ? 'recovered' : 'in_sync');
      return this.getStatus();
    }

    if (!input.persistence_writable) {
      return this.block(
        'write_incomplete',
        'Configuration metadata requires normalization but persistence recovery is not writable.',
        file,
        runtime,
      );
    }

    // Only a pair of truly legacy representations may be normalized without
    // an operator choice. Any present metadata was handled strictly above.
    const revision = 1;
    const normalized = withConfigMetadata(state, revision);
    this.commitDesired(
      normalized,
      input.restored ? 'legacy_metadata_upgrade' : 'fresh_config_initialization',
      input.restored,
      file.semantic_hash ?? file.raw_hash,
    );
    return this.getStatus();
  }

  getStatus(): ConfigRecoveryStatus {
    this.refreshManagedFileStatus();
    return {
      ...this.status,
      ...(this.status.conflicted_intent
        ? { conflicted_intent: JSON.parse(JSON.stringify(this.status.conflicted_intent)) as ConfigIntentConflict }
        : {}),
    };
  }

  isBlocked(): boolean {
    this.refreshManagedFileStatus();
    return !this.resolving
      && !this.journalMutationInProgress
      && !this.writeThroughCommitInProgress
      && this.status.resolution_required;
  }

  assertWritable(): void {
    this.refreshManagedFileStatus();
    if (!this.isBlocked()) return;
    throw new Error(`Configuration recovery is read-only: ${this.status.reason ?? 'explicit reconciliation is required'}`);
  }

  private commitRuntime(
    config: EngagementConfig,
    context: ConfigApplyContext,
    event?: ConfigCommitEvent,
    applicationCommand?: PersistedApplicationCommandV1,
  ): void {
    if (this.host.commitRuntimeConfig) {
      this.host.commitRuntimeConfig(
        config,
        context,
        event,
        applicationCommand,
      );
    } else {
      this.host.applyRuntimeConfig(config, context);
      if (event) this.host.recordConfigEvent(event);
      if (applicationCommand) {
        if (!this.host.recordApplicationCommand) {
          throw new Error(
            'The config host cannot persist an embedded application command.',
          );
        }
        this.host.recordApplicationCommand(applicationCommand);
      }
    }
    this.host.persistRuntimeState();
  }

  commit(nextConfig: EngagementConfig, source: string): EngagementConfig {
    this.assertWritable();
    this.verifyManagedFileUnchanged();
    const current = this.host.getRuntimeConfig();
    if (configsSemanticallyEqual(current, nextConfig)) return cloneConfig(current);
    const nextRevision = Math.max(current.config_revision ?? 0, 0) + 1;
    const next = withConfigMetadata(nextConfig, nextRevision);
    if (!this.configPath) {
      this.commitRuntime(next, { source, recovery: false, semantic_change: true });
      return this.host.getRuntimeConfig();
    }

    return this.commitDesired(next, source, false, this.status.file_hash);
  }

  commitWithCommand(
    nextConfig: EngagementConfig,
    source: string,
    buildCommand: (
      committedConfig: EngagementConfig,
    ) => PersistedApplicationCommandV1,
  ): {
    config: EngagementConfig;
    command: PersistedApplicationCommandV1;
  } {
    this.assertWritable();
    this.verifyManagedFileUnchanged();
    const current = this.host.getRuntimeConfig();
    const semanticChange = !configsSemanticallyEqual(current, nextConfig);
    const next = semanticChange
      ? withConfigMetadata(
          nextConfig,
          Math.max(current.config_revision ?? 0, 0) + 1,
        )
      : cloneConfig(current);
    const command = cloneApplicationCommand(buildCommand(next));
    if (command.status !== 'succeeded') {
      throw new Error(
        'A configuration write intent may only embed a succeeded application command.',
      );
    }
    if (!this.configPath) {
      this.commitRuntime(
        next,
        {
          source,
          recovery: false,
          semantic_change: semanticChange,
        },
        undefined,
        command,
      );
      this.durableConfig = cloneConfig(next);
      return { config: cloneConfig(next), command };
    }

    const config = this.commitDesired(
      next,
      source,
      false,
      this.status.file_hash,
      undefined,
      command,
    );
    return { config, command };
  }

  /** Re-establish file/runtime/state ownership after an explicit state
   * rollback restored an older configuration snapshot. The restored semantics
   * win, but receive a fresh monotonic revision so the rollback is observable
   * and older file metadata cannot masquerade as current authority. */
  adoptRestoredRuntimeConfig(source: string): EngagementConfig {
    const restored = cloneConfig(this.host.getRuntimeConfig());
    const file = this.observeFile();
    const revision = Math.max(
      restored.config_revision ?? 0,
      this.durableConfig.config_revision ?? 0,
      file.config?.config_revision ?? 0,
    ) + 1;
    const target = withConfigMetadata(restored, revision);
    if (this.configPath) {
      const observedFileHash = file.semantic_hash ?? file.raw_hash;
      if (!observedFileHash) throw new Error('The active config file could not be observed after snapshot rollback.');
      // StatePersistence has already made the selected snapshot the durable
      // head. An interrupted follow-up config write must therefore recognize
      // the restored state hash, not the pre-rollback cached head.
      this.durableConfig = cloneConfig(restored);
      return this.commitDesired(target, source, true, observedFileHash);
    }

    this.commitRuntime(
      target,
      {
        source,
        recovery: true,
        semantic_change: false,
      },
      {
        description: 'Configuration synchronized after snapshot rollback',
        result: 'success',
        details: {
          source,
          config_revision: target.config_revision,
          config_hash: target.config_hash,
        },
      },
    );
    this.durableConfig = cloneConfig(target);
    this.status = { status: 'unmanaged', resolution_required: false, intent_present: false };
    return cloneConfig(target);
  }

  /** Prepare the exact revision/hash embedded in a higher-level WAL record. */
  prepareJournalTarget(nextConfig: EngagementConfig): EngagementConfig {
    this.assertWritable();
    this.verifyManagedFileUnchanged();
    const current = this.host.getRuntimeConfig();
    return withConfigMetadata(nextConfig, Math.max(current.config_revision ?? 0, 0) + 1);
  }

  /** Install a target whose durable authority is a higher-level WAL record.
   * State persistence and WAL checkpoint advancement are owned by that caller. */
  installJournalTarget(
    next: EngagementConfig,
    source: string,
    recovery: boolean,
    expectedSourceHash: string,
  ): void {
    const parsed = engagementConfigSchema.parse(next);
    if (
      parsed.config_revision === undefined
      || parsed.config_hash === undefined
      || parsed.config_hash !== computeConfigHash(parsed)
    ) {
      throw new Error('Journaled configuration target has invalid revision/hash metadata.');
    }
    const current = this.host.getRuntimeConfig();
    this.journalMutationInProgress = true;
    if (this.configPath) {
      const file = this.observeFile();
      const observedFileHash = file.semantic_hash
        ?? file.raw_hash
        ?? hashObservationMarker({ kind: 'unknown' });
      if (recovery) {
        let existingIntent: ConfigWriteIntentV1 | undefined;
        let externalFileReason: string | undefined;
        if (!this.pendingJournalReplay && this.intentPath && existsSync(this.intentPath)) {
          try {
            existingIntent = this.readIntent();
            if (!existingIntent.source.startsWith('scope_replay')) {
              externalFileReason = 'A non-scope configuration intent is pending while scope WAL recovery is replaying.';
            }
          } catch (error) {
            externalFileReason = `The active configuration intent could not be validated during scope WAL recovery: ${error instanceof Error ? error.message : String(error)}`;
          }
        }
        const allowedFileHashes = existingIntent
          ? [existingIntent.from_file_hash, existingIntent.to_hash]
          : this.pendingJournalReplay
            ? [
                this.pendingJournalReplay.from_file_hash,
                this.pendingJournalReplay.target.config_hash,
                this.pendingJournalReplay.existing_intent_target_hash,
              ]
            : [expectedSourceHash, parsed.config_hash];
        if (!allowedFileHashes.includes(observedFileHash)) {
          externalFileReason = 'The active config file does not match the journaled scope source, target, or recovery intent.';
        }
        if (!this.pendingJournalReplay) {
          this.pendingJournalReplay = {
            created_at: this.host.nowIso(),
            from_file_hash: existingIntent?.from_file_hash ?? observedFileHash,
            from_state_hash: existingIntent?.from_state_hash ?? computeConfigHash(this.durableConfig),
            target: cloneConfig(parsed),
            ...(existingIntent ? {
              existing_intent_checksum: existingIntent.intent_checksum,
              existing_intent_target_hash: existingIntent.to_hash,
            } : {}),
            ...(externalFileReason ? {
              preserve_external_file: true,
              external_file_reason: externalFileReason,
            } : {}),
          };
        } else {
          this.pendingJournalReplay.target = cloneConfig(parsed);
          if (externalFileReason) {
            this.pendingJournalReplay.preserve_external_file = true;
            this.pendingJournalReplay.external_file_reason = externalFileReason;
          }
        }
      } else {
        if (observedFileHash !== expectedSourceHash && observedFileHash !== parsed.config_hash) {
          throw new Error('The active config file changed after the journaled scope operation was committed.');
        }
        if (observedFileHash !== parsed.config_hash) this.writeConfig(parsed, observedFileHash);
      }
    }
    this.host.applyRuntimeConfig(parsed, {
      source,
      recovery,
      semantic_change: !configsSemanticallyEqual(current, parsed),
    });
  }

  /** Publish a durable intent only after the complete WAL has replayed. */
  prepareJournalReplayCommit(): void {
    const pending = this.pendingJournalReplay;
    if (!pending || !this.configPath) return;
    if (pending.preserve_external_file) return;
    const file = this.observeFile();
    const observed = file.semantic_hash ?? file.raw_hash;
    if (
      observed !== pending.from_file_hash
      && observed !== pending.target.config_hash
      && observed !== pending.existing_intent_target_hash
    ) {
      pending.preserve_external_file = true;
      pending.external_file_reason = 'The active config file changed after scope WAL replay and before its recovered state checkpoint.';
      return;
    }
    let existing: ConfigWriteIntentV1 | undefined;
    if (this.intentPath && existsSync(this.intentPath)) {
      try {
        existing = this.readIntent();
      } catch (error) {
        pending.preserve_external_file = true;
        pending.external_file_reason = `The active configuration intent changed or became invalid before the recovered scope checkpoint: ${error instanceof Error ? error.message : String(error)}`;
        return;
      }
    }
    if (existing) {
      if (
        existing.intent_checksum !== pending.existing_intent_checksum
        || existing.to_hash !== pending.target.config_hash
      ) {
        pending.preserve_external_file = true;
        pending.external_file_reason = 'The retained scope recovery intent does not match the fully replayed configuration target.';
      }
      return;
    }
    const intent = this.createIntent({
      engagement_id: pending.target.id,
      created_at: pending.created_at,
      source: 'scope_replay',
      from_file_hash: pending.from_file_hash,
      from_state_hash: pending.from_state_hash,
      to_revision: pending.target.config_revision!,
      to_hash: pending.target.config_hash!,
      config: pending.target,
    });
    this.writeIntent(intent);
    pending.existing_intent_checksum = intent.intent_checksum;
  }

  /** Complete the external file side only after replayed state is durable. */
  completeJournalReplayCommit(): void {
    const pending = this.pendingJournalReplay;
    if (!pending) return;
    try {
      if (this.configPath) {
        const file = this.observeFile();
        const observed = file.semantic_hash ?? file.raw_hash;
        if (
          pending.preserve_external_file
          || (observed !== pending.from_file_hash && observed !== pending.target.config_hash)
        ) {
          const runtimeHash = computeConfigHash(this.host.getRuntimeConfig());
          if (runtimeHash !== pending.target.config_hash) {
            throw new Error('Recovered scope state cannot defer file reconciliation because runtime did not reach the committed target.');
          }
          this.durableConfig = cloneConfig(pending.target);
          const reason = pending.external_file_reason
            ?? 'The active config file changed before scope recovery could publish its final target.';
          if (this.intentPath && existsSync(this.intentPath)) {
            let retainedIntent: ConfigWriteIntentV1 | undefined;
            try {
              retainedIntent = this.readIntent();
            } catch {
              // The exact malformed bytes are preserved by quarantine below.
            }
            this.intentConflict = this.quarantineIntentConflict(
              file,
              pending.target,
              retainedIntent,
              new Error(reason),
            );
          }
          const preservedFile = this.observeFile();
          this.pendingJournalReplay = undefined;
          this.journalMutationInProgress = false;
          this.status = {
            ...this.statusFor(preservedFile, this.host.getRuntimeConfig()),
            status: 'diverged',
            resolution_required: true,
            reason: `${reason} The committed scope WAL was recovered to durable state without overwriting the file; explicit configuration reconciliation is required.`,
            ...(this.intentPath && existsSync(this.intentPath)
              ? { allowed_resolutions: [] }
              : {}),
          };
          return;
        }
        if (observed !== pending.target.config_hash) {
          try {
            this.writeConfig(pending.target, observed);
          } catch (error) {
            if ((error as Error & { code?: string }).code !== 'CONFIG_HASH_CONFLICT') throw error;
            pending.preserve_external_file = true;
            pending.external_file_reason = 'The active config file changed at the final compare-and-swap boundary for recovered scope state.';
            this.completeJournalReplayCommit();
            return;
          }
        }
      }
      this.assertTargetConverged(pending.target);
      this.durableConfig = cloneConfig(pending.target);
      this.removeIntent(pending.existing_intent_checksum);
      this.status = this.configPath
        ? this.inSyncStatus(pending.target, 'recovered')
        : { status: 'unmanaged', resolution_required: false, intent_present: false };
      this.pendingJournalReplay = undefined;
      this.journalMutationInProgress = false;
    } catch (error) {
      this.journalMutationInProgress = false;
      this.status = {
        ...this.statusFor(this.observeFile(), this.host.getRuntimeConfig()),
        status: 'write_incomplete',
        resolution_required: true,
        allowed_resolutions: [],
        reason: `Replayed scope configuration could not be published durably: ${error instanceof Error ? error.message : String(error)}`,
      };
      throw error;
    }
  }

  abortJournalReplay(): void {
    this.pendingJournalReplay = undefined;
    this.journalMutationInProgress = false;
  }

  completeJournalCommit(config: EngagementConfig, recovered: boolean): void {
    try {
      this.assertTargetConverged(config);
      this.journalMutationInProgress = false;
      this.durableConfig = cloneConfig(config);
      this.status = this.configPath
        ? this.inSyncStatus(config, recovered ? 'recovered' : 'in_sync')
        : { status: 'unmanaged', resolution_required: false, intent_present: false };
    } catch (error) {
      this.failJournalCommit(
        `Journaled configuration did not converge: ${error instanceof Error ? error.message : String(error)}`,
      );
      throw error;
    }
  }

  failJournalCommit(reason: string): void {
    this.journalMutationInProgress = false;
    const file = this.observeFile();
    this.status = {
      ...this.statusFor(file, this.host.getRuntimeConfig()),
      status: 'write_incomplete',
      resolution_required: true,
      allowed_resolutions: [],
      reason,
    };
  }

  resolve(input: ResolveConfigDivergenceInput): ResolveConfigDivergenceResult {
    const prepared = this.prepareResolution(input);
    return this.commitPreparedResolution(prepared);
  }

  commitPreparedResolution(
    prepared: PreparedConfigResolution,
    applicationCommand?: PersistedApplicationCommandV1,
  ): ResolveConfigDivergenceResult {
    return this.applyPreparedResolution(prepared, target =>
      this.commitDesired(
        target,
        `config_reconcile_${prepared.mode}`,
        true,
        prepared.expected_file_hash,
        prepared.intent_conflict,
        applicationCommand,
      ),
    );
  }

  previewPreparedResolution(
    prepared: PreparedConfigResolution,
  ): ResolveConfigDivergenceResult {
    return {
      resolved: true,
      mode: prepared.mode,
      config: cloneConfig(prepared.config),
      recovery: {
        ...this.inSyncStatus(prepared.config, 'recovered'),
        last_resolution: prepared.mode,
      },
    };
  }

  prepareResolution(input: ResolveConfigDivergenceInput): PreparedConfigResolution {
    this.refreshManagedFileStatus();
    if (!this.configPath || !this.status.resolution_required) {
      throw new Error('No active configuration divergence requires resolution.');
    }
    if (this.status.status === 'write_incomplete' || this.status.intent_present) {
      const error = new Error('A known configuration write is incomplete; restart to resume its durable intent before choosing reconciliation authority.');
      (error as Error & { code?: string }).code = 'CONFIG_WRITE_INCOMPLETE';
      throw error;
    }

    const file = this.observeFile();
    const state = this.durableConfig;
    const stateHash = computeConfigHash(state);
    const observedFileHash = file.semantic_hash ?? file.raw_hash;
    if (observedFileHash !== input.expected_file_hash || stateHash !== input.expected_state_hash) {
      const error = new Error('Configuration changed after it was inspected; refresh recovery status and retry.');
      (error as Error & { code?: string }).code = 'CONFIG_HASH_CONFLICT';
      throw error;
    }

    let target: EngagementConfig;
    if (input.mode === 'use_file') {
      if (!file.valid || !file.config) {
        throw new Error(`The active config file cannot be selected: ${file.error ?? 'schema validation failed'}`);
      }
      if (
        file.config.id !== state.id
        || file.config.created_at !== state.created_at
        || file.config.engagement_nonce !== state.engagement_nonce
      ) {
        throw new Error('The active engagement id, created_at, and engagement_nonce are immutable; use_state or restore the correct file.');
      }
      const revision = Math.max(file.config.config_revision ?? 0, state.config_revision ?? 0) + 1;
      target = withConfigMetadata(file.config, revision);
    } else {
      const revision = Math.max(file.config?.config_revision ?? 0, state.config_revision ?? 0, 0) + 1;
      target = withConfigMetadata(state, revision);
    }
    return {
      mode: input.mode,
      config: target,
      expected_file_hash: input.expected_file_hash,
      expected_state_hash: input.expected_state_hash,
      ...(this.intentConflict
        ? { intent_conflict: JSON.parse(JSON.stringify(this.intentConflict)) as ConfigIntentConflict }
        : {}),
    };
  }

  applyPreparedResolution(
    prepared: PreparedConfigResolution,
    apply: (target: EngagementConfig) => EngagementConfig,
  ): ResolveConfigDivergenceResult {
    this.resolving = true;
    try {
      const file = this.observeFile();
      const observedFileHash = file.semantic_hash ?? file.raw_hash;
      const durableHash = computeConfigHash(this.durableConfig);
      if (
        observedFileHash !== prepared.expected_file_hash
        || durableHash !== prepared.expected_state_hash
      ) {
        const error = new Error('Configuration changed after it was inspected; refresh recovery status and retry.');
        (error as Error & { code?: string }).code = 'CONFIG_HASH_CONFLICT';
        throw error;
      }
      const resolved = apply(cloneConfig(prepared.config));
      if (computeConfigHash(resolved) !== prepared.config.config_hash) {
        throw new Error('Configuration reconciliation did not install the prepared revision/hash target.');
      }
      this.intentConflict = undefined;
      this.status = {
        ...this.inSyncStatus(resolved, 'recovered'),
        last_resolution: prepared.mode,
      };
      return { resolved: true, mode: prepared.mode, config: cloneConfig(resolved), recovery: this.getStatus() };
    } finally {
      this.resolving = false;
    }
  }

  private commitDesired(
    next: EngagementConfig,
    source: string,
    recovery: boolean,
    expectedFileHash?: string,
    supersededIntentConflict?: ConfigIntentConflict,
    applicationCommand?: PersistedApplicationCommandV1,
  ): EngagementConfig {
    const stateBefore = this.host.getRuntimeConfig();
    const fileBefore = this.observeFile();
    const observedFileHash = fileBefore.semantic_hash ?? fileBefore.raw_hash;
    if (this.configPath && (!expectedFileHash || observedFileHash !== expectedFileHash)) {
      const error = new Error('Configuration changed after it was inspected; refresh recovery status and retry.');
      (error as Error & { code?: string }).code = 'CONFIG_HASH_CONFLICT';
      throw error;
    }
    const intent = this.createIntent({
      engagement_id: next.id,
      created_at: this.host.nowIso(),
      source,
      from_file_hash: expectedFileHash,
      from_state_hash: computeConfigHash(this.durableConfig),
      to_revision: next.config_revision!,
      to_hash: next.config_hash!,
      config: next,
      ...(supersededIntentConflict
        ? {
            superseded_intent_conflict: JSON.parse(JSON.stringify(supersededIntentConflict)) as ConfigIntentConflict,
          }
        : {}),
      ...(applicationCommand
        ? { application_command: cloneApplicationCommand(applicationCommand) }
        : {}),
    });

    this.writeThroughCommitInProgress = true;
    try {
      this.writeIntent(intent);
      this.writeConfig(next, expectedFileHash);
      this.commitRuntime(
        next,
        {
          source,
          recovery,
          semantic_change: !configsSemanticallyEqual(stateBefore, next),
        },
        {
          description: recovery
            ? source.includes('rollback')
              ? 'Configuration synchronized after snapshot rollback'
              : `Configuration divergence resolved with ${source.endsWith('use_file') ? 'file' : 'state'} authority`
            : 'Engagement configuration updated',
          result: 'success',
          details: {
            source,
            previous_revision: stateBefore.config_revision ?? null,
            config_revision: next.config_revision,
            config_hash: next.config_hash,
            expected_file_hash: expectedFileHash ?? null,
            previous_state_hash: intent.from_state_hash,
            target_hash: intent.to_hash,
            intent_checksum: intent.intent_checksum,
            recovery,
            ...(intent.superseded_intent_conflict
              ? { superseded_config_intent: intent.superseded_intent_conflict }
              : {}),
          },
        },
        intent.application_command,
      );
      this.assertTargetConverged(next);
      if (
        intent.application_command
        && this.host.hasApplicationCommand
        && !this.host.hasApplicationCommand(
          intent.application_command.idempotency_key,
        )
      ) {
        throw new Error(
          'Configuration converged without its embedded application command.',
        );
      }
      this.durableConfig = cloneConfig(next);
      this.removeIntent(intent.intent_checksum);
      this.status = this.inSyncStatus(next, recovery ? 'recovered' : 'in_sync');
      return cloneConfig(next);
    } catch (error) {
      this.status = {
        ...this.statusFor(this.observeFile(), this.host.getRuntimeConfig()),
        status: 'write_incomplete',
        resolution_required: true,
        intent_present: this.intentPath ? existsSync(this.intentPath) : false,
        allowed_resolutions: [],
        reason: `Configuration write did not complete durably: ${error instanceof Error ? error.message : String(error)}`,
      };
      throw error;
    } finally {
      this.writeThroughCommitInProgress = false;
    }
  }

  private resumeIntent(
    file: ConfigFileObservation,
    state: EngagementConfig,
    intent: ConfigWriteIntentV1 = this.readIntent(),
  ): void {
    const fileHash = file.semantic_hash ?? file.raw_hash;
    const stateHash = computeConfigHash(state);
    const fileRecognized = fileHash === intent.from_file_hash || fileHash === intent.to_hash;
    const stateRecognized = stateHash === intent.from_state_hash || stateHash === intent.to_hash;
    if (!fileRecognized || !stateRecognized) {
      throw new Error('Config write intent does not describe the current file/state pair.');
    }

    if (fileHash !== intent.to_hash) this.writeConfig(intent.config, fileHash);
    const stateNeedsCompletion = stateHash !== intent.to_hash;
    const commandNeedsCompletion = Boolean(
      intent.application_command
      && this.host.hasApplicationCommand
      && !this.host.hasApplicationCommand(
        intent.application_command.idempotency_key,
      ),
    );
    if (stateNeedsCompletion || commandNeedsCompletion) {
      this.commitRuntime(
        intent.config,
        {
          source: `${intent.source}_recovery`,
          recovery: true,
          semantic_change: !configsSemanticallyEqual(state, intent.config),
        },
        stateNeedsCompletion
          ? {
              description: 'Completed interrupted configuration write',
              result: 'success',
              details: {
                source: intent.source,
                config_revision: intent.to_revision,
                config_hash: intent.to_hash,
                expected_file_hash: intent.from_file_hash,
                previous_state_hash: intent.from_state_hash,
                target_hash: intent.to_hash,
                intent_checksum: intent.intent_checksum,
                ...(intent.superseded_intent_conflict
                  ? {
                      superseded_config_intent:
                        intent.superseded_intent_conflict,
                    }
                  : {}),
              },
            }
          : undefined,
        intent.application_command,
      );
    }
    this.assertTargetConverged(intent.config);
    if (
      intent.application_command
      && this.host.hasApplicationCommand
      && !this.host.hasApplicationCommand(
        intent.application_command.idempotency_key,
      )
    ) {
      throw new Error(
        'Recovered configuration is missing its embedded application command.',
      );
    }
    this.durableConfig = cloneConfig(intent.config);
    this.removeIntent(intent.intent_checksum);
    this.status = this.inSyncStatus(intent.config, 'recovered');
  }

  private observeFile(observedPath: string | undefined = this.configPath): ConfigFileObservation {
    if (!observedPath || !existsSync(observedPath)) {
      return {
        raw_hash: hashObservationMarker({ kind: 'missing' }),
        valid: false,
        error: `Active config file does not exist: ${observedPath ?? '(unmanaged)'}`,
      };
    }
    try {
      const bytes = readFileSync(observedPath);
      const rawHash = createHash('sha256').update(bytes).digest('hex');
      try {
        const parsed = engagementConfigSchema.parse(parseJsonBytes(bytes));
        return {
          raw_hash: rawHash,
          config: parsed,
          semantic_hash: computeConfigHash(parsed),
          valid: true,
        };
      } catch (error) {
        return {
          raw_hash: rawHash,
          valid: false,
          error: `Active config file is invalid: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    } catch (error) {
      let marker: unknown = { kind: 'unreadable' };
      try {
        const stat = statSync(observedPath);
        marker = {
          kind: 'unreadable',
          size: stat.size,
          mtime_ms: stat.mtimeMs,
          ctime_ms: stat.ctimeMs,
          inode: stat.ino,
          mode: stat.mode,
        };
      } catch {
        // The file may have disappeared between existsSync and readFileSync.
        marker = { kind: 'missing' };
      }
      return {
        raw_hash: hashObservationMarker(marker),
        valid: false,
        error: `Active config file is unreadable: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  private quarantineIntentConflict(
    file: ConfigFileObservation,
    state: EngagementConfig,
    intent: ConfigWriteIntentV1 | undefined,
    cause: unknown,
  ): ConfigIntentConflict {
    if (!this.intentPath) throw new Error('No active config intent path is configured.');
    const rawIntent = readFileSync(this.intentPath);
    const intentSha256 = createHash('sha256').update(rawIntent).digest('hex');
    const archivePath = `${this.intentPath}.conflict-${intentSha256}.json`;
    const observedFileHash = file.semantic_hash ?? file.raw_hash ?? hashObservationMarker({ kind: 'unknown' });
    const observedStateHash = computeConfigHash(state);
    const reason = cause instanceof Error ? cause.message : String(cause);
    const classify = (hash: string | undefined, from: string | undefined, to: string | undefined) =>
      hash !== undefined && hash === from ? 'from' as const
        : hash !== undefined && hash === to ? 'to' as const
          : 'third' as const;
    const body: Omit<ConfigIntentConflictRecordV1, 'conflict_checksum'> = {
      version: 1,
      engagement_id: state.id,
      detected_at: this.host.nowIso(),
      active_intent_path: this.intentPath,
      intent_raw_base64: rawIntent.toString('base64'),
      intent_sha256: intentSha256,
      ...(intent?.intent_checksum ? { intent_checksum: intent.intent_checksum } : {}),
      reason,
      observed_file: {
        hash: observedFileHash,
        ...(file.raw_hash ? { raw_hash: file.raw_hash } : {}),
        ...(file.semantic_hash ? { semantic_hash: file.semantic_hash } : {}),
        valid: file.valid,
      },
      observed_state_hash: observedStateHash,
      file_classification: file.valid
        ? classify(observedFileHash, intent?.from_file_hash, intent?.to_hash)
        : 'invalid',
      state_classification: classify(observedStateHash, intent?.from_state_hash, intent?.to_hash),
    };
    let record: ConfigIntentConflictRecordV1;
    if (existsSync(archivePath)) {
      record = this.readIntentConflict(archivePath);
      if (
        record.engagement_id !== state.id
        || record.intent_sha256 !== intentSha256
        || record.intent_raw_base64 !== body.intent_raw_base64
      ) {
        throw new Error('Existing config-intent conflict archive does not preserve the active intent bytes.');
      }
    } else {
      record = { ...body, conflict_checksum: checksumIntentConflict(body) };
      this.writeJsonAtomic(archivePath, record);
    }

    this.removeIntent(undefined, intentSha256);
    return this.intentConflictSummary(archivePath, record);
  }

  private readIntentConflict(path: string): ConfigIntentConflictRecordV1 {
    const value = parseJsonBytes(readFileSync(path));
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('Config-intent conflict archive must be an object.');
    }
    const candidate = value as ConfigIntentConflictRecordV1;
    const { conflict_checksum, ...body } = candidate;
    if (
      candidate.version !== 1
      || typeof candidate.engagement_id !== 'string'
      || candidate.engagement_id.length === 0
      || typeof candidate.detected_at !== 'string'
      || !Number.isFinite(Date.parse(candidate.detected_at))
      || typeof candidate.active_intent_path !== 'string'
      || candidate.active_intent_path.length === 0
      || typeof candidate.intent_raw_base64 !== 'string'
      || !isSha256(candidate.intent_sha256)
      || (candidate.intent_checksum !== undefined && !isSha256(candidate.intent_checksum))
      || typeof candidate.reason !== 'string'
      || candidate.reason.length === 0
      || !candidate.observed_file
      || typeof candidate.observed_file !== 'object'
      || !isSha256(candidate.observed_file.hash)
      || (candidate.observed_file.raw_hash !== undefined && !isSha256(candidate.observed_file.raw_hash))
      || (candidate.observed_file.semantic_hash !== undefined && !isSha256(candidate.observed_file.semantic_hash))
      || typeof candidate.observed_file.valid !== 'boolean'
      || !isSha256(candidate.observed_state_hash)
      || !['from', 'to', 'third', 'invalid'].includes(candidate.file_classification)
      || !['from', 'to', 'third'].includes(candidate.state_classification)
      || !isSha256(conflict_checksum)
      || checksumIntentConflict(body) !== conflict_checksum
    ) {
      throw new Error('Config-intent conflict archive checksum or metadata is invalid.');
    }
    const raw = Buffer.from(candidate.intent_raw_base64, 'base64');
    if (
      raw.toString('base64') !== candidate.intent_raw_base64
      || createHash('sha256').update(raw).digest('hex') !== candidate.intent_sha256
    ) {
      throw new Error('Config-intent conflict archive does not preserve the declared intent bytes.');
    }
    return candidate;
  }

  private hasArchivedConflictForActiveIntent(engagementId: string): boolean {
    if (!this.intentPath) return false;
    const rawIntent = readFileSync(this.intentPath);
    const intentSha256 = createHash('sha256').update(rawIntent).digest('hex');
    const archivePath = `${this.intentPath}.conflict-${intentSha256}.json`;
    if (!existsSync(archivePath)) return false;
    const record = this.readIntentConflict(archivePath);
    if (record.engagement_id !== engagementId) {
      throw new Error('The preserved config-intent conflict belongs to a different engagement.');
    }
    return true;
  }

  private findMatchingIntentConflict(
    state: EngagementConfig,
  ): ConfigIntentConflict | undefined {
    if (!this.intentPath) return undefined;
    const observedStateHash = computeConfigHash(state);
    const prefix = `${basename(this.intentPath)}.conflict-`;
    let names: string[];
    try {
      names = readdirSync(dirname(this.intentPath)).filter(name => name.startsWith(prefix) && name.endsWith('.json'));
    } catch {
      return undefined;
    }
    const matches = names.flatMap(name => {
      const path = join(dirname(this.intentPath!), name);
      try {
        const record = this.readIntentConflict(path);
        if (
          record.engagement_id !== state.id
          || record.observed_state_hash !== observedStateHash
        ) return [];
        return [{ path, record }];
      } catch {
        return [];
      }
    }).sort((left, right) =>
      left.record.detected_at.localeCompare(right.record.detected_at)
      || left.path.localeCompare(right.path),
    );
    const latest = matches.at(-1);
    return latest ? this.intentConflictSummary(latest.path, latest.record) : undefined;
  }

  private intentConflictSummary(
    archivePath: string,
    record: ConfigIntentConflictRecordV1,
  ): ConfigIntentConflict {
    return {
      archive_path: archivePath,
      intent_sha256: record.intent_sha256,
      ...(record.intent_checksum ? { intent_checksum: record.intent_checksum } : {}),
      reason: record.reason,
      observed_file_hash: record.observed_file.hash,
      observed_state_hash: record.observed_state_hash,
    };
  }

  private createIntent(input: Omit<ConfigWriteIntentV1, 'version' | 'intent_checksum'>): ConfigWriteIntentV1 {
    const body: Omit<ConfigWriteIntentV1, 'intent_checksum'> = {
      version: input.application_command ? 2 : 1,
      ...input,
    };
    return { ...body, intent_checksum: checksumIntent(body) };
  }

  private readIntent(path: string | undefined = this.intentPath): ConfigWriteIntentV1 {
    if (!path) throw new Error('No active config intent path is configured.');
    const value = parseJsonBytes(readFileSync(path));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Config write intent must be an object.');
    const candidate = value as ConfigWriteIntentV1;
    if (
      (candidate.version !== 1 && candidate.version !== 2)
      || candidate.engagement_id !== candidate.config?.id
    ) {
      throw new Error('Config write intent metadata is invalid.');
    }
    const { intent_checksum, ...body } = candidate;
    if (!/^[0-9a-f]{64}$/.test(intent_checksum) || checksumIntent(body) !== intent_checksum) {
      throw new Error('Config write intent checksum is invalid.');
    }
    const config = engagementConfigSchema.parse(candidate.config);
    if (
      config.config_revision !== candidate.to_revision
      || computeConfigHash(config) !== candidate.to_hash
      || config.config_hash !== candidate.to_hash
      || (candidate.superseded_intent_conflict !== undefined
        && !isIntentConflict(candidate.superseded_intent_conflict))
      || (candidate.version === 1
        && candidate.application_command !== undefined)
      || (candidate.version === 2
        && !isEmbeddedApplicationCommand(candidate.application_command))
    ) {
      throw new Error('Config write intent target metadata is inconsistent.');
    }
    return { ...candidate, config };
  }

  private writeIntent(intent: ConfigWriteIntentV1): void {
    if (!this.intentPath) return;
    this.writeJsonAtomic(this.intentPath, intent, capturedPath => {
      if (!capturedPath) return;
      const existing = this.readIntent(capturedPath);
      if (existing.intent_checksum !== intent.intent_checksum) {
        throw new Error('A different configuration write is already pending recovery.');
      }
    });
  }

  private removeIntent(expectedChecksum?: string, expectedRawSha256?: string): void {
    if (!this.intentPath || !existsSync(this.intentPath)) return;
    this.withWriteGuard(() => {
      removeFileDurableIf(this.intentPath!, capturedPath => {
        const raw = readFileSync(capturedPath);
        if (
          expectedRawSha256
          && createHash('sha256').update(raw).digest('hex') !== expectedRawSha256
        ) {
          throw new Error('Active config intent changed before its audited removal.');
        }
        if (expectedChecksum && this.readIntent(capturedPath).intent_checksum !== expectedChecksum) {
          throw new Error('A different configuration write replaced the intent before completion.');
        }
        if (!expectedChecksum && !expectedRawSha256) {
          throw new Error('Refusing to remove a configuration intent without its expected identity.');
        }
      });
    });
  }

  private writeConfig(config: EngagementConfig, expectedFileHash?: string): void {
    if (!this.configPath) return;
    this.writeJsonAtomic(
      this.configPath,
      config,
      expectedFileHash === undefined
        ? undefined
        : capturedPath => {
            const observed = this.observeFile(capturedPath);
            const observedHash = observed.semantic_hash ?? observed.raw_hash;
            if (observedHash !== expectedFileHash) {
              throw codedError(
                'Configuration changed at the durable compare-and-swap boundary; the external file was preserved.',
                'CONFIG_HASH_CONFLICT',
              );
            }
          },
    );
  }

  private writeJsonAtomic(path: string, value: unknown, assertCurrent?: (capturedPath?: string) => void): void {
    this.withWriteGuard(() => writeJsonAtomicDurable(path, value, assertCurrent));
  }

  private assertWriteAllowed(): void {
    this.host.assertWriteAllowed?.();
  }

  private withWriteGuard<T>(operation: () => T): T {
    if (this.host.withWriteGuard) return this.host.withWriteGuard(operation);
    this.assertWriteAllowed();
    return operation();
  }

  private block(
    status: 'diverged' | 'write_incomplete',
    reason: string,
    file: ConfigFileObservation,
    state: EngagementConfig,
  ): ConfigRecoveryStatus {
    this.status = {
      ...this.statusFor(file, state),
      status,
      resolution_required: true,
      reason,
    };
    return this.getStatus();
  }

  private statusFor(file: ConfigFileObservation, state: EngagementConfig): ConfigRecoveryStatus {
    const durable = this.durableConfig;
    const fileIdentityMatches = Boolean(
      file.valid
      && file.config
      && file.config.id === durable.id
      && file.config.created_at === durable.created_at
      && file.config.engagement_nonce === durable.engagement_nonce,
    );
    return {
      status: 'diverged',
      resolution_required: true,
      file_path: this.configPath,
      intent_path: this.intentPath,
      intent_present: this.intentPath ? existsSync(this.intentPath) : false,
      file_valid: file.valid,
      file_revision: file.config?.config_revision,
      state_revision: durable.config_revision,
      runtime_revision: state.config_revision,
      file_hash: file.semantic_hash ?? file.raw_hash,
      state_hash: computeConfigHash(durable),
      runtime_hash: computeConfigHash(state),
      allowed_resolutions: fileIdentityMatches ? ['use_file', 'use_state'] : ['use_state'],
      ...(this.intentConflict ? {
        conflicted_intent: JSON.parse(JSON.stringify(this.intentConflict)) as ConfigIntentConflict,
      } : {}),
    };
  }

  private inSyncStatus(config: EngagementConfig, status: 'in_sync' | 'recovered'): ConfigRecoveryStatus {
    return {
      status,
      resolution_required: false,
      file_path: this.configPath,
      intent_path: this.intentPath,
      intent_present: false,
      file_valid: true,
      file_revision: config.config_revision,
      state_revision: config.config_revision,
      runtime_revision: config.config_revision,
      file_hash: config.config_hash ?? computeConfigHash(config),
      state_hash: config.config_hash ?? computeConfigHash(config),
      runtime_hash: config.config_hash ?? computeConfigHash(config),
      allowed_resolutions: [],
    };
  }

  private refreshManagedFileStatus(): void {
    if (!this.configPath || this.resolving || this.journalMutationInProgress) return;

    if (this.status.resolution_required) {
      const previous = this.status;
      const observed = this.statusFor(this.observeFile(), this.host.getRuntimeConfig());
      this.status = {
        ...observed,
        status: previous.status,
        resolution_required: true,
        reason: previous.reason,
        ...(previous.last_resolution ? { last_resolution: previous.last_resolution } : {}),
        ...(previous.status === 'write_incomplete' || observed.intent_present
          ? { allowed_resolutions: [] }
          : {}),
      };
      return;
    }

    if (this.status.status !== 'in_sync' && this.status.status !== 'recovered') return;

    const file = this.observeFile();
    const runtime = this.host.getRuntimeConfig();
    const observedHash = file.semantic_hash ?? file.raw_hash;
    const expectedFileHash = this.status.file_hash;
    const expectedRuntimeHash = this.status.runtime_hash;
    const runtimeHash = computeConfigHash(runtime);
    const fileDeclaredValid = Boolean(
      file.valid
      && file.config?.config_revision !== undefined
      && file.config.config_hash === file.semantic_hash,
    );
    if (
      !fileDeclaredValid
      || observedHash !== expectedFileHash
      || runtimeHash !== expectedRuntimeHash
    ) {
      this.status = {
        ...this.statusFor(file, runtime),
        status: 'diverged',
        resolution_required: true,
        reason: runtimeHash !== expectedRuntimeHash
          ? 'Live configuration changed outside the revisioned configuration service.'
          : 'The active config file changed after startup; explicit reconciliation is required.',
      };
    }
  }

  private verifyManagedFileUnchanged(): void {
    this.refreshManagedFileStatus();
    if (this.status.resolution_required) {
      const error = new Error(this.status.reason ?? 'Active configuration changed after it was inspected.');
      (error as Error & { code?: string }).code = 'CONFIG_HASH_CONFLICT';
      throw error;
    }
  }

  private assertTargetConverged(target: EngagementConfig): void {
    const expectedHash = target.config_hash ?? computeConfigHash(target);
    const runtime = this.host.getRuntimeConfig();
    if (
      runtime.config_revision !== target.config_revision
      || runtime.config_hash !== expectedHash
      || computeConfigHash(runtime) !== expectedHash
    ) {
      const error = new Error('Live configuration did not converge to the durable write target.');
      (error as Error & { code?: string }).code = 'CONFIG_WRITE_INCOMPLETE';
      throw error;
    }
    if (!this.configPath) return;
    const file = this.observeFile();
    if (
      !file.valid
      || !file.config
      || file.semantic_hash !== expectedHash
      || file.config.config_revision !== target.config_revision
      || file.config.config_hash !== expectedHash
    ) {
      const error = new Error('Active config file did not converge to the durable write target.');
      (error as Error & { code?: string }).code = 'CONFIG_WRITE_INCOMPLETE';
      throw error;
    }
  }
}
