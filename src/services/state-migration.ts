// ============================================================
// Overwatch — State V0 → V1 migration inspection and backup
// ============================================================

import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'fs';
import { createHash, randomUUID } from 'crypto';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'path';
import {
  CURRENT_JOURNAL_VERSION,
  CURRENT_STATE_VERSION,
  LEGACY_JOURNAL_VERSION,
  LEGACY_STATE_VERSION,
  PersistedJournalVersionError,
  PersistedStateVersionError,
  detectJournalVersion,
  detectStateVersion,
  validatePersistedStateV1,
  type SupportedJournalVersion,
  type SupportedStateVersion,
} from './persisted-state.js';
import { MutationJournal } from './mutation-journal.js';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';
import { parseJsonBytes } from './durable-json.js';
import {
  configsSemanticallyEqual,
  computeConfigHash,
} from './engagement-config-service.js';
import { createOverwatchGraph } from './graphology-types.js';
import { engagementConfigSchema, type EngagementConfig } from '../types.js';
import {
  withStateMigrationWriteGuard,
} from './state-migration-lock.js';
export {
  acquireStateMigrationLease,
  assertStateMigrationWriteAllowed,
  stateMigrationLockDirectory,
  withStateMigrationWriteGuard,
  type StateMigrationLeaseRelease,
} from './state-migration-lock.js';

export type MigrationArtifactRole =
  | 'config'
  | 'state'
  | 'journal'
  | 'snapshot'
  | 'rollback_intent'
  | 'migration_intent'
  | 'config_intent'
  | 'config_recovery_artifact';

export interface MigrationArtifact {
  role: MigrationArtifactRole;
  path: string;
}

export interface MigrationBackupEntryV1 {
  role: MigrationArtifactRole;
  original_path: string;
  present: boolean;
  backup_path?: string;
  size_bytes?: number;
  sha256?: string;
  mode?: number;
}

export interface MigrationBackupManifestV1 {
  manifest_version: 1;
  created_at: string;
  source_state_version: SupportedStateVersion;
  target_state_version: typeof CURRENT_STATE_VERSION;
  source_journal_version: SupportedJournalVersion;
  target_journal_version: typeof CURRENT_JOURNAL_VERSION;
  state_file: string;
  config_file?: string;
  files: MigrationBackupEntryV1[];
}

export interface MigrationBackupResult {
  directory: string;
  manifest_path: string;
  manifest_sha256: string;
  manifest: MigrationBackupManifestV1;
}

export interface StateMigrationInspection {
  status: 'current' | 'migration_required' | 'blocked' | 'missing';
  state_file: string;
  config_file?: string;
  selected_base?: string;
  supported_state_version: typeof CURRENT_STATE_VERSION;
  supported_journal_version: typeof CURRENT_JOURNAL_VERSION;
  observed_state_version?: number;
  observed_journal_version?: number;
  migration_required: boolean;
  ready: boolean;
  config_semantics_match?: boolean;
  config_revision_seed_allowed?: boolean;
  source_files: Array<{
    role: MigrationArtifactRole;
    path: string;
    present: boolean;
    size_bytes?: number;
    sha256?: string;
  }>;
  blockers: string[];
  warnings: string[];
}

interface StateMigrationIntentV1 {
  version: 1;
  state_file: string;
  source_state_version: typeof LEGACY_STATE_VERSION;
  target_state_version: typeof CURRENT_STATE_VERSION;
  backup_manifest_path: string;
  backup_manifest_sha256: string;
  created_at: string;
  intent_checksum: string;
}

interface InspectedBase {
  path: string;
  source: 'state' | 'snapshot';
  rank: number;
  stateVersion: 0 | 1;
  journalVersion: SupportedJournalVersion;
  checkpoint: number;
  trustedCheckpoint: boolean;
  record: Record<string, unknown>;
  config: EngagementConfig;
}

const WAL_COMPACTION_AUTHORITY_SEMANTICS = 'full_state_sha256_json_v1';

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function isMissing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException).code === 'ENOENT';
}

function strictDirectoryNames(path: string): string[] {
  try {
    return readdirSync(path);
  } catch (error) {
    if (isMissing(error)) return [];
    throw error;
  }
}

function statOrMissing(path: string): ReturnType<typeof lstatSync> | undefined {
  try {
    return lstatSync(path);
  } catch (error) {
    if (isMissing(error)) return undefined;
    throw error;
  }
}

export function stateMigrationIntentPath(stateFilePath: string): string {
  return `${resolve(stateFilePath)}.migration-intent.json`;
}

export function hasStateMigrationIntent(stateFilePath: string): boolean {
  return statOrMissing(stateMigrationIntentPath(stateFilePath)) !== undefined;
}

export function listStateSnapshotPaths(stateFilePath: string): string[] {
  const absoluteStatePath = resolve(stateFilePath);
  const directory = dirname(absoluteStatePath);
  const base = basename(absoluteStatePath, '.json');
  const root = strictDirectoryNames(directory)
    .filter(name => name.startsWith(`${base}.snap-`) && name.endsWith('.json'))
    .map(name => resolve(directory, name));
  const nestedDirectory = join(directory, '.snapshots');
  const nested = strictDirectoryNames(nestedDirectory)
    .filter(name => name.startsWith(`${base}.snap-`) && name.endsWith('.json'))
    .map(name => resolve(nestedDirectory, name));
  return [...root, ...nested].sort();
}

function listConfigRecoveryArtifacts(configFilePath: string): string[] {
  const directory = dirname(configFilePath);
  const configName = basename(configFilePath);
  const intentName = `${configName}.write-intent.json`;
  const prefixes = [
    `${configName}.overwatch-cas-`,
    `${configName}.overwatch-remove-`,
    `${intentName}.overwatch-cas-`,
    `${intentName}.overwatch-remove-`,
    `${intentName}.conflict-`,
  ];
  return strictDirectoryNames(directory)
    .filter(candidate => prefixes.some(prefix => candidate.startsWith(prefix)))
    .map(candidate => resolve(directory, candidate))
    .sort();
}

export function inventoryStateMigrationArtifacts(
  stateFilePath: string,
  configFilePath?: string,
  snapshotPaths: string[] = listStateSnapshotPaths(stateFilePath),
): MigrationArtifact[] {
  const absoluteStatePath = resolve(stateFilePath);
  const absoluteConfigPath = configFilePath ? resolve(configFilePath) : undefined;
  const artifacts: MigrationArtifact[] = [];
  if (absoluteConfigPath) artifacts.push({ role: 'config', path: absoluteConfigPath });
  artifacts.push(
    { role: 'state', path: absoluteStatePath },
    { role: 'journal', path: resolve(MutationJournal.pathForState(absoluteStatePath)) },
    { role: 'rollback_intent', path: resolve(`${absoluteStatePath}.rollback-intent.json`) },
    { role: 'migration_intent', path: stateMigrationIntentPath(absoluteStatePath) },
  );
  for (const path of snapshotPaths) {
    artifacts.push({ role: 'snapshot', path: resolve(path) });
  }
  if (absoluteConfigPath) {
    artifacts.push({
      role: 'config_intent',
      path: resolve(`${absoluteConfigPath}.write-intent.json`),
    });
    for (const path of listConfigRecoveryArtifacts(absoluteConfigPath)) {
      artifacts.push({ role: 'config_recovery_artifact', path });
    }
  }
  const seen = new Set<string>();
  return artifacts.filter(artifact => {
    const key = `${artifact.role}:${artifact.path}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function readPinnedRegularFile(
  path: string,
): { bytes: Buffer; mode: number } | undefined {
  let fd: number | undefined;
  try {
    const noFollow = typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0;
    fd = openSync(path, constants.O_RDONLY | noFollow);
    const before = fstatSync(fd);
    if (!before.isFile()) {
      throw new Error(`migration source is not a regular file: ${path}`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    if (
      before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || bytes.length !== after.size
    ) {
      throw new Error(`migration source changed while it was being read: ${path}`);
    }
    return { bytes, mode: before.mode };
  } catch (error) {
    if (isMissing(error)) return undefined;
    throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function readArtifactEntry(
  artifact: MigrationArtifact,
): MigrationBackupEntryV1 & { bytes?: Buffer } {
  const pinned = readPinnedRegularFile(artifact.path);
  if (!pinned) {
    return {
      role: artifact.role,
      original_path: artifact.path,
      present: false,
    };
  }
  return {
    role: artifact.role,
    original_path: artifact.path,
    present: true,
    size_bytes: pinned.bytes.length,
    sha256: sha256(pinned.bytes),
    mode: pinned.mode,
    bytes: pinned.bytes,
  };
}

function durableExclusiveWrite(path: string, bytes: Uint8Array): void {
  let fd: number | undefined;
  try {
    fd = openSync(path, 'wx', 0o600);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  fsyncDirectory(dirname(path));
}

function durableAtomicWrite(path: string, bytes: Uint8Array): void {
  const directory = dirname(path);
  mkdirDurable(directory);
  const temporaryPath = `${path}.tmp-${process.pid}-${randomUUID()}`;
  let fd: number | undefined;
  try {
    fd = openSync(temporaryPath, 'wx', 0o600);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temporaryPath, path);
    fsyncDirectory(directory);
  } catch (error) {
    try { unlinkSync(temporaryPath); } catch { /* preserve original failure */ }
    throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function safeBackupName(index: number, entry: MigrationBackupEntryV1): string {
  const sourceName = basename(entry.original_path).replace(/[^A-Za-z0-9._-]/g, '_');
  return `${String(index).padStart(4, '0')}-${entry.role}-${sourceName}`;
}

function assertSourceStillMatches(entry: MigrationBackupEntryV1): void {
  const current = readPinnedRegularFile(entry.original_path);
  if (!entry.present) {
    if (current) {
      throw new Error(`migration source appeared during backup: ${entry.original_path}`);
    }
    return;
  }
  if (!current) {
    throw new Error(`migration source disappeared during backup: ${entry.original_path}`);
  }
  if (
    current.bytes.length !== entry.size_bytes
    || sha256(current.bytes) !== entry.sha256
  ) {
    throw new Error(`migration source changed during backup: ${entry.original_path}`);
  }
}

function resolveBackupEntryPath(
  directory: string,
  backupPath: string,
): string {
  if (isAbsolute(backupPath)) {
    throw new Error('migration backup entry path must be relative');
  }
  const filesDirectory = resolve(directory, 'files');
  const candidate = resolve(directory, backupPath);
  const rel = relative(filesDirectory, candidate);
  if (!rel || isAbsolute(rel) || rel === '..' || rel.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
    throw new Error(`migration backup entry escapes files/: ${backupPath}`);
  }
  return candidate;
}

export function verifyStateMigrationBackup(
  manifestPath: string,
): MigrationBackupResult {
  const absoluteManifestPath = resolve(manifestPath);
  const directory = dirname(absoluteManifestPath);
  const manifestStat = lstatSync(absoluteManifestPath);
  if (!manifestStat.isFile() || manifestStat.isSymbolicLink()) {
    throw new Error('migration backup manifest must be a regular file');
  }
  const manifestBytes = readFileSync(absoluteManifestPath);
  const manifestSha256 = sha256(manifestBytes);
  const expected = readFileSync(join(directory, 'manifest.sha256'), 'utf8').trim();
  if (expected !== manifestSha256) {
    throw new Error('migration backup manifest checksum does not match');
  }
  const manifest = parseJsonBytes(manifestBytes) as MigrationBackupManifestV1;
  if (
    manifest.manifest_version !== 1
    || (
      manifest.source_state_version !== LEGACY_STATE_VERSION
      && manifest.source_state_version !== CURRENT_STATE_VERSION
    )
    || manifest.target_state_version !== CURRENT_STATE_VERSION
    || (
      manifest.source_journal_version !== LEGACY_JOURNAL_VERSION
      && manifest.source_journal_version !== CURRENT_JOURNAL_VERSION
    )
    || manifest.target_journal_version !== CURRENT_JOURNAL_VERSION
    || typeof manifest.state_file !== 'string'
    || !Array.isArray(manifest.files)
  ) {
    throw new Error('migration backup manifest is invalid');
  }
  const seenSources = new Set<string>();
  const seenBackups = new Set<string>();
  for (const entry of manifest.files) {
    if (
      !entry
      || typeof entry !== 'object'
      || typeof entry.original_path !== 'string'
      || typeof entry.role !== 'string'
      || typeof entry.present !== 'boolean'
    ) {
      throw new Error('migration backup entry is invalid');
    }
    const sourceKey = `${entry.role}:${entry.original_path}`;
    if (seenSources.has(sourceKey)) {
      throw new Error(`migration backup contains duplicate source: ${entry.original_path}`);
    }
    seenSources.add(sourceKey);
    if (!entry.present) continue;
    if (!entry.backup_path || !entry.sha256 || entry.size_bytes === undefined) {
      throw new Error(`migration backup entry is incomplete: ${entry.original_path}`);
    }
    const backupFile = resolveBackupEntryPath(directory, entry.backup_path);
    if (seenBackups.has(backupFile)) {
      throw new Error(`migration backup reuses a file path: ${entry.backup_path}`);
    }
    seenBackups.add(backupFile);
    const backupStat = lstatSync(backupFile);
    if (!backupStat.isFile() || backupStat.isSymbolicLink()) {
      throw new Error(`migration backup entry is not a regular file: ${entry.original_path}`);
    }
    const bytes = readFileSync(backupFile);
    if (bytes.length !== entry.size_bytes || sha256(bytes) !== entry.sha256) {
      throw new Error(`migration backup checksum mismatch: ${entry.original_path}`);
    }
  }
  const complete = readFileSync(join(directory, 'complete'), 'utf8').trim();
  if (complete !== manifestSha256) {
    throw new Error('migration backup completion marker is invalid');
  }
  return {
    directory,
    manifest_path: absoluteManifestPath,
    manifest_sha256: manifestSha256,
    manifest,
  };
}

export function createStateMigrationBackup(input: {
  stateFilePath: string;
  configFilePath?: string;
  snapshotPaths?: string[];
  now?: Date;
  id?: string;
  sourceStateVersion?: SupportedStateVersion;
  sourceJournalVersion?: SupportedJournalVersion;
}): MigrationBackupResult {
  const stateFilePath = resolve(input.stateFilePath);
  const configFilePath = input.configFilePath ? resolve(input.configFilePath) : undefined;
  const snapshotPaths = input.snapshotPaths ?? listStateSnapshotPaths(stateFilePath);
  const initialSnapshotPaths = [...snapshotPaths].map(path => resolve(path)).sort();
  const artifacts = inventoryStateMigrationArtifacts(
    stateFilePath,
    configFilePath,
    initialSnapshotPaths,
  );

  const createdAt = (input.now ?? new Date()).toISOString();
  const sourceStateVersion = input.sourceStateVersion ?? LEGACY_STATE_VERSION;
  const sourceJournalVersion = input.sourceJournalVersion ?? LEGACY_JOURNAL_VERSION;
  const stamp = createdAt.replace(/[:.]/g, '-');
  const root = join(dirname(stateFilePath), '.migration-backups');
  mkdirDurable(root);
  const finalDirectory = join(
    root,
    `${basename(stateFilePath, '.json')}-${stamp}-v${sourceStateVersion}-j${sourceJournalVersion}-to-v${CURRENT_STATE_VERSION}-j${CURRENT_JOURNAL_VERSION}-${input.id ?? randomUUID()}`,
  );
  const stagingDirectory = `${finalDirectory}.staging`;
  mkdirSync(stagingDirectory);
  fsyncDirectory(root);
  const filesDirectory = join(stagingDirectory, 'files');
  mkdirSync(filesDirectory);
  fsyncDirectory(stagingDirectory);

  const files: MigrationBackupEntryV1[] = [];
  let hasRecoveryBase = false;
  let hasMatchingBase = false;
  for (const [index, artifact] of artifacts.entries()) {
    const captured = readArtifactEntry(artifact);
    const { bytes, ...manifestEntry } = captured;
    if (!captured.present || !bytes) {
      files.push(manifestEntry);
      continue;
    }
    if (captured.role === 'state' || captured.role === 'snapshot') {
      hasRecoveryBase = true;
      try {
        const parsed = parseJsonBytes(bytes);
        const stateVersion = detectStateVersion(parsed);
        const journalVersion = detectJournalVersion(parsed, stateVersion);
        if (
          stateVersion === sourceStateVersion
          && journalVersion === sourceJournalVersion
        ) {
          hasMatchingBase = true;
        }
      } catch (error) {
        if (
          error instanceof PersistedStateVersionError
          && error.kind === 'unsupported'
        ) {
          throw error;
        }
        // Corrupt non-selected bases are still important rollback evidence.
      }
    }
    const backupPath = join('files', safeBackupName(index, captured));
    durableExclusiveWrite(join(stagingDirectory, backupPath), bytes);
    const copied = readFileSync(join(stagingDirectory, backupPath));
    if (copied.length !== captured.size_bytes || sha256(copied) !== captured.sha256) {
      throw new Error(`migration backup verification failed: ${captured.original_path}`);
    }
    files.push({ ...manifestEntry, backup_path: backupPath });
  }
  if (!hasRecoveryBase) {
    throw new Error('migration backup requires a primary state or retained snapshot');
  }
  if (!hasMatchingBase) {
    throw new Error(
      `migration backup requires a validated V${sourceStateVersion}/journal-v${sourceJournalVersion} recovery base`,
    );
  }

  for (const entry of files) assertSourceStillMatches(entry);
  const currentSnapshotPaths = listStateSnapshotPaths(stateFilePath);
  if (JSON.stringify(currentSnapshotPaths) !== JSON.stringify(initialSnapshotPaths)) {
    throw new Error('snapshot inventory changed during migration backup');
  }

  const manifest: MigrationBackupManifestV1 = {
    manifest_version: 1,
    created_at: createdAt,
    source_state_version: sourceStateVersion,
    target_state_version: CURRENT_STATE_VERSION,
    source_journal_version: sourceJournalVersion,
    target_journal_version: CURRENT_JOURNAL_VERSION,
    state_file: stateFilePath,
    ...(configFilePath ? { config_file: configFilePath } : {}),
    files,
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2));
  const manifestSha256 = sha256(manifestBytes);
  durableExclusiveWrite(join(stagingDirectory, 'manifest.json'), manifestBytes);
  durableExclusiveWrite(
    join(stagingDirectory, 'manifest.sha256'),
    Buffer.from(`${manifestSha256}\n`),
  );
  durableExclusiveWrite(join(stagingDirectory, 'complete'), Buffer.from(`${manifestSha256}\n`));
  fsyncDirectory(filesDirectory);
  fsyncDirectory(stagingDirectory);
  renameSync(stagingDirectory, finalDirectory);
  fsyncDirectory(root);

  return verifyStateMigrationBackup(join(finalDirectory, 'manifest.json'));
}

/** Create a checksummed rollback bundle before a current V1 state begins
 * emitting journal-v2 transactions. The state-file replacement itself is
 * atomic, so this format-only upgrade does not require the V0 migration intent
 * protocol. */
export function createJournalUpgradeBackup(input: {
  stateFilePath: string;
  configFilePath?: string;
  snapshotPaths?: string[];
  now?: Date;
  id?: string;
}): MigrationBackupResult {
  return createStateMigrationBackup({
    ...input,
    sourceStateVersion: CURRENT_STATE_VERSION,
    sourceJournalVersion: LEGACY_JOURNAL_VERSION,
  });
}

function backupMatchesCurrentSources(
  backup: MigrationBackupResult,
  stateFilePath: string,
  configFilePath?: string,
): boolean {
  const snapshots = listStateSnapshotPaths(stateFilePath);
  const artifacts = inventoryStateMigrationArtifacts(
    stateFilePath,
    configFilePath,
    snapshots,
  ).filter(artifact => artifact.role !== 'migration_intent');
  const manifestEntries = backup.manifest.files
    .filter(entry => entry.role !== 'migration_intent');
  if (artifacts.length !== manifestEntries.length) return false;
  const byKey = new Map(
    manifestEntries.map(entry => [`${entry.role}:${resolve(entry.original_path)}`, entry]),
  );
  for (const artifact of artifacts) {
    const entry = byKey.get(`${artifact.role}:${resolve(artifact.path)}`);
    if (!entry) return false;
    try {
      assertSourceStillMatches(entry);
    } catch {
      return false;
    }
  }
  return true;
}

export function assertStateMigrationSourcesUnchanged(input: {
  backup: MigrationBackupResult;
  stateFilePath: string;
  configFilePath?: string;
}): void {
  if (!backupMatchesCurrentSources(
    input.backup,
    resolve(input.stateFilePath),
    input.configFilePath ? resolve(input.configFilePath) : undefined,
  )) {
    throw new Error(
      'migration source files or snapshot inventory changed after the checksummed backup was created',
    );
  }
}

export function findReusableStateMigrationBackup(input: {
  stateFilePath: string;
  configFilePath?: string;
}): MigrationBackupResult | undefined {
  const stateFilePath = resolve(input.stateFilePath);
  const root = join(dirname(stateFilePath), '.migration-backups');
  const names = strictDirectoryNames(root)
    .filter(name => !name.endsWith('.staging'))
    .sort()
    .reverse();
  for (const name of names) {
    const manifestPath = join(root, name, 'manifest.json');
    try {
      const backup = verifyStateMigrationBackup(manifestPath);
      if (
        resolve(backup.manifest.state_file) === stateFilePath
        && backupMatchesCurrentSources(backup, stateFilePath, input.configFilePath)
      ) {
        return backup;
      }
    } catch {
      // A corrupt/incomplete backup is never reused. It remains for audit.
    }
  }
  return undefined;
}

function stateMigrationIntentChecksum(
  intent: Omit<StateMigrationIntentV1, 'intent_checksum'>,
): string {
  return sha256(Buffer.from(JSON.stringify(intent)));
}

function readStateMigrationIntent(
  stateFilePath: string,
): StateMigrationIntentV1 | undefined {
  const path = stateMigrationIntentPath(stateFilePath);
  const stat = statOrMissing(path);
  if (!stat) return undefined;
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`state migration intent must be a regular file: ${path}`);
  }
  const record = parseJsonBytes(readFileSync(path)) as Partial<StateMigrationIntentV1>;
  if (
    record.version !== 1
    || typeof record.state_file !== 'string'
    || record.source_state_version !== LEGACY_STATE_VERSION
    || record.target_state_version !== CURRENT_STATE_VERSION
    || typeof record.backup_manifest_path !== 'string'
    || typeof record.backup_manifest_sha256 !== 'string'
    || typeof record.created_at !== 'string'
    || typeof record.intent_checksum !== 'string'
  ) {
    throw new Error('state migration intent is invalid');
  }
  const validated = record as StateMigrationIntentV1;
  const { intent_checksum: _checksum, ...unsigned } = validated;
  if (validated.intent_checksum !== stateMigrationIntentChecksum(unsigned)) {
    throw new Error('state migration intent checksum is invalid');
  }
  if (resolve(validated.state_file) !== resolve(stateFilePath)) {
    throw new Error('state migration intent references a different state file');
  }
  return validated;
}

function writeStateMigrationIntent(
  stateFilePath: string,
  backup: MigrationBackupResult,
): void {
  const unsigned: Omit<StateMigrationIntentV1, 'intent_checksum'> = {
    version: 1,
    state_file: resolve(stateFilePath),
    source_state_version: LEGACY_STATE_VERSION,
    target_state_version: CURRENT_STATE_VERSION,
    backup_manifest_path: backup.manifest_path,
    backup_manifest_sha256: backup.manifest_sha256,
    created_at: new Date().toISOString(),
  };
  const intent: StateMigrationIntentV1 = {
    ...unsigned,
    intent_checksum: stateMigrationIntentChecksum(unsigned),
  };
  durableAtomicWrite(
    stateMigrationIntentPath(stateFilePath),
    Buffer.from(`${JSON.stringify(intent, null, 2)}\n`),
  );
}

export function prepareStateMigrationBackup(input: {
  stateFilePath: string;
  configFilePath?: string;
}): MigrationBackupResult {
  const stateFilePath = resolve(input.stateFilePath);
  const existingIntent = readStateMigrationIntent(stateFilePath);
  if (existingIntent) {
    const backup = verifyStateMigrationBackup(existingIntent.backup_manifest_path);
    if (backup.manifest_sha256 !== existingIntent.backup_manifest_sha256) {
      throw new Error('state migration intent backup checksum does not match');
    }
    if (resolve(backup.manifest.state_file) !== stateFilePath) {
      throw new Error('state migration intent backup references a different state file');
    }
    const requestedConfigPath = input.configFilePath
      ? resolve(input.configFilePath)
      : undefined;
    const backedConfigPath = backup.manifest.config_file
      ? resolve(backup.manifest.config_file)
      : undefined;
    if (requestedConfigPath !== backedConfigPath) {
      throw new Error('state migration intent backup references a different active config path');
    }
    if (!backupMatchesCurrentSources(backup, stateFilePath, requestedConfigPath)) {
      throw new Error(
        'state migration sources changed after the rollback backup was created; refusing to publish V1 from an incomplete backup',
      );
    }
    return backup;
  }
  const backup = findReusableStateMigrationBackup(input)
    ?? createStateMigrationBackup(input);
  return backup;
}

/** Publish the crash-resume authority only after legacy WAL replay completes. */
export function activateStateMigration(
  stateFilePath: string,
  backup: MigrationBackupResult,
  ownerToken?: string,
): void {
  withStateMigrationWriteGuard(stateFilePath, ownerToken, () => {
    const existing = readStateMigrationIntent(stateFilePath);
    if (existing) {
      if (
        existing.backup_manifest_path !== backup.manifest_path
        || existing.backup_manifest_sha256 !== backup.manifest_sha256
      ) {
        throw new Error('state migration intent references a different backup');
      }
      return;
    }
    writeStateMigrationIntent(stateFilePath, backup);
  });
}

export function completeStateMigration(
  stateFilePath: string,
  ownerToken?: string,
): MigrationBackupResult | undefined {
  return withStateMigrationWriteGuard(stateFilePath, ownerToken, () => {
    const intentPath = stateMigrationIntentPath(stateFilePath);
    const stat = statOrMissing(intentPath);
    if (!stat) return undefined;
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`state migration intent must be a regular file: ${intentPath}`);
    }
    // Validate the intent and its rollback authority before retiring it.
    const intent = readStateMigrationIntent(stateFilePath)!;
    const backup = verifyStateMigrationBackup(intent.backup_manifest_path);
    if (backup.manifest_sha256 !== intent.backup_manifest_sha256) {
      throw new Error('state migration intent backup checksum does not match');
    }
    unlinkSync(intentPath);
    fsyncDirectory(dirname(intentPath));
    return backup;
  });
}

function inspectSourceFiles(
  stateFilePath: string,
  configFilePath?: string,
): StateMigrationInspection['source_files'] {
  return inventoryStateMigrationArtifacts(stateFilePath, configFilePath).map(artifact => {
    const pinned = readPinnedRegularFile(artifact.path);
    return pinned
      ? {
          role: artifact.role,
          path: artifact.path,
          present: true,
          size_bytes: pinned.bytes.length,
          sha256: sha256(pinned.bytes),
        }
      : { role: artifact.role, path: artifact.path, present: false };
  });
}

function parseConfig(value: unknown, label: string): EngagementConfig {
  const parsed = engagementConfigSchema.safeParse(value);
  if (!parsed.success) {
    throw new Error(
      `${label} configuration is invalid: ${parsed.error.issues.map(issue => issue.message).join('; ')}`,
    );
  }
  return parsed.data;
}

function validateCompactionAuthority(record: Record<string, unknown>): void {
  const raw = record.walCompactionAuthority;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return;
  const authority = raw as Record<string, unknown>;
  if (authority.semantics !== WAL_COMPACTION_AUTHORITY_SEMANTICS) return;
  if (typeof authority.payload_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(authority.payload_sha256)) {
    throw new Error('persisted WAL compaction authority is invalid');
  }
  const payload = { ...record };
  delete payload.walCompactionAuthority;
  const actual = sha256(Buffer.from(JSON.stringify(payload)));
  if (actual !== authority.payload_sha256) {
    throw new Error('persisted WAL compaction authority checksum does not match the state payload');
  }
}

function inspectBase(
  path: string,
  source: 'state' | 'snapshot',
  rank: number,
): InspectedBase {
  const record = parseJsonBytes(readFileSync(path)) as Record<string, unknown>;
  const stateVersion = detectStateVersion(record);
  const journalVersion = detectJournalVersion(record, stateVersion);
  validateCompactionAuthority(record);
  if (stateVersion === CURRENT_STATE_VERSION) validatePersistedStateV1(record);
  const config = parseConfig(record.config, 'state');
  if (!record.graph || typeof record.graph !== 'object' || Array.isArray(record.graph)) {
    throw new Error('persisted state is missing graph');
  }
  const scratch = createOverwatchGraph();
  scratch.import(record.graph as Parameters<typeof scratch.import>[0]);
  const checkpoint = record.journalSnapshotSeq === undefined
    ? 0
    : Number.isSafeInteger(record.journalSnapshotSeq) && (record.journalSnapshotSeq as number) >= 0
      ? record.journalSnapshotSeq as number
      : (() => { throw new Error('persisted journalSnapshotSeq must be a non-negative safe integer'); })();
  return {
    path,
    source,
    rank,
    stateVersion,
    journalVersion,
    checkpoint,
    trustedCheckpoint: journalVersion === LEGACY_JOURNAL_VERSION
      ? record.journalCheckpointSemantics === 'contiguous_applied_v1'
      : record.journalCheckpointSemantics === 'contiguous_committed_transactions_v2',
    record,
    config,
  };
}

/**
 * Side-effect-free local inspection used by `overwatch state migrate --check`.
 * It never constructs GraphEngine and never writes, renames, touches, or
 * checkpoints an engagement file. The live migration path still performs the
 * authoritative semantic WAL replay before committing V1.
 */
export function inspectStateMigration(input: {
  stateFilePath: string;
  configFilePath?: string;
}): StateMigrationInspection {
  const stateFilePath = resolve(input.stateFilePath);
  const configFilePath = input.configFilePath ? resolve(input.configFilePath) : undefined;
  let sourceFiles: StateMigrationInspection['source_files'] = [];
  const blockers: string[] = [];
  const warnings: string[] = [];
  try {
    sourceFiles = inspectSourceFiles(stateFilePath, configFilePath);
  } catch (error) {
    blockers.push(`migration artifact inventory failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  const base = {
    state_file: stateFilePath,
    ...(configFilePath ? { config_file: configFilePath } : {}),
    supported_state_version: CURRENT_STATE_VERSION,
    supported_journal_version: CURRENT_JOURNAL_VERSION,
    source_files: sourceFiles,
  };

  let snapshotPaths: string[] = [];
  try {
    snapshotPaths = listStateSnapshotPaths(stateFilePath);
  } catch (error) {
    blockers.push(`snapshot inventory failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  const candidates = [
    ...(statOrMissing(stateFilePath)
      ? [{ path: stateFilePath, source: 'state' as const, rank: 0 }]
      : []),
    ...snapshotPaths.map((path, index) => ({
      path,
      source: 'snapshot' as const,
      rank: index + 1,
    })),
  ];
  if (candidates.length === 0) {
    return {
      ...base,
      status: blockers.length > 0 ? 'blocked' : 'missing',
      migration_required: false,
      ready: false,
      blockers: blockers.length > 0
        ? blockers
        : [`no primary state or retained snapshot exists for ${stateFilePath}`],
      warnings,
    };
  }

  const valid: InspectedBase[] = [];
  const invalidVersioned: Array<{
    path: string;
    source: 'state' | 'snapshot';
    rank: number;
    checkpoint?: number;
    error: string;
  }> = [];
  let observedStateVersion: number | undefined;
  let observedJournalVersion: number | undefined;
  let invalidVersionedBlocked = false;
  for (const candidate of candidates) {
    try {
      const inspected = inspectBase(candidate.path, candidate.source, candidate.rank);
      valid.push(inspected);
    } catch (error) {
      if (
        error instanceof PersistedStateVersionError
        && error.kind === 'unsupported'
        && typeof error.observedVersion === 'number'
      ) {
        observedStateVersion = error.observedVersion;
        blockers.push(error.message);
        break;
      }
      if (
        error instanceof PersistedJournalVersionError
        && error.kind === 'unsupported'
        && typeof error.observedVersion === 'number'
      ) {
        observedJournalVersion = error.observedVersion;
        blockers.push(error.message);
        break;
      }
      try {
        const rejected = parseJsonBytes(readFileSync(candidate.path)) as Record<string, unknown>;
        const hasExplicitStateDiscriminator = Object.prototype.hasOwnProperty.call(
          rejected,
          'state_version',
        );
        const hasExplicitJournalDiscriminator = Object.prototype.hasOwnProperty.call(
          rejected,
          'journal_version',
        );
        if (
          rejected.state_version === CURRENT_STATE_VERSION
          || (
            (error instanceof PersistedStateVersionError
              || error instanceof PersistedJournalVersionError)
            && error.kind === 'invalid'
            && (hasExplicitStateDiscriminator || hasExplicitJournalDiscriminator)
          )
        ) {
          invalidVersioned.push({
            ...candidate,
            ...(Number.isSafeInteger(rejected.journalSnapshotSeq)
              && (rejected.journalSnapshotSeq as number) >= 0
              ? { checkpoint: rejected.journalSnapshotSeq as number }
              : {}),
            error: error instanceof Error ? error.message : String(error),
          });
        }
      } catch {
        // Unparseable bytes are ordinary corrupt-base candidates. Live recovery
        // may still use a valid retained snapshot for those.
      }
      warnings.push(
        `${candidate.source} base rejected (${candidate.path}): ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  valid.sort((left, right) =>
    right.checkpoint - left.checkpoint || left.rank - right.rank,
  );
  const bestValid = valid[0];
  const blockingInvalid = invalidVersioned
    .filter(candidate => !bestValid
      || candidate.rank < bestValid.rank
      || (
        candidate.checkpoint !== undefined
        && candidate.checkpoint > bestValid.checkpoint
      ))
    .sort((left, right) =>
      (right.checkpoint ?? -1) - (left.checkpoint ?? -1)
      || left.rank - right.rank,
    );
  if (blockingInvalid.length > 0) {
    invalidVersionedBlocked = true;
    const first = blockingInvalid[0];
    try {
      const rejected = parseJsonBytes(readFileSync(first.path)) as Record<string, unknown>;
      if (typeof rejected.state_version === 'number') {
        observedStateVersion = rejected.state_version;
      }
      if (typeof rejected.journal_version === 'number') {
        observedJournalVersion = rejected.journal_version;
      }
    } catch {
      // The blocker text remains authoritative when an observed numeric
      // discriminator is unavailable.
    }
    blockers.push(
      `persisted versioned recovery head is invalid and cannot be replaced automatically (${first.path}): ${first.error}`,
    );
  }
  if (blockers.length > 0) {
    return {
      ...base,
      status: 'blocked',
      ...(observedStateVersion !== undefined ? { observed_state_version: observedStateVersion } : {}),
      ...(observedJournalVersion !== undefined ? { observed_journal_version: observedJournalVersion } : {}),
      migration_required:
        !invalidVersionedBlocked
        && (
          observedStateVersion === LEGACY_STATE_VERSION
          || observedJournalVersion === LEGACY_JOURNAL_VERSION
        ),
      ready: false,
      blockers,
      warnings,
    };
  }
  const selected = valid[0];
  if (!selected) {
    return {
      ...base,
      status: 'blocked',
      migration_required: false,
      ready: false,
      blockers: ['no valid persisted recovery base was found'],
      warnings,
    };
  }

  observedStateVersion = selected.stateVersion;
  observedJournalVersion = selected.journalVersion;
  const journalPath = MutationJournal.pathForState(stateFilePath);
  const journalStat = statOrMissing(journalPath);
  let journalHasNewerRecords = false;
  if (journalStat) {
    if (!journalStat.isFile() || journalStat.isSymbolicLink()) {
      blockers.push(`mutation journal is not a regular file: ${journalPath}`);
    } else {
      try {
        const journal = new MutationJournal(stateFilePath);
        const issue = journal.inspectReplayIntegrity(selected.checkpoint, {
          trustedContiguousCheckpoint: selected.trustedCheckpoint,
        });
        if (issue) {
          blockers.push(`WAL replay preflight failed at line ${issue.line}: ${issue.reason}`);
        }
        journalHasNewerRecords = journal.getHighestPhysicalSeq() > selected.checkpoint;
      } catch (error) {
        blockers.push(`WAL replay preflight failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }
  if (statOrMissing(`${stateFilePath}.rollback-intent.json`)) {
    blockers.push('a pending rollback must complete before state migration');
  }
  if (hasStateMigrationIntent(stateFilePath)) {
    try {
      const intent = readStateMigrationIntent(stateFilePath)!;
      const backup = verifyStateMigrationBackup(intent.backup_manifest_path);
      if (backup.manifest_sha256 !== intent.backup_manifest_sha256) {
        throw new Error('state migration intent backup checksum does not match');
      }
      const requestedConfigPath = configFilePath ? resolve(configFilePath) : undefined;
      const backedConfigPath = backup.manifest.config_file
        ? resolve(backup.manifest.config_file)
        : undefined;
      if (requestedConfigPath !== backedConfigPath) {
        throw new Error('state migration intent backup references a different active config path');
      }
      if (
        selected.stateVersion === LEGACY_STATE_VERSION
        && !backupMatchesCurrentSources(backup, stateFilePath, requestedConfigPath)
      ) {
        throw new Error('state migration sources changed after the rollback backup was created');
      }
      warnings.push(
        selected.stateVersion === CURRENT_STATE_VERSION
          ? 'a completed V1 migration intent will be retired on the next writable startup'
          : 'a verified V0 migration backup is already active',
      );
    } catch (error) {
      blockers.push(
        `state migration intent is not safely resumable: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  let configSemanticsMatch: boolean | undefined;
  let configRevisionSeedAllowed: boolean | undefined;
  if (configFilePath) {
    const configStat = statOrMissing(configFilePath);
    if (!configStat) {
      warnings.push('active config file is missing; it will be recorded as absent in the migration backup and recovered from durable state');
      configRevisionSeedAllowed = false;
    } else if (!configStat.isFile() || configStat.isSymbolicLink()) {
      blockers.push(`active config is not a regular file: ${configFilePath}`);
    } else {
      try {
        const fileConfig = parseConfig(parseJsonBytes(readFileSync(configFilePath)), 'file');
        configSemanticsMatch = configsSemanticallyEqual(fileConfig, selected.config);
        const fileHasMetadata = fileConfig.config_revision !== undefined;
        const stateHasMetadata = selected.config.config_revision !== undefined;
        configRevisionSeedAllowed = configSemanticsMatch
          && !fileHasMetadata
          && !stateHasMetadata
          && !journalHasNewerRecords;
        if (journalHasNewerRecords) {
          warnings.push('WAL records newer than the selected base make config-revision seeding provisional until semantic replay completes');
        } else if (!configSemanticsMatch) {
          warnings.push('file and durable-state configuration semantics differ; structural migration can proceed, but explicit config reconciliation remains required');
        } else if (fileHasMetadata !== stateHasMetadata) {
          warnings.push('only one configuration representation has revision metadata; revision 1 will not be seeded automatically');
        } else if (
          fileHasMetadata
          && (
            fileConfig.config_hash !== computeConfigHash(fileConfig)
            || selected.config.config_hash !== computeConfigHash(selected.config)
          )
        ) {
          warnings.push('declared configuration metadata is inconsistent; explicit config reconciliation remains required');
        }
      } catch (error) {
        blockers.push(error instanceof Error ? error.message : String(error));
      }
    }
  }

  const migrationRequired =
    selected.stateVersion === LEGACY_STATE_VERSION
    || selected.journalVersion === LEGACY_JOURNAL_VERSION;
  return {
    ...base,
    selected_base: selected.path,
    status: blockers.length > 0
      ? 'blocked'
      : migrationRequired ? 'migration_required' : 'current',
    observed_state_version: selected.stateVersion,
    observed_journal_version: selected.journalVersion,
    migration_required: migrationRequired,
    ready: blockers.length === 0,
    ...(configSemanticsMatch !== undefined ? { config_semantics_match: configSemanticsMatch } : {}),
    ...(configRevisionSeedAllowed !== undefined ? { config_revision_seed_allowed: configRevisionSeedAllowed } : {}),
    blockers,
    warnings,
  };
}
