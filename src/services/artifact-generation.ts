// ============================================================
// Crash-consistent publication for related operator-visible files.
// ============================================================

import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
} from 'fs';
import { createHash, randomUUID } from 'crypto';
import { isAbsolute, join, relative, resolve, sep } from 'path';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';
import {
  DurableArtifactPublicationError,
  removeArtifactDurable,
  writeArtifactAtomicDurable,
} from './durable-artifact.js';
import { withStateMigrationWriteGuard } from './state-migration-lock.js';
import { readProcessStartIdentity } from './process-identity.js';

export interface ArtifactGenerationFile {
  content: string | Buffer;
  media_type?: string;
}

export interface ArtifactGenerationManifest {
  manifest_version: 1;
  namespace: string;
  generation_id: string;
  created_at: string;
  files: Array<{
    path: string;
    size_bytes: number;
    sha256: string;
    media_type?: string;
  }>;
}

export interface ArtifactGenerationPublication {
  generation_id: string;
  generation_committed: boolean;
  pointer_visible: true;
  commit_durability: 'confirmed' | 'uncertain';
  generation_path: string;
  generation_manifest: string;
  manifest_sha256: string;
  pointer_path: string;
  legacy_mirror_complete: boolean;
  warning?: string;
}

export interface ArtifactGenerationRecoveryRegistration {
  root: string;
  namespace: string;
  legacy_names: string[];
}

const SAFE_NAMESPACE = /^[A-Za-z0-9_-]{1,64}$/;
const GENERATION_RETENTION = 5;
const STALE_GENERATION_STAGE_MS = 60 * 60 * 1000;
const currentStartIdentity = readProcessStartIdentity(process.pid);
const currentStartHash = createHash('sha256')
  .update(currentStartIdentity ?? `unverifiable-current-process-${process.pid}`)
  .digest('hex')
  .slice(0, 16);

function pidMayBeLive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

function cleanupGenerationDebris(generationRoot: string, currentGenerationId?: string): void {
  const completed: Array<{ name: string; mtimeMs: number }> = [];
  let removed = false;
  for (const name of readdirSync(generationRoot)) {
    const path = join(generationRoot, name);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isDirectory()) continue;
    const stage = /^\.tmp-(\d+)-([uv])([0-9a-f]{16})-[0-9a-f-]{36}$/i.exec(name);
    if (stage) {
      if (Date.now() - stat.mtimeMs < STALE_GENERATION_STAGE_MS) continue;
      const pid = Number(stage[1]);
      let live = pidMayBeLive(pid);
      if (live && stage[2] === 'v') {
        const observed = readProcessStartIdentity(pid);
        live = observed === undefined
          || createHash('sha256').update(observed).digest('hex').slice(0, 16) === stage[3];
      }
      if (!live) {
        rmSync(path, { recursive: true, force: false });
        removed = true;
      }
      continue;
    }
    if (/^[0-9a-f-]{36}$/i.test(name)) completed.push({ name, mtimeMs: stat.mtimeMs });
  }
  if (!currentGenerationId) {
    if (removed) fsyncDirectory(generationRoot);
    return;
  }
  const retained = new Set([
    currentGenerationId,
    ...completed
      .filter(entry => entry.name !== currentGenerationId)
      .sort((left, right) => right.mtimeMs - left.mtimeMs)
      .slice(0, Math.max(0, GENERATION_RETENTION - 1))
      .map(entry => entry.name),
  ]);
  for (const entry of completed) {
    if (!retained.has(entry.name)) {
      rmSync(join(generationRoot, entry.name), { recursive: true, force: false });
      removed = true;
    }
  }
  if (removed) fsyncDirectory(generationRoot);
}

function safeLogicalPath(path: string): string {
  if (!path || isAbsolute(path) || path.includes('\0')) {
    throw new Error(`Invalid artifact generation path: ${path}`);
  }
  const normalized = path.split(/[\\/]+/).filter(Boolean).join('/');
  if (!normalized || normalized.split('/').some(segment => segment === '..' || segment === '.')) {
    throw new Error(`Invalid artifact generation path: ${path}`);
  }
  return normalized;
}

/** Normalize the small durable registration used to rediscover a committed
 * generation after process restart. The generation pointer and manifest still
 * remain the authority; this record only tells startup where to look. */
export function normalizeArtifactGenerationRecoveryRegistration(options: {
  root: string;
  namespace: string;
  legacy_names?: readonly string[];
}): ArtifactGenerationRecoveryRegistration {
  if (!SAFE_NAMESPACE.test(options.namespace)) {
    throw new Error(`Invalid artifact generation namespace: ${options.namespace}`);
  }
  return {
    root: resolve(options.root),
    namespace: options.namespace,
    legacy_names: [...new Set((options.legacy_names ?? []).map(safeLogicalPath))].sort(),
  };
}

function contentBuffer(content: string | Buffer): Buffer {
  return Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
}

function refreshLegacyMirrors(
  root: string,
  generationPath: string,
  logicalPaths: Iterable<string>,
  legacyNames: string[],
): void {
  const wanted = new Set(logicalPaths);
  for (const logicalPath of legacyNames) {
    const safePath = safeLogicalPath(logicalPath);
    if (!wanted.has(safePath)) removeArtifactDurable(join(root, ...safePath.split('/')));
  }
  for (const logicalPath of wanted) {
    const source = join(generationPath, ...logicalPath.split('/'));
    writeArtifactAtomicDurable(join(root, ...logicalPath.split('/')), readFileSync(source));
  }
}

/**
 * Publish an immutable, checksummed file set. The small pointer file is the
 * sole commit boundary: readers see the previous complete generation or the
 * next complete generation, never a partially replaced set.
 *
 * Fixed-name legacy mirrors are refreshed only after the pointer commits.
 * They remain compatibility conveniences, not the generation authority.
 */
export function publishArtifactGenerationDurable(options: {
  root: string;
  namespace: string;
  files: Record<string, ArtifactGenerationFile>;
  /** Logical names whose fixed-name mirrors should be removed when absent. */
  legacy_names?: string[];
}): ArtifactGenerationPublication {
  const registration = normalizeArtifactGenerationRecoveryRegistration(options);
  const root = registration.root;
  mkdirDurable(root);
  const generationRoot = join(root, '.overwatch-generations', options.namespace);
  mkdirDurable(generationRoot);
  const pointerPath = join(root, `.overwatch-${options.namespace}-current.json`);

  // Finish any mirror refresh interrupted after the previous pointer commit.
  // The generation remains authoritative, so repair is deterministic.
  if (existsSync(pointerPath)) {
    repairArtifactGenerationMirrors(root, options.namespace, registration.legacy_names);
  }

  return withStateMigrationWriteGuard(pointerPath, undefined, () => {
    cleanupGenerationDebris(generationRoot);
    const generationId = randomUUID();
    const stagingPath = join(
      generationRoot,
      `.tmp-${process.pid}-${currentStartIdentity ? 'v' : 'u'}${currentStartHash}-${generationId}`,
    );
    const generationPath = join(generationRoot, generationId);
    mkdirSync(stagingPath, { recursive: false, mode: 0o700 });
    fsyncDirectory(generationRoot);
    let generationRenamed = false;
    try {
      const normalizedFiles = new Map<string, ArtifactGenerationFile>();
      for (const [rawPath, value] of Object.entries(options.files)) {
        const logicalPath = safeLogicalPath(rawPath);
        if (normalizedFiles.has(logicalPath)) throw new Error(`Duplicate artifact generation path: ${logicalPath}`);
        normalizedFiles.set(logicalPath, value);
      }
      if (normalizedFiles.size === 0) throw new Error('Artifact generation requires at least one file.');

      const manifest: ArtifactGenerationManifest = {
        manifest_version: 1,
        namespace: options.namespace,
        generation_id: generationId,
        created_at: new Date().toISOString(),
        files: [],
      };
      for (const [logicalPath, value] of [...normalizedFiles.entries()].sort(([a], [b]) => a.localeCompare(b))) {
        const bytes = contentBuffer(value.content);
        const destination = join(stagingPath, ...logicalPath.split('/'));
        const rel = relative(stagingPath, destination);
        if (rel.startsWith(`..${sep}`) || rel === '..') throw new Error(`Artifact path escaped its generation: ${logicalPath}`);
        writeArtifactAtomicDurable(destination, bytes, { overwrite: false });
        manifest.files.push({
          path: logicalPath,
          size_bytes: bytes.byteLength,
          sha256: createHash('sha256').update(bytes).digest('hex'),
          ...(value.media_type ? { media_type: value.media_type } : {}),
        });
      }
      const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
      writeArtifactAtomicDurable(join(stagingPath, 'manifest.json'), manifestBytes, { overwrite: false });
      fsyncDirectory(stagingPath);
      renameSync(stagingPath, generationPath);
      generationRenamed = true;
      fsyncDirectory(generationRoot);

      const manifestSha256 = createHash('sha256').update(manifestBytes).digest('hex');
      let commitDurability: ArtifactGenerationPublication['commit_durability'] = 'confirmed';
      try {
        writeArtifactAtomicDurable(pointerPath, `${JSON.stringify({
          pointer_version: 1,
          namespace: options.namespace,
          generation_id: generationId,
          generation_path: relative(root, generationPath).split(sep).join('/'),
          manifest_path: relative(root, join(generationPath, 'manifest.json')).split(sep).join('/'),
          manifest_sha256: manifestSha256,
          committed_at: new Date().toISOString(),
        }, null, 2)}\n`);
      } catch (error) {
        if (
          error instanceof DurableArtifactPublicationError
          && error.publication_visible
          && error.destination_path === pointerPath
        ) {
          commitDurability = error.durability_confirmed ? 'confirmed' : 'uncertain';
        } else {
          throw error;
        }
      }

      let mirrorWarning: string | undefined;
      try {
        refreshLegacyMirrors(root, generationPath, normalizedFiles.keys(), registration.legacy_names);
      } catch (error) {
        mirrorWarning = `Generation committed, but legacy fixed-name mirrors need repair: ${error instanceof Error ? error.message : String(error)}`;
      }
      let cleanupWarning: string | undefined;
      try {
        cleanupGenerationDebris(generationRoot, generationId);
      } catch (error) {
        cleanupWarning = `Generation retention cleanup is pending: ${error instanceof Error ? error.message : String(error)}`;
      }
      return {
        generation_id: generationId,
        generation_committed: commitDurability === 'confirmed',
        pointer_visible: true,
        commit_durability: commitDurability,
        generation_path: generationPath,
        generation_manifest: join(generationPath, 'manifest.json'),
        manifest_sha256: manifestSha256,
        pointer_path: pointerPath,
        legacy_mirror_complete: mirrorWarning === undefined,
        ...(
          commitDurability === 'uncertain' || mirrorWarning || cleanupWarning
            ? {
                warning: [
                  ...(commitDurability === 'uncertain'
                    ? ['Generation pointer is visible, but its directory fsync could not be confirmed.']
                    : []),
                  ...(mirrorWarning ? [mirrorWarning] : []),
                  ...(cleanupWarning ? [cleanupWarning] : []),
                ].join(' '),
              }
            : {}
        ),
      };
    } catch (error) {
      if (!generationRenamed && existsSync(stagingPath)) {
        try {
          const stat = lstatSync(stagingPath);
          if (stat.isDirectory() && !stat.isSymbolicLink()) {
            rmSync(stagingPath, { recursive: true, force: true });
            fsyncDirectory(generationRoot);
          }
        } catch { /* preserve the publication failure */ }
      }
      throw error;
    }
  });
}

/** Repair fixed-name compatibility files from the authoritative generation. */
export function repairArtifactGenerationMirrors(
  root: string,
  namespace: string,
  legacyNames: string[] = [],
): boolean {
  if (!SAFE_NAMESPACE.test(namespace)) throw new Error(`Invalid artifact generation namespace: ${namespace}`);
  const absoluteRoot = resolve(root);
  const pointerPath = join(absoluteRoot, `.overwatch-${namespace}-current.json`);
  if (!existsSync(pointerPath)) return false;
  return withStateMigrationWriteGuard(pointerPath, undefined, () => {
    const current = readCurrentArtifactGeneration(absoluteRoot, namespace);
    if (!current) return false;
    refreshLegacyMirrors(
      absoluteRoot,
      current.generation_path,
      current.manifest.files.map(file => safeLogicalPath(file.path)),
      legacyNames,
    );
    return true;
  });
}

/** Resolve and validate the currently committed generation for readers/tests. */
export function readCurrentArtifactGeneration(root: string, namespace: string): {
  pointer: Record<string, unknown>;
  manifest: ArtifactGenerationManifest;
  generation_path: string;
} | null {
  if (!SAFE_NAMESPACE.test(namespace)) throw new Error(`Invalid artifact generation namespace: ${namespace}`);
  const absoluteRoot = resolve(root);
  const pointerPath = join(absoluteRoot, `.overwatch-${namespace}-current.json`);
  if (!existsSync(pointerPath)) return null;
  const pointer = JSON.parse(readFileSync(pointerPath, 'utf8')) as Record<string, unknown>;
  if (
    pointer.pointer_version !== 1
    || pointer.namespace !== namespace
    || typeof pointer.generation_id !== 'string'
    || !/^[0-9a-f-]{36}$/i.test(pointer.generation_id)
    || typeof pointer.generation_path !== 'string'
    || typeof pointer.manifest_path !== 'string'
    || typeof pointer.manifest_sha256 !== 'string'
    || !/^[0-9a-f]{64}$/i.test(pointer.manifest_sha256)
  ) {
    throw new Error(`Invalid ${namespace} generation pointer.`);
  }
  const generationPath = resolve(absoluteRoot, pointer.generation_path);
  const expectedGenerationPath = resolve(
    absoluteRoot,
    '.overwatch-generations',
    namespace,
    pointer.generation_id,
  );
  if (generationPath !== expectedGenerationPath) {
    throw new Error(`Artifact generation pointer escapes its namespace.`);
  }
  const manifestPath = join(generationPath, 'manifest.json');
  const expectedManifestRelative = relative(absoluteRoot, manifestPath).split(sep).join('/');
  if (pointer.manifest_path !== expectedManifestRelative) {
    throw new Error(`Artifact generation pointer declares the wrong manifest path.`);
  }
  const manifestBytes = readFileSync(manifestPath);
  if (
    typeof pointer.manifest_sha256 !== 'string'
    || createHash('sha256').update(manifestBytes).digest('hex') !== pointer.manifest_sha256
  ) throw new Error(`Artifact generation manifest checksum mismatch.`);
  const manifest = JSON.parse(manifestBytes.toString('utf8')) as ArtifactGenerationManifest;
  if (
    manifest.manifest_version !== 1
    || manifest.generation_id !== pointer.generation_id
    || manifest.namespace !== namespace
    || !Array.isArray(manifest.files)
  ) {
    throw new Error(`Artifact generation pointer/manifest identity mismatch.`);
  }
  const seen = new Set<string>();
  for (const file of manifest.files) {
    if (
      !file
      || typeof file.path !== 'string'
      || !Number.isSafeInteger(file.size_bytes)
      || file.size_bytes < 0
      || typeof file.sha256 !== 'string'
      || !/^[0-9a-f]{64}$/i.test(file.sha256)
      || (file.media_type !== undefined && typeof file.media_type !== 'string')
    ) throw new Error(`Invalid artifact generation member descriptor.`);
    const logicalPath = safeLogicalPath(file.path);
    if (seen.has(logicalPath)) throw new Error(`Duplicate artifact generation member: ${logicalPath}`);
    seen.add(logicalPath);
    const path = join(generationPath, ...logicalPath.split('/'));
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== file.size_bytes) {
      throw new Error(`Artifact generation member is unavailable: ${file.path}`);
    }
    const bytes = readFileSync(path);
    if (createHash('sha256').update(bytes).digest('hex') !== file.sha256) {
      throw new Error(`Artifact generation member checksum mismatch: ${file.path}`);
    }
  }
  return { pointer, manifest, generation_path: generationPath };
}
