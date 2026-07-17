// ============================================================
// Crash-safe publication for operator-visible filesystem artifacts.
// ============================================================

import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  openSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'fs';
import { randomBytes } from 'crypto';
import { dirname } from 'path';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';

export interface DurableArtifactOptions {
  /** Replace an existing destination atomically. Defaults to true. */
  overwrite?: boolean;
  /** Permissions used for the private staging file. Defaults to 0600. */
  mode?: number;
  /** Injectable directory durability boundary for deterministic tests. */
  syncDirectory?: (directory: string) => void;
}

export class DurableArtifactPublicationError extends Error {
  readonly publication_visible: boolean;
  readonly durability_confirmed: boolean;
  readonly destination_path: string;

  constructor(
    message: string,
    destinationPath: string,
    options: {
      publicationVisible: boolean;
      durabilityConfirmed: boolean;
      cause?: unknown;
    },
  ) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'DurableArtifactPublicationError';
    this.publication_visible = options.publicationVisible;
    this.durability_confirmed = options.durabilityConfirmed;
    this.destination_path = destinationPath;
  }
}

function removeStagingFile(path: string, syncDirectory: (directory: string) => void): void {
  if (!existsSync(path)) return;
  unlinkSync(path);
  syncDirectory(dirname(path));
}

/**
 * Publish a completely-written file that already lives beside its destination.
 * The staged file is fsynced before its name becomes visible, and the containing
 * directory is fsynced after every rename/link/unlink boundary.
 */
export function publishArtifactFileDurable(
  stagedPath: string,
  destinationPath: string,
  options: DurableArtifactOptions = {},
): void {
  const directory = dirname(destinationPath);
  if (dirname(stagedPath) !== directory) {
    throw new Error('Durable artifact staging must use the destination directory.');
  }
  const syncDirectory = options.syncDirectory ?? fsyncDirectory;
  mkdirDurable(directory, syncDirectory);

  const fd = openSync(stagedPath, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }

  if (options.overwrite === false) {
    // link(2) is the exclusive publication primitive: unlike rename, it cannot
    // silently replace another writer's completed artifact.
    linkSync(stagedPath, destinationPath);
    try {
      syncDirectory(directory);
    } catch (error) {
      throw new DurableArtifactPublicationError(
        `Artifact name is visible but its directory fsync failed: ${destinationPath}`,
        destinationPath,
        { publicationVisible: true, durabilityConfirmed: false, cause: error },
      );
    }
    try {
      removeStagingFile(stagedPath, syncDirectory);
    } catch (error) {
      throw new DurableArtifactPublicationError(
        `Artifact committed but private staging cleanup is incomplete: ${destinationPath}`,
        destinationPath,
        { publicationVisible: true, durabilityConfirmed: true, cause: error },
      );
    }
    return;
  }

  renameSync(stagedPath, destinationPath);
  try {
    syncDirectory(directory);
  } catch (error) {
    throw new DurableArtifactPublicationError(
      `Artifact name is visible but its directory fsync failed: ${destinationPath}`,
      destinationPath,
      { publicationVisible: true, durabilityConfirmed: false, cause: error },
    );
  }
}

/** Write bytes privately, fsync them, then atomically publish the final name. */
export function writeArtifactAtomicDurable(
  destinationPath: string,
  content: string | Buffer,
  options: DurableArtifactOptions = {},
): void {
  const directory = dirname(destinationPath);
  const syncDirectory = options.syncDirectory ?? fsyncDirectory;
  mkdirDurable(directory, syncDirectory);
  const stagedPath = `${destinationPath}.tmp-${process.pid}-${randomBytes(12).toString('hex')}`;
  let fd: number | undefined;
  let operationError: unknown;
  try {
    fd = openSync(stagedPath, 'wx', options.mode ?? 0o600);
    writeFileSync(fd, content);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    publishArtifactFileDurable(stagedPath, destinationPath, {
      ...options,
      syncDirectory,
    });
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* preserve the publication failure */ }
    }
    if (existsSync(stagedPath)) {
      try { removeStagingFile(stagedPath, syncDirectory); } catch (cleanupError) {
        if (operationError === undefined) throw cleanupError;
      }
    }
  }
}

/** Remove a published artifact and persist the directory-entry change. */
export function removeArtifactDurable(
  path: string,
  syncDirectory: (directory: string) => void = fsyncDirectory,
): boolean {
  if (!existsSync(path)) return false;
  unlinkSync(path);
  syncDirectory(dirname(path));
  return true;
}
