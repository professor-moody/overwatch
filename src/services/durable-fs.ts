// ============================================================
// Durable filesystem helpers
// ============================================================

import { closeSync, existsSync, fsyncSync, mkdirSync, openSync } from 'fs';
import { dirname, resolve } from 'path';

/** Ancestor fsync work that must be retried when recursive mkdir succeeded but
 * a later sync failed. The directory already exists on retry, so existence
 * alone is not proof that its parent entries reached stable storage. */
const pendingDirectorySyncs = new Map<string, string[]>();

/**
 * Persist directory-entry changes (create, rename, unlink) on POSIX.
 * Windows does not support opening directories through Node in the same
 * portable way, so the file-level fsync remains the durability boundary there.
 */
export function fsyncDirectory(path: string): void {
  if (process.platform === 'win32') return;

  let fd: number | undefined;
  try {
    fd = openSync(path, 'r');
    fsyncSync(fd);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * Recursively create a directory and persist every new ancestor entry.
 * `mkdirSync({ recursive: true })` can create several path components at once;
 * syncing only the leaf and its immediate parent leaves higher-level directory
 * entries vulnerable to a crash.
 */
export function mkdirDurable(
  path: string,
  syncDirectory: (directory: string) => void = fsyncDirectory,
): void {
  const target = resolve(path);
  const pending = pendingDirectorySyncs.get(target);
  const targetExists = existsSync(target);
  if (targetExists && !pending) return;

  let directoriesToSync = pending;
  if (!directoriesToSync || !targetExists) {
    const missing: string[] = [];
    let cursor = target;
    while (!existsSync(cursor)) {
      missing.push(cursor);
      const parent = dirname(cursor);
      if (parent === cursor) break;
      cursor = parent;
    }

    mkdirSync(target, { recursive: true });

    // Deepest-first sync persists each new directory's own contents, then the
    // parent entry that names it. A Set avoids repeated parent fsyncs.
    const uniqueDirectories = new Set<string>();
    for (const directory of missing) {
      uniqueDirectories.add(directory);
      uniqueDirectories.add(dirname(directory));
    }
    directoriesToSync = [...uniqueDirectories];
  }

  try {
    for (const directory of directoriesToSync) syncDirectory(directory);
    pendingDirectorySyncs.delete(target);
  } catch (error) {
    pendingDirectorySyncs.set(target, directoriesToSync);
    throw error;
  }
}
