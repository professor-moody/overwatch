import { existsSync, readdirSync, rmSync } from 'fs';
import { basename, dirname, join, resolve } from 'path';

/**
 * Remove only the persistence artifacts derived from one test state pathname.
 *
 * Journal v2 is enabled for every engagement, so deleting only `state.json`
 * leaves a valid non-empty WAL with no recovery base and correctly makes the
 * next test start read-only. Fixed-path unit tests should call this before and
 * after each case.
 */
export function cleanupTestPersistence(stateFilePath: string): void {
  const absoluteStatePath = resolve(stateFilePath);
  const directory = dirname(absoluteStatePath);
  const stateName = basename(absoluteStatePath);
  const stem = basename(absoluteStatePath, '.json');

  if (existsSync(directory)) {
    for (const entry of readdirSync(directory)) {
      const derived =
        entry === stateName
        || entry.startsWith(`${stateName}.`)
        || entry === `${stem}.journal.jsonl`
        || entry.startsWith(`${stem}.journal.jsonl.`);
      if (derived) rmSync(join(directory, entry), { recursive: true, force: true });
    }
  }

  const snapshotDirectory = join(directory, '.snapshots');
  if (existsSync(snapshotDirectory)) {
    for (const entry of readdirSync(snapshotDirectory)) {
      if (entry.startsWith(`${stem}.snap-`)) {
        rmSync(join(snapshotDirectory, entry), { recursive: true, force: true });
      }
    }
  }

  const backupDirectory = join(directory, '.migration-backups');
  if (existsSync(backupDirectory)) {
    for (const entry of readdirSync(backupDirectory)) {
      if (entry.startsWith(`${stem}-20`)) {
        rmSync(join(backupDirectory, entry), { recursive: true, force: true });
      }
    }
  }
}
