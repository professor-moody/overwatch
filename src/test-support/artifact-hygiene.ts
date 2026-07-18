import { lstatSync, readdirSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';

export interface ArtifactFingerprint {
  readonly kind: 'directory' | 'file' | 'link' | 'other';
  readonly inode: string;
  readonly size: string;
  readonly mtime_ns: string;
  readonly mode: string;
}

export type ArtifactSnapshot = ReadonlyMap<string, ArtifactFingerprint>;

export interface ArtifactSnapshotDiff {
  readonly added: string[];
  readonly removed: string[];
  readonly changed: string[];
}

const EXACT_ARTIFACT_NAMES = new Set([
  '.migration-backups',
  '.overwatch-mcp-token',
  '.snapshots',
  'engagement.json',
  'engagements',
  'eval-artifacts',
  'eval-baselines',
  'evidence',
  'logs',
  'reports',
  'retrospective',
  'session-jars',
  'smoke-engagement',
  'tapes',
]);

function isSensitiveRootEntry(name: string): boolean {
  if (EXACT_ARTIFACT_NAMES.has(name)) return true;
  return /^(?:engagement|evidence|reports?|state|tapes?)(?:[-.].*)$/u.test(name)
    || /\.snap-[^.]+\.json$/u.test(name);
}

function fingerprint(path: string): ArtifactFingerprint {
  const stat = lstatSync(path, { bigint: true });
  return {
    kind: stat.isDirectory()
      ? 'directory'
      : stat.isFile()
        ? 'file'
        : stat.isSymbolicLink()
          ? 'link'
          : 'other',
    inode: stat.ino.toString(),
    size: stat.size.toString(),
    mtime_ns: stat.mtimeNs.toString(),
    mode: stat.mode.toString(),
  };
}

function visit(root: string, path: string, snapshot: Map<string, ArtifactFingerprint>): void {
  let entryFingerprint: ArtifactFingerprint;
  try {
    entryFingerprint = fingerprint(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }

  const key = relative(root, path).split(sep).join('/');
  snapshot.set(key, entryFingerprint);
  if (entryFingerprint.kind === 'link') {
    throw new Error(
      `Cannot protect operator-owned artifact through a symbolic link: ${key || path}`,
    );
  }
  if (entryFingerprint.kind !== 'directory') return;

  for (const entry of readdirSync(path, { withFileTypes: true })) {
    visit(root, resolve(path, entry.name), snapshot);
  }
}

/**
 * Record metadata for operator-owned artifacts that must not be created,
 * removed, or modified by a test run. File contents are deliberately never
 * read, so the guard does not ingest engagement data or secrets.
 */
export function snapshotSensitiveArtifacts(workspaceRoot: string): ArtifactSnapshot {
  const root = resolve(workspaceRoot);
  const snapshot = new Map<string, ArtifactFingerprint>();
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!isSensitiveRootEntry(entry.name)) continue;
    visit(root, resolve(root, entry.name), snapshot);
  }
  return snapshot;
}

export function diffArtifactSnapshots(
  before: ArtifactSnapshot,
  after: ArtifactSnapshot,
): ArtifactSnapshotDiff {
  const added: string[] = [];
  const removed: string[] = [];
  const changed: string[] = [];

  for (const [path, value] of after) {
    const previous = before.get(path);
    if (!previous) added.push(path);
    else if (JSON.stringify(previous) !== JSON.stringify(value)) changed.push(path);
  }
  for (const path of before.keys()) {
    if (!after.has(path)) removed.push(path);
  }

  return {
    added: added.sort(),
    removed: removed.sort(),
    changed: changed.sort(),
  };
}

export function assertArtifactSnapshotUnchanged(
  before: ArtifactSnapshot,
  after: ArtifactSnapshot,
): void {
  const diff = diffArtifactSnapshots(before, after);
  if (diff.added.length === 0 && diff.removed.length === 0 && diff.changed.length === 0) return;

  const describe = (label: string, paths: string[]): string[] =>
    paths.slice(0, 25).map((path) => `  ${label}: ${path}`);
  const details = [
    ...describe('added', diff.added),
    ...describe('removed', diff.removed),
    ...describe('changed', diff.changed),
  ];
  const omitted = diff.added.length + diff.removed.length + diff.changed.length - details.length;
  if (omitted > 0) details.push(`  ... ${omitted} more artifact changes`);

  throw new Error([
    'The test run changed operator-owned artifacts in the checkout.',
    'Tests must use createTestSandbox() for state, evidence, reports, tapes, and logs.',
    ...details,
  ].join('\n'));
}
