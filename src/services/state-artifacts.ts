// ============================================================
// Overwatch — External artifact references for persisted state
// ============================================================

import { lstatSync, readFileSync, readdirSync } from 'fs';
import { createHash } from 'crypto';
import { basename, dirname, join, relative } from 'path';
import type { ActivityLogEntry } from './engine-context.js';
import type {
  PersistedArtifactReferenceV1,
  PersistedArtifactReferencesV1,
} from './persisted-state.js';

function reference(
  kind: PersistedArtifactReferenceV1['kind'],
  path: string,
): PersistedArtifactReferenceV1 {
  return { kind, path };
}

function unique(
  values: PersistedArtifactReferenceV1[],
): PersistedArtifactReferenceV1[] {
  const merged = new Map<string, PersistedArtifactReferenceV1>();
  for (const value of values) {
    const key = `${value.kind}:${value.path}`;
    merged.set(key, value);
  }
  return [...merged.values()];
}

/**
 * Preserve durable references that are not rediscoverable from the current
 * filesystem/activity projection. Newly discovered entries win for the same
 * kind/path so refreshed manifest checksums replace stale ones.
 */
export function mergeArtifactReferences(
  durable: PersistedArtifactReferencesV1 | undefined,
  discovered: PersistedArtifactReferencesV1,
): PersistedArtifactReferencesV1 {
  return {
    ...(discovered.evidence_manifest
      ? { evidence_manifest: discovered.evidence_manifest }
      : durable?.evidence_manifest
        ? { evidence_manifest: durable.evidence_manifest }
        : {}),
    ...(discovered.report_manifest
      ? { report_manifest: discovered.report_manifest }
      : durable?.report_manifest
        ? { report_manifest: durable.report_manifest }
        : {}),
    tapes: unique([...(durable?.tapes ?? []), ...discovered.tapes]),
    bundles: unique([...(durable?.bundles ?? []), ...discovered.bundles]),
    cookie_jars: unique([...(durable?.cookie_jars ?? []), ...discovered.cookie_jars]),
  };
}

function directoryNames(path: string): string[] {
  try {
    return readdirSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
}

function optionalManifestReference(
  kind: 'evidence_manifest' | 'report_manifest',
  stateDir: string,
  path: string,
): PersistedArtifactReferenceV1 | undefined {
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`artifact manifest must be a regular file: ${path}`);
    }
    const bytes = readFileSync(path);
    return {
      kind,
      path: relative(stateDir, path),
      sha256: createHash('sha256').update(bytes).digest('hex'),
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
}

/**
 * Build a small index only. Artifact contents remain in their dedicated
 * stores/files and are never copied into the state JSON.
 */
export function buildArtifactReferences(
  stateFilePath: string,
  activityLog: ActivityLogEntry[],
): PersistedArtifactReferencesV1 {
  const stateDir = dirname(stateFilePath);
  const evidenceManifest = join(stateDir, 'evidence', 'manifest.json');
  const reportManifest = join(stateDir, 'reports', 'manifest.json');

  const tapes: PersistedArtifactReferenceV1[] = [];
  const bundles: PersistedArtifactReferenceV1[] = [];
  for (const event of activityLog) {
    const details = event.details && typeof event.details === 'object'
      ? event.details as Record<string, unknown>
      : undefined;
    const tapePath = typeof details?.tape_path === 'string' ? details.tape_path : undefined;
    const bundlePath = typeof details?.bundle_path === 'string' ? details.bundle_path : undefined;
    if (tapePath) tapes.push(reference('tape', tapePath));
    if (bundlePath) bundles.push(reference('bundle', bundlePath));
  }

  // Older bundle events did not carry structured details. Files in the state
  // directory remain discoverable without embedding their contents.
  for (const name of directoryNames(stateDir)) {
    if (name.startsWith('bundle-') && name.endsWith('.tar.gz')) {
      bundles.push(reference('bundle', name));
    }
  }

  const cookieJars = directoryNames(join(stateDir, 'session-jars'))
    .filter(name => name.endsWith('.jar'))
    .map(name => reference('cookie_jar', join('session-jars', basename(name))));
  const evidenceReference = optionalManifestReference(
    'evidence_manifest',
    stateDir,
    evidenceManifest,
  );
  const reportReference = optionalManifestReference(
    'report_manifest',
    stateDir,
    reportManifest,
  );

  return {
    ...(evidenceReference ? { evidence_manifest: evidenceReference } : {}),
    ...(reportReference ? { report_manifest: reportReference } : {}),
    tapes: unique(tapes),
    bundles: unique(bundles),
    cookie_jars: unique(cookieJars),
  };
}
