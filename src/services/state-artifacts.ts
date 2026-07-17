// ============================================================
// Overwatch — External artifact references for persisted state
// ============================================================

import { closeSync, fstatSync, lstatSync, openSync, readSync, readdirSync, type Stats } from 'fs';
import { createHash } from 'crypto';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'path';
import type { ActivityLogEntry } from './engine-context.js';
import type {
  PersistedArtifactReferenceV1,
  PersistedArtifactReferencesV1,
} from './persisted-state.js';

const MAX_COOKIE_JAR_BYTES = 10 * 1024 * 1024;
const artifactHashCache = new Map<string, { identity: string; sha256: string }>();
const MAX_HASH_CACHE_ENTRIES = 4096;

function hashFileIncremental(path: string, expected: Stats): string {
  const identity = `${expected.dev}:${expected.ino}:${expected.size}:${expected.mtimeMs}:${expected.ctimeMs}`;
  const cached = artifactHashCache.get(path);
  if (cached?.identity === identity) return cached.sha256;
  const fd = openSync(path, 'r');
  const hash = createHash('sha256');
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.dev !== expected.dev || before.ino !== expected.ino) {
      throw new Error(`Artifact changed before hashing: ${path}`);
    }
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    while (offset < before.size) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, before.size - offset), offset);
      if (count === 0) throw new Error(`Artifact changed while hashing: ${path}`);
      hash.update(buffer.subarray(0, count));
      offset += count;
    }
    const after = fstatSync(fd);
    if (
      after.size !== before.size
      || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs
    ) throw new Error(`Artifact changed while hashing: ${path}`);
  } finally {
    closeSync(fd);
  }
  const sha256 = hash.digest('hex');
  artifactHashCache.set(path, { identity, sha256 });
  if (artifactHashCache.size > MAX_HASH_CACHE_ENTRIES) {
    artifactHashCache.delete(artifactHashCache.keys().next().value!);
  }
  return sha256;
}

function reference(
  kind: PersistedArtifactReferenceV1['kind'],
  path: string,
  stateDir: string,
  declared: Partial<PersistedArtifactReferenceV1> = {},
): PersistedArtifactReferenceV1 {
  const resolved = isAbsolute(path) ? path : join(stateDir, path);
  try {
    if (
      kind === 'cookie_jar'
      || kind === 'evidence_manifest'
      || kind === 'report_manifest'
    ) {
      const parent = lstatSync(dirname(resolved));
      if (parent.isSymbolicLink() || !parent.isDirectory()) {
        return { kind, path, ...declared, availability: 'invalid', integrity: 'unverified' };
      }
    }
    const stat = lstatSync(resolved);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      return { kind, path, ...declared, availability: 'invalid', integrity: 'unverified' };
    }
    if (kind === 'cookie_jar' && stat.size > MAX_COOKIE_JAR_BYTES) {
      return {
        kind,
        path,
        ...declared,
        size_bytes: stat.size,
        availability: 'invalid',
        integrity: 'unverified',
      };
    }
    // Artifact indexing runs during ordinary state persistence. Hash small
    // files inline, but retain declared bundle/tape digests without repeatedly
    // rereading multi-gigabyte operator artifacts on every mutation.
    // Cookie jars are bounded by their publisher, but can still be numerous.
    // Never synchronously reread every jar on each graph/state mutation; their
    // durable reference records availability and size, while consumers validate
    // Netscape structure and the 10 MiB bound before use.
    const shouldHash = kind !== 'cookie_jar' && stat.size <= 1024 * 1024;
    const observedSha = shouldHash
      ? hashFileIncremental(resolved, stat)
      : undefined;
    return {
      kind,
      path,
      ...declared,
      size_bytes: stat.size,
      availability: 'available',
      ...(observedSha ? {
        sha256: observedSha,
        integrity: declared.sha256 === undefined || declared.sha256 === observedSha
          ? 'verified'
          : 'unverified',
      } : { integrity: 'unverified' }),
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { kind, path, ...declared, availability: 'missing', integrity: 'unverified' };
    }
    // Artifact discovery is advisory and must never make the state/WAL commit
    // boundary fail. Retain the reference but surface that it could not be
    // safely inspected.
    return { kind, path, ...declared, availability: 'invalid', integrity: 'unverified' };
  }
}

function unique(
  values: PersistedArtifactReferenceV1[],
  stateDir: string,
): PersistedArtifactReferenceV1[] {
  const merged = new Map<string, PersistedArtifactReferenceV1>();
  for (const value of values) {
    const canonicalPath = isAbsolute(value.path)
      ? resolve(value.path)
      : resolve(stateDir, value.path);
    const key = `${value.kind}:${canonicalPath}`;
    const existing = merged.get(key);
    merged.set(key, existing
      ? {
          ...existing,
          ...value,
          // Keep the first public spelling for wire compatibility while the
          // canonical resolved path is used only as the dedupe identity.
          path: existing.path,
          ...(existing.bundle_id ? { bundle_id: existing.bundle_id } : {}),
          ...(existing.sha256 && !value.sha256 ? { sha256: existing.sha256 } : {}),
        }
      : value);
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
  stateFilePath: string,
): PersistedArtifactReferencesV1 {
  const stateDir = dirname(stateFilePath);
  const refresh = (value: PersistedArtifactReferenceV1): PersistedArtifactReferenceV1 =>
    reference(value.kind, value.path, stateDir, value);
  return {
    ...(discovered.evidence_manifest
      ? { evidence_manifest: discovered.evidence_manifest }
      : durable?.evidence_manifest
        ? { evidence_manifest: refresh(durable.evidence_manifest) }
        : {}),
    ...(discovered.report_manifest
      ? { report_manifest: discovered.report_manifest }
      : durable?.report_manifest
        ? { report_manifest: refresh(durable.report_manifest) }
        : {}),
    tapes: unique([...(durable?.tapes ?? []).map(refresh), ...discovered.tapes], stateDir),
    bundles: unique([...(durable?.bundles ?? []).map(refresh), ...discovered.bundles], stateDir),
    cookie_jars: unique([...(durable?.cookie_jars ?? []).map(refresh), ...discovered.cookie_jars], stateDir),
    ...(durable?.generation_registrations
      ? { generation_registrations: structuredClone(durable.generation_registrations) }
      : {}),
  };
}

function directoryNames(path: string): string[] {
  try {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isDirectory()) return [];
    return readdirSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    return [];
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
    const sha256 = hashFileIncremental(path, stat);
    return {
      kind,
      path: relative(stateDir, path),
      sha256,
      size_bytes: stat.size,
      availability: 'available',
      integrity: 'verified',
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    return {
      kind,
      path: relative(stateDir, path),
      availability: 'invalid',
      integrity: 'unverified',
    };
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
    if (tapePath) tapes.push(reference('tape', tapePath, stateDir, {
      ...(typeof details?.tape_sha256 === 'string' ? { sha256: details.tape_sha256 } : {}),
      ...(typeof details?.tape_size_bytes === 'number' ? { size_bytes: details.tape_size_bytes } : {}),
    }));
    if (bundlePath) bundles.push(reference('bundle', bundlePath, stateDir, {
      ...(typeof details?.sha256 === 'string' ? { sha256: details.sha256 } : {}),
      ...(typeof details?.size_bytes === 'number' ? { size_bytes: details.size_bytes } : {}),
      ...(typeof details?.bundle_id === 'string' ? { bundle_id: details.bundle_id } : {}),
    }));
  }

  // Older bundle events did not carry structured details. Files in the state
  // directory remain discoverable without embedding their contents.
  for (const name of directoryNames(stateDir)) {
    if (name.startsWith('bundle-') && name.endsWith('.tar.gz')) {
      bundles.push(reference('bundle', name, stateDir));
    }
  }

  const cookieJars = directoryNames(join(stateDir, 'session-jars'))
    .filter(name => name.endsWith('.jar'))
    .map(name => reference('cookie_jar', join('session-jars', basename(name)), stateDir));
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
    tapes: unique(tapes, stateDir),
    bundles: unique(bundles, stateDir),
    cookie_jars: unique(cookieJars, stateDir),
  };
}
