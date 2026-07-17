import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHash } from 'crypto';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { ActivityLogEntry } from '../engine-context.js';
import { buildArtifactReferences, mergeArtifactReferences } from '../state-artifacts.js';

let root: string;
let statePath: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'overwatch-state-artifacts-'));
  statePath = join(root, 'state.json');
  writeFileSync(statePath, '{}');
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

function event(details: Record<string, unknown>): ActivityLogEntry {
  return { event_type: 'system', details } as unknown as ActivityLogEntry;
}

describe('persisted artifact references', () => {
  it('records availability, size, and bounded integrity without embedding bytes', () => {
    const tapePath = join(root, 'tape.jsonl');
    const bundlePath = join(root, 'bundle-test.tar.gz');
    writeFileSync(tapePath, '{"frame":1}\n');
    writeFileSync(bundlePath, 'bundle bytes');
    mkdirSync(join(root, 'session-jars'));
    writeFileSync(join(root, 'session-jars', 'web.jar'), '# Netscape HTTP Cookie File\n');
    const bundleSha = createHash('sha256').update('bundle bytes').digest('hex');

    const refs = buildArtifactReferences(statePath, [
      event({ tape_path: tapePath, tape_size_bytes: 12 }),
      event({ bundle_path: bundlePath, bundle_id: 'bundle-1', size_bytes: 12, sha256: bundleSha }),
    ]);
    expect(refs.tapes[0]).toMatchObject({ kind: 'tape', availability: 'available', integrity: 'verified' });
    expect(refs.bundles[0]).toMatchObject({
      kind: 'bundle',
      bundle_id: 'bundle-1',
      size_bytes: 12,
      sha256: bundleSha,
      availability: 'available',
      integrity: 'verified',
    });
    expect(refs.cookie_jars[0]).toMatchObject({
      kind: 'cookie_jar',
      availability: 'available',
      integrity: 'unverified',
    });
  });

  it('retains missing paths as explicit offline references and never follows symlinks', () => {
    const missing = join(root, 'gone.jsonl');
    const outside = join(root, 'outside.tar.gz');
    const linked = join(root, 'bundle-linked.tar.gz');
    writeFileSync(outside, 'outside');
    symlinkSync(outside, linked);
    const refs = buildArtifactReferences(statePath, [
      event({ tape_path: missing }),
      event({ bundle_path: linked }),
    ]);
    expect(refs.tapes[0]).toMatchObject({ availability: 'missing', integrity: 'unverified' });
    expect(refs.bundles.find(reference => reference.path === linked)).toMatchObject({
      availability: 'invalid',
      integrity: 'unverified',
    });
  });

  it('refreshes durable references after external deletion instead of retaining false availability', () => {
    const tapePath = join(root, 'tape.jsonl');
    mkdirSync(join(root, 'session-jars'));
    const jarPath = join(root, 'session-jars', 'web.jar');
    writeFileSync(tapePath, '{}\n');
    writeFileSync(jarPath, '# Netscape HTTP Cookie File\n');
    mkdirSync(join(root, 'evidence'));
    writeFileSync(join(root, 'evidence', 'manifest.json'), '[]\n');
    const durable = buildArtifactReferences(statePath, [event({ tape_path: tapePath })]);
    expect(durable.tapes[0].availability).toBe('available');
    expect(durable.cookie_jars[0].availability).toBe('available');
    expect(durable.evidence_manifest?.availability).toBe('available');
    rmSync(tapePath);
    rmSync(jarPath);
    rmSync(join(root, 'evidence', 'manifest.json'));
    const merged = mergeArtifactReferences(durable, buildArtifactReferences(statePath, []), statePath);
    expect(merged.tapes[0].availability).toBe('missing');
    expect(merged.cookie_jars[0].availability).toBe('missing');
    expect(merged.evidence_manifest?.availability).toBe('missing');
  });

  it('does not enumerate through a symlinked session-jar root', () => {
    const outside = join(root, 'outside-jars');
    mkdirSync(outside);
    writeFileSync(join(outside, 'stolen.jar'), '# Netscape HTTP Cookie File\n');
    symlinkSync(outside, join(root, 'session-jars'));
    expect(buildArtifactReferences(statePath, []).cookie_jars).toEqual([]);
  });

  it('marks oversized cookie jars invalid without reading them into memory', () => {
    mkdirSync(join(root, 'session-jars'));
    const jar = join(root, 'session-jars', 'oversized.jar');
    writeFileSync(jar, '# Netscape HTTP Cookie File\n');
    truncateSync(jar, 10 * 1024 * 1024 + 1);
    expect(buildArtifactReferences(statePath, []).cookie_jars[0]).toMatchObject({
      kind: 'cookie_jar',
      size_bytes: 10 * 1024 * 1024 + 1,
      availability: 'invalid',
      integrity: 'unverified',
    });
  });
});
