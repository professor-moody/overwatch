import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  assertArtifactSnapshotUnchanged,
  diffArtifactSnapshots,
  snapshotSensitiveArtifacts,
} from './artifact-hygiene.js';
import { createTestSandbox } from './test-sandbox.js';

describe('artifact hygiene guard', () => {
  it('detects additions and changes beneath protected artifact roots', () => {
    const sandbox = createTestSandbox('artifact-hygiene');
    mkdirSync(sandbox.path('evidence'), { recursive: true });
    writeFileSync(sandbox.path('evidence', 'manifest.json'), 'before');
    writeFileSync(sandbox.path('state-test.json'), '{}');
    const before = snapshotSensitiveArtifacts(sandbox.root);

    writeFileSync(sandbox.path('evidence', 'manifest.json'), 'after-after');
    writeFileSync(sandbox.path('state-new.json'), '{}');
    mkdirSync(sandbox.path('eval-artifacts', 'run-1'), { recursive: true });
    writeFileSync(sandbox.path('eval-artifacts', 'run-1', 'manifest.json'), '{}');
    const after = snapshotSensitiveArtifacts(sandbox.root);
    const diff = diffArtifactSnapshots(before, after);

    expect(diff.added).toContain('state-new.json');
    expect(diff.added).toContain('eval-artifacts');
    expect(diff.added).toContain('eval-artifacts/run-1/manifest.json');
    expect(diff.changed).toContain('evidence/manifest.json');
    expect(() => assertArtifactSnapshotUnchanged(before, after))
      .toThrow(/changed operator-owned artifacts/u);
  });

  it('ignores ordinary build and scratch output', () => {
    const sandbox = createTestSandbox('artifact-hygiene-ignore');
    const before = snapshotSensitiveArtifacts(sandbox.root);
    mkdirSync(sandbox.path('dist'), { recursive: true });
    writeFileSync(sandbox.path('dist', 'index.js'), 'generated');
    mkdirSync(sandbox.path('tmp'), { recursive: true });
    writeFileSync(sandbox.path('tmp', 'fixture.json'), '{}');
    const after = snapshotSensitiveArtifacts(sandbox.root);

    expect(() => assertArtifactSnapshotUnchanged(before, after)).not.toThrow();
  });

  it('fails loudly when a protected artifact root is a symbolic link', () => {
    const sandbox = createTestSandbox('artifact-hygiene-symlink');
    mkdirSync(sandbox.path('external'), { recursive: true });
    symlinkSync(sandbox.path('external'), sandbox.path('evidence'));

    expect(() => snapshotSensitiveArtifacts(sandbox.root)).toThrow(/symbolic link/u);
  });
});
