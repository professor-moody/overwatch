import { describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
// The startup helper is intentionally plain ESM so it can run before TypeScript
// has been compiled.
// @ts-expect-error JavaScript startup helper has no declaration file.
import { buildInputFingerprint, inspectBuildFreshness } from '../../../scripts/build-fingerprint.mjs';

function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), 'ow-build-freshness-'));
  mkdirSync(join(root, 'src'), { recursive: true });
  mkdirSync(join(root, 'dist', 'dashboard-next'), { recursive: true });
  writeFileSync(join(root, 'src', 'index.ts'), 'export const value = 1;\n');
  writeFileSync(join(root, 'package.json'), '{}\n');
  writeFileSync(join(root, 'dist', 'index.js'), 'export const value = 1;\n');
  writeFileSync(join(root, 'dist', 'dashboard-next', 'index.html'), '<!doctype html>\n');
  return root;
}

describe('compiled build freshness', () => {
  it('detects missing metadata and source changes after a recorded build', () => {
    const root = fixture();
    try {
      expect(inspectBuildFreshness(root)).toMatchObject({
        fresh: false,
        reason: 'build freshness metadata is missing',
      });
      const input = buildInputFingerprint(root);
      writeFileSync(join(root, 'dist', 'build-info.json'), JSON.stringify({
        schema_version: 1,
        input_sha256: input.sha256,
      }));
      expect(inspectBuildFreshness(root).fresh).toBe(true);
      writeFileSync(join(root, 'src', 'index.ts'), 'export const value = 2;\n');
      expect(inspectBuildFreshness(root)).toMatchObject({
        fresh: false,
        reason: 'source files changed after the last build',
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('accepts a packaged dist that intentionally omits source', () => {
    const root = mkdtempSync(join(tmpdir(), 'ow-packaged-build-'));
    try {
      mkdirSync(join(root, 'dist', 'dashboard-next'), { recursive: true });
      writeFileSync(join(root, 'dist', 'index.js'), 'export {};\n');
      writeFileSync(join(root, 'dist', 'dashboard-next', 'index.html'), '<!doctype html>\n');
      expect(inspectBuildFreshness(root)).toMatchObject({ fresh: true, rebuildable: false });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
