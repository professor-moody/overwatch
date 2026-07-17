import { mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { assertTemporaryTestPath, createTestSandbox } from './test-sandbox.js';

describe('test sandbox capability boundary', () => {
  it('allows owned paths and rejects traversal', () => {
    const sandbox = createTestSandbox('capability');
    expect(assertTemporaryTestPath(sandbox.path('state.json'))).toBe(sandbox.path('state.json'));
    expect(() => sandbox.path('..', 'outside.json')).toThrow(/escapes its owned root/u);
    sandbox.cleanup();
    expect(() => sandbox.cleanup()).not.toThrow();
  });

  it('will not authorize another temporary directory for cleanup', () => {
    const unowned = mkdtempSync(join(tmpdir(), 'overwatch-unowned-test-'));
    try {
      expect(() => assertTemporaryTestPath(join(unowned, 'state.json')))
        .toThrow(/not owned by this test worker/u);
    } finally {
      rmSync(unowned, { recursive: true, force: true });
    }
  });

  it('rejects symlink traversal from an owned sandbox', () => {
    const sandbox = createTestSandbox('symlink-boundary');
    const outside = mkdtempSync(join(tmpdir(), 'overwatch-outside-test-'));
    try {
      symlinkSync(outside, sandbox.path('redirect'));
      expect(() => sandbox.path('redirect', 'state.json')).toThrow(/symbolic link/u);
      expect(() => assertTemporaryTestPath(join(sandbox.root, 'redirect', 'state.json')))
        .toThrow(/symbolic link/u);
    } finally {
      sandbox.cleanup();
      rmSync(outside, { recursive: true, force: true });
    }
  });
});
