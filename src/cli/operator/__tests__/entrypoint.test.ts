import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isEntrypoint } from '../entrypoint.js';

describe('isEntrypoint', () => {
  let dir: string;
  let script: string;   // the "real" module file (stands in for operator-cli.js)
  let link: string;     // an npm-link / global-bin style symlink to it (basename "overwatch")

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ow-entrypoint-'));
    script = join(dir, 'operator-cli.js');
    writeFileSync(script, '// stub');
    link = join(dir, 'overwatch');
    symlinkSync(script, link);
  });

  afterEach(() => {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('is true when invoked directly by its real path', () => {
    expect(isEntrypoint(script, pathToFileURL(script).href)).toBe(true);
  });

  it('is true when invoked via a symlink whose basename differs (the `npm link` case)', () => {
    // The regression: argv[1] is `…/overwatch`, not `…/operator-cli.js`. Realpath must
    // resolve the symlink back to the module so the CLI actually runs.
    expect(isEntrypoint(link, pathToFileURL(script).href)).toBe(true);
  });

  it('is false when the module is merely imported (argv1 is some other script)', () => {
    const other = join(dir, 'vitest-runner.js');
    writeFileSync(other, '// stub');
    expect(isEntrypoint(other, pathToFileURL(script).href)).toBe(false);
  });

  it('is false when argv1 is undefined', () => {
    expect(isEntrypoint(undefined, pathToFileURL(script).href)).toBe(false);
  });

  it('does not throw on a nonexistent argv1 (returns false)', () => {
    expect(isEntrypoint(join(dir, 'gone.js'), pathToFileURL(script).href)).toBe(false);
  });
});
