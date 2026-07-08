import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * True when a module is being executed directly as a program, INCLUDING when it is
 * invoked through an npm-link / global-bin symlink (where `process.argv[1]` is the
 * symlink path — e.g. `…/bin/overwatch` — not the resolved script file). We compare
 * the realpath'd paths so the symlink resolves to the same file as `import.meta.url`;
 * a plain `argv[1].endsWith('operator-cli.js')` check misses the symlink and silently
 * no-ops the CLI. Returns false when the module is merely imported (e.g. by tests),
 * so importing it never triggers `main()`.
 */
export function isEntrypoint(argv1: string | undefined, moduleUrl: string): boolean {
  if (!argv1) return false;
  try {
    return realpathSync(argv1) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}
