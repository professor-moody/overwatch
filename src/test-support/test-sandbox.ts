import { lstatSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

const REGISTRY_KEY = Symbol.for('overwatch.test-sandbox-roots');

function sandboxRegistry(): Set<string> {
  const globalRegistry = globalThis as typeof globalThis & {
    [REGISTRY_KEY]?: Set<string>;
  };
  if (!globalRegistry[REGISTRY_KEY]) globalRegistry[REGISTRY_KEY] = new Set();
  return globalRegistry[REGISTRY_KEY];
}

function safePrefix(prefix: string): string {
  const normalized = prefix.replace(/[^a-zA-Z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
  return normalized || 'sandbox';
}

function isInside(root: string, candidate: string): boolean {
  const remainder = relative(root, candidate);
  return remainder === '' || (!remainder.startsWith(`..${sep}`) && remainder !== '..' && !isAbsolute(remainder));
}

function assertNoSymlinkWithin(root: string, candidate: string): void {
  const remainder = relative(root, candidate);
  let current = root;
  const segments = remainder === '' ? [] : remainder.split(sep);

  for (const segment of ['', ...segments]) {
    if (segment) current = join(current, segment);
    try {
      if (lstatSync(current).isSymbolicLink()) {
        throw new Error(`Refusing a test path that traverses a symbolic link: ${current}`);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw error;
    }
  }
}

export interface TestSandbox {
  readonly root: string;
  path(...segments: string[]): string;
  cleanup(): void;
}

/**
 * Create a uniquely owned filesystem root for one test file or case.
 *
 * Cleanup is intentionally capability-based: only roots returned by this
 * function are registered, and cleanup refuses path traversal. This keeps a
 * failed test helper from ever deleting an operator checkout or engagement.
 */
export function createTestSandbox(prefix: string): TestSandbox {
  const root = resolve(mkdtempSync(join(tmpdir(), `overwatch-test-${safePrefix(prefix)}-`)));
  const registry = sandboxRegistry();
  registry.add(root);
  let cleaned = false;

  return {
    root,
    path(...segments: string[]): string {
      const candidate = resolve(root, ...segments);
      if (!isInside(root, candidate)) {
        throw new Error(`Test sandbox path escapes its owned root: ${candidate}`);
      }
      assertNoSymlinkWithin(root, candidate);
      return candidate;
    },
    cleanup(): void {
      if (cleaned) return;
      if (!registry.has(root)) {
        throw new Error(`Refusing to clean an unowned test sandbox: ${root}`);
      }
      rmSync(root, { recursive: true, force: true });
      registry.delete(root);
      cleaned = true;
    },
  };
}

/** Remove every sandbox registered by the current Vitest worker. */
export function cleanupRegisteredTestSandboxes(): void {
  const registry = sandboxRegistry();
  for (const root of [...registry]) {
    if (!registry.has(root)) continue;
    rmSync(root, { recursive: true, force: true });
    registry.delete(root);
  }
}

/** Guard legacy cleanup helpers while fixed-path tests are migrated. */
export function assertTemporaryTestPath(candidatePath: string): string {
  const absolute = resolve(candidatePath);
  const temporaryRoot = resolve(tmpdir());
  if (!isInside(temporaryRoot, absolute) || absolute === temporaryRoot) {
    throw new Error(
      `Refusing to clean test persistence outside the OS temporary directory: ${absolute}`,
    );
  }
  const owner = [...sandboxRegistry()].find(root => isInside(root, absolute));
  if (!owner) {
    throw new Error(`Refusing to clean a temporary path not owned by this test worker: ${absolute}`);
  }
  assertNoSymlinkWithin(owner, absolute);
  return absolute;
}
