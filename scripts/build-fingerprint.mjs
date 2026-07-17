import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

export const BUILD_INFO_FILE = 'dist/build-info.json';

const INPUT_PATHS = [
  'src',
  'scripts',
  'package.json',
  'package-lock.json',
  'tsconfig.json',
  'tsconfig.build.json',
];

function collectFiles(root, input, files) {
  const absolute = join(root, input);
  if (!existsSync(absolute)) return;
  const stat = statSync(absolute);
  if (stat.isFile()) {
    files.push(absolute);
    return;
  }
  if (!stat.isDirectory()) return;
  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist') continue;
    collectFiles(root, join(input, entry.name), files);
  }
}

export function isSourceCheckout(root) {
  return existsSync(join(root, 'src')) && existsSync(join(root, 'package.json'));
}

export function currentGitSha(root) {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 2_000,
    }).trim() || null;
  } catch {
    return null;
  }
}

export function buildInputFingerprint(root) {
  const files = [];
  for (const input of INPUT_PATHS) collectFiles(root, input, files);
  files.sort((left, right) => left.localeCompare(right));
  const hash = createHash('sha256');
  for (const file of files) {
    hash.update(relative(root, file));
    hash.update('\0');
    hash.update(readFileSync(file));
    hash.update('\0');
  }
  return { sha256: hash.digest('hex'), file_count: files.length };
}

export function readBuildInfo(root) {
  try {
    return JSON.parse(readFileSync(join(root, BUILD_INFO_FILE), 'utf8'));
  } catch {
    return null;
  }
}

export function inspectBuildFreshness(rootInput = process.cwd()) {
  const root = resolve(rootInput);
  const runtimePath = join(root, 'dist', 'index.js');
  const dashboardPath = join(root, 'dist', 'dashboard-next', 'index.html');
  const sourceCheckout = isSourceCheckout(root);
  const info = readBuildInfo(root);
  if (!existsSync(runtimePath) || !existsSync(dashboardPath)) {
    return {
      fresh: false,
      rebuildable: sourceCheckout,
      reason: 'compiled runtime or dashboard is missing',
      info,
    };
  }
  // Published packages intentionally omit TypeScript source. Their shipped dist
  // is authoritative and cannot be rebuilt with production-only dependencies.
  if (!sourceCheckout) return { fresh: true, rebuildable: false, info };

  const input = buildInputFingerprint(root);
  if (!info || info.input_sha256 !== input.sha256) {
    return {
      fresh: false,
      rebuildable: true,
      reason: info ? 'source files changed after the last build' : 'build freshness metadata is missing',
      info,
      input,
    };
  }
  return { fresh: true, rebuildable: true, info, input };
}
