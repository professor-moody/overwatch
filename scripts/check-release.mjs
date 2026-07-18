#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const readJson = path => JSON.parse(readFileSync(resolve(root, path), 'utf8'));
const packageJson = readJson('package.json');
const packageLock = readJson('package-lock.json');
const manifest = readJson('docs/reference/compatibility-manifest.json');
const changelog = readFileSync(resolve(root, 'CHANGELOG.md'), 'utf8');
const compatibility = readFileSync(resolve(root, 'docs/compatibility.md'), 'utf8');

const versions = new Map([
  ['package.json', packageJson.version],
  ['package-lock.json', packageLock.version],
  ['package-lock root package', packageLock.packages?.['']?.version],
  ['compatibility manifest', manifest.release_version],
]);
for (const [source, version] of versions) {
  if (version !== packageJson.version) {
    throw new Error(`${source} release ${String(version)} does not match package.json ${packageJson.version}`);
  }
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

const { manifest_sha256: declaredHash, ...manifestBody } = manifest;
const actualHash = createHash('sha256').update(stableJson(manifestBody)).digest('hex');
if (declaredHash !== actualHash) {
  throw new Error(`compatibility manifest checksum mismatch: expected ${declaredHash}, calculated ${actualHash}`);
}
if (!changelog.includes(`## ${packageJson.version} —`)) {
  throw new Error(`CHANGELOG.md has no release heading for ${packageJson.version}`);
}
if (!compatibility.includes(`Overwatch \`${packageJson.version}\``)) {
  throw new Error(`docs/compatibility.md does not declare Overwatch ${packageJson.version}`);
}

const buildInfoPath = resolve(root, 'dist/build-info.json');
if (existsSync(buildInfoPath)) {
  const buildInfo = readJson('dist/build-info.json');
  if (buildInfo.release_version !== packageJson.version) {
    throw new Error(`dist/build-info.json release ${String(buildInfo.release_version)} does not match ${packageJson.version}`);
  }
}

if (process.argv.includes('--require-head-tag')) {
  const expectedTag = `v${packageJson.version}`;
  const tagRef = `refs/tags/${expectedTag}`;
  const tagType = execFileSync('git', ['cat-file', '-t', tagRef], {
    cwd: root,
    encoding: 'utf8',
  }).trim();
  if (tagType !== 'tag') {
    throw new Error(`${expectedTag} must be an annotated tag`);
  }
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  const taggedCommit = execFileSync('git', ['rev-parse', `${tagRef}^{commit}`], {
    cwd: root,
    encoding: 'utf8',
  }).trim();
  if (taggedCommit !== head) {
    throw new Error(`${expectedTag} does not point at HEAD`);
  }
  const main = execFileSync('git', ['rev-parse', 'refs/remotes/origin/main'], {
    cwd: root,
    encoding: 'utf8',
  }).trim();
  if (head !== main) {
    throw new Error(`${expectedTag} points at ${head}, but the fetched origin/main release authority is ${main}`);
  }
}

console.log(`release contract ok (${packageJson.version}, ${actualHash})`);
