import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  BUILD_INFO_FILE,
  buildInputFingerprint,
  currentGitSha,
} from './build-fingerprint.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const input = buildInputFingerprint(root);
const output = join(root, BUILD_INFO_FILE);
const releaseVersion = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, `${JSON.stringify({
  schema_version: 1,
  release_version: releaseVersion,
  git_sha: currentGitSha(root),
  input_sha256: input.sha256,
  input_file_count: input.file_count,
  built_at: new Date().toISOString(),
}, null, 2)}\n`);
