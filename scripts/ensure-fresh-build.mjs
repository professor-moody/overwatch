import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { inspectBuildFreshness } from './build-fingerprint.mjs';

const root = resolve(dirname(new URL(import.meta.url).pathname), '..');
const initial = inspectBuildFreshness(root);
if (initial.fresh) process.exit(0);

if (!initial.rebuildable) {
  console.error(`[overwatch] Cannot start: ${initial.reason}. Reinstall the package.`);
  process.exit(1);
}

console.error(`[overwatch] ${initial.reason}; rebuilding before startup...`);
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const built = spawnSync(npm, ['run', 'build'], {
  cwd: root,
  stdio: 'inherit',
  env: process.env,
});
if (built.error || built.status !== 0) {
  console.error('[overwatch] Automatic rebuild failed. Run `npm ci && npm run build`, then start again.');
  process.exit(built.status || 1);
}

const verified = inspectBuildFreshness(root);
if (!verified.fresh) {
  console.error(`[overwatch] Build completed but is still not current: ${verified.reason}.`);
  process.exit(1);
}
