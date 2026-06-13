#!/usr/bin/env node
import { execFileSync } from 'node:child_process';

const forbidden = [
  /^package\/\.research_logs\//,
  /^package\/src\/.*(__tests__|\.test\.)/,
  /^package\/dist\/.*(__tests__|\.test\.|\.spec\.)/,
  /^package\/engagement\.json$/,
  /^package\/state-[^/]+\.json$/,
  /^package\/state-[^/]+\.journal\.jsonl$/,
  /^package\/evidence\//,
  /^package\/reports\//,
  /^package\/\.snapshots\//,
  /^package\/tmp\//,
  /^package\/fixtures\//,
  /^package\/engagements\//,
];

let packed;
try {
  packed = execFileSync('npm', ['pack', '--dry-run', '--json'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
} catch (err) {
  console.error(err?.stderr?.toString?.() || err?.message || String(err));
  process.exit(1);
}

const entries = JSON.parse(packed);
const files = entries?.[0]?.files?.map(f => f.path) ?? [];
const bad = [];
for (const file of files) {
  const packagePath = `package/${file}`;
  if (forbidden.some(re => re.test(packagePath))) bad.push(file);
}

if (bad.length > 0) {
  console.error('npm package contains forbidden files:');
  for (const file of bad) console.error(`  - ${file}`);
  process.exit(1);
}

console.log(`package hygiene ok (${files.length} files)`);
