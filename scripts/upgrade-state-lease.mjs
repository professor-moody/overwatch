#!/usr/bin/env node

import { acquireStateMigrationLease } from '../dist/services/state-migration-lock.js';

const stateFile = process.argv[2];
if (!stateFile) throw new Error('upgrade state lease requires a state-file path');

const releaseLease = acquireStateMigrationLease(stateFile);
let finished = false;
const finish = (exitCode = 0) => {
  if (finished) return;
  finished = true;
  process.stdin.pause();
  process.stdin.destroy();
  try {
    releaseLease();
  } catch (error) {
    process.stderr.write(`upgrade state lease release failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
  process.exit(exitCode);
};

process.stdout.write(`${JSON.stringify({ ready: true, token: releaseLease.token })}\n`);
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  if (chunk.includes('release')) finish(0);
});
process.stdin.on('end', () => finish(0));
process.on('SIGINT', () => finish(130));
process.on('SIGTERM', () => finish(143));
process.stdin.resume();
