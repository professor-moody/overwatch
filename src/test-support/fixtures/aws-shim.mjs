#!/usr/bin/env node
import { appendFileSync, readFileSync } from 'node:fs';

const EXPECTED_ARGV = ['sts', 'get-caller-identity', '--output', 'json'];
const invocationLog = process.env.OVERWATCH_EVAL_AWS_INVOCATION_LOG;
const fixtureFile = process.env.OVERWATCH_EVAL_AWS_FIXTURE_FILE;

if (!invocationLog || !fixtureFile) {
  process.stderr.write('Hermetic AWS shim is missing its fixture wiring.\n');
  process.exit(78);
}

const argv = process.argv.slice(2);
const exact = argv.length === EXPECTED_ARGV.length
  && argv.every((value, index) => value === EXPECTED_ARGV[index]);
if (!exact) {
  process.stderr.write(`Hermetic AWS shim only accepts ${EXPECTED_ARGV.join(' ')}; received ${argv.join(' ') || 'no arguments'}.\n`);
  process.exit(64);
}

appendFileSync(invocationLog, `${JSON.stringify({
  schema_version: 1,
  shim: 'overwatch-hermetic-aws',
  argv,
  expected_command: EXPECTED_ARGV,
  network_activity: false,
  invoked_at: new Date().toISOString(),
})}\n`, { mode: 0o600 });
process.stdout.write(readFileSync(fixtureFile, 'utf8'));
