#!/usr/bin/env node
import { appendFileSync, readFileSync } from 'node:fs';

const EXPECTED_TARGET = 'http://10.10.10.20';
const EXPECTED_ARGV = ['-u', EXPECTED_TARGET, '-jsonl'];
const invocationLog = process.env.OVERWATCH_EVAL_NUCLEI_INVOCATION_LOG;
const fixtureFile = process.env.OVERWATCH_EVAL_NUCLEI_FIXTURE_FILE;

if (!invocationLog || !fixtureFile) {
  process.stderr.write('Hermetic nuclei shim is missing its fixture wiring.\n');
  process.exit(78);
}

const argv = process.argv.slice(2);
const exact = argv.length === EXPECTED_ARGV.length
  && argv.every((value, index) => value === EXPECTED_ARGV[index]);
if (!exact) {
  process.stderr.write(`Hermetic nuclei shim only accepts ${EXPECTED_ARGV.join(' ')}; received ${argv.join(' ') || 'no arguments'}.\n`);
  process.exit(64);
}

appendFileSync(invocationLog, `${JSON.stringify({
  schema_version: 1,
  shim: 'overwatch-hermetic-nuclei',
  argv,
  expected_target: EXPECTED_TARGET,
  network_activity: false,
  invoked_at: new Date().toISOString(),
})}\n`, { mode: 0o600 });
process.stdout.write(readFileSync(fixtureFile, 'utf8'));
