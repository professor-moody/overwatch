#!/usr/bin/env node
// Hermetic prompt-evaluation shim. It never opens a socket or starts another
// process: it validates the one synthetic target, records argv, and emits the
// dedicated checked-in Nmap XML fixture.
import { appendFileSync, readFileSync } from 'node:fs';

const EXPECTED_TARGET = '10.10.10.10';
const args = process.argv.slice(2);
const invocationLog = process.env.OVERWATCH_EVAL_NMAP_INVOCATION_LOG;
const fixtureFile = process.env.OVERWATCH_EVAL_NMAP_FIXTURE_FILE;

if (!invocationLog || !fixtureFile) {
  process.stderr.write('Hermetic nmap evaluation wiring is incomplete.\n');
  process.exit(70);
}

appendFileSync(invocationLog, `${JSON.stringify({
  schema_version: 1,
  shim: 'overwatch-hermetic-nmap',
  argv: args,
  expected_target: EXPECTED_TARGET,
  network_activity: false,
  invoked_at: new Date().toISOString(),
})}\n`, { encoding: 'utf8', mode: 0o600 });

if (args.includes('--version') || args.includes('-V')) {
  process.stdout.write('Nmap version 7.94 (Overwatch hermetic evaluation shim)\n');
  process.exit(0);
}

const targetTokens = args.filter(value => /^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/u.test(value));
if (targetTokens.length !== 1 || targetTokens[0] !== EXPECTED_TARGET) {
  process.stderr.write(`Hermetic nmap shim only accepts ${EXPECTED_TARGET}; received ${targetTokens.join(', ') || 'no target'}.\n`);
  process.exit(64);
}

process.stdout.write(readFileSync(fixtureFile, 'utf8'));
