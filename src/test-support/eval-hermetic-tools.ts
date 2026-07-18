import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { delimiter, join, resolve } from 'node:path';

export const HERMETIC_RECON_TARGET = '10.10.10.10';

export interface HermeticNmapInvocation {
  schema_version: 1;
  shim: 'overwatch-hermetic-nmap';
  argv: string[];
  expected_target: string;
  network_activity: false;
  invoked_at: string;
}

export interface HermeticReconTooling {
  runtimeRoot: string;
  binDir: string;
  shimPath: string;
  fixturePath: string;
  invocationLogPath: string;
  path: string;
  env: {
    OVERWATCH_EVAL_NMAP_INVOCATION_LOG: string;
    OVERWATCH_EVAL_NMAP_FIXTURE_FILE: string;
  };
}

const SHIM_SOURCE = resolve('./src/test-support/fixtures/nmap-shim.mjs');
const FIXTURE_SOURCE = resolve('./src/test-support/fixtures/nmap-recon-10.10.10.10.xml');

/** Install the recon fixture entirely inside one temporary evaluation runtime. */
export function installHermeticReconTooling(runtimeRoot: string, inheritedPath = ''): HermeticReconTooling {
  const binDir = join(runtimeRoot, 'hermetic-bin');
  const fixtureDir = join(runtimeRoot, 'hermetic-fixtures');
  const shimPath = join(binDir, 'nmap');
  const fixturePath = join(fixtureDir, 'nmap-recon.xml');
  const invocationLogPath = join(runtimeRoot, 'nmap-invocations.ndjson');

  mkdirSync(binDir, { recursive: true, mode: 0o700 });
  mkdirSync(fixtureDir, { recursive: true, mode: 0o700 });
  copyFileSync(SHIM_SOURCE, shimPath);
  copyFileSync(FIXTURE_SOURCE, fixturePath);
  writeFileSync(invocationLogPath, '', { mode: 0o600 });
  chmodSync(binDir, 0o700);
  chmodSync(fixtureDir, 0o700);
  chmodSync(shimPath, 0o700);
  chmodSync(fixturePath, 0o600);
  chmodSync(invocationLogPath, 0o600);

  return {
    runtimeRoot,
    binDir,
    shimPath,
    fixturePath,
    invocationLogPath,
    path: inheritedPath ? `${binDir}${delimiter}${inheritedPath}` : binDir,
    env: {
      OVERWATCH_EVAL_NMAP_INVOCATION_LOG: invocationLogPath,
      OVERWATCH_EVAL_NMAP_FIXTURE_FILE: fixturePath,
    },
  };
}

export function readHermeticNmapInvocations(path: string): HermeticNmapInvocation[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(line => line.trim().length > 0)
    .map(line => JSON.parse(line) as HermeticNmapInvocation);
}
