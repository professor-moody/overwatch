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
export const HERMETIC_WEB_TARGET = 'http://10.10.10.20';
export const HERMETIC_CLOUD_ACCOUNT = '111122223333';
export const HERMETIC_CLOUD_ARN = `arn:aws:iam::${HERMETIC_CLOUD_ACCOUNT}:user/eval-operator`;

export type HermeticToolingKind = 'nmap-recon' | 'nuclei-web' | 'aws-sts-cloud';
export type HermeticShimName =
  | 'overwatch-hermetic-nmap'
  | 'overwatch-hermetic-nuclei'
  | 'overwatch-hermetic-aws';

export interface HermeticToolInvocation {
  schema_version: 1;
  shim: HermeticShimName;
  argv: string[];
  expected_target?: string;
  expected_command?: string[];
  network_activity: false;
  invoked_at: string;
}

export interface HermeticNmapInvocation extends HermeticToolInvocation {
  shim: 'overwatch-hermetic-nmap';
  expected_target: string;
}

export interface HermeticEvalTooling {
  kind: HermeticToolingKind;
  binary: 'nmap' | 'nuclei' | 'aws';
  runtimeRoot: string;
  binDir: string;
  fixtureDir: string;
  shimPath: string;
  fixturePath: string;
  invocationLogPath: string;
  path: string;
  env: Record<string, string>;
}

export type HermeticReconTooling = HermeticEvalTooling & {
  kind: 'nmap-recon';
  binary: 'nmap';
};

export const HERMETIC_EVAL_ENV_KEYS = [
  'OVERWATCH_EVAL_NMAP_INVOCATION_LOG',
  'OVERWATCH_EVAL_NMAP_FIXTURE_FILE',
  'OVERWATCH_EVAL_NUCLEI_INVOCATION_LOG',
  'OVERWATCH_EVAL_NUCLEI_FIXTURE_FILE',
  'OVERWATCH_EVAL_AWS_INVOCATION_LOG',
  'OVERWATCH_EVAL_AWS_FIXTURE_FILE',
] as const;

interface InstallFixtureOptions {
  kind: HermeticToolingKind;
  binary: HermeticEvalTooling['binary'];
  runtimeRoot: string;
  inheritedPath: string;
  shimSource: string;
  fixtureSource: string;
  fixtureName: string;
  invocationLogName: string;
  invocationEnv: string;
  fixtureEnv: string;
}

function installHermeticToolFixture(options: InstallFixtureOptions): HermeticEvalTooling {
  const binDir = join(options.runtimeRoot, 'hermetic-bin');
  const fixtureDir = join(options.runtimeRoot, 'hermetic-fixtures');
  const shimPath = join(binDir, options.binary);
  const fixturePath = join(fixtureDir, options.fixtureName);
  const invocationLogPath = join(options.runtimeRoot, options.invocationLogName);

  mkdirSync(binDir, { recursive: true, mode: 0o700 });
  mkdirSync(fixtureDir, { recursive: true, mode: 0o700 });
  copyFileSync(resolve(options.shimSource), shimPath);
  copyFileSync(resolve(options.fixtureSource), fixturePath);
  writeFileSync(invocationLogPath, '', { mode: 0o600 });
  chmodSync(binDir, 0o700);
  chmodSync(fixtureDir, 0o700);
  chmodSync(shimPath, 0o700);
  chmodSync(fixturePath, 0o600);
  chmodSync(invocationLogPath, 0o600);

  return {
    kind: options.kind,
    binary: options.binary,
    runtimeRoot: options.runtimeRoot,
    binDir,
    fixtureDir,
    shimPath,
    fixturePath,
    invocationLogPath,
    path: options.inheritedPath ? `${binDir}${delimiter}${options.inheritedPath}` : binDir,
    env: {
      [options.invocationEnv]: invocationLogPath,
      [options.fixtureEnv]: fixturePath,
    },
  };
}

/** Install the recon fixture entirely inside one temporary evaluation runtime. */
export function installHermeticReconTooling(runtimeRoot: string, inheritedPath = ''): HermeticReconTooling {
  return installHermeticToolFixture({
    kind: 'nmap-recon',
    binary: 'nmap',
    runtimeRoot,
    inheritedPath,
    shimSource: './src/test-support/fixtures/nmap-shim.mjs',
    fixtureSource: './src/test-support/fixtures/nmap-recon-10.10.10.10.xml',
    fixtureName: 'nmap-recon.xml',
    invocationLogName: 'nmap-invocations.ndjson',
    invocationEnv: 'OVERWATCH_EVAL_NMAP_INVOCATION_LOG',
    fixtureEnv: 'OVERWATCH_EVAL_NMAP_FIXTURE_FILE',
  }) as HermeticReconTooling;
}

/** Install a no-network nuclei fixture for the synthetic web target. */
export function installHermeticWebTooling(runtimeRoot: string, inheritedPath = ''): HermeticEvalTooling {
  return installHermeticToolFixture({
    kind: 'nuclei-web',
    binary: 'nuclei',
    runtimeRoot,
    inheritedPath,
    shimSource: './src/test-support/fixtures/nuclei-shim.mjs',
    fixtureSource: './src/test-support/fixtures/nuclei-web-10.10.10.20.jsonl',
    fixtureName: 'nuclei-web.jsonl',
    invocationLogName: 'nuclei-invocations.ndjson',
    invocationEnv: 'OVERWATCH_EVAL_NUCLEI_INVOCATION_LOG',
    fixtureEnv: 'OVERWATCH_EVAL_NUCLEI_FIXTURE_FILE',
  });
}

/** Install a no-network AWS STS fixture for the synthetic cloud credential. */
export function installHermeticCloudTooling(runtimeRoot: string, inheritedPath = ''): HermeticEvalTooling {
  return installHermeticToolFixture({
    kind: 'aws-sts-cloud',
    binary: 'aws',
    runtimeRoot,
    inheritedPath,
    shimSource: './src/test-support/fixtures/aws-shim.mjs',
    fixtureSource: './src/test-support/fixtures/aws-sts-cloud.json',
    fixtureName: 'aws-sts-cloud.json',
    invocationLogName: 'aws-invocations.ndjson',
    invocationEnv: 'OVERWATCH_EVAL_AWS_INVOCATION_LOG',
    fixtureEnv: 'OVERWATCH_EVAL_AWS_FIXTURE_FILE',
  });
}

export function installHermeticEvalTooling(
  kind: HermeticToolingKind,
  runtimeRoot: string,
  inheritedPath = '',
): HermeticEvalTooling {
  switch (kind) {
    case 'nmap-recon': return installHermeticReconTooling(runtimeRoot, inheritedPath);
    case 'nuclei-web': return installHermeticWebTooling(runtimeRoot, inheritedPath);
    case 'aws-sts-cloud': return installHermeticCloudTooling(runtimeRoot, inheritedPath);
  }
}

export function readHermeticToolInvocations(path: string): HermeticToolInvocation[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(line => line.trim().length > 0)
    .map(line => JSON.parse(line) as HermeticToolInvocation);
}

export function readHermeticNmapInvocations(path: string): HermeticNmapInvocation[] {
  return readHermeticToolInvocations(path) as HermeticNmapInvocation[];
}
