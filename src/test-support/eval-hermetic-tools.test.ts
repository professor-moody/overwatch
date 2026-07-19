import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import {
  HERMETIC_CLOUD_ARN,
  HERMETIC_RECON_TARGET,
  HERMETIC_WEB_TARGET,
  installHermeticCloudTooling,
  installHermeticReconTooling,
  installHermeticWebTooling,
  readHermeticNmapInvocations,
  readHermeticToolInvocations,
} from './eval-hermetic-tools.js';

function expectNoNetworkImports(sourcePath: string): void {
  const shimSource = readFileSync(resolve(sourcePath), 'utf8');
  expect(shimSource).not.toMatch(/node:(?:child_process|cluster|dgram|dns|http|https|net|tls)/u);
  expect(shimSource).not.toContain('fetch(');
}

describe('hermetic recon evaluation tooling', () => {
  it('runs only the synthetic target fixture and records that no network occurred', () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'ow-hermetic-recon-'));
    try {
      const tooling = installHermeticReconTooling(sandbox, process.env.PATH ?? '');
      const result = spawnSync('nmap', ['-sV', '-oX', '-', HERMETIC_RECON_TARGET], {
        encoding: 'utf8',
        env: { ...process.env, PATH: tooling.path, ...tooling.env },
      });

      expect(result.status).toBe(0);
      expect(result.stdout).toContain('<address addr="10.10.10.10" addrtype="ipv4"/>');
      expect(result.stdout).toContain('<service name="ssh"');
      expect(result.stdout).toContain('<service name="http"');
      expect(readHermeticNmapInvocations(tooling.invocationLogPath)).toEqual([
        expect.objectContaining({
          shim: 'overwatch-hermetic-nmap',
          argv: ['-sV', '-oX', '-', HERMETIC_RECON_TARGET],
          expected_target: HERMETIC_RECON_TARGET,
          network_activity: false,
        }),
      ]);
      expect(statSync(tooling.binDir).mode & 0o777).toBe(0o700);
      expect(statSync(tooling.shimPath).mode & 0o777).toBe(0o700);
      expect(statSync(tooling.invocationLogPath).mode & 0o777).toBe(0o600);

      expectNoNetworkImports('./src/test-support/fixtures/nmap-shim.mjs');
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });

  it('refuses any target other than the dedicated synthetic fixture', () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'ow-hermetic-recon-refuse-'));
    try {
      const tooling = installHermeticReconTooling(sandbox, process.env.PATH ?? '');
      const result = spawnSync('nmap', ['-sV', '192.0.2.10'], {
        encoding: 'utf8',
        env: { ...process.env, PATH: tooling.path, ...tooling.env },
      });
      expect(result.status).toBe(64);
      expect(result.stdout).toBe('');
      expect(result.stderr).toContain(`only accepts ${HERMETIC_RECON_TARGET}`);
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });
});

describe('hermetic web evaluation tooling', () => {
  it('returns only the synthetic nuclei result and records no network activity', () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'ow-hermetic-web-'));
    try {
      const tooling = installHermeticWebTooling(sandbox, process.env.PATH ?? '');
      const result = spawnSync('nuclei', ['-u', HERMETIC_WEB_TARGET, '-jsonl'], {
        encoding: 'utf8',
        env: { ...process.env, PATH: tooling.path, ...tooling.env },
      });

      expect(result.status).toBe(0);
      expect(result.stdout).toContain('exposed-admin-panel');
      expect(result.stdout).toContain(`${HERMETIC_WEB_TARGET}/admin`);
      expect(readHermeticToolInvocations(tooling.invocationLogPath)).toEqual([
        expect.objectContaining({
          shim: 'overwatch-hermetic-nuclei',
          argv: ['-u', HERMETIC_WEB_TARGET, '-jsonl'],
          expected_target: HERMETIC_WEB_TARGET,
          network_activity: false,
        }),
      ]);
      expect(statSync(tooling.shimPath).mode & 0o777).toBe(0o700);
      expect(statSync(tooling.fixturePath).mode & 0o777).toBe(0o600);
      expect(statSync(tooling.invocationLogPath).mode & 0o777).toBe(0o600);
      expectNoNetworkImports('./src/test-support/fixtures/nuclei-shim.mjs');
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });

  it('refuses any target or argument sequence outside the fixture command', () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'ow-hermetic-web-refuse-'));
    try {
      const tooling = installHermeticWebTooling(sandbox, process.env.PATH ?? '');
      const result = spawnSync('nuclei', ['-u', 'http://192.0.2.20', '-jsonl'], {
        encoding: 'utf8',
        env: { ...process.env, PATH: tooling.path, ...tooling.env },
      });
      expect(result.status).toBe(64);
      expect(result.stdout).toBe('');
      expect(result.stderr).toContain(`only accepts -u ${HERMETIC_WEB_TARGET} -jsonl`);
      expect(readHermeticToolInvocations(tooling.invocationLogPath)).toEqual([]);
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });
});

describe('hermetic cloud evaluation tooling', () => {
  it('returns only the synthetic STS identity and records no network activity', () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'ow-hermetic-cloud-'));
    try {
      const tooling = installHermeticCloudTooling(sandbox, process.env.PATH ?? '');
      const argv = ['sts', 'get-caller-identity', '--output', 'json'];
      const result = spawnSync('aws', argv, {
        encoding: 'utf8',
        env: { ...process.env, PATH: tooling.path, ...tooling.env },
      });

      expect(result.status).toBe(0);
      expect(JSON.parse(result.stdout)).toMatchObject({ Arn: HERMETIC_CLOUD_ARN });
      expect(readHermeticToolInvocations(tooling.invocationLogPath)).toEqual([
        expect.objectContaining({
          shim: 'overwatch-hermetic-aws',
          argv,
          expected_command: argv,
          network_activity: false,
        }),
      ]);
      expect(statSync(tooling.shimPath).mode & 0o777).toBe(0o700);
      expect(statSync(tooling.fixturePath).mode & 0o777).toBe(0o600);
      expect(statSync(tooling.invocationLogPath).mode & 0o777).toBe(0o600);
      expectNoNetworkImports('./src/test-support/fixtures/aws-shim.mjs');
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });

  it('refuses every AWS command except the fixed caller-identity invocation', () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'ow-hermetic-cloud-refuse-'));
    try {
      const tooling = installHermeticCloudTooling(sandbox, process.env.PATH ?? '');
      const result = spawnSync('aws', ['s3', 'ls'], {
        encoding: 'utf8',
        env: { ...process.env, PATH: tooling.path, ...tooling.env },
      });
      expect(result.status).toBe(64);
      expect(result.stdout).toBe('');
      expect(result.stderr).toContain('only accepts sts get-caller-identity --output json');
      expect(readHermeticToolInvocations(tooling.invocationLogPath)).toEqual([]);
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });
});
