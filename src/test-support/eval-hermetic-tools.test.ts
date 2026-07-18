import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import {
  HERMETIC_RECON_TARGET,
  installHermeticReconTooling,
  readHermeticNmapInvocations,
} from './eval-hermetic-tools.js';

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

      const shimSource = readFileSync(resolve('./src/test-support/fixtures/nmap-shim.mjs'), 'utf8');
      expect(shimSource).not.toMatch(/node:(?:child_process|cluster|dgram|dns|http|https|net|tls)/u);
      expect(shimSource).not.toContain('fetch(');
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
