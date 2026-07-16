import { execFileSync } from 'node:child_process';
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const repository = resolve('.');
const setupScript = join(repository, 'scripts', 'setup.mjs');
const template = join(repository, 'engagement-templates', 'ctf.json');

describe('daemon setup', () => {
  let directory = '';

  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
  });

  it('preserves the engagement and unrelated MCP servers while creating shared wiring', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-daemon-'));
    const engagement = {
      id: 'existing-engagement',
      name: 'Existing engagement',
      created_at: '2026-07-16T00:00:00.000Z',
      scope: { cidrs: ['10.1.0.0/24'], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.7 },
    };
    writeFileSync(
      join(directory, 'engagement.json'),
      `${JSON.stringify(engagement, null, 2)}\n`,
    );
    writeFileSync(
      join(directory, '.mcp.json'),
      `${JSON.stringify({
        mcpServers: {
          github: { type: 'http', url: 'https://example.test/mcp' },
          overwatch: { command: 'old-overwatch' },
        },
      }, null, 2)}\n`,
    );

    execFileSync(process.execPath, [
      setupScript,
      '--daemon',
      '--template',
      template,
    ], {
      cwd: repository,
      env: {
        ...process.env,
        OVERWATCH_SETUP_ROOT: directory,
        OVERWATCH_HTTP_PORT: '3210',
      },
      stdio: 'pipe',
    });

    expect(JSON.parse(readFileSync(join(directory, 'engagement.json'), 'utf8')))
      .toEqual(engagement);
    const mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.github).toEqual({
      type: 'http',
      url: 'https://example.test/mcp',
    });
    expect(mcp.mcpServers.overwatch).toMatchObject({
      type: 'http',
      url: 'http://127.0.0.1:3210/mcp',
    });
    const authorization = mcp.mcpServers.overwatch.headers.Authorization as string;
    const token = readFileSync(join(directory, '.overwatch-mcp-token'), 'utf8');
    expect(authorization).toBe(`Bearer ${token}`);
    expect(statSync(join(directory, '.mcp.json')).mode & 0o777).toBe(0o600);
    expect(statSync(join(directory, '.overwatch-mcp-token')).mode & 0o777).toBe(0o600);
  });

  it('redacts the generated bearer token during dry-run', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-dry-run-'));
    const output = execFileSync(process.execPath, [
      setupScript,
      '--daemon',
      '--dry-run',
      '--template',
      template,
    ], {
      cwd: repository,
      env: {
        ...process.env,
        OVERWATCH_SETUP_ROOT: directory,
      },
      encoding: 'utf8',
    });

    expect(output).toContain('Bearer <redacted>');
    expect(output).not.toMatch(/Bearer [a-f0-9]{64}/);
  });
});
