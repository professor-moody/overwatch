import { execFileSync } from 'node:child_process';
import {
  mkdirSync,
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

  it('uses shared-daemon wiring by default', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-default-'));
    execFileSync(process.execPath, [
      setupScript,
      '--template',
      template,
    ], {
      cwd: repository,
      env: {
        ...process.env,
        OVERWATCH_SETUP_ROOT: directory,
      },
      stdio: 'pipe',
    });

    const mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.overwatch).toMatchObject({
      type: 'http',
      url: 'http://127.0.0.1:3000/mcp',
    });
    expect(readFileSync(join(directory, '.overwatch-mcp-token'), 'utf8'))
      .toMatch(/^[a-f0-9]{64}$/);
  });

  it('retains an explicit private stdio compatibility mode', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-stdio-'));
    execFileSync(process.execPath, [
      setupScript,
      '--stdio',
      '--template',
      template,
    ], {
      cwd: repository,
      env: {
        ...process.env,
        OVERWATCH_SETUP_ROOT: directory,
      },
      stdio: 'pipe',
    });

    const mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.overwatch).toMatchObject({
      command: 'node',
      args: [join(directory, 'dist', 'index.js')],
    });
    expect(() => readFileSync(join(directory, '.overwatch-mcp-token'), 'utf8')).toThrow();
  });

  it('switches daemon to stdio and back without changing engagement or user settings', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-roundtrip-'));
    const engagementText = `${JSON.stringify({
      id: 'preserved-roundtrip',
      name: 'Preserved roundtrip',
      created_at: '2026-07-16T00:00:00.000Z',
      engagement_nonce: 'a'.repeat(64),
      scope: { cidrs: ['10.9.0.0/24'], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.7 },
    }, null, 2)}\n`;
    const settingsText = `${JSON.stringify({
      permissions: { allow: ['mcp__other__read'] },
      hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'custom-hook' }] }] },
    }, null, 2)}\n`;
    writeFileSync(join(directory, 'engagement.json'), engagementText);
    mkdirSync(join(directory, '.claude'), { recursive: true });
    writeFileSync(join(directory, '.claude', 'settings.json'), settingsText);
    writeFileSync(join(directory, '.mcp.json'), `${JSON.stringify({
      mcpServers: { other: { type: 'http', url: 'https://example.test/mcp' } },
    }, null, 2)}\n`);

    const runSetup = (args: string[]) => execFileSync(process.execPath, [
      setupScript,
      ...args,
      '--template',
      template,
    ], {
      cwd: repository,
      env: {
        ...process.env,
        OVERWATCH_SETUP_ROOT: directory,
        OVERWATCH_MCP_TOKEN: '',
      },
      stdio: 'pipe',
    });

    runSetup([]);
    runSetup(['--stdio']);
    expect(readFileSync(join(directory, 'engagement.json'), 'utf8')).toBe(engagementText);
    expect(readFileSync(join(directory, '.claude', 'settings.json'), 'utf8')).toBe(settingsText);
    let mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.other).toBeDefined();
    expect(mcp.mcpServers.overwatch).toMatchObject({
      command: 'node',
      args: [join(directory, 'dist', 'index.js')],
    });

    runSetup([]);
    expect(readFileSync(join(directory, 'engagement.json'), 'utf8')).toBe(engagementText);
    expect(readFileSync(join(directory, '.claude', 'settings.json'), 'utf8')).toBe(settingsText);
    mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.other).toBeDefined();
    expect(mcp.mcpServers.overwatch).toMatchObject({
      type: 'http',
      url: 'http://127.0.0.1:3000/mcp',
    });
  });

  it('uses the exported daemon token as the shared authentication authority', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-env-token-'));
    const token = 'externally-managed-daemon-token';
    execFileSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: {
        ...process.env,
        OVERWATCH_SETUP_ROOT: directory,
        OVERWATCH_MCP_TOKEN: token,
      },
      stdio: 'pipe',
    });

    const mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.overwatch.headers.Authorization).toBe(`Bearer ${token}`);
    expect(readFileSync(join(directory, '.overwatch-mcp-token'), 'utf8')).toBe(token);
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

  it('keeps empty-scope first-run guidance safe for durable engagement state', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-empty-scope-'));
    const output = execFileSync(process.execPath, [
      setupScript,
      '--template',
      template,
    ], {
      cwd: repository,
      env: {
        ...process.env,
        OVERWATCH_SETUP_ROOT: directory,
        OVERWATCH_MCP_TOKEN: '',
      },
      encoding: 'utf8',
    });

    expect(output).toContain('safe to start; add scope after launch');
    expect(output).toContain('update is journaled');
    expect(output).not.toContain('--force');
    expect(output).not.toContain('Edit engagement.json');
    expect(output).not.toContain('add scope first');
  });
});
