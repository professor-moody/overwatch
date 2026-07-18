import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const repository = resolve('.');
const setupScript = join(repository, 'scripts', 'setup.mjs');
const doctorScript = join(repository, 'scripts', 'doctor.mjs');
const template = join(repository, 'engagement-templates', 'ctf.json');
const sanitizedProcessEnv = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !key.startsWith('OVERWATCH_')),
);
function engagementConfig(id: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    name: id,
    created_at: '2026-07-17T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
    ...overrides,
  };
}

function durableState(id: string, marker?: string, overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    config: engagementConfig(id, overrides),
    graph: { attributes: {}, nodes: [], edges: [] },
    marker,
  });
}
const blockedSetupCases: Array<[string, (root: string) => void]> = [
  ['ambiguous state', (root) => {
    writeFileSync(join(root, 'state-one.json'), durableState('one'));
    writeFileSync(join(root, 'state-two.json'), durableState('two'));
  }],
  ['WAL only', (root) => {
    writeFileSync(join(root, 'state-wal-only.journal.jsonl'), 'preserve WAL bytes\n');
  }],
  ['migration backup only', (root) => {
    mkdirSync(join(root, '.migration-backups', 'backup-1'), { recursive: true });
    writeFileSync(join(root, '.migration-backups', 'backup-1', 'manifest.json'), '{}');
  }],
  ['config write intent only', (root) => {
    writeFileSync(join(root, 'engagement.json.write-intent.json'), '{}');
  }],
  ['atomic config temp only', (root) => {
    writeFileSync(join(root, 'engagement.json.tmp-123-complete'), '{"preserve":true}');
  }],
  ['atomic config-intent temp only', (root) => {
    writeFileSync(join(root, 'engagement.json.write-intent.json.tmp-123-complete'), '{}');
  }],
];

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
        ...sanitizedProcessEnv,
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
    const profilePath = join(directory, '.overwatch-runtime', 'profile.json');
    const profile = JSON.parse(readFileSync(profilePath, 'utf8'));
    expect(profile).toMatchObject({
      schema_version: 1,
      mode: 'daemon',
      config_path: join(directory, 'engagement.json'),
      state_file_path: join(directory, 'state-existing-engagement.json'),
      mcp_token_file: join(directory, '.overwatch-mcp-token'),
      mcp_config_path: join(directory, '.mcp.json'),
      http_port: 3210,
      dashboard_port: 8384,
    });
    expect(statSync(profilePath).mode & 0o777).toBe(0o600);
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
        ...sanitizedProcessEnv,
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
    expect(JSON.parse(readFileSync(
      join(directory, '.overwatch-runtime', 'profile.json'),
      'utf8',
    ))).toMatchObject({
      mode: 'daemon',
      config_path: join(directory, 'engagement.json'),
      state_file_path: expect.stringContaining('state-'),
    });
  });

  it('doctor reports a malformed runtime profile without a raw module crash', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-doctor-invalid-profile-'));
    const profileDirectory = join(directory, '.overwatch-runtime');
    mkdirSync(profileDirectory);
    writeFileSync(join(profileDirectory, 'profile.json'), '{broken json');

    const result = spawnSync(process.execPath, [doctorScript], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_DOCTOR_ROOT: directory },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('FAIL Runtime profile');
    expect(result.stdout).toContain('Run `npm run setup` to repair local wiring');
    expect(result.stderr).not.toContain('node:internal/modules/run_main');
  });

  it('doctor diagnoses a conflicting inherited runtime override', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-doctor-profile-conflict-'));
    execFileSync(process.execPath, [setupScript, '--daemon', '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      stdio: 'pipe',
    });

    const result = spawnSync(process.execPath, [doctorScript], {
      cwd: repository,
      env: {
        ...sanitizedProcessEnv,
        OVERWATCH_DOCTOR_ROOT: directory,
        OVERWATCH_CONFIG: join(directory, 'different-engagement.json'),
      },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('FAIL Runtime profile');
    expect(result.stdout).toContain('OVERWATCH_CONFIG conflicts with the persisted runtime profile');
  });

  it('retains external config/state, custom ports, and remote token authority on a plain rerun', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-profile-rerun-'));
    const setupRoot = join(directory, 'checkout');
    const external = join(directory, 'operator-state');
    mkdirSync(setupRoot);
    mkdirSync(external);
    const configPath = join(external, 'custom-engagement.json');
    const statePath = join(external, 'custom-state.json');
    writeFileSync(configPath, `${JSON.stringify(engagementConfig('external-profile'))}\n`);
    writeFileSync(statePath, durableState('external-profile', 'preserve'));

    const firstEnvironment = {
      ...sanitizedProcessEnv,
      OVERWATCH_SETUP_ROOT: setupRoot,
      OVERWATCH_CONFIG: configPath,
      OVERWATCH_STATE_FILE: statePath,
      OVERWATCH_HTTP_HOST: '0.0.0.0',
      OVERWATCH_HTTP_PORT: '43210',
      OVERWATCH_DASHBOARD_HOST: '0.0.0.0',
      OVERWATCH_DASHBOARD_PORT: '43211',
      OVERWATCH_DASHBOARD_TOKEN: 'remote-dashboard-authority',
    };
    execFileSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: firstEnvironment,
      stdio: 'pipe',
    });
    const profilePath = join(setupRoot, '.overwatch-runtime', 'profile.json');
    const firstProfile = JSON.parse(readFileSync(profilePath, 'utf8'));
    const firstConfig = readFileSync(configPath);
    const firstState = readFileSync(statePath);

    execFileSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: {
        ...sanitizedProcessEnv,
        OVERWATCH_SETUP_ROOT: setupRoot,
      },
      stdio: 'pipe',
    });

    const secondProfile = JSON.parse(readFileSync(profilePath, 'utf8'));
    expect(secondProfile).toMatchObject({
      config_path: configPath,
      state_file_path: statePath,
      http_host: '0.0.0.0',
      http_port: 43210,
      dashboard_host: '0.0.0.0',
      dashboard_port: 43211,
      dashboard_token_file: firstProfile.dashboard_token_file,
    });
    expect(readFileSync(secondProfile.dashboard_token_file, 'utf8'))
      .toBe('remote-dashboard-authority');
    expect(readFileSync(configPath)).toEqual(firstConfig);
    expect(readFileSync(statePath)).toEqual(firstState);
    expect(JSON.parse(readFileSync(join(setupRoot, '.mcp.json'), 'utf8'))
      .mcpServers.overwatch.url).toBe('http://127.0.0.1:43210/mcp');
  });

  it('replaces reordered legacy managed hooks instead of duplicating them', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-hook-upgrade-'));
    execFileSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      stdio: 'pipe',
    });
    const settingsPath = join(directory, '.claude', 'settings.json');
    const settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
    const managed = settings.hooks.PreToolUse[0];
    settings.hooks.PreToolUse.unshift({
      hooks: managed.hooks.map((hook: Record<string, unknown>) => ({
        args: hook.args,
        command: hook.command,
        type: hook.type,
      })),
      matcher: managed.matcher,
    });
    writeFileSync(settingsPath, `${JSON.stringify(settings, null, 2)}\n`);

    execFileSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      stdio: 'pipe',
    });
    const repaired = JSON.parse(readFileSync(settingsPath, 'utf8'));
    expect(repaired.hooks.PreToolUse).toHaveLength(2);
    expect(JSON.stringify(repaired).match(/overwatch-bash-guard\.mjs/g)).toHaveLength(1);
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
        ...sanitizedProcessEnv,
        OVERWATCH_SETUP_ROOT: directory,
      },
      stdio: 'pipe',
    });

    const mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.overwatch).toMatchObject({
      command: 'node',
      args: [join(repository, 'scripts', 'daemon-lifecycle.mjs'), 'run-stdio'],
      env: {
        OVERWATCH_RUNTIME_PROFILE: join(directory, '.overwatch-runtime', 'profile.json'),
      },
    });
    expect(() => readFileSync(join(directory, '.overwatch-mcp-token'), 'utf8')).toThrow();
  });

  it('refuses a private stdio writer until setup has published its runtime profile', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-stdio-no-profile-'));
    const runtimeDirectory = join(directory, '.overwatch-runtime');
    const result = spawnSync(process.execPath, [
      join(repository, 'scripts', 'daemon-lifecycle.mjs'),
      'run-stdio',
    ], {
      cwd: repository,
      env: {
        ...sanitizedProcessEnv,
        OVERWATCH_RUNTIME_PROFILE: join(runtimeDirectory, 'profile.json'),
        OVERWATCH_DAEMON_RECORD: join(runtimeDirectory, 'daemon.json'),
        OVERWATCH_DAEMON_LOG: join(runtimeDirectory, 'daemon.log'),
      },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('persisted runtime profile');
    expect(result.stderr).toContain('Run `npm run setup`');
    expect(existsSync(join(runtimeDirectory, 'profile.json'))).toBe(false);
  });

  it('switches daemon to stdio and back while merging hooks without duplicating user settings', () => {
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
        ...sanitizedProcessEnv,
        OVERWATCH_SETUP_ROOT: directory,
        OVERWATCH_MCP_TOKEN: '',
      },
      stdio: 'pipe',
    });

    runSetup([]);
    const settingsAfterFirstSetup = readFileSync(join(directory, '.claude', 'settings.json'), 'utf8');
    runSetup(['--stdio']);
    expect(readFileSync(join(directory, 'engagement.json'), 'utf8')).toBe(engagementText);
    expect(readFileSync(join(directory, '.claude', 'settings.json'), 'utf8')).toBe(settingsAfterFirstSetup);
    const settings = JSON.parse(settingsAfterFirstSetup);
    expect(settings.permissions).toEqual({ allow: ['mcp__other__read'] });
    expect(settings.hooks.SessionStart).toContainEqual(
      expect.objectContaining({ hooks: [expect.objectContaining({ command: 'custom-hook' })] }),
    );
    expect(settings.hooks.UserPromptSubmit).toHaveLength(1);
    expect(settings.hooks.PreToolUse).toHaveLength(2);
    expect(settings.hooks.PostToolUse).toHaveLength(2);
    expect(settings.hooks.PreCompact).toHaveLength(1);
    expect(settings.hooks.Stop).toHaveLength(1);
    let mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.other).toBeDefined();
    expect(mcp.mcpServers.overwatch).toMatchObject({
      command: 'node',
      args: [join(repository, 'scripts', 'daemon-lifecycle.mjs'), 'run-stdio'],
    });

    runSetup([]);
    expect(readFileSync(join(directory, 'engagement.json'), 'utf8')).toBe(engagementText);
    expect(readFileSync(join(directory, '.claude', 'settings.json'), 'utf8')).toBe(settingsAfterFirstSetup);
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
        ...sanitizedProcessEnv,
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
        ...sanitizedProcessEnv,
        OVERWATCH_SETUP_ROOT: directory,
      },
      encoding: 'utf8',
    });

    expect(output).toContain('Bearer <redacted>');
    expect(output).not.toMatch(/Bearer [a-f0-9]{64}/);
    expect(readdirSync(directory)).toEqual([]);
  });

  it('refuses malformed Claude settings before publishing any client wiring', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-invalid-settings-'));
    const engagementText = `${JSON.stringify(engagementConfig('invalid-settings'))}\n`;
    const stateText = durableState('invalid-settings', 'preserved');
    writeFileSync(join(directory, 'engagement.json'), engagementText);
    writeFileSync(join(directory, 'state-invalid-settings.json'), stateText);
    mkdirSync(join(directory, '.claude'));
    writeFileSync(join(directory, '.claude', 'settings.json'), '{ malformed settings');

    const result = spawnSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Refusing partial setup');
    expect(readFileSync(join(directory, 'engagement.json'), 'utf8')).toBe(engagementText);
    expect(readFileSync(join(directory, 'state-invalid-settings.json'), 'utf8')).toBe(stateText);
    expect(existsSync(join(directory, '.mcp.json'))).toBe(false);
    expect(existsSync(join(directory, '.overwatch-mcp-token'))).toBe(false);
    expect(existsSync(join(directory, '.overwatch-runtime'))).toBe(false);
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
        ...sanitizedProcessEnv,
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

  it('never lets --force replace an existing engagement or state', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-force-safe-'));
    const engagementText = '{"id":"force-safe","name":"Force safe","created_at":"2026-07-17T00:00:00.000Z","scope":{"cidrs":[],"domains":[],"exclusions":[]},"objectives":[],"opsec":{"name":"pentest","max_noise":1}}\n';
    const stateText = `${durableState('force-safe', 'must survive', { name: 'Force safe' })}\n`;
    const settingsText = '{"permissions":{"allow":["custom-user-setting"]}}\n';
    writeFileSync(join(directory, 'engagement.json'), engagementText);
    writeFileSync(join(directory, 'state-force-safe.json'), stateText);
    mkdirSync(join(directory, '.claude'));
    writeFileSync(join(directory, '.claude', 'settings.json'), settingsText);

    execFileSync(process.execPath, [setupScript, '--force', '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      stdio: 'pipe',
    });

    expect(readFileSync(join(directory, 'engagement.json'), 'utf8')).toBe(engagementText);
    expect(readFileSync(join(directory, 'state-force-safe.json'), 'utf8')).toBe(stateText);
    const mergedSettings = JSON.parse(readFileSync(join(directory, '.claude', 'settings.json'), 'utf8'));
    expect(mergedSettings.permissions).toEqual({ allow: ['custom-user-setting'] });
    expect(mergedSettings.hooks.UserPromptSubmit).toHaveLength(1);
  });

  it('configures recovery wiring without creating a competing config', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-recovery-'));
    const statePath = join(directory, 'state-recovery.json');
    const stateText = `${durableState('recovery', 'preserved')}\n`;
    const ownerPath = `${statePath}.runtime-owner.json`;
    const ownerBytes = Buffer.from('{"operational":"preserve"}\n');
    writeFileSync(statePath, stateText);
    writeFileSync(ownerPath, ownerBytes);

    const output = execFileSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(output).toContain('recovery wiring configured');
    expect(output).toContain(`OVERWATCH_STATE_FILE=${JSON.stringify(statePath)}`);
    expect(existsSync(join(directory, 'engagement.json'))).toBe(false);
    expect(readFileSync(statePath, 'utf8')).toBe(stateText);
    expect(readFileSync(ownerPath)).toEqual(ownerBytes);
    expect(existsSync(join(directory, '.mcp.json'))).toBe(true);
    expect(JSON.parse(readFileSync(
      join(directory, '.overwatch-runtime', 'profile.json'),
      'utf8',
    ))).toMatchObject({
      config_path: join(directory, 'engagement.json'),
      state_file_path: statePath,
    });
  });

  it.each(blockedSetupCases)('refuses %s before writing any setup file', (_label, arrange) => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-blocked-'));
    arrange(directory);
    const before = new Map(
      readdirSync(directory).map(name => [name, readFileIfRegular(join(directory, name))]),
    );

    const result = spawnSync(process.execPath, [setupScript, '--force', '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Refusing to create engagement.json');
    expect(existsSync(join(directory, 'engagement.json'))).toBe(false);
    expect(existsSync(join(directory, '.mcp.json'))).toBe(false);
    expect(existsSync(join(directory, '.overwatch-mcp-token'))).toBe(false);
    for (const [name, bytes] of before) {
      expect(readFileIfRegular(join(directory, name))).toEqual(bytes);
    }
  });

  it('wires a retained snapshot-only base without publishing a config', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-snapshot-recovery-'));
    const snapshotDirectory = join(directory, '.snapshots');
    const snapshotPath = join(snapshotDirectory, 'state-snapshot.snap-2026-07-17.json');
    const statePath = join(directory, 'state-snapshot.json');
    const snapshotBytes = Buffer.from(`${durableState('snapshot', 'preserved')}\n`);
    mkdirSync(snapshotDirectory, { recursive: true });
    writeFileSync(snapshotPath, snapshotBytes);

    const output = execFileSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(output).toContain(`recovery wiring configured for preserved state ${statePath}`);
    expect(existsSync(join(directory, 'engagement.json'))).toBe(false);
    expect(existsSync(statePath)).toBe(false);
    expect(readFileSync(snapshotPath)).toEqual(snapshotBytes);
  });

  it('honors an explicit state selection when several valid families remain', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-explicit-recovery-'));
    const firstPath = join(directory, 'state-first.json');
    const selectedPath = join(directory, 'state-selected.json');
    const selectedBytes = Buffer.from(`${durableState('selected', 'preserved')}\n`);
    writeFileSync(firstPath, durableState('first'));
    writeFileSync(selectedPath, selectedBytes);

    const output = execFileSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: {
        ...sanitizedProcessEnv,
        OVERWATCH_SETUP_ROOT: directory,
        OVERWATCH_STATE_FILE: selectedPath,
      },
      encoding: 'utf8',
    });

    expect(output).toContain(`recovery wiring configured for preserved state ${selectedPath}`);
    expect(existsSync(join(directory, 'engagement.json'))).toBe(false);
    expect(readFileSync(selectedPath)).toEqual(selectedBytes);
  });

  it('refuses a stale active config that does not match preserved state', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-stale-config-'));
    const configPath = join(directory, 'engagement.json');
    const configBytes = Buffer.from(JSON.stringify(engagementConfig('stale', {
      created_at: '2026-07-18T00:00:00.000Z',
      engagement_nonce: 'b'.repeat(64),
    })));
    const statePath = join(directory, 'state-original.json');
    const stateBytes = Buffer.from(durableState('original', 'preserved', {
      engagement_nonce: 'a'.repeat(64),
    }));
    writeFileSync(configPath, configBytes);
    writeFileSync(statePath, stateBytes);

    const result = spawnSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('active config does not match any');
    expect(readFileSync(configPath)).toEqual(configBytes);
    expect(readFileSync(statePath)).toEqual(stateBytes);
    expect(existsSync(join(directory, '.mcp.json'))).toBe(false);
  });

  it('selects state by immutable identity when the config id changed', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-identity-match-'));
    const nonce = 'a'.repeat(64);
    const configPath = join(directory, 'engagement.json');
    const statePath = join(directory, 'state-original.json');
    const configBytes = Buffer.from(JSON.stringify(engagementConfig('renamed', {
      engagement_nonce: nonce,
    })));
    writeFileSync(configPath, configBytes);
    writeFileSync(statePath, durableState('original', 'preserved', {
      engagement_nonce: nonce,
    }));

    const output = execFileSync(process.execPath, [setupScript, '--stdio', '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    const profile = JSON.parse(readFileSync(
      join(directory, '.overwatch-runtime', 'profile.json'),
      'utf8',
    ));
    expect(profile.state_file_path).toBe(statePath);
    expect(output).toContain('active config and durable state have different semantics');
    expect(readFileSync(configPath)).toEqual(configBytes);
  });

  it('surfaces same-id semantic divergence as read-only recovery', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-semantic-divergence-'));
    const configPath = join(directory, 'engagement.json');
    const statePath = join(directory, 'state-shared.json');
    const configBytes = Buffer.from(JSON.stringify(engagementConfig('shared', {
      scope: { cidrs: [], domains: ['file.example'], exclusions: [] },
    })));
    const stateBytes = Buffer.from(durableState('shared', 'preserved', {
      scope: { cidrs: [], domains: ['state.example'], exclusions: [] },
    }));
    writeFileSync(configPath, configBytes);
    writeFileSync(statePath, stateBytes);

    const output = execFileSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(output).toContain('active config and durable state have different semantics');
    expect(output).toContain('daemon will start read-only');
    expect(readFileSync(configPath)).toEqual(configBytes);
    expect(readFileSync(statePath)).toEqual(stateBytes);
  });

  it('wires a matching state family without claiming authority when retained bases disagree', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-base-authority-'));
    const configPath = join(directory, 'engagement.json');
    const statePath = join(directory, 'state-family.json');
    const snapshots = join(directory, '.snapshots');
    mkdirSync(snapshots);
    writeFileSync(configPath, JSON.stringify(engagementConfig('snapshot')));
    writeFileSync(statePath, durableState('primary', 'stale'));
    writeFileSync(
      join(snapshots, 'state-family.snap-2026-07-18T00-00-00-000Z.json'),
      durableState('snapshot', 'newer'),
    );

    const output = execFileSync(process.execPath, [setupScript, '--stdio', '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    const profile = JSON.parse(readFileSync(
      join(directory, '.overwatch-runtime', 'profile.json'),
      'utf8',
    ));
    expect(profile.state_file_path).toBe(statePath);
    expect(output).toContain('retained bases do not establish one configuration authority (legacy_unverified)');
    expect(output).toContain('startup will remain recovery/read-only');
    expect(output).not.toContain('active config and durable state have different semantics');
  });

  it('scans beside an external config instead of selecting checkout-local state', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-external-config-'));
    const external = join(directory, 'external');
    mkdirSync(external);
    const externalConfig = join(external, 'engagement.json');
    const externalState = join(external, 'state-external.json');
    writeFileSync(join(directory, 'state-unrelated.json'), durableState('unrelated'));
    writeFileSync(externalState, durableState('external', 'preserved'));

    const output = execFileSync(process.execPath, [setupScript, '--stdio', '--template', template], {
      cwd: repository,
      env: {
        ...sanitizedProcessEnv,
        OVERWATCH_SETUP_ROOT: directory,
        OVERWATCH_CONFIG: externalConfig,
      },
      encoding: 'utf8',
    });

    const mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.overwatch.env).toEqual({
      OVERWATCH_RUNTIME_PROFILE: join(directory, '.overwatch-runtime', 'profile.json'),
    });
    expect(output).toContain(
      `OVERWATCH_CONFIG=${JSON.stringify(externalConfig)} OVERWATCH_STATE_FILE=${JSON.stringify(externalState)} npm run doctor`,
    );
    expect(JSON.parse(readFileSync(
      join(directory, '.overwatch-runtime', 'profile.json'),
      'utf8',
    ))).toMatchObject({
      config_path: externalConfig,
      state_file_path: externalState,
      mcp_token_file: join(directory, '.overwatch-mcp-token'),
    });
    expect(existsSync(externalConfig)).toBe(false);
    expect(existsSync(join(directory, 'engagement.json'))).toBe(false);
  });

  it('preserves a parseable but invalid config while wiring its unique recovery state', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-invalid-config-recovery-'));
    const configPath = join(directory, 'engagement.json');
    const configBytes = Buffer.from('{}');
    const statePath = join(directory, 'state-recovery.json');
    writeFileSync(configPath, configBytes);
    writeFileSync(statePath, durableState('recovery', 'preserved'));

    const output = execFileSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(output).toContain(`recovery wiring configured for preserved state ${statePath}`);
    expect(output).toContain('invalid engagement.json was preserved byte-for-byte');
    expect(readFileSync(configPath)).toEqual(configBytes);
  });

  it('does not regenerate a missing MCP token while a runtime owner is live', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-live-token-'));
    execFileSync(process.execPath, [setupScript, '--daemon', '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      stdio: 'pipe',
    });
    const tokenPath = join(directory, '.overwatch-mcp-token');
    const profilePath = join(directory, '.overwatch-runtime', 'profile.json');
    const daemonPath = join(directory, '.overwatch-runtime', 'daemon.json');
    const mcpPath = join(directory, '.mcp.json');
    const configPath = join(directory, 'engagement.json');
    const profileBefore = readFileSync(profilePath);
    const mcpBefore = readFileSync(mcpPath);
    const configBefore = readFileSync(configPath);
    rmSync(tokenPath);
    writeFileSync(daemonPath, `${JSON.stringify({
      version: 1,
      pid: process.pid,
      command: 'test-live-owner',
    })}\n`);

    const result = spawnSync(process.execPath, [setupScript, '--daemon', '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Refusing to change runtime profile or credentials while Overwatch PID');
    expect(existsSync(tokenPath)).toBe(false);
    expect(readFileSync(profilePath)).toEqual(profileBefore);
    expect(readFileSync(mcpPath)).toEqual(mcpBefore);
    expect(readFileSync(configPath)).toEqual(configBefore);
  });

  it('does not adopt a changed nonempty token while the live daemon retains another authority', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-live-token-drift-'));
    execFileSync(process.execPath, [setupScript, '--daemon', '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      stdio: 'pipe',
    });
    const tokenPath = join(directory, '.overwatch-mcp-token');
    const daemonPath = join(directory, '.overwatch-runtime', 'daemon.json');
    const profilePath = join(directory, '.overwatch-runtime', 'profile.json');
    const mcpPath = join(directory, '.mcp.json');
    const originalToken = readFileSync(tokenPath, 'utf8').trim();
    const profileBefore = readFileSync(profilePath);
    const mcpBefore = readFileSync(mcpPath);
    writeFileSync(tokenPath, 'changed-while-live');
    const changedTokenBytes = readFileSync(tokenPath);
    writeFileSync(daemonPath, `${JSON.stringify({
      version: 1,
      pid: process.pid,
      command: 'test-live-owner',
      mcp_token_sha256: createHash('sha256').update(originalToken).digest('hex'),
    })}\n`);

    const result = spawnSync(process.execPath, [setupScript, '--daemon', '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Refusing to change runtime profile or credentials while Overwatch PID');
    expect(readFileSync(tokenPath)).toEqual(changedTokenBytes);
    expect(readFileSync(profilePath)).toEqual(profileBefore);
    expect(readFileSync(mcpPath)).toEqual(mcpBefore);
  });

  it.each([
    ['runtime profile', 'OVERWATCH_RUNTIME_PROFILE'],
    ['managed daemon record', 'OVERWATCH_DAEMON_RECORD'],
    ['managed daemon log', 'OVERWATCH_DAEMON_LOG'],
  ])('rejects a %s path that aliases engagement.json before writing anything', (_label, variable) => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-path-collision-'));
    const engagementPath = join(directory, 'engagement.json');
    const result = spawnSync(process.execPath, [setupScript, '--daemon', '--template', template], {
      cwd: repository,
      env: {
        ...sanitizedProcessEnv,
        OVERWATCH_SETUP_ROOT: directory,
        [variable]: engagementPath,
      },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/Runtime path collision|runtime profile .* is invalid/i);
    expect(readdirSync(directory)).toEqual([]);
  });

  it.each([
    ['.snapshots', '.snapshots'],
    ['engagements', 'engagements'],
  ])('rejects an operational path inside the durable %s directory', (label, directoryName) => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-snapshot-collision-'));
    const configPath = join(directory, 'engagement.json');
    const statePath = join(directory, 'state-preserved.json');
    const snapshotDirectory = join(directory, directoryName);
    writeFileSync(configPath, `${JSON.stringify(engagementConfig('preserved'))}\n`);
    writeFileSync(statePath, durableState('preserved', 'do-not-change'));
    const configBefore = readFileSync(configPath);
    const stateBefore = readFileSync(statePath);

    const result = spawnSync(process.execPath, [setupScript, '--daemon', '--template', template], {
      cwd: repository,
      env: {
        ...sanitizedProcessEnv,
        OVERWATCH_SETUP_ROOT: directory,
        OVERWATCH_STATE_FILE: statePath,
        OVERWATCH_DAEMON_LOG: join(snapshotDirectory, 'daemon.log'),
      },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`inside the protected ${label} artifact directory`);
    expect(readFileSync(configPath)).toEqual(configBefore);
    expect(readFileSync(statePath)).toEqual(stateBefore);
    expect(existsSync(snapshotDirectory)).toBe(false);
  });

  it.each([
    ['config write intent', (statePath: string) => `${join(dirname(statePath), 'engagement.json')}.write-intent.json`],
    ['config intent conflict', (statePath: string) => `${join(dirname(statePath), 'engagement.json')}.write-intent.json.conflict-deadbeef`],
    ['config intent temporary file', (statePath: string) => `${join(dirname(statePath), 'engagement.json')}.write-intent.json.tmp-deadbeef`],
    ['config temporary file', (statePath: string) => `${join(dirname(statePath), 'engagement.json')}.overwatch-deadbeef`],
    ['rollback intent', (statePath: string) => `${statePath}.rollback-intent.json`],
    ['migration intent', (statePath: string) => `${statePath}.migration-intent.json`],
    ['state temporary file', (statePath: string) => `${statePath}.tmp-deadbeef`],
    ['legacy root snapshot', (statePath: string) => `${statePath.replace(/\.json$/, '')}.snap-deadbeef.json`],
    ['journal quarantine', (statePath: string) => `${statePath.replace(/\.json$/, '')}.journal.jsonl.quarantine-deadbeef.jsonl`],
  ])('preserves a %s when a runtime log override aliases it', (_label, sidecarPath) => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-sidecar-collision-'));
    const configPath = join(directory, 'engagement.json');
    const statePath = join(directory, 'state-preserved.json');
    const sidecar = sidecarPath(statePath);
    writeFileSync(configPath, `${JSON.stringify(engagementConfig('preserved'))}\n`);
    writeFileSync(statePath, durableState('preserved', 'do-not-change'));
    writeFileSync(sidecar, 'preserve recovery authority\n');
    const before = readFileSync(sidecar);

    const result = spawnSync(process.execPath, [setupScript, '--daemon', '--template', template], {
      cwd: repository,
      env: {
        ...sanitizedProcessEnv,
        OVERWATCH_SETUP_ROOT: directory,
        OVERWATCH_STATE_FILE: statePath,
        OVERWATCH_DAEMON_LOG: sidecar,
      },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Runtime path collision');
    expect(readFileSync(sidecar)).toEqual(before);
  });

  it.skipIf(process.platform !== 'darwin')('rejects a fresh case-only operational alias on macOS', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-case-alias-'));
    const result = spawnSync(process.execPath, [setupScript, '--daemon', '--template', template], {
      cwd: repository,
      env: {
        ...sanitizedProcessEnv,
        OVERWATCH_SETUP_ROOT: directory,
        OVERWATCH_DAEMON_LOG: join(directory, 'ENGAGEMENT.JSON'),
      },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Runtime path collision');
    expect(readdirSync(directory)).toEqual([]);
  });

  it('preserves an unreadable existing config and exits before writing client wiring', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-invalid-config-'));
    const configPath = join(directory, 'engagement.json');
    const configBytes = Buffer.from('{ malformed operator config');
    writeFileSync(configPath, configBytes);

    const result = spawnSync(process.execPath, [setupScript, '--force', '--template', template], {
      cwd: repository,
      env: { ...sanitizedProcessEnv, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Refusing to replace unreadable or invalid engagement.json');
    expect(readFileSync(configPath)).toEqual(configBytes);
    expect(existsSync(join(directory, '.mcp.json'))).toBe(false);
    expect(existsSync(join(directory, '.overwatch-mcp-token'))).toBe(false);
  });
});

function readFileIfRegular(path: string): Buffer | null {
  try {
    return statSync(path).isFile() ? readFileSync(path) : null;
  } catch {
    return null;
  }
}
