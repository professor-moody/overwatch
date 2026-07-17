import { execFileSync, spawnSync } from 'node:child_process';
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
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const repository = resolve('.');
const setupScript = join(repository, 'scripts', 'setup.mjs');
const template = join(repository, 'engagement-templates', 'ctf.json');
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
      env: { ...process.env, OVERWATCH_SETUP_ROOT: directory },
      stdio: 'pipe',
    });

    expect(readFileSync(join(directory, 'engagement.json'), 'utf8')).toBe(engagementText);
    expect(readFileSync(join(directory, 'state-force-safe.json'), 'utf8')).toBe(stateText);
    expect(readFileSync(join(directory, '.claude', 'settings.json'), 'utf8')).toBe(settingsText);
  });

  it('configures recovery wiring without creating a competing config', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-recovery-'));
    const statePath = join(directory, 'state-recovery.json');
    const stateText = `${durableState('recovery', 'preserved')}\n`;
    writeFileSync(statePath, stateText);

    const output = execFileSync(process.execPath, [setupScript, '--template', template], {
      cwd: repository,
      env: { ...process.env, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(output).toContain('recovery wiring configured');
    expect(output).toContain(`OVERWATCH_STATE_FILE=${JSON.stringify(statePath)}`);
    expect(existsSync(join(directory, 'engagement.json'))).toBe(false);
    expect(readFileSync(statePath, 'utf8')).toBe(stateText);
    expect(existsSync(join(directory, '.mcp.json'))).toBe(true);
  });

  it.each(blockedSetupCases)('refuses %s before writing any setup file', (_label, arrange) => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-blocked-'));
    arrange(directory);
    const before = new Map(
      readdirSync(directory).map(name => [name, readFileIfRegular(join(directory, name))]),
    );

    const result = spawnSync(process.execPath, [setupScript, '--force', '--template', template], {
      cwd: repository,
      env: { ...process.env, OVERWATCH_SETUP_ROOT: directory },
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
      env: { ...process.env, OVERWATCH_SETUP_ROOT: directory },
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
        ...process.env,
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
      env: { ...process.env, OVERWATCH_SETUP_ROOT: directory },
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
      env: { ...process.env, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    const mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.overwatch.env.OVERWATCH_STATE_FILE).toBe(statePath);
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
      env: { ...process.env, OVERWATCH_SETUP_ROOT: directory },
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
      env: { ...process.env, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    const mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.overwatch.env.OVERWATCH_STATE_FILE).toBe(statePath);
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
        ...process.env,
        OVERWATCH_SETUP_ROOT: directory,
        OVERWATCH_CONFIG: externalConfig,
      },
      encoding: 'utf8',
    });

    const mcp = JSON.parse(readFileSync(join(directory, '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.overwatch.env).toMatchObject({
      OVERWATCH_CONFIG: externalConfig,
      OVERWATCH_STATE_FILE: externalState,
    });
    expect(output).toContain(
      `OVERWATCH_CONFIG=${JSON.stringify(externalConfig)} OVERWATCH_STATE_FILE=${JSON.stringify(externalState)} npm run doctor`,
    );
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
      env: { ...process.env, OVERWATCH_SETUP_ROOT: directory },
      encoding: 'utf8',
    });

    expect(output).toContain(`recovery wiring configured for preserved state ${statePath}`);
    expect(output).toContain('invalid engagement.json was preserved byte-for-byte');
    expect(readFileSync(configPath)).toEqual(configBytes);
  });

  it('preserves an unreadable existing config and exits before writing client wiring', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-setup-invalid-config-'));
    const configPath = join(directory, 'engagement.json');
    const configBytes = Buffer.from('{ malformed operator config');
    writeFileSync(configPath, configBytes);

    const result = spawnSync(process.execPath, [setupScript, '--force', '--template', template], {
      cwd: repository,
      env: { ...process.env, OVERWATCH_SETUP_ROOT: directory },
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
