import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { parseEngagementConfig } from '../config.js';
import { EngagementCommandService } from '../services/engagement-command-service.js';
import { EngagementManager } from '../services/engagement-manager.js';
import { GraphEngine } from '../services/graph-engine.js';

const repository = resolve('.');
const setupScript = join(repository, 'scripts', 'setup.mjs');
const template = join(repository, 'engagement-templates', 'ctf.json');
const hookDirectory = join(repository, '.claude', 'hooks');
const sanitizedEnvironment = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !key.startsWith('OVERWATCH_')),
);

function runSetup(root: string, args: string[]) {
  const result = spawnSync(process.execPath, [setupScript, ...args], {
    cwd: repository,
    env: {
      ...sanitizedEnvironment,
      OVERWATCH_SETUP_ROOT: root,
    },
    encoding: 'utf8',
  });
  if (result.error) throw result.error;
  expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
  return result;
}

function runContextHook(active: boolean) {
  const env = { ...sanitizedEnvironment };
  if (active) env.OVERWATCH_ENGAGEMENT_ACTIVE = '1';
  const result = spawnSync(
    process.execPath,
    [join(hookDirectory, 'overwatch-user-context.mjs')],
    {
      cwd: repository,
      env,
      input: JSON.stringify({
        hook_event_name: 'UserPromptSubmit',
        prompt: 'What should we scan next on the target?',
      }),
      encoding: 'utf8',
    },
  );
  if (result.error) throw result.error;
  expect(result.status, result.stderr).toBe(0);
  return result.stdout.trim();
}

describe('documented operator workflow', () => {
  let directory = '';
  let engine: GraphEngine | undefined;

  afterEach(() => {
    engine?.dispose();
    engine = undefined;
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = '';
  });

  it('keeps setup, hooks, engagement creation, and live scope semantics truthful', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-documented-flow-'));
    const first = runSetup(directory, [
      '--template', template,
      '--name', 'Documented workflow',
      '--id', 'documented-workflow',
      '--cidr', '10.77.0.0/24',
    ]);

    const configPath = join(directory, 'engagement.json');
    const profilePath = join(directory, '.overwatch-runtime', 'profile.json');
    const mcpPath = join(directory, '.mcp.json');
    const settingsPath = join(directory, '.claude', 'settings.json');
    const tokenPath = join(directory, '.overwatch-mcp-token');
    for (const path of [configPath, profilePath, mcpPath, settingsPath, tokenPath]) {
      expect(existsSync(path), `setup did not create ${path}`).toBe(true);
    }
    expect(statSync(profilePath).mode & 0o777).toBe(0o600);
    expect(statSync(tokenPath).mode & 0o777).toBe(0o600);

    const profile = JSON.parse(readFileSync(profilePath, 'utf8'));
    expect(profile).toMatchObject({
      schema_version: 1,
      mode: 'daemon',
      config_path: configPath,
      state_file_path: join(directory, 'state-documented-workflow.json'),
    });
    const mcp = JSON.parse(readFileSync(mcpPath, 'utf8'));
    expect(mcp.mcpServers.overwatch).toMatchObject({
      type: 'http',
      url: 'http://127.0.0.1:3000/mcp',
    });
    expect(mcp.mcpServers.overwatch.headers.Authorization).toBe(
      `Bearer ${readFileSync(tokenPath, 'utf8')}`,
    );
    const settings = readFileSync(settingsPath, 'utf8');
    expect(settings).toContain('overwatch-user-context.mjs');
    expect(settings).toContain('overwatch-bash-guard.mjs');

    expect(first.stdout).toContain('npm run daemon:start');
    expect(first.stdout).toContain('npm run doctor');
    expect(first.stdout).toContain('OVERWATCH_ENGAGEMENT_ACTIVE=1 claude');

    const originalConfig = readFileSync(configPath);
    const repeated = runSetup(directory, [
      '--template', template,
      '--name', 'Must not replace the engagement',
      '--cidr', '203.0.113.0/24',
    ]);
    expect(readFileSync(configPath).equals(originalConfig)).toBe(true);
    expect(repeated.stdout).toContain('documented-workflow');
    expect(repeated.stdout).toContain('OVERWATCH_ENGAGEMENT_ACTIVE=1 claude');

    expect(runContextHook(false)).toBe('');
    const activeHookOutput = JSON.parse(runContextHook(true));
    expect(activeHookOutput.hookSpecificOutput.additionalContext).toContain(
      'Overwatch grounding',
    );

    const manager = new EngagementManager(configPath);
    const activeId = manager.getActiveId();
    const inactive = manager.createEngagement({
      name: 'Future inactive configuration',
      cidrs: ['192.0.2.0/24'],
    });
    expect(inactive.is_active).toBe(false);
    expect(manager.getActiveId()).toBe(activeId);
    expect(readFileSync(configPath).equals(originalConfig)).toBe(true);
    expect(manager.listEngagements()).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: activeId, is_active: true }),
      expect.objectContaining({ id: inactive.id, is_active: false }),
    ]));
    expect(existsSync(inactive.state_path)).toBe(false);
    const inactiveStatePrefix = `state-${inactive.id}`;
    expect(
      readdirSync(dirname(inactive.config_path)).some(name => name.startsWith(inactiveStatePrefix)),
    ).toBe(false);

    const initial = parseEngagementConfig(readFileSync(configPath, 'utf8'));
    engine = new GraphEngine(
      initial,
      join(directory, `state-${initial.id}.json`),
      configPath,
    );
    const revisionBefore = engine.getConfig().config_revision ?? 0;
    const commands = new EngagementCommandService(engine);
    const execution = commands.updateScope({
      add_cidrs: ['198.51.100.0/24'],
      reason: 'documented live scope update',
    });
    expect(execution.status).toBe('succeeded');
    expect(execution.result?.after.cidrs).toContain('198.51.100.0/24');

    const liveConfig = parseEngagementConfig(readFileSync(configPath, 'utf8'));
    expect(liveConfig.scope.cidrs).toContain('198.51.100.0/24');
    expect(liveConfig.config_revision).toBeGreaterThan(revisionBefore);
    expect(liveConfig).toEqual(engine.getConfig());
  });
});
