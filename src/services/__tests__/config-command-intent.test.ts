import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import {
  EngagementConfigService,
  withConfigMetadata,
} from '../engagement-config-service.js';
import type { PersistedApplicationCommandV1 } from '../persisted-state.js';

function baseConfig(): EngagementConfig {
  return withConfigMetadata({
    id: 'config-command-intent',
    name: 'Config command intent',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, enabled: true },
  }, 1);
}

function command(config: EngagementConfig): PersistedApplicationCommandV1 {
  const now = '2026-07-16T01:00:00.000Z';
  return {
    command_id: 'config-command-after-crash',
    idempotency_key: 'idem_config_command_after_crash',
    input_sha256: 'a'.repeat(64),
    validated_input: { max_noise: 0.4 },
    command_kind: 'engagement.settings.patch',
    transport: 'dashboard',
    actor_task_id: null,
    status: 'succeeded',
    created_at: now,
    started_at: now,
    completed_at: now,
    result: { updated: true, opsec: config.opsec },
  };
}

describe('config command write-intent recovery', () => {
  const directories: string[] = [];

  afterEach(() => {
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('recovers the exact command with the config after a crash following file replacement', () => {
    const directory = mkdtempSync(
      join(tmpdir(), 'overwatch-config-command-intent-'),
    );
    directories.push(directory);
    const configPath = join(directory, 'engagement.json');
    const original = baseConfig();
    writeFileSync(configPath, `${JSON.stringify(original, null, 2)}\n`);
    let runtime = structuredClone(original);
    const commands = new Map<string, PersistedApplicationCommandV1>();
    let failCommit = false;
    const host = {
      getRuntimeConfig: () => runtime,
      nowIso: () => '2026-07-16T01:00:00.000Z',
      applyRuntimeConfig: (next: EngagementConfig) => {
        runtime = structuredClone(next);
      },
      commitRuntimeConfig: (
        next: EngagementConfig,
        _context: unknown,
        _event: unknown,
        applicationCommand?: PersistedApplicationCommandV1,
      ) => {
        if (failCommit) throw new Error('simulated crash before state commit');
        runtime = structuredClone(next);
        if (applicationCommand) {
          commands.set(
            applicationCommand.idempotency_key,
            structuredClone(applicationCommand),
          );
        }
      },
      recordConfigEvent: () => {},
      persistRuntimeState: () => {},
      hasApplicationCommand: (key: string) => commands.has(key),
    };
    const first = new EngagementConfigService(host, configPath);
    expect(first.initialize({
      restored: true,
      persistence_writable: true,
      durable_config: original,
    }).resolution_required).toBe(false);

    failCommit = true;
    expect(() => first.commitWithCommand(
      {
        ...runtime,
        opsec: { ...runtime.opsec, max_noise: 0.4 },
      },
      'engagement.settings.patch',
      command,
    )).toThrow('simulated crash');
    expect(existsSync(`${configPath}.write-intent.json`)).toBe(true);
    expect(commands.size).toBe(0);
    expect(JSON.parse(readFileSync(configPath, 'utf8')).opsec.max_noise)
      .toBe(0.4);

    failCommit = false;
    runtime = structuredClone(original);
    const recovered = new EngagementConfigService(host, configPath);
    expect(recovered.initialize({
      restored: true,
      persistence_writable: true,
      durable_config: original,
    })).toMatchObject({
      status: 'recovered',
      resolution_required: false,
    });
    expect(runtime.opsec.max_noise).toBe(0.4);
    expect(commands.get('idem_config_command_after_crash')).toMatchObject({
      command_id: 'config-command-after-crash',
      status: 'succeeded',
      result: { updated: true, opsec: { max_noise: 0.4 } },
    });
    expect(existsSync(`${configPath}.write-intent.json`)).toBe(false);
  });
});
