import {
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import { RecoveryCommandService } from '../recovery-command-service.js';

function config(name: string): EngagementConfig {
  return {
    id: 'recovery-command-test',
    name,
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

describe('RecoveryCommandService deferred startup replay', () => {
  let directory: string | undefined;
  let engine: GraphEngine | undefined;

  afterEach(() => {
    engine?.dispose();
    if (directory) rmSync(directory, { recursive: true, force: true });
  });

  it('retries deferred lifecycle recovery without recommitting a succeeded config command', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-recovery-command-'));
    const configPath = join(directory, 'engagement.json');
    const statePath = join(directory, 'state.json');
    const durable = config('Durable state name');
    writeFileSync(configPath, `${JSON.stringify(durable, null, 2)}\n`);
    engine = new GraphEngine(durable, statePath, configPath);
    engine.flushNow();
    engine.dispose();

    const fileConfig = config('File-authoritative name');
    writeFileSync(configPath, `${JSON.stringify(fileConfig, null, 2)}\n`);
    engine = new GraphEngine(fileConfig, statePath, configPath);
    const recovery = engine.getConfigRecoveryStatus();
    expect(recovery).toMatchObject({
      resolution_required: true,
      file_hash: expect.stringMatching(/^[a-f0-9]{64}$/),
      state_hash: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    let attempts = 0;
    engine.setRuntimeOwnershipRecoveryHandler(() => {
      attempts++;
      if (attempts === 1) throw new Error('synthetic deferred recovery failure');
    });
    const service = new RecoveryCommandService(engine);
    const input = {
      mode: 'use_file' as const,
      expected_file_hash: recovery.file_hash!,
      expected_state_hash: recovery.state_hash!,
    };
    const metadata = {
      command_id: 'config-recovery-command',
      idempotency_key: 'config-recovery-retry',
    };

    expect(() => service.resolveConfig(input, metadata))
      .toThrow('synthetic deferred recovery failure');
    expect(engine.getApplicationCommandById(metadata.command_id))
      .toMatchObject({ status: 'succeeded' });
    expect(engine.isPersistenceWritable()).toBe(false);

    const replay = service.resolveConfig(input, metadata);
    expect(replay).toMatchObject({
      command_id: metadata.command_id,
      status: 'succeeded',
      replayed: true,
    });
    expect(attempts).toBe(2);
    expect(engine.isPersistenceWritable()).toBe(true);
    expect(engine.listApplicationCommands().filter(command =>
      command.command_id === metadata.command_id)).toHaveLength(1);

    expect(service.resolveConfig(input, metadata).replayed).toBe(true);
    expect(attempts).toBe(2);
  });
});
