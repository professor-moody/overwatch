import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import {
  withApplicationCommandInvocation,
} from '../application-command-service.js';
import {
  EngagementCommandService,
} from '../engagement-command-service.js';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal } from '../mutation-journal.js';

function config(): EngagementConfig {
  return {
    id: 'engagement-command-test',
    name: 'Engagement command test',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: {
      cidrs: ['10.0.0.0/24'],
      domains: [],
      exclusions: [],
      hosts: ['seed.internal'],
      url_patterns: ['https://seed.internal/*'],
    },
    objectives: [],
    opsec: {
      name: 'pentest',
      max_noise: 0.7,
      enabled: true,
    },
  };
}

function invoke<T>(
  commandId: string,
  idempotencyKey: string,
  operation: () => T,
): T {
  return withApplicationCommandInvocation({
    transport: 'dashboard',
    command_id: commandId,
    idempotency_key: idempotencyKey,
  }, operation);
}

describe('EngagementCommandService', () => {
  let directory: string;
  let engine: GraphEngine;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-engagement-command-'));
    engine = new GraphEngine(config(), join(directory, 'state.json'));
  });

  afterEach(() => {
    engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  it('returns the original objective UUID for an exact retry', () => {
    const service = new EngagementCommandService(engine);
    const create = () => invoke(
      'objective-create-command',
      'objective-create-retry',
      () => service.addObjective({
        description: 'Own the target',
        target_node_type: 'host',
      }),
    );

    const first = create();
    const second = create();

    expect(first.result?.objective.id).toBeDefined();
    expect(second).toMatchObject({
      command_id: first.command_id,
      replayed: true,
      result: {
        objective: { id: first.result?.objective.id },
      },
    });
    expect(engine.getConfig().objectives).toHaveLength(1);
  });

  it('replays objective update and delete after live state has changed', () => {
    const service = new EngagementCommandService(engine);
    const created = service.addObjective({ description: 'Initial objective' });
    const objectiveId = created.result!.objective.id;
    const update = () => invoke(
      'objective-update-command',
      'objective-update-retry',
      () => service.updateObjective(objectiveId, {
        description: 'Updated objective',
      }),
    );
    const remove = () => invoke(
      'objective-delete-command',
      'objective-delete-retry',
      () => service.deleteObjective(objectiveId),
    );

    const firstUpdate = update();
    expect(firstUpdate.result?.objective.description).toBe('Updated objective');
    const firstDelete = remove();
    expect(engine.getConfig().objectives).toHaveLength(0);
    expect(update()).toMatchObject({
      replayed: true,
      result: firstUpdate.result,
    });
    expect(remove()).toMatchObject({
      replayed: true,
      result: firstDelete.result,
    });
  });

  it('records a semantic no-op without incrementing the config revision', () => {
    const service = new EngagementCommandService(engine);
    const before = engine.getConfig();
    const execution = invoke(
      'settings-noop-command',
      'settings-noop',
      () => service.updateSettings({ max_noise: before.opsec.max_noise }),
    );

    expect(execution.result).toMatchObject({
      updated: false,
      opsec: { max_noise: before.opsec.max_noise },
    });
    expect(engine.getConfig().config_revision).toBe(before.config_revision);
    expect(engine.getApplicationCommandById(execution.command_id)?.status)
      .toBe('succeeded');
  });

  it('preserves non-network scope fields in a replacement command', () => {
    const execution = new EngagementCommandService(engine).replaceScope({
      cidrs: ['10.0.0.0/24', '10.0.1.0/24'],
      domains: ['internal.example'],
      exclusions: [],
      hosts: ['new.internal'],
      url_patterns: ['https://new.internal/*'],
      aws_accounts: ['123456789012'],
    });

    expect(execution.result).toMatchObject({
      applied: true,
      scope: {
        hosts: ['new.internal'],
        url_patterns: ['https://new.internal/*'],
        aws_accounts: ['123456789012'],
      },
      after: {
        hosts: ['new.internal'],
        url_patterns: ['https://new.internal/*'],
        aws_accounts: ['123456789012'],
      },
    });
    expect(engine.getConfig().scope.hosts).toEqual(['new.internal']);
  });

  it('keeps config and scope command history out of composite state patches', () => {
    const statePath = join(directory, 'state.json');
    engine.flushNow();
    const checkpoint = JSON.parse(readFileSync(statePath, 'utf8')) as {
      journalSnapshotSeq: number;
    };
    const service = new EngagementCommandService(engine);
    invoke(
      'bounded-settings-command',
      'bounded-settings-retry',
      () => service.updateSettings({ max_noise: 0.5 }),
    );
    invoke(
      'bounded-scope-command',
      'bounded-scope-retry',
      () => service.replaceScope({
        ...engine.getConfig().scope,
        cidrs: ['10.0.0.0/24', '10.0.3.0/24'],
      }),
    );

    const transactions = new MutationJournal(statePath)
      .readTransactionsSince(checkpoint.journalSnapshotSeq);
    const configTransaction = transactions.find(transaction =>
      transaction.operations.some(operation => operation.type === 'state_patch')
      && transaction.operations.some(operation =>
        operation.type === 'application_command_change'
        && (operation.payload as { after?: { command_id?: string } }).after?.command_id
          === 'bounded-settings-command'))!;
    const scopeTransaction = transactions.find(transaction =>
      transaction.operations.some(operation => operation.type === 'scope_updated'))!;

    for (const transaction of [configTransaction, scopeTransaction]) {
      expect(transaction.operations.map(operation => operation.type))
        .toContain('application_command_change');
      expect(JSON.stringify(transaction.operations)).not.toContain('applicationCommands');
    }
  });

  it('commits a combined scope, OPSEC, and objective patch once and replays after restart', () => {
    engine.dispose();
    const configPath = join(directory, 'engagement.json');
    const statePath = join(directory, 'managed-state.json');
    writeFileSync(configPath, `${JSON.stringify(config(), null, 2)}\n`);
    engine = new GraphEngine(config(), statePath, configPath);
    const beforeRevision = engine.getConfig().config_revision!;
    const input = {
      scope: {
        cidrs: ['10.0.0.0/24', '10.0.2.0/24'],
        domains: [],
        exclusions: [],
      },
      opsec: { max_noise: 0.4 },
      objectives: [{
        id: 'combined-objective',
        description: 'Combined objective',
        achieved: false,
      }],
    };
    const apply = () => invoke(
      'combined-config-command',
      'combined-config-retry',
      () => new EngagementCommandService(engine).patchConfig(input),
    );
    const first = apply();
    expect(first.result?.config.config_revision).toBe(beforeRevision + 1);
    expect(engine.getConfig()).toMatchObject({
      scope: { cidrs: ['10.0.0.0/24', '10.0.2.0/24'] },
      opsec: { max_noise: 0.4 },
      objectives: [{ id: 'combined-objective' }],
    });
    expect(JSON.parse(readFileSync(configPath, 'utf8'))).toEqual(
      engine.getConfig(),
    );

    engine.flushNow();
    engine.dispose();
    engine = new GraphEngine(
      JSON.parse(readFileSync(configPath, 'utf8')) as EngagementConfig,
      statePath,
      configPath,
    );
    const replay = apply();
    expect(replay).toMatchObject({
      command_id: first.command_id,
      replayed: true,
      result: first.result,
    });
    expect(engine.getConfig().config_revision).toBe(beforeRevision + 1);
  });
});
