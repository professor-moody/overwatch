import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { EngagementConfig } from '../../types.js';
import { parseEngagementConfig } from '../../config.js';
import { GraphEngine } from '../graph-engine.js';
import { DashboardServer } from '../dashboard-server.js';
import { MutationJournal, type MutationType } from '../mutation-journal.js';
import { withConfigMetadata } from '../engagement-config-service.js';
import { ConfigDivergenceResolveResponseSchema, RecoveryStatusResponseSchema } from '../../contracts/dashboard-v1.js';

function legacyConfig(): EngagementConfig {
  return {
    id: 'dashboard-recovery',
    name: 'Dashboard Recovery',
    created_at: '2026-07-15T00:00:00.000Z',
    scope: { cidrs: ['10.70.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', enabled: false, max_noise: 0.5 },
    engagement_nonce: 'd'.repeat(64),
    hash_chain_enabled: true,
    subagent_isolation: 'in_process',
  };
}

describe('dashboard recovery API', () => {
  let dir: string;
  let configPath: string;
  let statePath: string;
  let engine: GraphEngine | undefined;
  let dashboard: DashboardServer | undefined;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ow-dashboard-recovery-'));
    configPath = join(dir, 'engagement.json');
    statePath = join(dir, 'state.json');
  });

  afterEach(async () => {
    if (dashboard) await dashboard.stop().catch(() => undefined);
    engine?.dispose();
    rmSync(dir, { recursive: true, force: true });
  });

  async function startServer(nextEngine: GraphEngine): Promise<string> {
    engine = nextEngine;
    dashboard = new DashboardServer(nextEngine, 0, '127.0.0.1', undefined, undefined);
    const started = await dashboard.start();
    if (!started.started) throw new Error(started.error ?? 'dashboard did not start');
    return dashboard.address;
  }

  async function json(
    base: string,
    path: string,
    init?: RequestInit,
  ): Promise<{ status: number; body: Record<string, any> }> {
    const response = await fetch(`${base}${path}`, init);
    return { status: response.status, body: await response.json() as Record<string, any> };
  }

  function seed(): EngagementConfig {
    const legacy = legacyConfig();
    writeFileSync(configPath, JSON.stringify(legacy));
    const first = new GraphEngine(legacy, statePath, configPath);
    first.persistImmediate();
    first.dispose();
    return parseEngagementConfig(readFileSync(configPath, 'utf8'));
  }

  it('keeps recovery inspectable, validates requests strictly, and permits only reconciliation', async () => {
    const durable = seed();
    const external = withConfigMetadata({ ...durable, name: 'External edit' }, 2);
    writeFileSync(configPath, JSON.stringify(external));
    const base = await startServer(new GraphEngine(external, statePath, configPath));

    const recovery = await json(base, '/api/recovery');
    expect(() => RecoveryStatusResponseSchema.parse(recovery.body)).not.toThrow();
    expect(recovery).toMatchObject({
      status: 200,
      body: {
        recovery: {
          writable: false,
          config_recovery: { status: 'diverged', resolution_required: true },
        },
      },
    });
    const configRecovery = recovery.body.recovery.config_recovery;

    const blocked = await json(base, '/api/settings', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ opsec: { enabled: false } }),
    });
    expect(blocked).toMatchObject({ status: 503, body: { code: 'PERSISTENCE_READ_ONLY' } });

    const invalid = await json(base, '/api/recovery/config/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resolution: 'use_state',
        expected_file_hash: configRecovery.file_hash,
        expected_state_hash: configRecovery.state_hash,
        unexpected: true,
      }),
    });
    expect(invalid.status).toBe(400);

    const invalidMode = await json(base, '/api/recovery/config/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resolution: 'guess',
        expected_file_hash: configRecovery.file_hash,
        expected_state_hash: configRecovery.state_hash,
      }),
    });
    expect(invalidMode.status).toBe(400);

    const invalidHash = await json(base, '/api/recovery/config/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resolution: 'use_state',
        expected_file_hash: 'not-a-hash',
        expected_state_hash: configRecovery.state_hash,
      }),
    });
    expect(invalidHash.status).toBe(400);

    const stale = await json(base, '/api/recovery/config/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resolution: 'use_state',
        expected_file_hash: '0'.repeat(64),
        expected_state_hash: configRecovery.state_hash,
      }),
    });
    expect(stale).toMatchObject({ status: 409, body: { code: 'CONFIG_HASH_CONFLICT' } });

    const resolved = await json(base, '/api/recovery/config/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resolution: 'use_state',
        expected_file_hash: configRecovery.file_hash,
        expected_state_hash: configRecovery.state_hash,
      }),
    });
    expect(resolved).toMatchObject({
      status: 200,
      body: { resolved: true, mode: 'use_state', recovery: { status: 'recovered' } },
    });
    expect(() => ConfigDivergenceResolveResponseSchema.parse(resolved.body)).not.toThrow();
    expect(parseEngagementConfig(readFileSync(configPath, 'utf8')).name).toBe(durable.name);

    const repeated = await json(base, '/api/recovery/config/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resolution: 'use_state',
        expected_file_hash: resolved.body.config.config_hash,
        expected_state_hash: resolved.body.config.config_hash,
      }),
    });
    expect(repeated.status).toBe(409);
  });

  it('applies file authority through the HTTP surface, including a scope transaction', async () => {
    const durable = seed();
    const external = withConfigMetadata({
      ...durable,
      name: 'File-authoritative engagement',
      scope: {
        ...durable.scope,
        cidrs: [...durable.scope.cidrs, '10.71.0.0/24'],
      },
    }, 2);
    writeFileSync(configPath, JSON.stringify(external));
    const base = await startServer(new GraphEngine(external, statePath, configPath));
    const inspected = await json(base, '/api/recovery');
    const configRecovery = inspected.body.recovery.config_recovery;

    const resolved = await json(base, '/api/recovery/config/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resolution: 'use_file',
        expected_file_hash: configRecovery.file_hash,
        expected_state_hash: configRecovery.state_hash,
      }),
    });

    expect(resolved).toMatchObject({
      status: 200,
      body: {
        resolved: true,
        mode: 'use_file',
        config: {
          name: 'File-authoritative engagement',
          scope: { cidrs: expect.arrayContaining(['10.71.0.0/24']) },
        },
        recovery: { status: 'recovered', resolution_required: false },
      },
    });
    expect(() => ConfigDivergenceResolveResponseSchema.parse(resolved.body)).not.toThrow();
    expect(parseEngagementConfig(readFileSync(configPath, 'utf8'))).toEqual(engine!.getConfig());
    expect(engine!.getFullHistory().filter(event => event.event_type === 'scope_updated')).toHaveLength(1);
    expect(engine!.getPersistenceRecoveryStatus()).toMatchObject({ complete: true, writable: true });
  });

  it('rejects reconciliation over an incomplete WAL with a stable recovery response', async () => {
    const durable = seed();
    const state = JSON.parse(readFileSync(statePath, 'utf8')) as { journalSnapshotSeq?: number };
    const journal = new MutationJournal(statePath);
    journal.setNextSeq(state.journalSnapshotSeq ?? 0, {
      appliedThroughSeq: state.journalSnapshotSeq ?? 0,
    });
    journal.appendTransaction({
      operations: [{ type: 'future_mutation' as MutationType, payload: {} }],
      ts: new Date().toISOString(),
    });
    const external = withConfigMetadata({ ...durable, name: 'External during WAL failure' }, 2);
    writeFileSync(configPath, JSON.stringify(external));
    const configBefore = readFileSync(configPath);
    const stateBefore = readFileSync(statePath);
    const walBefore = readFileSync(journal.getPath());
    const base = await startServer(new GraphEngine(external, statePath, configPath));

    const inspected = await json(base, '/api/recovery');
    expect(inspected).toMatchObject({
      status: 200,
      body: {
        recovery: {
          writable: false,
          persistence_reason: expect.stringContaining('unsupported'),
          config_recovery: { status: 'diverged', resolution_required: true },
        },
      },
    });
    const configRecovery = inspected.body.recovery.config_recovery;
    const rejected = await json(base, '/api/recovery/config/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resolution: 'use_state',
        expected_file_hash: configRecovery.file_hash,
        expected_state_hash: configRecovery.state_hash,
      }),
    });
    expect(rejected).toMatchObject({
      status: 503,
      body: {
        code: 'PERSISTENCE_READ_ONLY',
        recovery: { writable: false },
      },
    });
    expect(readFileSync(configPath)).toEqual(configBefore);
    expect(readFileSync(statePath)).toEqual(stateBefore);
    expect(readFileSync(journal.getPath())).toEqual(walBefore);
  });
});
