import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
// Plain ESM is shared by setup and doctor before TypeScript has been compiled.
// @ts-expect-error JavaScript startup helper has no declaration file.
import { configurationSemanticsEqual, inventoryEngagementArtifacts, selectRecoveryState, validateEngagementConfigShape } from '../../../scripts/engagement-artifacts.mjs';

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

function durableState(id: string, overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    config: engagementConfig(id, overrides),
    graph: { attributes: {}, nodes: [], edges: [] },
  });
}

describe('engagement artifact inventory', () => {
  let directory = '';

  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
  });

  it('distinguishes a fresh directory from one recoverable state family', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-artifacts-'));
    const fresh = inventoryEngagementArtifacts(directory);
    expect(fresh.artifacts).toEqual([]);
    expect(selectRecoveryState(fresh)).toEqual({ status: 'none' });

    writeFileSync(join(directory, 'state-preserved.json'), durableState('preserved'));
    writeFileSync(join(directory, 'state-preserved.journal.jsonl'), 'committed bytes\n');
    mkdirSync(join(directory, '.snapshots'));
    writeFileSync(
      join(directory, '.snapshots', 'state-preserved.snap-2026-07-17T00-00-00-000Z-1.json'),
      durableState('preserved'),
    );

    const recovered = inventoryEngagementArtifacts(directory);
    expect(recovered.state_families).toEqual([expect.objectContaining({
      state_path: join(directory, 'state-preserved.json'),
      has_primary: true,
      has_snapshot: true,
      has_wal: true,
      has_embedded_config: true,
    })]);
    expect(selectRecoveryState(recovered)).toMatchObject({
      status: 'selected',
      via: 'unique_family',
      family: { state_path: join(directory, 'state-preserved.json') },
    });
  });

  it('fails selection for ambiguous, WAL-only, and backup-only inventories', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-artifacts-blocked-'));
    writeFileSync(join(directory, 'state-one.json'), durableState('one'));
    writeFileSync(join(directory, 'state-two.json'), durableState('two'));
    expect(selectRecoveryState(inventoryEngagementArtifacts(directory)).status)
      .toBe('ambiguous');

    rmSync(join(directory, 'state-one.json'));
    rmSync(join(directory, 'state-two.json'));
    writeFileSync(join(directory, 'state-wal-only.journal.jsonl'), 'bytes\n');
    expect(selectRecoveryState(inventoryEngagementArtifacts(directory)).status)
      .toBe('no_base');

    rmSync(join(directory, 'state-wal-only.journal.jsonl'));
    mkdirSync(join(directory, '.migration-backups', 'backup-1'), { recursive: true });
    writeFileSync(join(directory, '.migration-backups', 'backup-1', 'manifest.json'), '{}');
    const backupOnly = inventoryEngagementArtifacts(directory);
    expect(backupOnly.artifacts).toContainEqual(expect.objectContaining({
      kind: 'durable_directory',
      path: join(directory, '.migration-backups'),
    }));
    expect(selectRecoveryState(backupOnly)).toEqual({ status: 'none' });
  });

  it('honors an explicit custom state path without guessing among local families', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-artifacts-explicit-'));
    const custom = join(directory, 'custom-recovery.json');
    writeFileSync(custom, durableState('custom'));
    writeFileSync(join(directory, 'state-other.json'), durableState('other'));

    const inventory = inventoryEngagementArtifacts(directory, {
      explicitStateFile: custom,
    });
    expect(selectRecoveryState(inventory)).toMatchObject({
      status: 'selected',
      via: 'environment',
      family: { state_path: custom },
    });
  });

  it('does not treat a corrupt or config-less physical base as recoverable', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-artifacts-invalid-base-'));
    writeFileSync(join(directory, 'state-corrupt.json'), '{ malformed');
    writeFileSync(join(directory, 'state-empty.json'), '{}');

    const inventory = inventoryEngagementArtifacts(directory);

    expect(inventory.state_families).toEqual(expect.arrayContaining([
      expect.objectContaining({ has_primary: true, has_embedded_config: false }),
    ]));
    expect(selectRecoveryState(inventory).status).toBe('no_base');
  });

  it('matches an active config by id, then immutable identity, and never guesses an unrelated state', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-artifacts-config-match-'));
    const nonce = 'a'.repeat(64);
    writeFileSync(join(directory, 'state-original.json'), durableState('original', {
      engagement_nonce: nonce,
    }));

    const inventory = inventoryEngagementArtifacts(directory);
    expect(selectRecoveryState(inventory, {
      activeConfig: engagementConfig('original', { engagement_nonce: nonce }),
    })).toMatchObject({
      status: 'selected',
      via: 'config_id',
      semantic_match: 'unknown',
      base_config_status: 'legacy_unverified',
    });
    expect(selectRecoveryState(inventory, {
      activeConfig: engagementConfig('renamed', { engagement_nonce: nonce }),
    })).toMatchObject({ status: 'selected', via: 'config_identity', semantic_match: false });
    expect(selectRecoveryState(inventory, {
      activeConfig: engagementConfig('unrelated', {
        created_at: '2026-07-18T00:00:00.000Z',
        engagement_nonce: 'b'.repeat(64),
      }),
    })).toMatchObject({ status: 'unmatched_config' });
  });

  it('scans beside an external config and includes atomic config temporary files', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-artifacts-external-'));
    const external = join(directory, 'external');
    mkdirSync(external);
    writeFileSync(join(directory, 'state-root.json'), durableState('root'));
    writeFileSync(join(external, 'state-external.json'), durableState('external'));
    writeFileSync(join(external, 'engagement.json.tmp-123-random'), '{"complete":"config"}');
    writeFileSync(join(external, 'engagement.json.write-intent.json.tmp-123-random'), '{}');

    const inventory = inventoryEngagementArtifacts(directory, {
      configPath: join(external, 'engagement.json'),
    });

    expect(inventory.state_families.map((family: { state_path: string }) => family.state_path))
      .toEqual([join(external, 'state-external.json')]);
    expect(inventory.artifacts).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'config_temp' }),
      expect.objectContaining({ kind: 'config_intent_temp' }),
    ]));
  });

  it('does not claim primary authority when retained bases disagree', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-artifacts-effective-base-'));
    const snapshots = join(directory, '.snapshots');
    mkdirSync(snapshots);
    writeFileSync(join(directory, 'state-history.json'), durableState('current', {
      created_at: '2026-07-18T00:00:00.000Z',
    }));
    writeFileSync(
      join(snapshots, 'state-history.snap-2026-07-17T00-00-00-000Z.json'),
      durableState('historical'),
    );

    const inventory = inventoryEngagementArtifacts(directory);
    expect(inventory.state_families[0]).toMatchObject({
      base_config_status: 'legacy_unverified',
    });
    expect(inventory.state_families[0].effective_config).toBeUndefined();
    expect(selectRecoveryState(inventory, {
      activeConfig: engagementConfig('historical'),
    })).toMatchObject({
      status: 'selected',
      via: 'config_id',
      semantic_match: 'unknown',
      base_config_status: 'legacy_unverified',
    });
  });

  it('keeps configuration convergence unknown for a newer snapshot, invalid primary, or rollback authority', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-artifacts-authority-'));
    const snapshots = join(directory, '.snapshots');
    mkdirSync(snapshots);
    const statePath = join(directory, 'state-authority.json');
    writeFileSync(statePath, JSON.stringify({
      config: engagementConfig('primary'),
      journalSnapshotSeq: 3,
      // A readable config does not make this a valid recovery base.
    }));
    writeFileSync(
      join(snapshots, 'state-authority.snap-2026-07-18T00-00-00-000Z.json'),
      JSON.stringify({
        config: engagementConfig('snapshot'),
        graph: { attributes: {}, nodes: [], edges: [] },
        journalSnapshotSeq: 9,
      }),
    );

    let inventory = inventoryEngagementArtifacts(directory);
    expect(inventory.state_families[0]).toMatchObject({
      base_config_status: 'incomplete',
    });
    expect(selectRecoveryState(inventory, {
      activeConfig: engagementConfig('snapshot'),
    })).toMatchObject({
      status: 'selected',
      semantic_match: 'unknown',
    });

    writeFileSync(`${statePath}.rollback-intent.json`, JSON.stringify({
      version: 1,
      checkpoint: 9,
      selected_snapshot: '.snapshots/state-authority.snap-2026-07-18T00-00-00-000Z.json',
      selected_snapshot_sha256: 'a'.repeat(64),
      intent_checksum: 'b'.repeat(64),
    }));
    inventory = inventoryEngagementArtifacts(directory);
    expect(inventory.state_families[0]).toMatchObject({
      base_config_status: 'rollback_pending',
      has_rollback_intent: true,
    });
    expect(selectRecoveryState(inventory, {
      activeConfig: engagementConfig('snapshot'),
    })).toMatchObject({
      semantic_match: 'unknown',
      base_config_status: 'rollback_pending',
    });
  });

  it('never treats a readable config inside an invalid state container as converged', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-artifacts-invalid-container-'));
    const statePath = join(directory, 'state-invalid.json');
    writeFileSync(statePath, JSON.stringify({ config: engagementConfig('invalid') }));

    let inventory = inventoryEngagementArtifacts(directory);
    expect(inventory.state_families[0]).toMatchObject({
      base_config_status: 'incomplete',
      has_embedded_config: false,
    });
    expect(selectRecoveryState(inventory, {
      activeConfig: engagementConfig('invalid'),
    }).status).toBe('no_base');

    const snapshots = join(directory, '.snapshots');
    mkdirSync(snapshots);
    writeFileSync(
      join(snapshots, 'state-invalid.snap-2026-07-18T00-00-00-000Z.json'),
      durableState('invalid'),
    );
    inventory = inventoryEngagementArtifacts(directory);
    expect(selectRecoveryState(inventory, {
      activeConfig: engagementConfig('invalid'),
    })).toMatchObject({
      status: 'selected',
      semantic_match: 'unknown',
      base_config_status: 'incomplete',
    });
  });

  it('recognizes a marker-only pending rollback without a sidecar', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-artifacts-inline-rollback-'));
    const state = JSON.parse(durableState('rollback')) as Record<string, unknown>;
    state.rollbackIntent = {
      version: 1,
      checkpoint: 0,
      selected_snapshot: '.snapshots/state-rollback.snap-selected.json',
      selected_snapshot_sha256: 'a'.repeat(64),
      intent_checksum: 'b'.repeat(64),
    };
    writeFileSync(join(directory, 'state-rollback.json'), JSON.stringify(state));

    const inventory = inventoryEngagementArtifacts(directory);
    expect(inventory.state_families[0]).toMatchObject({
      has_rollback_intent: true,
      base_config_status: 'rollback_pending',
    });
    expect(selectRecoveryState(inventory, {
      activeConfig: engagementConfig('rollback'),
    })).toMatchObject({
      status: 'selected',
      semantic_match: 'unknown',
      base_config_status: 'rollback_pending',
    });
  });

  it('never reports legacy V0 configuration authority as converged', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-artifacts-legacy-v0-'));
    const state = JSON.parse(durableState('legacy')) as Record<string, unknown>;
    state.campaigns = ['not-a-map-entry'];
    writeFileSync(join(directory, 'state-legacy.json'), JSON.stringify(state));

    const inventory = inventoryEngagementArtifacts(directory);
    expect(inventory.state_families[0]).toMatchObject({
      base_config_status: 'legacy_unverified',
      has_embedded_config: true,
    });
    expect(selectRecoveryState(inventory, {
      activeConfig: engagementConfig('legacy'),
    })).toMatchObject({
      status: 'selected',
      semantic_match: 'unknown',
      base_config_status: 'legacy_unverified',
    });
  });

  it('uses the authoritative runtime config schema and semantic comparison', () => {
    const valid = engagementConfig('valid');
    expect(validateEngagementConfigShape(valid).valid).toBe(true);
    for (const invalid of [
      { ...valid, objectives: [null] },
      { ...valid, scope: { ...valid.scope, hosts: [42] } },
      { ...valid, engagement_nonce: 'not-a-valid-nonce' },
      { ...valid, opsec: { ...valid.opsec, approval_mode: 'sometimes' } },
      { ...valid, hash_chain_enabled: 'yes' },
    ]) expect(validateEngagementConfigShape(invalid).valid).toBe(false);

    expect(configurationSemanticsEqual(
      { ...valid, config_revision: 1, config_hash: 'a'.repeat(64) },
      { ...valid, config_revision: 2, config_hash: 'b'.repeat(64) },
    )).toBe(true);
    expect(configurationSemanticsEqual(
      valid,
      { ...valid, scope: { ...valid.scope, domains: ['changed.example'] } },
    )).toBe(false);
  });
});
