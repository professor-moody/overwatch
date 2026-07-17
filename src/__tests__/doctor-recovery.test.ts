import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const repository = resolve('.');
const doctorScript = join(repository, 'scripts', 'doctor.mjs');

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

function runDoctor(root: string, extraEnv: Record<string, string> = {}) {
  return spawnSync(process.execPath, [doctorScript], {
    cwd: repository,
    env: {
      ...process.env,
      OVERWATCH_DOCTOR_ROOT: root,
      OVERWATCH_DASHBOARD_PORT: '0',
      ...extraEnv,
    },
    encoding: 'utf8',
  });
}

describe('doctor recovery guidance', () => {
  let directory = '';

  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
  });

  it('selects a unique preserved state without recommending setup', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-doctor-recovery-'));
    const statePath = join(directory, 'state-preserved.json');
    const bytes = Buffer.from(`${durableState('preserved', 'unchanged')}\n`);
    writeFileSync(statePath, bytes);

    const result = runDoctor(directory);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain(`preserved recovery state selected at ${statePath}`);
    expect(result.stdout).toContain('inspect Recovery');
    expect(result.stdout).not.toContain('setup --force');
    expect(readFileSync(statePath)).toEqual(bytes);
  });

  it('requires explicit selection when multiple recovery states exist', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-doctor-ambiguous-'));
    writeFileSync(join(directory, 'state-one.json'), durableState('one'));
    writeFileSync(join(directory, 'state-two.json'), durableState('two'));

    const result = runDoctor(directory);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('multiple recoverable state families exist');
    expect(result.stdout).toContain('Set OVERWATCH_STATE_FILE');
    expect(result.stdout).toContain('never run setup --force over these artifacts');
  });

  it('treats a missing nonce as legacy metadata rather than permission to rewrite config', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-doctor-nonce-'));
    writeFileSync(join(directory, 'engagement.json'), JSON.stringify({
      id: 'legacy-nonce',
      name: 'Legacy nonce',
      created_at: '2026-07-17T00:00:00.000Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 1 },
    }));

    const result = runDoctor(directory);

    expect(result.stdout).toContain('WAL durability remains enabled');
    expect(result.stdout).not.toContain('setup -- --force');
  });

  it('reports an unmatched stale config instead of a fresh derived state path', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-doctor-stale-config-'));
    writeFileSync(join(directory, 'engagement.json'), JSON.stringify(engagementConfig('stale', {
      created_at: '2026-07-18T00:00:00.000Z',
      engagement_nonce: 'b'.repeat(64),
    })));
    writeFileSync(join(directory, 'state-original.json'), durableState('original', undefined, {
      engagement_nonce: 'a'.repeat(64),
    }));

    const result = runDoctor(directory);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('active config does not match any preserved state family');
    expect(result.stdout).not.toContain('state-stale.json');
  });

  it('reports the runtime-compatible state selected by immutable config identity', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-doctor-identity-'));
    const nonce = 'a'.repeat(64);
    const statePath = join(directory, 'state-original.json');
    writeFileSync(join(directory, 'engagement.json'), JSON.stringify(engagementConfig('renamed', {
      engagement_nonce: nonce,
    })));
    writeFileSync(statePath, durableState('original', undefined, { engagement_nonce: nonce }));

    const result = runDoctor(directory);

    expect(result.stdout).toContain(`${statePath} (config_identity)`);
    expect(result.stdout).not.toContain('state-renamed.json');
  });

  it('reports same-id semantic divergence as explicit config recovery', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-doctor-semantic-divergence-'));
    const configPath = join(directory, 'engagement.json');
    const statePath = join(directory, 'state-shared.json');
    writeFileSync(configPath, JSON.stringify(engagementConfig('shared', {
      scope: { cidrs: [], domains: ['file.example'], exclusions: [] },
    })));
    writeFileSync(statePath, durableState('shared', 'preserved', {
      scope: { cidrs: [], domains: ['state.example'], exclusions: [] },
    }));

    const result = runDoctor(directory);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain(`${statePath} (config_id)`);
    expect(result.stdout).toContain('Config convergence');
    expect(result.stdout).toContain('different configuration semantics');
    expect(result.stdout).toContain('reconcile with the exact file/state hashes');
  });

  it('reports configuration authority as unknown when retained bases disagree', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-doctor-base-authority-'));
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

    const result = runDoctor(directory);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain(`${statePath} (config_id)`);
    expect(result.stdout).toContain('Config convergence');
    expect(result.stdout).toContain('retained recovery bases do not establish one configuration authority (legacy_unverified)');
    expect(result.stdout).not.toContain('active config does not match any preserved state family');
  });

  it('inventories beside an external config instead of the checkout root', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-doctor-external-'));
    const external = join(directory, 'external');
    const configPath = join(external, 'engagement.json');
    const statePath = join(external, 'state-external.json');
    const stateBytes = Buffer.from(durableState('external', 'preserved'));
    const rootStatePath = join(directory, 'state-unrelated.json');
    mkdirSync(external);
    writeFileSync(statePath, stateBytes);
    writeFileSync(rootStatePath, durableState('unrelated'));

    const result = runDoctor(directory, { OVERWATCH_CONFIG: configPath });

    expect(result.stdout).toContain(`preserved recovery state selected at ${statePath}`);
    expect(result.stdout).not.toContain(rootStatePath);
    expect(readFileSync(statePath)).toEqual(stateBytes);
  });

  it('treats parseable invalid JSON as invalid config and selects retained state', () => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-doctor-invalid-shape-'));
    const configPath = join(directory, 'engagement.json');
    const statePath = join(directory, 'state-recovery.json');
    writeFileSync(configPath, '{}');
    writeFileSync(statePath, durableState('recovery'));

    const result = runDoctor(directory);

    expect(result.stdout).toContain('schema validation failed');
    expect(result.stdout).toContain(`preserved recovery state selected at ${statePath}`);
    expect(result.stdout).not.toContain('state-undefined.json');
  });
});
