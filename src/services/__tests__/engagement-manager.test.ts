import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { EngagementConfig } from '../../types.js';
import { EngagementManager, EngagementManagerError } from '../engagement-manager.js';

function expectManagerError(
  action: () => unknown,
  code: EngagementManagerError['code'],
): void {
  try {
    action();
    throw new Error(`Expected ${code}`);
  } catch (error) {
    expect(error).toBeInstanceOf(EngagementManagerError);
    expect(error).toMatchObject({ code });
  }
}

describe('EngagementManager — engagement ID containment', () => {
  let dir: string;
  let activePath: string;
  let mgr: EngagementManager;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-eng-mgr-'));
    activePath = join(dir, 'engagement.json');
    mgr = new EngagementManager(activePath);
    // Seed one valid engagement so positive lookups still work.
    writeFileSync(
      join(mgr.engagementsDir, 'real-eng.json'),
      JSON.stringify({ id: 'real-eng', name: 'Real', scope: { cidrs: [], domains: [], exclusions: [] } }, null, 2),
    );
    // Seed a tempting target outside engagements/ to prove traversal can't reach it.
    writeFileSync(join(dir, 'secret.json'), JSON.stringify({ id: '../secret', name: 'leak' }));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('getEngagement reads a normal id', () => {
    const got = mgr.getEngagement('real-eng');
    expect(got?.id).toBe('real-eng');
  });

  it.each([
    '../secret',
    '..',
    '.',
    '.hidden',
    'has/slash',
    'has\\backslash',
    'with space',
    'null\u0000byte',
    '',
  ])('getEngagement refuses traversal/invalid id: %j', (id) => {
    expect(mgr.getEngagement(id)).toBeNull();
  });

  it.each(['../secret', 'has/slash', '.', '..'])('updateEngagement refuses traversal/invalid id: %j', (id) => {
    const before = readFileSync(join(dir, 'secret.json'), 'utf-8');
    expectManagerError(
      () => mgr.updateEngagement(id, { name: 'pwned' }),
      'ENGAGEMENT_VALIDATION_FAILED',
    );
    // sibling file untouched
    expect(readFileSync(join(dir, 'secret.json'), 'utf-8')).toBe(before);
  });

  it('does not create an engagements/ file for a rejected id', () => {
    expectManagerError(
      () => mgr.updateEngagement('../escape', { name: 'x' }),
      'ENGAGEMENT_VALIDATION_FAILED',
    );
    expect(existsSync(join(mgr.engagementsDir, '../escape.json'))).toBe(false);
  });

  it('distinguishes a missing engagement from invalid input', () => {
    expectManagerError(
      () => mgr.updateEngagement('missing-engagement', { name: 'x' }),
      'ENGAGEMENT_NOT_FOUND',
    );
  });
});

describe('EngagementManager — editing the ACTIVE engagement targets the live config', () => {
  let dir: string;
  let activePath: string;
  let mgr: EngagementManager;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-eng-active-'));
    activePath = join(dir, 'engagement.json');
    mgr = new EngagementManager(activePath);
    // The ACTIVE engagement lives at the active config path.
    writeFileSync(activePath, JSON.stringify({
      id: 'act-eng', name: 'Live', created_at: '2026-01-01T00:00:00.000Z',
      scope: { cidrs: [], domains: [], exclusions: [] }, objectives: [],
      opsec: { name: 'pentest', max_noise: 0.5 },
    }, null, 2));
    // A stale mirror in engagements/ that edits must NOT hit.
    writeFileSync(join(mgr.engagementsDir, 'act-eng.json'), JSON.stringify({
      id: 'act-eng', name: 'Stale Mirror', created_at: '2026-01-01T00:00:00.000Z',
      scope: { cidrs: [], domains: [], exclusions: [] }, objectives: [],
      opsec: { name: 'pentest', max_noise: 0.5 },
    }, null, 2));
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('writes the active config (visible to getEngagement), not the stale mirror', () => {
    const updated = mgr.updateEngagement('act-eng', { name: 'Renamed Live' });
    expect(updated?.name).toBe('Renamed Live');
    // getEngagement reads the active config → reflects the edit (was unchanged before the fix)
    expect(mgr.getEngagement('act-eng')?.name).toBe('Renamed Live');
    expect(JSON.parse(readFileSync(activePath, 'utf-8')).name).toBe('Renamed Live');
    // the stale mirror is left untouched
    expect(JSON.parse(readFileSync(join(mgr.engagementsDir, 'act-eng.json'), 'utf-8')).name).toBe('Stale Mirror');
  });
});

// ============================================================
// Dashboard create-flow round-trip
// Mirrors the exact payload shape posted by the React EngagementsPanel
// "Create Engagement" form so we catch regressions where the produced
// engagement.json fails to load via parseEngagementConfig() — i.e. would
// not be a valid engagement file the server can boot from.
// ============================================================

describe('EngagementManager — dashboard create flow produces a valid engagement.json', () => {
  let dir: string;
  let activePath: string;
  let mgr: EngagementManager;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-eng-create-'));
    activePath = join(dir, 'engagement.json');
    mgr = new EngagementManager(activePath);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  // The exact shape posted by CreateEngagementForm.submit() with no template.
  function dashboardPayload(overrides: Record<string, unknown> = {}) {
    return {
      name: 'Test Engagement',
      profile: 'network',
      cidrs: ['10.0.0.0/24'],
      domains: ['corp.local'],
      exclusions: ['10.0.0.1'],
      hosts: undefined,
      url_patterns: undefined,
      aws_accounts: undefined,
      azure_subscriptions: undefined,
      gcp_projects: undefined,
      opsec: {
        max_noise: 0.7,
        approval_mode: 'approve-critical',
        approval_timeout_ms: 300_000,
        // UI sends null when no time window is configured.
        time_window: null,
        blacklisted_techniques: undefined,
      },
      objectives: [
        { id: 'obj-1', description: 'Achieve Domain Admin' },
      ],
      failure_patterns: undefined,
      phases: undefined,
      ...overrides,
    } as Parameters<EngagementManager['createEngagement']>[0];
  }

  it('write the file and reload it via parseEngagementConfig (no template)', async () => {
    const summary = mgr.createEngagement(dashboardPayload());
    expect(summary.id).toMatch(/^test-engagement-/);
    expect(existsSync(summary.config_path)).toBe(true);

    const { parseEngagementConfig } = await import('../../config.js');
    const raw = readFileSync(summary.config_path, 'utf-8');
    const cfg = parseEngagementConfig(raw);

    expect(cfg.id).toBe(summary.id);
    expect(cfg.scope.cidrs).toEqual(['10.0.0.0/24']);
    expect(cfg.opsec.name).toBe('pentest');
    expect(cfg.opsec.max_noise).toBe(0.7);
    expect(cfg.opsec.approval_mode).toBe('approve-critical');
    // Crucial: `time_window: null` from the UI must not leak into the file
    // (schema treats the field as an optional object — null is rejected).
    expect(cfg.opsec.time_window).toBeUndefined();
    expect(cfg.objectives[0].achieved).toBe(false);
  });

  it('writes the file and reloads it via parseEngagementConfig (with template)', async () => {
    const summary = mgr.createEngagement(dashboardPayload({
      template_id: 'internal-pentest',
      profile: 'goad_ad',
    }));
    const { parseEngagementConfig } = await import('../../config.js');
    const cfg = parseEngagementConfig(readFileSync(summary.config_path, 'utf-8'));

    expect(cfg.template).toBe('internal-pentest');
    expect(cfg.profile).toBe('goad_ad');
    expect(cfg.opsec.name).toBe('pentest');
    expect(cfg.opsec.time_window).toBeUndefined();
    expect(cfg.phases?.length).toBeGreaterThan(0);
  });

  it('preserves an explicit time_window when supplied', async () => {
    const summary = mgr.createEngagement(dashboardPayload({
      opsec: {
        max_noise: 0.5,
        approval_mode: 'approve-critical',
        approval_timeout_ms: 60_000,
        time_window: { start_hour: 9, end_hour: 17 },
      },
    }));
    const { parseEngagementConfig } = await import('../../config.js');
    const cfg = parseEngagementConfig(readFileSync(summary.config_path, 'utf-8'));
    expect(cfg.opsec.time_window).toEqual({ start_hour: 9, end_hour: 17 });
  });

  it('produced file is bootable: loadEngagementConfigFile reads it back', async () => {
    const summary = mgr.createEngagement(dashboardPayload());
    const { loadEngagementConfigFile } = await import('../../config.js');
    const cfg = loadEngagementConfigFile(summary.config_path);
    expect(cfg.id).toBe(summary.id);
    expect(cfg.name).toBe('Test Engagement');
  });

  it('persistConfig writes a pre-built config to engagements/<id>.json (from-template path)', async () => {
    const { buildEngagementConfig } = await import('../engagement-builder.js');
    const config = buildEngagementConfig({ name: 'Prebuilt', cidrs: ['10.0.0.0/24'] });
    const summary = mgr.persistConfig(config);
    expect(existsSync(summary.config_path)).toBe(true);
    expect(summary.id).toBe(config.id);
    const { loadEngagementConfigFile } = await import('../../config.js');
    expect(loadEngagementConfigFile(summary.config_path).id).toBe(config.id);
  });

  it('persistConfig refuses an unsafe (path-traversal) id', async () => {
    const { buildEngagementConfig } = await import('../engagement-builder.js');
    const config = buildEngagementConfig({ name: 'x' });
    (config as { id: string }).id = '../escape';
    expect(() => mgr.persistConfig(config)).toThrow(/unsafe id/i);
    expect(existsSync(join(dir, 'escape.json'))).toBe(false);
  });

  it('persistConfig refuses to silently overwrite an existing engagement', async () => {
    const { buildEngagementConfig } = await import('../engagement-builder.js');
    const config = buildEngagementConfig({ name: 'Dup' });
    mgr.persistConfig(config);
    expect(() => mgr.persistConfig(config)).toThrow(/already exists/i);
  });

  it('persistConfig mints a 64-hex nonce when the config lacks one (from-template invariant)', async () => {
    const { buildEngagementConfig } = await import('../engagement-builder.js');
    const config = buildEngagementConfig({ name: 'NoNonce' });
    delete (config as { engagement_nonce?: string }).engagement_nonce;
    const summary = mgr.persistConfig(config);
    const written = JSON.parse(readFileSync(summary.config_path, 'utf-8'));
    expect(written.engagement_nonce).toMatch(/^[0-9a-f]{64}$/);
  });

  it('classifies a durable create failure separately from validation and conflicts', async () => {
    const failure = Object.assign(new Error('disk full'), { code: 'ENOSPC' });
    const failing = new EngagementManager(activePath, () => { throw failure; });
    const { buildEngagementConfig } = await import('../engagement-builder.js');
    const config = buildEngagementConfig({ name: 'Must Persist' });

    expectManagerError(
      () => failing.persistConfig(config),
      'ENGAGEMENT_PERSISTENCE_FAILED',
    );
  });

  it('classifies inactive update validation, stored-config conflict, and durable write failure', async () => {
    const { buildEngagementConfig } = await import('../engagement-builder.js');
    const stored = buildEngagementConfig({ name: 'Inactive Stored' });
    writeFileSync(join(mgr.engagementsDir, `${stored.id}.json`), JSON.stringify(stored));

    expectManagerError(
      () => mgr.updateEngagement(stored.id, { scope: { cidrs: ['not-a-cidr'] } }),
      'ENGAGEMENT_VALIDATION_FAILED',
    );

    writeFileSync(join(mgr.engagementsDir, `${stored.id}.json`), '{"id":');
    expectManagerError(
      () => mgr.updateEngagement(stored.id, { name: 'Cannot repair implicitly' }),
      'ENGAGEMENT_CONFLICT',
    );

    const invalidStored = { ...stored, name: '' };
    writeFileSync(join(mgr.engagementsDir, `${stored.id}.json`), JSON.stringify(invalidStored));
    expectManagerError(
      () => mgr.updateEngagement(stored.id, { name: 'Cannot repair implicitly' }),
      'ENGAGEMENT_CONFLICT',
    );

    writeFileSync(join(mgr.engagementsDir, `${stored.id}.json`), JSON.stringify(stored));
    const failing = new EngagementManager(activePath, () => {
      throw Object.assign(new Error('read-only filesystem'), { code: 'EROFS' });
    });
    expectManagerError(
      () => failing.updateEngagement(stored.id, { name: 'Must Persist' }),
      'ENGAGEMENT_PERSISTENCE_FAILED',
    );
  });

  it('rejects malformed or unsupported inactive PATCH values without rewriting the file', async () => {
    const { buildEngagementConfig } = await import('../engagement-builder.js');
    const stored = buildEngagementConfig({ name: 'Strict Inactive Patch' });
    const path = join(mgr.engagementsDir, `${stored.id}.json`);
    writeFileSync(path, JSON.stringify(stored));
    const before = readFileSync(path);

    const invalidUpdates: Record<string, unknown>[] = [
      {},
      { name: 42 },
      { ignored_setting: true },
      { scope: { cidrs: '10.0.0.0/24' } },
      { scope: { cidrs: [], ignored_scope_key: true } },
      { opsec: { approval_timeout_seconds: 30 } },
      { available_models: ['valid-model', 42] },
    ];
    for (const update of invalidUpdates) {
      expectManagerError(
        () => mgr.updateEngagement(stored.id, update),
        'ENGAGEMENT_VALIDATION_FAILED',
      );
      expect(readFileSync(path)).toEqual(before);
    }
  });

  it('preserves valid partial-merge behavior and avoids revision bumps for semantic no-ops', async () => {
    const { buildEngagementConfig } = await import('../engagement-builder.js');
    const stored = buildEngagementConfig({ name: 'Valid Inactive Patch' });
    const summary = mgr.persistConfig(stored);
    const before = JSON.parse(readFileSync(summary.config_path, 'utf8')) as EngagementConfig;

    const updated = mgr.updateEngagement(stored.id, {
      name: 'Valid Inactive Patch Updated',
      scope: { domains: ['example.test'] },
      opsec: { enabled: true, max_noise: 0.4, time_window: null },
      available_models: ['model-a', 'model-b'],
      objectives: [{ id: 'objective-1', description: 'Validate updates', achieved: false }],
      failure_patterns: [{ technique: 'enumeration', warning: 'watch the logs' }],
      phases: [{ id: 'phase-1', name: 'Recon', order: 0 }],
    });
    expect(updated).toMatchObject({
      name: 'Valid Inactive Patch Updated',
      config_revision: (before.config_revision ?? 0) + 1,
      scope: { domains: ['example.test'] },
      opsec: { enabled: true, max_noise: 0.4 },
      available_models: ['model-a', 'model-b'],
    });

    const bytesAfterUpdate = readFileSync(summary.config_path);
    const noOp = mgr.updateEngagement(stored.id, { name: updated.name });
    expect(noOp.config_revision).toBe(updated.config_revision);
    expect(readFileSync(summary.config_path)).toEqual(bytesAfterUpdate);
  });
});
