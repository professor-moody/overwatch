import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { EngagementManager } from '../engagement-manager.js';

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
    expect(mgr.updateEngagement(id, { name: 'pwned' })).toBeNull();
    // sibling file untouched
    expect(readFileSync(join(dir, 'secret.json'), 'utf-8')).toBe(before);
  });

  it('does not create an engagements/ file for a rejected id', () => {
    mgr.updateEngagement('../escape', { name: 'x' });
    expect(existsSync(join(mgr.engagementsDir, '../escape.json'))).toBe(false);
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
});
