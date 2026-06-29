import { describe, it, expect } from 'vitest';
import { buildEngagementConfig, OPSEC_PROFILES, slugifyName } from '../engagement-builder.js';

describe('buildEngagementConfig', () => {
  it('mints id (slug + base36), ISO created_at, and a 64-hex nonce', () => {
    const cfg = buildEngagementConfig({ name: 'My Lab!! Test', cidrs: ['10.10.10.0/24'] });
    expect(cfg.id).toMatch(/^my-lab-test-[a-z0-9]+$/);
    expect(() => new Date(cfg.created_at).toISOString()).not.toThrow();
    expect(cfg.engagement_nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(cfg.scope.cidrs).toEqual(['10.10.10.0/24']);
  });

  it('defaults to the pentest OPSEC profile + network profile (flat path)', () => {
    const cfg = buildEngagementConfig({ name: 'x' });
    expect(cfg.opsec.name).toBe('pentest');
    expect(cfg.opsec.max_noise).toBe(0.7);
    expect(cfg.profile).toBe('network');
    expect(cfg.objectives).toEqual([]);
  });

  it('resolves a named opsec_profile (quiet → 0.2)', () => {
    const cfg = buildEngagementConfig({ name: 'x', opsec_profile: 'quiet' });
    expect(cfg.opsec.name).toBe('quiet');
    expect(cfg.opsec.max_noise).toBe(OPSEC_PROFILES.quiet.max_noise);
  });

  it('normalizes objectives (auto ids + achieved:false)', () => {
    const cfg = buildEngagementConfig({ name: 'x', objectives: [{ id: '', description: 'Get DA' }] });
    expect(cfg.objectives).toHaveLength(1);
    expect(cfg.objectives[0].description).toBe('Get DA');
    expect(cfg.objectives[0].achieved).toBe(false);
    expect(cfg.objectives[0].id).toBeTruthy();
  });

  it('rejects an invalid CIDR via the schema', () => {
    expect(() => buildEngagementConfig({ name: 'x', cidrs: ['not-a-cidr'] })).toThrow();
  });

  it('merges a template + overrides (template path)', () => {
    const cfg = buildEngagementConfig({ name: 'From CTF', template_id: 'ctf', cidrs: ['192.168.1.0/24'] });
    expect(cfg.template).toBe('ctf');
    expect(cfg.name).toBe('From CTF');
    expect(cfg.scope.cidrs).toEqual(['192.168.1.0/24']);
    expect(cfg.engagement_nonce).toMatch(/^[0-9a-f]{64}$/);
  });

  it('throws on an unknown template', () => {
    expect(() => buildEngagementConfig({ name: 'x', template_id: 'nope-does-not-exist' })).toThrow(/Template not found/);
  });

  it('slugifyName lowercases, hyphenates, and caps length', () => {
    expect(slugifyName('  Hello, World!  ')).toBe('hello-world');
    expect(slugifyName('a'.repeat(80)).length).toBeLessThanOrEqual(40);
  });
});
