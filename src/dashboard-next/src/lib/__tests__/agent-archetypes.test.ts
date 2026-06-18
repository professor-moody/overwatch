import { describe, it, expect } from 'vitest';
import { classifyDeployInput, recommendArchetypeFor } from '../agent-archetypes';

describe('classifyDeployInput', () => {
  it('treats IP/CIDR/domain input as a raw quick-deploy target', () => {
    expect(classifyDeployInput('10.20.0.20')).toMatchObject({ kind: 'raw', cidrs: ['10.20.0.20/32'] });
    expect(classifyDeployInput('10.30.0.0/24')).toMatchObject({ kind: 'raw', cidrs: ['10.30.0.0/24'] });
    expect(classifyDeployInput('evil.example.com')).toMatchObject({ kind: 'raw', domains: ['evil.example.com'] });
    const mixed = classifyDeployInput('10.20.0.20, shop.example.com');
    expect(mixed.kind).toBe('raw');
    if (mixed.kind === 'raw') expect(mixed.target).toBe('10.20.0.20, shop.example.com');
  });

  it('treats graph node ids (no valid target) as node-dispatch', () => {
    const r = classifyDeployInput('h-app cred-oidc cloud-id-power');
    expect(r).toEqual({ kind: 'nodes', nodeIds: ['h-app', 'cred-oidc', 'cloud-id-power'] });
  });

  it('is empty for blank input', () => {
    expect(classifyDeployInput('   ')).toEqual({ kind: 'empty' });
  });

  it('flags valid-target + unrecognized-token input as mixed (blocking, not a silent drop)', () => {
    const r = classifyDeployInput('10.0.0.5 cred-oidc');
    expect(r.kind).toBe('mixed');
    if (r.kind === 'mixed') {
      expect(r.cidrs).toEqual(['10.0.0.5/32']);
      expect(r.invalid).toContain('cred-oidc');
    }
  });
});

describe('recommendArchetypeFor', () => {
  it('recommends recon for a raw target', () => {
    expect(recommendArchetypeFor({ rawTarget: true })).toBe('recon_scanner');
  });
  it('recommends by node type, default fallback', () => {
    expect(recommendArchetypeFor({ nodeType: 'credential' })).toBe('credential_operator');
    expect(recommendArchetypeFor({ nodeType: 'webapp' })).toBe('web_tester');
    expect(recommendArchetypeFor({ nodeType: 'host' })).toBe('recon_scanner');
    expect(recommendArchetypeFor({ nodeType: 'unknown' })).toBe('default');
    expect(recommendArchetypeFor({})).toBe('default');
  });
});
