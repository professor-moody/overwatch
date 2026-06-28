import { describe, it, expect } from 'vitest';
import { isPassiveTechnique, PASSIVE_TECHNIQUES } from '../osint-techniques.js';

describe('OSINT technique classification (Phase 2B)', () => {
  it('classifies public-source techniques as passive (0 noise, off-target)', () => {
    expect(isPassiveTechnique('crt_sh')).toBe(true);
    expect(isPassiveTechnique('whois')).toBe(true);
    expect(isPassiveTechnique('subfinder')).toBe(true);
    expect(isPassiveTechnique('theharvester')).toBe(true);
    expect(PASSIVE_TECHNIQUES.has('passive_dns')).toBe(true);
  });

  it('treats light-active and target-facing techniques as NOT passive', () => {
    // Light-active OSINT contacts in-scope assets → ordinary low-noise path.
    expect(isPassiveTechnique('httpx')).toBe(false);
    expect(isPassiveTechnique('dnsx')).toBe(false);
    // Target-facing techniques.
    expect(isPassiveTechnique('portscan')).toBe(false);
    expect(isPassiveTechnique(undefined)).toBe(false);
    expect(isPassiveTechnique(null)).toBe(false);
    expect(isPassiveTechnique('')).toBe(false);
  });
});
