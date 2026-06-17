import { describe, it, expect } from 'vitest';
import { parseTargetBlob, mergeScopeWithTargets, hasParsedTargets } from '../target-input';
import type { ScopeConfig } from '../types';

describe('parseTargetBlob', () => {
  it('classifies CIDR, bare IP (→/32), and domain (lowercased)', () => {
    const r = parseTargetBlob('10.0.0.0/24 10.20.0.5 Example.COM');
    expect(r.cidrs).toEqual(['10.0.0.0/24', '10.20.0.5/32']);
    expect(r.domains).toEqual(['example.com']);
    expect(r.invalid).toEqual([]);
  });

  it('tokenizes on whitespace and commas (matches the command bar splitter)', () => {
    const r = parseTargetBlob('10.0.0.0/24,  10.0.0.1\n10.0.0.2 , evil.example.com');
    expect(r.cidrs).toEqual(['10.0.0.0/24', '10.0.0.1/32', '10.0.0.2/32']);
    expect(r.domains).toEqual(['evil.example.com']);
  });

  it('rejects IPv6 and other junk as invalid', () => {
    const r = parseTargetBlob('2001:db8::1 fe80::1 not_a_host ::1');
    expect(r.cidrs).toEqual([]);
    expect(r.domains).toEqual([]);
    expect(r.invalid).toEqual(['2001:db8::1', 'fe80::1', 'not_a_host', '::1']);
  });

  it('mirrors command-bar quirks: trailing-dot domain invalid, octets not range-checked', () => {
    // DOMAIN_RE rejects a trailing dot; structural regexes don't range-check octets.
    const r = parseTargetBlob('example.com. 999.1.2.3 10.0.0.0/99');
    expect(r.domains).toEqual([]);
    expect(r.invalid).toContain('example.com.');
    expect(r.cidrs).toEqual(['999.1.2.3/32', '10.0.0.0/99']);
  });

  it('dedupes within each bucket', () => {
    const r = parseTargetBlob('10.0.0.5 10.0.0.5 a.com a.com 10.0.0.0/24 10.0.0.0/24');
    expect(r.cidrs).toEqual(['10.0.0.5/32', '10.0.0.0/24']);
    expect(r.domains).toEqual(['a.com']);
  });

  it('returns empty buckets for an empty/whitespace blob', () => {
    const r = parseTargetBlob('   \n  ,, ');
    expect(r.cidrs).toEqual([]);
    expect(r.domains).toEqual([]);
    expect(r.invalid).toEqual([]);
    expect(r.truncated).toBe(false);
    expect(hasParsedTargets(r)).toBe(false);
  });

  it('caps the valid set and flags truncation', () => {
    const many = Array.from({ length: 300 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256}`).join(' ');
    const r = parseTargetBlob(many);
    expect(r.cidrs.length).toBe(256);
    expect(r.truncated).toBe(true);
  });
});

describe('mergeScopeWithTargets', () => {
  it('unions new cidrs/domains into current scope, preserving other fields', () => {
    const current: ScopeConfig = {
      cidrs: ['10.0.0.0/24'],
      domains: ['old.example.com'],
      exclusions: ['10.0.0.9/32'],
      hosts: ['jump'],
    };
    const parsed = parseTargetBlob('10.30.0.0/24 new.example.com 10.0.0.0/24');
    const merged = mergeScopeWithTargets(current, parsed);
    expect(merged.cidrs).toEqual(['10.0.0.0/24', '10.30.0.0/24']); // existing first, deduped
    expect(merged.domains).toEqual(['old.example.com', 'new.example.com']);
    expect(merged.exclusions).toEqual(['10.0.0.9/32']); // untouched
    expect(merged.hosts).toEqual(['jump']); // untouched
  });

  it('handles undefined current scope', () => {
    const parsed = parseTargetBlob('10.0.0.0/24 a.com');
    const merged = mergeScopeWithTargets(undefined, parsed);
    expect(merged.cidrs).toEqual(['10.0.0.0/24']);
    expect(merged.domains).toEqual(['a.com']);
  });
});

describe('hasParsedTargets', () => {
  it('is true only when there is at least one valid target', () => {
    expect(hasParsedTargets(parseTargetBlob('10.0.0.0/24'))).toBe(true);
    expect(hasParsedTargets(parseTargetBlob('a.com'))).toBe(true);
    expect(hasParsedTargets(parseTargetBlob('garbage ::1'))).toBe(false);
  });
});
