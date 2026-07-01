import { describe, it, expect } from 'vitest';
import { matchesSubjectPattern } from '../cross-tier-inference.js';

describe('matchesSubjectPattern — OIDC sub-claim wildcard matching', () => {
  it('matches literals and single wildcards (segment + trailing)', () => {
    expect(matchesSubjectPattern('repo:acme/webapp:ref:refs/heads/main', 'repo:acme/webapp:ref:refs/heads/main')).toBe(true);
    expect(matchesSubjectPattern('repo:acme/webapp:ref:refs/heads/main', 'repo:acme/*:ref:refs/heads/main')).toBe(true);
    // Trailing wildcard spans colons (semantics preserved with .*).
    expect(matchesSubjectPattern('repo:acme/webapp:ref:refs/heads/main', 'repo:acme/webapp:*')).toBe(true);
    expect(matchesSubjectPattern('repo:acme/webapp:ref:refs/heads/main', 'repo:evil/*')).toBe(false);
  });

  it('undefined pattern matches; undefined subject does not', () => {
    expect(matchesSubjectPattern('anything', undefined)).toBe(true);
    expect(matchesSubjectPattern(undefined, 'repo:*')).toBe(false);
  });

  it('escapes regex metacharacters in the pattern (no injection)', () => {
    expect(matchesSubjectPattern('a.b', 'a.b')).toBe(true);
    expect(matchesSubjectPattern('axb', 'a.b')).toBe(false); // `.` is literal, not any-char
  });

  it('does not ReDoS on adjacent wildcards against a long non-matching subject', () => {
    // Pre-fix this built `.+.+.+…` → catastrophic backtracking. Must complete fast.
    const pattern = 'repo:' + '*'.repeat(50) + ':x';
    const subject = 'repo:' + 'a'.repeat(2000); // no trailing `:x` → forces backtracking
    const start = process.hrtime.bigint();
    const result = matchesSubjectPattern(subject, pattern);
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
    expect(result).toBe(false);
    expect(elapsedMs).toBeLessThan(100); // linear, not exponential
  });

  it('rejects an over-long pattern/subject instead of compiling a huge regex', () => {
    expect(matchesSubjectPattern('x', 'a'.repeat(300))).toBe(false);
    expect(matchesSubjectPattern('a'.repeat(2000), 'a*')).toBe(false);
  });
});
