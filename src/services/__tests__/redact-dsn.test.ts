import { describe, it, expect } from 'vitest';
import { redactDsn } from '../postgres-source.js';

describe('redactDsn', () => {
  it('redacts a URI-form password', () => {
    const out = redactDsn('postgres://svc:s3cret@db.corp.local:5432/app');
    expect(out).not.toContain('s3cret');
    expect(out).toContain('svc:[redacted]@');
    expect(out).toContain('db.corp.local:5432/app'); // host/port/db preserved
  });

  it('fully redacts a URI password containing @ (no tail leak — the old `[^@]*` bug)', () => {
    const out = redactDsn('postgres://svc:p@ss@w0rd@db.corp.local:5432/app');
    expect(out).not.toMatch(/ss@w0rd/);
    expect(out).not.toContain('p@ss@w0rd');
    expect(out).toContain('svc:[redacted]@');
    expect(out).toContain('db.corp.local');
  });

  it('redacts a libpq key/value DSN password (was left entirely unredacted)', () => {
    for (const dsn of [
      "host=db.corp.local user=svc password=s3cret dbname=app",
      "host=db user=svc password='s3 cret' sslmode=require",
      "password=s3cret host=db",
      "PGPASSWORD=s3cret",
    ]) {
      const out = redactDsn(dsn);
      expect(out).not.toContain('s3cret');
      expect(out).not.toContain('s3 cret');
      expect(out.toLowerCase()).toContain('password=[redacted]');
    }
  });

  it('redacts a URI password with NO trailing host (postgres://user:secret@)', () => {
    for (const dsn of ['postgres://user:supersecret@', 'postgres://user:secret@ ', 'postgres://user:pw@/var/run/pg']) {
      const out = redactDsn(dsn);
      expect(out).not.toContain('supersecret');
      expect(out).not.toMatch(/:secret@|:pw@/);
      expect(out).toContain(':[redacted]@');
    }
  });

  it('libpq redaction stops at delimiters (does not swallow following key/value pairs)', () => {
    const out = redactDsn('password=s3cret;host=db.corp.local&sslmode=require');
    expect(out).not.toContain('s3cret');
    expect(out).toContain('host=db.corp.local'); // following pairs preserved
    expect(out).toContain('sslmode=require');
  });

  it('redacts EVERY URI DSN in a multi-DSN string (g flag)', () => {
    const out = redactDsn('postgres://u1:p1secret@h1 postgres://u2:p2secret@h2');
    expect(out).not.toContain('p1secret');
    expect(out).not.toContain('p2secret'); // second DSN must not leak
  });

  it('leaves a passwordless DSN untouched', () => {
    const dsn = 'host=db user=svc dbname=app sslmode=require';
    expect(redactDsn(dsn)).toBe(dsn);
  });
});
