import { describe, it, expect } from 'vitest';
import {
  BoundedStreamBuffer,
  STREAM_HARD_CAP,
  STREAM_HEAD_KEEP,
  STREAM_TAIL_KEEP,
  scrubSecretsFromText,
  REDACTED_SECRET,
  TRUNCATION_MARKER,
} from '../_process-runner.js';

describe('scrubSecretsFromText', () => {
  it('replaces every occurrence of each secret', () => {
    const out = scrubSecretsFromText('login as admin with hunter2 (hunter2)', ['hunter2']);
    expect(out).not.toContain('hunter2');
    expect(out.split(REDACTED_SECRET).length - 1).toBe(2);
  });

  it('scrubs the url-encoded form of a secret (reflected form body)', () => {
    const out = scrubSecretsFromText('echo: p%40ss%20word', ['p@ss word', 'p%40ss%20word']);
    expect(out).not.toContain('p%40ss%20word');
  });

  it('scrubs a secret split across the inline-truncation marker (no partial leak)', () => {
    const secret = 'S3cr3tPassw0rd';
    const straddled = secret.slice(0, 5) + TRUNCATION_MARKER + secret.slice(5); // head|marker|tail
    const out = scrubSecretsFromText(`before ${straddled} after`, [secret]);
    expect(out).not.toContain(secret.slice(0, 5)); // no head fragment
    expect(out).not.toContain(secret.slice(5));    // no tail fragment
    expect(out).toContain(TRUNCATION_MARKER);       // truncation signal preserved
  });

  it('is a no-op with no secrets or empty text', () => {
    expect(scrubSecretsFromText('nothing here', [])).toBe('nothing here');
    expect(scrubSecretsFromText('', ['x'])).toBe('');
  });
});

describe('BoundedStreamBuffer', () => {
  it('retains everything below the hard cap', () => {
    const buf = new BoundedStreamBuffer();
    buf.push(Buffer.from('hello '));
    buf.push(Buffer.from('world'));
    expect(buf.total_bytes).toBe(11);
    expect(buf.dropped_bytes).toBe(0);
    expect(buf.cap_exceeded).toBe(false);
    expect(buf.toFullString()).toBe('hello world');
  });

  it('drops middle bytes once the hard cap is exceeded but keeps head and tail', () => {
    const buf = new BoundedStreamBuffer();
    // 1 MiB chunks of distinct content so we can find them in the result.
    const chunkSize = 1024 * 1024;
    const headFiller = Buffer.alloc(chunkSize, 'H'.charCodeAt(0));
    const midFiller = Buffer.alloc(chunkSize, 'M'.charCodeAt(0));
    const tailFiller = Buffer.alloc(chunkSize, 'T'.charCodeAt(0));

    // Fill head window (4 MiB).
    for (let i = 0; i < STREAM_HEAD_KEEP / chunkSize; i++) buf.push(headFiller);
    // Push enough middle to overflow the cap by a wide margin (e.g. 32 MiB).
    for (let i = 0; i < 32; i++) buf.push(midFiller);
    // Push 4 MiB of tail.
    for (let i = 0; i < STREAM_TAIL_KEEP / chunkSize; i++) buf.push(tailFiller);

    expect(buf.cap_exceeded).toBe(true);
    expect(buf.total_bytes).toBe(STREAM_HEAD_KEEP + 32 * chunkSize + STREAM_TAIL_KEEP);
    expect(buf.dropped_bytes).toBeGreaterThan(0);
    // Retained memory is bounded.
    const out = buf.toFullString();
    // head + marker + tail. Allow a small slack for the marker.
    expect(out.length).toBeLessThan(STREAM_HEAD_KEEP + STREAM_TAIL_KEEP + 1024);
    // Head bytes preserved at start, tail bytes preserved at end.
    expect(out.slice(0, 4)).toBe('HHHH');
    expect(out.slice(-4)).toBe('TTTT');
    // Truncation marker present.
    expect(out).toMatch(/middle bytes dropped/);
  });

  it('total_bytes always reflects produced bytes even with extreme input', () => {
    const buf = new BoundedStreamBuffer();
    const big = Buffer.alloc(STREAM_HARD_CAP + 1024 * 1024, 0x41); // 17 MiB of 'A'
    buf.push(big);
    expect(buf.total_bytes).toBe(big.length);
    expect(buf.cap_exceeded).toBe(true);
    // Retained is bounded.
    const retained = buf.toFullString();
    expect(retained.length).toBeLessThan(STREAM_HEAD_KEEP + STREAM_TAIL_KEEP + 1024);
  });
});
