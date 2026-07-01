import { describe, it, expect, vi } from 'vitest';
import { createMcpAuthMiddleware, isLoopbackHost } from '../mcp-auth.js';

function makeReqRes(headers: Record<string, string> = {}) {
  const req = { headers } as any;
  const res = {
    statusCode: 0,
    body: undefined as unknown,
    status(code: number) { this.statusCode = code; return this; },
    json(payload: unknown) { this.body = payload; return this; },
  };
  const next = vi.fn();
  return { req, res, next };
}

describe('isLoopbackHost', () => {
  it('recognizes loopback hosts', () => {
    for (const h of ['127.0.0.1', 'localhost', '::1', '[::1]', 'LOCALHOST']) {
      expect(isLoopbackHost(h)).toBe(true);
    }
  });
  it('rejects non-loopback / empty hosts', () => {
    for (const h of ['0.0.0.0', '10.0.0.5', 'example.com', '', undefined as unknown as string]) {
      expect(isLoopbackHost(h)).toBe(false);
    }
  });
  it('recognizes non-canonical IPv6 loopback forms', () => {
    for (const h of ['0:0:0:0:0:0:0:1', '0000::0001', '::0001', '[0:0:0:0:0:0:0:1]', '0000:0000:0000:0000:0000:0000:0000:0001']) {
      expect(isLoopbackHost(h)).toBe(true);
    }
  });
  it('rejects non-loopback IPv6 addresses', () => {
    for (const h of ['::2', 'fe80::1', '2001:db8::1', '::']) {
      expect(isLoopbackHost(h)).toBe(false);
    }
  });
  it('rejects embedded-IPv4 addresses that superficially look like ::1 (e.g. ::1.2.3.4)', () => {
    for (const h of ['::1.2.3.4', '[::1.2.3.4]', '::1.99.99.99', '::0:1.2.3.4']) {
      expect(isLoopbackHost(h)).toBe(false);
    }
  });
});

describe('createMcpAuthMiddleware', () => {
  it('loopback + no token + not required → open (calls next)', () => {
    const mw = createMcpAuthMiddleware({ host: '127.0.0.1', getToken: () => undefined });
    const { req, res, next } = makeReqRes();
    mw(req, res as any, next);
    expect(next).toHaveBeenCalledOnce();
    expect(res.statusCode).toBe(0);
  });

  it('non-loopback + no token → 403 (token required but unset)', () => {
    const mw = createMcpAuthMiddleware({ host: '0.0.0.0', getToken: () => undefined });
    const { req, res, next } = makeReqRes();
    mw(req, res as any, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it('requireToken + no token → 403 even on loopback', () => {
    const mw = createMcpAuthMiddleware({ host: '127.0.0.1', requireToken: true, getToken: () => undefined });
    const { req, res, next } = makeReqRes();
    mw(req, res as any, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it('token configured + matching bearer → next()', () => {
    const mw = createMcpAuthMiddleware({ host: '127.0.0.1', getToken: () => 'secret' });
    const { req, res, next } = makeReqRes({ authorization: 'Bearer secret' });
    mw(req, res as any, next);
    expect(next).toHaveBeenCalledOnce();
    expect(res.statusCode).toBe(0);
  });

  it('token configured + missing/wrong bearer → 401 (enforced even on loopback)', () => {
    const mw = createMcpAuthMiddleware({ host: '127.0.0.1', getToken: () => 'secret' });

    const missing = makeReqRes();
    mw(missing.req, missing.res as any, missing.next);
    expect(missing.next).not.toHaveBeenCalled();
    expect(missing.res.statusCode).toBe(401);

    const wrong = makeReqRes({ authorization: 'Bearer nope' });
    mw(wrong.req, wrong.res as any, wrong.next);
    expect(wrong.next).not.toHaveBeenCalled();
    expect(wrong.res.statusCode).toBe(401);
  });

  it('constant-time compare handles a DIFFERENT-LENGTH bearer without throwing (401, not a crash)', () => {
    const mw = createMcpAuthMiddleware({ host: '127.0.0.1', getToken: () => 'a-long-secret-token' });
    const short = makeReqRes({ authorization: 'Bearer x' });
    expect(() => mw(short.req, short.res as any, short.next)).not.toThrow();
    expect(short.next).not.toHaveBeenCalled();
    expect(short.res.statusCode).toBe(401);
    // exact match still succeeds
    const okReq = makeReqRes({ authorization: 'Bearer a-long-secret-token' });
    mw(okReq.req, okReq.res as any, okReq.next);
    expect(okReq.next).toHaveBeenCalledOnce();
  });

  it('non-loopback + matching token → next()', () => {
    const mw = createMcpAuthMiddleware({ host: '10.0.0.5', getToken: () => 'secret' });
    const { req, res, next } = makeReqRes({ authorization: 'Bearer secret' });
    mw(req, res as any, next);
    expect(next).toHaveBeenCalledOnce();
  });
});
