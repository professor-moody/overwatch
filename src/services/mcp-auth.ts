// ============================================================
// Overwatch — MCP HTTP transport auth
// Bearer-token guard for the /mcp endpoint when Overwatch runs as a
// daemon with multiple MCP clients (primary + headless sub-agents).
//
// Policy (fail-closed where it matters):
//  - If OVERWATCH_MCP_TOKEN is set, it is ALWAYS enforced (even on loopback) —
//    if you configured a token, you meant it.
//  - If the bind host is non-loopback, a token is REQUIRED (403 if unset).
//  - If `requireToken` is true (e.g. headless sub-agents enabled), a token is
//    REQUIRED even on loopback.
//  - Otherwise (loopback dev, no token, not required), the endpoint is open —
//    preserving the zero-config local experience.
// ============================================================

import type { Request, Response, NextFunction } from 'express';
import { timingSafeEqual, createHash } from 'crypto';
import { isIPv6 } from 'net';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]', '0:0:0:0:0:0:0:1']);

/** True for any IPv6 loopback representation (`::1`, `0:0:…:1`, `0000::0001`, …).
 *  Expands `::` and checks all groups are zero except a final `1`, so a
 *  non-canonical loopback bind host is still recognised. */
function isIpv6Loopback(addr: string): boolean {
  const s = addr.replace(/^\[/, '').replace(/\]$/, '');
  if (!isIPv6(s)) return false;
  const halves = s.split('::');
  let groups: string[];
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    const fill = 8 - left.length - right.length;
    if (fill < 0) return false;
    groups = [...left, ...new Array(fill).fill('0'), ...right];
  } else {
    groups = s.split(':');
  }
  // Every group must be a pure 1–4 hex field. Without this, an embedded-IPv4
  // suffix (`::1.2.3.4`) survives as one "group" and parseInt('1.2.3.4',16)===1,
  // which would misclassify a routable address as loopback.
  if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/.test(g || '0'))) return false;
  return groups.slice(0, 7).every(g => parseInt(g, 16) === 0) && parseInt(groups[7], 16) === 1;
}

export function isLoopbackHost(host: string | undefined): boolean {
  if (!host) return false;
  const t = host.trim().toLowerCase();
  if (LOOPBACK_HOSTS.has(t)) return true;
  return isIpv6Loopback(t);
}

/** Constant-time token comparison. Both tokens are SHA-256'd to a fixed 32-byte
 *  digest so `timingSafeEqual` gets equal-length buffers (it throws otherwise)
 *  and there is no early-exit or length side-channel on the raw token. */
function tokensMatch(provided: string | null, expected: string): boolean {
  if (provided === null) return false;
  const a = createHash('sha256').update(provided).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

export interface McpAuthOptions {
  /** The host the MCP server is bound to. */
  host: string;
  /** Force a token even on loopback (e.g. when headless sub-agents are enabled). */
  requireToken?: boolean;
  /**
   * Token resolver — defaults to reading OVERWATCH_MCP_TOKEN at call time so
   * tests can inject a value without mutating process.env.
   */
  getToken?: () => string | undefined;
}

function extractBearer(req: Request): string | null {
  const auth = req.headers['authorization'];
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

/**
 * Express middleware enforcing the policy above. Exported separately from app.ts
 * so it can be unit-tested without standing up the full HTTP transport.
 */
export function createMcpAuthMiddleware(opts: McpAuthOptions) {
  const getToken = opts.getToken ?? (() => process.env.OVERWATCH_MCP_TOKEN);
  const loopback = isLoopbackHost(opts.host);
  return (req: Request, res: Response, next: NextFunction): void => {
    const expected = getToken();
    // Enforce when: a token is configured at all, OR explicitly required, OR a
    // non-loopback bind. Loopback + no token + not required => open (dev).
    const enforce = !!expected || opts.requireToken === true || !loopback;
    if (!enforce) {
      next();
      return;
    }
    if (!expected) {
      res.status(403).json({ error: 'OVERWATCH_MCP_TOKEN is required but not configured' });
      return;
    }
    if (!tokensMatch(extractBearer(req), expected)) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  };
}
