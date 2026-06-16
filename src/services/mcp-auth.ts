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

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]', '0:0:0:0:0:0:0:1']);

export function isLoopbackHost(host: string | undefined): boolean {
  if (!host) return false;
  return LOOPBACK_HOSTS.has(host.trim().toLowerCase());
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
    if (extractBearer(req) !== expected) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  };
}
