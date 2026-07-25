import { createConnection } from 'node:net';

/**
 * L5: liveness probe by CONNECTING to a port, not by binding it.
 *
 * The daemon lifecycle wrapper polls the runtime port to detect readiness. The
 * old occupancy test BOUND the port (net.createServer().listen) — which races the
 * daemon child that is concurrently trying to bind the SAME port during its own
 * startup, so whichever side loses gets EADDRINUSE (a ~1%-per-start flake where the
 * child aborts as "already running" or the wrapper reports "exited before becoming
 * ready"). A connect probe never holds the port, so it cannot displace the child.
 *
 * Resolves `true` when a TCP connection is accepted (something is listening),
 * `false` on connection-refused or a short timeout (nothing there yet — keep
 * polling). Never throws; always tears the socket down.
 *
 * Extracted into its own module because scripts/daemon-lifecycle.mjs self-invokes
 * main() at import time, so its internals can't be imported into a unit test.
 */
export function portAcceptsConnection(port, host, timeoutMs = 500) {
  if (!Number.isSafeInteger(port) || port <= 0 || port > 65_535) {
    return Promise.resolve(false);
  }
  // Normalize like the wrapper's probeHost: a wildcard-bound daemon is reachable on
  // loopback, and connect() wants a bare host (no brackets) even for IPv6.
  let target = String(host).trim();
  const lower = target.toLowerCase();
  if (lower === '0.0.0.0') target = '127.0.0.1';
  else if (lower === '::' || lower === '[::]') target = '::1';
  else if (target.startsWith('[') && target.endsWith(']')) target = target.slice(1, -1);

  return new Promise(resolve => {
    let settled = false;
    const socket = createConnection({ port, host: target });
    const done = value => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch { /* already torn down */ }
      resolve(value);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
  });
}
