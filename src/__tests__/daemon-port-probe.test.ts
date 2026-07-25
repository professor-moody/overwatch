import { describe, it, expect, afterEach } from 'vitest';
import { createServer, type Server } from 'node:net';
import { portAcceptsConnection } from '../../scripts/port-probe.mjs';

// L5: the daemon readiness probe must detect a listener by CONNECTING, not by
// binding the port it is polling — binding races the daemon child that is
// concurrently binding the same port (EADDRINUSE ~1%/start).
describe('portAcceptsConnection (L5 — connect, do not bind)', () => {
  const servers: Server[] = [];
  const listen = (host: string): Promise<{ port: number; server: Server }> =>
    new Promise((resolveListen, reject) => {
      const server = createServer();
      servers.push(server);
      server.once('error', reject);
      server.listen(0, host, () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') resolveListen({ port: addr.port, server });
        else reject(new Error('no port'));
      });
    });
  const close = (server: Server): Promise<void> => new Promise(r => server.close(() => r()));

  afterEach(async () => {
    await Promise.all(servers.splice(0).map(close));
  });

  it('returns false when nothing is listening (connection refused)', async () => {
    const { server, port } = await listen('127.0.0.1');
    await close(server); // free the port
    servers.length = 0;
    expect(await portAcceptsConnection(port, '127.0.0.1', 300)).toBe(false);
  });

  it('returns true when a server is listening, and never holds the port', async () => {
    const { port } = await listen('127.0.0.1');
    expect(await portAcceptsConnection(port, '127.0.0.1', 300)).toBe(true);
    // The probe connected but did not bind — a second probe still succeeds.
    expect(await portAcceptsConnection(port, '127.0.0.1', 300)).toBe(true);
  });

  it('L5 regression: probing a free port never blocks a concurrent bind of that port', async () => {
    // Get a known-free port.
    const { server, port } = await listen('127.0.0.1');
    await close(server);
    servers.length = 0;

    // Concurrently: probe the (free) port AND bind it. The OLD bind-based probe
    // would hold the port and race the listen -> EADDRINUSE; the connect probe
    // never binds, so the listen always wins.
    const boundOk = new Promise<boolean>((res) => {
      const s = createServer();
      servers.push(s);
      s.once('error', () => res(false));
      s.listen(port, '127.0.0.1', () => res(true));
    });
    const [probe, bound] = await Promise.all([
      portAcceptsConnection(port, '127.0.0.1', 300),
      boundOk,
    ]);
    expect(bound).toBe(true);   // reversion signal: the bind is never blocked by the probe
    expect(typeof probe).toBe('boolean');
  });

  it('normalizes a 0.0.0.0 wildcard host to loopback', async () => {
    const { port } = await listen('127.0.0.1');
    // A wildcard-bound daemon is reachable on loopback; 0.0.0.0 must be probed there.
    expect(await portAcceptsConnection(port, '0.0.0.0', 300)).toBe(true);
  });

  it('returns false for an out-of-range port without throwing', async () => {
    expect(await portAcceptsConnection(0, '127.0.0.1')).toBe(false);
    expect(await portAcceptsConnection(70000, '127.0.0.1')).toBe(false);
  });
});
