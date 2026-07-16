import { describe, it, expect } from 'vitest';
import { connect, createServer } from 'net';
import { LocalPtyAdapter, SshAdapter, SocketAdapter } from '../session-adapters.js';

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close(() => reject(new Error('No TCP port allocated')));
        return;
      }
      const port = address.port;
      server.close(() => resolve(port));
    });
  });
}

async function connectAndClose(port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port }, () => socket.end());
    socket.once('close', () => resolve());
    socket.once('error', reject);
  });
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let i = 0; i < 50; i += 1) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('Timed out waiting for predicate');
}

describe('Session Adapters', () => {
  describe('LocalPtyAdapter', () => {
    it('has kind "local_pty"', () => {
      const adapter = new LocalPtyAdapter();
      expect(adapter.kind).toBe('local_pty');
    });
  });

  describe('SshAdapter', () => {
    it('has kind "ssh"', () => {
      const adapter = new SshAdapter();
      expect(adapter.kind).toBe('ssh');
    });

    it('rejects spawn without host', async () => {
      const adapter = new SshAdapter();
      await expect(adapter.spawn({})).rejects.toThrow('SSH adapter requires a host');
    });
  });

  describe('SocketAdapter', () => {
    it('has kind "socket"', () => {
      const adapter = new SocketAdapter();
      expect(adapter.kind).toBe('socket');
    });

    it('rejects spawn without port', async () => {
      const adapter = new SocketAdapter();
      await expect(adapter.spawn({ mode: 'connect', host: '127.0.0.1' })).rejects.toThrow('Socket adapter requires a port');
    });

    it('rejects connect mode without host', async () => {
      const adapter = new SocketAdapter();
      await expect(adapter.spawn({ mode: 'connect', port: 4444 })).rejects.toThrow('Socket adapter connect mode requires a host');
    });

    it('accepts port zero for an ephemeral listen socket', async () => {
      const adapter = new SocketAdapter();
      const handle = await adapter.spawn({
        mode: 'listen',
        bind_host: '127.0.0.1',
        port: 0,
        sessionId: 'ephemeral-listener',
      });
      expect(handle.capabilities.tty_quality).toBe('dumb');
      expect(() => handle.close()).not.toThrow();
    });

    it('rejects before opening a transport when the persistence signal is already aborted', async () => {
      const adapter = new SocketAdapter();
      const controller = new AbortController();
      controller.abort(new Error('persistence read-only'));
      await expect(adapter.spawn({
        mode: 'connect',
        host: '127.0.0.1',
        port: 4444,
        abort_signal: controller.signal,
      })).rejects.toThrow('persistence read-only');
    });

    it('cleanup is idempotent for unknown session', () => {
      const adapter = new SocketAdapter();
      // Should not throw
      adapter.cleanup('nonexistent-session');
    });

    it('rejects (does not hang) when the connection is refused', async () => {
      const adapter = new SocketAdapter();
      // getFreePort closes the server before returning, so nothing is listening →
      // ECONNREFUSED. Before the fix, wireSocket's error handler set closed=true first,
      // so the connect promise's `!closed` reject guard never fired and open_session hung.
      const port = await getFreePort();
      const spawn = adapter.spawn({ mode: 'connect', host: '127.0.0.1', port, sessionId: 'refused-1' });
      const outcome = await Promise.race([
        spawn.then(() => 'resolved').catch(() => 'rejected'),
        new Promise<string>(r => setTimeout(() => r('timeout'), 1500)),
      ]);
      expect(outcome).toBe('rejected'); // settled with a rejection, not hung
    });

    it('rearm listen mode keeps the listener alive after a connection closes', async () => {
      const adapter = new SocketAdapter();
      const port = await getFreePort();
      const handle = await adapter.spawn({
        mode: 'listen',
        bind_host: '127.0.0.1',
        port,
        sessionId: 'rearm-test',
        accept_mode: 'rearm',
      });
      let disconnects = 0;
      let exits = 0;
      handle.onDisconnect?.(() => { disconnects += 1; });
      handle.onExit(() => { exits += 1; });

      await connectAndClose(port);
      await waitFor(() => disconnects === 1);
      await connectAndClose(port);
      await waitFor(() => disconnects === 2);

      expect(exits).toBe(0);
      handle.close();
    });

    it('destroys an unacknowledged accepted socket and keeps a rearm listener retryable', async () => {
      const adapter = new SocketAdapter();
      const port = await getFreePort();
      let accepts = 0;
      const handle = await adapter.spawn({
        mode: 'listen',
        bind_host: '127.0.0.1',
        port,
        sessionId: 'durable-ack-test',
        accept_mode: 'rearm',
        onConnect() {
          accepts += 1;
          if (accepts === 1) throw new Error('descriptor commit failed');
        },
      });
      let disconnects = 0;
      handle.onDisconnect?.(() => { disconnects += 1; });

      await connectAndClose(port);
      await waitFor(() => accepts === 1);
      expect(disconnects).toBe(0);

      await connectAndClose(port);
      await waitFor(() => disconnects === 1);
      expect(accepts).toBe(2);
      handle.close();
    });

    it('closes an active listener when the persistence signal aborts', async () => {
      const adapter = new SocketAdapter();
      const controller = new AbortController();
      const port = await getFreePort();
      const handle = await adapter.spawn({
        mode: 'listen',
        bind_host: '127.0.0.1',
        port,
        sessionId: 'abort-listener-test',
        abort_signal: controller.signal,
      });

      controller.abort(new Error('persistence read-only'));
      const outcome = await Promise.race([
        connectAndClose(port).then(() => 'connected').catch(() => 'rejected'),
        new Promise<string>(resolve => setTimeout(() => resolve('timeout'), 1500)),
      ]);
      expect(outcome).toBe('rejected');
      expect(() => handle.close()).not.toThrow();
    });
  });
});
