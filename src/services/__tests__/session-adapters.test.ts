import { describe, it, expect } from 'vitest';
import { LocalPtyAdapter, SshAdapter, SocketAdapter } from '../session-adapters.js';

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

    it('cleanup is idempotent for unknown session', () => {
      const adapter = new SocketAdapter();
      // Should not throw
      adapter.cleanup('nonexistent-session');
    });
  });
});
