import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { RingBuffer, SessionManager } from '../session-manager.js';
import { LocalPtyAdapter, SocketAdapter } from '../session-adapters.js';
import type { AdapterHandle, SessionCapabilities } from '../../types.js';
import type { SessionAdapterFactory } from '../session-manager.js';
import { createServer } from 'net';

// ============================================================
// RingBuffer Tests
// ============================================================

describe('RingBuffer', () => {
  it('writes and reads basic data', () => {
    const buf = new RingBuffer(1024);
    buf.write('hello world');
    const result = buf.read(0);
    expect(result.text).toBe('hello world');
    expect(result.startPos).toBe(0);
    expect(result.endPos).toBe(11);
    expect(result.truncated).toBe(false);
  });

  it('tracks absolute end_pos monotonically', () => {
    const buf = new RingBuffer(1024);
    expect(buf.endPos).toBe(0);
    buf.write('abc');
    expect(buf.endPos).toBe(3);
    buf.write('def');
    expect(buf.endPos).toBe(6);
  });

  it('handles overflow/wrap correctly', () => {
    const buf = new RingBuffer(10);
    buf.write('0123456789'); // fill exactly
    expect(buf.endPos).toBe(10);
    buf.write('ABCDE'); // overwrite first 5
    expect(buf.endPos).toBe(15);

    // Reading from 0 should be truncated (buffer only holds pos 5-14)
    const result = buf.read(0);
    expect(result.truncated).toBe(true);
    expect(result.startPos).toBe(5);
    expect(result.text).toBe('56789ABCDE');
  });

  it('read from current endPos returns empty', () => {
    const buf = new RingBuffer(1024);
    buf.write('hello');
    const result = buf.read(5);
    expect(result.text).toBe('');
    expect(result.startPos).toBe(5);
    expect(result.endPos).toBe(5);
    expect(result.truncated).toBe(false);
  });

  it('read from future position returns empty', () => {
    const buf = new RingBuffer(1024);
    buf.write('hello');
    const result = buf.read(100);
    expect(result.text).toBe('');
    expect(result.truncated).toBe(false);
  });

  it('tail returns last N characters', () => {
    const buf = new RingBuffer(1024);
    buf.write('hello world');
    const result = buf.tail(5);
    expect(result.text).toBe('world');
    expect(result.startPos).toBe(6);
    expect(result.endPos).toBe(11);
  });

  it('tail with N larger than buffer returns all', () => {
    const buf = new RingBuffer(1024);
    buf.write('hi');
    const result = buf.tail(100);
    expect(result.text).toBe('hi');
    expect(result.startPos).toBe(0);
  });

  it('incremental reads work with cursors', () => {
    const buf = new RingBuffer(1024);
    buf.write('first');
    const r1 = buf.read(0);
    expect(r1.text).toBe('first');
    expect(r1.endPos).toBe(5);

    buf.write(' second');
    const r2 = buf.read(r1.endPos);
    expect(r2.text).toBe(' second');
    expect(r2.startPos).toBe(5);
    expect(r2.endPos).toBe(12);
  });

  it('startPos reflects oldest available data', () => {
    const buf = new RingBuffer(10);
    expect(buf.startPos).toBe(0);
    buf.write('12345');
    expect(buf.startPos).toBe(0);
    buf.write('6789012345'); // total 15, capacity 10
    expect(buf.startPos).toBe(5); // oldest available is pos 5
    expect(buf.endPos).toBe(15);
  });

  it('empty buffer returns empty reads', () => {
    const buf = new RingBuffer(1024);
    const result = buf.read(0);
    expect(result.text).toBe('');
    expect(result.endPos).toBe(0);
  });
});

// ============================================================
// Mock adapter for SessionManager tests
// ============================================================

function createMockAdapter(): { adapter: SessionAdapterFactory; handle: AdapterHandle; dataCbs: Array<(chunk: string) => void>; exitCbs: Array<(info: { exitCode?: number; signal?: number }) => void> } {
  const dataCbs: Array<(chunk: string) => void> = [];
  const exitCbs: Array<(info: { exitCode?: number; signal?: number }) => void> = [];
  const written: string[] = [];

  const handle: AdapterHandle = {
    pid: 12345,
    capabilities: {
      has_stdin: true,
      has_stdout: true,
      supports_resize: true,
      supports_signals: true,
      tty_quality: 'full',
    },
    write(data: string) { written.push(data); },
    resize(_cols: number, _rows: number) {},
    kill(_signal?: string) {},
    close() {},
    onData(cb) { dataCbs.push(cb); },
    onExit(cb) { exitCbs.push(cb); },
  };

  const adapter: SessionAdapterFactory = {
    kind: 'local_pty',
    async spawn(_options) {
      return handle;
    },
  };

  return { adapter, handle, dataCbs, exitCbs };
}

// ============================================================
// SessionManager Tests
// ============================================================

describe('SessionManager', () => {
  let manager: SessionManager;
  let mockAdapter: ReturnType<typeof createMockAdapter>;

  beforeEach(() => {
    manager = new SessionManager(null);
    mockAdapter = createMockAdapter();
    manager.registerAdapter(mockAdapter.adapter);
  });

  afterEach(async () => {
    await manager.shutdown();
  });

  describe('create', () => {
    it('creates a session and returns metadata + initial output', async () => {
      const result = await manager.create({
        kind: 'local_pty',
        title: 'test shell',
        agent_id: 'agent-1',
        initial_wait_ms: 0,
      });

      expect(result.metadata.kind).toBe('local_pty');
      expect(result.metadata.title).toBe('test shell');
      expect(result.metadata.state).toBe('connected');
      expect(result.metadata.claimed_by).toBe('agent-1');
      expect(result.metadata.transport).toBe('pty');
      expect(result.metadata.capabilities.tty_quality).toBe('full');
      expect(result.initial.session_id).toBe(result.metadata.id);
    });

    it('throws for unregistered adapter kind', async () => {
      await expect(manager.create({
        kind: 'ssh',
        title: 'no adapter',
      })).rejects.toThrow('No adapter registered for session kind: ssh');
    });
  });

  describe('write', () => {
    it('writes data to session', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });
      const result = manager.write(metadata.id, 'hello');
      expect(result.session_id).toBe(metadata.id);
      expect(result.end_pos).toBeGreaterThanOrEqual(0);
    });

    it('rejects write from non-owner', async () => {
      const { metadata } = await manager.create({
        kind: 'local_pty',
        title: 'test',
        agent_id: 'agent-1',
        initial_wait_ms: 0,
      });

      expect(() => manager.write(metadata.id, 'hello', 'agent-2'))
        .toThrow('claimed by "agent-1"');
    });

    it('allows write with force override', async () => {
      const { metadata } = await manager.create({
        kind: 'local_pty',
        title: 'test',
        agent_id: 'agent-1',
        initial_wait_ms: 0,
      });

      expect(() => manager.write(metadata.id, 'hello', 'agent-2', true))
        .not.toThrow();
    });
  });

  describe('read', () => {
    it('reads from buffer with cursor', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });

      // Simulate adapter output
      for (const cb of mockAdapter.dataCbs) cb('prompt$ ');

      const result = manager.read(metadata.id, 0);
      expect(result.text).toBe('prompt$ ');
      expect(result.start_pos).toBe(0);
      expect(result.end_pos).toBe(8);
      expect(result.truncated).toBe(false);
    });

    it('supports incremental reads via cursor', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });

      for (const cb of mockAdapter.dataCbs) cb('line1\n');
      const r1 = manager.read(metadata.id, 0);
      expect(r1.text).toBe('line1\n');

      for (const cb of mockAdapter.dataCbs) cb('line2\n');
      const r2 = manager.read(metadata.id, r1.end_pos);
      expect(r2.text).toBe('line2\n');
      expect(r2.start_pos).toBe(6);
    });

    it('reads tail when from_pos omitted', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });
      for (const cb of mockAdapter.dataCbs) cb('some output here');

      const result = manager.read(metadata.id, undefined, 4);
      expect(result.text).toBe('here');
    });
  });

  describe('list', () => {
    it('lists all sessions', async () => {
      await manager.create({ kind: 'local_pty', title: 'shell 1', initial_wait_ms: 0 });
      await manager.create({ kind: 'local_pty', title: 'shell 2', initial_wait_ms: 0 });

      const all = manager.list();
      expect(all.length).toBe(2);
    });

    it('filters active only', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'shell 1', initial_wait_ms: 0 });
      await manager.create({ kind: 'local_pty', title: 'shell 2', initial_wait_ms: 0 });
      manager.close(metadata.id);

      const active = manager.list(true);
      expect(active.length).toBe(1);
      expect(active[0].title).toBe('shell 2');
    });
  });

  describe('close', () => {
    it('closes session and returns final output', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });
      for (const cb of mockAdapter.dataCbs) cb('final output');

      const result = manager.close(metadata.id);
      expect(result.metadata.state).toBe('closed');
      expect(result.metadata.closed_at).toBeDefined();
      expect(result.final.text).toContain('final output');
    });

    it('cannot write to closed session', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });
      manager.close(metadata.id);

      expect(() => manager.write(metadata.id, 'hello'))
        .toThrow('not connected');
    });
  });

  describe('update', () => {
    it('updates capabilities', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });
      const updated = manager.update(metadata.id, {
        capabilities: { tty_quality: 'partial' },
      });
      expect(updated.capabilities.tty_quality).toBe('partial');
      // Other capabilities should remain
      expect(updated.capabilities.has_stdin).toBe(true);
    });

    it('transfers ownership', async () => {
      const { metadata } = await manager.create({
        kind: 'local_pty',
        title: 'test',
        agent_id: 'agent-1',
        initial_wait_ms: 0,
      });
      const updated = manager.update(metadata.id, { claimed_by: 'agent-2' }, 'agent-1');
      expect(updated.claimed_by).toBe('agent-2');
    });

    it('updates title and notes', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'old title', initial_wait_ms: 0 });
      const updated = manager.update(metadata.id, {
        title: 'new title',
        notes: 'upgraded shell',
      });
      expect(updated.title).toBe('new title');
      expect(updated.notes).toBe('upgraded shell');
    });
  });

  describe('resize', () => {
    it('resizes PTY session', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });
      // Should not throw for PTY session
      expect(() => manager.resize(metadata.id, 200, 50)).not.toThrow();
    });
  });

  describe('signal', () => {
    it('sends signal to PTY session', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });
      expect(() => manager.signal(metadata.id, 'SIGINT')).not.toThrow();
    });
  });

  describe('sendCommand (experimental)', () => {
    it('sends command and captures output', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });

      // Simulate delayed output after command is sent
      const sendPromise = manager.sendCommand(metadata.id, 'whoami', {
        timeout_ms: 3000,
        idle_ms: 200,
      });

      // Simulate output arriving
      setTimeout(() => {
        for (const cb of mockAdapter.dataCbs) cb('whoami\nroot\nprompt$ ');
      }, 50);

      const result = await sendPromise;
      expect(result.text).toContain('root');
      expect(result.session_id).toBe(metadata.id);
    });

    it('respects wait_for regex', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });

      const sendPromise = manager.sendCommand(metadata.id, 'ls', {
        timeout_ms: 5000,
        idle_ms: 2000, // long idle so regex wins
        wait_for: '\\$',
      });

      setTimeout(() => {
        for (const cb of mockAdapter.dataCbs) cb('file1 file2\n$ ');
      }, 50);

      const result = await sendPromise;
      expect(result.text).toContain('file1');
    });

    it('times out if no output', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });

      const start = Date.now();
      const result = await manager.sendCommand(metadata.id, 'hang', {
        timeout_ms: 300,
        idle_ms: 100,
      });
      const elapsed = Date.now() - start;

      expect(elapsed).toBeLessThan(1000);
      expect(result.session_id).toBe(metadata.id);
    });
  });

  describe('session exit handling', () => {
    it('marks session closed when adapter exits', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });
      expect(manager.getSession(metadata.id)?.state).toBe('connected');

      // Simulate exit
      for (const cb of mockAdapter.exitCbs) cb({ exitCode: 0 });

      expect(manager.getSession(metadata.id)?.state).toBe('closed');
    });
  });

  describe('concurrent reads', () => {
    it('multiple agents can read independently via cursors', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });

      for (const cb of mockAdapter.dataCbs) cb('chunk1');
      const agent1Read = manager.read(metadata.id, 0);
      expect(agent1Read.text).toBe('chunk1');

      for (const cb of mockAdapter.dataCbs) cb('chunk2');
      // Agent 1 reads from where it left off
      const agent1Read2 = manager.read(metadata.id, agent1Read.end_pos);
      expect(agent1Read2.text).toBe('chunk2');

      // Agent 2 reads everything from the beginning
      const agent2Read = manager.read(metadata.id, 0);
      expect(agent2Read.text).toBe('chunk1chunk2');
    });
  });

  describe('getSession', () => {
    it('returns null for unknown session', () => {
      expect(manager.getSession('nonexistent')).toBeNull();
    });

    it('returns metadata for existing session', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });
      const fetched = manager.getSession(metadata.id);
      expect(fetched).not.toBeNull();
      expect(fetched!.title).toBe('test');
    });
  });
});

// ============================================================
// Ownership enforcement regression tests
// ============================================================

describe('SessionManager — ownership enforcement', () => {
  let manager: SessionManager;
  let mockAdapter: ReturnType<typeof createMockAdapter>;
  let sessionId: string;

  beforeEach(async () => {
    manager = new SessionManager(null);
    mockAdapter = createMockAdapter();
    manager.registerAdapter(mockAdapter.adapter);
    const result = await manager.create({
      kind: 'local_pty',
      title: 'claimed shell',
      agent_id: 'owner-agent',
      initial_wait_ms: 0,
    });
    sessionId = result.metadata.id;
  });

  afterEach(async () => {
    await manager.shutdown();
  });

  describe('write — omitted agent_id bypass (P1)', () => {
    it('rejects write when agent_id is omitted on a claimed session', () => {
      expect(() => manager.write(sessionId, 'hello'))
        .toThrow('claimed by "owner-agent"');
    });

    it('rejects write when agent_id is undefined on a claimed session', () => {
      expect(() => manager.write(sessionId, 'hello', undefined))
        .toThrow('claimed by "owner-agent"');
    });

    it('allows write from the owning agent', () => {
      expect(() => manager.write(sessionId, 'hello', 'owner-agent'))
        .not.toThrow();
    });

    it('allows write with force even from wrong agent', () => {
      expect(() => manager.write(sessionId, 'hello', 'other-agent', true))
        .not.toThrow();
    });
  });

  describe('update — no ownership check (P2)', () => {
    it('rejects update when agent_id is omitted on a claimed session', () => {
      expect(() => manager.update(sessionId, { notes: 'hijack' }))
        .toThrow('claimed by "owner-agent"');
    });

    it('rejects update from wrong agent', () => {
      expect(() => manager.update(sessionId, { notes: 'hijack' }, 'other-agent'))
        .toThrow('claimed by "owner-agent"');
    });

    it('allows update from the owning agent', () => {
      expect(() => manager.update(sessionId, { notes: 'legit' }, 'owner-agent'))
        .not.toThrow();
    });

    it('allows update with force from wrong agent', () => {
      const updated = manager.update(sessionId, { notes: 'forced' }, 'other-agent', true);
      expect(updated.notes).toBe('forced');
    });
  });

  describe('resize — no ownership check (P2)', () => {
    it('rejects resize when agent_id is omitted on a claimed session', () => {
      expect(() => manager.resize(sessionId, 200, 50))
        .toThrow('claimed by "owner-agent"');
    });

    it('allows resize from the owning agent', () => {
      expect(() => manager.resize(sessionId, 200, 50, 'owner-agent'))
        .not.toThrow();
    });

    it('allows resize with force from wrong agent', () => {
      expect(() => manager.resize(sessionId, 200, 50, 'other-agent', true))
        .not.toThrow();
    });
  });

  describe('signal — no ownership check (P2)', () => {
    it('rejects signal when agent_id is omitted on a claimed session', () => {
      expect(() => manager.signal(sessionId, 'SIGINT'))
        .toThrow('claimed by "owner-agent"');
    });

    it('allows signal from the owning agent', () => {
      expect(() => manager.signal(sessionId, 'SIGINT', 'owner-agent'))
        .not.toThrow();
    });

    it('allows signal with force from wrong agent', () => {
      expect(() => manager.signal(sessionId, 'SIGINT', 'other-agent', true))
        .not.toThrow();
    });
  });

  describe('close — no ownership check (P2)', () => {
    it('rejects close when agent_id is omitted on a claimed session', () => {
      expect(() => manager.close(sessionId))
        .toThrow('claimed by "owner-agent"');
    });

    it('allows close from the owning agent', () => {
      expect(() => manager.close(sessionId, 'owner-agent'))
        .not.toThrow();
    });

    it('allows close with force from wrong agent', async () => {
      // Need a fresh session since the owning-agent test above may have closed it
      const r = await manager.create({
        kind: 'local_pty',
        title: 'another claimed',
        agent_id: 'owner-agent',
        initial_wait_ms: 0,
      });
      expect(() => manager.close(r.metadata.id, 'other-agent', true))
        .not.toThrow();
    });
  });

  describe('unclaimed sessions remain open to all', () => {
    it('allows write without agent_id on unclaimed session', async () => {
      const r = await manager.create({
        kind: 'local_pty',
        title: 'unclaimed shell',
        initial_wait_ms: 0,
      });
      expect(() => manager.write(r.metadata.id, 'hello'))
        .not.toThrow();
    });

    it('allows close without agent_id on unclaimed session', async () => {
      const r = await manager.create({
        kind: 'local_pty',
        title: 'unclaimed shell',
        initial_wait_ms: 0,
      });
      expect(() => manager.close(r.metadata.id))
        .not.toThrow();
    });
  });
});

// ============================================================
// Dumb socket adapter test (degraded capabilities)
// ============================================================

describe('SocketAdapter — dumb session', () => {
  let socketAdapter: SocketAdapter;

  beforeEach(() => {
    socketAdapter = new SocketAdapter();
  });

  it('creates a listener that starts in pending state', async () => {
    const manager = new SessionManager(null);

    // Create a mock socket adapter that resolves immediately for testing
    const mockSocketAdapter: SessionAdapterFactory = {
      kind: 'socket',
      async spawn(options) {
        const dataCbs: Array<(chunk: string) => void> = [];
        const exitCbs: Array<(info: { exitCode?: number; signal?: number }) => void> = [];

        const caps: SessionCapabilities = {
          has_stdin: true,
          has_stdout: true,
          supports_resize: false,
          supports_signals: false,
          tty_quality: 'dumb',
        };

        return {
          pid: undefined,
          capabilities: caps,
          write(_data: string) {},
          close() {},
          onData(cb) { dataCbs.push(cb); },
          onExit(cb) { exitCbs.push(cb); },
        };
      },
    };

    manager.registerAdapter(mockSocketAdapter);

    const result = await manager.create({
      kind: 'socket',
      title: 'reverse shell',
      mode: 'listen',
      port: 0,
      initial_wait_ms: 0,
    });

    expect(result.metadata.kind).toBe('socket');
    expect(result.metadata.transport).toBe('tcp-listen');
    expect(result.metadata.capabilities.tty_quality).toBe('dumb');
    expect(result.metadata.capabilities.supports_resize).toBe(false);
    expect(result.metadata.capabilities.supports_signals).toBe(false);
    expect(result.metadata.pid).toBeUndefined();

    await manager.shutdown();
  });

  it('dumb session rejects resize gracefully', async () => {
    const manager = new SessionManager(null);

    const mockSocketAdapter: SessionAdapterFactory = {
      kind: 'socket',
      async spawn() {
        const onConnect = arguments[0]?.onConnect;
        // Simulate immediate connection
        if (onConnect) setTimeout(onConnect, 0);

        return {
          pid: undefined,
          capabilities: {
            has_stdin: true,
            has_stdout: true,
            supports_resize: false,
            supports_signals: false,
            tty_quality: 'dumb',
          },
          write() {},
          close() {},
          onData() {},
          onExit() {},
        };
      },
    };

    manager.registerAdapter(mockSocketAdapter);

    const result = await manager.create({
      kind: 'socket',
      title: 'test socket',
      mode: 'connect',
      host: '127.0.0.1',
      port: 9999,
      initial_wait_ms: 0,
    });

    // Wait for pending→connected transition if needed
    await new Promise(r => setTimeout(r, 50));

    // For a socket session with pending state, we need it connected first
    // The mock goes straight to the result, but state may still be pending
    // Update state manually for this test since mock doesn't trigger onConnect properly
    manager.update(result.metadata.id, {});

    expect(() => manager.resize(result.metadata.id, 100, 50))
      .toThrow('does not support resize');

    await manager.shutdown();
  });

  it('dumb session rejects signal gracefully', async () => {
    const manager = new SessionManager(null);

    const dataCbs: Array<(chunk: string) => void> = [];

    const mockSocketAdapter: SessionAdapterFactory = {
      kind: 'socket',
      async spawn(options) {
        const onConnect = (options as any).onConnect;
        if (onConnect) setTimeout(onConnect, 0);

        return {
          pid: undefined,
          capabilities: {
            has_stdin: true,
            has_stdout: true,
            supports_resize: false,
            supports_signals: false,
            tty_quality: 'dumb',
          },
          write() {},
          close() {},
          onData(cb: (chunk: string) => void) { dataCbs.push(cb); },
          onExit() {},
        };
      },
    };

    manager.registerAdapter(mockSocketAdapter);

    const result = await manager.create({
      kind: 'socket',
      title: 'test socket',
      mode: 'connect',
      host: '127.0.0.1',
      port: 9999,
      initial_wait_ms: 0,
    });

    // Wait for connect callback
    await new Promise(r => setTimeout(r, 50));

    expect(() => manager.signal(result.metadata.id, 'SIGINT'))
      .toThrow('does not support signals');

    await manager.shutdown();
  });

  it('dumb session supports incremental cursor reads', async () => {
    const manager = new SessionManager(null);
    const dataCbs: Array<(chunk: string) => void> = [];

    const mockSocketAdapter: SessionAdapterFactory = {
      kind: 'socket',
      async spawn(options) {
        const onConnect = (options as any).onConnect;
        if (onConnect) setTimeout(onConnect, 0);

        return {
          pid: undefined,
          capabilities: {
            has_stdin: true,
            has_stdout: true,
            supports_resize: false,
            supports_signals: false,
            tty_quality: 'dumb',
          },
          write() {},
          close() {},
          onData(cb: (chunk: string) => void) { dataCbs.push(cb); },
          onExit() {},
        };
      },
    };

    manager.registerAdapter(mockSocketAdapter);

    const result = await manager.create({
      kind: 'socket',
      title: 'test socket',
      mode: 'connect',
      host: '127.0.0.1',
      port: 9999,
      initial_wait_ms: 0,
    });

    // Wait for connect
    await new Promise(r => setTimeout(r, 50));

    // Feed data
    for (const cb of dataCbs) cb('bash-4.4$ ');
    const r1 = manager.read(result.metadata.id, 0);
    expect(r1.text).toBe('bash-4.4$ ');
    expect(r1.end_pos).toBe(10);

    for (const cb of dataCbs) cb('id\nuid=0(root)\n');
    const r2 = manager.read(result.metadata.id, r1.end_pos);
    expect(r2.text).toBe('id\nuid=0(root)\n');
    expect(r2.start_pos).toBe(10);
    expect(r2.truncated).toBe(false);

    // Full read from start
    const rFull = manager.read(result.metadata.id, 0);
    expect(rFull.text).toBe('bash-4.4$ id\nuid=0(root)\n');

    await manager.shutdown();
  });
});

// ============================================================
// SshAdapter argument building (mock, no real SSH)
// ============================================================

describe('SshAdapter', () => {
  it('can be imported', async () => {
    const { SshAdapter } = await import('../session-adapters.js');
    const adapter = new SshAdapter();
    expect(adapter.kind).toBe('ssh');
  });
});

// ============================================================
// LocalPtyAdapter — real spawn test
// ============================================================

// Real PTY tests — skipped if node-pty can't spawn in this environment (e.g. Node v25+)
function canSpawnPty(): boolean {
  try {
    const ptyMod = require('node-pty');
    const p = ptyMod.spawn('/bin/sh', [], { name: 'xterm', cols: 80, rows: 24 });
    p.kill();
    return true;
  } catch {
    return false;
  }
}

const describePty = canSpawnPty() ? describe : describe.skip;

describePty('LocalPtyAdapter — real PTY', () => {
  it('spawns a shell and captures echo output', async () => {
    const adapter = new LocalPtyAdapter();
    const handle = await adapter.spawn({
      shell: '/bin/sh',
      cols: 80,
      rows: 24,
    });

    expect(handle.pid).toBeGreaterThan(0);
    expect(handle.capabilities.tty_quality).toBe('full');
    expect(handle.capabilities.supports_resize).toBe(true);

    const output: string[] = [];
    handle.onData((chunk) => output.push(chunk));

    // Send a command
    handle.write('echo OVERWATCH_TEST_MARKER\n');

    // Wait for output
    await new Promise(r => setTimeout(r, 500));

    const combined = output.join('');
    expect(combined).toContain('OVERWATCH_TEST_MARKER');

    handle.close();
  });

  it('reports exit', async () => {
    const adapter = new LocalPtyAdapter();
    const handle = await adapter.spawn({
      shell: '/bin/sh',
      cols: 80,
      rows: 24,
    });

    const exitPromise = new Promise<{ exitCode?: number; signal?: number }>((resolve) => {
      handle.onExit(resolve);
    });

    handle.write('exit\n');

    const exitInfo = await exitPromise;
    expect(exitInfo.exitCode).toBeDefined();
  });
});
