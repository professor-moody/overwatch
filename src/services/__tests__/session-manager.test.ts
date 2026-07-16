import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RingBuffer, SessionManager } from '../session-manager.js';
import { LocalPtyAdapter } from '../session-adapters.js';
import type { AdapterHandle, SessionCapabilities } from '../../types.js';
import type { SessionAdapterFactory } from '../session-manager.js';
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

function createMockAdapter(): {
  adapter: SessionAdapterFactory;
  handle: AdapterHandle;
  dataCbs: Array<(chunk: string) => void>;
  exitCbs: Array<(info: { exitCode?: number; signal?: number }) => void>;
  written: string[];
  wasClosed(): boolean;
} {
  const dataCbs: Array<(chunk: string) => void> = [];
  const exitCbs: Array<(info: { exitCode?: number; signal?: number }) => void> = [];
  const written: string[] = [];
  let closed = false;

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
    close() { closed = true; },
    onData(cb) { dataCbs.push(cb); },
    onExit(cb) { exitCbs.push(cb); },
  };

  const adapter: SessionAdapterFactory = {
    kind: 'local_pty',
    async spawn(_options) {
      return handle;
    },
  };

  return { adapter, handle, dataCbs, exitCbs, written, wasClosed: () => closed };
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

    it('durably reserves a pending descriptor before spawning the runtime handle', async () => {
      const durableStates: string[] = [];
      let spawnObservedReservation = false;
      manager.onDurableEvent(event => {
        durableStates.push(event.session.state);
      });
      manager.registerAdapter({
        kind: 'local_pty',
        async spawn() {
          spawnObservedReservation = durableStates[0] === 'pending';
          return mockAdapter.handle;
        },
      });

      const result = await manager.create({
        kind: 'local_pty',
        title: 'reserved shell',
        initial_wait_ms: 0,
      });

      expect(spawnObservedReservation).toBe(true);
      expect(durableStates).toEqual(['pending', 'connected']);
      expect(result.metadata.state).toBe('connected');
    });

    it('does not spawn when the durable descriptor reservation fails', async () => {
      let spawned = false;
      manager.onDurableEvent(() => {
        throw new Error('synthetic descriptor journal failure');
      });
      manager.registerAdapter({
        kind: 'local_pty',
        async spawn() {
          spawned = true;
          return mockAdapter.handle;
        },
      });

      await expect(manager.create({
        kind: 'local_pty',
        title: 'must not spawn',
        initial_wait_ms: 0,
      })).rejects.toThrow('synthetic descriptor journal failure');
      expect(spawned).toBe(false);
    });

    it('throws for unregistered adapter kind', async () => {
      await expect(manager.create({
        kind: 'ssh',
        title: 'no adapter',
      })).rejects.toThrow('No adapter registered for session kind: ssh');
    });

    it.each([
      {
        name: 'empty host',
        options: { kind: 'local_pty' as const, title: 'shell', host: '' },
        message: 'Session host must not be empty',
      },
      {
        name: 'empty owner',
        options: { kind: 'local_pty' as const, title: 'shell', agent_id: '' },
        message: 'Session agent_id must not be empty',
      },
      {
        name: 'out-of-range port',
        options: { kind: 'local_pty' as const, title: 'shell', port: 65_536 },
        message: 'Session port must be an integer from 0 through 65535',
      },
      {
        name: 'empty validation technique',
        options: {
          kind: 'local_pty' as const,
          title: 'shell',
          default_validation: { technique: '' },
        },
        message: 'default_validation.technique must not be empty',
      },
    ])('rejects $name before spawning an adapter', async ({ options, message }) => {
      const spawn = vi.spyOn(mockAdapter.adapter, 'spawn');
      await expect(manager.create({
        ...options,
        initial_wait_ms: 0,
      })).rejects.toThrow(message);
      expect(spawn).not.toHaveBeenCalled();
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

    it('does not write target bytes when the descriptor update cannot commit', async () => {
      let durableEvents = 0;
      manager.onDurableEvent(() => {
        durableEvents++;
        if (durableEvents === 3) throw new Error('synthetic descriptor update failure');
      });
      const { metadata } = await manager.create({
        kind: 'local_pty',
        title: 'fail-closed write',
        initial_wait_ms: 0,
      });

      expect(() => manager.write(metadata.id, 'must-not-send'))
        .toThrow('synthetic descriptor update failure');
      expect(mockAdapter.written).toEqual([]);
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

    it('keeps the runtime open when durable close cannot commit', async () => {
      let durableEvents = 0;
      manager.onDurableEvent(() => {
        durableEvents++;
        if (durableEvents === 3) throw new Error('synthetic descriptor close failure');
      });
      const { metadata } = await manager.create({
        kind: 'local_pty',
        title: 'fail-closed close',
        initial_wait_ms: 0,
      });

      expect(() => manager.close(metadata.id))
        .toThrow('synthetic descriptor close failure');
      expect(mockAdapter.wasClosed()).toBe(false);
      expect(manager.getSession(metadata.id)?.state).toBe('connected');
    });

    it('retains retryable handle ownership and records an error when runtime close throws', async () => {
      const durableStates: Array<{ state: string; notes?: string }> = [];
      manager.onDurableEvent(event => {
        durableStates.push({
          state: event.session.state,
          notes: event.session.notes,
        });
      });
      const closeHandle = vi.spyOn(mockAdapter.handle, 'close')
        .mockImplementationOnce(() => {
          throw new Error('synthetic adapter close failure');
        })
        .mockImplementation(() => undefined);
      const { metadata } = await manager.create({
        kind: 'local_pty',
        title: 'retryable close',
        initial_wait_ms: 0,
      });

      expect(() => manager.close(metadata.id))
        .toThrow('runtime close failed: synthetic adapter close failure');
      expect(closeHandle).toHaveBeenCalledTimes(1);
      expect(manager.getSession(metadata.id)).toMatchObject({
        state: 'error',
        closed_at: undefined,
        notes: expect.stringContaining('Runtime close failed: synthetic adapter close failure'),
      });
      expect(durableStates.at(-1)).toMatchObject({
        state: 'error',
        notes: expect.stringContaining('Runtime close failed: synthetic adapter close failure'),
      });
      expect(
        (manager as unknown as {
          sessions: Map<string, { handle: AdapterHandle | null }>;
        }).sessions.get(metadata.id)?.handle,
      ).toBe(mockAdapter.handle);

      expect(manager.close(metadata.id).metadata.state).toBe('closed');
      expect(closeHandle).toHaveBeenCalledTimes(2);
      expect(
        (manager as unknown as {
          sessions: Map<string, { handle: AdapterHandle | null }>;
        }).sessions.get(metadata.id)?.handle,
      ).toBeNull();
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

    it('rolls back metadata when the descriptor update cannot commit', async () => {
      let durableEvents = 0;
      manager.onDurableEvent(() => {
        durableEvents++;
        if (durableEvents === 3) throw new Error('synthetic metadata update failure');
      });
      const { metadata } = await manager.create({
        kind: 'local_pty',
        title: 'original title',
        initial_wait_ms: 0,
      });

      expect(() => manager.update(metadata.id, { title: 'must not stick' }))
        .toThrow('synthetic metadata update failure');
      expect(manager.getSession(metadata.id)?.title).toBe('original title');
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
    it('does not send a command when the descriptor update cannot commit', async () => {
      let durableEvents = 0;
      manager.onDurableEvent(() => {
        durableEvents++;
        if (durableEvents === 3) throw new Error('synthetic command descriptor failure');
      });
      const { metadata } = await manager.create({
        kind: 'local_pty',
        title: 'fail-closed command',
        initial_wait_ms: 0,
      });

      await expect(manager.sendCommand(metadata.id, 'must-not-run'))
        .rejects.toThrow('synthetic command descriptor failure');
      expect(mockAdapter.written).toEqual([]);
    });

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

    it('waits for timeout_ms when no output arrives (not early idle return)', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });

      const start = Date.now();
      const result = await manager.sendCommand(metadata.id, 'hang', {
        timeout_ms: 300,
        idle_ms: 100,
      });
      const elapsed = Date.now() - start;

      // Should wait close to timeout_ms, NOT return early after idle_ms
      expect(elapsed).toBeGreaterThanOrEqual(250);
      expect(elapsed).toBeLessThan(1000);
      expect(result.text).toBe('');
      expect(result.session_id).toBe(metadata.id);
    });

    it('captures delayed first output (no early empty return)', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });

      const sendPromise = manager.sendCommand(metadata.id, 'slow-cmd', {
        timeout_ms: 2000,
        idle_ms: 200,
      });

      // Output arrives after 400ms — well past the old idle_ms window
      setTimeout(() => {
        for (const cb of mockAdapter.dataCbs) cb('delayed result\nprompt$ ');
      }, 400);

      const result = await sendPromise;
      expect(result.text).toContain('delayed result');
    });

    it('captures sparse multi-burst output', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });

      const sendPromise = manager.sendCommand(metadata.id, 'multi-burst', {
        timeout_ms: 3000,
        idle_ms: 300,
      });

      // First burst at 50ms
      setTimeout(() => {
        for (const cb of mockAdapter.dataCbs) cb('line1\n');
      }, 50);

      // Second burst at 250ms (within idle_ms of first burst)
      setTimeout(() => {
        for (const cb of mockAdapter.dataCbs) cb('line2\nprompt$ ');
      }, 250);

      const result = await sendPromise;
      expect(result.text).toContain('line1');
      expect(result.text).toContain('line2');
    });

    it('throws on invalid wait_for regex', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });
      await expect(manager.sendCommand(metadata.id, 'ls', {
        wait_for: '[invalid(',
      })).rejects.toThrow('Invalid wait_for regex');
    });

    it('throws when wait_for regex exceeds length limit', async () => {
      const { metadata } = await manager.create({ kind: 'local_pty', title: 'test', initial_wait_ms: 0 });
      const longPattern = 'a'.repeat(1001);
      await expect(manager.sendCommand(metadata.id, 'ls', {
        wait_for: longPattern,
      })).rejects.toThrow('wait_for pattern too long');
    });
  });

  describe('create() error handling', () => {
    it('closes adapter handle when create fails after handle is attached', async () => {
      let handleClosed = false;
      const failingAdapter: SessionAdapterFactory = {
        kind: 'ssh' as any,
        async spawn() {
          return {
            pid: 99999,
            capabilities: { has_stdin: true, has_stdout: true, supports_resize: false, supports_signals: false, tty_quality: 'full' as const },
            write() {},
            resize() {},
            kill() {},
            close() { handleClosed = true; },
            onData() {},
            onExit() {},
          };
        },
      };

      const fakeEngine = {
        logActionEvent() {},
        ingestSessionResult() { throw new Error('Injected engine failure'); },
      };
      const engineManager = new SessionManager(fakeEngine as any);
      engineManager.registerAdapter(failingAdapter);

      await expect(engineManager.create({
        kind: 'ssh' as any,
        title: 'fail-test',
        host: 'nonexistent.invalid',
        target_node: 'host-target',
        initial_wait_ms: 0,
      })).rejects.toThrow('Injected engine failure');

      expect(handleClosed).toBe(true);
      await engineManager.shutdown();
    });

    it('retains a failed cleanup handle and retries it during shutdown', async () => {
      const handle = createMockAdapter().handle;
      const closeHandle = vi.spyOn(handle, 'close')
        .mockImplementationOnce(() => {
          throw new Error('synthetic create cleanup failure');
        })
        .mockImplementation(() => undefined);
      const failingAdapter: SessionAdapterFactory = {
        kind: 'ssh' as any,
        async spawn() {
          return handle;
        },
      };
      const fakeEngine = {
        logActionEvent() {},
        ingestSessionResult() { throw new Error('Injected engine failure'); },
      };
      const engineManager = new SessionManager(fakeEngine as any);
      engineManager.registerAdapter(failingAdapter);

      await expect(engineManager.create({
        kind: 'ssh' as any,
        title: 'cleanup-retry',
        host: 'nonexistent.invalid',
        target_node: 'host-target',
        initial_wait_ms: 0,
      })).rejects.toThrow('failed to open and runtime cleanup failed');

      const [failed] = engineManager.list();
      expect(failed).toMatchObject({
        state: 'error',
        closed_at: undefined,
        notes: expect.stringContaining('Session-open cleanup could not close runtime'),
      });
      expect(
        (engineManager as unknown as {
          sessions: Map<string, { handle: AdapterHandle | null }>;
        }).sessions.get(failed!.id)?.handle,
      ).toBe(handle);

      await engineManager.shutdown();
      expect(closeHandle).toHaveBeenCalledTimes(2);
      expect(
        (engineManager as unknown as {
          sessions: Map<string, { handle: AdapterHandle | null }>;
        }).sessions.get(failed!.id)?.handle,
      ).toBeNull();
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

  describe('shutdown — closes claimed sessions via force bypass', () => {
    it('closes claimed sessions during shutdown', async () => {
      // sessionId is claimed by 'owner-agent' from beforeEach
      // shutdown must bypass ownership to close it
      await manager.shutdown();
      const meta = manager.getSession(sessionId);
      expect(meta?.state).toBe('closed');
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
  it('creates a listener that starts in pending state', async () => {
    const manager = new SessionManager(null);

    // Create a mock socket adapter that resolves immediately for testing
    const mockSocketAdapter: SessionAdapterFactory = {
      kind: 'socket',
      async spawn(_options) {
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

  it('records graph access when a socket session connects with target and principal metadata', async () => {
    const ingestCalls: unknown[] = [];
    const events: unknown[] = [];
    let connect: (() => void) | undefined;
    const engine = {
      ingestSessionResult(result: unknown) { ingestCalls.push(result); },
      logActionEvent(event: unknown) { events.push(event); },
    };
    const manager = new SessionManager(engine as any);
    const sessionEvents: Array<{ type: string; session: { state: string }; sessions: unknown[] }> = [];
    manager.onEvent(event => sessionEvents.push(event));
    const mockSocketAdapter: SessionAdapterFactory = {
      kind: 'socket',
      async spawn(options) {
        connect = (options as { onConnect?: () => void }).onConnect;
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
      title: 'reverse shell',
      mode: 'listen',
      port: 4444,
      target_node: 'host-1',
      principal_node: 'user-1',
      credential_node: 'cred-1',
      action_id: 'act-1',
      frontier_item_id: 'frontier-1',
      initial_wait_ms: 0,
    });

    expect(manager.getSession(result.metadata.id)?.state).toBe('pending');
    connect?.();

    expect(manager.getSession(result.metadata.id)?.state).toBe('connected');
    expect(ingestCalls).toEqual([
      expect.objectContaining({
        success: true,
        confirmed: true,
        target_node: 'host-1',
        principal_node: 'user-1',
        credential_node: 'cred-1',
        action_id: 'act-1',
        frontier_item_id: 'frontier-1',
        session_id: result.metadata.id,
      }),
    ]);
    expect(events).toEqual(expect.arrayContaining([
      expect.objectContaining({ event_type: 'session_connected' }),
    ]));
    expect(sessionEvents.map(event => `${event.type}:${event.session.state}`)).toEqual([
      'session_created:pending',
      'session_updated:connected',
    ]);
    expect(sessionEvents[1].sessions).toHaveLength(1);

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

// ============================================================
// auth_status on SSH session metadata
// ============================================================

describe('SessionManager — SSH auth_status in metadata', () => {
  function createSshMock(initialOutput: string) {
    const dataCbs: Array<(chunk: string) => void> = [];
    const exitCbs: Array<(info: { exitCode?: number; signal?: number }) => void> = [];

    const handle: AdapterHandle = {
      pid: 77777,
      capabilities: { has_stdin: true, has_stdout: true, supports_resize: false, supports_signals: false, tty_quality: 'full' as const },
      write() {},
      resize() {},
      kill() {},
      close() {},
      onData(cb) { dataCbs.push(cb); },
      onExit(cb) { exitCbs.push(cb); },
    };

    const adapter: SessionAdapterFactory = {
      kind: 'ssh' as any,
      async spawn() {
        // Simulate initial output arriving immediately
        setTimeout(() => {
          for (const cb of dataCbs) cb(initialOutput);
        }, 10);
        return handle;
      },
    };

    return { adapter, handle, dataCbs, exitCbs };
  }

  function makeFakeEngine() {
    return {
      logActionEvent() {},
      ingestSessionResult() {},
      getConfig() {
        return {
          scope: { cidrs: ['10.0.0.0/8'], domains: [], exclusions: [] },
        };
      },
    };
  }

  it('sets auth_status to auth_failed on permission denied', async () => {
    const { adapter } = createSshMock('Permission denied (publickey).\r\n');
    const engine = makeFakeEngine();
    const mgr = new SessionManager(engine as any);
    mgr.registerAdapter(adapter);

    const result = await mgr.create({
      kind: 'ssh' as any,
      title: 'auth-fail-test',
      host: '10.0.0.1',
      target_node: 'host-1',
      initial_wait_ms: 100,
    });

    expect(result.metadata.auth_status).toBe('auth_failed');
    await mgr.shutdown();
  });

  it('sets auth_status to auth_prompt on password prompt', async () => {
    const { adapter } = createSshMock('user@10.0.0.1\'s password: ');
    const engine = makeFakeEngine();
    const mgr = new SessionManager(engine as any);
    mgr.registerAdapter(adapter);

    const result = await mgr.create({
      kind: 'ssh' as any,
      title: 'prompt-test',
      host: '10.0.0.1',
      target_node: 'host-1',
      initial_wait_ms: 100,
    });

    expect(result.metadata.auth_status).toBe('auth_prompt');
    await mgr.shutdown();
  });

  it('sets auth_status to connected_unconfirmed when no auth signals detected', async () => {
    // Output that doesn't match any auth failure, prompt, or success pattern
    const { adapter } = createSshMock('Welcome to Ubuntu 22.04\r\n');
    const engine = makeFakeEngine();
    const mgr = new SessionManager(engine as any);
    mgr.registerAdapter(adapter);

    const result = await mgr.create({
      kind: 'ssh' as any,
      title: 'unconfirmed-test',
      host: '10.0.0.1',
      target_node: 'host-1',
      initial_wait_ms: 100,
    });

    // Without a shell prompt pattern match, detectSshAuthSuccess returns false,
    // so auth_status should be connected_unconfirmed or shell_confirmed depending
    // on whether the echo probe succeeds. Since the mock doesn't respond to the
    // probe, it will be connected_unconfirmed.
    expect(['connected_unconfirmed', 'shell_confirmed']).toContain(result.metadata.auth_status);
    await mgr.shutdown();
  });
});

// ============================================================
// 7.13: Session Idle Timeout
// ============================================================

describe('Session Idle Timeout', () => {
  it('reaps sessions that exceed idle timeout', async () => {
    const mgr = new SessionManager(null, 100); // 100ms timeout
    const mock = createMockAdapter();
    mgr.registerAdapter(mock.adapter);

    const result = await mgr.create({ kind: 'local_pty', title: 'idle-test', initial_wait_ms: 0 });
    expect(mgr.list().filter(s => s.state === 'connected')).toHaveLength(1);

    // Fast-forward last_activity_at by manipulating it
    const session = (mgr as any).sessions.get(result.metadata.id);
    session.metadata.last_activity_at = new Date(Date.now() - 200).toISOString();

    const reaped = mgr.reapIdleSessions();
    expect(reaped).toContain(result.metadata.id);
    expect(mgr.list().filter(s => s.state === 'connected')).toHaveLength(0);
  });

  it('retains an idle runtime when close fails and shutdown retries ownership', async () => {
    const mgr = new SessionManager(null, 100);
    const mock = createMockAdapter();
    const closeHandle = vi.spyOn(mock.handle, 'close')
      .mockImplementationOnce(() => {
        throw new Error('synthetic idle close failure');
      })
      .mockImplementation(() => undefined);
    mgr.registerAdapter(mock.adapter);

    const result = await mgr.create({
      kind: 'local_pty',
      title: 'idle-close-retry',
      initial_wait_ms: 0,
    });
    const internal = (mgr as unknown as {
      sessions: Map<string, {
        metadata: { last_activity_at: string };
        handle: AdapterHandle | null;
      }>;
    }).sessions.get(result.metadata.id)!;
    internal.metadata.last_activity_at = new Date(Date.now() - 200).toISOString();

    expect(mgr.reapIdleSessions()).toEqual([]);
    expect(mgr.getSession(result.metadata.id)).toMatchObject({
      state: 'error',
      closed_at: undefined,
      notes: expect.stringContaining('Idle reaper runtime close failed'),
    });
    expect(internal.handle).toBe(mock.handle);
    expect(mgr.listUnresolvedRuntimeOwnership()).toEqual([
      expect.objectContaining({ id: result.metadata.id, state: 'error' }),
    ]);
    expect(() => mgr.reconcileAfterStateRollback())
      .toThrow('retain live or unresolved runtime ownership');

    await mgr.shutdown();
    expect(closeHandle).toHaveBeenCalledTimes(2);
    expect(internal.handle).toBeNull();
    expect(() => mgr.reconcileAfterStateRollback()).not.toThrow();
    expect(mgr.list()).toEqual([]);
  });

  it('does not reap active sessions', async () => {
    const mgr = new SessionManager(null, 100);
    const mock = createMockAdapter();
    mgr.registerAdapter(mock.adapter);

    await mgr.create({ kind: 'local_pty', title: 'active-test', initial_wait_ms: 0 });
    // Don't manipulate the timestamp — session was just created

    const reaped = mgr.reapIdleSessions();
    expect(reaped).toHaveLength(0);
    expect(mgr.list().filter(s => s.state === 'connected')).toHaveLength(1);
    await mgr.shutdown();
  });

  it('skips reaping when idleTimeoutMs is 0 (disabled)', async () => {
    const mgr = new SessionManager(null, 0);
    const mock = createMockAdapter();
    mgr.registerAdapter(mock.adapter);

    const result = await mgr.create({ kind: 'local_pty', title: 'no-timeout', initial_wait_ms: 0 });
    const session = (mgr as any).sessions.get(result.metadata.id);
    session.metadata.last_activity_at = new Date(Date.now() - 999999).toISOString();

    const reaped = mgr.reapIdleSessions();
    expect(reaped).toHaveLength(0);
    await mgr.shutdown();
  });

  it('freezes instead of reaping through read surfaces while persistence is read-only', async () => {
    const mgr = new SessionManager(null, 100);
    const mock = createMockAdapter();
    mgr.registerAdapter(mock.adapter);

    const result = await mgr.create({ kind: 'local_pty', title: 'degraded-read', initial_wait_ms: 0 });
    const session = (mgr as any).sessions.get(result.metadata.id);
    session.metadata.last_activity_at = new Date(Date.now() - 200).toISOString();
    (mgr as any).engine = { isPersistenceWritable: () => false };

    expect(mgr.list()).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: result.metadata.id, state: 'closed' }),
    ]));
    expect(mgr.read(result.metadata.id).session_id).toBe(result.metadata.id);
    expect(mgr.reapIdleSessions()).toEqual([]);
    expect(mgr.getSession(result.metadata.id)?.state).toBe('closed');
    expect(mock.wasClosed()).toBe(true);

    (mgr as any).engine = null;
    await mgr.shutdown();
  });
});

describe('SessionManager persistence freeze', () => {
  it('routes a direct close through the persistence freeze when durability is degraded', async () => {
    let writable = true;
    const durableEvents: unknown[] = [];
    const engine = {
      isPersistenceWritable: () => writable,
      logActionEvent: (event: unknown) => { durableEvents.push(event); },
      onSessionClosed: () => { durableEvents.push('graph-session-close'); },
    };
    const mgr = new SessionManager(engine as any);
    const mock = createMockAdapter();
    mgr.registerAdapter(mock.adapter);
    const result = await mgr.create({ kind: 'local_pty', title: 'direct-close', initial_wait_ms: 0 });
    const eventCountBeforeFreeze = durableEvents.length;

    writable = false;
    expect(() => mgr.close(result.metadata.id)).toThrow(/persistence is read-only/i);

    expect(mock.wasClosed()).toBe(true);
    expect(mgr.getSession(result.metadata.id)?.state).toBe('closed');
    expect(durableEvents).toHaveLength(eventCountBeforeFreeze);
    await mgr.shutdown();
  });

  it('closes live handles without durable callbacks and rejects later operations', async () => {
    let writable = true;
    const durableEvents: unknown[] = [];
    const engine = {
      isPersistenceWritable: () => writable,
      logActionEvent: (event: unknown) => { durableEvents.push(event); },
      onSessionClosed: () => { durableEvents.push('graph-session-close'); },
    };
    const mgr = new SessionManager(engine as any);
    const mock = createMockAdapter();
    mgr.registerAdapter(mock.adapter);

    const result = await mgr.create({ kind: 'local_pty', title: 'freeze-me', initial_wait_ms: 0 });
    const eventCountBeforeFreeze = durableEvents.length;
    writable = false;

    // The unref'd gate monitor must detect the transition without a new API call.
    await new Promise(resolve => setTimeout(resolve, 325));
    expect(mock.wasClosed()).toBe(true);
    expect(mgr.getSession(result.metadata.id)?.state).toBe('closed');
    expect(durableEvents).toHaveLength(eventCountBeforeFreeze);

    expect(() => mgr.write(result.metadata.id, 'whoami')).toThrow(/persistence is read-only/i);
    expect(() => mgr.update(result.metadata.id, { title: 'must-not-change' }, undefined, true))
      .toThrow(/persistence is read-only/i);
    expect(mgr.getSession(result.metadata.id)?.title).toBe('freeze-me');
    await expect(mgr.sendCommand(result.metadata.id, 'id')).rejects.toThrow(/persistence is read-only/i);
    await expect(mgr.create({ kind: 'local_pty', title: 'must-not-open', initial_wait_ms: 0 }))
      .rejects.toThrow(/persistence is read-only/i);

    // Late adapter callbacks are isolated and cannot write lifecycle state.
    expect(() => mock.exitCbs.forEach(cb => cb({ exitCode: 0 }))).not.toThrow();
    expect(durableEvents).toHaveLength(eventCountBeforeFreeze);
    await mgr.shutdown();
  });

  it('interrupts a command already waiting for session output', async () => {
    let writable = true;
    const engine = {
      isPersistenceWritable: () => writable,
      logActionEvent() {},
    };
    const mgr = new SessionManager(engine as any);
    const mock = createMockAdapter();
    mgr.registerAdapter(mock.adapter);
    const result = await mgr.create({ kind: 'local_pty', title: 'running-command', initial_wait_ms: 0 });

    const pending = mgr.sendCommand(result.metadata.id, 'sleep 30', { timeout_ms: 5_000 });
    expect(mock.written).toContain('sleep 30\n');
    writable = false;

    await expect(pending).resolves.toMatchObject({ completion_reason: 'session_closed' });
    expect(mock.wasClosed()).toBe(true);
    await mgr.shutdown();
  });

  it('closes a pending listener instead of accepting a connection after gate closure', async () => {
    let writable = true;
    const logActionEvent = vi.fn();
    const ingestSessionResult = vi.fn();
    const engine = {
      isPersistenceWritable: () => writable,
      logActionEvent,
      ingestSessionResult,
    };
    const mgr = new SessionManager(engine as any);
    const mock = createMockAdapter();
    let connect: (() => void) | undefined;
    mgr.registerAdapter({
      kind: 'socket',
      async spawn(options) {
        connect = (options as { onConnect?: () => void }).onConnect;
        return mock.handle;
      },
    });

    const result = await mgr.create({
      kind: 'socket',
      title: 'pending-listener',
      mode: 'listen',
      target_node: 'host-1',
      initial_wait_ms: 0,
    });
    expect(result.metadata.state).toBe('pending');
    const eventCount = logActionEvent.mock.calls.length;

    writable = false;
    expect(() => connect?.()).not.toThrow();

    expect(mock.wasClosed()).toBe(true);
    expect(mgr.getSession(result.metadata.id)?.state).toBe('closed');
    expect(ingestSessionResult).not.toHaveBeenCalled();
    expect(logActionEvent).toHaveBeenCalledTimes(eventCount);
    await mgr.shutdown();
  });

  it('aborts an adapter spawn that is still pending when persistence degrades', async () => {
    let writable = true;
    const engine = { isPersistenceWritable: () => writable };
    const mgr = new SessionManager(engine as any, 0);
    let adapterSignal: AbortSignal | undefined;
    const adapter: SessionAdapterFactory = {
      kind: 'socket',
      spawn(options) {
        const signal = options.abort_signal as AbortSignal;
        adapterSignal = signal;
        return new Promise((_resolve, reject) => {
          const onAbort = () => reject(signal.reason ?? new Error('aborted'));
          if (signal.aborted) onAbort();
          else signal.addEventListener('abort', onAbort, { once: true });
        });
      },
    };
    mgr.registerAdapter(adapter);

    const pending = mgr.create({
      kind: 'socket',
      title: 'pending-listener',
      mode: 'listen',
      port: 4444,
      initial_wait_ms: 0,
    });
    expect(adapterSignal?.aborted).toBe(false);
    writable = false;

    await expect(pending).rejects.toMatchObject({ code: 'PERSISTENCE_READ_ONLY' });
    expect(adapterSignal?.aborted).toBe(true);
    await mgr.shutdown();
  });
});

// ============================================================
// detectSshAuthSuccess — username/login + echo-not-output guards
// ============================================================

describe('SessionManager.detectSshAuthSuccess — prompt guards', () => {
  function makeFakeSession(text: string, writeFn: (data: string) => void) {
    const buf = new RingBuffer(8192);
    buf.write(text);
    return {
      metadata: { id: '12345678-aaaa-bbbb-cccc-000000000001' },
      buffer: buf,
      handle: { write: writeFn } as any,
    } as any;
  }

  it('returns false at a Username: prompt even if probe is echoed back', async () => {
    const mgr = new SessionManager(null);
    const session = makeFakeSession('Username: ', (data) => {
      // appliance-style echo: input is mirrored back as terminal echo
      session.buffer.write(data);
    });
    const ok = await (mgr as any).detectSshAuthSuccess(session);
    expect(ok).toBe(false);
  });

  it('returns false at a login: prompt', async () => {
    const mgr = new SessionManager(null);
    const session = makeFakeSession('login: ', () => {});
    const ok = await (mgr as any).detectSshAuthSuccess(session);
    expect(ok).toBe(false);
  });

  it('does not accept marker that only appears as terminal echo of the probe', async () => {
    const mgr = new SessionManager(null);
    // No shell prompt suffix, no non-shell prompt match — falls through to
    // the echo probe. The fake handle echoes the full `echo MARKER` line
    // back but never produces a separate output line. Should return false.
    const session = makeFakeSession('connecting...\r\n', (data) => {
      session.buffer.write(data); // echo only
    });
    const ok = await (mgr as any).detectSshAuthSuccess(session);
    expect(ok).toBe(false);
  });

  it('accepts marker that appears on its own line (real shell behavior)', async () => {
    const mgr = new SessionManager(null);
    const session = makeFakeSession('connecting...\r\n', (data) => {
      // echo back, then output marker on its own line as a shell would
      session.buffer.write(data);
      const m = data.match(/__OW_READY_[a-f0-9]+__/);
      if (m) session.buffer.write('\r\n' + m[0] + '\r\n');
    });
    const ok = await (mgr as any).detectSshAuthSuccess(session);
    expect(ok).toBe(true);
  });
});
