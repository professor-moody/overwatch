import { afterEach, describe, expect, it, vi } from 'vitest';
import { connect, type Socket } from 'net';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { AdapterHandle, EngagementConfig } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import { SocketAdapter } from '../session-adapters.js';
import {
  SessionManager,
  sessionIdleReaperIntervalMs,
  type SessionAdapterFactory,
} from '../session-manager.js';

function config(): EngagementConfig {
  return {
    id: 'session-lifecycle',
    name: 'Session lifecycle',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

async function waitFor(predicate: () => boolean, message: string): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for ${message}`);
}

async function openClient(port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port }, () => resolve(socket));
    socket.once('error', reject);
  });
}

function seedTarget(engine: GraphEngine): void {
  const now = new Date().toISOString();
  engine.addNode({
    id: 'principal-1',
    type: 'user',
    label: 'Operator',
    discovered_at: now,
    confidence: 1,
  });
  engine.addNode({
    id: 'target-1',
    type: 'host',
    label: 'Target',
    discovered_at: now,
    confidence: 1,
  });
}

describe('session listener generations', () => {
  const managers = new Set<SessionManager>();
  const engines = new Set<GraphEngine>();
  const directories = new Set<string>();
  const sockets = new Set<Socket>();

  afterEach(async () => {
    vi.useRealTimers();
    for (const socket of sockets) socket.destroy();
    sockets.clear();
    for (const manager of managers) {
      try { await manager.shutdown(); } catch { /* asserted by individual tests */ }
    }
    managers.clear();
    for (const engine of engines) engine.dispose();
    engines.clear();
    for (const directory of directories) {
      rmSync(directory, { recursive: true, force: true });
    }
    directories.clear();
  });

  it('closes one generation edge and creates a fresh buffer and edge on reconnect', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-session-generation-'));
    directories.add(directory);
    const engine = new GraphEngine(config(), join(directory, 'state.json'));
    engines.add(engine);
    seedTarget(engine);

    const manager = new SessionManager(engine);
    managers.add(manager);
    manager.registerAdapter(new SocketAdapter());
    manager.onDurableEvent(event => engine.recordSessionDescriptor(event.session));

    const created = await manager.create({
      kind: 'socket',
      title: 'generation listener',
      mode: 'listen',
      accept_mode: 'rearm',
      bind_host: '127.0.0.1',
      port: 0,
      target_node: 'target-1',
      principal_node: 'principal-1',
      initial_wait_ms: 0,
    });
    expect(created.metadata.port).toBeGreaterThan(0);
    expect(created.metadata.state).toBe('pending');
    expect(created.metadata.connection_generation).toBe(0);

    const first = await openClient(created.metadata.port!);
    sockets.add(first);
    await waitFor(
      () => manager.getSession(created.metadata.id)?.state === 'connected',
      'first accepted connection',
    );
    const firstMetadata = manager.getSession(created.metadata.id)!;
    expect(firstMetadata).toMatchObject({
      listener_id: created.metadata.id,
      connection_generation: 1,
      connection_id: `${created.metadata.id}:g1`,
    });
    first.write('generation-one\n');
    await waitFor(
      () => manager.read(created.metadata.id).text.includes('generation-one'),
      'first generation output',
    );
    const firstGenerationRead = manager.read(created.metadata.id, 0);
    expect(firstGenerationRead).toMatchObject({
      connection_id: `${created.metadata.id}:g1`,
      connection_generation: 1,
      text: expect.stringContaining('generation-one'),
    });

    const edge = () => engine.exportGraph().edges.find(candidate =>
      candidate.properties.type === 'HAS_SESSION')!;
    expect(edge().properties).toMatchObject({
      session_live: true,
      session_id: `${created.metadata.id}:g1`,
      listener_id: created.metadata.id,
      connection_generation: 1,
      live_session_ids: [`${created.metadata.id}:g1`],
    });
    manager.update(created.metadata.id, {
      capabilities: {
        tty_quality: 'full',
        supports_resize: true,
        supports_signals: true,
      },
    });

    first.end();
    await waitFor(
      () => manager.getSession(created.metadata.id)?.state === 'pending',
      'listener rearm after disconnect',
    );
    expect(manager.getSession(created.metadata.id)).toMatchObject({
      connection_id: undefined,
      last_connection_id: `${created.metadata.id}:g1`,
      last_connection_state: 'disconnected',
    });
    expect(edge().properties).toMatchObject({
      session_live: false,
      live_session_ids: [],
    });

    const second = await openClient(created.metadata.port!);
    sockets.add(second);
    await waitFor(
      () => manager.getSession(created.metadata.id)?.connection_generation === 2,
      'second accepted connection',
    );
    expect(manager.read(created.metadata.id).text).not.toContain('generation-one');
    expect(manager.getSession(created.metadata.id)?.capabilities).toMatchObject({
      tty_quality: 'dumb',
      supports_resize: false,
      supports_signals: false,
    });
    second.write('generation-two\n');
    await waitFor(
      () => manager.read(created.metadata.id).text.includes('generation-two'),
      'second generation output',
    );
    expect(manager.read(created.metadata.id, firstGenerationRead.end_pos)).toMatchObject({
      connection_id: `${created.metadata.id}:g2`,
      connection_generation: 2,
      text: expect.stringContaining('generation-two'),
    });
    expect(() => manager.read(
      created.metadata.id,
      firstGenerationRead.end_pos,
      undefined,
      {
        connection_id: `${created.metadata.id}:g1`,
        connection_generation: 1,
      },
    )).toThrow(/connection generation changed/i);
    expect(edge().properties).toMatchObject({
      session_live: true,
      session_id: `${created.metadata.id}:g2`,
      connection_generation: 2,
      live_session_ids: [`${created.metadata.id}:g2`],
    });
  });

  it('recovers an accepted listener as resume_available and resumes only on request', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-session-resume-'));
    directories.add(directory);
    const statePath = join(directory, 'state.json');
    const firstEngine = new GraphEngine(config(), statePath);
    engines.add(firstEngine);
    seedTarget(firstEngine);
    const firstManager = new SessionManager(firstEngine);
    managers.add(firstManager);
    firstManager.registerAdapter(new SocketAdapter());
    const unsubscribe = firstManager.onDurableEvent(event =>
      firstEngine.recordSessionDescriptor(event.session));

    const created = await firstManager.create({
      kind: 'socket',
      title: 'restartable listener',
      mode: 'listen',
      accept_mode: 'rearm',
      bind_host: '127.0.0.1',
      port: 0,
      target_node: 'target-1',
      principal_node: 'principal-1',
      initial_wait_ms: 0,
    });
    const port = created.metadata.port!;
    const firstClient = await openClient(port);
    sockets.add(firstClient);
    await waitFor(
      () => firstManager.getSession(created.metadata.id)?.connection_generation === 1,
      'pre-crash generation',
    );
    firstEngine.recordSessionDescriptor({
      ...firstManager.getSession(created.metadata.id)!,
      auth_status: 'shell_confirmed',
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: true,
        supports_signals: true,
        tty_quality: 'full',
      },
    });
    firstEngine.flushNow();

    // Model process loss: close runtime without writing a graceful descriptor.
    unsubscribe();
    (firstManager as unknown as { engine: GraphEngine | null }).engine = null;
    await firstManager.shutdown();
    managers.delete(firstManager);
    firstEngine.dispose();
    engines.delete(firstEngine);

    const restarted = new GraphEngine(config(), statePath);
    engines.add(restarted);
    const recovered = restarted.getSessionDescriptors().find(
      descriptor => descriptor.session_id === created.metadata.id,
    );
    expect(recovered).toMatchObject({
      lifecycle: 'closed',
      recovery_lifecycle: 'resume_available',
      connection_generation: 1,
      connection_id: undefined,
      last_connection_id: `${created.metadata.id}:g1`,
      last_connection_state: 'interrupted',
      resume_intent: {
        policy: 'manual',
        requested: true,
      },
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'dumb',
      },
    });
    expect(recovered?.auth_status).toBeUndefined();
    const recoveredEdge = restarted.exportGraph().edges.find(candidate =>
      candidate.properties.type === 'HAS_SESSION');
    expect(recoveredEdge?.properties.session_live).toBe(false);

    const manager = new SessionManager(restarted);
    managers.add(manager);
    manager.registerAdapter(new SocketAdapter());
    manager.onDurableEvent(event => restarted.recordSessionDescriptor(event.session));
    manager.restorePersistedDescriptors(restarted.getSessionDescriptors());
    expect(manager.getSession(created.metadata.id)).toMatchObject({
      state: 'resume_available',
      auth_status: undefined,
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'dumb',
      },
    });

    const resumed = await manager.resume(created.metadata.id, undefined, true);
    expect(resumed.metadata).toMatchObject({
      state: 'pending',
      id: created.metadata.id,
      listener_id: created.metadata.id,
      connection_generation: 1,
      port,
    });
    expect(restarted.exportGraph().edges.find(candidate =>
      candidate.properties.type === 'HAS_SESSION')?.properties.session_live).toBe(false);
    await expect(manager.resume(created.metadata.id, undefined, true))
      .rejects.toThrow('not an explicitly resumable listener');

    const secondClient = await openClient(port);
    sockets.add(secondClient);
    await waitFor(
      () => manager.getSession(created.metadata.id)?.connection_generation === 2,
      'post-resume generation',
    );
    expect(manager.getSession(created.metadata.id)?.connection_id)
      .toBe(`${created.metadata.id}:g2`);
  });

  it('rejects an accepted socket when the durable generation transaction fails', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-session-accept-failure-'));
    directories.add(directory);
    const engine = new GraphEngine(config(), join(directory, 'state.json'));
    engines.add(engine);
    const manager = new SessionManager(engine);
    managers.add(manager);
    manager.registerAdapter(new SocketAdapter());
    manager.onDurableEvent(event => engine.recordSessionDescriptor(event.session));
    const created = await manager.create({
      kind: 'socket',
      title: 'durable accept gate',
      mode: 'listen',
      accept_mode: 'rearm',
      bind_host: '127.0.0.1',
      port: 0,
      target_node: 'target-1',
      principal_node: 'principal-1',
      initial_wait_ms: 0,
    });

    const rejectedClient = await openClient(created.metadata.port!);
    sockets.add(rejectedClient);
    await waitFor(
      () => rejectedClient.destroyed,
      'uncommitted socket destruction',
    );
    expect(manager.getSession(created.metadata.id)).toMatchObject({
      state: 'pending',
      connection_generation: 0,
    });
    expect(manager.getSession(created.metadata.id)?.connection_id).toBeUndefined();
    expect(engine.exportGraph().edges.some(edge =>
      edge.properties.type === 'HAS_SESSION')).toBe(false);

    seedTarget(engine);
    const acceptedClient = await openClient(created.metadata.port!);
    sockets.add(acceptedClient);
    await waitFor(
      () => manager.getSession(created.metadata.id)?.connection_generation === 1,
      'retry after durable accept failure',
    );
    expect(engine.exportGraph().edges.find(edge =>
      edge.properties.type === 'HAS_SESSION')?.properties.session_live).toBe(true);
  });

  it('ignores stale disconnects and prevents an old command from consuming new-generation output', async () => {
    let accept: ((info: { connection_token: string }) => void) | undefined;
    let disconnect: ((info?: { connection_token?: string }) => void) | undefined;
    let emitData: ((chunk: string) => void) | undefined;
    const handle: AdapterHandle = {
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'dumb',
      },
      write() {},
      close() {},
      onData(cb) { emitData = cb; },
      onExit() {},
      onDisconnect(cb) {
        disconnect = info => cb(info);
      },
    };
    const manager = new SessionManager(null);
    managers.add(manager);
    manager.registerAdapter({
      kind: 'socket',
      async spawn(options) {
        accept = info => {
          (options.onConnect as (event: { connection_token: string }) => void)(info);
        };
        return handle;
      },
    });
    const created = await manager.create({
      kind: 'socket',
      title: 'isolated generations',
      mode: 'listen',
      accept_mode: 'rearm',
      port: 4444,
      initial_wait_ms: 0,
    });

    accept!({ connection_token: 'generation-one' });
    emitData!('old-output\n');
    const pendingCommand = manager.sendCommand(created.metadata.id, 'whoami', {
      timeout_ms: 1_000,
      idle_ms: 200,
    });
    disconnect!({ connection_token: 'generation-one' });
    accept!({ connection_token: 'generation-two' });
    emitData!('new-generation-output\n');
    disconnect!({ connection_token: 'generation-one' });
    disconnect!();

    expect(manager.getSession(created.metadata.id)).toMatchObject({
      state: 'connected',
      connection_generation: 2,
      connection_id: `${created.metadata.id}:g2`,
    });
    const commandResult = await pendingCommand;
    expect(commandResult.completion_reason).toBe('session_closed');
    expect(commandResult.text).not.toContain('new-generation-output');

    const settlingCommand = manager.sendCommand(created.metadata.id, 'hostname', {
      timeout_ms: 1_000,
      idle_ms: 200,
    });
    await new Promise(resolve => setTimeout(resolve, 10));
    emitData!('partial-generation-two\n');
    await new Promise(resolve => setTimeout(resolve, 70));
    disconnect!({ connection_token: 'generation-two' });
    accept!({ connection_token: 'generation-three' });
    emitData!('generation-three-output\n');
    const settlingResult = await settlingCommand;
    expect(settlingResult.completion_reason).toBe('session_closed');
    expect(settlingResult.text).toContain('partial-generation-two');
    expect(settlingResult.text).not.toContain('generation-three-output');

    disconnect!({ connection_token: 'generation-three' });
    expect(manager.getSession(created.metadata.id)?.state).toBe('pending');
  });

  it('retries a transient durable disconnect failure before reopening the listener', async () => {
    let accept: ((info: { connection_token: string }) => void) | undefined;
    let disconnect: ((info?: { connection_token?: string }) => void) | undefined;
    const closeSessionDurably = vi.fn()
      .mockImplementationOnce(() => {
        throw new Error('synthetic first disconnect commit failure');
      })
      .mockImplementation(() => undefined);
    const engine = {
      isPersistenceWritable: () => true,
      isStatePersistenceWritable: () => true,
      logActionEvent() {},
      connectSessionGenerationDurably() {},
      closeSessionDurably,
    } as unknown as GraphEngine;
    const handle: AdapterHandle = {
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
      onDisconnect(cb) {
        disconnect = info => cb(info);
      },
    };
    const manager = new SessionManager(engine);
    managers.add(manager);
    manager.registerAdapter({
      kind: 'socket',
      async spawn(options) {
        accept = info => {
          (options.onConnect as (event: { connection_token: string }) => void)(info);
        };
        return handle;
      },
    });
    const created = await manager.create({
      kind: 'socket',
      title: 'retry disconnect lifecycle',
      mode: 'listen',
      accept_mode: 'rearm',
      port: 4444,
      initial_wait_ms: 0,
    });

    accept!({ connection_token: 'generation-one' });
    disconnect!({ connection_token: 'generation-one' });

    expect(closeSessionDurably).toHaveBeenCalledTimes(2);
    expect(manager.getSession(created.metadata.id)).toMatchObject({
      state: 'pending',
      connection_generation: 1,
      connection_id: undefined,
      last_connection_state: 'disconnected',
    });
  });

  it('retries a transient durable process-exit failure before marking the session closed', async () => {
    let exit: ((info: { exitCode?: number; signal?: number }) => void) | undefined;
    const closeSessionDurably = vi.fn()
      .mockImplementationOnce(() => {
        throw new Error('synthetic first exit commit failure');
      })
      .mockImplementation(() => undefined);
    const engine = {
      isPersistenceWritable: () => true,
      isStatePersistenceWritable: () => true,
      logActionEvent() {},
      closeSessionDurably,
    } as unknown as GraphEngine;
    const manager = new SessionManager(engine);
    managers.add(manager);
    manager.registerAdapter({
      kind: 'local_pty',
      async spawn() {
        return {
          capabilities: {
            has_stdin: true,
            has_stdout: true,
            supports_resize: true,
            supports_signals: true,
            tty_quality: 'full',
          },
          write() {},
          close() {},
          onData() {},
          onExit(cb) {
            exit = cb;
          },
        };
      },
    });
    const created = await manager.create({
      kind: 'local_pty',
      title: 'retry exit lifecycle',
      initial_wait_ms: 0,
    });

    exit!({ exitCode: 0 });

    expect(closeSessionDurably).toHaveBeenCalledTimes(2);
    expect(manager.getSession(created.metadata.id)).toMatchObject({
      state: 'closed',
      connection_id: undefined,
      last_connection_state: 'closed',
    });
  });

  it('retires a listener locally when an irreversible disconnect cannot be committed', async () => {
    let accept: ((info: { connection_token: string }) => void) | undefined;
    let disconnect: ((info?: { connection_token?: string }) => void) | undefined;
    const closeHandle = vi.fn();
    const closeSessionDurably = vi.fn(() => {
      throw new Error('synthetic persistent disconnect commit failure');
    });
    const engine = {
      isPersistenceWritable: () => true,
      isStatePersistenceWritable: () => true,
      logActionEvent() {},
      connectSessionGenerationDurably() {},
      closeSessionDurably,
    } as unknown as GraphEngine;
    const manager = new SessionManager(engine);
    managers.add(manager);
    manager.registerAdapter({
      kind: 'socket',
      async spawn(options) {
        accept = info => {
          (options.onConnect as (event: { connection_token: string }) => void)(info);
        };
        return {
          capabilities: {
            has_stdin: true,
            has_stdout: true,
            supports_resize: false,
            supports_signals: false,
            tty_quality: 'dumb',
          },
          write() {},
          close: closeHandle,
          onData() {},
          onExit() {},
          onDisconnect(cb) {
            disconnect = info => cb(info);
          },
        };
      },
    });
    const created = await manager.create({
      kind: 'socket',
      title: 'retire failed listener',
      mode: 'listen',
      accept_mode: 'rearm',
      port: 4444,
      initial_wait_ms: 0,
    });

    accept!({ connection_token: 'generation-one' });
    disconnect!({ connection_token: 'generation-one' });

    expect(closeSessionDurably).toHaveBeenCalledTimes(3);
    expect(closeHandle).toHaveBeenCalledTimes(1);
    expect(manager.getSession(created.metadata.id)).toMatchObject({
      state: 'error',
      connection_id: undefined,
      last_connection_state: 'interrupted',
      notes: expect.stringContaining('could not be durably finalized'),
    });
    expect(
      (manager as unknown as {
        sessions: Map<string, { handle: AdapterHandle | null }>;
      }).sessions.get(created.metadata.id)?.handle,
    ).toBeNull();
  });

  it('leaves a failed explicit resume retryable without claiming a live listener', async () => {
    const manager = new SessionManager(null);
    managers.add(manager);
    manager.registerAdapter({
      kind: 'socket',
      async spawn() {
        throw new Error('EADDRINUSE');
      },
    });
    manager.restorePersistedDescriptors([{
      session_id: 'listener-retry',
      kind: 'socket',
      adapter: 'socket',
      transport: 'tcp-listen',
      lifecycle: 'closed',
      recovery_lifecycle: 'resume_available',
      listener_id: 'listener-retry',
      connection_generation: 3,
      mode: 'listen',
      bind_host: '127.0.0.1',
      accept_mode: 'rearm',
      title: 'retry listener',
      port: 4444,
      started_at: '2026-07-16T00:00:00.000Z',
      last_activity_at: '2026-07-16T00:00:00.000Z',
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'dumb',
      },
      resume_intent: {
        policy: 'manual',
        requested: true,
        prior_state: 'pending',
        recovery_prior_state: 'resume_available',
        recorded_at: '2026-07-16T00:00:00.000Z',
      },
    }]);

    await expect(manager.resume('listener-retry', undefined, true))
      .rejects.toThrow('EADDRINUSE');
    expect(manager.getSession('listener-retry')).toMatchObject({
      state: 'resume_available',
      connection_generation: 3,
      connection_id: undefined,
      resume_policy: 'manual',
      notes: expect.stringContaining('Listener resume failed: EADDRINUSE'),
    });
    expect(manager.listUnresolvedRuntimeOwnership()).toEqual([]);
  });

  it('does not report a listener active until the resume bind is complete', async () => {
    let resolveSpawn!: (handle: AdapterHandle) => void;
    const spawnPromise = new Promise<AdapterHandle>(resolve => {
      resolveSpawn = resolve;
    });
    const handle: AdapterHandle = {
      bound_port: 4444,
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
      onDisconnect() {},
    };
    const manager = new SessionManager(null);
    managers.add(manager);
    manager.registerAdapter({
      kind: 'socket',
      async spawn() { return spawnPromise; },
    });
    manager.restorePersistedDescriptors([{
      session_id: 'listener-slow-resume',
      kind: 'socket',
      transport: 'tcp-listen',
      lifecycle: 'closed',
      recovery_lifecycle: 'resume_available',
      mode: 'listen',
      bind_host: '127.0.0.1',
      accept_mode: 'rearm',
      title: 'Slow resume',
      port: 4444,
      started_at: '2026-07-16T00:00:00.000Z',
      last_activity_at: '2026-07-16T00:00:00.000Z',
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'dumb',
      },
      resume_intent: {
        policy: 'manual',
        requested: true,
        prior_state: 'pending',
        recovery_prior_state: 'resume_available',
        recorded_at: '2026-07-16T00:00:00.000Z',
      },
    }]);

    const pendingResume = manager.resume('listener-slow-resume', undefined, true);
    expect(manager.getSession('listener-slow-resume')?.state).toBe('resume_available');
    expect(manager.list(true)).toEqual([]);
    expect(manager.listUnresolvedRuntimeOwnership()).toContainEqual(
      expect.objectContaining({ id: 'listener-slow-resume' }),
    );
    await expect(manager.resume('listener-slow-resume', undefined, true))
      .rejects.toThrow('already in progress');

    resolveSpawn(handle);
    await expect(pendingResume).resolves.toMatchObject({
      metadata: {
        id: 'listener-slow-resume',
        state: 'pending',
      },
    });
    expect(manager.list(true)).toContainEqual(expect.objectContaining({
      id: 'listener-slow-resume',
      state: 'pending',
    }));
  });
});

describe('session idle reaper', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('uses half the timeout capped at thirty seconds', () => {
    expect(sessionIdleReaperIntervalMs(60_000)).toBe(30_000);
    expect(sessionIdleReaperIntervalMs(10_000)).toBe(5_000);
    expect(sessionIdleReaperIntervalMs(0)).toBeNull();
  });

  it('is unrefd, reaps without a read/list call, and stops before shutdown persistence', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-07-16T00:00:00.000Z'));
    let closed = false;
    const handle: AdapterHandle = {
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'dumb',
      },
      write() {},
      close() { closed = true; },
      onData() {},
      onExit() {},
    };
    const adapter: SessionAdapterFactory = {
      kind: 'local_pty',
      async spawn() { return handle; },
    };
    const manager = new SessionManager(null, 10_000);
    manager.registerAdapter(adapter);
    const timer = (manager as unknown as {
      idleReaperTimer: ReturnType<typeof setInterval> | null;
    }).idleReaperTimer;
    expect(timer).not.toBeNull();
    expect(timer && 'hasRef' in timer ? timer.hasRef() : false).toBe(false);

    const created = await manager.create({
      kind: 'local_pty',
      title: 'idle generation',
      initial_wait_ms: 0,
    });
    await vi.advanceTimersByTimeAsync(15_000);
    expect(closed).toBe(true);
    expect(manager.getSession(created.metadata.id)?.state).toBe('closed');

    const secondManager = new SessionManager(null, 10_000);
    secondManager.registerAdapter(adapter);
    const second = await secondManager.create({
      kind: 'local_pty',
      title: 'shutdown race',
      initial_wait_ms: 0,
    });
    secondManager.beginShutdown();
    expect((secondManager as unknown as {
      idleReaperTimer: ReturnType<typeof setInterval> | null;
    }).idleReaperTimer).toBeNull();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(secondManager.getSession(second.metadata.id)?.state).toBe('connected');
    await secondManager.shutdown();
    expect(secondManager.getSession(second.metadata.id)?.state).toBe('interrupted');
    await manager.shutdown();
  });
});
