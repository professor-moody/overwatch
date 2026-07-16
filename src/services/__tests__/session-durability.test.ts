import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { AdapterHandle, EngagementConfig } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal } from '../mutation-journal.js';
import {
  SessionManager,
  type SessionAdapterFactory,
  type SessionEvent,
} from '../session-manager.js';

function config(): EngagementConfig {
  return {
    id: 'session-durability',
    name: 'Session durability',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function adapter(
  beforeSpawn: () => void,
): { adapter: SessionAdapterFactory; handle: AdapterHandle } {
  const handle: AdapterHandle = {
    pid: 4242,
    capabilities: {
      has_stdin: true,
      has_stdout: true,
      supports_resize: true,
      supports_signals: true,
      tty_quality: 'full',
    },
    write() {},
    resize() {},
    kill() {},
    close() {},
    onData() {},
    onExit() {},
  };
  return {
    handle,
    adapter: {
      kind: 'local_pty',
      async spawn() {
        beforeSpawn();
        return handle;
      },
    },
  };
}

describe('session descriptor transaction boundary', () => {
  let directory: string;
  let statePath: string;
  const engines = new Set<GraphEngine>();
  const managers = new Set<SessionManager>();

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-session-durability-'));
    statePath = join(directory, 'state.json');
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    for (const manager of managers) {
      // Tests that model a crash detach the runtime manager from the durable
      // engine before best-effort handle cleanup.
      (manager as unknown as { engine: GraphEngine | null }).engine = null;
      await manager.shutdown();
    }
    managers.clear();
    for (const engine of engines) engine.dispose();
    engines.clear();
    rmSync(directory, { recursive: true, force: true });
  });

  it('reserves before spawn and recovers a crash-before-snapshot truthfully', async () => {
    const first = new GraphEngine(config(), statePath);
    engines.add(first);
    first.flushNow();
    const baseCheckpoint = (JSON.parse(readFileSync(statePath, 'utf-8')) as {
      journalSnapshotSeq: number;
    }).journalSnapshotSeq;

    const manager = new SessionManager(first);
    managers.add(manager);
    const unsubscribe = manager.onDurableEvent(event => {
      first.recordSessionDescriptor(event.session);
    });
    const fake = adapter(() => {
      expect(first.getSessionDescriptors()).toContainEqual(expect.objectContaining({
        lifecycle: 'pending',
        title: 'reserved shell',
      }));
    });
    manager.registerAdapter(fake.adapter);

    const created = await manager.create({
      kind: 'local_pty',
      title: 'reserved shell',
      initial_wait_ms: 0,
    });
    expect(created.metadata.state).toBe('connected');
    expect(first.getSessionDescriptors()).toContainEqual(expect.objectContaining({
      session_id: created.metadata.id,
      lifecycle: 'connected',
    }));

    const transactions = new MutationJournal(statePath).readTransactionsSince(baseCheckpoint);
    const descriptorTransactions = transactions.filter(transaction =>
      transaction.operations.length === 1
      && transaction.operations[0]?.type === 'state_patch'
      && (transaction.operations[0].payload as any).slices.session_descriptors
    );
    expect(descriptorTransactions).toHaveLength(2);
    expect(descriptorTransactions.map(transaction =>
      (transaction.operations[0]!.payload as any).slices.session_descriptors[0].lifecycle
    )).toEqual(['pending', 'connected']);

    // Simulate process death: stop descriptor callbacks and runtime handles
    // without allowing the debounced state snapshot to run.
    unsubscribe();
    (manager as unknown as { engine: GraphEngine | null }).engine = null;
    await manager.shutdown();
    managers.delete(manager);
    first.dispose();
    engines.delete(first);

    const restarted = new GraphEngine(config(), statePath);
    engines.add(restarted);
    expect(restarted.getSessionDescriptors()).toContainEqual(expect.objectContaining({
      session_id: created.metadata.id,
      lifecycle: 'error',
      recovery_lifecycle: 'interrupted',
      closed_at: undefined,
      last_connection_state: 'interrupted',
      resume_intent: expect.objectContaining({
        policy: 'none',
        requested: false,
      }),
    }));
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      highest_contiguous_applied_seq: expect.any(Number),
    });
    expect(
      restarted.getPersistenceRecoveryStatus().highest_contiguous_applied_seq,
    ).toBeGreaterThanOrEqual(baseCheckpoint + transactions.length + 1);
  });

  it('refuses to spawn a real-engine session without a durable descriptor owner', async () => {
    const engine = new GraphEngine(config(), statePath);
    engines.add(engine);
    const manager = new SessionManager(engine);
    managers.add(manager);
    const spawn = vi.fn(async () => adapter(() => undefined).handle);
    manager.registerAdapter({
      kind: 'local_pty',
      spawn,
    });

    await expect(manager.create({
      kind: 'local_pty',
      title: 'unowned runtime',
      initial_wait_ms: 0,
    })).rejects.toThrow('no durable descriptor owner is registered');
    expect(spawn).not.toHaveBeenCalled();
    expect(manager.list()).toEqual([]);
    expect(engine.getSessionDescriptors()).toEqual([]);
  });

  it('deep-detaches nested metadata at ingress, egress, and both event boundaries', async () => {
    const engine = new GraphEngine(config(), statePath);
    engines.add(engine);
    const manager = new SessionManager(engine);
    managers.add(manager);
    const fake = adapter(() => undefined);
    manager.registerAdapter(fake.adapter);

    const observedBestEffort: SessionEvent[] = [];
    manager.onDurableEvent(event => {
      engine.recordSessionDescriptor(event.session);
      event.session.capabilities.has_stdin = false;
      if (event.session.default_validation) {
        event.session.default_validation.technique = 'mutated-durable-event';
      }
      event.session.reachability_warnings?.push('mutated-durable-event');
      const listed = event.sessions[0];
      if (listed) {
        listed.capabilities.has_stdout = false;
        if (listed.default_validation) {
          listed.default_validation.target_ip = '203.0.113.200';
        }
        listed.reachability_warnings?.push('mutated-durable-event-list');
      }
    });
    manager.onEvent(event => {
      event.session.capabilities.has_stdin = false;
      if (event.session.default_validation) {
        event.session.default_validation.technique = 'mutated-best-effort-event';
      }
      event.session.reachability_warnings?.push('mutated-best-effort-event');
      const listed = event.sessions[0];
      if (listed) {
        listed.capabilities.has_stdout = false;
        if (listed.default_validation) {
          listed.default_validation.target_ip = '203.0.113.201';
        }
        listed.reachability_warnings?.push('mutated-best-effort-event-list');
      }
    });
    manager.onEvent(event => {
      observedBestEffort.push(structuredClone(event));
    });

    const defaultValidation = {
      technique: 'T1059',
      target_ip: '192.0.2.10',
      allow_unverified_scope: false,
    };
    const reachabilityWarnings = ['operator must expose listener'];
    const created = await manager.create({
      kind: 'local_pty',
      title: 'detached metadata',
      default_validation: defaultValidation,
      reachability_warnings: reachabilityWarnings,
      initial_wait_ms: 0,
    });

    defaultValidation.technique = 'mutated-create-input';
    defaultValidation.target_ip = '203.0.113.10';
    reachabilityWarnings.push('mutated-create-input');
    created.metadata.capabilities.has_stdin = false;
    created.metadata.default_validation!.technique = 'mutated-create-result';
    created.metadata.reachability_warnings!.push('mutated-create-result');

    const fetched = manager.getSession(created.metadata.id)!;
    fetched.capabilities.has_stdout = false;
    fetched.default_validation!.target_ip = '203.0.113.11';
    fetched.reachability_warnings!.push('mutated-get');

    const listed = manager.list().find(entry => entry.id === created.metadata.id)!;
    listed.capabilities.tty_quality = 'none';
    listed.default_validation!.technique = 'mutated-list';
    listed.reachability_warnings!.push('mutated-list');

    const expectedNestedMetadata = {
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: true,
        supports_signals: true,
        tty_quality: 'full',
      },
      default_validation: {
        technique: 'T1059',
        target_ip: '192.0.2.10',
        allow_unverified_scope: false,
      },
      reachability_warnings: ['operator must expose listener'],
    };
    expect(manager.getSession(created.metadata.id)).toMatchObject(expectedNestedMetadata);
    expect(
      engine.getSessionDescriptors().find(
        descriptor => descriptor.session_id === created.metadata.id,
      ),
    ).toMatchObject(expectedNestedMetadata);
    expect(observedBestEffort.at(-1)?.session).toMatchObject(expectedNestedMetadata);
    expect(observedBestEffort.at(-1)?.sessions[0]).toMatchObject(expectedNestedMetadata);
  });

  it('keeps runtime, descriptor, and HAS_SESSION live when atomic close cannot append', async () => {
    const engine = new GraphEngine(config(), statePath);
    engines.add(engine);
    const manager = new SessionManager(engine);
    managers.add(manager);
    manager.onDurableEvent(event => {
      engine.recordSessionDescriptor(event.session);
    });
    const fake = adapter(() => undefined);
    manager.registerAdapter(fake.adapter);

    const observedAt = '2026-07-16T02:00:00.000Z';
    engine.addNode({
      id: 'session-principal',
      type: 'user',
      label: 'Session principal',
      discovered_at: observedAt,
      confidence: 1,
    });
    engine.addNode({
      id: 'session-target',
      type: 'host',
      label: 'Session target',
      discovered_at: observedAt,
      confidence: 1,
    });
    const created = await manager.create({
      kind: 'local_pty',
      title: 'atomic close',
      target_node: 'session-target',
      principal_node: 'session-principal',
      initial_wait_ms: 0,
    });
    engine.ingestSessionResult({
      success: true,
      target_node: 'session-target',
      principal_node: 'session-principal',
      session_id: created.metadata.connection_id,
    });
    engine.flushNow();
    const baseCheckpoint = (JSON.parse(readFileSync(statePath, 'utf-8')) as {
      journalSnapshotSeq: number;
    }).journalSnapshotSeq;
    const closeHandle = vi.spyOn(fake.handle, 'close');
    const journal = (engine as any).ctx.mutationJournal as MutationJournal;
    vi.spyOn(journal, 'appendTransaction').mockImplementationOnce(() => {
      throw new Error('synthetic atomic session close append failure');
    });

    expect(() => manager.close(created.metadata.id))
      .toThrow('synthetic atomic session close append failure');
    expect(closeHandle).not.toHaveBeenCalled();
    expect(manager.getSession(created.metadata.id)?.state).toBe('connected');
    expect(engine.getSessionDescriptors()).toContainEqual(expect.objectContaining({
      session_id: created.metadata.id,
      lifecycle: 'connected',
    }));
    const edgeId = engine.findEdgeId('session-principal', 'session-target', 'HAS_SESSION');
    expect(edgeId).toBeTruthy();
    expect((engine as any).ctx.graph.getEdgeAttribute(edgeId, 'session_live')).toBe(true);
    expect(new MutationJournal(statePath).readTransactionsSince(baseCheckpoint)).toEqual([]);
  });

  it('freezes the handle synchronously after a committed close apply failure and replays it once', async () => {
    const first = new GraphEngine(config(), statePath);
    engines.add(first);
    const manager = new SessionManager(first);
    managers.add(manager);
    manager.onDurableEvent(event => {
      first.recordSessionDescriptor(event.session);
    });
    const fake = adapter(() => undefined);
    manager.registerAdapter(fake.adapter);

    const observedAt = '2026-07-16T03:00:00.000Z';
    first.addNode({
      id: 'post-commit-principal',
      type: 'user',
      label: 'Post-commit principal',
      discovered_at: observedAt,
      confidence: 1,
    });
    first.addNode({
      id: 'post-commit-target',
      type: 'host',
      label: 'Post-commit target',
      discovered_at: observedAt,
      confidence: 1,
    });
    const created = await manager.create({
      kind: 'local_pty',
      title: 'post-commit close',
      target_node: 'post-commit-target',
      principal_node: 'post-commit-principal',
      initial_wait_ms: 0,
    });
    first.ingestSessionResult({
      success: true,
      target_node: 'post-commit-target',
      principal_node: 'post-commit-principal',
      session_id: created.metadata.connection_id,
    });
    first.flushNow();
    const baseCheckpoint = (JSON.parse(readFileSync(statePath, 'utf-8')) as {
      journalSnapshotSeq: number;
    }).journalSnapshotSeq;

    const closeHandle = vi.spyOn(fake.handle, 'close');
    const persistence = (first as unknown as {
      persistence: {
        applyTransactionDraft(
          draft: unknown,
          mutators?: unknown,
        ): unknown;
      };
    }).persistence;
    const applyTransactionDraft = persistence.applyTransactionDraft.bind(persistence);
    let closeApplyCalls = 0;
    vi.spyOn(persistence, 'applyTransactionDraft').mockImplementation((draft, mutators) => {
      const result = applyTransactionDraft(draft, mutators);
      closeApplyCalls++;
      if (closeApplyCalls === 2) {
        throw new Error('synthetic committed session close apply failure');
      }
      return result;
    });

    expect(() => manager.close(created.metadata.id))
      .toThrow('synthetic committed session close apply failure');
    expect(closeApplyCalls).toBe(2);
    expect(closeHandle).toHaveBeenCalledTimes(1);
    expect(manager.getSession(created.metadata.id)?.state).toBe('closed');
    expect(first.getPersistenceRecoveryStatus()).toMatchObject({
      complete: false,
      writable: false,
      reason: expect.stringContaining('failed during in-memory application'),
    });
    const committed = new MutationJournal(statePath).readTransactionsSince(baseCheckpoint);
    expect(committed).toHaveLength(1);

    (manager as unknown as { engine: GraphEngine | null }).engine = null;
    await manager.shutdown();
    managers.delete(manager);
    first.dispose();
    engines.delete(first);
    vi.restoreAllMocks();

    const second = new GraphEngine(config(), statePath);
    engines.add(second);
    expect(second.getSessionDescriptors()).toContainEqual(expect.objectContaining({
      session_id: created.metadata.id,
      lifecycle: 'closed',
      resume_intent: expect.objectContaining({
        policy: 'none',
        requested: false,
      }),
    }));
    const edgeId = second.findEdgeId(
      'post-commit-principal',
      'post-commit-target',
      'HAS_SESSION',
    );
    expect(edgeId).toBeTruthy();
    expect((second as any).ctx.graph.getEdgeAttribute(edgeId, 'session_live')).toBe(false);
    expect(second.getFullHistory().filter(
      entry => entry.event_type === 'session_closed'
        && entry.details?.session_id === created.metadata.id,
    )).toHaveLength(1);
    expect(second.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      journal: { applied: 1 },
    });

    second.flushNow();
    second.dispose();
    engines.delete(second);
    const third = new GraphEngine(config(), statePath);
    engines.add(third);
    expect(third.getFullHistory().filter(
      entry => entry.event_type === 'session_closed'
        && entry.details?.session_id === created.metadata.id,
    )).toHaveLength(1);
  });

  it('preserves graceful rearm resume intent while ordinary close remains terminal', async () => {
    const first = new GraphEngine(config(), statePath);
    engines.add(first);
    const manager = new SessionManager(first);
    managers.add(manager);
    manager.onDurableEvent(event => {
      first.recordSessionDescriptor(event.session);
    });

    const observedAt = '2026-07-16T04:00:00.000Z';
    first.addNode({
      id: 'rearm-principal',
      type: 'user',
      label: 'Rearm principal',
      discovered_at: observedAt,
      confidence: 1,
    });
    first.addNode({
      id: 'rearm-target',
      type: 'host',
      label: 'Rearm target',
      discovered_at: observedAt,
      confidence: 1,
    });

    let spawnCount = 0;
    const handles: AdapterHandle[] = [];
    manager.registerAdapter({
      kind: 'socket',
      async spawn(options) {
        spawnCount++;
        const fake = adapter(() => undefined).handle;
        fake.close = vi.fn();
        handles.push(fake);
        if (spawnCount === 2) {
          (options.onConnect as (() => void) | undefined)?.();
        }
        return fake;
      },
    });

    const pending = await manager.create({
      kind: 'socket',
      title: 'pending resumable listener',
      mode: 'listen',
      accept_mode: 'rearm',
      port: 4444,
      initial_wait_ms: 0,
    });
    const connected = await manager.create({
      kind: 'socket',
      title: 'connected resumable listener',
      mode: 'listen',
      accept_mode: 'rearm',
      port: 5555,
      target_node: 'rearm-target',
      principal_node: 'rearm-principal',
      initial_wait_ms: 0,
    });
    const ordinary = await manager.create({
      kind: 'socket',
      title: 'operator-closed listener',
      mode: 'listen',
      accept_mode: 'rearm',
      port: 6666,
      initial_wait_ms: 0,
    });
    expect(pending.metadata.state).toBe('pending');
    expect(connected.metadata.state).toBe('connected');
    expect(ordinary.metadata.state).toBe('pending');

    manager.close(ordinary.metadata.id);
    await manager.shutdown();
    for (const handle of handles) {
      expect(handle.close).toHaveBeenCalledTimes(1);
    }

    const liveDescriptors = first.getSessionDescriptors();
    expect(liveDescriptors.find(
      descriptor => descriptor.session_id === pending.metadata.id,
    )).toMatchObject({
      lifecycle: 'closed',
      recovery_lifecycle: 'resume_available',
      resume_intent: {
        policy: 'manual',
        requested: true,
        prior_state: 'pending',
        recovery_prior_state: 'resume_available',
      },
    });
    expect(liveDescriptors.find(
      descriptor => descriptor.session_id === connected.metadata.id,
    )).toMatchObject({
      lifecycle: 'closed',
      recovery_lifecycle: 'resume_available',
      last_connection_state: 'interrupted',
      resume_intent: {
        policy: 'manual',
        requested: true,
        prior_state: 'connected',
        recovery_prior_state: 'resume_available',
      },
    });
    expect(liveDescriptors.find(
      descriptor => descriptor.session_id === ordinary.metadata.id,
    )).toMatchObject({
      lifecycle: 'closed',
      resume_intent: { policy: 'none', requested: false },
    });
    const firstEdgeId = first.findEdgeId(
      'rearm-principal',
      'rearm-target',
      'HAS_SESSION',
    );
    expect(firstEdgeId).toBeTruthy();
    expect((first as any).ctx.graph.getEdgeAttribute(firstEdgeId, 'session_live')).toBe(false);

    (manager as unknown as { engine: GraphEngine | null }).engine = null;
    managers.delete(manager);
    first.dispose();
    engines.delete(first);

    const restarted = new GraphEngine(config(), statePath);
    engines.add(restarted);
    const descriptors = restarted.getSessionDescriptors();
    expect(descriptors.find(
      descriptor => descriptor.session_id === pending.metadata.id,
    )).toMatchObject({
      lifecycle: 'closed',
      recovery_lifecycle: 'resume_available',
      resume_intent: {
        policy: 'manual',
        requested: true,
        prior_state: 'pending',
        recovery_prior_state: 'resume_available',
      },
    });
    expect(descriptors.find(
      descriptor => descriptor.session_id === connected.metadata.id,
    )).toMatchObject({
      lifecycle: 'closed',
      recovery_lifecycle: 'resume_available',
      last_connection_state: 'interrupted',
      resume_intent: {
        policy: 'manual',
        requested: true,
        prior_state: 'connected',
        recovery_prior_state: 'resume_available',
      },
    });
    expect(descriptors.find(
      descriptor => descriptor.session_id === ordinary.metadata.id,
    )).toMatchObject({
      lifecycle: 'closed',
      resume_intent: { policy: 'none', requested: false },
    });
    const restartedEdgeId = restarted.findEdgeId(
      'rearm-principal',
      'rearm-target',
      'HAS_SESSION',
    );
    expect(restartedEdgeId).toBeTruthy();
    expect((restarted as any).ctx.graph.getEdgeAttribute(restartedEdgeId, 'session_live')).toBe(false);
  });
});
