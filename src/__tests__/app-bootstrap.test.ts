import { describe, it, expect, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { createOverwatchApp, registerAllTools, shutdownOverwatchApp, ToolRegistrar, type OverwatchApp } from '../app.js';
import { InProcessTapeController } from '../services/in-process-tape.js';

describe('app bootstrap', () => {
  it('creates the core app without binding a transport', () => {
    const app = createOverwatchApp({
      configPath: resolve('./engagement.example.json'),
      skillDir: resolve('./skills'),
      dashboardPort: 0,
    });

    expect(app.server).toBeDefined();
    expect(app.engine).toBeDefined();
    expect(app.sessionManager).toBeDefined();
    expect(app.dashboard).toBeNull();
  });

  it('registers all tools without requiring stdio startup', () => {
    const app = createOverwatchApp({
      configPath: resolve('./engagement.example.json'),
      skillDir: resolve('./skills'),
      dashboardPort: 0,
    });

    const toolNames: string[] = [];
    const fakeServer = {
      registerTool(name: string, _config?: any, _cb?: any) {
        toolNames.push(name);
        return { enable() {}, disable() {}, enabled: true };
      },
    } as any;

    registerAllTools(fakeServer, {
      engine: app.engine,
      skills: app.skills,
      processTracker: app.processTracker,
      sessionManager: app.sessionManager,
      engagementManager: app.engagementManager,
      getDashboardStatus: () => ({ enabled: false, running: false }),
    });

    // Minimum expected tool count — increase this when adding new tools
    expect(toolNames.length).toBeGreaterThanOrEqual(39);
    expect(toolNames).toContain('get_state');
    expect(toolNames).toContain('run_retrospective');
    expect(toolNames).toContain('generate_report');
    expect(toolNames).toContain('open_session');
    expect(toolNames).toContain('create_engagement');
    expect(toolNames).toContain('list_engagements');
    expect(toolNames).toContain('add_objective');
    expect(toolNames).toContain('set_opsec');
    expect(toolNames).toContain('close_session');
    expect(toolNames).toContain('update_scope');
    expect(toolNames).toContain('get_system_prompt');
    expect(toolNames).toContain('ingest_azurehound');
    expect(toolNames).toContain('dispatch_subnet_agents');
  });

  it('keeps read-only MCP tools available while rejecting mutations in degraded recovery', async () => {
    const handlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();
    const fakeServer = {
      registerTool(name: string, _config: unknown, callback: (...args: unknown[]) => Promise<unknown>) {
        handlers.set(name, callback);
        return { enable() {}, disable() {}, enabled: true };
      },
    };
    const recovery = {
      outcome: 'incomplete' as const,
      source: 'state' as const,
      complete: false,
      writable: false,
      reason: 'sequence gap',
      base_checkpoint: 1,
      highest_allocated_seq: 3,
      highest_on_disk_seq: 3,
      highest_contiguous_applied_seq: 1,
      consecutive_persistence_failures: 0,
      journal: {
        enabled: true,
        read: 2,
        attempted: 1,
        applied: 0,
        skipped: 1,
        failed: 0,
        malformed: false,
        preserved: true,
      },
    };
    const registrar = new ToolRegistrar(fakeServer as never, {
      isPersistenceWritable: () => false,
      getPersistenceRecoveryStatus: () => recovery,
    });
    let mutationCalls = 0;
    let readCalls = 0;
    registrar.registerTool('mutating_test', {
      description: 'mutates',
      annotations: { readOnlyHint: false },
    }, async () => {
      mutationCalls++;
      return { content: [{ type: 'text' as const, text: 'mutated' }] };
    });
    registrar.registerTool('read_test', {
      description: 'reads',
      annotations: { readOnlyHint: true },
    }, async () => {
      readCalls++;
      return { content: [{ type: 'text' as const, text: 'read' }] };
    });
    registrar.registerTool('get_state', {
      description: 'conditionally snapshots',
      annotations: { readOnlyHint: true },
    }, async () => ({ content: [{ type: 'text' as const, text: 'state' }] }));
    registrar.registerTool('get_system_prompt', {
      description: 'conditionally snapshots despite a mutating annotation',
      annotations: { readOnlyHint: false },
    }, async () => ({ content: [{ type: 'text' as const, text: 'prompt' }] }));
    registrar.registerTool('check_processes', {
      description: 'refreshes durable process status despite a read annotation',
      annotations: { readOnlyHint: true },
    }, async () => ({ content: [{ type: 'text' as const, text: 'processes' }] }));

    const blocked = await handlers.get('mutating_test')!({});
    const allowed = await handlers.get('read_test')!({});
    const snapshotBlocked = await handlers.get('get_state')!({ snapshot: true });
    const stateAllowed = await handlers.get('get_state')!({ snapshot: false });
    const promptSnapshotBlocked = await handlers.get('get_system_prompt')!({ snapshot: true });
    const promptReadAllowed = await handlers.get('get_system_prompt')!({ snapshot: false });
    const processRefreshBlocked = await handlers.get('check_processes')!({});
    expect(blocked).toMatchObject({ isError: true });
    expect(JSON.stringify(blocked)).toContain('PERSISTENCE_READ_ONLY');
    expect(mutationCalls).toBe(0);
    expect(allowed).toMatchObject({ content: [{ text: 'read' }] });
    expect(readCalls).toBe(1);
    expect(snapshotBlocked).toMatchObject({ isError: true });
    expect(stateAllowed).toMatchObject({ content: [{ text: 'state' }] });
    expect(promptSnapshotBlocked).toMatchObject({ isError: true });
    expect(promptReadAllowed).toMatchObject({ content: [{ text: 'prompt' }] });
    expect(processRefreshBlocked).toMatchObject({ isError: true });
  });

  it('always tears down runtime and disposes while skipping degraded durable writes', async () => {
    const taskShutdown = vi.fn().mockRejectedValue(new Error('task shutdown failed'));
    const transportClose = vi.fn().mockResolvedValue(undefined);
    const sessionShutdown = vi.fn().mockResolvedValue(undefined);
    const dashboardStop = vi.fn().mockResolvedValue(undefined);
    const tapeDisable = vi.fn().mockResolvedValue(undefined);
    const dispose = vi.fn();
    const setTrackedProcesses = vi.fn();
    const persist = vi.fn();
    const flushNow = vi.fn();
    const httpServerClose = vi.fn((callback: (error?: Error) => void) => callback());

    const app = {
      taskExecution: { shutdown: taskShutdown },
      httpTransports: { session: { close: transportClose } },
      httpServer: { close: httpServerClose },
      sessionManager: { shutdown: sessionShutdown },
      dashboard: { stop: dashboardStop },
      tape: { disable: tapeDisable },
      processTracker: { serialize: vi.fn(() => []) },
      engine: {
        isPersistenceWritable: () => false,
        setTrackedProcesses,
        persist,
        flushNow,
        dispose,
      },
    } as unknown as OverwatchApp;

    await expect(shutdownOverwatchApp(app)).rejects.toThrow('task shutdown failed');

    expect(transportClose).toHaveBeenCalledOnce();
    expect(httpServerClose).toHaveBeenCalledOnce();
    expect(sessionShutdown).toHaveBeenCalledOnce();
    expect(dashboardStop).toHaveBeenCalledOnce();
    expect(tapeDisable).toHaveBeenCalledWith({ audit: false });
    expect(setTrackedProcesses).not.toHaveBeenCalled();
    expect(persist).not.toHaveBeenCalled();
    expect(flushNow).not.toHaveBeenCalled();
    expect(dispose).toHaveBeenCalledOnce();
  });

  it('closes a real tape without an audit mutation during degraded shutdown', async () => {
    const tapeDir = mkdtempSync(join(tmpdir(), 'overwatch-degraded-shutdown-tape-'));
    let writable = true;
    const logActionEvent = vi.fn(() => ({ event_id: 'evt-tape-start' }));
    const dispose = vi.fn();
    const engine = {
      isPersistenceWritable: () => writable,
      logActionEvent,
      setTrackedProcesses: vi.fn(),
      persist: vi.fn(),
      flushNow: vi.fn(),
      dispose,
    };
    const tape = new InProcessTapeController(engine as any, { defaultDir: tapeDir });

    try {
      tape.enable({ sessionId: 'shutdown-test' });
      expect(tape.getStatus().enabled).toBe(true);
      writable = false;

      const app = {
        taskExecution: { shutdown: vi.fn().mockResolvedValue(undefined) },
        httpTransports: {},
        sessionManager: { shutdown: vi.fn().mockResolvedValue(undefined) },
        dashboard: null,
        tape,
        processTracker: { serialize: vi.fn(() => []) },
        engine,
      } as unknown as OverwatchApp;

      await expect(shutdownOverwatchApp(app)).resolves.toBeUndefined();

      expect(tape.getStatus()).toMatchObject({ enabled: false, frame_count: 0 });
      expect(tape.getStatus().path).toBeUndefined();
      expect(logActionEvent).toHaveBeenCalledTimes(1);
      expect(engine.setTrackedProcesses).not.toHaveBeenCalled();
      expect(engine.persist).not.toHaveBeenCalled();
      expect(engine.flushNow).not.toHaveBeenCalled();
      expect(dispose).toHaveBeenCalledOnce();
    } finally {
      rmSync(tapeDir, { recursive: true, force: true });
    }
  });
});
