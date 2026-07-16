import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import { reconcileRuntimeOwnershipOnStartup } from '../runtime-ownership-recovery.js';
import type { EngagementConfig } from '../../types.js';
import type { ProcessIdentityObserver } from '../process-identity.js';

function config(): EngagementConfig {
  return {
    id: 'runtime-recovery',
    name: 'Runtime recovery',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'test', max_noise: 1 },
  };
}

function fingerprint(): string {
  return 'a'.repeat(64);
}

describe('runtime ownership startup recovery', () => {
  const directories: string[] = [];
  const engines: GraphEngine[] = [];

  afterEach(() => {
    for (const engine of engines.splice(0)) engine.dispose();
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  function engine(): GraphEngine {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-runtime-recovery-'));
    directories.push(directory);
    const created = new GraphEngine(config(), join(directory, 'state.json'));
    engines.push(created);
    return created;
  }

  it('finalizes an unacknowledged reservation exactly once', () => {
    const graph = engine();
    graph.logActionEvent({
      action_id: 'action-reserved',
      description: 'reserved action',
      event_type: 'action_started',
      category: 'frontier',
    });
    graph.reserveRuntimeRun({
      run_id: 'run-reserved',
      kind: 'tracked_process',
      action_id: 'action-reserved',
      daemon_owner: 'daemon-test',
      command_fingerprint: fingerprint(),
      evidence_state: 'pending',
    });

    expect(reconcileRuntimeOwnershipOnStartup(graph)).toMatchObject({
      examined: 1,
      interrupted: 1,
      unresolved: 0,
    });
    expect(reconcileRuntimeOwnershipOnStartup(graph).examined).toBe(0);
    expect(graph.getRuntimeRuns()[0]).toMatchObject({
      lifecycle: 'interrupted',
      finalization_status: 'interrupted',
      action_terminal_event_id: expect.any(String),
    });
    expect(graph.getFullHistory().filter(event =>
      event.action_id === 'action-reserved'
      && (event.event_type === 'action_completed' || event.event_type === 'action_failed')))
      .toHaveLength(1);
  });

  it('terminates a verified orphan group before marking the run interrupted', () => {
    const graph = engine();
    graph.reserveRuntimeRun({
      run_id: 'run-verified',
      kind: 'headless_agent',
      task_id: 'task-1',
      daemon_owner: 'daemon-old',
      command_fingerprint: fingerprint(),
    });
    graph.acknowledgeRuntimeRunOwnership('run-verified', {
      pid: 5001,
      process_group_id: 5001,
      process_start_identity: 'start-verified',
      ownership_token: 'token-verified',
    });
    graph.markRuntimeRunLaunched('run-verified', 5002);
    let alive = true;
    const observer: ProcessIdentityObserver = {
      isAlive: () => alive,
      observe: pid => ({
        pid,
        process_group_id: 5001,
        process_start_identity: 'start-verified',
        ownership_token: 'token-verified',
      }),
    };
    const signals: NodeJS.Signals[] = [];

    const summary = reconcileRuntimeOwnershipOnStartup(graph, {
      observer,
      wait: () => undefined,
      signal: (_run, signal) => {
        signals.push(signal);
        alive = false;
        return {
          status: 'verified',
          observed: {
            pid: 5001,
            process_group_id: 5001,
            process_start_identity: 'start-verified',
            ownership_token: 'token-verified',
          },
        };
      },
    });

    expect(signals).toEqual(['SIGTERM']);
    expect(summary).toMatchObject({ terminated: 1, interrupted: 1, unresolved: 0 });
    expect(graph.getRuntimeRuns()[0]).toMatchObject({ lifecycle: 'interrupted' });
  });

  it.skipIf(process.platform === 'win32')(
    'refuses to acknowledge managed ownership without a supervisor-owned group and start identity',
    () => {
      const graph = engine();
      graph.reserveRuntimeRun({
        run_id: 'run-invalid-identity',
        kind: 'headless_agent',
        daemon_owner: 'daemon-old',
        command_fingerprint: fingerprint(),
      });

      expect(() => graph.acknowledgeRuntimeRunOwnership('run-invalid-identity', {
        pid: 5001,
        process_group_id: 5000,
        process_start_identity: 'start',
        ownership_token: 'token-invalid',
      })).toThrow(/supervisor-owned process group/);
      expect(() => graph.acknowledgeRuntimeRunOwnership('run-invalid-identity', {
        pid: 5001,
        process_group_id: 5001,
        ownership_token: 'token-invalid',
      })).toThrow(/process start identity/);
      expect(() => graph.acknowledgeRuntimeRunOwnership('run-invalid-identity', {
        pid: 5001,
        process_group_id: 5001,
        process_start_identity: 'start',
      })).toThrow(/ownership token/);
      expect(graph.getRuntimeRuns()[0].lifecycle).toBe('reserved');
    },
  );

  it.each([
    {
      name: 'reused',
      storedStart: 'old-start',
      observedStart: 'new-start',
      expected: 'different physical process',
    },
    {
      name: 'unverifiable',
      storedStart: undefined,
      observedStart: undefined,
      expected: 'cannot be verified',
    },
  ])('never signals a $name pid and surfaces unresolved ownership', ({ storedStart, observedStart, expected }) => {
    const graph = engine();
    graph.setRuntimeRuns([{
      run_id: `run-${expected}`,
      kind: 'tracked_process',
      daemon_owner: 'daemon-old',
      command_fingerprint: fingerprint(),
      ownership_mode: 'managed_supervisor',
      signal_scope: 'process_group',
      pid: 6001,
      process_group_id: 6001,
      process_start_identity: storedStart,
      ownership_token: 'token-stored',
      started_at: '2026-07-16T00:00:00.000Z',
      ownership_acknowledged_at: '2026-07-16T00:00:00.001Z',
      launched_at: '2026-07-16T00:00:00.002Z',
      target_pid: 6002,
      lifecycle: 'running',
      evidence_state: 'none',
    }]);
    const observer: ProcessIdentityObserver = {
      isAlive: () => true,
      observe: pid => ({
        pid,
        process_group_id: 6001,
        process_start_identity: observedStart,
        ownership_token: 'token-stored',
      }),
    };
    const signal = vi.fn();

    const summary = reconcileRuntimeOwnershipOnStartup(graph, {
      observer,
      signal,
      wait: () => undefined,
    });

    expect(signal).not.toHaveBeenCalled();
    expect(summary.unresolved).toBe(1);
    expect(graph.getRuntimeRuns()[0]).toMatchObject({
      lifecycle: 'unknown',
      recovery_warning: expect.stringContaining(expected),
    });
    expect(graph.getPersistenceRecoveryStatus().runtime_ownership_warnings).toEqual([
      expect.objectContaining({
        run_id: `run-${expected}`,
        message: expect.stringContaining(expected),
      }),
    ]);
  });

  it('escalates a verified process group from TERM to KILL when it remains alive', () => {
    const graph = engine();
    graph.setRuntimeRuns([{
      run_id: 'run-stubborn',
      kind: 'headless_agent',
      daemon_owner: 'daemon-old',
      command_fingerprint: fingerprint(),
      ownership_mode: 'managed_supervisor',
      signal_scope: 'process_group',
      pid: 6101,
      process_group_id: 6101,
      process_start_identity: 'start-stubborn',
      ownership_token: 'token-stubborn',
      started_at: '2026-07-16T00:00:00.000Z',
      ownership_acknowledged_at: '2026-07-16T00:00:00.001Z',
      launched_at: '2026-07-16T00:00:00.002Z',
      lifecycle: 'running',
    }]);
    let alive = true;
    const observer: ProcessIdentityObserver = {
      isAlive: () => alive,
      observe: pid => ({
        pid,
        process_group_id: 6101,
        process_start_identity: 'start-stubborn',
        ownership_token: 'token-stubborn',
      }),
    };
    const signals: NodeJS.Signals[] = [];

    const summary = reconcileRuntimeOwnershipOnStartup(graph, {
      observer,
      wait: () => undefined,
      signal: (_run, signal) => {
        signals.push(signal);
        if (signal === 'SIGKILL') alive = false;
        return {
          status: 'verified',
          observed: {
            pid: 6101,
            process_group_id: 6101,
            process_start_identity: 'start-stubborn',
            ownership_token: 'token-stubborn',
          },
        };
      },
    });

    expect(signals).toEqual(['SIGTERM', 'SIGKILL']);
    expect(summary).toMatchObject({ terminated: 1, interrupted: 1, unresolved: 0 });
  });

  it.each([
    {
      name: 'external adopted',
      ownership_mode: 'external_adopted' as const,
      signal_scope: 'none' as const,
    },
    {
      name: 'legacy',
      ownership_mode: undefined,
      signal_scope: undefined,
    },
  ])('never signals a $name process record', ({ ownership_mode, signal_scope }) => {
    const graph = engine();
    graph.setRuntimeRuns([{
      run_id: `run-${ownership_mode ?? 'legacy'}`,
      kind: 'tracked_process',
      daemon_owner: 'daemon-old',
      command_fingerprint: fingerprint(),
      ownership_mode,
      signal_scope,
      pid: 6201,
      process_group_id: 6201,
      process_start_identity: 'start-external',
      started_at: '2026-07-16T00:00:00.000Z',
      ownership_acknowledged_at: '2026-07-16T00:00:00.001Z',
      lifecycle: 'running',
    }]);
    const signal = vi.fn();

    const summary = reconcileRuntimeOwnershipOnStartup(graph, {
      observer: {
        isAlive: () => true,
        observe: pid => ({
          pid,
          process_group_id: 6201,
          process_start_identity: 'start-external',
        }),
      },
      signal,
    });

    expect(signal).not.toHaveBeenCalled();
    expect(summary.unresolved).toBe(1);
    expect(graph.getRuntimeRuns()[0].lifecycle).toBe('unknown');
  });

  it('continues recovery when signaling races with process exit', () => {
    const graph = engine();
    graph.setRuntimeRuns([{
      run_id: 'run-race',
      kind: 'headless_agent',
      daemon_owner: 'daemon-old',
      command_fingerprint: fingerprint(),
      ownership_mode: 'managed_supervisor',
      signal_scope: 'process_group',
      pid: 6301,
      process_group_id: 6301,
      process_start_identity: 'start-race',
      ownership_token: 'token-race',
      started_at: '2026-07-16T00:00:00.000Z',
      ownership_acknowledged_at: '2026-07-16T00:00:00.001Z',
      lifecycle: 'running',
    }]);
    let checks = 0;
    const summary = reconcileRuntimeOwnershipOnStartup(graph, {
      observer: {
        isAlive: () => checks++ === 0,
        observe: pid => ({
          pid,
          process_group_id: 6301,
          process_start_identity: 'start-race',
          ownership_token: 'token-race',
        }),
      },
      signal: () => { throw new Error('ESRCH'); },
    });

    expect(summary).toMatchObject({ interrupted: 1, unresolved: 0 });
    expect(graph.getRuntimeRuns()[0].lifecycle).toBe('interrupted');
  });

  it('surfaces a signal permission failure without aborting remaining recovery', () => {
    const graph = engine();
    graph.setRuntimeRuns([{
      run_id: 'run-denied',
      kind: 'headless_agent',
      daemon_owner: 'daemon-old',
      command_fingerprint: fingerprint(),
      ownership_mode: 'managed_supervisor',
      signal_scope: 'process_group',
      pid: 6401,
      process_group_id: 6401,
      process_start_identity: 'start-denied',
      ownership_token: 'token-denied',
      started_at: '2026-07-16T00:00:00.000Z',
      ownership_acknowledged_at: '2026-07-16T00:00:00.001Z',
      lifecycle: 'running',
    }]);
    const summary = reconcileRuntimeOwnershipOnStartup(graph, {
      observer: {
        isAlive: () => true,
        observe: pid => ({
          pid,
          process_group_id: 6401,
          process_start_identity: 'start-denied',
          ownership_token: 'token-denied',
        }),
      },
      signal: () => { throw new Error('EPERM'); },
    });

    expect(summary).toMatchObject({ interrupted: 0, unresolved: 1 });
    expect(graph.getPersistenceRecoveryStatus().runtime_ownership_warnings?.[0].message)
      .toContain('EPERM');
  });

  it('surfaces deferred active ownership while the durable write gate is closed', () => {
    const graph = engine();
    graph.reserveRuntimeRun({
      run_id: 'run-deferred',
      kind: 'tracked_process',
      daemon_owner: 'daemon-current',
      command_fingerprint: fingerprint(),
    });
    vi.spyOn(graph, 'isPersistenceWritable').mockReturnValue(false);

    expect(reconcileRuntimeOwnershipOnStartup(graph).examined).toBe(0);
    expect(graph.getPersistenceRecoveryStatus().runtime_ownership_warnings).toEqual([
      expect.objectContaining({
        run_id: 'run-deferred',
        lifecycle: 'reserved',
        message: expect.stringContaining('deferred'),
      }),
    ]);
  });

  it('does not present an ordinary known terminal failure as unresolved ownership', () => {
    const graph = engine();
    graph.reserveRuntimeRun({
      run_id: 'run-known-failure',
      kind: 'tracked_process',
      daemon_owner: 'daemon-current',
      command_fingerprint: fingerprint(),
    });
    graph.finalizeRuntimeRun({
      run_id: 'run-known-failure',
      lifecycle: 'failed',
      recovery_warning: 'Target binary was not found.',
    });

    expect(graph.getPersistenceRecoveryStatus().runtime_ownership_warnings).toBeUndefined();
  });

  it.each([
    {
      terminal: 'action_completed' as const,
      expected: 'completed',
      details: {},
    },
    {
      terminal: 'action_failed' as const,
      expected: 'failed',
      details: { reason: 'nonzero_exit' },
    },
  ])('adopts an already-durable $terminal outcome after a split finalization crash', ({
    terminal,
    expected,
    details,
  }) => {
    const graph = engine();
    graph.beginRuntimeAction({
      run: {
        run_id: `run-split-${expected}`,
        kind: 'tracked_process',
        action_id: `action-split-${expected}`,
        daemon_owner: 'daemon-old',
        command_fingerprint: fingerprint(),
      },
      event: {
        action_id: `action-split-${expected}`,
        description: 'split action',
        event_type: 'action_started',
      },
    });
    graph.logActionEvent({
      action_id: `action-split-${expected}`,
      description: 'split terminal',
      event_type: terminal,
      details,
    });
    graph.persist();

    reconcileRuntimeOwnershipOnStartup(graph);

    expect(graph.getRuntimeRuns()[0]).toMatchObject({
      lifecycle: expected,
      finalization_status: expected,
      action_terminal_event_id: expect.any(String),
    });
    expect(graph.getFullHistory().filter(event =>
      event.action_id === `action-split-${expected}`
      && (event.event_type === 'action_completed' || event.event_type === 'action_failed')))
      .toHaveLength(1);
  });

  it('does not associate a second attempt with an older terminal sharing the action id', () => {
    const graph = engine();
    graph.beginRuntimeAction({
      run: {
        run_id: 'run-attempt-1',
        kind: 'tracked_process',
        action_id: 'action-reused',
        daemon_owner: 'daemon-old',
        command_fingerprint: fingerprint(),
      },
      event: {
        action_id: 'action-reused',
        description: 'attempt one',
        event_type: 'action_started',
      },
    });
    graph.finishRuntimeAction({
      run_id: 'run-attempt-1',
      lifecycle: 'completed',
      event: {
        action_id: 'action-reused',
        description: 'attempt one complete',
        event_type: 'action_completed',
      },
    });
    graph.beginRuntimeAction({
      run: {
        run_id: 'run-attempt-2',
        kind: 'tracked_process',
        action_id: 'action-reused',
        daemon_owner: 'daemon-old',
        command_fingerprint: fingerprint(),
      },
      event: {
        action_id: 'action-reused',
        description: 'attempt two',
        event_type: 'action_started',
      },
    });

    reconcileRuntimeOwnershipOnStartup(graph);

    expect(graph.getRuntimeRuns()).toEqual(expect.arrayContaining([
      expect.objectContaining({ run_id: 'run-attempt-1', lifecycle: 'completed' }),
      expect.objectContaining({ run_id: 'run-attempt-2', lifecycle: 'interrupted' }),
    ]));
    expect(graph.getFullHistory().filter(event =>
      event.action_id === 'action-reused'
      && (event.event_type === 'action_completed' || event.event_type === 'action_failed')))
      .toHaveLength(2);
  });

  it('persists exact-once unfinished-action finalization across repeated reopens', () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-runtime-reopen-'));
    directories.push(directory);
    const statePath = join(directory, 'state.json');
    const first = new GraphEngine(config(), statePath);
    engines.push(first);
    first.beginRuntimeAction({
      run: {
        run_id: 'run-reopen',
        kind: 'tracked_process',
        action_id: 'action-reopen',
        daemon_owner: 'daemon-old',
        command_fingerprint: fingerprint(),
      },
      event: {
        action_id: 'action-reopen',
        description: 'reopen action',
        event_type: 'action_started',
      },
    });
    first.flushNow();
    first.dispose();
    engines.splice(engines.indexOf(first), 1);

    const second = new GraphEngine(config(), statePath);
    engines.push(second);
    expect(reconcileRuntimeOwnershipOnStartup(second).interrupted).toBe(1);
    second.flushNow();
    second.dispose();
    engines.splice(engines.indexOf(second), 1);

    const third = new GraphEngine(config(), statePath);
    engines.push(third);
    expect(reconcileRuntimeOwnershipOnStartup(third).examined).toBe(0);
    expect(third.getFullHistory().filter(event =>
      event.action_id === 'action-reopen'
      && (event.event_type === 'action_completed' || event.event_type === 'action_failed')))
      .toHaveLength(1);
    expect(third.getRuntimeRuns()[0].action_terminal_event_id).toEqual(expect.any(String));
  });

  it('bounds terminal runtime history while retaining active ownership records', () => {
    const graph = engine();
    graph.setRuntimeRuns([
      ...Array.from({ length: 1_000 }, (_, index) => ({
        run_id: `terminal-${String(index).padStart(4, '0')}`,
        kind: 'tracked_process' as const,
        daemon_owner: 'daemon-old',
        command_fingerprint: fingerprint(),
        started_at: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
        completed_at: new Date(Date.UTC(2026, 0, 1, 1, 0, index)).toISOString(),
        lifecycle: 'completed' as const,
        finalization_status: 'completed' as const,
      })),
      {
        run_id: 'active-final',
        kind: 'tracked_process',
        daemon_owner: 'daemon-current',
        command_fingerprint: fingerprint(),
        started_at: '2026-07-16T00:00:00.000Z',
        lifecycle: 'reserved',
      },
    ]);

    graph.finalizeRuntimeRun({
      run_id: 'active-final',
      lifecycle: 'completed',
    });

    const runs = graph.getRuntimeRuns();
    expect(runs).toHaveLength(1_000);
    expect(runs).toContainEqual(expect.objectContaining({ run_id: 'active-final' }));
    expect(runs).not.toContainEqual(expect.objectContaining({ run_id: 'terminal-0000' }));
  });
});
