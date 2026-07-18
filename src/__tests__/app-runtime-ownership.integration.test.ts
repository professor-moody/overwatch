import { afterEach, describe, expect, it } from 'vitest';
import { spawn, type ChildProcess } from 'child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  createOverwatchApp,
  shutdownOverwatchApp,
  type OverwatchApp,
} from '../app.js';
import { GraphEngine } from '../services/graph-engine.js';
import { withConfigMetadata } from '../services/engagement-config-service.js';
import { spawnManagedRuntimeSupervisor } from '../services/managed-runtime-supervisor.js';
import {
  observeProcessIdentity,
  processIsAlive,
  verifyRuntimeProcessIdentity,
} from '../services/process-identity.js';
import type { EngagementConfig } from '../types.js';

function config(id: string): EngagementConfig {
  return {
    id,
    name: 'Runtime ownership app recovery',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'test', max_noise: 1 },
  };
}

function killGroup(child: ChildProcess | undefined): void {
  if (!child?.pid) return;
  if (process.platform !== 'win32') {
    try {
      process.kill(-child.pid, 'SIGKILL');
      return;
    } catch {}
  }
  try { child.kill('SIGKILL'); } catch {}
}

describe.skipIf(process.platform === 'win32')('application runtime ownership recovery', () => {
  const directories: string[] = [];
  const apps: OverwatchApp[] = [];
  const children: ChildProcess[] = [];

  afterEach(async () => {
    for (const app of apps.splice(0)) {
      try { await shutdownOverwatchApp(app); } catch {}
    }
    for (const child of children.splice(0)) killGroup(child);
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('refuses a second runtime owner for the same state even on another port', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-app-daemon-owner-'));
    directories.push(directory);
    const statePath = join(directory, 'state.json');
    const configPath = join(directory, 'engagement.json');
    const engagement = config(`app-daemon-owner-${Date.now()}`);
    writeFileSync(configPath, JSON.stringify(engagement));

    const first = createOverwatchApp({
      config: engagement,
      configPath,
      stateFilePath: statePath,
      skillDir: join(process.cwd(), 'skills'),
      dashboardPort: 0,
      runtimeOwnership: {
        transport: 'http',
        dashboard_url: 'http://127.0.0.1:18384',
        mcp_url: 'http://127.0.0.1:13000/mcp',
      },
    });
    apps.push(first);
    const checkpointBefore = first.engine.getPersistenceRecoveryStatus().highest_contiguous_applied_seq;

    expect(() => createOverwatchApp({
      config: engagement,
      configPath,
      stateFilePath: statePath,
      skillDir: join(process.cwd(), 'skills'),
      dashboardPort: 0,
      runtimeOwnership: {
        transport: 'http',
        dashboard_url: 'http://127.0.0.1:28384',
        mcp_url: 'http://127.0.0.1:23000/mcp',
      },
    })).toThrow(/already owned by Overwatch PID/);
    expect(first.engine.getPersistenceRecoveryStatus().highest_contiguous_applied_seq)
      .toBe(checkpointBefore);

    await shutdownOverwatchApp(first);
    apps.splice(apps.indexOf(first), 1);
    const replacement = createOverwatchApp({
      config: engagement,
      configPath,
      stateFilePath: statePath,
      skillDir: join(process.cwd(), 'skills'),
      dashboardPort: 0,
      runtimeOwnership: {
        transport: 'http',
        dashboard_url: 'http://127.0.0.1:28384',
        mcp_url: 'http://127.0.0.1:23000/mcp',
      },
    });
    apps.push(replacement);
  });

  it('reclaims a verified orphan group before createOverwatchApp returns', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-app-runtime-'));
    directories.push(directory);
    const statePath = join(directory, 'state.json');
    const engagement = config(`app-runtime-${Date.now()}`);
    const seed = new GraphEngine(engagement, statePath);
    seed.reserveRuntimeRun({
      run_id: 'runtime-orphan',
      kind: 'tracked_process',
      action_id: 'action-orphan',
      daemon_owner: 'daemon-prior',
      command_fingerprint: 'a'.repeat(64),
      evidence_state: 'pending',
    });
    const handle = spawnManagedRuntimeSupervisor(
      {
        binary: process.execPath,
        args: [
          '-e',
          'process.on("SIGTERM", () => {}); process.stdout.write("ready"); setInterval(() => {}, 1000)',
        ],
      },
      {
        onSupervisorReady: identity => {
          seed.acknowledgeRuntimeRunOwnership('runtime-orphan', identity);
        },
        onTargetLaunched: targetPid => {
          seed.markRuntimeRunLaunched('runtime-orphan', targetPid);
        },
      },
    );
    children.push(handle.child);
    let output = '';
    handle.child.stdout?.on('data', chunk => { output += chunk.toString('utf8'); });
    const identity = await handle.ready;
    await handle.launched;
    for (let attempt = 0; attempt < 20 && output !== 'ready'; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    expect(output).toBe('ready');
    expect(verifyRuntimeProcessIdentity(seed.getRuntimeRuns()[0])).toMatchObject({
      status: 'verified',
    });
    expect(observeProcessIdentity(identity.pid).ownership_token).toBe(identity.ownership_token);
    seed.flushNow();
    seed.dispose();

    const app = createOverwatchApp({
      config: engagement,
      stateFilePath: statePath,
      skillDir: join(process.cwd(), 'skills'),
      dashboardPort: 0,
    });
    apps.push(app);

    expect(app.engine.getRuntimeRuns()).toContainEqual(expect.objectContaining({
      run_id: 'runtime-orphan',
      lifecycle: 'interrupted',
      finalization_status: 'interrupted',
    }));
    expect(app.engine.getFullHistory().filter(event =>
      event.action_id === 'action-orphan'
      && (event.event_type === 'action_completed' || event.event_type === 'action_failed')))
      .toHaveLength(1);
    expect(processIsAlive(identity.pid)).toBe(false);
    await handle.targetExit;
  });

  it('never signals a mismatched physical process and surfaces the unresolved owner', () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-app-runtime-mismatch-'));
    directories.push(directory);
    const statePath = join(directory, 'state.json');
    const engagement = config(`app-runtime-mismatch-${Date.now()}`);
    const target = spawn(
      process.execPath,
      [
        '-e',
        'setInterval(() => {}, 1000)',
        '--',
        '--overwatch-runtime-token=11111111-1111-4111-8111-111111111111',
      ],
      {
        detached: true,
        stdio: 'ignore',
      },
    );
    children.push(target);
    expect(target.pid).toEqual(expect.any(Number));
    const observed = observeProcessIdentity(target.pid!);
    expect(observed.process_group_id).toBe(target.pid);
    expect(observed.process_start_identity).toEqual(expect.any(String));
    expect(observed.ownership_token).toBe('11111111-1111-4111-8111-111111111111');

    const seed = new GraphEngine(engagement, statePath);
    seed.setRuntimeRuns([{
      run_id: 'runtime-mismatch',
      kind: 'tracked_process',
      daemon_owner: 'daemon-prior',
      command_fingerprint: 'b'.repeat(64),
      ownership_mode: 'managed_supervisor',
      signal_scope: 'process_group',
      pid: target.pid,
      process_group_id: target.pid,
      process_start_identity: `${observed.process_start_identity}-different`,
      ownership_token: observed.ownership_token,
      started_at: '2026-07-16T00:00:00.000Z',
      ownership_acknowledged_at: '2026-07-16T00:00:00.001Z',
      launched_at: '2026-07-16T00:00:00.002Z',
      lifecycle: 'running',
    }]);
    seed.flushNow();
    seed.dispose();

    const app = createOverwatchApp({
      config: engagement,
      stateFilePath: statePath,
      skillDir: join(process.cwd(), 'skills'),
      dashboardPort: 0,
    });
    apps.push(app);

    expect(processIsAlive(target.pid!)).toBe(true);
    expect(app.engine.getRuntimeRuns()).toContainEqual(expect.objectContaining({
      run_id: 'runtime-mismatch',
      lifecycle: 'unknown',
      recovery_warning: expect.stringContaining('different physical process'),
    }));
    expect(app.engine.getPersistenceRecoveryStatus().runtime_ownership_warnings).toEqual([
      expect.objectContaining({
        run_id: 'runtime-mismatch',
        pid: target.pid,
        message: expect.stringContaining('different physical process'),
      }),
    ]);
  });

  it('reclaims deferred ownership before config reconciliation reopens the write gate', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-app-runtime-config-'));
    directories.push(directory);
    const statePath = join(directory, 'state.json');
    const configPath = join(directory, 'engagement.json');
    const engagement = withConfigMetadata(
      config(`app-runtime-config-${Date.now()}`),
      1,
    );
    writeFileSync(configPath, JSON.stringify(engagement));
    const seed = new GraphEngine(engagement, statePath, configPath);
    seed.reserveRuntimeRun({
      run_id: 'runtime-config-deferred',
      kind: 'tracked_process',
      daemon_owner: 'daemon-prior',
      command_fingerprint: 'c'.repeat(64),
    });
    const handle = spawnManagedRuntimeSupervisor(
      {
        binary: process.execPath,
        args: [
          '-e',
          'process.on("SIGTERM", () => {}); process.stdout.write("ready"); setInterval(() => {}, 1000)',
        ],
      },
      {
        onSupervisorReady: identity => {
          seed.acknowledgeRuntimeRunOwnership('runtime-config-deferred', identity);
        },
        onTargetLaunched: targetPid => {
          seed.markRuntimeRunLaunched('runtime-config-deferred', targetPid);
        },
      },
    );
    children.push(handle.child);
    let output = '';
    handle.child.stdout?.on('data', chunk => { output += chunk.toString('utf8'); });
    const identity = await handle.ready;
    await handle.launched;
    for (let attempt = 0; attempt < 20 && output !== 'ready'; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    expect(output).toBe('ready');
    seed.flushNow();
    seed.dispose();

    writeFileSync(configPath, JSON.stringify(withConfigMetadata({
      ...engagement,
      name: 'Unexplained external edit',
    }, 2)));
    const app = createOverwatchApp({
      configPath,
      stateFilePath: statePath,
      skillDir: join(process.cwd(), 'skills'),
      dashboardPort: 0,
    });
    apps.push(app);
    const blocked = app.engine.getPersistenceRecoveryStatus();

    expect(app.engine.isPersistenceWritable()).toBe(false);
    expect(processIsAlive(identity.pid)).toBe(true);
    expect(blocked.runtime_ownership_warnings).toEqual([
      expect.objectContaining({
        run_id: 'runtime-config-deferred',
        message: expect.stringContaining('deferred'),
      }),
    ]);
    expect(blocked.config_recovery).toMatchObject({
      resolution_required: true,
      file_hash: expect.any(String),
      state_hash: expect.any(String),
    });

    app.engine.resolveConfigDivergence({
      mode: 'use_state',
      expected_file_hash: blocked.config_recovery!.file_hash!,
      expected_state_hash: blocked.config_recovery!.state_hash!,
    });

    expect(app.engine.isPersistenceWritable()).toBe(true);
    expect(processIsAlive(identity.pid)).toBe(false);
    expect(app.engine.getRuntimeRuns()).toContainEqual(expect.objectContaining({
      run_id: 'runtime-config-deferred',
      lifecycle: 'interrupted',
    }));
    await handle.targetExit;
  });
});
