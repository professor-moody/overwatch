import { describe, it, expect, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { createOverwatchApp, registerAllTools, shutdownOverwatchApp, ToolRegistrar, type OverwatchApp } from '../app.js';
import { InProcessTapeController } from '../services/in-process-tape.js';
import { EngagementManager } from '../services/engagement-manager.js';
import { GraphEngine } from '../services/graph-engine.js';
import { MutationJournal } from '../services/mutation-journal.js';
import { CURRENT_JOURNAL_VERSION, CURRENT_STATE_VERSION } from '../services/persisted-state.js';
import type { EngagementConfig, SessionMetadata } from '../types.js';
import { registerEngagementTools } from '../tools/engagement.js';
import { withErrorBoundary } from '../tools/error-boundary.js';
import { verifyStateMigrationBackup } from '../services/state-migration.js';
import { getApplicationCommandInvocation } from '../services/application-command-service.js';
import {
  buildToolRegistryManifest,
  canonicalJson,
} from '../services/tool-descriptor-registry.js';

const completeAnnotations = (readOnlyHint: boolean) => ({
  readOnlyHint,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
});

function recoveryConfig(): EngagementConfig {
  return {
    id: 'app-bootstrap-recovery',
    name: 'App bootstrap recovery',
    created_at: '2026-07-15T00:00:00.000Z',
    scope: { cidrs: ['10.30.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

const incompleteBootstrapArtifactCases: Array<[
  string,
  (directory: string) => Array<[string, Buffer]>,
]> = [
  ['a quarantined WAL tail', directory => {
    const path = join(directory, 'state-recovery.journal.jsonl.quarantine-2026-07-17');
    const bytes = Buffer.from('preserve quarantined WAL bytes\n');
    writeFileSync(path, bytes);
    return [[path, bytes]];
  }],
  ['a state writer lock', directory => {
    const path = join(directory, 'state-recovery.json.writer-lock');
    const bytes = Buffer.from('{"owner":"interrupted"}\n');
    writeFileSync(path, bytes);
    return [[path, bytes]];
  }],
  ['a state temporary file', directory => {
    const path = join(directory, 'state-recovery.json.tmp-crash');
    const bytes = Buffer.from('{"partial":"state"}\n');
    writeFileSync(path, bytes);
    return [[path, bytes]];
  }],
  ['a config write intent', directory => {
    const path = join(directory, 'engagement.json.write-intent.json');
    const bytes = Buffer.from('{"phase":"prepared"}\n');
    writeFileSync(path, bytes);
    return [[path, bytes]];
  }],
  ['an atomic config temporary file', directory => {
    const path = join(directory, 'engagement.json.tmp-123-complete');
    const bytes = Buffer.from('{"complete":"unpublished config"}\n');
    writeFileSync(path, bytes);
    return [[path, bytes]];
  }],
  ['an atomic config-intent temporary file', directory => {
    const path = join(directory, 'engagement.json.write-intent.json.tmp-123-complete');
    const bytes = Buffer.from('{"complete":"unpublished intent"}\n');
    writeFileSync(path, bytes);
    return [[path, bytes]];
  }],
  ['a migration backup', directory => {
    const path = join(directory, '.migration-backups', 'backup-1', 'manifest.json');
    const bytes = Buffer.from('{"backup":"preserve"}\n');
    mkdirSync(join(directory, '.migration-backups', 'backup-1'), { recursive: true });
    writeFileSync(path, bytes);
    return [[path, bytes]];
  }],
  ['retained evidence', directory => {
    const path = join(directory, 'evidence', 'manifest.json');
    const bytes = Buffer.from('{"evidence":"preserve"}\n');
    mkdirSync(join(directory, 'evidence'), { recursive: true });
    writeFileSync(path, bytes);
    return [[path, bytes]];
  }],
];

describe('app bootstrap', () => {
  it('binds MCP session credentials to canonical task actors without trusting body aliases', async () => {
    const handlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();
    const terminalHandlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();
    const fakeServer = {
      registerTool(name: string, _config: unknown, callback: (...args: unknown[]) => Promise<unknown>) {
        handlers.set(name, callback);
        return { enable() {}, disable() {}, enabled: true };
      },
    };
    const recovery = {
      outcome: 'clean' as const,
      source: 'state' as const,
      complete: true,
      writable: true,
      base_checkpoint: 0,
      highest_allocated_seq: 0,
      highest_on_disk_seq: 0,
      highest_contiguous_applied_seq: 0,
      consecutive_persistence_failures: 0,
      journal: {
        enabled: true,
        read: 0,
        attempted: 0,
        applied: 0,
        skipped: 0,
        failed: 0,
        malformed: false,
        preserved: false,
      },
    };
    const registrar = new ToolRegistrar(fakeServer as never, {
      isPersistenceWritable: () => true,
      getPersistenceRecoveryStatus: () => recovery,
    }, 'task-dashboard-agent');
    const registerInvocationProbe = (
      target: ToolRegistrar,
    ) => target.registerTool('get_history', {
      description: 'returns command invocation ownership',
      annotations: completeAnnotations(true),
    }, async () => ({
      content: [{
        type: 'text' as const,
        text: JSON.stringify(getApplicationCommandInvocation()),
      }],
    }));
    registerInvocationProbe(registrar);

    const terminalServer = {
      registerTool(name: string, _config: unknown, callback: (...args: unknown[]) => Promise<unknown>) {
        terminalHandlers.set(name, callback);
        return { enable() {}, disable() {}, enabled: true };
      },
    };
    const terminalRegistrar = new ToolRegistrar(terminalServer as never, {
      isPersistenceWritable: () => true,
      getPersistenceRecoveryStatus: () => recovery,
    }, null);
    registerInvocationProbe(terminalRegistrar);

    const dashboardAgent = await handlers.get('get_history')!(
      { agent_id: 'dashboard-agent' },
      { requestId: 1, sessionId: 'dashboard-agent-session' },
    ) as { content: Array<{ text: string }> };
    const terminalPrimary = await terminalHandlers.get('get_history')!(
      { task_id: 'task-dashboard-agent', agent_id: 'dashboard-agent' },
      { requestId: 1, sessionId: 'terminal-primary-session' },
    ) as { content: Array<{ text: string }> };

    expect(JSON.parse(dashboardAgent.content[0].text)).toMatchObject({
      actor_task_id: 'task-dashboard-agent',
      session_id: 'dashboard-agent-session',
    });
    expect(JSON.parse(terminalPrimary.content[0].text)).toMatchObject({
      actor_task_id: null,
      session_id: 'terminal-primary-session',
    });

    const bareRetryA = await terminalHandlers.get('get_history')!(
      {},
      { requestId: 7 },
    ) as { content: Array<{ text: string }> };
    const bareRetryB = await terminalHandlers.get('get_history')!(
      {},
      { requestId: 7 },
    ) as { content: Array<{ text: string }> };
    const bareContextA = JSON.parse(bareRetryA.content[0].text);
    const bareContextB = JSON.parse(bareRetryB.content[0].text);
    expect(bareContextA.session_id).toMatch(/^mcp-runtime-/);
    expect(bareContextB.session_id).toBe(bareContextA.session_id);
  });

  it('starts read-only from durable state when the active config is missing, then permits use_state recovery', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-recovery-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'state-app-bootstrap-recovery.json');
    const config = recoveryConfig();
    writeFileSync(configPath, JSON.stringify(config));
    const seed = new GraphEngine(config, stateFilePath, configPath);
    seed.flushNow();
    seed.dispose();
    unlinkSync(configPath);

    let app: OverwatchApp | undefined;
    try {
      app = createOverwatchApp({
        configPath,
        stateFilePath,
        skillDir: resolve('./skills'),
        // Construct the dashboard-owned EngagementManager too; degraded
        // startup must keep that secondary surface read-only.
        dashboardPort: 8384,
      });
      const recovery = app.engine.getConfigRecoveryStatus();
      expect(recovery).toMatchObject({
        status: 'diverged',
        resolution_required: true,
        file_valid: false,
        allowed_resolutions: ['use_state'],
      });
      expect(recovery.file_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(app.engine.isPersistenceWritable()).toBe(false);
      expect(() => app!.engine.getState()).not.toThrow();
      expect(() => (app!.dashboard as any).buildFrontendState()).not.toThrow();

      app.engine.resolveConfigDivergence({
        mode: 'use_state',
        expected_file_hash: recovery.file_hash!,
        expected_state_hash: recovery.state_hash!,
      });
      expect(existsSync(configPath)).toBe(true);
      expect(app.engine.isPersistenceWritable()).toBe(true);
      const resumedRuntime = await app.sessionManager.create({
        kind: 'socket',
        title: 'post-reconciliation listener',
        mode: 'listen',
        accept_mode: 'rearm',
        bind_host: '127.0.0.1',
        port: 0,
        initial_wait_ms: 0,
      });
      expect(resumedRuntime.metadata).toMatchObject({
        state: 'pending',
        port: expect.any(Number),
      });
      app.sessionManager.close(resumedRuntime.metadata.id, undefined, true);
    } finally {
      if (app) await shutdownOverwatchApp(app);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('materializes a bootstrap config before enabling managed ownership', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-bootstrap-'));
    const configPath = join(dir, 'engagement.json');
    const previous = process.env.OVERWATCH_BOOTSTRAP;
    process.env.OVERWATCH_BOOTSTRAP = '1';
    let app: OverwatchApp | undefined;
    try {
      app = createOverwatchApp({
        configPath,
        skillDir: resolve('./skills'),
        dashboardPort: 0,
      });
      expect(existsSync(configPath)).toBe(true);
      expect(app.engine.getConfigRecoveryStatus()).toMatchObject({
        status: 'in_sync',
        resolution_required: false,
      });
      expect(app.engine.isPersistenceWritable()).toBe(true);
    } finally {
      if (app) await shutdownOverwatchApp(app);
      if (previous === undefined) delete process.env.OVERWATCH_BOOTSTRAP;
      else process.env.OVERWATCH_BOOTSTRAP = previous;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.each(incompleteBootstrapArtifactCases)(
    'refuses empty-engagement bootstrap when the config is missing beside %s',
    (_label, arrange) => {
      const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-artifact-gate-'));
      const configPath = join(dir, 'engagement.json');
      const retained = arrange(dir);
      const previous = process.env.OVERWATCH_BOOTSTRAP;
      process.env.OVERWATCH_BOOTSTRAP = '1';
      try {
        expect(() => createOverwatchApp({
          configPath,
          skillDir: resolve('./skills'),
          dashboardPort: 0,
        })).toThrow(/durable state\/WAL\/snapshot artifacts could not be validated/i);
        expect(existsSync(configPath)).toBe(false);
        for (const [path, bytes] of retained) expect(readFileSync(path)).toEqual(bytes);
      } finally {
        if (previous === undefined) delete process.env.OVERWATCH_BOOTSTRAP;
        else process.env.OVERWATCH_BOOTSTRAP = previous;
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it('refuses explicit-state bootstrap when only its quarantined WAL remains', () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-explicit-artifact-gate-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'custom-state.json');
    const quarantinePath = join(dir, 'custom-state.journal.jsonl.quarantine-restart');
    const bytes = Buffer.from('preserve explicit WAL quarantine\n');
    writeFileSync(quarantinePath, bytes);
    const previous = process.env.OVERWATCH_BOOTSTRAP;
    process.env.OVERWATCH_BOOTSTRAP = '1';
    try {
      expect(() => createOverwatchApp({
        configPath,
        stateFilePath,
        skillDir: resolve('./skills'),
        dashboardPort: 0,
      })).toThrow(/durable state\/WAL\/snapshot artifacts could not be validated/i);
      expect(existsSync(configPath)).toBe(false);
      expect(readFileSync(quarantinePath)).toEqual(bytes);
    } finally {
      if (previous === undefined) delete process.env.OVERWATCH_BOOTSTRAP;
      else process.env.OVERWATCH_BOOTSTRAP = previous;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('unions explicit-state and config-side recovery artifacts before bootstrap', () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-explicit-config-artifact-'));
    const configPath = join(dir, 'engagement.json');
    const explicitState = join(dir, 'missing-explicit.json');
    const intentPath = `${configPath}.write-intent.json`;
    const intentBytes = Buffer.from('{"phase":"prepared"}\n');
    writeFileSync(intentPath, intentBytes);
    const previous = process.env.OVERWATCH_BOOTSTRAP;
    process.env.OVERWATCH_BOOTSTRAP = '1';
    try {
      expect(() => createOverwatchApp({
        configPath,
        stateFilePath: explicitState,
        skillDir: resolve('./skills'),
        dashboardPort: 0,
      })).toThrow(/durable state\/WAL\/snapshot artifacts could not be validated/i);
      expect(existsSync(configPath)).toBe(false);
      expect(readFileSync(intentPath)).toEqual(intentBytes);
    } finally {
      if (previous === undefined) delete process.env.OVERWATCH_BOOTSTRAP;
      else process.env.OVERWATCH_BOOTSTRAP = previous;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.each(['legacy', 'future'] as const)(
    'does not publish a bootstrap config ahead of an explicit %s durable state',
    async format => {
      const dir = mkdtempSync(join(tmpdir(), `overwatch-app-bootstrap-${format}-`));
      const configPath = join(dir, 'engagement.json');
      const stateFilePath = join(dir, 'state-app-bootstrap-recovery.json');
      const config = recoveryConfig();
      writeFileSync(configPath, JSON.stringify(config));
      const seed = new GraphEngine(config, stateFilePath, configPath);
      seed.persistImmediate();
      seed.dispose();

      const state = JSON.parse(readFileSync(stateFilePath, 'utf8')) as Record<string, any>;
      if (format === 'legacy') {
        delete state.state_version;
        delete state.journal_version;
        delete state.walCompactionAuthority;
        delete state.config.config_revision;
        delete state.config.config_hash;
        // This fixture models a complete snapshot-only V0 base. Retaining
        // journal-v2 transactions at/below a checkpoint after deleting its
        // contiguous-checkpoint semantics is intentionally ambiguous and must
        // remain degraded rather than being treated as a migratable V0 state.
        rmSync(MutationJournal.pathForState(stateFilePath), { force: true });
      } else {
        state.state_version = 2;
      }
      writeFileSync(stateFilePath, JSON.stringify(state));
      unlinkSync(configPath);
      const stateBefore = readFileSync(stateFilePath);
      const previous = process.env.OVERWATCH_BOOTSTRAP;
      process.env.OVERWATCH_BOOTSTRAP = '1';
      let app: OverwatchApp | undefined;
      try {
        app = createOverwatchApp({
          configPath,
          stateFilePath,
          skillDir: resolve('./skills'),
          dashboardPort: 0,
        });
        expect(existsSync(configPath)).toBe(false);
        if (format === 'future') {
          expect(app.engine.isPersistenceWritable()).toBe(false);
          expect(readFileSync(stateFilePath)).toEqual(stateBefore);
        } else {
          const recovery = app.engine.getPersistenceRecoveryStatus();
          expect(JSON.parse(readFileSync(stateFilePath, 'utf8'))).toMatchObject({
            state_version: CURRENT_STATE_VERSION,
            journal_version: CURRENT_JOURNAL_VERSION,
          });
          const backup = verifyStateMigrationBackup(
            join(recovery.state_migration!.backup_path!, 'manifest.json'),
          );
          expect(backup.manifest.files).toContainEqual({
            role: 'config',
            original_path: configPath,
            present: false,
          });
        }
      } finally {
        if (app) await shutdownOverwatchApp(app);
        if (previous === undefined) delete process.env.OVERWATCH_BOOTSTRAP;
        else process.env.OVERWATCH_BOOTSTRAP = previous;
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it('does not let an out-of-band config id change select a fresh state path', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-id-divergence-'));
    const configPath = join(dir, 'engagement.json');
    const original = recoveryConfig();
    const originalStatePath = join(dir, `state-${original.id}.json`);
    writeFileSync(configPath, JSON.stringify(original));
    const seed = new GraphEngine(original, originalStatePath, configPath);
    seed.flushNow();
    seed.dispose();
    const changed = { ...original, id: 'out-of-band-id' };
    writeFileSync(configPath, JSON.stringify(changed));

    let app: OverwatchApp | undefined;
    try {
      app = createOverwatchApp({ configPath, skillDir: resolve('./skills'), dashboardPort: 0 });
      expect(app.engine.getStateFilePath()).toBe(originalStatePath);
      expect(app.engine.getConfig().id).toBe(original.id);
      expect(app.engine.getConfigRecoveryStatus()).toMatchObject({
        status: 'diverged',
        resolution_required: true,
      });
      expect(existsSync(join(dir, 'state-out-of-band-id.json'))).toBe(false);
    } finally {
      if (app) await shutdownOverwatchApp(app);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses a fresh state path when the active config matches no durable family', () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-unmatched-config-'));
    const configPath = join(dir, 'engagement.json');
    const original = recoveryConfig();
    const originalStatePath = join(dir, `state-${original.id}.json`);
    writeFileSync(configPath, JSON.stringify(original));
    const seed = new GraphEngine(original, originalStatePath, configPath);
    seed.flushNow();
    seed.dispose();
    const stale = {
      ...original,
      id: 'unrelated-config',
      created_at: '2026-07-17T12:00:00.000Z',
      engagement_nonce: 'b'.repeat(64),
    };
    writeFileSync(configPath, JSON.stringify(stale));

    try {
      expect(() => createOverwatchApp({
        configPath,
        skillDir: resolve('./skills'),
        dashboardPort: 0,
      })).toThrow(/active config does not match the durable state families/i);
      expect(existsSync(join(dir, 'state-unrelated-config.json'))).toBe(false);
      expect(existsSync(originalStatePath)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('does not repair evidence artifacts before config divergence is reconciled', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-evidence-divergence-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'state-app-bootstrap-recovery.json');
    const config = recoveryConfig();
    writeFileSync(configPath, JSON.stringify(config));
    const seed = new GraphEngine(config, stateFilePath, configPath);
    seed.persistImmediate();
    seed.dispose();

    const external = { ...config, name: 'External config edit' };
    writeFileSync(configPath, JSON.stringify(external));
    const evidenceDir = join(dir, 'evidence');
    mkdirSync(evidenceDir, { recursive: true });
    const manifestPath = join(evidenceDir, 'manifest.json');
    const corruptBytes = Buffer.from('{ corrupt evidence manifest');
    writeFileSync(manifestPath, corruptBytes);
    const directoryBefore = readdirSync(evidenceDir).sort();

    let app: OverwatchApp | undefined;
    try {
      app = createOverwatchApp({
        configPath,
        stateFilePath,
        skillDir: resolve('./skills'),
        dashboardPort: 0,
      });
      expect(app.engine.getConfigRecoveryStatus()).toMatchObject({
        status: 'diverged',
        resolution_required: true,
      });
      expect(app.engine.isPersistenceWritable()).toBe(false);
      expect(() => app!.engine.getEvidenceStore().store({
        evidence_type: 'log',
        content: 'must not land',
      })).toThrow(/read-only/i);
      expect(readFileSync(manifestPath)).toEqual(corruptBytes);
      expect(readdirSync(evidenceDir).sort()).toEqual(directoryBefore);
    } finally {
      if (app) await shutdownOverwatchApp(app);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('applies use_file config changes without replacing durable engagement state', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-use-file-state-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'state-app-use-file-state.json');
    const original = recoveryConfig();
    writeFileSync(configPath, JSON.stringify(original));
    const seed = new GraphEngine(original, stateFilePath, configPath);
    const seededAt = new Date().toISOString();
    seed.ingestFinding({
      id: 'finding-before-config-edit',
      agent_id: 'preserved-agent',
      timestamp: seededAt,
      nodes: [{
        id: 'host-10-30-0-10',
        type: 'host',
        label: 'Preserved host',
        ip: '10.30.0.10',
        discovered_at: seededAt,
        confidence: 1,
      }],
      edges: [],
      raw_output: 'preserved finding output',
    });
    (seed as unknown as {
      ctx: {
        coldStore: {
          add: (node: {
            id: string;
            type: 'host';
            label: string;
            ip: string;
            discovered_at: string;
            last_seen_at: string;
          }) => void;
        };
      };
    }).ctx.coldStore.add({
      id: 'cold-before-config-edit',
      type: 'host',
      label: 'Preserved cold host',
      ip: '192.0.2.44',
      discovered_at: seededAt,
      last_seen_at: seededAt,
    });
    seed.registerAgent({
      id: 'completed-task-before-config-edit',
      agent_id: 'preserved-agent',
      assigned_at: seededAt,
      completed_at: seededAt,
      status: 'completed',
      subgraph_node_ids: ['host-10-30-0-10'],
    });
    const campaign = seed.createCampaign({
      name: 'Preserved campaign',
      strategy: 'enumeration',
      item_ids: ['frontier-before-config-edit'],
    });
    seed.setRuntimeRuns([{
      run_id: 'runtime-before-config-edit',
      kind: 'tracked_process',
      daemon_owner: 'preserved-daemon',
      command_fingerprint: 'a'.repeat(64),
      started_at: seededAt,
      completed_at: seededAt,
      lifecycle: 'completed',
      finalization_status: 'completed',
    }]);
    seed.recordSessionDescriptor({
      id: 'listener-before-config-edit',
      kind: 'socket',
      transport: 'tcp-listen',
      state: 'resume_available',
      mode: 'listen',
      accept_mode: 'rearm',
      bind_host: '127.0.0.1',
      port: 0,
      title: 'Preserved listener',
      started_at: seededAt,
      last_activity_at: seededAt,
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'dumb',
      },
      buffer_end_pos: 0,
      resume_policy: 'manual',
    });
    const planId = seed.createCommandPlan({
      command: 'preserve this coordination outcome',
      ops: [],
      now: Date.now(),
      ttlMs: 10 * 60_000,
    });
    seed.recordCommandOutcome(planId, [{ preserved: true }], Date.now(), 10 * 60_000);
    const evidenceId = seed.getEvidenceStore().store({
      evidence_type: 'command_output',
      finding_id: 'finding-before-config-edit',
      agent_id: 'preserved-agent',
      content: 'preserved evidence content',
    });
    seed.persistImmediate();
    seed.dispose();

    writeFileSync(configPath, JSON.stringify({
      ...original,
      name: 'Operator edited config',
      scope: {
        ...original.scope,
        domains: [...original.scope.domains, 'new-scope.example'],
      },
    }));

    let app: OverwatchApp | undefined;
    try {
      app = createOverwatchApp({
        configPath,
        stateFilePath,
        skillDir: resolve('./skills'),
        dashboardPort: 8384,
      });
      const recovery = app.engine.getConfigRecoveryStatus();
      expect(recovery).toMatchObject({
        status: 'diverged',
        resolution_required: true,
      });
      expect(app.engine.getNode('host-10-30-0-10')).toBeDefined();
      expect(app.engine.getState({ activityCount: 100 })).toMatchObject({
        graph_summary: {
          cold_node_count: 1,
        },
        agents: expect.arrayContaining([
          expect.objectContaining({
            id: 'completed-task-before-config-edit',
            agent_id: 'preserved-agent',
            status: 'completed',
          }),
        ]),
      });
      expect(app.engine.getCampaign(campaign.id)).toMatchObject({
        name: 'Preserved campaign',
      });
      expect(app.engine.getRuntimeRuns()).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            run_id: 'runtime-before-config-edit',
            lifecycle: 'completed',
          }),
        ]),
      );
      expect(app.sessionManager.getSession('listener-before-config-edit')).toMatchObject({
        state: 'resume_available',
        resume_policy: 'manual',
      });
      expect(app.engine.getCommandOutcome(planId)).toMatchObject({
        results: [{ preserved: true }],
      });
      expect(app.engine.getEvidenceStore().getContent(evidenceId)).toBe('preserved evidence content');

      const journalPath = MutationJournal.pathForState(stateFilePath);
      const stateBeforeRead = readFileSync(stateFilePath);
      const configBeforeRead = readFileSync(configPath);
      const journalBeforeRead = existsSync(journalPath) ? readFileSync(journalPath) : undefined;
      expect(() => app!.engine.getState()).not.toThrow();
      expect(() => (app!.dashboard as any).buildFrontendState()).not.toThrow();
      expect(readFileSync(stateFilePath)).toEqual(stateBeforeRead);
      expect(readFileSync(configPath)).toEqual(configBeforeRead);
      expect(existsSync(journalPath) ? readFileSync(journalPath) : undefined).toEqual(journalBeforeRead);

      app.engine.resolveConfigDivergence({
        mode: 'use_file',
        expected_file_hash: recovery.file_hash!,
        expected_state_hash: recovery.state_hash!,
      });

      expect(app.engine.getConfig()).toMatchObject({
        name: 'Operator edited config',
        scope: expect.objectContaining({
          domains: expect.arrayContaining(['new-scope.example']),
        }),
      });
      expect(app.engine.getNode('host-10-30-0-10')).toMatchObject({
        label: 'Preserved host',
      });
      expect(app.engine.getState({ activityCount: 100 })).toMatchObject({
        agents: expect.arrayContaining([
          expect.objectContaining({
            id: 'completed-task-before-config-edit',
            agent_id: 'preserved-agent',
            status: 'completed',
          }),
        ]),
        recent_activity: expect.arrayContaining([
          expect.objectContaining({
            linked_finding_ids: expect.arrayContaining(['finding-before-config-edit']),
          }),
        ]),
        graph_summary: {
          cold_node_count: 1,
        },
      });
      expect(app.engine.getCampaign(campaign.id)).toMatchObject({
        name: 'Preserved campaign',
      });
      expect(app.engine.getRuntimeRuns()).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            run_id: 'runtime-before-config-edit',
            lifecycle: 'completed',
          }),
        ]),
      );
      expect(app.engine.getCommandOutcome(planId)).toMatchObject({
        results: [{ preserved: true }],
      });
      expect(app.engine.getEvidenceStore().getContent(evidenceId)).toBe('preserved evidence content');
      expect(app.engine.isPersistenceWritable()).toBe(true);

      const resumed = await app.sessionManager.resume('listener-before-config-edit', undefined, true);
      expect(resumed.metadata).toMatchObject({
        id: 'listener-before-config-edit',
        state: 'pending',
        port: expect.any(Number),
      });
      app.sessionManager.close('listener-before-config-edit', undefined, true);

      await shutdownOverwatchApp(app);
      app = createOverwatchApp({
        configPath,
        stateFilePath,
        skillDir: resolve('./skills'),
        dashboardPort: 0,
      });
      expect(app.engine.getConfig()).toMatchObject({
        name: 'Operator edited config',
      });
      expect(app.engine.getNode('host-10-30-0-10')).toMatchObject({
        label: 'Preserved host',
      });
      expect(app.engine.getState({ activityCount: 100 })).toMatchObject({
        graph_summary: {
          cold_node_count: 1,
        },
        agents: expect.arrayContaining([
          expect.objectContaining({
            id: 'completed-task-before-config-edit',
            status: 'completed',
          }),
        ]),
      });
      expect(app.engine.getCampaign(campaign.id)).toMatchObject({
        name: 'Preserved campaign',
      });
      expect(app.engine.getRuntimeRuns()).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            run_id: 'runtime-before-config-edit',
            lifecycle: 'completed',
          }),
        ]),
      );
      expect(app.engine.getCommandOutcome(planId)).toMatchObject({
        results: [{ preserved: true }],
      });
      expect(app.engine.getEvidenceStore().getContent(evidenceId)).toBe('preserved evidence content');
    } finally {
      if (app) await shutdownOverwatchApp(app);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reconciles process ownership after rolling back to a snapshot with older config', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-rollback-runtime-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'state-app-bootstrap-recovery.json');
    const config = recoveryConfig();
    writeFileSync(configPath, JSON.stringify(config));
    let app: OverwatchApp | undefined;
    try {
      app = createOverwatchApp({
        configPath,
        stateFilePath,
        skillDir: resolve('./skills'),
        dashboardPort: 0,
      });
      const internals = (app.engine as unknown as {
        ctx: { lastSnapshotTime: number };
      }).ctx;
      internals.lastSnapshotTime = Date.now();
      app.processTracker.restore([{
        id: 'process-before',
        pid: 424241,
        command: 'before',
        description: 'before rollback',
        started_at: '2026-07-16T00:00:00.000Z',
        status: 'unknown',
      }]);
      const sessionAt = '2026-07-16T00:00:30.000Z';
      app.engine.addNode({
        id: 'rollback-principal',
        type: 'user',
        label: 'Rollback principal',
        discovered_at: sessionAt,
        confidence: 1,
      });
      app.engine.addNode({
        id: 'rollback-target',
        type: 'host',
        label: 'Rollback target',
        ip: '10.30.0.20',
        discovered_at: sessionAt,
        confidence: 1,
      });
      const connectedSession: SessionMetadata = {
        id: 'rollback-session',
        kind: 'local_pty',
        adapter: 'local_pty',
        transport: 'pty',
        state: 'connected',
        connection_generation: 1,
        connection_id: 'rollback-session:g1',
        connection_started_at: sessionAt,
        title: 'Rollback shell',
        target_node: 'rollback-target',
        principal_node: 'rollback-principal',
        started_at: sessionAt,
        last_activity_at: sessionAt,
        capabilities: {
          has_stdin: true,
          has_stdout: true,
          supports_resize: true,
          supports_signals: true,
          tty_quality: 'full',
        },
        buffer_end_pos: 0,
        resume_policy: 'none',
      };
      app.engine.connectSessionGenerationDurably(
        connectedSession,
        'Rollback fixture connected',
      );
      app.engine.flushNow();

      internals.lastSnapshotTime = 0;
      app.engine.persistImmediate();
      const snapshot = app.engine.listSnapshots().at(-1);
      expect(snapshot).toBeDefined();

      app.processTracker.restore([{
        id: 'process-after',
        pid: 424242,
        command: 'after',
        description: 'after snapshot',
        started_at: '2026-07-16T00:01:00.000Z',
        status: 'unknown',
      }]);
      app.engine.closeSessionDurably({
        ...connectedSession,
        state: 'closed',
        connection_id: undefined,
        connection_started_at: undefined,
        last_connection_id: connectedSession.connection_id,
        last_connection_state: 'closed',
        last_connection_closed_at: '2026-07-16T00:01:30.000Z',
        closed_at: '2026-07-16T00:01:30.000Z',
      }, 'Rollback fixture closed after snapshot', {
        connection_id: connectedSession.connection_id,
      });
      app.engine.flushNow();
      app.engine.updateConfig({ name: 'Config after snapshot' });

      expect(app.engine.rollbackToSnapshot(snapshot!)).toBe(true);
      expect(app.engine.isPersistenceWritable()).toBe(true);
      expect(app.engine.getConfig().name).toBe(config.name);
      expect(app.processTracker.serialize()).toEqual([
        expect.objectContaining({ id: 'process-before' }),
      ]);
      expect(app.engine.getSessionDescriptors()).toContainEqual(
        expect.objectContaining({
          session_id: 'rollback-session',
          lifecycle: 'error',
          recovery_lifecycle: 'interrupted',
          connection_id: undefined,
          last_connection_id: 'rollback-session:g1',
          last_connection_state: 'interrupted',
        }),
      );
      expect(app.sessionManager.getSession('rollback-session')).toMatchObject({
        state: 'interrupted',
        connection_id: undefined,
      });
      const rolledBackSessionEdge = app.engine.exportGraph().edges.find(edge =>
        edge.properties.type === 'HAS_SESSION'
        && edge.properties.session_id === 'rollback-session:g1');
      expect(rolledBackSessionEdge?.properties).toMatchObject({
        session_live: false,
        live_session_ids: [],
        live_session_refs: [],
      });
      expect(existsSync(`${stateFilePath}.rollback-intent.json`)).toBe(false);
    } finally {
      if (app) await shutdownOverwatchApp(app);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('does not substitute or hide a sole neighboring state for a valid unrelated config', () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-neighbor-state-'));
    const configPath = join(dir, 'engagement.json');
    const active = recoveryConfig();
    const unrelated = {
      ...recoveryConfig(),
      id: 'unrelated-engagement',
      name: 'Unrelated engagement',
      created_at: '2026-07-14T00:00:00.000Z',
    };
    const unrelatedStatePath = join(dir, `state-${unrelated.id}.json`);
    writeFileSync(configPath, JSON.stringify(active));
    const seed = new GraphEngine(unrelated, unrelatedStatePath);
    seed.persistImmediate();
    seed.dispose();

    try {
      expect(() => createOverwatchApp({
        configPath,
        skillDir: resolve('./skills'),
        dashboardPort: 0,
      })).toThrow(/active config does not match the durable state families/i);
      expect(existsSync(join(dir, `state-${active.id}.json`))).toBe(false);
      expect(existsSync(unrelatedStatePath)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('selects a state family when a newer retained snapshot matches the active config', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-newer-snapshot-family-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'state-family.json');
    const active = recoveryConfig();
    const stale = {
      ...active,
      id: 'stale-primary',
      name: 'Stale primary',
      created_at: '2026-07-14T00:00:00.000Z',
    };
    writeFileSync(configPath, JSON.stringify(active));
    const staleSeed = new GraphEngine(stale, stateFilePath);
    staleSeed.persistImmediate();
    staleSeed.dispose();

    const candidateDir = join(dir, 'candidate');
    mkdirSync(candidateDir);
    const candidatePath = join(candidateDir, 'state-candidate.json');
    const currentSeed = new GraphEngine(active, candidatePath);
    currentSeed.addNode({
      id: 'snapshot-proof',
      type: 'host',
      label: 'Snapshot proof',
      ip: '10.30.0.40',
      discovered_at: '2026-07-17T00:00:00.000Z',
      confidence: 1,
    });
    currentSeed.persistImmediate();
    currentSeed.dispose();
    const snapshots = join(dir, '.snapshots');
    mkdirSync(snapshots, { recursive: true });
    writeFileSync(
      join(snapshots, 'state-family.snap-2026-07-17T00-00-00-000Z.json'),
      readFileSync(candidatePath),
    );
    rmSync(candidateDir, { recursive: true, force: true });
    const familyJournal = MutationJournal.pathForState(stateFilePath);
    if (existsSync(familyJournal)) unlinkSync(familyJournal);

    let app: OverwatchApp | undefined;
    try {
      app = createOverwatchApp({
        configPath,
        skillDir: resolve('./skills'),
        dashboardPort: 0,
      });
      expect(app.engine.getPersistenceRecoveryStatus()).toMatchObject({
        source: 'snapshot',
        writable: true,
      });
      expect(app.engine.exportGraph().nodes.some(node => node.id === 'snapshot-proof')).toBe(true);
    } finally {
      if (app) await shutdownOverwatchApp(app);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('never substitutes a neighboring state when an explicit recovery state is invalid', () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-explicit-state-'));
    const configPath = join(dir, 'engagement.json');
    const explicitState = join(dir, 'state-explicit.json');
    const unrelatedState = join(dir, 'state-unrelated.json');
    writeFileSync(configPath, '{ malformed');
    writeFileSync(explicitState, '{ corrupt');
    writeFileSync(unrelatedState, JSON.stringify({ config: recoveryConfig() }));
    try {
      expect(() => createOverwatchApp({
        configPath,
        stateFilePath: explicitState,
        skillDir: resolve('./skills'),
        dashboardPort: 0,
      })).toThrow(/explicit durable state.*no valid recovery base/i);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('boots recovery interfaces from a retained snapshot when config and primary state are unusable', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-snapshot-bootstrap-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'state-app-bootstrap-recovery.json');
    const config = recoveryConfig();
    writeFileSync(configPath, JSON.stringify(config));
    const seed = new GraphEngine(config, stateFilePath, configPath);
    seed.flushNow();
    seed.dispose();
    const snapshots = join(dir, '.snapshots');
    mkdirSync(snapshots, { recursive: true });
    writeFileSync(
      join(snapshots, 'state-app-bootstrap-recovery.snap-2026-07-15T00-00-00-000Z.json'),
      readFileSync(stateFilePath),
    );
    writeFileSync(stateFilePath, '{ corrupt primary');
    unlinkSync(configPath);

    let app: OverwatchApp | undefined;
    try {
      app = createOverwatchApp({
        configPath,
        stateFilePath,
        skillDir: resolve('./skills'),
        dashboardPort: 8384,
      });
      expect(app.engine.getPersistenceRecoveryStatus()).toMatchObject({
        source: 'snapshot',
        writable: false,
        config_recovery: { status: 'diverged', file_valid: false },
      });
    } finally {
      if (app) await shutdownOverwatchApp(app);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('opens a future state read-only without repairing config or evidence artifacts', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-future-state-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'state-app-bootstrap-recovery.json');
    const config = recoveryConfig();
    writeFileSync(configPath, JSON.stringify(config));
    const seed = new GraphEngine(config, stateFilePath, configPath);
    seed.persistImmediate();
    seed.dispose();

    const future = JSON.parse(readFileSync(stateFilePath, 'utf8')) as Record<string, unknown>;
    future.state_version = 2;
    const futureBytes = Buffer.from(JSON.stringify(future));
    writeFileSync(stateFilePath, futureBytes);
    const configBytes = readFileSync(configPath);
    const casArtifact = `${configPath}.overwatch-cas-999-deadbeef.previous`;
    writeFileSync(casArtifact, configBytes);
    const intentPath = `${configPath}.write-intent.json`;
    writeFileSync(intentPath, '{ malformed intent');
    const evidenceDir = join(dir, 'evidence');
    mkdirSync(evidenceDir, { recursive: true });
    const evidenceManifest = join(evidenceDir, 'manifest.json');
    const evidenceBytes = Buffer.from('{ malformed evidence');
    writeFileSync(evidenceManifest, evidenceBytes);
    const directoryBefore = readdirSync(dir).sort();

    let app: OverwatchApp | undefined;
    try {
      app = createOverwatchApp({
        configPath,
        stateFilePath,
        skillDir: resolve('./skills'),
        dashboardPort: 8384,
      });
      expect(app.engine.getPersistenceRecoveryStatus()).toMatchObject({
        complete: false,
        writable: false,
        state_migration: {
          status: 'blocked',
          observed_state_version: 2,
        },
      });
    } finally {
      if (app) await shutdownOverwatchApp(app);
      expect(readFileSync(stateFilePath)).toEqual(futureBytes);
      expect(readFileSync(configPath)).toEqual(configBytes);
      expect(readFileSync(casArtifact)).toEqual(configBytes);
      expect(readFileSync(intentPath, 'utf8')).toBe('{ malformed intent');
      expect(readFileSync(evidenceManifest)).toEqual(evidenceBytes);
      expect(readdirSync(dir).sort()).toEqual(directoryBefore);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('creates the core app without binding a transport', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-core-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'state-app-bootstrap-recovery.json');
    writeFileSync(configPath, JSON.stringify(recoveryConfig()));
    const app = createOverwatchApp({
      configPath,
      stateFilePath,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
    });

    try {
      expect(app.server).toBeDefined();
      expect(app.engine).toBeDefined();
      expect(app.sessionManager).toBeDefined();
      expect(app.dashboard).toBeNull();
    } finally {
      await shutdownOverwatchApp(app);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('exposes the live revisioned config to embedded callers', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-live-config-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'state-app-bootstrap-recovery.json');
    writeFileSync(configPath, JSON.stringify(recoveryConfig()));
    const app = createOverwatchApp({
      configPath,
      stateFilePath,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
    });

    try {
      const previousRevision = app.config.config_revision!;
      app.engine.updateConfig({ name: 'Live embedded config' });
      expect(app.config).toMatchObject({
        name: 'Live embedded config',
        config_revision: previousRevision + 1,
      });
      expect(app.config).toEqual(app.engine.getConfig());
    } finally {
      await shutdownOverwatchApp(app);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('registers all tools without requiring stdio startup', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-tools-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'state-app-bootstrap-recovery.json');
    writeFileSync(configPath, JSON.stringify(recoveryConfig()));
    const app = createOverwatchApp({
      configPath,
      stateFilePath,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'tool-schema-parity', version: '1.0.0' });
    await app.server.connect(serverTransport);
    await client.connect(clientTransport);

    const toolNames: string[] = [];
    const fakeServer = {
      registerTool(name: string, _config?: any, _cb?: any) {
        toolNames.push(name);
        return { enable() {}, disable() {}, enabled: true };
      },
    } as any;

    try {
      const registeredTools = registerAllTools(fakeServer, {
        engine: app.engine,
        skills: app.skills,
        processTracker: app.processTracker,
        sessionManager: app.sessionManager,
        engagementManager: app.engagementManager,
        getDashboardStatus: () => ({ enabled: false, running: false }),
      });

      const publicManifest = JSON.parse(readFileSync(
        resolve('./docs/reference/tool-schema-manifest.json'),
        'utf8',
      ));
      const runtimeManifest = buildToolRegistryManifest(registeredTools);
      expect(runtimeManifest).toEqual({
        manifest_version: publicManifest.manifest_version,
        tool_count: publicManifest.tool_count,
        registry_sha256: publicManifest.registry_sha256,
        categories: publicManifest.categories,
        tools: publicManifest.tools,
      });
      expect(toolNames).toHaveLength(publicManifest.tool_count);
      expect(new Set(toolNames).size).toBe(publicManifest.tool_count);
      expect(toolNames.slice().sort()).toEqual(
        publicManifest.tools.map((tool: { name: string }) => tool.name).sort(),
      );
      expect(toolNames).toContain('get_state');
      expect(toolNames).toContain('list_playbook_runs');
      expect(toolNames).toContain('start_playbook_step');
      expect(toolNames).toContain('interrupt_playbook_attempt');
      expect(toolNames).toContain('run_retrospective');
      expect(toolNames).toContain('generate_report');
      expect(toolNames).toContain('open_session');
      expect(toolNames).toContain('create_engagement');
      expect(toolNames).toContain('list_engagements');
      expect(toolNames).toContain('add_objective');
      expect(toolNames).toContain('set_opsec');
      expect(toolNames).toContain('close_session');
      expect(toolNames).toContain('resume_session');

      // Hashes and the checked manifest must describe the schema that an actual
      // MCP client receives, including the SDK's empty-object behavior.
      const listed = await client.listTools();
      const listedByName = new Map(listed.tools.map(tool => [tool.name, tool]));
      expect(listedByName.size).toBe(app.registeredTools.length);
      for (const descriptor of app.registeredTools) {
        const sdkTool = listedByName.get(descriptor.name);
        expect(sdkTool, descriptor.name).toBeDefined();
        expect(canonicalJson(descriptor.input_schema), descriptor.name)
          .toBe(canonicalJson(sdkTool!.inputSchema));
        expect(canonicalJson(descriptor.output_schema), descriptor.name)
          .toBe(canonicalJson(sdkTool!.outputSchema ?? null));
      }
      expect(toolNames).toContain('update_scope');
      expect(toolNames).toContain('get_system_prompt');
      expect(toolNames).toContain('ingest_azurehound');
      expect(toolNames).toContain('dispatch_subnet_agents');
      expect(toolNames).toContain('get_recovery_status');
      expect(toolNames).toContain('resolve_config_divergence');
    } finally {
      await client.close();
      await shutdownOverwatchApp(app);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('hydrates recovered session descriptors into the runtime listing surface', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-session-restore-'));
    const configPath = join(dir, 'engagement.json');
    const stateFilePath = join(dir, 'state-app-session-restore.json');
    writeFileSync(configPath, JSON.stringify(recoveryConfig()));
    const first = createOverwatchApp({
      configPath,
      stateFilePath,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
    });
    const now = new Date().toISOString();
    first.engine.recordSessionDescriptor({
      id: 'listener-restored',
      kind: 'socket',
      adapter: 'socket',
      transport: 'tcp-listen',
      state: 'resume_available',
      listener_id: 'listener-restored',
      connection_generation: 2,
      resume_policy: 'manual',
      mode: 'listen',
      bind_host: '127.0.0.1',
      accept_mode: 'rearm',
      title: 'Recovered listener',
      port: 4444,
      started_at: now,
      last_activity_at: now,
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'dumb',
      },
      buffer_end_pos: 0,
    });
    first.engine.flushNow();
    await shutdownOverwatchApp(first);

    const restarted = createOverwatchApp({
      configPath,
      stateFilePath,
      skillDir: resolve('./skills'),
      dashboardPort: 0,
    });
    try {
      expect(restarted.sessionManager.list()).toContainEqual(expect.objectContaining({
        id: 'listener-restored',
        state: 'resume_available',
        listener_id: 'listener-restored',
        connection_generation: 2,
        buffer_end_pos: 0,
      }));
    } finally {
      await shutdownOverwatchApp(restarted);
      rmSync(dir, { recursive: true, force: true });
    }
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
    registrar.registerTool('add_objective', {
      description: 'mutates',
      annotations: completeAnnotations(false),
    }, async () => {
      mutationCalls++;
      return { content: [{ type: 'text' as const, text: 'mutated' }] };
    });
    registrar.registerTool('get_history', {
      description: 'reads',
      annotations: completeAnnotations(true),
    }, async () => {
      readCalls++;
      return { content: [{ type: 'text' as const, text: 'read' }] };
    });
    registrar.registerTool('get_state', {
      description: 'conditionally snapshots',
      annotations: completeAnnotations(true),
    }, async () => ({ content: [{ type: 'text' as const, text: 'state' }] }));
    registrar.registerTool('get_system_prompt', {
      description: 'conditionally snapshots despite a mutating annotation',
      annotations: completeAnnotations(false),
    }, async () => ({ content: [{ type: 'text' as const, text: 'prompt' }] }));
    registrar.registerTool('check_processes', {
      description: 'refreshes durable process status despite a read annotation',
      annotations: completeAnnotations(true),
    }, async () => ({ content: [{ type: 'text' as const, text: 'processes' }] }));
    let recoveryResolutionCalls = 0;
    registrar.registerTool('resolve_config_divergence', {
      description: 'the narrow configuration recovery mutation',
      annotations: completeAnnotations(false),
    }, async () => {
      recoveryResolutionCalls++;
      return { content: [{ type: 'text' as const, text: 'resolved' }] };
    });

    const blocked = await handlers.get('add_objective')!({});
    const allowed = await handlers.get('get_history')!({});
    const snapshotBlocked = await handlers.get('get_state')!({ snapshot: true });
    const stateAllowed = await handlers.get('get_state')!({ snapshot: false });
    const promptSnapshotBlocked = await handlers.get('get_system_prompt')!({ snapshot: true });
    const promptReadAllowed = await handlers.get('get_system_prompt')!({ snapshot: false });
    const processRefreshBlocked = await handlers.get('check_processes')!({});
    const recoveryResolutionAllowed = await handlers.get('resolve_config_divergence')!({});
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
    expect(recoveryResolutionAllowed).toMatchObject({ content: [{ text: 'resolved' }] });
    expect(recoveryResolutionCalls).toBe(1);
  });

  it('maps a late durability failure returned by the MCP error boundary to recovery read-only', async () => {
    const handlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();
    const fakeServer = {
      registerTool(name: string, _config: unknown, callback: (...args: unknown[]) => Promise<unknown>) {
        handlers.set(name, callback);
        return { enable() {}, disable() {}, enabled: true };
      },
    };
    const healthyRecovery: ReturnType<GraphEngine['getPersistenceRecoveryStatus']> = {
      outcome: 'clean',
      source: 'state',
      complete: true,
      writable: true,
      base_checkpoint: 7,
      highest_allocated_seq: 7,
      highest_on_disk_seq: 7,
      highest_contiguous_applied_seq: 7,
      consecutive_persistence_failures: 0,
      journal: {
        enabled: true,
        read: 0,
        attempted: 0,
        applied: 0,
        skipped: 0,
        failed: 0,
        malformed: false,
        preserved: false,
      },
      config_recovery: {
        status: 'in_sync',
        resolution_required: false,
        intent_present: false,
      },
    };
    const lateRecovery: ReturnType<GraphEngine['getPersistenceRecoveryStatus']> = {
      ...healthyRecovery,
      outcome: 'incomplete',
      complete: false,
      writable: false,
      reason: 'configuration write did not complete durably',
      last_persistence_error: 'config fsync failed',
      config_recovery: {
        status: 'write_incomplete',
        resolution_required: true,
        intent_present: true,
        allowed_resolutions: [],
        reason: 'configuration write did not complete durably',
      },
    };
    let writable = true;
    const registrar = new ToolRegistrar(fakeServer as never, {
      isPersistenceWritable: () => writable,
      getPersistenceRecoveryStatus: () => writable ? healthyRecovery : lateRecovery,
    });
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      registrar.registerTool('set_opsec', {
        description: 'fails during a durable write',
        annotations: completeAnnotations(false),
      }, withErrorBoundary('late_boundary_failure', async () => {
        writable = false;
        throw Object.assign(new Error('config fsync failed'), { code: 'ENOSPC' });
      }));

      const result = await handlers.get('set_opsec')!({}) as {
        isError?: boolean;
        content: Array<{ text: string }>;
      };
      const payload = JSON.parse(result.content[0].text);

      expect(result.isError).toBe(true);
      expect(payload).toMatchObject({
        success: false,
        error: 'config fsync failed',
        code: 'PERSISTENCE_READ_ONLY',
        persistence_error_code: 'ENOSPC',
        classification: 'internal_error',
        tool: 'late_boundary_failure',
        recovery: {
          writable: false,
          last_persistence_error: 'config fsync failed',
          config_recovery: { status: 'write_incomplete', intent_present: true },
        },
      });
    } finally {
      stderr.mockRestore();
    }
  });

  it('does not globalize create_engagement inactive-file persistence failure while engine recovery is healthy', async () => {
    const handlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();
    const fakeServer = {
      registerTool(name: string, _config: unknown, callback: (...args: unknown[]) => Promise<unknown>) {
        handlers.set(name, callback);
        return { enable() {}, disable() {}, enabled: true };
      },
    };
    const healthyRecovery: ReturnType<GraphEngine['getPersistenceRecoveryStatus']> = {
      outcome: 'clean',
      source: 'state',
      complete: true,
      writable: true,
      base_checkpoint: 3,
      highest_allocated_seq: 3,
      highest_on_disk_seq: 3,
      highest_contiguous_applied_seq: 3,
      consecutive_persistence_failures: 0,
      journal: {
        enabled: true,
        read: 0,
        attempted: 0,
        applied: 0,
        skipped: 0,
        failed: 0,
        malformed: false,
        preserved: false,
      },
      config_recovery: {
        status: 'in_sync',
        resolution_required: false,
        intent_present: false,
      },
    };
    const registrar = new ToolRegistrar(fakeServer as never, {
      isPersistenceWritable: () => true,
      getPersistenceRecoveryStatus: () => healthyRecovery,
    });
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-app-inactive-create-'));
    const manager = new EngagementManager(join(dir, 'engagement.json'), () => {
      throw Object.assign(new Error('disk full'), { code: 'ENOSPC' });
    });
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      registerEngagementTools(registrar as never, {} as GraphEngine, manager);

      const result = await handlers.get('create_engagement')!({
        name: 'Inactive must persist',
        dry_run: false,
      }) as { isError?: boolean; content: Array<{ text: string }> };
      const payload = JSON.parse(result.content[0].text);

      expect(result.isError).toBe(true);
      expect(payload).toMatchObject({
        success: false,
        code: 'ENGAGEMENT_PERSISTENCE_FAILED',
        classification: 'internal_error',
        tool: 'create_engagement',
        error: expect.stringContaining('was not durably persisted: disk full'),
      });
      expect(payload).not.toHaveProperty('recovery');
      expect(payload).not.toHaveProperty('persistence_error_code');
    } finally {
      stderr.mockRestore();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('adds late recovery to the rich run_tool interruption payload without dropping attribution', async () => {
    const handlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();
    const fakeServer = {
      registerTool(name: string, _config: unknown, callback: (...args: unknown[]) => Promise<unknown>) {
        handlers.set(name, callback);
        return { enable() {}, disable() {}, enabled: true };
      },
    };
    const healthyRecovery: ReturnType<GraphEngine['getPersistenceRecoveryStatus']> = {
      outcome: 'clean',
      source: 'state',
      complete: true,
      writable: true,
      base_checkpoint: 11,
      highest_allocated_seq: 11,
      highest_on_disk_seq: 11,
      highest_contiguous_applied_seq: 11,
      consecutive_persistence_failures: 0,
      journal: {
        enabled: true,
        read: 0,
        attempted: 0,
        applied: 0,
        skipped: 0,
        failed: 0,
        malformed: false,
        preserved: false,
      },
    };
    const lateRecovery: ReturnType<GraphEngine['getPersistenceRecoveryStatus']> = {
      ...healthyRecovery,
      outcome: 'incomplete',
      complete: false,
      writable: false,
      reason: 'mutation journal append is ambiguous',
      journal: {
        ...healthyRecovery.journal,
        preserved: true,
      },
    };
    let recovery = healthyRecovery;
    const registrar = new ToolRegistrar(fakeServer as never, {
      isPersistenceWritable: () => recovery.writable,
      getPersistenceRecoveryStatus: () => recovery,
    });
    registrar.registerTool('run_tool', {
      description: 'instrumented target process',
      annotations: completeAnnotations(false),
    }, async () => {
      recovery = lateRecovery;
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            action_id: 'act-rich-interruption',
            executed: false,
            interrupted: true,
            code: 'PERSISTENCE_READ_ONLY',
            reason: 'persistence_degraded',
            error: 'Target execution was interrupted because durable persistence became read-only.',
            recovery: { writable: false, stale: true },
            stdout_evidence_id: 'evidence-before-interruption',
            phase: 'action_started',
          }, null, 2),
        }],
        isError: true,
      };
    });

    const result = await handlers.get('run_tool')!({}) as {
      isError?: boolean;
      content: Array<{ text: string }>;
    };
    const payload = JSON.parse(result.content[0].text);

    expect(result.isError).toBe(true);
    expect(result.content).toHaveLength(1);
    expect(payload).toMatchObject({
      action_id: 'act-rich-interruption',
      executed: false,
      interrupted: true,
      code: 'PERSISTENCE_READ_ONLY',
      reason: 'persistence_degraded',
      error: 'Target execution was interrupted because durable persistence became read-only.',
      stdout_evidence_id: 'evidence-before-interruption',
      phase: 'action_started',
      recovery: {
        complete: false,
        writable: false,
        reason: 'mutation journal append is ambiguous',
      },
    });
    expect(payload.recovery).not.toHaveProperty('stale');
  });

  it('maps a rejected late storage error but preserves an ordinary MCP tool error', async () => {
    const handlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();
    const fakeServer = {
      registerTool(name: string, _config: unknown, callback: (...args: unknown[]) => Promise<unknown>) {
        handlers.set(name, callback);
        return { enable() {}, disable() {}, enabled: true };
      },
    };
    let writable = true;
    const recovery = () => ({
      outcome: writable ? 'clean' as const : 'incomplete' as const,
      source: 'state' as const,
      complete: writable,
      writable,
      ...(!writable ? { reason: 'state persistence failed' } : {}),
      base_checkpoint: 4,
      highest_allocated_seq: 5,
      highest_on_disk_seq: 5,
      highest_contiguous_applied_seq: 4,
      consecutive_persistence_failures: writable ? 0 : 3,
      ...(!writable ? { last_persistence_error: 'state rename failed' } : {}),
      journal: {
        enabled: true,
        read: 0,
        attempted: 0,
        applied: 0,
        skipped: 0,
        failed: 0,
        malformed: false,
        preserved: false,
      },
    });
    const registrar = new ToolRegistrar(fakeServer as never, {
      isPersistenceWritable: () => writable,
      getPersistenceRecoveryStatus: recovery,
    });
    registrar.registerTool('update_scope', {
      description: 'rejects after storage fails',
      annotations: completeAnnotations(false),
    }, async () => {
      writable = false;
      throw Object.assign(new Error('state rename failed'), { code: 'EIO' });
    });
    registrar.registerTool('correct_graph', {
      description: 'returns an ordinary validation failure',
      annotations: completeAnnotations(false),
    }, async () => ({
      content: [{
        type: 'text' as const,
        text: JSON.stringify({ success: false, error: 'target is required', classification: 'validation_error' }),
      }],
      isError: true,
    }));

    const rejected = await handlers.get('update_scope')!({}) as { content: Array<{ text: string }> };
    const rejectedPayload = JSON.parse(rejected.content[0].text);
    expect(rejectedPayload).toMatchObject({
      error: 'state rename failed',
      code: 'PERSISTENCE_READ_ONLY',
      recovery: { writable: false, consecutive_persistence_failures: 3 },
    });

    writable = true;
    const ordinary = await handlers.get('correct_graph')!({}) as { content: Array<{ text: string }> };
    expect(JSON.parse(ordinary.content[0].text)).toEqual({
      success: false,
      error: 'target is required',
      classification: 'validation_error',
    });
  });

  it('maps a late reconciliation write failure without masking a hash conflict', async () => {
    const handlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();
    const fakeServer = {
      registerTool(name: string, _config: unknown, callback: (...args: unknown[]) => Promise<unknown>) {
        handlers.set(name, callback);
        return { enable() {}, disable() {}, enabled: true };
      },
    };
    const diverged: ReturnType<GraphEngine['getPersistenceRecoveryStatus']> = {
      outcome: 'incomplete',
      source: 'state',
      complete: false,
      writable: false,
      reason: 'configuration reconciliation is required',
      base_checkpoint: 2,
      highest_allocated_seq: 2,
      highest_on_disk_seq: 2,
      highest_contiguous_applied_seq: 2,
      consecutive_persistence_failures: 0,
      journal: {
        enabled: true,
        read: 0,
        attempted: 0,
        applied: 0,
        skipped: 0,
        failed: 0,
        malformed: false,
        preserved: false,
      },
      config_recovery: {
        status: 'diverged',
        resolution_required: true,
        intent_present: false,
        allowed_resolutions: ['use_file', 'use_state'],
      },
    };
    let recovery = diverged;
    let attempt = 0;
    const registrar = new ToolRegistrar(fakeServer as never, {
      isPersistenceWritable: () => false,
      getPersistenceRecoveryStatus: () => recovery,
    });
    registrar.registerTool('resolve_config_divergence', {
      description: 'reconciles configuration',
      annotations: completeAnnotations(false),
    }, async () => {
      attempt++;
      if (attempt === 1) {
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              success: false,
              error: 'Configuration changed after it was inspected',
              code: 'CONFIG_HASH_CONFLICT',
            }),
          }],
          isError: true,
        };
      }
      recovery = {
        ...diverged,
        reason: 'configuration write did not complete durably',
        last_persistence_error: 'config rename failed',
        config_recovery: {
          status: 'write_incomplete',
          resolution_required: true,
          intent_present: true,
          allowed_resolutions: [],
        },
      };
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({ success: false, error: 'config rename failed', code: 'EIO' }),
        }],
        isError: true,
      };
    });

    const conflict = await handlers.get('resolve_config_divergence')!({}) as { content: Array<{ text: string }> };
    expect(JSON.parse(conflict.content[0].text)).toMatchObject({ code: 'CONFIG_HASH_CONFLICT' });
    expect(JSON.parse(conflict.content[0].text)).not.toHaveProperty('recovery');

    const storageFailure = await handlers.get('resolve_config_divergence')!({}) as { content: Array<{ text: string }> };
    expect(JSON.parse(storageFailure.content[0].text)).toMatchObject({
      error: 'config rename failed',
      code: 'PERSISTENCE_READ_ONLY',
      recovery: { config_recovery: { status: 'write_incomplete', intent_present: true } },
    });
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

  it('continues runtime cleanup when pre-shutdown session persistence fails', async () => {
    const sessionShutdown = vi.fn().mockResolvedValue(undefined);
    const dashboardStop = vi.fn().mockResolvedValue(undefined);
    const tapeDisable = vi.fn().mockResolvedValue(undefined);
    const dispose = vi.fn();
    const app = {
      taskExecution: { shutdown: vi.fn().mockResolvedValue(undefined) },
      httpTransports: {},
      sessionManager: {
        list: vi.fn(() => [{
          id: 'session-1',
          state: 'connected',
        }]),
        shutdown: sessionShutdown,
      },
      dashboard: { stop: dashboardStop },
      tape: { disable: tapeDisable },
      processTracker: {
        serialize: vi.fn(() => []),
        setMutationGuard: vi.fn(),
      },
      engine: {
        isPersistenceWritable: () => true,
        recordSessionDescriptor: vi.fn(() => {
          throw new Error('descriptor persistence failed');
        }),
        setTrackedProcesses: vi.fn(),
        persist: vi.fn(),
        flushNow: vi.fn(),
        setRollbackCoordinator: vi.fn(),
        dispose,
      },
    } as unknown as OverwatchApp;

    await expect(shutdownOverwatchApp(app)).rejects.toThrow('descriptor persistence failed');
    expect(sessionShutdown).toHaveBeenCalledOnce();
    expect(dashboardStop).toHaveBeenCalledOnce();
    expect(tapeDisable).toHaveBeenCalledOnce();
    expect(dispose).toHaveBeenCalledOnce();
  });

  it('closes a real tape without an audit mutation during degraded shutdown', async () => {
    const tapeDir = mkdtempSync(join(tmpdir(), 'overwatch-degraded-shutdown-tape-'));
    let writable = true;
    const logActionEvent = vi.fn(() => ({ event_id: 'evt-tape-start' }));
    const dispose = vi.fn();
    const engine = {
      isPersistenceWritable: () => writable,
      assertPersistenceWritable: () => {
        if (!writable) throw new Error('Durable mutations are disabled.');
      },
      logActionEvent,
      setTrackedProcesses: vi.fn(),
      persist: vi.fn(),
      flushNow: vi.fn(),
      setRollbackCoordinator: vi.fn(),
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
        processTracker: {
          serialize: vi.fn(() => []),
          setMutationGuard: vi.fn(),
        },
        engine,
      } as unknown as OverwatchApp;

      await expect(shutdownOverwatchApp(app)).resolves.toBeUndefined();

      expect(tape.getStatus()).toMatchObject({ enabled: false, frame_count: 0 });
      // The closed descriptor remains visible for operator diagnostics and
      // bundle discovery even though no live handle remains.
      expect(tape.getStatus().path).toContain(tapeDir);
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
