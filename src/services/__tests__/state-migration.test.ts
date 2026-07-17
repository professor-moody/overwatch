import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EngagementConfig, SessionMetadata } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal } from '../mutation-journal.js';
import {
  CURRENT_JOURNAL_VERSION,
  CURRENT_STATE_VERSION,
  LEGACY_JOURNAL_VERSION,
  LEGACY_STATE_VERSION,
  detectJournalVersion,
  detectStateVersion,
  validatePersistedStateV1,
} from '../persisted-state.js';
import {
  acquireStateMigrationLease,
  activateStateMigration,
  createStateMigrationBackup,
  findReusableStateMigrationBackup,
  inspectStateMigration,
  prepareStateMigrationBackup,
  verifyStateMigrationBackup,
} from '../state-migration.js';

const NOW = '2026-07-16T00:00:00.000Z';

function config(): EngagementConfig {
  return {
    id: 'migration-test',
    name: 'Migration Test',
    created_at: NOW,
    scope: {
      cidrs: ['10.20.30.0/24'],
      domains: ['migration.test'],
      exclusions: [],
    },
    objectives: [],
    opsec: {
      name: 'pentest',
      max_noise: 0.7,
      blacklisted_techniques: [],
    },
  };
}

function stripConfigMetadata(value: EngagementConfig): EngagementConfig {
  const copy = structuredClone(value) as EngagementConfig & {
    config_revision?: number;
    config_hash?: string;
  };
  delete copy.config_revision;
  delete copy.config_hash;
  return copy;
}

function downgradePrimaryToV0(
  statePath: string,
  configPath?: string,
): { stateBytes: Buffer; configBytes?: Buffer; checkpoint: number } {
  const state = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, unknown>;
  delete state.state_version;
  delete state.journal_version;
  delete state.journalCheckpointSemantics;
  delete state.walCompactionAuthority;
  state.config = stripConfigMetadata(state.config as EngagementConfig);
  const bytes = Buffer.from(JSON.stringify(state));
  writeFileSync(statePath, bytes);
  rmSync(MutationJournal.pathForState(statePath), { force: true });
  let configBytes: Buffer | undefined;
  if (configPath) {
    const legacyConfig = stripConfigMetadata(
      JSON.parse(readFileSync(configPath, 'utf8')) as EngagementConfig,
    );
    configBytes = Buffer.from(`${JSON.stringify(legacyConfig, null, 2)}\n`);
    writeFileSync(configPath, configBytes);
  }
  return {
    stateBytes: bytes,
    configBytes,
    checkpoint: state.journalSnapshotSeq as number,
  };
}

function node(id: string) {
  return {
    id,
    type: 'host' as const,
    label: id,
    ip: '10.20.30.10',
    alive: true,
    discovered_at: NOW,
    confidence: 1,
  };
}

function refreshCompactionAuthority(state: Record<string, unknown>): Buffer {
  delete state.walCompactionAuthority;
  const payload = JSON.stringify(state);
  return Buffer.from(JSON.stringify({
    ...state,
    walCompactionAuthority: {
      semantics: 'full_state_sha256_json_v1',
      payload_sha256: createHash('sha256').update(payload).digest('hex'),
    },
  }));
}

describe('PersistedStateV1 and migration', () => {
  let directory: string;
  let statePath: string;
  let configPath: string;
  const engines: GraphEngine[] = [];

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-state-migration-'));
    statePath = join(directory, 'state-migration-test.json');
    configPath = join(directory, 'engagement.json');
  });

  afterEach(() => {
    for (const engine of engines.splice(0)) engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  function open(
    engagementConfig: EngagementConfig = config(),
    managed = true,
  ): GraphEngine {
    const engine = new GraphEngine(
      engagementConfig,
      statePath,
      managed ? configPath : undefined,
    );
    engines.push(engine);
    return engine;
  }

  function close(engine: GraphEngine): void {
    const index = engines.indexOf(engine);
    if (index >= 0) engines.splice(index, 1);
    engine.dispose();
  }

  it('detects only an absent discriminator as legacy V0', () => {
    expect(detectStateVersion({ config: {}, graph: {} })).toBe(LEGACY_STATE_VERSION);
    expect(detectStateVersion({ state_version: 1 })).toBe(CURRENT_STATE_VERSION);
    expect(() => detectStateVersion({ state_version: 0 })).toThrow(/positive safe integer/);
    expect(() => detectStateVersion({ state_version: 2 })).toThrow(/unsupported/);
    expect(detectJournalVersion({ config: {}, graph: {} }, LEGACY_STATE_VERSION))
      .toBe(LEGACY_JOURNAL_VERSION);
    expect(detectJournalVersion(
      { state_version: 1, journal_version: 2 },
      CURRENT_STATE_VERSION,
    )).toBe(CURRENT_JOURNAL_VERSION);
    expect(() => detectJournalVersion(
      { state_version: 1, journal_version: 3 },
      CURRENT_STATE_VERSION,
    )).toThrow(/unsupported/);
  });

  it('round-trips the complete V1 coordination surface without runtime handles or secrets', () => {
    const engine = open(config(), false);
    engine.registerAgent({
      id: 'task-1',
      agent_id: 'agent-1',
      assigned_at: NOW,
      status: 'completed',
      subgraph_node_ids: [],
    });
    const proposed = engine.getProposedPlanStore().add({
      command: 'pause task',
      summary: 'pause task',
      ops: [{
        op: 'directive',
        task_id: 'task-1',
        agent_label: 'agent-1',
        kind: 'pause',
      }],
    });
    const query = engine.getAgentQueryStore().add({
      task_id: 'task-1',
      agent_id: 'agent-1',
      question: 'continue?',
    });
    const commandPlan = engine.createCommandPlan({
      command: 'scan 10.20.30.10',
      ops: [{ op: 'scope', add_cidrs: ['10.20.30.10/32'] }],
    });
    engine.recordCommandOutcome('completed-plan', [{ ok: true }]);
    engine.setFrontierWeights({
      fan_out: { host: 12 },
      noise: { network_discovery: 0.42 },
    });
    const metadata: SessionMetadata & {
      password?: string;
      env?: Record<string, string>;
    } = {
      id: 'session-1',
      kind: 'ssh',
      transport: 'ssh',
      state: 'closed',
      title: 'closed shell',
      host: '10.20.30.10',
      started_at: NOW,
      last_activity_at: NOW,
      closed_at: NOW,
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: true,
        supports_signals: true,
        tty_quality: 'full',
      },
      buffer_end_pos: 999,
      password: 'supersecret',
      env: { TOKEN: 'supersecret' },
    };
    engine.recordSessionDescriptor(metadata);
    engine.setTrackedProcesses([{
      id: 'process-1',
      pid: 424242,
      command: 'nmap 10.20.30.10',
      description: 'scan',
      started_at: NOW,
      status: 'unknown',
    }]);
    engine.setPlaybookRuns([{ run_id: 'playbook-1', status: 'pending' }]);
    const context = (engine as unknown as { ctx: {
      chainEventsSinceCheckpoint: number;
      recentFindingHashes: Map<string, number>;
      dedupCount: number;
    } }).ctx;
    context.chainEventsSinceCheckpoint = 7;
    context.recentFindingHashes.set('hash-1', 1234);
    context.dedupCount = 3;
    mkdirSync(join(directory, 'reports'), { recursive: true });
    writeFileSync(join(directory, 'reports', 'manifest.json'), '[]');
    engine.persistImmediate();

    const state = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, unknown>;
    expect(validatePersistedStateV1(state).state_version).toBe(1);
    expect(state).toMatchObject({
      state_version: 1,
      journal_version: CURRENT_JOURNAL_VERSION,
      chainEventsSinceCheckpoint: 7,
      dedupCount: 3,
      frontierWeights: {
        fan_out: { host: 12 },
        noise: { network_discovery: 0.42 },
      },
    });
    expect(state.proposedPlans).toMatchObject({
      plans: [expect.objectContaining({ plan_id: proposed.plan_id })],
    });
    expect(state.agentQueries).toMatchObject({
      queries: [expect.objectContaining({ query_id: query.query_id })],
    });
    expect(state.agents).toEqual(expect.arrayContaining([
      ['task-1', expect.objectContaining({
        task_id: 'task-1',
        agent_label: 'agent-1',
        id: 'task-1',
        agent_id: 'agent-1',
      })],
    ]));
    expect(state.commandPlans).toEqual(expect.arrayContaining([
      [commandPlan, expect.objectContaining({ command: 'scan 10.20.30.10' })],
    ]));
    expect(state.commandOutcomes).toEqual(expect.arrayContaining([
      ['completed-plan', expect.objectContaining({ results: [{ ok: true }] })],
    ]));
    expect(state.artifactReferences).toMatchObject({
      report_manifest: {
        kind: 'report_manifest',
        path: 'reports/manifest.json',
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      },
    });
    const serialized = JSON.stringify(state);
    expect(serialized).not.toContain('supersecret');
    expect(serialized).not.toContain('buffer_end_pos');
    close(engine);

    const restarted = open(config(), false);
    expect(restarted.getProposedPlanStore().get(proposed.plan_id)).toBeDefined();
    expect(restarted.getAgentQueryStore().get(query.query_id)).toMatchObject({
      owner_task_id: 'task-1',
      owner_agent_label: 'agent-1',
    });
    expect(restarted.getCommandPlan(commandPlan)?.command).toBe('scan 10.20.30.10');
    expect(restarted.getCommandOutcome('completed-plan')?.results).toEqual([{ ok: true }]);
    expect(restarted.getSessionDescriptors()).toEqual([
      expect.objectContaining({ session_id: 'session-1', lifecycle: 'closed' }),
    ]);
    expect(restarted.getRuntimeRuns()).toEqual([
      expect.objectContaining({ run_id: 'process-1', lifecycle: 'unknown' }),
    ]);
    expect(restarted.getPlaybookRuns()).toEqual([
      expect.objectContaining({ run_id: 'playbook-1', status: 'pending' }),
    ]);
    expect(restarted.getFrontierWeights()).toMatchObject({
      fan_out: { host: 12 },
      noise: { network_discovery: 0.42 },
    });
  });

  it('rejects ambiguous or structurally unusable V1 coordination records', () => {
    const engine = open(config(), false);
    engine.recordSessionDescriptor({
      id: 'session-1',
      kind: 'local_pty',
      transport: 'pty',
      state: 'closed',
      title: 'shell',
      started_at: NOW,
      last_activity_at: NOW,
      closed_at: NOW,
      capabilities: {
        has_stdin: false,
        has_stdout: true,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'none',
      },
      buffer_end_pos: 0,
    });
    engine.setTrackedProcesses([{
      id: 'process-1',
      pid: 1234,
      command: 'scan',
      description: 'scan',
      started_at: NOW,
      status: 'running',
    }]);
    const proposal = engine.getProposedPlanStore().add({
      command: 'pause',
      summary: 'pause',
      ops: [{ op: 'directive', task_id: 'task-1', agent_label: 'a', kind: 'pause' }],
    });
    engine.persistImmediate();
    const base = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, any>;

    const mismatchedAgent = structuredClone(base);
    mismatchedAgent.agents = [[
      'task-key',
      {
        id: 'different-task',
        agent_id: 'agent-1',
        assigned_at: NOW,
        status: 'running',
        subgraph_node_ids: [],
      },
    ]];
    expect(() => validatePersistedStateV1(mismatchedAgent)).toThrow(/id must match map key/);

    const duplicateSession = structuredClone(base);
    duplicateSession.sessionDescriptors.push(structuredClone(duplicateSession.sessionDescriptors[0]));
    expect(() => validatePersistedStateV1(duplicateSession)).toThrow(/duplicate session_id/);

    const invalidResume = structuredClone(base);
    Object.assign(invalidResume.sessionDescriptors[0], {
      kind: 'socket',
      lifecycle: 'closed',
      recovery_lifecycle: 'resume_available',
      mode: 'listen',
      accept_mode: 'rearm',
      connection_id: undefined,
      resume_intent: {
        policy: 'none',
        requested: false,
        recorded_at: NOW,
      },
    });
    expect(() => validatePersistedStateV1(invalidResume))
      .toThrow(/resume_available requires/);

    const backwardReadableResume = structuredClone(base);
    Object.assign(backwardReadableResume.sessionDescriptors[0], {
      kind: 'socket',
      lifecycle: 'closed',
      recovery_lifecycle: 'resume_available',
      mode: 'listen',
      accept_mode: 'rearm',
      connection_id: undefined,
      resume_intent: {
        policy: 'manual',
        requested: true,
        prior_state: 'pending',
        recovery_prior_state: 'resume_available',
        recorded_at: NOW,
      },
    });
    expect(() => validatePersistedStateV1(backwardReadableResume)).not.toThrow();
    const priorBinaryView = structuredClone(backwardReadableResume);
    delete priorBinaryView.sessionDescriptors[0].recovery_lifecycle;
    delete priorBinaryView.sessionDescriptors[0].resume_intent.recovery_prior_state;
    expect(priorBinaryView.sessionDescriptors[0].lifecycle).toBe('closed');
    expect(() => validatePersistedStateV1(priorBinaryView)).not.toThrow();

    const incompatibleRecoveryFallback = structuredClone(backwardReadableResume);
    incompatibleRecoveryFallback.sessionDescriptors[0].lifecycle = 'error';
    expect(() => validatePersistedStateV1(incompatibleRecoveryFallback))
      .toThrow(/incompatible V1 lifecycle fallback/);

    const invalidConnectedGeneration = structuredClone(base);
    Object.assign(invalidConnectedGeneration.sessionDescriptors[0], {
      lifecycle: 'connected',
      connection_generation: 0,
      connection_id: 'session-1:g0',
    });
    expect(() => validatePersistedStateV1(invalidConnectedGeneration))
      .toThrow(/connection_generation >= 1/);

    const invalidInterruptedConnection = structuredClone(base);
    Object.assign(invalidInterruptedConnection.sessionDescriptors[0], {
      lifecycle: 'error',
      recovery_lifecycle: 'interrupted',
      connection_generation: 1,
      connection_id: 'session-1:g1',
    });
    expect(() => validatePersistedStateV1(invalidInterruptedConnection))
      .toThrow(/connection_id is only valid/);

    const duplicateRuntime = structuredClone(base);
    duplicateRuntime.runtimeRuns.push(structuredClone(duplicateRuntime.runtimeRuns[0]));
    expect(() => validatePersistedStateV1(duplicateRuntime)).toThrow(/duplicate run_id/);

    const duplicateProposal = structuredClone(base);
    duplicateProposal.proposedPlans.plans.push({
      ...structuredClone(duplicateProposal.proposedPlans.plans[0]),
      plan_id: proposal.plan_id,
    });
    expect(() => validatePersistedStateV1(duplicateProposal)).toThrow(/duplicate plan_id/);

    const missingActivityIdentity = structuredClone(base);
    missingActivityIdentity.activityLog = [{
      description: 'would previously be assigned a new id and timestamp',
    }];
    expect(() => validatePersistedStateV1(missingActivityIdentity)).toThrow(/event_id/);

    const duplicateActivity = structuredClone(base);
    duplicateActivity.activityLog = [{
      event_id: 'event-1',
      timestamp: NOW,
      description: 'first',
    }, {
      event_id: 'event-1',
      timestamp: NOW,
      description: 'second',
    }];
    expect(() => validatePersistedStateV1(duplicateActivity)).toThrow(/duplicate event_id/);

    const duplicateCold = structuredClone(base);
    duplicateCold.coldStore = [{
      id: 'cold-1',
      type: 'host',
      label: 'cold one',
      discovered_at: NOW,
      last_seen_at: NOW,
    }, {
      id: 'cold-1',
      type: 'host',
      label: 'cold duplicate',
      discovered_at: NOW,
      last_seen_at: NOW,
    }];
    expect(() => validatePersistedStateV1(duplicateCold)).toThrow(/duplicate cold node id/);

    const malformedCommand = structuredClone(base);
    malformedCommand.commandPlans = [[
      'bad-dispatch',
      {
        command: 'dispatch',
        created_at: 1,
        expires_at: 2,
        ops: [{ op: 'dispatch' }],
      },
    ]];
    expect(() => validatePersistedStateV1(malformedCommand)).toThrow(/target_node_ids/);

    const malformedCapabilities = structuredClone(base);
    delete malformedCapabilities.sessionDescriptors[0].capabilities.has_stdout;
    expect(() => validatePersistedStateV1(malformedCapabilities)).toThrow(/has_stdout/);

    const malformedRuntime = structuredClone(base);
    malformedRuntime.runtimeRuns[0].pid = 'not-a-pid';
    expect(() => validatePersistedStateV1(malformedRuntime)).toThrow(/pid/);

    const enrichedRuntime = structuredClone(base);
    enrichedRuntime.runtimeRuns = [{
      run_id: 'runtime-managed',
      kind: 'headless_agent',
      task_id: 'task-1',
      action_id: 'action-1',
      pid: 4242,
      target_pid: 4243,
      process_group_id: 4242,
      process_start_identity: 'physical-start',
      ownership_token: 'ownership-token',
      daemon_owner: 'daemon-1',
      command_fingerprint: 'a'.repeat(64),
      ownership_mode: 'managed_supervisor',
      signal_scope: 'process_group',
      started_at: NOW,
      identity_recorded_at: NOW,
      ownership_acknowledged_at: NOW,
      launched_at: NOW,
      lifecycle: 'running',
      evidence_state: 'pending',
      action_started_event_id: 'event-start',
    }];
    enrichedRuntime.trackedProcesses = [{
      id: 'runtime-managed',
      pid: 4242,
      command: 'claude -p',
      description: 'managed agent',
      started_at: NOW,
      status: 'running',
      task_id: 'task-1',
      action_id: 'action-1',
      process_group_id: 4242,
      process_start_identity: 'physical-start',
      ownership_token: 'ownership-token',
      daemon_owner: 'daemon-1',
      command_fingerprint: 'a'.repeat(64),
      ownership_mode: 'managed_supervisor',
      signal_scope: 'process_group',
    }];
    expect(() => validatePersistedStateV1(enrichedRuntime)).not.toThrow();

    const signalableExternal = structuredClone(enrichedRuntime);
    signalableExternal.runtimeRuns[0].ownership_mode = 'external_adopted';
    expect(() => validatePersistedStateV1(signalableExternal)).toThrow(/signal_scope none/);

    const missingManagedGroup = structuredClone(enrichedRuntime);
    delete missingManagedGroup.runtimeRuns[0].process_group_id;
    expect(() => validatePersistedStateV1(missingManagedGroup)).toThrow(/supervisor-owned process group/);

    const missingManagedToken = structuredClone(enrichedRuntime);
    delete missingManagedToken.runtimeRuns[0].ownership_token;
    expect(() => validatePersistedStateV1(missingManagedToken)).toThrow(/ownership token/);

    const mismatchedFinalization = structuredClone(enrichedRuntime);
    mismatchedFinalization.runtimeRuns[0].lifecycle = 'completed';
    mismatchedFinalization.runtimeRuns[0].finalization_status = 'failed';
    expect(() => validatePersistedStateV1(mismatchedFinalization)).toThrow(/must match lifecycle/);

    const invalidTrackedOwnership = structuredClone(enrichedRuntime);
    invalidTrackedOwnership.trackedProcesses[0].ownership_mode = 'external_adopted';
    expect(() => validatePersistedStateV1(invalidTrackedOwnership)).toThrow(/signal_scope none/);

    const wrongManifestKind = structuredClone(base);
    wrongManifestKind.artifactReferences.evidence_manifest = {
      kind: 'bundle',
      path: 'evidence/manifest.json',
    };
    expect(() => validatePersistedStateV1(wrongManifestKind)).toThrow(/kind must be evidence_manifest/);

    const duplicateArtifact = structuredClone(base);
    duplicateArtifact.artifactReferences.tapes = [{
      kind: 'tape',
      path: 'tapes/session.jsonl',
    }, {
      kind: 'tape',
      path: 'tapes/session.jsonl',
    }];
    expect(() => validatePersistedStateV1(duplicateArtifact)).toThrow(/duplicate artifact reference/);
  });

  it('retains durable artifact references that are not currently rediscoverable', () => {
    const initial = open(config(), false);
    initial.persistImmediate();
    close(initial);
    const state = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, any>;
    state.artifactReferences.tapes.push({
      kind: 'tape',
      path: '/offline/archive/operator-session.jsonl',
      sha256: 'a'.repeat(64),
    });
    writeFileSync(statePath, refreshCompactionAuthority(state));

    const restarted = open(config(), false);
    restarted.persistImmediate();
    close(restarted);

    const persisted = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, any>;
    expect(persisted.artifactReferences.tapes).toEqual(expect.arrayContaining([expect.objectContaining({
      kind: 'tape',
      path: '/offline/archive/operator-session.jsonl',
      sha256: 'a'.repeat(64),
      availability: 'missing',
    })]));
  });

  it('persists the current claimed session owner by exact task id', () => {
    const engine = open(config(), false);
    const context = (engine as unknown as {
      ctx: {
        agents: Map<string, {
          id: string;
          agent_id: string;
          assigned_at: string;
          status: 'running';
          subgraph_node_ids: string[];
        }>;
      };
    }).ctx;
    context.agents.set('task-original', {
      id: 'task-original',
      agent_id: 'agent-original',
      assigned_at: NOW,
      status: 'running',
      subgraph_node_ids: [],
    });
    context.agents.set('task-current', {
      id: 'task-current',
      agent_id: 'agent-current',
      assigned_at: NOW,
      status: 'running',
      subgraph_node_ids: [],
    });

    const descriptor = engine.recordSessionDescriptor({
      id: 'session-owned',
      kind: 'local_pty',
      transport: 'pty',
      state: 'connected',
      title: 'owned shell',
      agent_id: 'agent-original',
      claimed_by: 'task-current',
      started_at: NOW,
      last_activity_at: NOW,
      capabilities: {
        has_stdin: true,
        has_stdout: true,
        supports_resize: true,
        supports_signals: true,
        tty_quality: 'full',
      },
      buffer_end_pos: 0,
    });

    expect(descriptor.owner_task_id).toBe('task-current');
  });

  it('normalizes optional empty session metadata and round-trips ephemeral port zero', () => {
    const engine = open(config(), false);
    const descriptor = engine.recordSessionDescriptor({
      id: 'session-boundary',
      kind: 'socket',
      transport: 'tcp-listen',
      state: 'pending',
      mode: 'listen',
      title: 'ephemeral listener',
      host: '',
      user: '',
      target_node: '',
      action_id: '',
      port: 0,
      started_at: NOW,
      last_activity_at: NOW,
      capabilities: {
        has_stdin: false,
        has_stdout: true,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'dumb',
      },
      buffer_end_pos: 0,
      default_validation: {
        technique: 'session_command',
        target_ip: '',
      },
    });
    expect(descriptor).toMatchObject({
      session_id: 'session-boundary',
      port: 0,
    });
    expect(descriptor.host).toBeUndefined();
    expect(descriptor.user).toBeUndefined();
    expect(descriptor.target_node).toBeUndefined();
    expect(descriptor.action_id).toBeUndefined();
    expect(descriptor.default_validation?.target_ip).toBeUndefined();
    engine.persistImmediate();
    close(engine);

    const restarted = open(config(), false);
    expect(restarted.isPersistenceWritable()).toBe(true);
    expect(restarted.getSessionDescriptors()).toContainEqual(
      expect.objectContaining({
        session_id: 'session-boundary',
        port: 0,
      }),
    );
  });

  it('backs up a completely replayed V0 engagement before publishing V1', () => {
    writeFileSync(configPath, `${JSON.stringify(config(), null, 2)}\n`);
    const initial = open(config());
    initial.persistImmediate();
    close(initial);

    const legacy = downgradePrimaryToV0(statePath, configPath);
    const journal = new MutationJournal(statePath);
    journal.setNextSeq(legacy.checkpoint, { appliedThroughSeq: legacy.checkpoint });
    journal.append({
      type: 'add_node',
      payload: { props: node('replayed-node') },
      ts: NOW,
    });
    const walBefore = readFileSync(journal.getPath());
    const legacyConfig = JSON.parse(readFileSync(configPath, 'utf8')) as EngagementConfig;

    const migrated = open(legacyConfig);
    expect(migrated.getNode('replayed-node')).toBeDefined();
    const recovery = migrated.getPersistenceRecoveryStatus();
    expect(recovery).toMatchObject({
      complete: true,
      writable: true,
      state_migration: {
        status: 'migrated',
        observed_state_version: 0,
        supported_state_version: 1,
        migration_required: false,
      },
    });
    const backupPath = recovery.state_migration?.backup_path;
    expect(backupPath).toBeDefined();
    const backup = verifyStateMigrationBackup(join(backupPath!, 'manifest.json'));
    const backedState = backup.manifest.files.find(entry => entry.role === 'state');
    const backedWal = backup.manifest.files.find(entry => entry.role === 'journal');
    const backedConfig = backup.manifest.files.find(entry => entry.role === 'config');
    expect(backedState?.sha256).toBe(
      createHash('sha256').update(legacy.stateBytes).digest('hex'),
    );
    expect(backedWal?.sha256).toBe(createHash('sha256').update(walBefore).digest('hex'));
    expect(backedConfig?.sha256).toBe(
      createHash('sha256').update(legacy.configBytes!).digest('hex'),
    );
    expect(JSON.parse(readFileSync(statePath, 'utf8'))).toMatchObject({
      state_version: 1,
      journal_version: CURRENT_JOURNAL_VERSION,
      config: { config_revision: 1 },
    });
    expect(JSON.parse(readFileSync(configPath, 'utf8'))).toMatchObject({
      config_revision: 1,
    });
  });

  it('publishes structural V1 migration even when config semantics require reconciliation', () => {
    writeFileSync(configPath, `${JSON.stringify(config(), null, 2)}\n`);
    const initial = open(config());
    initial.persistImmediate();
    close(initial);
    downgradePrimaryToV0(statePath, configPath);
    const externalConfig = {
      ...JSON.parse(readFileSync(configPath, 'utf8')) as EngagementConfig,
      name: 'Externally changed name',
    };
    const externalBytes = Buffer.from(`${JSON.stringify(externalConfig, null, 2)}\n`);
    writeFileSync(configPath, externalBytes);

    const migrated = open(externalConfig);
    expect(migrated.getConfigRecoveryStatus()).toMatchObject({
      status: 'diverged',
      resolution_required: true,
    });
    expect(migrated.getPersistenceRecoveryStatus()).toMatchObject({
      writable: false,
      state_migration: {
        status: 'migrated',
      },
      state_recovery: {
        complete: true,
        writable: true,
      },
    });
    expect(JSON.parse(readFileSync(statePath, 'utf8'))).toMatchObject({
      state_version: 1,
      journal_version: CURRENT_JOURNAL_VERSION,
    });
    expect(readFileSync(configPath)).toEqual(externalBytes);
    expect(existsSync(`${statePath}.migration-intent.json`)).toBe(false);
  });

  it('retains migration backup metadata when restart retires a post-publication intent', () => {
    const initial = open(config(), false);
    initial.persistImmediate();
    close(initial);
    const legacy = downgradePrimaryToV0(statePath);
    const release = acquireStateMigrationLease(statePath);
    const backup = prepareStateMigrationBackup({ stateFilePath: statePath });
    activateStateMigration(statePath, backup, release.token);
    release();

    const published = JSON.parse(legacy.stateBytes.toString()) as Record<string, unknown>;
    published.state_version = CURRENT_STATE_VERSION;
    published.journal_version = CURRENT_JOURNAL_VERSION;
    published.journalCheckpointSemantics = 'contiguous_committed_transactions_v2';
    writeFileSync(statePath, refreshCompactionAuthority(published));

    const resumed = open(config(), false);
    expect(resumed.getPersistenceRecoveryStatus().state_migration).toMatchObject({
      status: 'migrated',
      observed_state_version: LEGACY_STATE_VERSION,
      observed_journal_version: LEGACY_JOURNAL_VERSION,
      supported_state_version: CURRENT_STATE_VERSION,
      supported_journal_version: CURRENT_JOURNAL_VERSION,
      migration_required: false,
      backup_path: backup.directory,
      backup_manifest_sha256: backup.manifest_sha256,
    });
    expect(existsSync(`${statePath}.migration-intent.json`)).toBe(false);
  });

  it('backs up V0 before replay but does not activate migration when WAL replay is incomplete', () => {
    writeFileSync(configPath, `${JSON.stringify(config(), null, 2)}\n`);
    const initial = open(config());
    initial.persistImmediate();
    close(initial);
    const legacy = downgradePrimaryToV0(statePath, configPath);
    const journalPath = MutationJournal.pathForState(statePath);
    writeFileSync(journalPath, '{"seq":1');
    const walBefore = readFileSync(journalPath);

    const degraded = open(
      JSON.parse(readFileSync(configPath, 'utf8')) as EngagementConfig,
    );
    const recovery = degraded.getPersistenceRecoveryStatus();
    expect(recovery).toMatchObject({
      complete: false,
      writable: false,
      state_migration: {
        status: 'blocked',
        observed_state_version: 0,
        observed_journal_version: LEGACY_JOURNAL_VERSION,
        migration_required: true,
        backup_path: expect.any(String),
        backup_manifest_sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      },
      journal: {
        format_version: LEGACY_JOURNAL_VERSION,
      },
    });
    expect(readFileSync(statePath)).toEqual(legacy.stateBytes);
    expect(readFileSync(journalPath)).toEqual(walBefore);
    expect(verifyStateMigrationBackup(
      join(recovery.state_migration!.backup_path!, 'manifest.json'),
    ).manifest.files.some(entry => entry.role === 'journal' && entry.present)).toBe(true);
    expect(existsSync(`${statePath}.migration-intent.json`)).toBe(false);
  });

  it.each([
    { field: 'state_version', value: 2 },
    { field: 'journal_version', value: 3 },
  ])('keeps future $field bytes unchanged across repeated restarts', ({ field, value }) => {
    writeFileSync(configPath, `${JSON.stringify(config(), null, 2)}\n`);
    const initial = open(config());
    initial.addNode(node('future-node'));
    initial.persistImmediate();
    close(initial);
    const snapshotDirectory = join(directory, '.snapshots');
    mkdirSync(snapshotDirectory, { recursive: true });
    const snapshotPath = join(
      snapshotDirectory,
      'state-migration-test.snap-2026-07-16T00-00-00-000Z-1.json',
    );
    writeFileSync(snapshotPath, readFileSync(statePath));
    const future = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, unknown>;
    future[field] = value;
    const futureBytes = Buffer.from(JSON.stringify(future));
    writeFileSync(statePath, futureBytes);
    const snapshotBytes = readFileSync(snapshotPath);
    const configBytes = readFileSync(configPath);
    const beforeNames = readdirSync(directory).sort();

    for (let restart = 0; restart < 3; restart++) {
      const degraded = open(
        JSON.parse(readFileSync(configPath, 'utf8')) as EngagementConfig,
      );
      const migration = degraded.getPersistenceRecoveryStatus().state_migration;
      expect(degraded.isPersistenceWritable()).toBe(false);
      expect(migration).toMatchObject({
        status: 'blocked',
        supported_state_version: 1,
        supported_journal_version: CURRENT_JOURNAL_VERSION,
      });
      if (field === 'state_version') {
        expect(migration?.observed_state_version).toBe(2);
      } else {
        expect(migration?.observed_journal_version).toBe(3);
      }
      close(degraded);
      expect(readFileSync(statePath)).toEqual(futureBytes);
      expect(readFileSync(snapshotPath)).toEqual(snapshotBytes);
      expect(readFileSync(configPath)).toEqual(configBytes);
      expect(readdirSync(directory).sort()).toEqual(beforeNames);
    }
  });

  it('does not create recovery sidecars or lock directories while inspecting a future state', () => {
    const futureBytes = Buffer.from(JSON.stringify({
      state_version: 2,
      journal_version: CURRENT_JOURNAL_VERSION,
      config: config(),
      graph: { attributes: {}, nodes: [], edges: [] },
    }));
    writeFileSync(statePath, futureBytes);
    const before = readdirSync(directory).sort();

    const degraded = open(config(), false);
    expect(degraded.isPersistenceWritable()).toBe(false);
    close(degraded);

    expect(readFileSync(statePath)).toEqual(futureBytes);
    expect(readdirSync(directory).sort()).toEqual(before);
  });

  it.each([
    { field: 'state_version', value: 0 },
    { field: 'state_version', value: null },
    { field: 'state_version', value: '1' },
    { field: 'journal_version', value: 0 },
    { field: 'journal_version', value: null },
    { field: 'journal_version', value: '1' },
  ])('keeps invalid explicit $field=$value byte-preserved across repeated restarts', ({
    field,
    value,
  }) => {
    writeFileSync(configPath, `${JSON.stringify(config(), null, 2)}\n`);
    const initial = open(config());
    initial.addNode(node('invalid-version-node'));
    initial.persistImmediate();
    close(initial);
    const invalid = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, unknown>;
    invalid[field] = value;
    const invalidBytes = Buffer.from(JSON.stringify(invalid));
    writeFileSync(statePath, invalidBytes);
    const configBytes = readFileSync(configPath);
    const beforeNames = readdirSync(directory).sort();

    for (let restart = 0; restart < 3; restart++) {
      const degraded = open(
        JSON.parse(readFileSync(configPath, 'utf8')) as EngagementConfig,
      );
      expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
        outcome: 'incomplete',
        source: 'state',
        complete: false,
        writable: false,
        state_migration: {
          status: 'blocked',
          migration_required: false,
        },
      });
      expect(inspectStateMigration({
        stateFilePath: statePath,
        configFilePath: configPath,
      })).toMatchObject({
        status: 'blocked',
        ready: false,
        migration_required: false,
      });
      close(degraded);
      expect(readFileSync(statePath)).toEqual(invalidBytes);
      expect(readFileSync(configPath)).toEqual(configBytes);
      expect(readdirSync(directory).sort()).toEqual(beforeNames);
    }
  });

  it('does not reseed over a recognized but malformed V1 envelope', () => {
    const initial = open(config(), false);
    initial.addNode(node('must-survive-invalid-v1'));
    initial.persistImmediate();
    close(initial);
    rmSync(join(directory, '.snapshots'), { recursive: true, force: true });
    const malformed = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, unknown>;
    malformed.graph = {
      attributes: {},
      nodes: [
        { key: 'duplicate-node', attributes: {} },
        { key: 'duplicate-node', attributes: {} },
      ],
      edges: [],
    };
    const malformedBytes = Buffer.from(JSON.stringify(malformed));
    writeFileSync(statePath, malformedBytes);

    for (let restart = 0; restart < 2; restart++) {
      const degraded = open(config(), false);
      expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
        outcome: 'incomplete',
        source: 'state',
        complete: false,
        writable: false,
        state_migration: {
          status: 'blocked',
          observed_state_version: 1,
        },
      });
      close(degraded);
      expect(readFileSync(statePath)).toEqual(malformedBytes);
    }
  });

  it('does not overwrite a checksum-valid malformed V1 head from an older valid snapshot', () => {
    const initial = open(config(), false);
    initial.addNode(node('snapshot-node'));
    initial.persistImmediate();
    close(initial);
    const snapshotDirectory = join(directory, '.snapshots');
    mkdirSync(snapshotDirectory, { recursive: true });
    const snapshotPath = join(
      snapshotDirectory,
      'state-migration-test.snap-2026-07-16T00-00-00-000Z-1.json',
    );
    const snapshotBytes = readFileSync(statePath);
    writeFileSync(snapshotPath, snapshotBytes);

    const malformed = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, unknown>;
    malformed.graph = {
      attributes: {},
      nodes: [
        { key: 'duplicate-node', attributes: {} },
        { key: 'duplicate-node', attributes: {} },
      ],
      edges: [],
    };
    const malformedBytes = refreshCompactionAuthority(malformed);
    writeFileSync(statePath, malformedBytes);

    const degraded = open(config(), false);
    expect(degraded.getPersistenceRecoveryStatus()).toMatchObject({
      complete: false,
      writable: false,
      state_migration: {
        status: 'blocked',
        observed_state_version: 1,
      },
    });
    expect(readFileSync(statePath)).toEqual(malformedBytes);
    expect(readFileSync(snapshotPath)).toEqual(snapshotBytes);
    expect(inspectStateMigration({ stateFilePath: statePath })).toMatchObject({
      status: 'blocked',
      observed_state_version: 1,
      ready: false,
    });
  });

  it('backs up a missing config as an absent entry and reuses the verified backup', () => {
    writeFileSync(statePath, JSON.stringify({ config: config(), graph: { attributes: {}, nodes: [], edges: [] } }));
    const missingConfig = join(directory, 'missing-engagement.json');
    const backup = createStateMigrationBackup({
      stateFilePath: statePath,
      configFilePath: missingConfig,
    });
    expect(backup.manifest.files).toContainEqual({
      role: 'config',
      original_path: missingConfig,
      present: false,
    });
    expect(findReusableStateMigrationBackup({
      stateFilePath: statePath,
      configFilePath: missingConfig,
    })?.manifest_sha256).toBe(backup.manifest_sha256);
  });

  it('captures current config and intent CAS recovery artifacts', () => {
    writeFileSync(statePath, JSON.stringify({
      config: config(),
      graph: { attributes: {}, nodes: [], edges: [] },
    }));
    writeFileSync(configPath, JSON.stringify(config()));
    const artifacts = [
      `${configPath}.overwatch-cas-1-a.previous`,
      `${configPath}.overwatch-cas-1-b.previous.archived`,
      `${configPath}.overwatch-cas-1-c.previous.target`,
      `${configPath}.write-intent.json.overwatch-cas-1-d.previous.archived`,
      `${configPath}.write-intent.json.conflict-${'a'.repeat(64)}.json`,
    ];
    for (const [index, path] of artifacts.entries()) {
      writeFileSync(path, `artifact-${index}`);
    }
    const backup = createStateMigrationBackup({
      stateFilePath: statePath,
      configFilePath: configPath,
    });
    const backedPaths = backup.manifest.files
      .filter(entry => entry.role === 'config_recovery_artifact')
      .map(entry => entry.original_path);
    expect(backedPaths).toEqual(expect.arrayContaining(artifacts));
  });

  it('rejects a migration backup after any copied artifact changes', () => {
    writeFileSync(statePath, JSON.stringify({
      config: config(),
      graph: { attributes: {}, nodes: [], edges: [] },
    }));
    const backup = createStateMigrationBackup({ stateFilePath: statePath });
    const stateEntry = backup.manifest.files.find(entry => entry.role === 'state')!;
    writeFileSync(join(backup.directory, stateEntry.backup_path!), 'tampered');
    expect(() => verifyStateMigrationBackup(backup.manifest_path))
      .toThrow(/checksum mismatch/);
  });

  it('refuses to reuse an activated migration backup after any source changes', () => {
    writeFileSync(statePath, JSON.stringify({
      config: config(),
      graph: { attributes: {}, nodes: [], edges: [] },
    }));
    writeFileSync(configPath, JSON.stringify(config()));
    const release = acquireStateMigrationLease(statePath);
    const backup = prepareStateMigrationBackup({
      stateFilePath: statePath,
      configFilePath: configPath,
    });
    activateStateMigration(statePath, backup, release.token);
    release();

    writeFileSync(statePath, JSON.stringify({
      config: config(),
      graph: { attributes: {}, nodes: [{ key: 'new', attributes: {} }], edges: [] },
    }));
    expect(() => prepareStateMigrationBackup({
      stateFilePath: statePath,
      configFilePath: configPath,
    })).toThrow(/sources changed|incomplete backup/);
    expect(inspectStateMigration({
      stateFilePath: statePath,
      configFilePath: configPath,
    })).toMatchObject({
      status: 'blocked',
      ready: false,
    });
  });

  it('blocks ordinary WAL, state, and active-config writes while another migration owns the state', () => {
    writeFileSync(configPath, `${JSON.stringify(config(), null, 2)}\n`);
    const initial = open(config());
    initial.persistImmediate();
    close(initial);
    const stateBefore = readFileSync(statePath);
    const configBefore = readFileSync(configPath);
    const release = acquireStateMigrationLease(statePath);

    const journal = new MutationJournal(statePath);
    expect(() => journal.append({
      type: 'add_node',
      payload: { props: node('blocked-node') },
      ts: NOW,
    })).toThrow(/migration|blocked/i);

    const blocked = open(
      JSON.parse(readFileSync(configPath, 'utf8')) as EngagementConfig,
    );
    expect(blocked.isPersistenceWritable()).toBe(false);
    expect(() => blocked.persistImmediate()).toThrow(/migration|degraded/i);
    expect(() => blocked.updateConfig({ name: 'must-not-land' })).toThrow(/migration|degraded/i);
    expect(readFileSync(statePath)).toEqual(stateBefore);
    expect(readFileSync(configPath)).toEqual(configBefore);

    release();
    expect(blocked.isPersistenceWritable()).toBe(false);
    expect(blocked.getPersistenceRecoveryStatus().reason).toMatch(/restart|migration owner/i);
  });

  it('holds an exclusive migration lease until the V1 publication boundary releases it', () => {
    const release = acquireStateMigrationLease(statePath);
    expect(() => acquireStateMigrationLease(statePath)).toThrow(/already owned/);
    release();
    const releaseAgain = acquireStateMigrationLease(statePath);
    releaseAgain();
    expect(existsSync(`${statePath}.migration-lock`)).toBe(false);
  });

  it('rejects symlinked migration sources instead of producing an incomplete backup', () => {
    const realState = join(directory, 'real-state.json');
    writeFileSync(realState, '{}');
    symlinkSync(realState, statePath);
    expect(() => createStateMigrationBackup({ stateFilePath: statePath }))
      .toThrow();
    const backupRoot = join(directory, '.migration-backups');
    if (existsSync(backupRoot)) {
      expect(readdirSync(backupRoot).some(name => !name.endsWith('.staging'))).toBe(false);
    }
  });

  it('checks snapshot fallback and blocks malformed WAL without mutating sources', () => {
    const initial = open(config(), false);
    initial.persistImmediate();
    close(initial);
    const legacy = downgradePrimaryToV0(statePath);
    const snapshotDirectory = join(directory, '.snapshots');
    mkdirSync(snapshotDirectory, { recursive: true });
    const snapshotPath = join(
      snapshotDirectory,
      'state-migration-test.snap-2026-07-16T00-00-00-000Z-1.json',
    );
    renameSync(statePath, snapshotPath);
    const journalPath = MutationJournal.pathForState(statePath);
    writeFileSync(journalPath, `${JSON.stringify({
      seq: legacy.checkpoint + 1,
      ts: NOW,
      type: 'future_mutation',
      payload: {},
    })}\n`);
    const snapshotBefore = readFileSync(snapshotPath);
    const walBefore = readFileSync(journalPath);

    const inspection = inspectStateMigration({ stateFilePath: statePath });
    expect(inspection).toMatchObject({
      status: 'blocked',
      selected_base: snapshotPath,
      observed_state_version: 0,
      migration_required: true,
      ready: false,
    });
    expect(inspection.blockers.join(' ')).toMatch(/WAL replay preflight failed/);
    expect(readFileSync(snapshotPath)).toEqual(snapshotBefore);
    expect(readFileSync(journalPath)).toEqual(walBefore);
  });
});
