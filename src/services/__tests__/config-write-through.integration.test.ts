import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { parseEngagementConfig } from '../../config.js';
import type { EngagementConfig } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import { computeConfigHash, withConfigMetadata } from '../engagement-config-service.js';
import type { EngineContext } from '../engine-context.js';
import type { DropNodeMutationPayloadV1, ScopeUpdatedMutationPayloadV1 } from '../mutation-journal.js';
import { planIdentityRewrite } from '../identity-reconciliation.js';

function legacyConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'write-through',
    name: 'Write Through',
    created_at: '2026-01-01T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', enabled: false, max_noise: 0.5 },
    engagement_nonce: 'a'.repeat(64),
    hash_chain_enabled: true,
    subagent_isolation: 'in_process',
    ...overrides,
  };
}

function internals(engine: GraphEngine): EngineContext {
  return (engine as unknown as { ctx: EngineContext }).ctx;
}

describe('revisioned active config write-through', () => {
  let dir: string;
  let configPath: string;
  let statePath: string;
  const engines: GraphEngine[] = [];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ow-config-integration-'));
    configPath = join(dir, 'engagement.json');
    statePath = join(dir, 'state.json');
  });

  afterEach(() => {
    for (const engine of engines) engine.dispose();
    rmSync(dir, { recursive: true, force: true });
  });

  function start(config?: EngagementConfig): GraphEngine {
    const engine = new GraphEngine(
      config ?? parseEngagementConfig(readFileSync(configPath, 'utf8')),
      statePath,
      configPath,
    );
    engines.push(engine);
    return engine;
  }

  it('converges a legacy file, then writes every active update to file and state', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());

    expect(first.getConfig()).toMatchObject({ config_revision: 1 });
    expect(parseEngagementConfig(readFileSync(configPath, 'utf8'))).toEqual(first.getConfig());

    const updated = first.updateConfig({ name: 'Durably Renamed', opsec: { enabled: true } });
    expect(updated).toMatchObject({ name: 'Durably Renamed', config_revision: 2, opsec: { enabled: true } });
    expect(parseEngagementConfig(readFileSync(configPath, 'utf8'))).toEqual(updated);

    first.dispose();
    const restarted = start();
    expect(restarted.getConfig()).toEqual(updated);
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({
      writable: true,
      config_recovery: { resolution_required: false, file_revision: 2, state_revision: 2 },
    });
  });

  it('starts read-only on unexplained divergence and resolves with optimistic hashes', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const stateConfig = first.updateConfig({ name: 'Durable State' });
    first.dispose();

    const external = withConfigMetadata({ ...stateConfig, name: 'External File Edit' }, 3);
    writeFileSync(configPath, JSON.stringify(external));
    const diverged = start(external);
    const status = diverged.getPersistenceRecoveryStatus();
    expect(status).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      config_recovery: { status: 'diverged', resolution_required: true },
    });
    expect(diverged.getConfig().name).toBe('Durable State');
    expect(() => diverged.updateConfig({ name: 'Blocked' })).toThrow(/read-only/i);

    const resolved = diverged.resolveConfigDivergence({
      mode: 'use_file',
      expected_file_hash: status.config_recovery!.file_hash!,
      expected_state_hash: status.config_recovery!.state_hash!,
    });
    expect(resolved.config).toMatchObject({ name: 'External File Edit', config_revision: 4 });
    expect(diverged.isPersistenceWritable()).toBe(true);
    expect(parseEngagementConfig(readFileSync(configPath, 'utf8'))).toEqual(diverged.getConfig());
    const resolutionEvent = diverged.getFullHistory().find(event =>
      event.event_type === 'config_updated'
      && event.details?.source === 'config_reconcile_use_file',
    );
    expect(resolutionEvent?.details).toMatchObject({
      expected_file_hash: status.config_recovery!.file_hash,
      previous_state_hash: status.config_recovery!.state_hash,
      target_hash: resolved.config.config_hash,
      intent_checksum: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
  });

  it('carries a quarantined intent audit through file-authoritative scope reconciliation', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const current = first.getConfig();
    const external = withConfigMetadata({
      ...current,
      name: 'External scope authority',
      scope: {
        ...current.scope,
        cidrs: [...current.scope.cidrs, '10.66.0.0/24'],
      },
    }, 9);
    const persistence = (first as unknown as {
      persistence: { persistImmediate: () => void };
    }).persistence;
    const persistImmediate = persistence.persistImmediate.bind(persistence);
    persistence.persistImmediate = () => {
      persistImmediate();
      writeFileSync(configPath, JSON.stringify(external));
    };

    expect(() => first.updateConfig({ name: 'Durable interrupted target' }))
      .toThrow(/did not converge/i);
    persistence.persistImmediate = persistImmediate;
    const intentPath = `${configPath}.write-intent.json`;
    expect(existsSync(intentPath)).toBe(true);
    first.dispose();

    const restarted = start(external);
    const blocked = restarted.getPersistenceRecoveryStatus();
    expect(blocked).toMatchObject({
      writable: false,
      config_recovery: {
        status: 'diverged',
        intent_present: false,
        allowed_resolutions: ['use_file', 'use_state'],
        conflicted_intent: {
          archive_path: expect.stringContaining('.write-intent.json.conflict-'),
        },
      },
    });
    const conflict = structuredClone(blocked.config_recovery!.conflicted_intent!);
    expect(existsSync(conflict.archive_path)).toBe(true);
    expect(existsSync(intentPath)).toBe(false);

    const resolved = restarted.resolveConfigDivergence({
      mode: 'use_file',
      expected_file_hash: blocked.config_recovery!.file_hash!,
      expected_state_hash: blocked.config_recovery!.state_hash!,
    });
    expect(resolved.config).toMatchObject({
      name: 'External scope authority',
      config_revision: 10,
      scope: { cidrs: expect.arrayContaining(['10.66.0.0/24']) },
    });
    const resolutionEvents = restarted.getFullHistory().filter(event =>
      event.event_type === 'config_updated'
      && event.details?.resolution === 'use_file',
    );
    expect(resolutionEvents).toHaveLength(1);
    expect(resolutionEvents[0].details).toMatchObject({
      superseded_config_intent: conflict,
    });
    expect(existsSync(conflict.archive_path)).toBe(true);

    restarted.dispose();
    const finalRestart = start();
    expect(finalRestart.getPersistenceRecoveryStatus()).toMatchObject({
      writable: true,
      config_recovery: { resolution_required: false, intent_present: false },
    });
    expect(finalRestart.getConfig()).toEqual(resolved.config);
  });

  it('routes generic active config scope edits through the scope transaction', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const engine = start(legacyConfig());
    const cold = {
      id: 'host-10-61-0-8',
      type: 'host',
      label: '10.61.0.8',
      ip: '10.61.0.8',
      discovered_at: '2026-01-01T00:00:05.000Z',
      last_seen_at: '2026-01-01T00:00:05.000Z',
      provenance: 'test',
      confidence: 1,
    };
    internals(engine).coldAdd(cold);
    engine.persistImmediate();

    const updated = engine.updateConfig({
      name: 'Scope and name together',
      scope: { ...engine.getConfig().scope, cidrs: [...engine.getConfig().scope.cidrs, '10.61.0.0/24'] },
    });

    expect(updated.name).toBe('Scope and name together');
    expect(updated.scope.cidrs).toContain('10.61.0.0/24');
    expect(engine.getNode(cold.id)).toMatchObject({ ip: cold.ip });
    expect(engine.exportGraph().cold_nodes ?? []).not.toContainEqual(expect.objectContaining({ id: cold.id }));
    expect(engine.getFullHistory().filter(event => event.event_type === 'scope_updated')).toHaveLength(1);
    expect(parseEngagementConfig(readFileSync(configPath, 'utf8'))).toEqual(updated);
  });

  it('commits objective achievement through the revisioned config owner and survives restart', () => {
    const objectiveId = 'objective-obtain-crown-host';
    const initial = legacyConfig({
      objectives: [{
        id: objectiveId,
        description: 'Obtain the crown host',
        target_node_type: 'host',
        target_criteria: { hostname: 'crown.example.test' },
        achieved: false,
      }],
    });
    writeFileSync(configPath, JSON.stringify(initial));
    const first = start(initial);
    const beforeRevision = first.getConfig().config_revision!;

    first.ingestFinding({
      id: 'finding-objective-achieved',
      timestamp: '2026-01-01T00:00:05.000Z',
      agent_id: 'agent-objective',
      action_id: 'action-objective',
      tool_name: 'objective-test',
      nodes: [{
        id: 'host-crown',
        type: 'host',
        label: 'crown.example.test',
        hostname: 'crown.example.test',
        obtained: true,
      }],
      edges: [],
    });

    const achieved = first.getConfig();
    expect(achieved.config_revision).toBe(beforeRevision + 1);
    expect(achieved.objectives).toContainEqual(expect.objectContaining({
      id: objectiveId,
      achieved: true,
      achieved_at: expect.any(String),
    }));
    expect(parseEngagementConfig(readFileSync(configPath, 'utf8'))).toEqual(achieved);
    expect(first.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      config_recovery: {
        resolution_required: false,
        file_revision: achieved.config_revision,
        state_revision: achieved.config_revision,
        runtime_revision: achieved.config_revision,
        file_hash: achieved.config_hash,
        state_hash: achieved.config_hash,
        runtime_hash: achieved.config_hash,
      },
    });

    // Do not add a separate graph snapshot after ingestion. The config service
    // itself must have made the achieved objective durable before returning.
    first.dispose();
    const restarted = start();
    expect(restarted.getConfig()).toEqual(achieved);
    expect(restarted.getConfig().objectives[0]).toMatchObject({ achieved: true });
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({ complete: true, writable: true });
  });

  it('synchronizes file, runtime, and durable state after rolling back an older snapshot', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const original = first.getConfig();

    // Rotate the revision-1 primary into the retained snapshot inventory.
    internals(first).lastSnapshotTime = 0;
    first.persistImmediate();
    const snapshot = first.listSnapshots()[0];
    expect(snapshot).toBeDefined();

    const newer = first.updateConfig({ name: 'Configuration after snapshot' });
    expect(newer.config_revision).toBe((original.config_revision ?? 0) + 1);

    expect(first.rollbackToSnapshot(snapshot)).toBe(true);
    const restored = first.getConfig();
    expect(restored.name).toBe(original.name);
    expect(restored.config_revision).toBeGreaterThan(newer.config_revision!);
    expect(parseEngagementConfig(readFileSync(configPath, 'utf8'))).toEqual(restored);
    expect(first.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      config_recovery: {
        status: 'recovered',
        resolution_required: false,
        file_revision: restored.config_revision,
        state_revision: restored.config_revision,
        runtime_revision: restored.config_revision,
        file_hash: restored.config_hash,
        state_hash: restored.config_hash,
        runtime_hash: restored.config_hash,
      },
    });
    expect(first.getFullHistory().filter(event =>
      event.event_type === 'config_updated'
      && event.details?.source === 'snapshot.rollback',
    )).toHaveLength(1);

    first.dispose();
    const restarted = start();
    expect(restarted.getConfig()).toEqual(restored);
    expect(parseEngagementConfig(readFileSync(configPath, 'utf8'))).toEqual(restored);
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({ complete: true, writable: true });
  });

  it('retains rollback authority across a crash before config adoption', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const original = first.getConfig();
    internals(first).lastSnapshotTime = 0;
    first.persistImmediate();
    const snapshot = first.listSnapshots()[0]!;
    const newer = first.updateConfig({ name: 'Newer file that rollback must not restore' });

    const internal = first as unknown as {
      configService: { adoptRestoredRuntimeConfig: (source: string) => EngagementConfig };
    };
    internal.configService.adoptRestoredRuntimeConfig = () => {
      throw new Error('synthetic crash before config adoption');
    };

    expect(() => first.rollbackToSnapshot(snapshot)).toThrow('synthetic crash');
    expect(existsSync(`${statePath}.rollback-intent.json`)).toBe(true);
    expect(parseEngagementConfig(readFileSync(configPath, 'utf8'))).toEqual(newer);
    first.dispose();

    const restarted = start();
    expect(restarted.getConfig().name).toBe(original.name);
    expect(restarted.getConfig().config_revision).toBeGreaterThan(newer.config_revision!);
    expect(parseEngagementConfig(readFileSync(configPath, 'utf8'))).toEqual(restarted.getConfig());
    expect(existsSync(`${statePath}.rollback-intent.json`)).toBe(false);
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      config_recovery: { resolution_required: false },
    });
  });

  it('completes deferred agent, session, and approval reconciliation before reopening writes', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const at = '2026-01-01T00:00:05.500Z';
    first.addNode({ id: 'user-stale-runtime', type: 'user', label: 'operator', discovered_at: at, confidence: 1 });
    first.addNode({ id: 'host-stale-runtime', type: 'host', label: 'target', discovered_at: at, confidence: 1 });
    first.addEdge('user-stale-runtime', 'host-stale-runtime', {
      type: 'HAS_SESSION',
      confidence: 1,
      discovered_at: at,
      tested: true,
      session_id: 'session-before-restart',
      live_session_ids: ['session-before-restart'],
      session_live: true,
    });
    first.registerAgent({
      id: 'task-before-diverged-restart',
      agent_id: 'agent-before-diverged-restart',
      assigned_at: at,
      status: 'running',
      subgraph_node_ids: ['host-stale-runtime'],
    });
    first.recordApprovalRequest({
      action_id: 'approval-before-diverged-restart',
      description: 'pending target action',
      agent_id: 'agent-before-diverged-restart',
      opsec_context: {
        global_noise_spent: 0,
        noise_budget_remaining: 1,
        recommended_approach: 'normal',
        defensive_signals: [],
      },
      validation_result: 'valid',
    });
    first.persistImmediate();
    const durable = first.getConfig();
    first.dispose();

    const external = withConfigMetadata({ ...durable, name: 'Unexplained operator edit' }, 9);
    writeFileSync(configPath, JSON.stringify(external));
    const diverged = start(external);
    const edgeId = diverged.findEdgeId('user-stale-runtime', 'host-stale-runtime', 'HAS_SESSION')!;
    expect(diverged.isPersistenceWritable()).toBe(false);
    expect(diverged.getTask('task-before-diverged-restart')?.status).toBe('running');
    expect(internals(diverged).graph.getEdgeAttribute(edgeId, 'session_live')).toBe(true);
    expect(diverged.getApprovalRequest('approval-before-diverged-restart')?.status).toBe('pending');

    const recovery = diverged.getConfigRecoveryStatus();
    diverged.resolveConfigDivergence({
      mode: 'use_state',
      expected_file_hash: recovery.file_hash!,
      expected_state_hash: recovery.state_hash!,
    });

    expect(diverged.getTask('task-before-diverged-restart')?.status).toBe('interrupted');
    expect(internals(diverged).graph.getEdgeAttribute(edgeId, 'session_live')).toBe(false);
    expect(internals(diverged).graph.getEdgeAttribute(edgeId, 'live_session_ids')).toEqual([]);
    expect(diverged.getApprovalRequest('approval-before-diverged-restart')).toMatchObject({
      status: 'aborted',
      reason: expect.stringContaining('restart'),
    });
    expect(diverged.getPersistenceRecoveryStatus()).toMatchObject({ complete: true, writable: true });

    diverged.dispose();
    const restarted = start();
    expect(restarted.getTask('task-before-diverged-restart')?.status).toBe('interrupted');
    expect(restarted.getApprovalRequest('approval-before-diverged-restart')?.status).toBe('aborted');
    const restartedEdge = restarted.findEdgeId('user-stale-runtime', 'host-stale-runtime', 'HAS_SESSION')!;
    expect(internals(restarted).graph.getEdgeAttribute(restartedEdge, 'session_live')).toBe(false);
  });

  it('applies a file-authoritative scope diff with promotions and durable audit', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const cold = {
      id: 'host-10-62-0-8',
      type: 'host',
      label: '10.62.0.8',
      ip: '10.62.0.8',
      discovered_at: '2026-01-01T00:00:06.000Z',
      last_seen_at: '2026-01-01T00:00:06.000Z',
      provenance: 'test',
      confidence: 1,
    };
    internals(first).coldAdd(cold);
    first.persistImmediate();
    const state = first.getConfig();
    first.dispose();

    const external = withConfigMetadata({
      ...state,
      scope: { ...state.scope, cidrs: [...state.scope.cidrs, '10.62.0.0/24'] },
    }, (state.config_revision ?? 0) + 1);
    writeFileSync(configPath, JSON.stringify(external));
    const diverged = start(external);
    const recovery = diverged.getConfigRecoveryStatus();
    const resolved = diverged.resolveConfigDivergence({
      mode: 'use_file',
      expected_file_hash: recovery.file_hash!,
      expected_state_hash: recovery.state_hash!,
    });

    expect(resolved.config.scope.cidrs).toContain('10.62.0.0/24');
    expect(diverged.getNode(cold.id)).toMatchObject({ ip: cold.ip });
    expect(diverged.exportGraph().cold_nodes ?? []).not.toContainEqual(expect.objectContaining({ id: cold.id }));
    const scopeEvents = diverged.getFullHistory().filter(event => event.event_type === 'scope_updated');
    expect(scopeEvents).toHaveLength(1);
    expect(scopeEvents[0].details).toMatchObject({
      source_config_hash: recovery.state_hash,
      source_file_hash: recovery.file_hash,
      target_config_hash: resolved.config.config_hash,
      operation_checksum: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    const configEvents = diverged.getFullHistory().filter(event =>
      event.event_type === 'config_updated' && event.details?.resolution === 'use_file',
    );
    expect(configEvents).toHaveLength(1);
    expect(configEvents[0].details).toMatchObject({
      expected_file_hash: recovery.file_hash,
      previous_state_hash: recovery.state_hash,
      target_hash: resolved.config.config_hash,
      operation_checksum: expect.stringMatching(/^[0-9a-f]{64}$/),
    });

    diverged.dispose();
    const restarted = start();
    expect(restarted.getNode(cold.id)).toMatchObject({ ip: cold.ip });
    expect(restarted.getFullHistory().filter(event => event.event_type === 'scope_updated')).toHaveLength(1);
  });

  it('replays one committed scope operation after a crash before in-memory apply', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const ctx = internals(first);
    const cold = {
      id: 'host-10-20-0-8',
      type: 'host',
      label: '10.20.0.8',
      ip: '10.20.0.8',
      discovered_at: '2026-01-01T00:00:01.000Z',
      last_seen_at: '2026-01-01T00:00:01.000Z',
      provenance: 'test',
      confidence: 1,
    };
    ctx.coldAdd(cold);
    first.persistImmediate();

    const source = first.getConfig();
    const afterScope = { ...source.scope, cidrs: [...source.scope.cidrs, '10.20.0.0/24'] };
    const target = withConfigMetadata(
      { ...source, scope: afterScope },
      (source.config_revision ?? 0) + 1,
    );
    const payload: ScopeUpdatedMutationPayloadV1 = {
      payload_version: 1,
      operation_id: 'scope-crash-test',
      occurred_at: '2026-01-01T00:00:02.000Z',
      reason: 'crash recovery test',
      source_config_hash: computeConfigHash(source),
      source_file_hash: computeConfigHash(source),
      target_config: target,
      before_scope: source.scope,
      after_scope: afterScope,
      promotions: [{
        cold_record: cold,
        hot_node: {
          id: cold.id,
          type: 'host',
          label: cold.label,
          ip: cold.ip,
          discovered_at: cold.discovered_at,
          last_seen_at: cold.last_seen_at,
          discovered_by: cold.provenance,
          confidence: 1,
        },
      }],
      inferred_edges: [],
      inference_events: [],
      affected_node_count: 1,
    };

    // WAL fsync succeeds; the process dies before applying anything.
    ctx.journalMutation('scope_updated', payload as unknown as Record<string, unknown>);
    first.dispose();

    const restarted = start();
    expect(restarted.getConfig().scope.cidrs).toContain('10.20.0.0/24');
    expect(restarted.getNode(cold.id)).toMatchObject({ ip: '10.20.0.8' });
    expect(restarted.exportGraph().cold_nodes ?? []).not.toContainEqual(expect.objectContaining({ id: cold.id }));
    const scopeEvents = restarted.getFullHistory().filter(event =>
      event.event_type === 'scope_updated' && event.details?.operation_id === payload.operation_id,
    );
    expect(scopeEvents).toHaveLength(1);
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({ complete: true, writable: true });

    restarted.dispose();
    const third = start();
    expect(third.getNode(cold.id)).toMatchObject({ ip: '10.20.0.8' });
    expect(third.getFullHistory().filter(event => event.details?.operation_id === payload.operation_id)).toHaveLength(1);
  });

  it('replays non-empty scope inference effects exactly once across second and third restart', () => {
    const config = legacyConfig({
      objectives: [{
        id: 'scope-inference-objective',
        description: 'Recover the scope-derived attack path',
        target_node_type: 'host',
        target_criteria: { ntds_dumped: true },
        achieved: false,
      }],
    });
    writeFileSync(configPath, JSON.stringify(config));
    const first = start(config);
    const ctx = internals(first);
    ctx.inferenceRules.push({
      id: 'rule-scope-recovery-test',
      name: 'Scope recovery test inference',
      description: 'A promoted host creates a deterministic path to the configured objective',
      trigger: { node_type: 'host' },
      produces: [{
        edge_type: 'PATH_TO_OBJECTIVE',
        source_selector: 'trigger_node',
        target_selector: 'nearest_objective',
        confidence: 0.73,
      }],
    });
    const cold = {
      id: 'host-10-21-0-8',
      type: 'host',
      label: '10.21.0.8',
      ip: '10.21.0.8',
      discovered_at: '2026-01-01T00:00:02.100Z',
      last_seen_at: '2026-01-01T00:00:02.100Z',
      provenance: 'test',
      confidence: 1,
    };
    ctx.coldAdd(cold);
    first.persistImmediate();
    const baseSeq = ctx.journalSnapshotSeq;

    // Exercise the public planner so the durable record contains the real
    // frozen inference delta, then simulate process death after append/fsync
    // but before the live applier changes config, cold store, graph, or audit.
    const originalApply = first.applyScopeUpdatedMutation;
    first.applyScopeUpdatedMutation = () => {
      throw new Error('synthetic crash before scope inference apply');
    };
    try {
      expect(() => first.updateScope({
        add_cidrs: ['10.21.0.0/24'],
        reason: 'recover non-empty scope inference',
      })).toThrow('synthetic crash before scope inference apply');
    } finally {
      first.applyScopeUpdatedMutation = originalApply;
    }

    const scopeOperation = ctx.mutationJournal!
      .readTransactionsSince(baseSeq)
      .flatMap(transaction => transaction.operations)
      .find(operation => operation.type === 'scope_updated');
    expect(scopeOperation).toBeDefined();
    const scopePayload = scopeOperation!.payload as unknown as ScopeUpdatedMutationPayloadV1;
    expect(scopePayload.inferred_edges).toHaveLength(1);
    expect(scopePayload.inference_events).toHaveLength(1);
    const operationId = scopePayload.operation_id;
    const inferredEdgeId = scopePayload.inferred_edges[0].edge_id;
    first.dispose();

    for (let restart = 2; restart <= 3; restart++) {
      const recovered = start();
      expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({ complete: true, writable: true });
      expect(recovered.getConfig().scope.cidrs).toContain('10.21.0.0/24');
      expect(recovered.getNode(cold.id)).toMatchObject({ ip: cold.ip });
      expect(recovered.exportGraph().cold_nodes ?? []).not.toContainEqual(expect.objectContaining({ id: cold.id }));
      expect(internals(recovered).graph.hasEdge(inferredEdgeId)).toBe(true);
      expect(recovered.findEdgeId(cold.id, 'obj-scope-inference-objective', 'PATH_TO_OBJECTIVE')).toBe(inferredEdgeId);

      const inferenceEvents = recovered.getFullHistory().filter(event =>
        event.event_type === 'inference_generated'
        && event.details?.scope_operation_id === operationId,
      );
      expect(inferenceEvents, `restart ${restart} inference audit`).toHaveLength(1);
      expect(inferenceEvents[0]).toMatchObject({
        target_node_ids: [cold.id, 'obj-scope-inference-objective'],
        details: {
          rule_id: 'rule-scope-recovery-test',
          edge_type: 'PATH_TO_OBJECTIVE',
          scope_operation_id: operationId,
          scope_event_index: 0,
        },
      });
      expect(recovered.getFullHistory().filter(event =>
        event.event_type === 'scope_updated'
        && event.details?.operation_id === operationId,
      ), `restart ${restart} scope audit`).toHaveLength(1);
      recovered.dispose();
    }
  });

  it('leaves config, cold promotions, and audit untouched when public scope WAL append fails', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const ctx = internals(first);
    const cold = {
      id: 'host-10-22-0-8',
      type: 'host',
      label: '10.22.0.8',
      ip: '10.22.0.8',
      discovered_at: '2026-01-01T00:00:02.200Z',
      last_seen_at: '2026-01-01T00:00:02.200Z',
      provenance: 'test',
      confidence: 1,
    };
    ctx.coldAdd(cold);
    first.persistImmediate();

    const configBefore = structuredClone(first.getConfig());
    const fileBefore = readFileSync(configPath);
    const coldBefore = structuredClone(ctx.coldStore.get(cold.id));
    const historyBefore = structuredClone(first.getFullHistory());
    const journal = ctx.mutationJournal!;
    const walPath = journal.getPath();
    const walBefore = existsSync(walPath) ? readFileSync(walPath) : undefined;
    const originalAppendTransaction = journal.appendTransaction;
    journal.appendTransaction = (() => {
      throw new Error('synthetic scope WAL fsync failure');
    }) as typeof journal.appendTransaction;
    try {
      expect(() => first.updateScope({
        add_cidrs: ['10.22.0.0/24'],
        reason: 'must not apply without a durable scope record',
      })).toThrow('synthetic scope WAL fsync failure');
    } finally {
      journal.appendTransaction = originalAppendTransaction;
    }

    expect(first.getConfig()).toEqual(configBefore);
    expect(readFileSync(configPath)).toEqual(fileBefore);
    expect(ctx.coldStore.get(cold.id)).toEqual(coldBefore);
    expect(first.getNode(cold.id)).toBeNull();
    expect(first.getFullHistory()).toEqual(historyBefore);
    expect(existsSync(`${configPath}.write-intent.json`)).toBe(false);
    expect(existsSync(walPath)).toBe(walBefore !== undefined);
    if (walBefore) expect(readFileSync(walPath)).toEqual(walBefore);
    first.dispose();

    const restarted = start();
    expect(restarted.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      config_recovery: { resolution_required: false },
    });
    expect(restarted.getConfig()).toEqual(configBefore);
    expect(readFileSync(configPath)).toEqual(fileBefore);
    expect(internals(restarted).coldStore.get(cold.id)).toEqual(coldBefore);
    expect(restarted.getNode(cold.id)).toBeNull();
    expect(restarted.getFullHistory().filter(event => event.event_type === 'scope_updated')).toHaveLength(0);
    expect(existsSync(`${configPath}.write-intent.json`)).toBe(false);
  });

  it('does not change config bytes when a later malformed WAL record makes replay incomplete', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    first.flushNow();
    const ctx = internals(first);
    const source = first.getConfig();
    const afterScope = { ...source.scope, cidrs: [...source.scope.cidrs, '10.40.0.0/24'] };
    const target = withConfigMetadata({ ...source, scope: afterScope }, (source.config_revision ?? 0) + 1);
    const payload: ScopeUpdatedMutationPayloadV1 = {
      payload_version: 1,
      operation_id: 'scope-before-malformed-tail',
      occurred_at: '2026-01-01T00:00:03.000Z',
      reason: 'prove partial replay is externally non-destructive',
      source_config_hash: computeConfigHash(source),
      source_file_hash: computeConfigHash(source),
      target_config: target,
      before_scope: source.scope,
      after_scope: afterScope,
      promotions: [],
      inferred_edges: [],
      inference_events: [],
      affected_node_count: 0,
    };
    ctx.journalMutation('scope_updated', payload as unknown as Record<string, unknown>);
    const journalPath = ctx.mutationJournal!.getPath();
    appendFileSync(journalPath, '{"seq":999,"broken"');
    const fileBefore = readFileSync(configPath);
    const walBefore = readFileSync(journalPath);
    first.dispose();

    const second = start();
    expect(second.getPersistenceRecoveryStatus()).toMatchObject({
      complete: false,
      writable: false,
      config_recovery: {
        status: 'write_incomplete',
        resolution_required: true,
        allowed_resolutions: [],
        state_revision: source.config_revision,
        runtime_revision: target.config_revision,
        state_hash: source.config_hash,
        runtime_hash: target.config_hash,
      },
    });
    expect(second.getConfig().scope.cidrs).toContain('10.40.0.0/24');
    expect(readFileSync(configPath)).toEqual(fileBefore);
    expect(readFileSync(journalPath)).toEqual(walBefore);
    second.dispose();

    const third = start();
    expect(third.getPersistenceRecoveryStatus()).toMatchObject({
      complete: false,
      writable: false,
      config_recovery: {
        state_hash: source.config_hash,
        runtime_hash: target.config_hash,
      },
    });
    expect(readFileSync(configPath)).toEqual(fileBefore);
    expect(readFileSync(journalPath)).toEqual(walBefore);
  });

  it('recovers committed scope WAL without overwriting a third-state config, then permits reconciliation', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    first.flushNow();
    const ctx = internals(first);
    const source = first.getConfig();
    const afterScope = { ...source.scope, cidrs: [...source.scope.cidrs, '10.50.0.0/24'] };
    const target = withConfigMetadata({ ...source, scope: afterScope }, (source.config_revision ?? 0) + 1);
    const payload: ScopeUpdatedMutationPayloadV1 = {
      payload_version: 1,
      operation_id: 'scope-third-state-guard',
      occurred_at: '2026-01-01T00:00:04.000Z',
      reason: 'third-state guard',
      source_config_hash: computeConfigHash(source),
      source_file_hash: computeConfigHash(source),
      target_config: target,
      before_scope: source.scope,
      after_scope: afterScope,
      promotions: [],
      inferred_edges: [],
      inference_events: [],
      affected_node_count: 0,
    };
    const scopeSeq = ctx.journalMutation('scope_updated', payload as unknown as Record<string, unknown>);
    const external = withConfigMetadata({ ...source, name: 'Unexplained external state' }, 9);
    writeFileSync(configPath, JSON.stringify(external));
    const fileBefore = readFileSync(configPath);
    first.dispose();

    const restarted = start(external);
    expect(restarted.getStatePersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      complete: true,
      writable: true,
      base_checkpoint: scopeSeq,
      highest_contiguous_applied_seq: scopeSeq,
    });
    const blocked = restarted.getPersistenceRecoveryStatus();
    expect(blocked).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      config_recovery: {
        status: 'diverged',
        resolution_required: true,
        file_hash: external.config_hash,
        state_hash: target.config_hash,
        allowed_resolutions: ['use_file', 'use_state'],
      },
    });
    expect(restarted.getConfig().scope.cidrs).toContain('10.50.0.0/24');
    expect(readFileSync(configPath)).toEqual(fileBefore);
    expect(existsSync(`${configPath}.write-intent.json`)).toBe(false);
    expect(restarted.getFullHistory().filter(event =>
      event.event_type === 'scope_updated'
      && event.details?.operation_id === payload.operation_id,
    )).toHaveLength(1);

    const resolved = restarted.resolveConfigDivergence({
      mode: 'use_state',
      expected_file_hash: blocked.config_recovery!.file_hash!,
      expected_state_hash: blocked.config_recovery!.state_hash!,
    });
    expect(resolved.config).toMatchObject({
      name: source.name,
      config_revision: 10,
      scope: { cidrs: expect.arrayContaining(['10.50.0.0/24']) },
    });
    expect(readFileSync(configPath, 'utf8')).toBe(`${JSON.stringify(resolved.config, null, 2)}\n`);
    expect(restarted.isPersistenceWritable()).toBe(true);

    restarted.dispose();
    const finalRestart = start();
    expect(finalRestart.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      config_recovery: { resolution_required: false },
    });
    expect(finalRestart.getFullHistory().filter(event =>
      event.event_type === 'scope_updated'
      && event.details?.operation_id === payload.operation_id,
    )).toHaveLength(1);
  });

  it('stops scope replay on an incompatible cold-store generation and preserves the WAL', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const ctx = internals(first);
    const cold = {
      id: 'host-10-70-0-8',
      type: 'host',
      label: '10.70.0.8',
      ip: '10.70.0.8',
      discovered_at: '2026-01-01T00:00:04.500Z',
      last_seen_at: '2026-01-01T00:00:04.500Z',
      provenance: 'original-generation',
      confidence: 1,
    };
    ctx.coldAdd(cold);
    first.persistImmediate();
    rmSync(join(dir, '.snapshots'), { recursive: true, force: true });

    const source = first.getConfig();
    const afterScope = { ...source.scope, cidrs: [...source.scope.cidrs, '10.70.0.0/24'] };
    const target = withConfigMetadata({ ...source, scope: afterScope }, (source.config_revision ?? 0) + 1);
    const payload: ScopeUpdatedMutationPayloadV1 = {
      payload_version: 1,
      operation_id: 'scope-cold-generation-guard',
      occurred_at: '2026-01-01T00:00:04.600Z',
      reason: 'exact cold generation guard',
      source_config_hash: computeConfigHash(source),
      source_file_hash: computeConfigHash(source),
      target_config: target,
      before_scope: source.scope,
      after_scope: afterScope,
      promotions: [{
        cold_record: cold,
        hot_node: {
          id: cold.id,
          type: 'host',
          label: cold.label,
          ip: cold.ip,
          discovered_at: cold.discovered_at,
          last_seen_at: cold.last_seen_at,
          discovered_by: cold.provenance,
          confidence: 1,
        },
      }],
      inferred_edges: [],
      inference_events: [],
      affected_node_count: 1,
    };
    // The same id now belongs to a distinct cold-store generation. Persist a
    // base that cannot satisfy the frozen operation without destroying it,
    // then append the operation so it remains newer than that base.
    const replacement = { ...cold, label: 'replacement generation', provenance: 'replacement-generation' };
    ctx.coldStore.import([replacement]);
    first.persistImmediate();
    ctx.journalMutation('scope_updated', payload as unknown as Record<string, unknown>);
    const walPath = ctx.mutationJournal!.getPath();
    const walBefore = readFileSync(walPath);
    first.dispose();

    for (let restart = 0; restart < 2; restart++) {
      const recovered = start();
      expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({ complete: false, writable: false });
      expect(recovered.getConfig().scope.cidrs).not.toContain('10.70.0.0/24');
      expect(recovered.getNode(cold.id)).toBeNull();
      expect(internals(recovered).coldStore.get(cold.id)).toMatchObject({
        label: 'replacement generation',
        provenance: 'replacement-generation',
      });
      expect(readFileSync(walPath)).toEqual(walBefore);
      recovered.dispose();
    }
  });

  it('stops node-drop replay when a node id has been reused and preserves the WAL', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const ctx = internals(first);
    const at = '2026-01-01T00:00:04.700Z';
    first.addNode({
      id: 'host-drop-generation',
      type: 'host',
      label: 'original generation',
      hostname: 'original.example.test',
      discovered_at: at,
      confidence: 1,
    });
    first.addNode({ id: 'host-drop-peer', type: 'host', label: 'peer', discovered_at: at, confidence: 1 });
    const edge = first.addEdge('host-drop-generation', 'host-drop-peer', {
      type: 'RELATED',
      confidence: 1,
      discovered_at: at,
      tested: true,
    });
    first.persistImmediate();
    rmSync(join(dir, '.snapshots'), { recursive: true, force: true });

    const expectedNode = structuredClone(ctx.graph.getNodeAttributes('host-drop-generation'));
    const expectedEdge = structuredClone(ctx.graph.getEdgeAttributes(edge.id));
    const payload: DropNodeMutationPayloadV1 = {
      payload_version: 1,
      operation_id: 'drop-node-generation-guard',
      occurred_at: '2026-01-01T00:00:04.800Z',
      reason: 'exact node generation guard',
      node_id: 'host-drop-generation',
      expected_type: 'host',
      expected_node: { node_id: 'host-drop-generation', props: expectedNode },
      incident_edges: [{
        edge_id: edge.id,
        source: 'host-drop-generation',
        target: 'host-drop-peer',
        edge_type: 'RELATED',
        props: expectedEdge,
      }],
    };
    ctx.graph.replaceNodeAttributes('host-drop-generation', {
      ...expectedNode,
      label: 'replacement generation',
      hostname: 'replacement.example.test',
    });
    first.persistImmediate();
    ctx.journalMutation('drop_node', payload as unknown as Record<string, unknown>);
    const walPath = ctx.mutationJournal!.getPath();
    const walBefore = readFileSync(walPath);
    first.dispose();

    for (let restart = 0; restart < 2; restart++) {
      const recovered = start();
      expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({ complete: false, writable: false });
      expect(recovered.getNode('host-drop-generation')).toMatchObject({
        label: 'replacement generation',
        hostname: 'replacement.example.test',
      });
      expect(recovered.findEdgeId('host-drop-generation', 'host-drop-peer', 'RELATED')).toBe(edge.id);
      expect(readFileSync(walPath)).toEqual(walBefore);
      recovered.dispose();
    }
  });

  it('replays a durable node drop with its exact incident-edge cascade', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const at = '2026-01-01T00:00:07.000Z';
    first.addNode({ id: 'host-drop', type: 'host', label: 'drop', discovered_at: at, confidence: 1 });
    first.addNode({ id: 'host-peer', type: 'host', label: 'peer', discovered_at: at, confidence: 1 });
    first.addEdge('host-drop', 'host-peer', {
      type: 'RELATED',
      confidence: 1,
      discovered_at: at,
      tested: true,
    });
    first.persistImmediate();

    const correction = first.correctGraph('remove invalid duplicate host', [
      { kind: 'drop_node', node_id: 'host-drop' },
    ]);
    expect(correction).toMatchObject({
      dropped_nodes: ['host-drop'],
      dropped_edges: [expect.any(String)],
    });
    first.dispose();

    const restarted = start();
    expect(restarted.getNode('host-drop')).toBeNull();
    expect(restarted.findEdgeId('host-drop', 'host-peer', 'RELATED')).toBeNull();
    expect(restarted.getFullHistory().filter(event =>
      event.event_type === 'graph_corrected'
      && Array.isArray(event.details?.dropped_nodes)
      && event.details.dropped_nodes.includes('host-drop'),
    )).toHaveLength(1);
    restarted.dispose();

    const third = start();
    expect(third.getNode('host-drop')).toBeNull();
    expect(third.getFullHistory().filter(event =>
      event.event_type === 'graph_corrected'
      && Array.isArray(event.details?.dropped_nodes)
      && event.details.dropped_nodes.includes('host-drop'),
    )).toHaveLength(1);
  });

  it('keeps mixed node-drop and patch corrections atomic and durable', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const at = '2026-01-01T00:00:07.250Z';
    first.addNode({ id: 'host-mixed-drop', type: 'host', label: 'drop me', discovered_at: at, confidence: 1 });
    first.addNode({
      id: 'host-mixed-keep',
      type: 'host',
      label: 'old label',
      stale_property: true,
      discovered_at: at,
      confidence: 1,
    });
    first.addEdge('host-mixed-drop', 'host-mixed-keep', {
      type: 'RELATED', confidence: 1, discovered_at: at, tested: true,
    });
    first.persistImmediate();

    const result = first.correctGraph('apply a mixed operator correction', [
      { kind: 'drop_node', node_id: 'host-mixed-drop' },
      {
        kind: 'patch_node',
        node_id: 'host-mixed-keep',
        set_properties: { label: 'verified label' },
        unset_properties: ['stale_property'],
      },
    ]);
    expect(result).toMatchObject({
      dropped_nodes: ['host-mixed-drop'],
      dropped_edges: [expect.any(String)],
      patched_nodes: ['host-mixed-keep'],
    });
    expect(first.getNode('host-mixed-drop')).toBeNull();
    expect(first.getNode('host-mixed-keep')).toMatchObject({ label: 'verified label' });
    expect(first.getNode('host-mixed-keep')).not.toHaveProperty('stale_property');
    first.dispose();

    const restarted = start();
    expect(restarted.getNode('host-mixed-drop')).toBeNull();
    expect(restarted.getNode('host-mixed-keep')).toMatchObject({ label: 'verified label' });
    expect(restarted.getNode('host-mixed-keep')).not.toHaveProperty('stale_property');
    const audits = restarted.getFullHistory().filter(event =>
      event.event_type === 'graph_corrected'
      && event.details?.reason === 'apply a mixed operator correction',
    );
    expect(audits).toHaveLength(1);
    expect(audits[0].details?.dropped_nodes).toEqual(['host-mixed-drop']);
  });

  it('rejects an ambiguous correction reference without changing parallel edges', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const engine = start(legacyConfig());
    const at = '2026-01-01T00:00:07.400Z';
    engine.addNode({ id: 'host-parallel-a', type: 'host', label: 'a', discovered_at: at, confidence: 1 });
    engine.addNode({ id: 'host-parallel-b', type: 'host', label: 'b', discovered_at: at, confidence: 1 });
    const graph = internals(engine).graph;
    graph.addEdgeWithKey('legacy-parallel-edge-1', 'host-parallel-a', 'host-parallel-b', {
      type: 'RELATED', confidence: 0.5, discovered_at: at, tested: false,
    });
    graph.addEdgeWithKey('legacy-parallel-edge-2', 'host-parallel-a', 'host-parallel-b', {
      type: 'RELATED', confidence: 0.9, discovered_at: at, tested: true,
    });
    engine.persistImmediate();
    const walBefore = readFileSync(internals(engine).mutationJournal!.getPath());

    expect(() => engine.correctGraph('ambiguous legacy edge', [{
      kind: 'drop_edge',
      source_id: 'host-parallel-a',
      edge_type: 'RELATED',
      target_id: 'host-parallel-b',
    }])).toThrow(/ambiguous.*parallel edges/i);
    expect(graph.hasEdge('legacy-parallel-edge-1')).toBe(true);
    expect(graph.hasEdge('legacy-parallel-edge-2')).toBe(true);
    expect(readFileSync(internals(engine).mutationJournal!.getPath())).toEqual(walBefore);
  });

  it('replays a frozen multi-operation graph correction without a post-mutation snapshot', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const at = '2026-01-01T00:00:07.500Z';
    for (const id of ['host-source', 'host-old-target', 'host-new-target']) {
      first.addNode({
        id,
        type: 'host',
        label: id,
        discovered_at: at,
        confidence: 1,
        ...(id === 'host-source' ? { stale_alias: 'remove-me' } : {}),
      });
    }
    first.addEdge('host-source', 'host-old-target', {
      type: 'RELATED',
      confidence: 0.6,
      discovered_at: at,
      tested: true,
    });
    first.persistImmediate();
    const baseSeq = internals(first).journalSnapshotSeq;

    const result = first.correctGraph('repair the host relation and label', [
      {
        kind: 'replace_edge',
        source_id: 'host-source',
        edge_type: 'RELATED',
        target_id: 'host-old-target',
        new_target_id: 'host-new-target',
        confidence: 1,
        properties: { correction_note: 'operator verified' },
      },
      {
        kind: 'patch_node',
        node_id: 'host-source',
        set_properties: { label: 'corrected source', hostname: 'source.example.test' },
        unset_properties: ['stale_alias'],
      },
    ], 'action-correct-graph');
    expect(result).toMatchObject({
      dropped_edges: [expect.any(String)],
      replaced_edges: [{ old_edge_id: expect.any(String), new_edge_id: expect.any(String) }],
      patched_nodes: ['host-source'],
    });
    expect(internals(first).mutationJournal!
      .readTransactionsSince(baseSeq)
      .flatMap(transaction => transaction.operations)
      .some(operation => operation.type === 'graph_corrected')).toBe(true);
    first.dispose();

    let operationId: string | undefined;
    for (let restart = 0; restart < 2; restart++) {
      const recovered = start();
      expect(recovered.getNode('host-source')).toMatchObject({
        label: 'corrected source',
        hostname: 'source.example.test',
      });
      expect(recovered.getNode('host-source')).not.toHaveProperty('stale_alias');
      expect(recovered.findEdgeId('host-source', 'host-old-target', 'RELATED')).toBeNull();
      expect(recovered.findEdgeId('host-source', 'host-new-target', 'RELATED')).not.toBeNull();
      const audits = recovered.getFullHistory().filter(event =>
        event.event_type === 'graph_corrected'
        && event.details?.reason === 'repair the host relation and label',
      );
      expect(audits).toHaveLength(1);
      operationId ??= audits[0].details?.operation_id as string | undefined;
      expect(audits[0].details?.operation_id).toBe(operationId);
      recovered.dispose();
    }
  });

  it('replays a frozen identity rewrite appended before live application exactly once', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const at = '2026-01-01T00:00:08.000Z';
    first.addNode({
      id: 'bh-user-alice',
      type: 'user',
      label: 'unresolved alice',
      identity_status: 'unresolved',
      identity_markers: ['user:acct:example:alice'],
      discovered_at: at,
      confidence: 0.8,
    });
    first.addNode({
      id: 'user-example-alice',
      type: 'user',
      label: 'ALICE@EXAMPLE',
      username: 'alice',
      domain_name: 'example',
      identity_status: 'canonical',
      identity_markers: ['user:acct:example:alice'],
      discovered_at: at,
      confidence: 1,
    });
    first.addNode({ id: 'host-alice', type: 'host', label: 'host', discovered_at: at, confidence: 1 });
    first.addEdge('bh-user-alice', 'host-alice', {
      type: 'HAS_SESSION',
      confidence: 1,
      discovered_at: at,
      tested: true,
    });
    first.persistImmediate();

    const operationId = 'identity-crash-before-apply';
    const plan = planIdentityRewrite(internals(first).graph, 'user-example-alice', {
      operation_id: operationId,
      occurred_at: at,
      agent_id: 'agent-identity',
      action_id: 'action-identity',
    });
    expect(plan.payload).not.toBeNull();
    internals(first).journalMutation(
      'identity_rewrite',
      plan.payload as unknown as Record<string, unknown>,
      'action-identity',
    );
    first.dispose();

    for (let restart = 0; restart < 2; restart++) {
      const recovered = start();
      expect(recovered.getNode('bh-user-alice')).toBeNull();
      expect(recovered.getNode('user-example-alice')).toMatchObject({
        identity_status: 'canonical',
        confidence: 1,
      });
      const edgeId = recovered.findEdgeId('user-example-alice', 'host-alice', 'HAS_SESSION');
      expect(edgeId).not.toBeNull();
      expect(recovered.getFullHistory().filter(event =>
        event.details?.identity_operation_id === operationId,
      )).toHaveLength(1);
      recovered.dispose();
    }
  });

  it('uses the durable identity rewrite in public finding ingestion without an immediate snapshot', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const at = '2026-01-01T00:00:09.000Z';
    first.addNode({
      id: 'bh-user-bob',
      type: 'user',
      label: 'unresolved bob',
      identity_status: 'unresolved',
      identity_markers: ['user:acct:example:bob'],
      discovered_at: at,
      confidence: 0.7,
    });
    first.addNode({ id: 'host-bob', type: 'host', label: 'host', discovered_at: at, confidence: 1 });
    first.addEdge('bh-user-bob', 'host-bob', {
      type: 'HAS_SESSION',
      confidence: 1,
      discovered_at: at,
      tested: true,
    });
    first.persistImmediate();
    const baseSeq = internals(first).journalSnapshotSeq;

    const result = first.ingestFinding({
      id: 'finding-bob',
      timestamp: at,
      agent_id: 'agent-bob',
      action_id: 'action-bob',
      tool_name: 'identity-test',
      nodes: [{
        id: 'incoming-bob',
        type: 'user',
        label: 'BOB@EXAMPLE',
        username: 'bob',
        domain_name: 'example',
      }],
      edges: [],
    });
    expect(result.updated_nodes).toContain('user-example-bob');
    expect(first.getNode('bh-user-bob')).toBeNull();
    expect(internals(first).mutationJournal!
      .readTransactionsSince(baseSeq)
      .flatMap(transaction => transaction.operations)
      .some(operation => operation.type === 'identity_rewrite')).toBe(true);
    first.dispose();

    const recovered = start();
    expect(recovered.getNode('bh-user-bob')).toBeNull();
    expect(recovered.getNode('user-example-bob')).not.toBeNull();
    expect(recovered.findEdgeId('user-example-bob', 'host-bob', 'HAS_SESSION')).not.toBeNull();
  });

  it('journals credential-domain backfill and stale-auth degradation from public ingestion', () => {
    writeFileSync(configPath, JSON.stringify(legacyConfig()));
    const first = start(legacyConfig());
    const at = '2026-01-01T00:00:10.000Z';
    first.ingestFinding({
      id: 'finding-credential-follow-ons',
      timestamp: at,
      agent_id: 'agent-credential-follow-ons',
      action_id: 'action-credential-follow-ons',
      tool_name: 'credential-follow-on-test',
      nodes: [
        {
          id: 'incoming-carol',
          type: 'user',
          label: 'CAROL@EXAMPLE.TEST',
          username: 'carol',
          domain_name: 'example.test',
        },
        {
          id: 'cred-carol-expired',
          type: 'credential',
          label: 'carol password',
          cred_type: 'plaintext',
          cred_material_kind: 'plaintext_password',
          cred_user: 'carol',
          cred_value: 'test-only-secret',
          credential_status: 'expired',
        },
        {
          id: 'service-carol-target',
          type: 'service',
          label: 'target service',
          service_name: 'ssh',
        },
      ],
      edges: [
        {
          source: 'incoming-carol',
          target: 'cred-carol-expired',
          properties: { type: 'OWNS_CRED', confidence: 1, discovered_at: at, tested: true },
        },
        {
          source: 'cred-carol-expired',
          target: 'service-carol-target',
          properties: { type: 'POTENTIAL_AUTH', confidence: 0.8, discovered_at: at, tested: false },
        },
      ],
    });

    expect(first.getNode('cred-carol-expired')).toMatchObject({
      cred_domain: 'example.test',
      cred_domain_inferred: true,
      cred_domain_source: 'graph_inference',
    });
    const authEdge = first.findEdgeId('cred-carol-expired', 'service-carol-target', 'POTENTIAL_AUTH')!;
    expect(internals(first).graph.getEdgeAttribute(authEdge, 'confidence')).toBeCloseTo(0.4);
    first.dispose();

    const recovered = start();
    expect(recovered.getNode('cred-carol-expired')).toMatchObject({
      cred_domain: 'example.test',
      cred_domain_inferred: true,
      cred_domain_source: 'graph_inference',
    });
    const recoveredAuthEdge = recovered.findEdgeId('cred-carol-expired', 'service-carol-target', 'POTENTIAL_AUTH')!;
    expect(internals(recovered).graph.getEdgeAttribute(recoveredAuthEdge, 'confidence')).toBeCloseTo(0.4);
    expect(recovered.getPersistenceRecoveryStatus()).toMatchObject({ complete: true, writable: true });
  });
});
